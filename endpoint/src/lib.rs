mod errors;

use tonic::{
  transport::{Channel, Endpoint},
  Request,
};

pub mod coordinator_proto {
  tonic::include_proto!("coordinator_proto");
}

use crate::errors::EndpointError;
use coordinator_proto::{
  call_client::CallClient, AppendReq, AppendResp, NewLedgerReq, NewLedgerResp, ReadLatestReq,
  ReadLatestResp, ReadViewByIndexReq, ReadViewByIndexResp,
};
use ledger::{
  signature::{PrivateKey, PrivateKeyTrait, PublicKeyTrait, SignatureTrait},
  Block, CustomSerde, NimbleDigest, NimbleHashTrait,
};
use std::{
  convert::TryFrom,
  sync::{Arc, RwLock},
};
use verifier::{
  errors::VerificationError, verify_append, verify_new_ledger, verify_read_latest, VerifierState,
};

#[derive(Debug, Clone)]
pub struct Connection {
  client: CallClient<Channel>,
}

impl Connection {
  pub async fn new(coordinator_endpoint_address: String) -> Result<Self, EndpointError> {
    let connection_attempt = Endpoint::from_shared(coordinator_endpoint_address);
    let connection = match connection_attempt {
      Ok(connection) => connection,
      Err(_err) => return Err(EndpointError::CoordinatorHostNameNotFound),
    };
    let channel = connection.connect_lazy();
    let client = CallClient::new(channel);
    Ok(Self { client })
  }

  pub async fn new_ledger(&self, handle: &[u8], block: &[u8]) -> Result<Vec<u8>, EndpointError> {
    let req = Request::new(NewLedgerReq {
      handle: handle.to_vec(),
      block: block.to_vec(),
    });
    let NewLedgerResp { receipt } = self
      .client
      .clone()
      .new_ledger(req)
      .await
      .map_err(|e| {
        eprintln!("Failed to create a new ledger {:?}", e);
        EndpointError::FailedToCreateNewCounter
      })?
      .into_inner();
    Ok(receipt)
  }

  pub async fn append(
    &self,
    handle: &[u8],
    block: &[u8],
    expected_height: u64,
  ) -> Result<Vec<u8>, EndpointError> {
    let req = Request::new(AppendReq {
      handle: handle.to_vec(),
      block: block.to_vec(),
      expected_height,
    });
    let AppendResp { receipt } = self
      .client
      .clone()
      .append(req)
      .await
      .map_err(|e| {
        eprintln!("Failed to append to a ledger {:?}", e);
        EndpointError::FailedToIncrementCounter
      })?
      .into_inner();
    Ok(receipt)
  }

  pub async fn read_latest(
    &self,
    handle: &[u8],
    nonce: &[u8],
  ) -> Result<(Vec<u8>, Vec<u8>), EndpointError> {
    let ReadLatestResp { block, receipt } = self
      .client
      .clone()
      .read_latest(ReadLatestReq {
        handle: handle.to_vec(),
        nonce: nonce.to_vec(),
      })
      .await
      .map_err(|e| {
        eprintln!("Failed to read a ledger {:?}", e);
        EndpointError::FailedToReadCounter
      })?
      .into_inner();
    Ok((block, receipt))
  }

  pub async fn read_view_by_index(
    &self,
    index: usize,
  ) -> Result<(Vec<u8>, Vec<u8>), EndpointError> {
    let ReadViewByIndexResp { block, receipt } = self
      .client
      .clone()
      .read_view_by_index(ReadViewByIndexReq {
        index: index as u64,
      })
      .await
      .map_err(|_e| EndpointError::FailedToReadViewLedger)?
      .into_inner();
    Ok((block, receipt))
  }
}

pub struct EndpointState {
  conn: Connection,
  id: NimbleDigest,
  sk: PrivateKey,
  vs: Arc<RwLock<VerifierState>>,
}

impl EndpointState {
  pub async fn new(hostname: String) -> Result<Self, EndpointError> {
    // make a connection to the coordinator
    let conn = {
      let res = Connection::new(hostname).await;

      match res {
        Ok(conn) => conn,
        Err(e) => {
          panic!("Endpoint Error: {:?}", e);
        },
      }
    };

    // initialize id and vs
    let (id, vs) = {
      let mut vs = VerifierState::default();

      let (block, receipt) = conn.read_view_by_index(1usize).await.unwrap();

      let res = vs.apply_view_change(&block, &receipt);
      assert!(res.is_ok());

      // the hash of the genesis block of the view ledger uniquely identifies a particular instance of NimbleLedger
      let id = Block::from_bytes(&block).unwrap().hash();

      (id, vs)
    };

    // produce a private key pair to sign responses
    let sk = PrivateKey::new();

    Ok(EndpointState {
      conn,
      id,
      sk,
      vs: Arc::new(RwLock::new(vs)),
    })
  }

  pub fn get_identity(&self) -> Result<(Vec<u8>, Vec<u8>), EndpointError> {
    Ok((
      self.id.to_bytes(),
      self.sk.get_public_key().unwrap().to_bytes(),
    ))
  }

  async fn update_view(&self) -> Result<(), EndpointError> {
    loop {
      let mut idx = {
        if let Ok(vs_rd) = self.vs.read() {
          vs_rd.get_view_ledger_height()
        } else {
          return Err(EndpointError::FailedToAcquireReadLock);
        }
      };

      idx += 1;
      let res = self.conn.read_view_by_index(idx).await;
      if res.is_err() {
        break;
      }

      let (block, receipt) = res.unwrap();
      if let Ok(mut vs_wr) = self.vs.write() {
        let res = vs_wr.apply_view_change(&block, &receipt);
        if res.is_err() {
          return Err(EndpointError::FailedToApplyViewChange);
        }
      } else {
        return Err(EndpointError::FailedToAcquireWriteLock);
      }
    }
    Ok(())
  }

  pub async fn new_counter(&self, handle: &[u8], tag: &[u8]) -> Result<Vec<u8>, EndpointError> {
    // issue a request to the coordinator and receive a response
    let receipt = {
      let res = self.conn.new_ledger(handle, tag).await;
      if res.is_err() {
        return Err(EndpointError::FailedToCreateNewCounter);
      }
      res.unwrap()
    };

    // verify the response received from the coordinator; TODO: handle the case where vs does not have the returned view hash
    let res = {
      if let Ok(vs_rd) = self.vs.read() {
        verify_new_ledger(&vs_rd, handle, tag, &receipt)
      } else {
        return Err(EndpointError::FailedToAcquireReadLock);
      }
    };
    if res.is_err() {
      if res.unwrap_err() != VerificationError::ViewNotFound {
        return Err(EndpointError::FailedToVerifyNewCounter);
      } else {
        let res = self.update_view().await;
        if res.is_err() {
          return Err(EndpointError::FailedToVerifyNewCounter);
        }
        let res = {
          if let Ok(vs_rd) = self.vs.read() {
            verify_new_ledger(&vs_rd, handle, tag, &receipt)
          } else {
            return Err(EndpointError::FailedToAcquireReadLock);
          }
        };
        if res.is_err() {
          eprintln!("failed to create a new counter {:?}", res);
          return Err(EndpointError::FailedToVerifyNewCounter);
        }
      }
    }

    // sign a message that unequivocally identifies the counter and tag
    let msg = {
      let s = format!(
        "NewCounter id: {:?}, handle = {:?}, tag = {:?}, counter = {:?}",
        self.id.to_bytes(),
        handle,
        tag,
        1_usize
      );
      NimbleDigest::digest(s.as_bytes())
    };
    let signature = self.sk.sign(&msg.to_bytes()).unwrap().to_bytes();

    Ok(signature)
  }

  pub async fn increment_counter(
    &self,
    handle: &[u8],
    tag: &[u8],
    expected_counter: u64,
  ) -> Result<Vec<u8>, EndpointError> {
    // convert u64 to usize, returning error
    let expected_height = {
      let res = usize::try_from(expected_counter);
      if res.is_err() {
        return Err(EndpointError::FailedToConvertCounter);
      }
      res.unwrap()
    };

    // issue a request to the coordinator and receive a response
    let receipt = {
      let res = self.conn.append(handle, tag, expected_counter).await;

      if res.is_err() {
        return Err(EndpointError::FailedToIncrementCounter);
      }
      res.unwrap()
    };

    // verify the response received from the coordinator; TODO: handle the case where vs does not have the returned view hash
    let res = {
      if let Ok(vs_rd) = self.vs.read() {
        verify_append(&vs_rd, handle, tag, expected_height, &receipt)
      } else {
        return Err(EndpointError::FailedToAcquireReadLock);
      }
    };
    if res.is_err() {
      if res.unwrap_err() != VerificationError::ViewNotFound {
        return Err(EndpointError::FailedToVerifyIncrementedCounter);
      } else {
        let res = self.update_view().await;
        if res.is_err() {
          return Err(EndpointError::FailedToVerifyIncrementedCounter);
        }
        let res = {
          if let Ok(vs_rd) = self.vs.read() {
            verify_append(&vs_rd, handle, tag, expected_height, &receipt)
          } else {
            return Err(EndpointError::FailedToAcquireReadLock);
          }
        };
        if res.is_err() {
          eprintln!("failed to increment a counter {:?}", res);
          return Err(EndpointError::FailedToVerifyIncrementedCounter);
        }
      }
    }

    // sign a message that unequivocally identifies the counter and tag
    let msg = {
      let s = format!(
        "IncrementCounter id: {:?}, handle = {:?}, tag = {:?}, counter = {:?}",
        self.id.to_bytes(),
        handle,
        tag,
        expected_height
      );
      NimbleDigest::digest(s.as_bytes())
    };
    let signature = self.sk.sign(&msg.to_bytes()).unwrap().to_bytes();

    Ok(signature)
  }

  pub async fn read_counter(
    &self,
    handle: &[u8],
    nonce: &[u8],
  ) -> Result<(Vec<u8>, u64, Vec<u8>), EndpointError> {
    // issue a request to the coordinator and receive a response
    let (block, receipt) = {
      let res = self.conn.read_latest(handle, nonce).await;

      if res.is_err() {
        return Err(EndpointError::FailedToReadCounter);
      }
      res.unwrap()
    };

    // verify the response received from the coordinator; TODO: handle the case where vs does not have the returned view hash
    let res = {
      if let Ok(vs_rd) = self.vs.read() {
        verify_read_latest(&vs_rd, handle, block.as_ref(), nonce, &receipt)
      } else {
        return Err(EndpointError::FailedToAcquireReadLock);
      }
    };
    let counter = {
      if res.is_err() {
        if res.unwrap_err() != VerificationError::ViewNotFound {
          return Err(EndpointError::FaieldToVerifyReadCounter);
        } else {
          let res = self.update_view().await;
          if res.is_err() {
            return Err(EndpointError::FaieldToVerifyReadCounter);
          }
          let res = {
            if let Ok(vs_rd) = self.vs.read() {
              verify_read_latest(&vs_rd, handle, block.as_ref(), nonce, &receipt)
            } else {
              return Err(EndpointError::FailedToAcquireReadLock);
            }
          };
          if res.is_err() {
            return Err(EndpointError::FaieldToVerifyReadCounter);
          } else {
            res.unwrap()
          }
        }
      } else {
        res.unwrap()
      }
    };

    // sign a message that unequivocally identifies the counter and tag
    let msg = {
      let s = format!(
        "ReadCounter id: {:?}, handle = {:?}, tag = {:?}, counter = {:?}, nonce = {:?}",
        self.id.to_bytes(),
        handle,
        block,
        counter,
        nonce
      );
      NimbleDigest::digest(s.as_bytes())
    };
    let signature = self.sk.sign(&msg.to_bytes()).unwrap().to_bytes();

    // respond to the light client
    Ok((block, counter as u64, signature))
  }
}
