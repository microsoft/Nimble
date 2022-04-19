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
use std::convert::TryFrom;
use verifier::{verify_append, verify_new_ledger, verify_read_latest, VerifierState};

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
      .map_err(|_err| EndpointError::UnableToConnectToCoordinator)?
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
      .map_err(|_err| EndpointError::UnableToConnectToCoordinator)?
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
      .map_err(|_err| EndpointError::UnableToConnectToCoordinator)?
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
      .map_err(|_err| EndpointError::UnableToConnectToCoordinator)?
      .into_inner();
    Ok((block, receipt))
  }
}

pub struct EndpointState {
  conn: Connection,
  id: NimbleDigest,
  vs: VerifierState,
  sk: PrivateKey,
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

    Ok(EndpointState { conn, id, vs, sk })
  }

  pub fn get_identity(&self) -> Result<(Vec<u8>, Vec<u8>), EndpointError> {
    Ok((
      self.id.to_bytes(),
      self.sk.get_public_key().unwrap().to_bytes(),
    ))
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
    let res = verify_new_ledger(&self.vs, handle, tag, &receipt);
    if res.is_err() {
      return Err(EndpointError::FailedToVerifyNewCounter);
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
    let res = verify_append(&self.vs, tag, expected_height, &receipt);
    if res.is_err() {
      return Err(EndpointError::FailedToVerifyIncrementedCounter);
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
    let res = verify_read_latest(&self.vs, block.as_ref(), nonce, &receipt);
    if res.is_err() {
      return Err(EndpointError::FaieldToVerifyReadCounter);
    }

    let (tag, counter) = res.unwrap();

    // sign a message that unequivocally identifies the counter and tag
    let msg = {
      let s = format!(
        "ReadCounter id: {:?}, handle = {:?}, tag = {:?}, counter = {:?}, nonce = {:?}",
        self.id.to_bytes(),
        handle,
        tag,
        counter,
        nonce
      );
      NimbleDigest::digest(s.as_bytes())
    };
    let signature = self.sk.sign(&msg.to_bytes()).unwrap().to_bytes();

    // respond to the light client
    Ok((tag, counter as u64, signature))
  }
}
