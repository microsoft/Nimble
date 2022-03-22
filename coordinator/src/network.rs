use crate::errors::CoordinatorError;
use ledger::{
  signature::{PublicKey, PublicKeyTrait},
  Handle, LedgerTailMap, LedgerView, MetaBlock, NimbleDigest, Nonce, Receipt,
};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tonic::transport::{Channel, Endpoint};
use tonic::{Code, Status};

pub mod endorser_proto {
  tonic::include_proto!("endorser_proto");
}

use endorser_proto::endorser_call_client::EndorserCallClient;
use endorser_proto::{
  AppendReq, AppendResp, AppendViewLedgerReq, AppendViewLedgerResp, GetPublicKeyReq,
  GetPublicKeyResp, InitializeStateReq, InitializeStateResp, LedgerTailMapEntry, NewLedgerReq,
  NewLedgerResp, ReadLatestReq, ReadLatestResp, ReadLatestStateReq, ReadLatestStateResp,
  ReadLatestViewLedgerReq, ReadLatestViewLedgerResp,
};

#[derive(Debug, Default)]
pub struct ConnectionStore {
  store: Arc<RwLock<HashMap<Vec<u8>, EndorserCallClient<Channel>>>>,
}

impl ConnectionStore {
  pub fn new() -> ConnectionStore {
    ConnectionStore {
      store: Arc::new(RwLock::new(HashMap::new())),
    }
  }

  pub fn get_all(&self) -> Vec<Vec<u8>> {
    self
      .store
      .read()
      .expect("Failed to get the read lock")
      .iter()
      .map(|(pk, _ec)| pk.clone())
      .collect::<Vec<Vec<u8>>>()
  }

  pub async fn connect_endorser(&mut self, hostname: String) -> Result<Vec<u8>, CoordinatorError> {
    let res = Endpoint::from_shared(hostname.to_string());
    if res.is_err() {
      return Err(CoordinatorError::CannotResolveHostName);
    }
    let endorser_endpoint = res.unwrap();
    let channel = endorser_endpoint.connect_lazy();
    let mut client = EndorserCallClient::new(channel);

    let req = tonic::Request::new(GetPublicKeyReq {});
    let res = client.get_public_key(req).await;
    if res.is_err() {
      return Err(CoordinatorError::FailedToConnectToEndorser);
    }
    let GetPublicKeyResp { pk } = res.unwrap().into_inner();
    println!("Connected Successfully to {:?}", &hostname);

    let res = PublicKey::from_bytes(&pk);
    if res.is_err() {
      return Err(CoordinatorError::UnableToRetrievePublicKey);
    }

    if let Ok(mut conn_map) = self.store.write() {
      conn_map.insert(pk.clone(), client);
    } else {
      eprintln!("Failed to acquire the write lock");
      return Err(CoordinatorError::FailedToAcquireWriteLock);
    }
    Ok(pk)
  }

  pub async fn initialize_state(
    &mut self,
    endorsers: &[Vec<u8>],
    ledger_tail_map: &LedgerTailMap,
    view_ledger_tail_height: &(NimbleDigest, usize),
    block_hash: &NimbleDigest,
    cond_updated_tail_hash: &NimbleDigest,
  ) -> Result<Receipt, CoordinatorError> {
    let ledger_tail_map_proto: Vec<LedgerTailMapEntry> = ledger_tail_map
      .iter()
      .map(|(handle, (tail, height))| LedgerTailMapEntry {
        handle: handle.to_bytes(),
        tail: tail.to_bytes(),
        height: *height as u64,
      })
      .collect();

    let mut jobs = Vec::new();
    if let Ok(conn_map) = self.store.read() {
      for pk in endorsers {
        if !conn_map.contains_key(pk) {
          eprintln!("No endorser has this public key {:?}", pk);
          return Err(CoordinatorError::InvalidEndorserPublicKey);
        }
        let mut endorser_client = conn_map[pk].clone();
        let ledger_tail_map = ledger_tail_map_proto.clone();
        let view_ledger_tail = view_ledger_tail_height.0.to_bytes();
        let view_ledger_height = view_ledger_tail_height.1 as u64;
        let block_hash = block_hash.to_bytes();
        let cond_updated_tail_hash = cond_updated_tail_hash.to_bytes();
        let pk_bytes = pk.clone();
        let job = tokio::spawn(async move {
          let response = endorser_client
            .initialize_state(tonic::Request::new(InitializeStateReq {
              ledger_tail_map,
              view_ledger_tail,
              view_ledger_height,
              block_hash,
              cond_updated_tail_hash,
            }))
            .await;
          (pk_bytes, response)
        });
        jobs.push(job);
      }
    } else {
      eprintln!("Failed to acquire the read lock");
      return Err(CoordinatorError::FailedToAcquireReadLock);
    }

    let mut receipt_bytes: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = Vec::new();
    for job in jobs {
      let res = job.await;
      if let Ok((pk, res2)) = res {
        if let Ok(resp) = res2 {
          let InitializeStateResp { view, signature } = resp.into_inner();
          receipt_bytes.push((pk, view, signature));
        } else {
          eprintln!("initialize_state failed: {:?}", res2.unwrap_err());
          return Err(CoordinatorError::FailedToInitializeEndorser);
        }
      } else {
        eprintln!("initialize_state failed: {:?}", res.unwrap_err());
        return Err(CoordinatorError::FailedToInitializeEndorser);
      }
    }
    let res = Receipt::from_bytes_with_uniqueness_check(&receipt_bytes);
    match res {
      Ok(receipt) => Ok(receipt),
      Err(_) => Err(CoordinatorError::EndorsersInDifferentViews),
    }
  }

  pub async fn create_ledger(&self, ledger_handle: &Handle) -> Result<Receipt, CoordinatorError> {
    let mut jobs = Vec::new();
    for (pk, ec) in self
      .store
      .read()
      .expect("Failed to get the read lock")
      .iter()
    {
      let mut endorser_client = ec.clone();
      let handle = *ledger_handle;
      let pk_bytes = pk.clone();
      let job = tokio::spawn(async move {
        let response = endorser_client
          .new_ledger(tonic::Request::new(NewLedgerReq {
            handle: handle.to_bytes(),
          }))
          .await;
        (pk_bytes, response)
      });
      jobs.push(job);
    }

    let mut receipt_bytes: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = Vec::new();
    for job in jobs {
      let res = job.await;
      if let Ok((pk, res2)) = res {
        if let Ok(resp) = res2 {
          let NewLedgerResp { view, signature } = resp.into_inner();
          receipt_bytes.push((pk, view, signature));
        } else {
          eprintln!("create_ledger failed: {:?}", res2.unwrap_err());
          return Err(CoordinatorError::FailedToCreateLedger);
        }
      } else {
        eprintln!("create_ledger failed: {:?}", res.unwrap_err());
        return Err(CoordinatorError::FailedToCreateLedger);
      }
    }
    let res = Receipt::from_bytes_with_uniqueness_check(&receipt_bytes);
    match res {
      Ok(receipt) => Ok(receipt),
      Err(_) => Err(CoordinatorError::EndorsersInDifferentViews),
    }
  }

  async fn retry_append_ledger(
    &self,
    pk: &[u8],
    ledger_handle: &Handle,
    block_hash: &NimbleDigest,
    tail_hash: &NimbleDigest,
    tail_height: usize,
  ) -> Result<tonic::Response<AppendResp>, tonic::Status> {
    let job = {
      if let Ok(conn_map) = self.store.read() {
        if !conn_map.contains_key(pk) {
          return Err(Status::aborted("No endorser has this public key"));
        } else {
          let mut endorser_client = conn_map[pk].clone();
          let handle = *ledger_handle;
          let block = *block_hash;
          let tail = *tail_hash;
          tokio::spawn(async move {
            let response = endorser_client
              .append(tonic::Request::new(AppendReq {
                handle: handle.to_bytes(),
                block_hash: block.to_bytes(),
                cond_updated_tail_hash: tail.to_bytes(),
                cond_updated_tail_height: tail_height as u64,
              }))
              .await;
            response
          })
        }
      } else {
        return Err(Status::aborted("Failed to acquire the read lock"));
      }
    };

    let res = job.await;
    if res.is_err() {
      return Err(Status::aborted("Failed to append in retry"));
    }
    res.unwrap()
  }

  pub async fn append_ledger(
    &self,
    ledger_handle: &Handle,
    block_hash: &NimbleDigest,
    tail_hash: &NimbleDigest,
    tail_height: usize,
  ) -> Result<Receipt, CoordinatorError> {
    let mut jobs = Vec::new();
    for (pk, ec) in self
      .store
      .read()
      .expect("Failed to get the read lock")
      .iter()
    {
      let mut endorser_client = ec.clone();
      let handle = *ledger_handle;
      let block = *block_hash;
      let tail = *tail_hash;
      let pk_bytes = pk.clone();
      let job = tokio::spawn(async move {
        let response = endorser_client
          .append(tonic::Request::new(AppendReq {
            handle: handle.to_bytes(),
            block_hash: block.to_bytes(),
            cond_updated_tail_hash: tail.to_bytes(),
            cond_updated_tail_height: tail_height as u64,
          }))
          .await;
        (pk_bytes, response)
      });
      jobs.push(job);
    }

    let mut receipt_bytes: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = Vec::new();
    for job in jobs {
      let res = job.await;
      if let Ok((pk, res2)) = res {
        if let Ok(resp) = res2 {
          let AppendResp { view, signature } = resp.into_inner();
          receipt_bytes.push((pk, view, signature));
        } else {
          let status = res2.unwrap_err();
          if status.code() != Code::FailedPrecondition {
            eprintln!("append_ledger failed: {:?}", status);
            return Err(CoordinatorError::FailedToAppendLedger);
          }
          loop {
            // This means an out-of-order append; let's retry.
            let res3 = self
              .retry_append_ledger(&pk, ledger_handle, block_hash, tail_hash, tail_height)
              .await;
            if let Ok(resp) = res3 {
              let AppendResp { view, signature } = resp.into_inner();
              receipt_bytes.push((pk, view, signature));
              break;
            } else {
              if status.code() == Code::FailedPrecondition {
                continue;
              }
              eprintln!("append_ledger failed: {:?}", status);
              return Err(CoordinatorError::FailedToAppendLedger);
            }
          }
        }
      } else {
        eprintln!("append_ledger failed: {:?}", res.unwrap_err());
        return Err(CoordinatorError::FailedToAppendLedger);
      }
    }
    let res = Receipt::from_bytes_with_uniqueness_check(&receipt_bytes);
    match res {
      Ok(receipt) => Ok(receipt),
      Err(_) => Err(CoordinatorError::EndorsersInDifferentViews),
    }
  }

  pub async fn read_ledger_tail(
    &self,
    ledger_handle: &Handle,
    client_nonce: &Nonce,
  ) -> Result<Receipt, CoordinatorError> {
    let mut jobs = Vec::new();
    for (pk, ec) in self
      .store
      .read()
      .expect("Failed to get the read lock")
      .iter()
    {
      let mut endorser_client = ec.clone();
      let handle = *ledger_handle;
      let nonce = *client_nonce;
      let pk_bytes = pk.clone();
      let job = tokio::spawn(async move {
        let response = endorser_client
          .read_latest(tonic::Request::new(ReadLatestReq {
            handle: handle.to_bytes(),
            nonce: nonce.get(),
          }))
          .await;
        (pk_bytes, response)
      });
      jobs.push(job);
    }

    let mut receipt_bytes: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = Vec::new();
    for job in jobs {
      let res = job.await;
      if let Ok((pk, res2)) = res {
        if let Ok(resp) = res2 {
          let ReadLatestResp { view, signature } = resp.into_inner();
          receipt_bytes.push((pk, view, signature));
        } else {
          eprintln!("read_ledger_tail failed: {:?}", res2.unwrap_err());
          return Err(CoordinatorError::FailedToReadLedger);
        }
      } else {
        eprintln!("read_ledger_tail failed: {:?}", res.unwrap_err());
        return Err(CoordinatorError::FailedToReadLedger);
      }
    }
    let res = Receipt::from_bytes_with_uniqueness_check(&receipt_bytes);
    match res {
      Ok(receipt) => Ok(receipt),
      Err(_) => Err(CoordinatorError::EndorsersInDifferentViews),
    }
  }

  pub async fn append_view_ledger(
    &self,
    endorsers: &[Vec<u8>],
    block_hash: &NimbleDigest,
    tail_hash: &NimbleDigest,
  ) -> Result<Receipt, CoordinatorError> {
    let mut jobs = Vec::new();
    if let Ok(conn_map) = self.store.read() {
      for pk in endorsers {
        if !conn_map.contains_key(pk) {
          eprintln!("No endorser has this public key {:?}", pk);
          return Err(CoordinatorError::InvalidEndorserPublicKey);
        }
        let mut endorser_client = conn_map[pk].clone();
        let block = *block_hash;
        let tail = *tail_hash;
        let pk_bytes = pk.clone();
        let job = tokio::spawn(async move {
          let response = endorser_client
            .append_view_ledger(tonic::Request::new(AppendViewLedgerReq {
              block_hash: block.to_bytes(),
              cond_updated_tail_hash: tail.to_bytes(),
            }))
            .await;
          (pk_bytes, response)
        });
        jobs.push(job);
      }
    } else {
      eprintln!("Failed to acquire the read lock");
      return Err(CoordinatorError::FailedToAcquireReadLock);
    }

    let mut receipt_bytes: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = Vec::new();
    for job in jobs {
      let res = job.await;
      if let Ok((pk, res2)) = res {
        if let Ok(resp) = res2 {
          let AppendViewLedgerResp { view, signature } = resp.into_inner();
          receipt_bytes.push((pk, view, signature));
        } else {
          eprintln!("append_view_ledger failed: {:?}", res2.unwrap_err());
          return Err(CoordinatorError::FailedToAppendViewLedger);
        }
      } else {
        eprintln!("append_view_ledger failed: {:?}", res.unwrap_err());
        return Err(CoordinatorError::FailedToAppendViewLedger);
      }
    }
    let res = Receipt::from_bytes_with_uniqueness_check(&receipt_bytes);
    match res {
      Ok(receipt) => Ok(receipt),
      Err(_) => Err(CoordinatorError::EndorsersInDifferentViews),
    }
  }

  #[allow(dead_code)]
  pub async fn read_view_ledger_tail(
    &self,
    client_nonce: &Nonce,
  ) -> Result<Receipt, CoordinatorError> {
    let mut jobs = Vec::new();
    for (pk, ec) in self
      .store
      .read()
      .expect("Failed to get the read lock")
      .iter()
    {
      let mut endorser_client = ec.clone();
      let nonce = *client_nonce;
      let pk_bytes = pk.clone();
      let job = tokio::spawn(async move {
        let response = endorser_client
          .read_latest_view_ledger(tonic::Request::new(ReadLatestViewLedgerReq {
            nonce: nonce.get(),
          }))
          .await;
        (pk_bytes, response)
      });
      jobs.push(job);
    }

    let mut receipt_bytes: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = Vec::new();
    for job in jobs {
      let res = job.await;
      if let Ok((pk, res2)) = res {
        if let Ok(resp) = res2 {
          let ReadLatestViewLedgerResp { view, signature } = resp.into_inner();
          receipt_bytes.push((pk, view, signature));
        } else {
          eprintln!("read_view_ledger_tail failed: {:?}", res2.unwrap_err());
          return Err(CoordinatorError::FailedToReadViewLedger);
        }
      } else {
        eprintln!("read_view_ledger_tail failed: {:?}", res.unwrap_err());
        return Err(CoordinatorError::FailedToReadViewLedger);
      }
    }
    let res = Receipt::from_bytes_with_uniqueness_check(&receipt_bytes);
    match res {
      Ok(receipt) => Ok(receipt),
      Err(_) => Err(CoordinatorError::EndorsersInDifferentViews),
    }
  }

  #[allow(dead_code)]
  pub async fn read_latest_state(
    &self,
    view_ledger_height: usize,
    to_lock: bool,
    client_nonce: &Nonce,
  ) -> Result<(Vec<(Vec<u8>, LedgerView, bool)>, Receipt), CoordinatorError> {
    let mut jobs = Vec::new();
    for (pk, ec) in self
      .store
      .read()
      .expect("Failed to get the read lock")
      .iter()
    {
      let mut endorser_client = ec.clone();
      let nonce = *client_nonce;
      let pk_bytes = pk.clone();
      let job = tokio::spawn(async move {
        let response = endorser_client
          .read_latest_state(tonic::Request::new(ReadLatestStateReq {
            nonce: nonce.get(),
            view_ledger_height: view_ledger_height as u64,
            to_lock,
          }))
          .await;
        (pk_bytes, response)
      });
      jobs.push(job);
    }

    let mut ledger_views = Vec::new();
    let mut receipt_bytes: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = Vec::new();
    for job in jobs {
      let res = job.await;
      if let Ok((pk, res2)) = res {
        if let Ok(resp) = res2 {
          let ReadLatestStateResp {
            view,
            ledger_tail_map,
            view_ledger_tail_prev,
            view_ledger_tail_view,
            view_ledger_tail_height,
            is_locked,
            signature,
          } = resp.into_inner();
          let ledger_tail_map_rs: HashMap<NimbleDigest, (NimbleDigest, usize)> = ledger_tail_map
            .into_iter()
            .map(|e| {
              (
                NimbleDigest::from_bytes(&e.handle).unwrap(),
                (
                  NimbleDigest::from_bytes(&e.tail).unwrap(),
                  e.height as usize,
                ),
              )
            })
            .collect();
          let ledger_view = LedgerView {
            view_tail_metablock: MetaBlock::new(
              &NimbleDigest::from_bytes(&view_ledger_tail_prev).unwrap(), // TODO: better error handling
              &NimbleDigest::from_bytes(&view_ledger_tail_view).unwrap(),
              view_ledger_tail_height as usize,
            ),
            ledger_tail_map: ledger_tail_map_rs,
          };
          ledger_views.push((pk.clone(), ledger_view, is_locked));
          receipt_bytes.push((pk, view, signature));
        } else {
          eprintln!("read_view_ledger_tail failed: {:?}", res2.unwrap_err());
          return Err(CoordinatorError::FailedToReadViewLedger);
        }
      } else {
        eprintln!("read_view_ledger_tail failed: {:?}", res.unwrap_err());
        return Err(CoordinatorError::FailedToReadViewLedger);
      }
    }
    let res = Receipt::from_bytes_with_uniqueness_check(&receipt_bytes);
    match res {
      Ok(receipt) => Ok((ledger_views, receipt)),
      Err(_) => Err(CoordinatorError::EndorsersInDifferentViews),
    }
  }
}
