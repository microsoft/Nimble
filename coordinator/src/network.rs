use crate::errors::CoordinatorError;
use ledger::{
  signature::{PublicKey, PublicKeyTrait},
  CustomSerde, Handle, LedgerView, MetaBlock, NimbleDigest, Nonce, Receipt,
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
  ReadLatestViewLedgerReq, ReadLatestViewLedgerResp, UnlockReq,
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
    ledger_view: &LedgerView,
    block_hash: &NimbleDigest,
    expected_height: usize,
  ) -> Result<Receipt, CoordinatorError> {
    let ledger_tail_map_proto: Vec<LedgerTailMapEntry> = ledger_view
      .ledger_tail_map
      .iter()
      .map(|(handle, metablock)| LedgerTailMapEntry {
        handle: handle.to_bytes(),
        metablock: metablock.to_bytes(),
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
        let view_tail_metablock = ledger_view.view_tail_metablock.to_bytes().to_vec();
        let block_hash = block_hash.to_bytes();
        let pk_bytes = pk.clone();
        let job = tokio::spawn(async move {
          let response = endorser_client
            .initialize_state(tonic::Request::new(InitializeStateReq {
              ledger_tail_map,
              view_tail_metablock,
              block_hash,
              expected_height: expected_height as u64,
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

    let mut receipts: Vec<Receipt> = Vec::new();
    for job in jobs {
      let res = job.await;
      if let Ok((_pk, res2)) = res {
        if let Ok(resp) = res2 {
          let InitializeStateResp { receipt } = resp.into_inner();
          if let Ok(receipt_rs) = Receipt::from_bytes(&receipt) {
            receipts.push(receipt_rs);
          } else {
            eprintln!("initialize_state failed: invalid receipt");
            return Err(CoordinatorError::InvalidReceipt);
          }
        } else {
          eprintln!("initialize_state failed: {:?}", res2.unwrap_err());
          return Err(CoordinatorError::FailedToInitializeEndorser);
        }
      } else {
        eprintln!("initialize_state failed: {:?}", res.unwrap_err());
        return Err(CoordinatorError::FailedToInitializeEndorser);
      }
    }
    let res = Receipt::merge_receipts(&receipts);
    match res {
      Ok(receipt) => Ok(receipt),
      Err(_) => Err(CoordinatorError::EndorsersInDifferentViews),
    }
  }

  pub async fn create_ledger(
    &self,
    endorsers: &[Vec<u8>],
    ledger_handle: &Handle,
    ignore_lock: bool,
  ) -> Result<Receipt, CoordinatorError> {
    let mut jobs = Vec::new();
    if let Ok(conn_map) = self.store.read() {
      for pk in endorsers {
        if !conn_map.contains_key(pk) {
          eprintln!("No endorser has this public key {:?}", pk);
          return Err(CoordinatorError::InvalidEndorserPublicKey);
        }
        let mut endorser_client = conn_map[pk].clone();
        let handle = *ledger_handle;
        let pk_bytes = pk.clone();
        let job = tokio::spawn(async move {
          let response = endorser_client
            .new_ledger(tonic::Request::new(NewLedgerReq {
              handle: handle.to_bytes(),
              ignore_lock,
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

    let mut receipts: Vec<Receipt> = Vec::new();
    for job in jobs {
      let res = job.await;
      if let Ok((_pk, res2)) = res {
        if let Ok(resp) = res2 {
          let NewLedgerResp { receipt } = resp.into_inner();
          if let Ok(receipt_rs) = Receipt::from_bytes(&receipt) {
            receipts.push(receipt_rs);
          } else {
            eprintln!("initialize_state failed: invalid receipt");
            return Err(CoordinatorError::InvalidReceipt);
          }
        } else {
          eprintln!("create_ledger failed: {:?}", res2.unwrap_err());
          return Err(CoordinatorError::FailedToCreateLedger);
        }
      } else {
        eprintln!("create_ledger failed: {:?}", res.unwrap_err());
        return Err(CoordinatorError::FailedToCreateLedger);
      }
    }
    let res = Receipt::merge_receipts(&receipts);
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
    expected_height: usize,
    ignore_lock: bool,
  ) -> Result<tonic::Response<AppendResp>, tonic::Status> {
    let job = {
      if let Ok(conn_map) = self.store.read() {
        if !conn_map.contains_key(pk) {
          return Err(Status::aborted("No endorser has this public key"));
        } else {
          let mut endorser_client = conn_map[pk].clone();
          let handle = *ledger_handle;
          let block = *block_hash;
          tokio::spawn(async move {
            let response = endorser_client
              .append(tonic::Request::new(AppendReq {
                handle: handle.to_bytes(),
                block_hash: block.to_bytes(),
                expected_height: expected_height as u64,
                ignore_lock,
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
    endorsers: &[Vec<u8>],
    ledger_handle: &Handle,
    block_hash: &NimbleDigest,
    expected_height: usize,
    ignore_lock: bool,
  ) -> Result<Receipt, CoordinatorError> {
    let mut jobs = Vec::new();
    if let Ok(conn_map) = self.store.read() {
      for pk in endorsers {
        if !conn_map.contains_key(pk) {
          eprintln!("No endorser has this public key {:?}", pk);
          return Err(CoordinatorError::InvalidEndorserPublicKey);
        }
        let mut endorser_client = conn_map[pk].clone();
        let handle = *ledger_handle;
        let block = *block_hash;
        let pk_bytes = pk.clone();
        let job = tokio::spawn(async move {
          let response = endorser_client
            .append(tonic::Request::new(AppendReq {
              handle: handle.to_bytes(),
              block_hash: block.to_bytes(),
              expected_height: expected_height as u64,
              ignore_lock,
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

    let mut receipts: Vec<Receipt> = Vec::new();
    for job in jobs {
      let res = job.await;
      if let Ok((pk, res2)) = res {
        if let Ok(resp) = res2 {
          let AppendResp { receipt } = resp.into_inner();
          if let Ok(receipt_rs) = Receipt::from_bytes(&receipt) {
            receipts.push(receipt_rs);
          } else {
            eprintln!("initialize_state failed: invalid receipt");
            return Err(CoordinatorError::InvalidReceipt);
          }
        } else {
          let status = res2.unwrap_err();
          if status.code() != Code::FailedPrecondition {
            eprintln!("append_ledger failed: {:?}", status);
            return Err(CoordinatorError::FailedToAppendLedger);
          }
          loop {
            // This means an out-of-order append; let's retry.
            let res3 = self
              .retry_append_ledger(&pk, ledger_handle, block_hash, expected_height, ignore_lock)
              .await;
            if let Ok(resp) = res3 {
              let AppendResp { receipt } = resp.into_inner();
              if let Ok(receipt_rs) = Receipt::from_bytes(&receipt) {
                receipts.push(receipt_rs);
              } else {
                eprintln!("initialize_state failed: invalid receipt");
                return Err(CoordinatorError::InvalidReceipt);
              }
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
    let res = Receipt::merge_receipts(&receipts);
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

    let mut receipts: Vec<Receipt> = Vec::new();
    for job in jobs {
      let res = job.await;
      if let Ok((_pk, res2)) = res {
        if let Ok(resp) = res2 {
          let ReadLatestResp { receipt } = resp.into_inner();
          if let Ok(receipt_rs) = Receipt::from_bytes(&receipt) {
            receipts.push(receipt_rs);
          } else {
            eprintln!("initialize_state failed: invalid receipt");
            return Err(CoordinatorError::InvalidReceipt);
          }
        } else {
          eprintln!("read_ledger_tail failed: {:?}", res2.unwrap_err());
          return Err(CoordinatorError::FailedToReadLedger);
        }
      } else {
        eprintln!("read_ledger_tail failed: {:?}", res.unwrap_err());
        return Err(CoordinatorError::FailedToReadLedger);
      }
    }
    let res = Receipt::merge_receipts(&receipts);
    match res {
      Ok(receipt) => Ok(receipt),
      Err(_) => Err(CoordinatorError::EndorsersInDifferentViews),
    }
  }

  pub async fn append_view_ledger(
    &self,
    endorsers: &[Vec<u8>],
    block_hash: &NimbleDigest,
    expected_height: usize,
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
        let pk_bytes = pk.clone();
        let job = tokio::spawn(async move {
          let response = endorser_client
            .append_view_ledger(tonic::Request::new(AppendViewLedgerReq {
              block_hash: block.to_bytes(),
              expected_height: expected_height as u64,
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

    let mut receipts: Vec<Receipt> = Vec::new();
    for job in jobs {
      let res = job.await;
      if let Ok((_pk, res2)) = res {
        if let Ok(resp) = res2 {
          let AppendViewLedgerResp { receipt } = resp.into_inner();
          if let Ok(receipt_rs) = Receipt::from_bytes(&receipt) {
            receipts.push(receipt_rs);
          } else {
            eprintln!("initialize_state failed: invalid receipt");
            return Err(CoordinatorError::InvalidReceipt);
          }
        } else {
          eprintln!("append_view_ledger failed: {:?}", res2.unwrap_err());
          return Err(CoordinatorError::FailedToAppendViewLedger);
        }
      } else {
        eprintln!("append_view_ledger failed: {:?}", res.unwrap_err());
        return Err(CoordinatorError::FailedToAppendViewLedger);
      }
    }
    let res = Receipt::merge_receipts(&receipts);
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

    let mut receipts: Vec<Receipt> = Vec::new();
    for job in jobs {
      let res = job.await;
      if let Ok((_pk, res2)) = res {
        if let Ok(resp) = res2 {
          let ReadLatestViewLedgerResp { receipt } = resp.into_inner();
          if let Ok(receipt_rs) = Receipt::from_bytes(&receipt) {
            receipts.push(receipt_rs);
          } else {
            eprintln!("initialize_state failed: invalid receipt");
            return Err(CoordinatorError::InvalidReceipt);
          }
        } else {
          eprintln!("read_view_ledger_tail failed: {:?}", res2.unwrap_err());
          return Err(CoordinatorError::FailedToReadViewLedger);
        }
      } else {
        eprintln!("read_view_ledger_tail failed: {:?}", res.unwrap_err());
        return Err(CoordinatorError::FailedToReadViewLedger);
      }
    }
    let res = Receipt::merge_receipts(&receipts);
    match res {
      Ok(receipt) => Ok(receipt),
      Err(_) => Err(CoordinatorError::EndorsersInDifferentViews),
    }
  }

  pub async fn read_latest_state(
    &self,
    endorsers: &[Vec<u8>],
    to_lock: bool,
  ) -> Result<Vec<(PublicKey, LedgerView)>, CoordinatorError> {
    let mut jobs = Vec::new();
    if let Ok(conn_map) = self.store.read() {
      for pk in endorsers {
        if !conn_map.contains_key(pk) {
          eprintln!("No endorser has this public key {:?}", pk);
          return Err(CoordinatorError::InvalidEndorserPublicKey);
        }
        let mut endorser_client = conn_map[pk].clone();
        let pk_bytes = pk.clone();
        let job = tokio::spawn(async move {
          let response = endorser_client
            .read_latest_state(tonic::Request::new(ReadLatestStateReq { to_lock }))
            .await;
          (pk_bytes, response)
        });
        jobs.push(job);
      }
    } else {
      eprintln!("Failed to acquire the read lock");
      return Err(CoordinatorError::FailedToAcquireReadLock);
    }

    let mut ledger_views = Vec::new();
    for job in jobs {
      let res = job.await;
      if let Ok((pk, res2)) = res {
        if let Ok(resp) = res2 {
          let ReadLatestStateResp {
            ledger_tail_map,
            view_tail_metablock,
          } = resp.into_inner();
          let ledger_tail_map_rs: HashMap<NimbleDigest, MetaBlock> = ledger_tail_map
            .into_iter()
            .map(|e| {
              (
                NimbleDigest::from_bytes(&e.handle).unwrap(),
                MetaBlock::from_bytes(&e.metablock).unwrap(),
              )
            })
            .collect();
          let ledger_view = LedgerView {
            view_tail_metablock: MetaBlock::from_bytes(&view_tail_metablock).unwrap(),
            ledger_tail_map: ledger_tail_map_rs,
          };
          ledger_views.push((PublicKey::from_bytes(&pk).unwrap(), ledger_view));
        } else {
          eprintln!("read_latest_state failed: res2={:?}", res2.unwrap_err());
          return Err(CoordinatorError::FailedToReadLatestState);
        }
      } else {
        eprintln!("read_latest_state failed: res={:?}", res.unwrap_err());
        return Err(CoordinatorError::FailedToReadLatestState);
      }
    }
    Ok(ledger_views)
  }

  pub async fn unlock_endorsers(&self, endorsers: &[Vec<u8>]) -> Result<(), CoordinatorError> {
    let mut jobs = Vec::new();
    if let Ok(conn_map) = self.store.read() {
      for pk in endorsers {
        if !conn_map.contains_key(pk) {
          eprintln!("No endorser has this public key {:?}", pk);
          return Err(CoordinatorError::InvalidEndorserPublicKey);
        }
        let mut endorser_client = conn_map[pk].clone();
        let job = tokio::spawn(async move {
          let response = endorser_client
            .unlock(tonic::Request::new(UnlockReq {}))
            .await;
          response
        });
        jobs.push(job);
      }
    } else {
      eprintln!("Failed to acquire the read lock");
      return Err(CoordinatorError::FailedToAcquireReadLock);
    }

    for job in jobs {
      let res = job.await;
      if let Ok(res2) = res {
        if let Err(error) = res2 {
          eprintln!("unlock_endorsers failed: res2={:?}", error);
          return Err(CoordinatorError::FailedToUnlock);
        }
      } else {
        eprintln!("unlock_endorsers failed: res={:?}", res.unwrap_err());
        return Err(CoordinatorError::FailedToUnlock);
      }
    }
    Ok(())
  }
}
