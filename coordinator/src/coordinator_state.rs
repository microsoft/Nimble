use crate::errors::CoordinatorError;
use ledger::{
  compute_aggregated_block_hash, compute_max_cut,
  signature::{PublicKey, PublicKeyTrait},
  Block, CustomSerde, EndorserHostnames, Handle, LedgerTailMap, MetaBlock, NimbleDigest,
  NimbleHashTrait, Nonce, Receipt, Receipts, VerifierState,
};
use std::{
  collections::HashMap,
  convert::TryInto,
  sync::{Arc, RwLock},
};
use store::ledger::{
  azure_table::TableLedgerStore, filestore::FileStore, in_memory::InMemoryLedgerStore,
  mongodb_cosmos::MongoCosmosLedgerStore, LedgerEntry, LedgerStore,
};
use store::{errors::LedgerStoreError, errors::StorageError};
use tokio::sync::mpsc;
use tonic::{
  transport::{Channel, Endpoint},
  Code, Status,
};

#[allow(clippy::derive_partial_eq_without_eq)]
pub mod endorser_proto {
  tonic::include_proto!("endorser_proto");
}

use endorser_proto::endorser_call_client::EndorserCallClient;

type EndorserConnMap = HashMap<Vec<u8>, (EndorserCallClient<Channel>, String)>;

type LedgerStoreRef = Arc<Box<dyn LedgerStore + Send + Sync>>;

pub struct CoordinatorState {
  ledger_store: LedgerStoreRef,
  conn_map: Arc<RwLock<EndorserConnMap>>,
  verifier_state: Arc<RwLock<VerifierState>>,
}

const ENDORSER_MPSC_CHANNEL_BUFFER: usize = 8; // limited by the number of endorsers
const ENDORSER_CONNECT_TIMEOUT: u64 = 10; // seconds: the connect timeout to endorsres
const ENDORSER_REQUEST_TIMEOUT: u64 = 10; // seconds: the request timeout to endorsers

async fn update_endorser(
  ledger_store: LedgerStoreRef,
  mut endorser_client: EndorserCallClient<Channel>,
  handle: NimbleDigest,
  start: usize,
  end: usize,
) -> Result<(), Status> {
  for idx in start..=end {
    let ledger_entry = {
      let res = ledger_store.read_ledger_by_index(&handle, idx).await;
      if res.is_err() {
        eprintln!("Failed to read ledger by index {:?}", res);
        return Err(Status::aborted("Failed to read ledger by index"));
      }
      res.unwrap()
    };

    let receipt = if idx == 0 {
      let endorser_proto::NewLedgerResp { receipt } = endorser_client
        .new_ledger(tonic::Request::new(endorser_proto::NewLedgerReq {
          handle: handle.to_bytes(),
          block_hash: compute_aggregated_block_hash(
            &ledger_entry.get_block().hash().to_bytes(),
            &ledger_entry.get_nonces().hash().to_bytes(),
          )
          .to_bytes(),
        }))
        .await?
        .into_inner();

      receipt
    } else {
      let endorser_proto::AppendResp { receipt } = endorser_client
        .append(tonic::Request::new(endorser_proto::AppendReq {
          handle: handle.to_bytes(),
          block_hash: compute_aggregated_block_hash(
            &ledger_entry.get_block().hash().to_bytes(),
            &ledger_entry.get_nonces().hash().to_bytes(),
          )
          .to_bytes(),
          expected_height: idx as u64,
        }))
        .await?
        .into_inner();

      receipt
    };

    let res = Receipt::from_bytes(&receipt);
    if res.is_ok() {
      let receipt_rs = res.unwrap();
      let mut receipts = Receipts::new();
      receipts.add(&receipt_rs);
      let res = ledger_store
        .attach_ledger_receipts(&handle, idx, &receipts)
        .await;
      if res.is_err() {
        eprintln!(
          "Failed to attach ledger receipt to the ledger store ({:?})",
          res
        );
      }
    } else {
      eprintln!("Failed to parse a receipt ({:?})", res);
    }
  }

  Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CoordinatorAction {
  DoNothing,
  IncrementReceipt,
  UpdateEndorser,
  RemoveEndorser,
}

fn process_error(
  endorser: &str,
  handle: Option<&NimbleDigest>,
  status: &Status,
) -> CoordinatorAction {
  match status.code() {
    Code::Aborted => {
      eprintln!("operation aborted to due to ledger store");
      CoordinatorAction::DoNothing
    },
    Code::AlreadyExists => {
      if let Some(h) = handle {
        eprintln!("ledger {:?} already exists in endorser {}", h, endorser);
      } else {
        eprintln!(
          "the requested operation was already done in endorser {}",
          endorser
        );
      }
      CoordinatorAction::IncrementReceipt
    },
    Code::Cancelled => {
      eprintln!("endorser {} is locked", endorser);
      CoordinatorAction::DoNothing
    },
    Code::FailedPrecondition | Code::NotFound => {
      if let Some(h) = handle {
        eprintln!("ledger {:?} lags behind in endorser {}", h, endorser);
      } else {
        eprintln!("a ledger lags behind in endorser {}", endorser);
      }
      CoordinatorAction::UpdateEndorser
    },
    Code::InvalidArgument => {
      if let Some(h) = handle {
        eprintln!(
          "the requested height for ledger {:?} in endorser {} is too small",
          h, endorser
        );
      } else {
        eprintln!(
          "the requested height for a ledger in endorser {} is too small",
          endorser
        );
      }
      CoordinatorAction::DoNothing
    },
    Code::OutOfRange => {
      if let Some(h) = handle {
        eprintln!(
          "the requested height for ledger {:?} in endorser {} is out of range",
          h, endorser
        );
      } else {
        eprintln!(
          "the requested height for a ledger in endorser {} is out of range",
          endorser
        );
      }
      CoordinatorAction::DoNothing
    },

    Code::Unavailable => {
      eprintln!("the endorser is already finalized");
      CoordinatorAction::DoNothing
    },
    Code::Unimplemented => {
      eprintln!("the endorser is not initialized");
      CoordinatorAction::DoNothing
    },
    Code::Internal | Code::Unknown | Code::ResourceExhausted => CoordinatorAction::RemoveEndorser,
    _ => {
      eprintln!("Unhandled status={:?}", status);
      CoordinatorAction::DoNothing
    },
  }
}

impl CoordinatorState {
  pub async fn new(
    ledger_store_type: &str,
    args: &HashMap<String, String>,
  ) -> Result<CoordinatorState, CoordinatorError> {
    let coordinator = match ledger_store_type {
      "mongodb_cosmos" => CoordinatorState {
        ledger_store: Arc::new(Box::new(MongoCosmosLedgerStore::new(args).await.unwrap())),
        conn_map: Arc::new(RwLock::new(HashMap::new())),
        verifier_state: Arc::new(RwLock::new(VerifierState::new())),
      },
      "table" => CoordinatorState {
        ledger_store: Arc::new(Box::new(TableLedgerStore::new(args).await.unwrap())),
        conn_map: Arc::new(RwLock::new(HashMap::new())),
        verifier_state: Arc::new(RwLock::new(VerifierState::new())),
      },
      "filestore" => CoordinatorState {
        ledger_store: Arc::new(Box::new(FileStore::new(args).await.unwrap())),
        conn_map: Arc::new(RwLock::new(HashMap::new())),
        verifier_state: Arc::new(RwLock::new(VerifierState::new())),
      },
      _ => CoordinatorState {
        ledger_store: Arc::new(Box::new(InMemoryLedgerStore::new())),
        conn_map: Arc::new(RwLock::new(HashMap::new())),
        verifier_state: Arc::new(RwLock::new(VerifierState::new())),
      },
    };

    let res = coordinator.ledger_store.read_view_ledger_tail().await;
    if res.is_err() {
      eprintln!("Failed to read the view ledger tail {:?}", res);
      return Err(CoordinatorError::FailedToReadViewLedger);
    }

    let (view_ledger_tail, tail_height) = res.unwrap();

    for idx in 1..=tail_height {
      let res = coordinator
        .ledger_store
        .read_view_ledger_by_index(idx)
        .await;
      if res.is_err() {
        eprintln!(
          "Failed to read the view ledger entry at index {} ({:?})",
          idx, res
        );
        return Err(CoordinatorError::FailedToReadViewLedger);
      }
      let view_ledger_entry = res.unwrap();
      if let Ok(mut vs) = coordinator.verifier_state.write() {
        let res = vs.apply_view_change(
          &view_ledger_entry.get_block().to_bytes(),
          &view_ledger_entry.get_receipts().to_bytes(),
        );
        if res.is_err() {
          eprintln!("Failed to apply view change at index {} ({:?})", idx, res);
          return Err(CoordinatorError::FailedToVerifyViewChange);
        }
      } else {
        return Err(CoordinatorError::FailedToAcquireWriteLock);
      }
    }

    if tail_height > 0 {
      let res = bincode::deserialize(&view_ledger_tail.get_block().to_bytes());
      if res.is_err() {
        eprintln!(
          "Failed to deserialize the view ledger tail's genesis block {:?}",
          res
        );
        return Err(CoordinatorError::FailedToSerde);
      }
      let endorser_hostnames: EndorserHostnames = res.unwrap();

      let hostnames = (0..endorser_hostnames.len())
        .map(|i| endorser_hostnames[i].1.clone())
        .collect::<Vec<String>>();

      println!("endorsers in the latest view: {:?}", hostnames);

      let pks = coordinator.connect_endorsers(&hostnames).await;

      // Remove endorsers that don't have the latest view
      let res = coordinator.filter_endorsers(&pks, tail_height).await;
      if let Err(error) = res {
        eprintln!(
          "Failed to filter the endorsers with the latest view {:?}",
          error
        );
        return Err(error);
      }
    }
    Ok(coordinator)
  }

  fn get_endorser_client(&self, pk: &[u8]) -> Option<(EndorserCallClient<Channel>, String)> {
    if let Ok(conn_map_rd) = self.conn_map.read() {
      if !conn_map_rd.contains_key(pk) {
        eprintln!("No endorser has this public key {:?}", pk);
        None
      } else {
        Some((conn_map_rd[pk].0.clone(), conn_map_rd[pk].1.clone()))
      }
    } else {
      eprintln!("Failed to acquire read lock");
      None
    }
  }

  pub fn get_endorser_pks(&self) -> Vec<Vec<u8>> {
    if let Ok(conn_map_rd) = self.conn_map.read() {
      conn_map_rd
        .iter()
        .map(|(pk, (_ec, _hostname))| pk.clone())
        .collect::<Vec<Vec<u8>>>()
    } else {
      eprintln!("Failed to acquire read lock");
      Vec::new()
    }
  }

  pub fn get_endorser_uris(&self) -> Vec<String> {
    if let Ok(conn_map_rd) = self.conn_map.read() {
      conn_map_rd
        .iter()
        .map(|(_pk, (_ec, hostname))| hostname.clone())
        .collect::<Vec<String>>()
    } else {
      eprintln!("Failed to acquire read lock");
      Vec::new()
    }
  }

  fn get_endorser_hostnames(&self) -> EndorserHostnames {
    if let Ok(conn_map_rd) = self.conn_map.read() {
      conn_map_rd
        .iter()
        .map(|(pk, (_ec, hostname))| (pk.clone(), hostname.clone()))
        .collect::<Vec<(Vec<u8>, String)>>()
    } else {
      eprintln!("Failed to acquire read lock");
      Vec::new()
    }
  }

  pub fn get_endorser_pk(&self, hostname: &str) -> Option<Vec<u8>> {
    if let Ok(conn_map_rd) = self.conn_map.read() {
      for (pk, (_client, uri)) in conn_map_rd.iter() {
        if uri == hostname {
          return Some(pk.clone());
        }
      }
    }
    None
  }

  async fn connect_endorsers(&self, hostnames: &[String]) -> EndorserHostnames {
    let (mpsc_tx, mut mpsc_rx) = mpsc::channel(ENDORSER_MPSC_CHANNEL_BUFFER);
    for hostname in hostnames {
      let tx = mpsc_tx.clone();
      let endorser = hostname.clone();

      let _job = tokio::spawn(async move {
        let res = Endpoint::from_shared(endorser.to_string());
        if let Ok(endorser_endpoint) = res {
          let endorser_endpoint = endorser_endpoint
            .connect_timeout(std::time::Duration::from_secs(ENDORSER_CONNECT_TIMEOUT));
          let endorser_endpoint =
            endorser_endpoint.timeout(std::time::Duration::from_secs(ENDORSER_REQUEST_TIMEOUT));
          let res = endorser_endpoint.connect().await;
          if let Ok(channel) = res {
            let mut client = EndorserCallClient::new(channel);

            let req = tonic::Request::new(endorser_proto::GetPublicKeyReq {});
            let res = client.get_public_key(req).await;
            if let Ok(resp) = res {
              let endorser_proto::GetPublicKeyResp { pk } = resp.into_inner();
              let _ = tx.send((endorser, Ok((client, pk)))).await;
            } else {
              eprintln!("Failed to retrieve the public key: {:?}", res);
              let _ = tx
                .send((endorser, Err(CoordinatorError::UnableToRetrievePublicKey)))
                .await;
            }
          } else {
            eprintln!("Failed to connect to the endorser {}: {:?}", endorser, res);
            let _ = tx
              .send((endorser, Err(CoordinatorError::FailedToConnectToEndorser)))
              .await;
          }
        } else {
          eprintln!("Failed to resolve the endorser host name: {:?}", res);
          let _ = tx
            .send((endorser, Err(CoordinatorError::CannotResolveHostName)))
            .await;
        }
      });
    }

    drop(mpsc_tx);

    let mut endorser_hostnames = EndorserHostnames::new();
    while let Some((endorser, res)) = mpsc_rx.recv().await {
      if let Ok((client, pk)) = res {
        if PublicKey::from_bytes(&pk).is_err() {
          eprintln!("Public key is invalid from endorser {:?}", endorser);
          continue;
        }
        if let Ok(mut conn_map_wr) = self.conn_map.write() {
          conn_map_wr.entry(pk.clone()).or_insert_with(|| {
            endorser_hostnames.push((pk, endorser.clone()));
            (client, endorser)
          });
        } else {
          eprintln!("Failed to acquire the write lock");
        }
      }
    }

    endorser_hostnames
  }

  pub async fn disconnect_endorsers(&self, endorsers: &EndorserHostnames) {
    if let Ok(mut conn_map_wr) = self.conn_map.write() {
      for (pk, uri) in endorsers {
        let res = conn_map_wr.remove_entry(pk);
        if let Some((_pk, (client, _uri))) = res {
          drop(client);
          eprintln!("Removed endorser {}", uri);
        } else {
          eprintln!("Failed to find the endorser to disconnect {}", uri);
        }
      }
    } else {
      eprintln!("Failed to acquire the write lock");
    }
  }

  async fn filter_endorsers(
    &self,
    endorsers: &EndorserHostnames,
    view_ledger_height: usize,
  ) -> Result<(), CoordinatorError> {
    let (mpsc_tx, mut mpsc_rx) = mpsc::channel(ENDORSER_MPSC_CHANNEL_BUFFER);
    for (pk, _uri) in endorsers {
      let (mut endorser_client, endorser) = match self.get_endorser_client(pk) {
        Some((client, endorser)) => (client, endorser),
        None => continue,
      };

      let tx = mpsc_tx.clone();
      let pk_bytes = pk.clone();
      let _job = tokio::spawn(async move {
        let res = endorser_client
          .read_state(tonic::Request::new(endorser_proto::ReadStateReq {}))
          .await;
        let _ = tx.send((endorser, pk_bytes, res)).await;
      });
    }

    drop(mpsc_tx);

    while let Some((endorser, pk_bytes, res)) = mpsc_rx.recv().await {
      let mut to_keep = false;
      match res {
        Ok(resp) => {
          let endorser_proto::ReadStateResp { receipt, .. } = resp.into_inner();
          let res = Receipt::from_bytes(&receipt);
          match res {
            Ok(receipt_rs) => {
              if receipt_rs.get_height() == view_ledger_height {
                to_keep = true;
              } else {
                eprintln!(
                  "expected view ledger height={}, endorser's view ledger height={}",
                  view_ledger_height,
                  receipt_rs.get_height(),
                );
              }
            },
            Err(error) => {
              eprintln!("Failed to parse the metablock {:?}", error);
            },
          }
        },
        Err(status) => {
          eprintln!("Failed to get the view tail metablock {:?}", status);
          if CoordinatorAction::RemoveEndorser != process_error(&endorser, None, &status) {
            to_keep = true;
          }
        },
      }
      if !to_keep {
        self.disconnect_endorsers(&vec![(pk_bytes, endorser)]).await;
      }
    }

    Ok(())
  }

  async fn endorser_initialize_state(
    &self,
    endorsers: &EndorserHostnames,
    ledger_tail_map: &LedgerTailMap,
    view_tail_metablock: &MetaBlock,
    block_hash: &NimbleDigest,
    expected_height: usize,
  ) -> Result<Receipts, CoordinatorError> {
    let ledger_tail_map_proto: Vec<endorser_proto::LedgerTailMapEntry> = ledger_tail_map
      .iter()
      .map(|(handle, metablock)| endorser_proto::LedgerTailMapEntry {
        handle: handle.to_bytes(),
        metablock: metablock.to_bytes(),
      })
      .collect();

    let (mpsc_tx, mut mpsc_rx) = mpsc::channel(ENDORSER_MPSC_CHANNEL_BUFFER);
    for (pk, _uri) in endorsers {
      let (mut endorser_client, endorser) = match self.get_endorser_client(pk) {
        Some((client, endorser)) => (client, endorser),
        None => continue,
      };

      let tx = mpsc_tx.clone();
      let ledger_tail_map_copy = ledger_tail_map_proto.clone();
      let view_tail_metablock_bytes = view_tail_metablock.to_bytes().to_vec();
      let block_hash_copy = block_hash.to_bytes();
      let pk_bytes = pk.clone();
      let _job = tokio::spawn(async move {
        let res = endorser_client
          .initialize_state(tonic::Request::new(endorser_proto::InitializeStateReq {
            ledger_tail_map: ledger_tail_map_copy,
            view_tail_metablock: view_tail_metablock_bytes,
            block_hash: block_hash_copy,
            expected_height: expected_height as u64,
          }))
          .await;
        let _ = tx.send((endorser, pk_bytes, res)).await;
      });
    }

    drop(mpsc_tx);

    let mut receipts = Receipts::new();
    while let Some((endorser, pk_bytes, res)) = mpsc_rx.recv().await {
      match res {
        Ok(resp) => {
          let endorser_proto::InitializeStateResp { receipt } = resp.into_inner();
          let res = Receipt::from_bytes(&receipt);
          match res {
            Ok(receipt_rs) => receipts.add(&receipt_rs),
            Err(error) => eprintln!("Failed to parse a receipt ({:?})", error),
          }
        },
        Err(status) => {
          eprintln!(
            "Failed to initialize the state of endorser {} (status={:?})",
            endorser, status
          );
          if let CoordinatorAction::RemoveEndorser = process_error(&endorser, None, &status) {
            eprintln!(
              "initialize_state from endorser {} received unexpected error {:?}",
              endorser, status
            );
            self.disconnect_endorsers(&vec![(pk_bytes, endorser)]).await;
          }
        },
      }
    }

    Ok(receipts)
  }

  async fn endorser_create_ledger(
    &self,
    endorsers: &[Vec<u8>],
    ledger_handle: &Handle,
    ledger_block_hash: &NimbleDigest,
  ) -> Result<Receipts, CoordinatorError> {
    let (mpsc_tx, mut mpsc_rx) = mpsc::channel(ENDORSER_MPSC_CHANNEL_BUFFER);
    for pk in endorsers {
      let (mut endorser_client, endorser) = match self.get_endorser_client(pk) {
        Some((client, endorser)) => (client, endorser),
        None => continue,
      };

      let tx = mpsc_tx.clone();
      let handle = *ledger_handle;
      let block_hash = *ledger_block_hash;
      let pk_bytes = pk.clone();
      let _job = tokio::spawn(async move {
        let res = endorser_client
          .new_ledger(tonic::Request::new(endorser_proto::NewLedgerReq {
            handle: handle.to_bytes(),
            block_hash: block_hash.to_bytes(),
          }))
          .await;
        let _ = tx.send((endorser, pk_bytes, res)).await;
      });
    }

    drop(mpsc_tx);

    let mut receipts = Receipts::new();
    while let Some((endorser, pk_bytes, res)) = mpsc_rx.recv().await {
      match res {
        Ok(resp) => {
          let endorser_proto::NewLedgerResp { receipt } = resp.into_inner();
          let res = Receipt::from_bytes(&receipt);
          match res {
            Ok(receipt_rs) => {
              receipts.add(&receipt_rs);
              if let Ok(vs) = self.verifier_state.read() {
                if receipts.check_quorum(&vs).is_ok() {
                  return Ok(receipts);
                }
              }
            },
            Err(error) => eprintln!("Failed to parse a receipt ({:?})", error),
          }
        },
        Err(status) => {
          eprintln!(
            "Failed to create a ledger {:?} in endorser {} (status={:?})",
            ledger_handle, endorser, status
          );
          if process_error(&endorser, Some(ledger_handle), &status)
            == CoordinatorAction::RemoveEndorser
          {
            eprintln!(
              "create_ledger from endorser {} received unexpected error {:?}",
              endorser, status
            );
            self.disconnect_endorsers(&vec![(pk_bytes, endorser)]).await;
          }
        },
      }
    }

    Ok(receipts)
  }

  pub async fn endorser_append_ledger(
    &self,
    endorsers: &[Vec<u8>],
    ledger_handle: &Handle,
    block_hash: &NimbleDigest,
    expected_height: usize,
  ) -> Result<Receipts, CoordinatorError> {
    let (mpsc_tx, mut mpsc_rx) = mpsc::channel(ENDORSER_MPSC_CHANNEL_BUFFER);

    for pk in endorsers {
      let (mut endorser_client, endorser) = match self.get_endorser_client(pk) {
        Some((client, endorser)) => (client, endorser),
        None => continue,
      };

      let tx = mpsc_tx.clone();
      let handle = *ledger_handle;
      let block = *block_hash;
      let pk_bytes = pk.clone();
      let ledger_store = self.ledger_store.clone();
      let _job = tokio::spawn(async move {
        loop {
          let res = endorser_client
            .append(tonic::Request::new(endorser_proto::AppendReq {
              handle: handle.to_bytes(),
              block_hash: block.to_bytes(),
              expected_height: expected_height as u64,
            }))
            .await;
          match res {
            Ok(resp) => {
              let endorser_proto::AppendResp { receipt } = resp.into_inner();
              let _ = tx.send((endorser, pk_bytes, Ok(receipt))).await;
              break;
            },
            Err(status) => match process_error(&endorser, Some(&handle), &status) {
              CoordinatorAction::UpdateEndorser => {
                let height_to_start = {
                  if status.code() == Code::NotFound {
                    0
                  } else {
                    let bytes = status.details();
                    let ledger_height = u64::from_le_bytes(bytes[0..].try_into().unwrap()) as usize;
                    ledger_height.checked_add(1).unwrap()
                  }
                };
                let height_to_end = expected_height - 1;
                let res = update_endorser(
                  ledger_store.clone(),
                  endorser_client.clone(),
                  handle,
                  height_to_start,
                  height_to_end,
                )
                .await;
                match res {
                  Ok(_resp) => {
                    continue;
                  },
                  Err(status) => match process_error(&endorser, Some(&handle), &status) {
                    CoordinatorAction::RemoveEndorser => {
                      let _ = tx
                        .send((endorser, pk_bytes, Err(CoordinatorError::UnexpectedError)))
                        .await;
                      break;
                    },
                    CoordinatorAction::IncrementReceipt => {
                      continue;
                    },
                    _ => {
                      let _ = tx
                        .send((
                          endorser,
                          pk_bytes,
                          Err(CoordinatorError::FailedToAppendLedger),
                        ))
                        .await;
                      break;
                    },
                  },
                }
              },
              CoordinatorAction::RemoveEndorser => {
                let _ = tx
                  .send((endorser, pk_bytes, Err(CoordinatorError::UnexpectedError)))
                  .await;
                break;
              },
              CoordinatorAction::IncrementReceipt => {
                let _ = tx
                  .send((
                    endorser,
                    pk_bytes,
                    Err(CoordinatorError::LedgerAlreadyExists),
                  ))
                  .await;
                break;
              },
              _ => {
                let _ = tx
                  .send((
                    endorser,
                    pk_bytes,
                    Err(CoordinatorError::FailedToAppendLedger),
                  ))
                  .await;
                break;
              },
            },
          }
        }
      });
    }

    drop(mpsc_tx);

    let mut receipts = Receipts::new();
    while let Some((endorser, pk_bytes, res)) = mpsc_rx.recv().await {
      match res {
        Ok(receipt) => match Receipt::from_bytes(&receipt) {
          Ok(receipt_rs) => {
            receipts.add(&receipt_rs);
            if let Ok(vs) = self.verifier_state.read() {
              if receipts.check_quorum(&vs).is_ok() {
                return Ok(receipts);
              }
            }
          },
          Err(error) => {
            eprintln!("Failed to parse a receipt (err={:?}", error);
          },
        },
        Err(error) => {
          if error == CoordinatorError::UnexpectedError {
            eprintln!(
              "append_ledger from endorser {} received unexpected error {:?}",
              endorser, error
            );
            self.disconnect_endorsers(&vec![(pk_bytes, endorser)]).await;
          }
        },
      }
    }

    Ok(receipts)
  }

  async fn endorser_update_ledger(
    &self,
    endorsers: &[Vec<u8>],
    ledger_handle: &Handle,
    max_height: usize,
    endorser_height_map: &HashMap<String, usize>,
  ) {
    let (mpsc_tx, mut mpsc_rx) = mpsc::channel(ENDORSER_MPSC_CHANNEL_BUFFER);

    for pk in endorsers {
      let (endorser_client, endorser) = match self.get_endorser_client(pk) {
        Some((client, endorser)) => (client, endorser),
        None => continue,
      };

      let height_to_start = {
        if !endorser_height_map.contains_key(&endorser) {
          0
        } else {
          endorser_height_map[&endorser].checked_add(1).unwrap()
        }
      };

      if height_to_start > max_height {
        continue;
      }

      let ledger_store = self.ledger_store.clone();
      let handle = *ledger_handle;
      let pk_bytes = pk.clone();
      let tx = mpsc_tx.clone();
      let _job = tokio::spawn(async move {
        let res = update_endorser(
          ledger_store,
          endorser_client,
          handle,
          height_to_start,
          max_height,
        )
        .await;
        let _ = tx.send((endorser, pk_bytes, res)).await;
      });
    }

    drop(mpsc_tx);

    while let Some((endorser, pk_bytes, res)) = mpsc_rx.recv().await {
      match res {
        Ok(()) => {},
        Err(status) => {
          if process_error(&endorser, Some(ledger_handle), &status)
            == CoordinatorAction::RemoveEndorser
          {
            eprintln!(
              "update_endorser {} received unexpected error {:?}",
              endorser, status,
            );
            self.disconnect_endorsers(&vec![(pk_bytes, endorser)]).await;
          }
        },
      }
    }
  }

  async fn endorser_read_ledger_tail(
    &self,
    endorsers: &[Vec<u8>],
    ledger_handle: &Handle,
    client_nonce: &Nonce,
  ) -> Result<(Receipts, usize), CoordinatorError> {
    let (mpsc_tx, mut mpsc_rx) = mpsc::channel(ENDORSER_MPSC_CHANNEL_BUFFER);

    for pk in endorsers {
      let (mut endorser_client, endorser) = match self.get_endorser_client(pk) {
        Some((client, endorser)) => (client, endorser),
        None => continue,
      };

      let tx = mpsc_tx.clone();
      let handle = *ledger_handle;
      let nonce = *client_nonce;
      let pk_bytes = pk.clone();
      let _job = tokio::spawn(async move {
        let res = endorser_client
          .read_latest(tonic::Request::new(endorser_proto::ReadLatestReq {
            handle: handle.to_bytes(),
            nonce: nonce.to_bytes(),
          }))
          .await;
        match res {
          Ok(resp) => {
            let endorser_proto::ReadLatestResp { receipt } = resp.into_inner();
            let _ = tx.send((endorser, pk_bytes, Ok(receipt))).await;
          },
          Err(status) => match process_error(&endorser, Some(&handle), &status) {
            CoordinatorAction::RemoveEndorser => {
              let _ = tx
                .send((endorser, pk_bytes, Err(CoordinatorError::UnexpectedError)))
                .await;
            },
            _ => {
              let _ = tx
                .send((
                  endorser,
                  pk_bytes,
                  Err(CoordinatorError::FailedToReadLedger),
                ))
                .await;
            },
          },
        }
      });
    }

    drop(mpsc_tx);

    let mut receipts = Receipts::new();
    let mut endorser_height_map: HashMap<String, usize> = HashMap::new();
    let mut max_height = 0;

    while let Some((endorser, pk_bytes, res)) = mpsc_rx.recv().await {
      match res {
        Ok(receipt) => match Receipt::from_bytes(&receipt) {
          Ok(receipt_rs) => {
            endorser_height_map.insert(endorser, receipt_rs.get_height());
            if max_height < receipt_rs.get_height() {
              max_height = receipt_rs.get_height();
            }
            receipts.add(&receipt_rs);
            if let Ok(vs) = self.verifier_state.read() {
              if let Ok(h) = receipts.check_quorum(&vs) {
                return Ok((receipts, h));
              }
            }
          },
          Err(error) => {
            eprintln!("Failed to parse a receipt (err={:?}", error);
          },
        },
        Err(error) => {
          if error == CoordinatorError::UnexpectedError {
            eprintln!(
              "read_ledger from endorser {} received unexpected error {:?}",
              endorser, error
            );
            self.disconnect_endorsers(&vec![(pk_bytes, endorser)]).await;
          }
        },
      }
    }

    // Since we didn't reach a quorum, let's have endorsers catch up
    self
      .endorser_update_ledger(endorsers, ledger_handle, max_height, &endorser_height_map)
      .await;

    Err(CoordinatorError::FailedToObtainQuorum)
  }

  async fn endorser_finalize_state(
    &self,
    endorsers: &EndorserHostnames,
    block_hash: &NimbleDigest,
    expected_height: usize,
  ) -> Result<(Receipts, HashMap<NimbleDigest, LedgerTailMap>), CoordinatorError> {
    let (mpsc_tx, mut mpsc_rx) = mpsc::channel(ENDORSER_MPSC_CHANNEL_BUFFER);

    for (pk, _uri) in endorsers {
      let (mut endorser_client, endorser) = match self.get_endorser_client(pk) {
        Some((client, endorser)) => (client, endorser),
        None => continue,
      };

      let tx = mpsc_tx.clone();
      let block = *block_hash;
      let pk_bytes = pk.clone();
      let _job = tokio::spawn(async move {
        let res = endorser_client
          .finalize_state(tonic::Request::new(endorser_proto::FinalizeStateReq {
            block_hash: block.to_bytes(),
            expected_height: expected_height as u64,
          }))
          .await;
        let _ = tx.send((endorser, pk_bytes, res)).await;
      });
    }

    drop(mpsc_tx);

    let mut receipts = Receipts::new();
    let mut ledger_tail_maps = HashMap::new();

    while let Some((endorser, pk_bytes, res)) = mpsc_rx.recv().await {
      match res {
        Ok(resp) => {
          let endorser_proto::FinalizeStateResp {
            receipt,
            ledger_tail_map,
          } = resp.into_inner();
          let res = Receipt::from_bytes(&receipt);
          let receipt_rs = match res {
            Ok(receipt_rs) => {
              receipts.add(&receipt_rs);
              receipt_rs
            },
            Err(error) => {
              eprintln!("Failed to parse a receipt ({:?})", error);
              continue;
            },
          };
          let ledger_tail_map_rs: HashMap<NimbleDigest, MetaBlock> = ledger_tail_map
            .into_iter()
            .map(|e| {
              (
                NimbleDigest::from_bytes(&e.handle).unwrap(),
                MetaBlock::from_bytes(&e.metablock).unwrap(),
              )
            })
            .collect();
          if !ledger_tail_maps.contains_key(receipt_rs.get_view()) {
            ledger_tail_maps.insert(*receipt_rs.get_view(), ledger_tail_map_rs);
          }
        },
        Err(status) => {
          eprintln!(
            "Failed to append view ledger to endorser {} (status={:?})",
            endorser, status
          );
          if let CoordinatorAction::RemoveEndorser = process_error(&endorser, None, &status) {
            self.disconnect_endorsers(&vec![(pk_bytes, endorser)]).await;
          }
        },
      }
    }

    Ok((receipts, ledger_tail_maps))
  }

  pub async fn replace_endorsers(&self, hostnames: &[String]) -> Result<(), CoordinatorError> {
    let existing_endorsers = self.get_endorser_hostnames();

    // Connect to new endorsers
    let new_endorsers = self.connect_endorsers(hostnames).await;
    if new_endorsers.is_empty() {
      return Err(CoordinatorError::NoNewEndorsers);
    }

    // Package the list of endorsers into a genesis block of the view ledger
    let view_ledger_genesis_block = {
      let res = bincode::serialize(&new_endorsers);
      if res.is_err() {
        eprintln!("Failed to serialize endorser hostnames {:?}", res);
        return Err(CoordinatorError::FailedToSerde);
      }
      let block_vec = res.unwrap();
      Block::new(&block_vec)
    };

    // Read the current ledger tail
    let res = self.ledger_store.read_view_ledger_tail().await;

    if res.is_err() {
      eprintln!(
        "Failed to read from the view ledger in the ledger store ({:?})",
        res.unwrap_err()
      );
      return Err(CoordinatorError::FailedToCallLedgerStore);
    }

    let (tail, height) = res.unwrap();

    // Store the genesis block of the view ledger in the ledger store
    let res = self
      .ledger_store
      .append_view_ledger(&view_ledger_genesis_block, height + 1)
      .await;
    if let Err(e) = res {
      eprintln!(
        "Failed to append to the view ledger in the ledger store ({:?})",
        e,
      );
      return Err(CoordinatorError::FailedToCallLedgerStore);
    }

    let view_ledger_height = res.unwrap();

    let (finalize_receipts, ledger_tail_maps) = if existing_endorsers.is_empty() {
      assert!(view_ledger_height == 1);

      (Receipts::new(), HashMap::new())
    } else {
      let res = self
        .endorser_finalize_state(
          &existing_endorsers,
          &view_ledger_genesis_block.hash(),
          view_ledger_height,
        )
        .await;
      if res.is_err() {
        eprintln!(
          "Failed to read the latest state of endorsers ({:?})",
          res.unwrap_err()
        );
        return Err(CoordinatorError::FailedToReadLatestState);
      }
      res.unwrap()
    };

    // Compute the max cut
    let max_cut = compute_max_cut(&ledger_tail_maps);

    // Retrieve the view tail metablock
    let view_tail_receipts = tail.get_receipts();
    let view_tail_metablock = if view_tail_receipts.is_empty() {
      if view_ledger_height != 1 {
        eprintln!("cannot get view tail metablock from empty receipts");
        return Err(CoordinatorError::UnexpectedError);
      } else {
        MetaBlock::default()
      }
    } else {
      let res = view_tail_receipts.get_metablock();
      match res {
        Ok(metablock) => metablock,
        Err(_e) => {
          eprintln!("faield to retrieve metablock from view receipts");
          return Err(CoordinatorError::UnexpectedError);
        },
      }
    };

    // Initialize new endorsers
    let res = self
      .endorser_initialize_state(
        &new_endorsers,
        &max_cut,
        &view_tail_metablock,
        &view_ledger_genesis_block.hash(),
        view_ledger_height,
      )
      .await;
    if res.is_err() {
      eprintln!(
        "Failed to initialize the endorser state ({:?})",
        res.unwrap_err()
      );
      return Err(CoordinatorError::FailedToInitializeEndorser);
    }
    let initialize_receipts = res.unwrap();

    // Store the receipts in the view ledger
    let mut receipts = Receipts::new();
    receipts.merge_receipts(&finalize_receipts);
    receipts.merge_receipts(&initialize_receipts);
    let res = self
      .ledger_store
      .attach_view_ledger_receipts(view_ledger_height, &receipts)
      .await;
    if res.is_err() {
      eprintln!(
        "Failed to attach view ledger receipt in the ledger store ({:?})",
        res.unwrap_err()
      );
      return Err(CoordinatorError::FailedToCallLedgerStore);
    }

    // Apply view change to the verifier state
    if let Ok(mut vs) = self.verifier_state.write() {
      if let Err(e) =
        vs.apply_view_change(&view_ledger_genesis_block.to_bytes(), &receipts.to_bytes())
      {
        eprintln!("Failed to apply view change: {:?}", e);
      }
    } else {
      return Err(CoordinatorError::FailedToAcquireWriteLock);
    }

    // Disconnect existing endorsers
    self.disconnect_endorsers(&existing_endorsers).await;

    Ok(())
  }

  pub async fn reset_ledger_store(&self) {
    let res = self.ledger_store.reset_store().await;
    assert!(res.is_ok());
  }

  pub async fn create_ledger(
    &self,
    endorsers_opt: Option<Vec<Vec<u8>>>,
    handle_bytes: &[u8],
    block_bytes: &[u8],
  ) -> Result<Receipts, CoordinatorError> {
    let handle = NimbleDigest::digest(handle_bytes);
    let genesis_block = Block::new(block_bytes);
    let block_hash =
      NimbleDigest::digest(&genesis_block.hash().to_bytes()).digest_with(&NimbleDigest::default());

    let res = self
      .ledger_store
      .create_ledger(&handle, genesis_block.clone())
      .await;
    if res.is_err() {
      eprintln!(
        "Failed to create ledger in the ledger store ({:?})",
        res.unwrap_err()
      );
      return Err(CoordinatorError::FailedToCreateLedger);
    }

    // Make a request to the endorsers for NewLedger using the handle which returns a signature.
    let receipts = {
      let endorsers = match endorsers_opt {
        Some(ref endorsers) => endorsers.clone(),
        None => self.get_endorser_pks(),
      };
      let res = self
        .endorser_create_ledger(&endorsers, &handle, &block_hash)
        .await;
      if res.is_err() {
        eprintln!("Failed to create ledger in endorsers ({:?})", res);
        return Err(res.unwrap_err());
      }
      res.unwrap()
    };

    // Store the receipt
    let res = self
      .ledger_store
      .attach_ledger_receipts(&handle, 0, &receipts)
      .await;
    if res.is_err() {
      eprintln!(
        "Failed to attach ledger receipt to the ledger store ({:?})",
        res
      );
      return Err(CoordinatorError::FailedToAttachReceipt);
    }

    Ok(receipts)
  }

  pub async fn append_ledger(
    &self,
    endorsers_opt: Option<Vec<Vec<u8>>>,
    handle_bytes: &[u8],
    block_bytes: &[u8],
    expected_height: usize,
  ) -> Result<(NimbleDigest, Receipts), CoordinatorError> {
    if expected_height == 0 {
      return Err(CoordinatorError::InvalidHeight);
    }

    let handle = NimbleDigest::digest(handle_bytes);
    let data_block = Block::new(block_bytes);

    let res = self
      .ledger_store
      .append_ledger(&handle, &data_block, expected_height)
      .await;
    if res.is_err() {
      eprintln!(
        "Failed to append to the ledger in the ledger store {:?}",
        res.unwrap_err()
      );
      return Err(CoordinatorError::FailedToAppendLedger);
    }

    let (actual_height, nonces) = res.unwrap();
    assert!(actual_height == expected_height);

    let hash_block = data_block.hash();
    let hash_nonces = nonces.hash();
    let block_hash = compute_aggregated_block_hash(&hash_block.to_bytes(), &hash_nonces.to_bytes());

    let receipts = {
      let endorsers = match endorsers_opt {
        Some(endorsers) => endorsers,
        None => self.get_endorser_pks(),
      };
      let res = self
        .endorser_append_ledger(&endorsers, &handle, &block_hash, actual_height)
        .await;
      if res.is_err() {
        eprintln!("Failed to append to the ledger in endorsers {:?}", res);
        return Err(res.unwrap_err());
      }
      res.unwrap()
    };

    let res = self
      .ledger_store
      .attach_ledger_receipts(&handle, expected_height, &receipts)
      .await;
    if res.is_err() {
      eprintln!(
        "Failed to attach ledger receipt to the ledger store ({:?})",
        res.unwrap_err()
      );
      return Err(CoordinatorError::FailedToAttachReceipt);
    }

    Ok((hash_nonces, receipts))
  }

  async fn read_ledger_tail_internal(
    &self,
    handle: &NimbleDigest,
    nonce: &Nonce,
  ) -> Result<LedgerEntry, CoordinatorError> {
    let endorsers = self.get_endorser_pks();
    let res = self
      .endorser_read_ledger_tail(&endorsers, handle, nonce)
      .await;
    match res {
      Ok((receipts, height)) => {
        let mut ledger_entry = {
          let res = self.ledger_store.read_ledger_by_index(handle, height).await;
          if res.is_err() {
            eprintln!(
              "Failed to read the ledger from the ledger store {:?}",
              res.unwrap_err()
            );
            return Err(CoordinatorError::FailedToCallLedgerStore);
          }
          res.unwrap()
        };
        ledger_entry.set_receipts(receipts);
        Ok(ledger_entry)
      },
      Err(error) => {
        eprintln!("Failed to read the ledger tail {:?}", error);
        Err(error)
      },
    }
  }

  async fn read_ledger_by_index_internal(
    &self,
    handle: &NimbleDigest,
    height: usize,
  ) -> Result<LedgerEntry, CoordinatorError> {
    let res = self.ledger_store.read_ledger_by_index(handle, height).await;
    match res {
      Ok(ledger_entry) => Ok(ledger_entry),
      Err(error) => match error {
        LedgerStoreError::LedgerError(StorageError::InvalidIndex) => {
          Err(CoordinatorError::InvalidHeight)
        },
        _ => Err(CoordinatorError::FailedToCallLedgerStore),
      },
    }
  }

  pub async fn read_ledger_tail(
    &self,
    handle_bytes: &[u8],
    nonce_bytes: &[u8],
  ) -> Result<LedgerEntry, CoordinatorError> {
    let nonce = {
      let nonce_op = Nonce::new(nonce_bytes);
      if nonce_op.is_err() {
        eprintln!("Nonce is invalide");
        return Err(CoordinatorError::InvalidNonce);
      }
      nonce_op.unwrap().to_owned()
    };

    let handle = NimbleDigest::digest(handle_bytes);

    let mut nonce_attached = false;
    let mut nonce_attached_height = 0;

    loop {
      match self.read_ledger_tail_internal(&handle, &nonce).await {
        Ok(ledger_entry) => return Ok(ledger_entry),
        Err(error) => match error {
          CoordinatorError::FailedToObtainQuorum => {
            if !nonce_attached {
              let res = self.ledger_store.attach_ledger_nonce(&handle, &nonce).await;
              if res.is_err() {
                eprintln!(
                  "Failed to attach the nonce for reading ledger tail {:?}",
                  res.unwrap_err()
                );
                return Err(CoordinatorError::FailedToAttachNonce);
              }
              nonce_attached = true;
              nonce_attached_height = res.unwrap();
            }
            match self
              .read_ledger_by_index_internal(&handle, nonce_attached_height)
              .await
            {
              Ok(ledger_entry) => return Ok(ledger_entry),
              Err(error) => match error {
                CoordinatorError::FailedToObtainQuorum | CoordinatorError::InvalidHeight => {
                  continue;
                },
                _ => {
                  return Err(error);
                },
              },
            }
          },
          _ => {
            return Err(error);
          },
        },
      }
    }
  }

  pub async fn read_ledger_by_index(
    &self,
    handle_bytes: &[u8],
    index: usize,
  ) -> Result<LedgerEntry, CoordinatorError> {
    let handle = NimbleDigest::digest(handle_bytes);

    match self.ledger_store.read_ledger_by_index(&handle, index).await {
      Ok(ledger_entry) => Ok(ledger_entry),
      Err(error) => {
        eprintln!(
          "Failed to read ledger by index from the ledger store {:?}",
          error,
        );
        Err(CoordinatorError::FailedToReadLedger)
      },
    }
  }

  pub async fn read_view_by_index(&self, index: usize) -> Result<LedgerEntry, CoordinatorError> {
    let ledger_entry = {
      let res = self.ledger_store.read_view_ledger_by_index(index).await;
      if res.is_err() {
        return Err(CoordinatorError::FailedToReadViewLedger);
      }
      res.unwrap()
    };

    Ok(ledger_entry)
  }
}
