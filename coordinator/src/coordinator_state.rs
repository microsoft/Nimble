use crate::errors::CoordinatorError;
use ledger::{
  signature::{PublicKey, PublicKeyTrait},
  Block, CustomSerde, EndorserHostnames, Handle, LedgerView, MetaBlock, NimbleDigest,
  NimbleHashTrait, Nonce, Receipt,
};
use std::{
  collections::{HashMap, HashSet},
  convert::TryInto,
  sync::{Arc, RwLock},
};
use store::ledger::{
  azure_table::TableLedgerStore, filestore::FileStore, in_memory::InMemoryLedgerStore,
  mongodb_cosmos::MongoCosmosLedgerStore, LedgerEntry, LedgerStore,
};
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

type QuorumSizeMap = HashMap<NimbleDigest, usize>;

pub struct CoordinatorState {
  ledger_store: LedgerStoreRef,
  conn_map: Arc<RwLock<EndorserConnMap>>,
  quorum_size: Arc<RwLock<QuorumSizeMap>>,
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
  ignore_lock: bool,
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
          block_hash: ledger_entry.get_block().hash().to_bytes(),
          ignore_lock,
        }))
        .await?
        .into_inner();

      receipt
    } else {
      let endorser_proto::AppendResp { receipt } = endorser_client
        .append(tonic::Request::new(endorser_proto::AppendReq {
          handle: handle.to_bytes(),
          block_hash: ledger_entry.get_block().hash().to_bytes(),
          expected_height: idx as u64,
          ignore_lock,
        }))
        .await?
        .into_inner();

      receipt
    };

    let res = Receipt::from_bytes(&receipt);
    if res.is_ok() {
      let receipt_rs = res.unwrap();
      let res = ledger_store
        .attach_ledger_receipt(&handle, &receipt_rs)
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
    Code::Internal
    | Code::Unavailable
    | Code::Unknown
    | Code::ResourceExhausted
    | Code::Unimplemented => CoordinatorAction::RemoveEndorser,
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
        quorum_size: Arc::new(RwLock::new(HashMap::new())),
      },
      "table" => CoordinatorState {
        ledger_store: Arc::new(Box::new(TableLedgerStore::new(args).await.unwrap())),
        conn_map: Arc::new(RwLock::new(HashMap::new())),
        quorum_size: Arc::new(RwLock::new(HashMap::new())),
      },
      "filestore" => CoordinatorState {
        ledger_store: Arc::new(Box::new(FileStore::new(args).await.unwrap())),
        conn_map: Arc::new(RwLock::new(HashMap::new())),
        quorum_size: Arc::new(RwLock::new(HashMap::new())),
      },
      _ => CoordinatorState {
        ledger_store: Arc::new(Box::new(InMemoryLedgerStore::new())),
        conn_map: Arc::new(RwLock::new(HashMap::new())),
        quorum_size: Arc::new(RwLock::new(HashMap::new())),
      },
    };

    let res = coordinator.ledger_store.read_view_ledger_tail().await;
    if res.is_err() {
      eprintln!("Failed to read the view ledger tail {:?}", res);
      return Err(CoordinatorError::FailedToReadViewLedger);
    }

    let (view_ledger_tail, tail_height) = res.unwrap();
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

      let hostnames = (0..endorser_hostnames.pk_hostnames.len())
        .map(|i| endorser_hostnames.pk_hostnames[i].1.clone())
        .collect::<Vec<String>>();

      println!("endorsers in the latest view: {:?}", hostnames);

      // Read the latest view's receipt
      let res = coordinator
        .ledger_store
        .read_view_ledger_by_index(tail_height)
        .await;
      if res.is_err() {
        eprintln!(
          "Failed to read the view ledger at index {} ({:?})",
          tail_height, res
        );
        return Err(CoordinatorError::FailedToReadViewLedger);
      }
      let view_ledger_entry = res.unwrap();
      let view_tail_hash = view_ledger_entry.get_receipt().get_metablock_hash();
      // TODO: support failure recovery in the middle of a view change
      assert!(view_tail_hash != NimbleDigest::default());

      let pks = coordinator.connect_endorsers(&hostnames).await;

      // Remove endorsers that don't have the latest view
      let res = coordinator.filter_endorsers(&pks, &view_tail_hash).await;
      if let Err(error) = res {
        eprintln!(
          "Failed to filter the endorsers with the latest view {:?}",
          error
        );
        return Err(error);
      }

      // Update the quorum size map
      coordinator
        .set_quorum_size(view_tail_hash, hostnames.len() / 2 + 1)
        .await;
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
    EndorserHostnames {
      pk_hostnames: if let Ok(conn_map_rd) = self.conn_map.read() {
        conn_map_rd
          .iter()
          .map(|(pk, (_ec, hostname))| (pk.clone(), hostname.clone()))
          .collect::<Vec<(Vec<u8>, String)>>()
      } else {
        eprintln!("Failed to acquire read lock");
        Vec::new()
      },
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

  async fn set_quorum_size(&self, view_hash: NimbleDigest, quorum_size: usize) {
    self
      .quorum_size
      .write()
      .unwrap()
      .insert(view_hash, quorum_size);
  }

  async fn get_quorum_size(&self, view_hash: &NimbleDigest) -> usize {
    self.quorum_size.read().unwrap()[view_hash]
  }

  async fn connect_endorsers(&self, hostnames: &[String]) -> Vec<Vec<u8>> {
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

    let mut pks = Vec::new();
    while let Some((endorser, res)) = mpsc_rx.recv().await {
      if let Ok((client, pk)) = res {
        if PublicKey::from_bytes(&pk).is_err() {
          eprintln!("Public key is invalid from endorser {:?}", endorser);
          continue;
        }
        if let Ok(mut conn_map_wr) = self.conn_map.write() {
          conn_map_wr.entry(pk.clone()).or_insert_with(|| {
            pks.push(pk);
            (client, endorser)
          });
        } else {
          eprintln!("Failed to acquire the write lock");
        }
      }
    }

    pks
  }

  pub async fn disconnect_endorser(&self, hostname: &str) -> Result<(), CoordinatorError> {
    let pk = {
      if let Ok(conn_map_rd) = self.conn_map.read() {
        let res = conn_map_rd
          .iter()
          .find(|(_pk, (_client, uri))| *hostname == *uri);
        if let Some((pk, (_client, _uri))) = res {
          pk.clone()
        } else {
          eprintln!("Failed to find the endorser to disconnect {}", hostname);
          return Err(CoordinatorError::InvalidEndorserUri);
        }
      } else {
        return Err(CoordinatorError::FailedToAcquireReadLock);
      }
    };

    if let Ok(mut conn_map_wr) = self.conn_map.write() {
      let res = conn_map_wr.remove_entry(&pk);
      if let Some((_pk, (client, _uri))) = res {
        drop(client);
        eprintln!("Removed endorser {}", hostname);
        Ok(())
      } else {
        eprintln!("Failed to find the endorser to disconnect {}", hostname);
        Err(CoordinatorError::InvalidEndorserUri)
      }
    } else {
      eprintln!("Failed to acquire the write lock");
      Err(CoordinatorError::FailedToAcquireWriteLock)
    }
  }

  async fn filter_endorsers(
    &self,
    endorsers: &[Vec<u8>],
    view_tail_hash: &NimbleDigest,
  ) -> Result<(), CoordinatorError> {
    let (mpsc_tx, mut mpsc_rx) = mpsc::channel(ENDORSER_MPSC_CHANNEL_BUFFER);
    for pk in endorsers {
      let (mut endorser_client, endorser) = match self.get_endorser_client(pk) {
        Some((client, endorser)) => (client, endorser),
        None => continue,
      };

      let tx = mpsc_tx.clone();
      let _job = tokio::spawn(async move {
        let res = endorser_client
          .read_latest_view_ledger(tonic::Request::new(
            endorser_proto::ReadLatestViewLedgerReq {},
          ))
          .await;
        let _ = tx.send((endorser, res)).await;
      });
    }

    drop(mpsc_tx);

    while let Some((endorser, res)) = mpsc_rx.recv().await {
      let mut to_keep = false;
      match res {
        Ok(resp) => {
          let endorser_proto::ReadLatestViewLedgerResp {
            view_tail_metablock,
          } = resp.into_inner();
          let res = MetaBlock::from_bytes(&view_tail_metablock);
          match res {
            Ok(metablock) => {
              if metablock.hash() == *view_tail_hash {
                to_keep = true;
              } else {
                eprintln!(
                  "view_tail_hash={:?}, metablock_hash={:?}",
                  view_tail_hash,
                  metablock.hash()
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
        let _ = self.disconnect_endorser(&endorser).await;
      }
    }

    Ok(())
  }

  async fn endorser_initialize_state(
    &self,
    endorsers: &[Vec<u8>],
    ledger_view: &LedgerView,
    block_hash: &NimbleDigest,
    expected_height: usize,
  ) -> Result<Receipt, CoordinatorError> {
    let ledger_tail_map_proto: Vec<endorser_proto::LedgerTailMapEntry> = ledger_view
      .ledger_tail_map
      .iter()
      .map(|(handle, metablock)| endorser_proto::LedgerTailMapEntry {
        handle: handle.to_bytes(),
        metablock: metablock.to_bytes(),
      })
      .collect();

    let (mpsc_tx, mut mpsc_rx) = mpsc::channel(ENDORSER_MPSC_CHANNEL_BUFFER);
    for pk in endorsers {
      let (mut endorser_client, endorser) = match self.get_endorser_client(pk) {
        Some((client, endorser)) => (client, endorser),
        None => continue,
      };

      let tx = mpsc_tx.clone();
      let ledger_tail_map = ledger_tail_map_proto.clone();
      let view_tail_metablock = ledger_view.view_tail_metablock.to_bytes().to_vec();
      let block_hash = block_hash.to_bytes();
      let _job = tokio::spawn(async move {
        let res = endorser_client
          .initialize_state(tonic::Request::new(endorser_proto::InitializeStateReq {
            ledger_tail_map,
            view_tail_metablock,
            block_hash,
            expected_height: expected_height as u64,
          }))
          .await;
        let _ = tx.send((endorser, res)).await;
      });
    }

    drop(mpsc_tx);

    let mut receipts: Vec<Receipt> = Vec::new();
    while let Some((endorser, res)) = mpsc_rx.recv().await {
      match res {
        Ok(resp) => {
          let endorser_proto::InitializeStateResp { receipt } = resp.into_inner();
          let res = Receipt::from_bytes(&receipt);
          match res {
            Ok(receipt_rs) => receipts.push(receipt_rs),
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
            let _ = self.disconnect_endorser(&endorser).await;
          }
        },
      }
    }

    match Receipt::merge_receipts(&receipts) {
      Ok(receipt) => Ok(receipt),
      Err(_) => Err(CoordinatorError::EndorsersNotInSync),
    }
  }

  async fn endorser_create_ledger(
    &self,
    endorsers: &[Vec<u8>],
    ledger_handle: &Handle,
    ledger_block_hash: &NimbleDigest,
    ignore_lock: bool,
  ) -> Result<Receipt, CoordinatorError> {
    let (mpsc_tx, mut mpsc_rx) = mpsc::channel(ENDORSER_MPSC_CHANNEL_BUFFER);
    for pk in endorsers {
      let (mut endorser_client, endorser) = match self.get_endorser_client(pk) {
        Some((client, endorser)) => (client, endorser),
        None => continue,
      };

      let tx = mpsc_tx.clone();
      let handle = *ledger_handle;
      let block_hash = *ledger_block_hash;

      let _job = tokio::spawn(async move {
        let res = endorser_client
          .new_ledger(tonic::Request::new(endorser_proto::NewLedgerReq {
            handle: handle.to_bytes(),
            block_hash: block_hash.to_bytes(),
            ignore_lock,
          }))
          .await;
        let _ = tx.send((endorser, res)).await;
      });
    }

    drop(mpsc_tx);

    let mut quorum_size = 0;
    let mut receipts: Vec<Receipt> = Vec::new();
    let mut receipt_count: usize = 0;
    while let Some((endorser, res)) = mpsc_rx.recv().await {
      match res {
        Ok(resp) => {
          let endorser_proto::NewLedgerResp { receipt } = resp.into_inner();
          let res = Receipt::from_bytes(&receipt);
          match res {
            Ok(receipt_rs) => {
              if quorum_size == 0 {
                quorum_size = self.get_quorum_size(receipt_rs.get_view()).await;
              }
              receipts.push(receipt_rs);
              receipt_count += 1;
            },
            Err(error) => eprintln!("Failed to parse a receipt ({:?})", error),
          }
        },
        Err(status) => {
          eprintln!(
            "Failed to create a ledger {:?} in endorser {} (status={:?})",
            ledger_handle, endorser, status
          );
          match process_error(&endorser, Some(ledger_handle), &status) {
            CoordinatorAction::IncrementReceipt => {
              receipt_count += 1;
            },
            CoordinatorAction::RemoveEndorser => {
              eprintln!(
                "create_ledger from endorser {} received unexpected error {:?}",
                endorser, status
              );
              let _ = self.disconnect_endorser(&endorser).await;
            },
            _ => {},
          }
        },
      }
      if receipt_count == quorum_size {
        break;
      }
    }

    match Receipt::merge_receipts(&receipts) {
      Ok(receipt) => Ok(receipt),
      Err(_) => Err(CoordinatorError::EndorsersNotInSync),
    }
  }

  pub async fn endorser_append_ledger(
    &self,
    endorsers: &[Vec<u8>],
    ledger_handle: &Handle,
    block_hash: &NimbleDigest,
    expected_height: usize,
  ) -> Result<Receipt, CoordinatorError> {
    let (mpsc_tx, mut mpsc_rx) = mpsc::channel(ENDORSER_MPSC_CHANNEL_BUFFER);

    for pk in endorsers {
      let (mut endorser_client, endorser) = match self.get_endorser_client(pk) {
        Some((client, endorser)) => (client, endorser),
        None => continue,
      };

      let tx = mpsc_tx.clone();
      let handle = *ledger_handle;
      let block = *block_hash;
      let ledger_store = self.ledger_store.clone();
      let _job = tokio::spawn(async move {
        loop {
          let res = endorser_client
            .append(tonic::Request::new(endorser_proto::AppendReq {
              handle: handle.to_bytes(),
              block_hash: block.to_bytes(),
              expected_height: expected_height as u64,
              ignore_lock: false,
            }))
            .await;
          match res {
            Ok(resp) => {
              let endorser_proto::AppendResp { receipt } = resp.into_inner();
              let _ = tx.send((endorser, Ok(receipt))).await;
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
                  false,
                )
                .await;
                match res {
                  Ok(_resp) => {
                    continue;
                  },
                  Err(status) => match process_error(&endorser, Some(&handle), &status) {
                    CoordinatorAction::RemoveEndorser => {
                      let _ = tx
                        .send((endorser, Err(CoordinatorError::UnexpectedError)))
                        .await;
                      break;
                    },
                    CoordinatorAction::IncrementReceipt => {
                      continue;
                    },
                    _ => {
                      let _ = tx
                        .send((endorser, Err(CoordinatorError::FailedToAppendLedger)))
                        .await;
                      break;
                    },
                  },
                }
              },
              CoordinatorAction::RemoveEndorser => {
                let _ = tx
                  .send((endorser, Err(CoordinatorError::UnexpectedError)))
                  .await;
                break;
              },
              CoordinatorAction::IncrementReceipt => {
                let _ = tx
                  .send((endorser, Err(CoordinatorError::LedgerAlreadyExists)))
                  .await;
                break;
              },
              _ => {
                let _ = tx
                  .send((endorser, Err(CoordinatorError::FailedToAppendLedger)))
                  .await;
                break;
              },
            },
          }
        }
      });
    }

    drop(mpsc_tx);

    let mut quorum_size = 0;
    let mut receipts: Vec<Receipt> = Vec::new();
    let mut receipt_count = 0;
    while let Some((endorser, res)) = mpsc_rx.recv().await {
      match res {
        Ok(receipt) => match Receipt::from_bytes(&receipt) {
          Ok(receipt_rs) => {
            if quorum_size == 0 {
              quorum_size = self.get_quorum_size(receipt_rs.get_view()).await;
            }
            receipts.push(receipt_rs);
            receipt_count += 1;
          },
          Err(error) => {
            eprintln!("Failed to parse a receipt (err={:?}", error);
          },
        },
        Err(error) => match error {
          CoordinatorError::LedgerAlreadyExists => {
            receipt_count += 1;
          },
          CoordinatorError::UnexpectedError => {
            eprintln!(
              "append_ledger from endorser {} received unexpected error {:?}",
              endorser, error
            );
            let _ = self.disconnect_endorser(&endorser).await;
          },
          _ => {},
        },
      }
      if receipt_count == quorum_size {
        break;
      }
    }

    match Receipt::merge_receipts(&receipts) {
      Ok(receipt) => Ok(receipt),
      Err(_) => Err(CoordinatorError::EndorsersNotInSync),
    }
  }

  async fn endorser_read_ledger_tail(
    &self,
    endorsers: &[Vec<u8>],
    ledger_handle: &Handle,
    client_nonce: &Nonce,
    expected_height: usize,
  ) -> Result<Receipt, CoordinatorError> {
    let (mpsc_tx, mut mpsc_rx) = mpsc::channel(ENDORSER_MPSC_CHANNEL_BUFFER);

    for pk in endorsers {
      let (mut endorser_client, endorser) = match self.get_endorser_client(pk) {
        Some((client, endorser)) => (client, endorser),
        None => continue,
      };

      let tx = mpsc_tx.clone();
      let handle = *ledger_handle;
      let nonce = *client_nonce;
      let ledger_store = self.ledger_store.clone();
      let _job = tokio::spawn(async move {
        loop {
          let res = endorser_client
            .read_latest(tonic::Request::new(endorser_proto::ReadLatestReq {
              handle: handle.to_bytes(),
              nonce: nonce.get(),
              expected_height: expected_height as u64,
            }))
            .await;
          match res {
            Ok(resp) => {
              let endorser_proto::ReadLatestResp { receipt } = resp.into_inner();
              let _ = tx.send((endorser, Ok(receipt))).await;
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
                let height_to_end = expected_height;
                let res = update_endorser(
                  ledger_store.clone(),
                  endorser_client.clone(),
                  handle,
                  height_to_start,
                  height_to_end,
                  false,
                )
                .await;
                match res {
                  Ok(_resp) => {
                    continue;
                  },
                  Err(status) => match process_error(&endorser, Some(&handle), &status) {
                    CoordinatorAction::RemoveEndorser => {
                      let _ = tx
                        .send((endorser, Err(CoordinatorError::UnexpectedError)))
                        .await;
                      break;
                    },
                    CoordinatorAction::IncrementReceipt => {
                      continue;
                    },
                    _ => {
                      let _ = tx
                        .send((endorser, Err(CoordinatorError::FailedToAppendLedger)))
                        .await;
                      break;
                    },
                  },
                }
              },
              CoordinatorAction::RemoveEndorser => {
                let _ = tx
                  .send((endorser, Err(CoordinatorError::UnexpectedError)))
                  .await;
                break;
              },
              CoordinatorAction::IncrementReceipt => {
                let _ = tx
                  .send((endorser, Err(CoordinatorError::LedgerAlreadyExists)))
                  .await;
                break;
              },
              _ => {
                let _ = tx
                  .send((endorser, Err(CoordinatorError::FailedToAppendLedger)))
                  .await;
                break;
              },
            },
          }
        }
      });
    }

    drop(mpsc_tx);

    let mut quorum_size = 0;
    let mut receipts: Vec<Receipt> = Vec::new();
    let mut receipt_count = 0;
    while let Some((endorser, res)) = mpsc_rx.recv().await {
      match res {
        Ok(receipt) => match Receipt::from_bytes(&receipt) {
          Ok(receipt_rs) => {
            if quorum_size == 0 {
              quorum_size = self.get_quorum_size(receipt_rs.get_view()).await;
            }
            receipts.push(receipt_rs);
            receipt_count += 1;
          },
          Err(error) => {
            eprintln!("Failed to parse a receipt (err={:?}", error);
          },
        },
        Err(error) => match error {
          CoordinatorError::LedgerAlreadyExists => {
            receipt_count += 1;
          },
          CoordinatorError::UnexpectedError => {
            eprintln!(
              "read_ledger from endorser {} received unexpected error {:?}",
              endorser, error
            );
            let _ = self.disconnect_endorser(&endorser).await;
          },
          _ => {},
        },
      }
      if receipt_count == quorum_size {
        break;
      }
    }

    match Receipt::merge_receipts(&receipts) {
      Ok(receipt) => Ok(receipt),
      Err(_) => Err(CoordinatorError::EndorsersNotInSync),
    }
  }

  async fn endorser_append_view_ledger(
    &self,
    endorsers: &[Vec<u8>],
    block_hash: &NimbleDigest,
    expected_height: usize,
  ) -> Result<Receipt, CoordinatorError> {
    let (mpsc_tx, mut mpsc_rx) = mpsc::channel(ENDORSER_MPSC_CHANNEL_BUFFER);

    for pk in endorsers {
      let (mut endorser_client, endorser) = match self.get_endorser_client(pk) {
        Some((client, endorser)) => (client, endorser),
        None => continue,
      };

      let tx = mpsc_tx.clone();
      let block = *block_hash;
      let _job = tokio::spawn(async move {
        let res = endorser_client
          .append_view_ledger(tonic::Request::new(endorser_proto::AppendViewLedgerReq {
            block_hash: block.to_bytes(),
            expected_height: expected_height as u64,
          }))
          .await;
        let _ = tx.send((endorser, res)).await;
      });
    }

    drop(mpsc_tx);

    let mut receipts: Vec<Receipt> = Vec::new();
    while let Some((endorser, res)) = mpsc_rx.recv().await {
      match res {
        Ok(resp) => {
          let endorser_proto::AppendViewLedgerResp { receipt } = resp.into_inner();
          let res = Receipt::from_bytes(&receipt);
          match res {
            Ok(receipt_rs) => receipts.push(receipt_rs),
            Err(error) => eprintln!("Failed to parse a receipt ({:?})", error),
          }
        },
        Err(status) => {
          eprintln!(
            "Failed to append view ledger to endorser {} (status={:?})",
            endorser, status
          );
          if let CoordinatorAction::RemoveEndorser = process_error(&endorser, None, &status) {
            let _ = self.disconnect_endorser(&endorser).await;
          }
        },
      }
    }

    match Receipt::merge_receipts(&receipts) {
      Ok(receipt) => Ok(receipt),
      Err(_) => Err(CoordinatorError::EndorsersNotInSync),
    }
  }

  async fn endorser_read_latest_state(
    &self,
    endorsers: &[Vec<u8>],
    to_lock: bool,
  ) -> Result<Vec<(PublicKey, LedgerView)>, CoordinatorError> {
    let (mpsc_tx, mut mpsc_rx) = mpsc::channel(ENDORSER_MPSC_CHANNEL_BUFFER);

    for pk in endorsers {
      let (mut endorser_client, endorser) = match self.get_endorser_client(pk) {
        Some((client, endorser)) => (client, endorser),
        None => continue,
      };

      let tx = mpsc_tx.clone();
      let pk_bytes = pk.clone();
      let _job = tokio::spawn(async move {
        let res = endorser_client
          .read_latest_state(tonic::Request::new(endorser_proto::ReadLatestStateReq {
            to_lock,
          }))
          .await;
        tx.send((endorser, pk_bytes, res)).await.unwrap();
      });
    }

    drop(mpsc_tx);

    let mut ledger_views = Vec::new();
    while let Some((endorser, pk, res)) = mpsc_rx.recv().await {
      match res {
        Ok(resp) => {
          let endorser_proto::ReadLatestStateResp {
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
        },
        Err(status) => {
          eprintln!(
            "Failed to read the latest state of endorser {} (status={:?})",
            endorser, status
          );
          if let CoordinatorAction::RemoveEndorser = process_error(&endorser, None, &status) {
            let _ = self.disconnect_endorser(&endorser).await;
          }
        },
      }
    }

    Ok(ledger_views)
  }

  async fn unlock_endorsers(&self, endorsers: &[Vec<u8>]) -> Result<(), CoordinatorError> {
    let (mpsc_tx, mut mpsc_rx) = mpsc::channel(ENDORSER_MPSC_CHANNEL_BUFFER);

    for pk in endorsers {
      let (mut endorser_client, endorser) = match self.get_endorser_client(pk) {
        Some((client, endorser)) => (client, endorser),
        None => continue,
      };

      let tx = mpsc_tx.clone();
      let _job = tokio::spawn(async move {
        let res = endorser_client
          .unlock(tonic::Request::new(endorser_proto::UnlockReq {}))
          .await;
        let _ = tx.send((endorser, res)).await;
      });
    }

    drop(mpsc_tx);

    while let Some((endorser, res)) = mpsc_rx.recv().await {
      match res {
        Ok(_resp) => {},
        Err(status) => {
          eprintln!("Failed to unlock endorser {}", endorser);
          if let CoordinatorAction::RemoveEndorser = process_error(&endorser, None, &status) {
            let _ = self.disconnect_endorser(&endorser).await;
          }
        },
      }
    }

    Ok(())
  }

  async fn sync_ledger_views(
    &self,
    ledger_views: &[(PublicKey, LedgerView)],
  ) -> Result<LedgerView, CoordinatorError> {
    if ledger_views.is_empty() {
      return Err(CoordinatorError::EmptyLedgerViews);
    }
    let mut max_cut = LedgerView {
      view_tail_metablock: MetaBlock::default(),
      ledger_tail_map: HashMap::new(),
    };

    // All view tail metablock should be the same
    let view_metablocks = (0..ledger_views.len())
      .map(|i| ledger_views[i].1.view_tail_metablock.hash())
      .collect::<HashSet<NimbleDigest>>();

    if view_metablocks.len() != 1 {
      return Err(CoordinatorError::NonUniqueViews);
    }

    max_cut.view_tail_metablock = ledger_views
      .iter()
      .next()
      .unwrap()
      .1
      .view_tail_metablock
      .clone();

    // Find the tails in the max cut
    for (_pk, ledger_view) in ledger_views {
      for (handle, metablock) in ledger_view.ledger_tail_map.iter() {
        if !max_cut.ledger_tail_map.contains_key(handle)
          || max_cut.ledger_tail_map[handle].get_height() < metablock.get_height()
        {
          max_cut.ledger_tail_map.insert(*handle, metablock.clone());
        }
      }
    }

    let (mpsc_tx, mut mpsc_rx) = mpsc::channel(ENDORSER_MPSC_CHANNEL_BUFFER);

    // Update endorsers to the max cut
    for (pk, ledger_view) in ledger_views {
      let (client, endorser) = match self.get_endorser_client(&pk.to_bytes()) {
        Some((client, endorser)) => (client, endorser),
        None => continue,
      };

      for (handle, metablock) in max_cut.ledger_tail_map.iter() {
        if ledger_view.ledger_tail_map.contains_key(handle)
          && ledger_view.ledger_tail_map[handle].get_height() >= metablock.get_height()
        {
          continue;
        }
        let height_to_start = {
          if !ledger_view.ledger_tail_map.contains_key(handle) {
            0
          } else {
            ledger_view.ledger_tail_map[handle]
              .get_height()
              .checked_add(1)
              .unwrap()
          }
        };
        let height_to_end = metablock.get_height();

        let ledger_store = self.ledger_store.clone();
        let endorser_client = client.clone();
        let endorser_uri = endorser.clone();
        let ledger_handle = *handle;
        let tx = mpsc_tx.clone();
        let _job = tokio::spawn(async move {
          let res = update_endorser(
            ledger_store,
            endorser_client,
            ledger_handle,
            height_to_start,
            height_to_end,
            true,
          )
          .await;
          let _ = tx.send((endorser_uri, res)).await;
        });
      }
    }

    drop(mpsc_tx);

    while let Some((endorser, res)) = mpsc_rx.recv().await {
      if let Err(status) = res {
        match status.code() {
          Code::Aborted => eprintln!("LEDGER_STORE error!"),
          Code::AlreadyExists => {},
          Code::Internal | Code::Unavailable | Code::Unknown => {
            // disconnect endorser
            eprintln!(
              "endorser {} became unavailable due to {:?}",
              endorser, status
            );
            let res = self.disconnect_endorser(&endorser).await;
            if let Err(error) = res {
              eprintln!(
                "Failed to remove endorser {} from the cohort (err={:?}",
                endorser, error
              );
            } else {
              eprintln!("Removed endorser {} from the cohort", endorser);
            }
          },
          _ => eprintln!(
            "Failed to update endorser {} with an unknown status {:?}",
            endorser, status
          ),
        }
      }
    }

    Ok(max_cut)
  }

  pub async fn add_endorsers(&self, hostnames: &[String]) -> Result<(), CoordinatorError> {
    let existing_endorsers = self.get_endorser_pks();

    // Connect to new endorsers
    let new_endorsers = self.connect_endorsers(hostnames).await;
    if new_endorsers.is_empty() {
      return Err(CoordinatorError::NoNewEndorsers);
    }

    let ledger_view = {
      if existing_endorsers.is_empty() {
        LedgerView {
          view_tail_metablock: MetaBlock::default(),
          ledger_tail_map: HashMap::new(),
        }
      } else {
        let res = self
          .endorser_read_latest_state(&existing_endorsers, true)
          .await;
        if res.is_err() {
          eprintln!(
            "Failed to read the latest state of endorsers ({:?})",
            res.unwrap_err()
          );
          return Err(CoordinatorError::FailedToReadLatestState);
        }
        let ledger_views = res.unwrap();

        let res = self.sync_ledger_views(&ledger_views).await;
        if res.is_err() {
          eprintln!("Failed to merge/sync ledger views ({:?})", res);
          return Err(res.unwrap_err());
        }
        res.unwrap()
      }
    };

    let endorser_pk_hostnames = self.get_endorser_hostnames();
    // Package the list of endorsers into a genesis block of the view ledger
    let view_ledger_genesis_block = {
      let res = bincode::serialize(&endorser_pk_hostnames);
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

    let (_tail, height) = res.unwrap();

    // Ignore tail result for now. TODO: for fault tolerance, we'll need to do more.

    // Store the genesis block of the view ledger in the ledger store
    let res = self
      .ledger_store
      .append_view_ledger(&view_ledger_genesis_block, height + 1)
      .await;
    if res.is_err() {
      eprintln!(
        "Failed to append to the view ledger in the ledger store ({:?})",
        res.unwrap_err()
      );
      return Err(CoordinatorError::FailedToCallLedgerStore);
    }

    let view_ledger_height = res.unwrap();

    // Initialize new endorsers
    let receipt1 = {
      let res = self
        .endorser_initialize_state(
          &new_endorsers,
          &ledger_view,
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
      res.unwrap()
    };

    let receipt = {
      if !existing_endorsers.is_empty() {
        // Update existing endorsers
        let receipt2 = {
          let res = self
            .endorser_append_view_ledger(
              &existing_endorsers,
              &view_ledger_genesis_block.hash(),
              view_ledger_height,
            )
            .await;
          if res.is_err() {
            eprintln!(
              "Failed to append to the view ledger ({:?})",
              res.unwrap_err()
            );
            return Err(CoordinatorError::FailedToInitializeEndorser);
          }
          res.unwrap()
        };

        Receipt::merge_receipts(&[receipt1, receipt2]).unwrap()
      } else {
        receipt1
      }
    };

    // Store the receipt in the view ledger
    let res = self.ledger_store.attach_view_ledger_receipt(&receipt).await;
    if res.is_err() {
      eprintln!(
        "Failed to attach view ledger receipt in the ledger store ({:?})",
        res.unwrap_err()
      );
      return Err(CoordinatorError::FailedToCallLedgerStore);
    }

    // Update quorum size
    self
      .set_quorum_size(
        receipt.get_metablock_hash(),
        endorser_pk_hostnames.pk_hostnames.len() / 2 + 1,
      )
      .await;

    let res = self.unlock_endorsers(&existing_endorsers).await;
    if res.is_err() {
      eprintln!("Failed to unlock endorsers ({:?})", res.unwrap_err());
      return Err(CoordinatorError::FailedToUnlock);
    }

    Ok(())
  }

  pub async fn reset_ledger_store(&self) {
    let res = self.ledger_store.reset_store().await;
    assert!(res.is_ok());
  }

  pub async fn query_endorsers(&self) -> Result<Vec<(PublicKey, LedgerView)>, CoordinatorError> {
    self
      .endorser_read_latest_state(&self.get_endorser_pks(), false)
      .await
  }

  pub async fn create_ledger(
    &self,
    endorsers_opt: Option<Vec<Vec<u8>>>,
    handle_bytes: &[u8],
    block_bytes: &[u8],
  ) -> Result<Receipt, CoordinatorError> {
    let handle = NimbleDigest::digest(handle_bytes);
    let genesis_block = Block::new(block_bytes);
    let block_hash = genesis_block.hash();

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
    let receipt = {
      let endorsers = match endorsers_opt {
        Some(ref endorsers) => endorsers.clone(),
        None => self.get_endorser_pks(),
      };
      let res = self
        .endorser_create_ledger(&endorsers, &handle, &block_hash, false)
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
      .attach_ledger_receipt(&handle, &receipt)
      .await;
    if res.is_err() {
      eprintln!(
        "Failed to attach ledger receipt to the ledger store ({:?})",
        res
      );
      return Err(CoordinatorError::FailedToAttachReceipt);
    }

    Ok(receipt)
  }

  pub async fn append_ledger(
    &self,
    endorsers_opt: Option<Vec<Vec<u8>>>,
    handle_bytes: &[u8],
    block_bytes: &[u8],
    expected_height: usize,
  ) -> Result<Receipt, CoordinatorError> {
    if expected_height == 0 {
      return Err(CoordinatorError::InvalidHeight);
    }

    let handle = NimbleDigest::digest(handle_bytes);
    let data_block = Block::new(block_bytes);
    let hash_of_block = data_block.hash();

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

    let (actual_height, _nonce_list) = res.unwrap();
    assert!(actual_height == expected_height);

    let receipt = {
      let endorsers = match endorsers_opt {
        Some(endorsers) => endorsers,
        None => self.get_endorser_pks(),
      };
      let res = self
        .endorser_append_ledger(&endorsers, &handle, &hash_of_block, actual_height)
        .await;
      if res.is_err() {
        eprintln!("Failed to append to the ledger in endorsers {:?}", res);
        return Err(res.unwrap_err());
      }
      res.unwrap()
    };

    let res = self
      .ledger_store
      .attach_ledger_receipt(&handle, &receipt)
      .await;
    if res.is_err() {
      eprintln!(
        "Failed to attach ledger receipt to the ledger store ({:?})",
        res.unwrap_err()
      );
      return Err(CoordinatorError::FailedToAttachReceipt);
    }

    Ok(receipt)
  }

  pub async fn read_ledger_tail(
    &self,
    handle_bytes: &[u8],
    nonce_bytes: &[u8],
  ) -> Result<(Block, Receipt), CoordinatorError> {
    let nonce = {
      let nonce_op = Nonce::new(nonce_bytes);
      if nonce_op.is_err() {
        eprintln!("Nonce is invalide");
        return Err(CoordinatorError::InvalidNonce);
      }
      nonce_op.unwrap().to_owned()
    };

    let handle = NimbleDigest::digest(handle_bytes);

    let (ledger_entry, height) = {
      let res = self.ledger_store.read_ledger_tail(&handle).await;
      if res.is_err() {
        eprintln!(
          "Failed to read the ledger tail from the ledger store {:?}",
          res.unwrap_err()
        );
        return Err(CoordinatorError::FailedToReadLatestState);
      }
      res.unwrap()
    };

    let receipt = {
      let endorsers = self.get_endorser_pks();
      let res = self
        .endorser_read_ledger_tail(&endorsers, &handle, &nonce, height)
        .await;
      if res.is_err() {
        eprintln!(
          "Failed to read the ledger tail from endorsers {:?}",
          res.unwrap_err()
        );
        return Err(CoordinatorError::FailedToReadLatestState);
      }
      res.unwrap()
    };

    Ok((ledger_entry.get_block().clone(), receipt))
  }

  pub async fn read_ledger_by_index(
    &self,
    handle_bytes: &[u8],
    index: usize,
  ) -> Result<LedgerEntry, CoordinatorError> {
    let handle = NimbleDigest::digest(handle_bytes);

    let ledger_entry = {
      let res = self.ledger_store.read_ledger_by_index(&handle, index).await;
      if res.is_err() {
        eprintln!(
          "Failed to read ledger by index from the ledger store {:?}",
          res.unwrap_err()
        );
        return Err(CoordinatorError::FailedToReadLedger);
      }
      res.unwrap()
    };

    Ok(ledger_entry)
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
