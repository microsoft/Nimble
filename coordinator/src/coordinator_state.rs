use crate::errors::CoordinatorError;
use ledger::{
  compute_aggregated_block_hash, compute_cut_diffs, compute_max_cut,
  errors::VerificationError,
  signature::{PublicKey, PublicKeyTrait},
  Block, CustomSerde, EndorserHostnames, Handle, IdSig, MetaBlock, NimbleDigest, NimbleHashTrait,
  Nonce, Nonces, Receipt, Receipts, VerifierState,
};
use log::{error, info, warn};
use rand::{random, Rng};
use std::{
  collections::{HashMap, HashSet}, convert::TryInto, f32::consts::E, ops::Deref, sync::{atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering::SeqCst}, Arc, RwLock}, time::Duration, u64::MAX
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

use clokwerk::TimeUnits;
use ledger::endorser_proto;

//use tracing::{error, info};
//use tracing_subscriber;

const DEFAULT_NUM_GRPC_CHANNELS: usize = 1; // the default number of GRPC channels

enum EndorserUsageState {
  Uninitialized,
  Initialized,
  Active,
  Finalized,
}

struct EndorserClients {
  clients: Vec<endorser_proto::endorser_call_client::EndorserCallClient<Channel>>,
  uri: String,
  failures: u64,
  usage_state: EndorserUsageState,
}

type EndorserConnMap = HashMap<Vec<u8>, EndorserClients>;

type LedgerStoreRef = Arc<Box<dyn LedgerStore + Send + Sync>>;

#[derive(Clone)]
pub struct CoordinatorState {
  pub(crate) ledger_store: LedgerStoreRef,
  conn_map: Arc<RwLock<EndorserConnMap>>,
  verifier_state: Arc<RwLock<VerifierState>>,
  num_grpc_channels: usize,
  _used_nonces: Arc<RwLock<HashSet<Vec<u8>>>>,
}

const ENDORSER_MPSC_CHANNEL_BUFFER: usize = 8; // limited by the number of endorsers
const ENDORSER_CONNECT_TIMEOUT: u64 = 10; // seconds: the connect timeout to endorsres

const ATTESTATION_STR: &str = "THIS IS A PLACE HOLDER FOR ATTESTATION";

//static _LOG_FILE_LOCATION: &str = "log.txt";
static DEAD_ENDORSERS: AtomicUsize = AtomicUsize::new(0); // Set the number of currently dead endorsers
static DESIRED_QUORUM_SIZE: AtomicU64 = AtomicU64::new(MAX);
static MAX_FAILURES: AtomicU64 = AtomicU64::new(3);
static ENDORSER_REQUEST_TIMEOUT: AtomicU64 = AtomicU64::new(10);
static ENDORSER_DEAD_ALLOWANCE: AtomicU64 = AtomicU64::new(66);
static PING_INTERVAL: AtomicU32 = AtomicU32::new(10); // seconds
static DEACTIVATE_AUTO_RECONFIG: AtomicBool = AtomicBool::new(false);

async fn get_public_key_with_retry(
  endorser_client: &mut endorser_proto::endorser_call_client::EndorserCallClient<Channel>,
  request: endorser_proto::GetPublicKeyReq,
) -> Result<tonic::Response<endorser_proto::GetPublicKeyResp>, Status> {
  loop {
    let res = endorser_client
      .get_public_key(tonic::Request::new(request.clone()))
      .await;
    match res {
      Ok(resp) => {
        return Ok(resp);
      },
      Err(status) => {
        match status.code() {
          Code::ResourceExhausted => {
            continue;
          },
          _ => {
            return Err(status);
          },
        };
      },
    };
  }
}

async fn get_ping_with_retry(
  endorser_client: &mut endorser_proto::endorser_call_client::EndorserCallClient<Channel>,
  request: endorser_proto::PingReq,
) -> Result<tonic::Response<endorser_proto::PingResp>, Status> {
  loop {
    let res = endorser_client
      .ping(tonic::Request::new(request.clone()))
      .await;
    match res {
      Ok(resp) => {
        return Ok(resp);
      },
      Err(status) => {
        match status.code() {
          Code::ResourceExhausted => {
            continue;
          },
          _ => {
            return Err(status);
          },
        };
      },
    };
  }
}

async fn new_ledger_with_retry(
  endorser_client: &mut endorser_proto::endorser_call_client::EndorserCallClient<Channel>,
  request: endorser_proto::NewLedgerReq,
) -> Result<tonic::Response<endorser_proto::NewLedgerResp>, Status> {
  loop {
    let res = endorser_client
      .new_ledger(tonic::Request::new(request.clone()))
      .await;
    match res {
      Ok(resp) => {
        return Ok(resp);
      },
      Err(status) => {
        match status.code() {
          Code::ResourceExhausted => {
            continue;
          },
          _ => {
            return Err(status);
          },
        };
      },
    };
  }
}

async fn append_with_retry(
  endorser_client: &mut endorser_proto::endorser_call_client::EndorserCallClient<Channel>,
  request: endorser_proto::AppendReq,
) -> Result<tonic::Response<endorser_proto::AppendResp>, Status> {
  loop {
    let res = endorser_client
      .append(tonic::Request::new(request.clone()))
      .await;
    match res {
      Ok(resp) => {
        return Ok(resp);
      },
      Err(status) => {
        match status.code() {
          Code::ResourceExhausted => {
            continue;
          },
          _ => {
            return Err(status);
          },
        };
      },
    };
  }
}

async fn read_latest_with_retry(
  endorser_client: &mut endorser_proto::endorser_call_client::EndorserCallClient<Channel>,
  request: endorser_proto::ReadLatestReq,
) -> Result<tonic::Response<endorser_proto::ReadLatestResp>, Status> {
  loop {
    let res = endorser_client
      .read_latest(tonic::Request::new(request.clone()))
      .await;
    match res {
      Ok(resp) => {
        return Ok(resp);
      },
      Err(status) => {
        match status.code() {
          Code::ResourceExhausted => {
            continue;
          },
          _ => {
            return Err(status);
          },
        };
      },
    };
  }
}

async fn initialize_state_with_retry(
  endorser_client: &mut endorser_proto::endorser_call_client::EndorserCallClient<Channel>,
  group_identity: Vec<u8>,
  ledger_tail_map: Arc<Vec<endorser_proto::LedgerTailMapEntry>>,
  view_tail_metablock: Vec<u8>,
  block_hash: Vec<u8>,
  expected_height: usize,
) -> Result<tonic::Response<endorser_proto::InitializeStateResp>, Status> {
  loop {
    let res = endorser_client
      .initialize_state(tonic::Request::new(endorser_proto::InitializeStateReq {
        group_identity: group_identity.clone(),
        ledger_tail_map: ledger_tail_map.deref().clone(),
        view_tail_metablock: view_tail_metablock.clone(),
        block_hash: block_hash.clone(),
        expected_height: expected_height as u64,
      }))
      .await;
    match res {
      Ok(resp) => {
        return Ok(resp);
      },
      Err(status) => {
        match status.code() {
          Code::ResourceExhausted => {
            continue;
          },
          _ => {
            return Err(status);
          },
        };
      },
    };
  }
}

async fn finalize_state_with_retry(
  endorser_client: &mut endorser_proto::endorser_call_client::EndorserCallClient<Channel>,
  request: endorser_proto::FinalizeStateReq,
) -> Result<tonic::Response<endorser_proto::FinalizeStateResp>, Status> {
  loop {
    let res = endorser_client
      .finalize_state(tonic::Request::new(request.clone()))
      .await;
    match res {
      Ok(resp) => {
        return Ok(resp);
      },
      Err(status) => {
        match status.code() {
          Code::ResourceExhausted => {
            continue;
          },
          _ => {
            return Err(status);
          },
        };
      },
    };
  }
}

async fn read_state_with_retry(
  endorser_client: &mut endorser_proto::endorser_call_client::EndorserCallClient<Channel>,
  request: endorser_proto::ReadStateReq,
) -> Result<tonic::Response<endorser_proto::ReadStateResp>, Status> {
  loop {
    let res = endorser_client
      .read_state(tonic::Request::new(request.clone()))
      .await;
    match res {
      Ok(resp) => {
        return Ok(resp);
      },
      Err(status) => {
        match status.code() {
          Code::ResourceExhausted => {
            continue;
          },
          _ => {
            return Err(status);
          },
        };
      },
    };
  }
}

async fn activate_with_retry(
  endorser_client: &mut endorser_proto::endorser_call_client::EndorserCallClient<Channel>,
  old_config: Vec<u8>,
  new_config: Vec<u8>,
  ledger_tail_maps: Arc<Vec<endorser_proto::LedgerTailMap>>,
  ledger_chunks: Vec<endorser_proto::LedgerChunkEntry>,
  receipts: Vec<u8>,
) -> Result<tonic::Response<endorser_proto::ActivateResp>, Status> {
  loop {
    let res = endorser_client
      .activate(tonic::Request::new(endorser_proto::ActivateReq {
        old_config: old_config.clone(),
        new_config: new_config.clone(),
        ledger_tail_maps: ledger_tail_maps.deref().clone(),
        ledger_chunks: ledger_chunks.clone(),
        receipts: receipts.clone(),
      }))
      .await;
    match res {
      Ok(resp) => {
        return Ok(resp);
      },
      Err(status) => {
        match status.code() {
          Code::ResourceExhausted => {
            continue;
          },
          _ => {
            return Err(status);
          },
        };
      },
    };
  }
}

async fn update_endorser(
  ledger_store: LedgerStoreRef,
  endorser_client: &mut endorser_proto::endorser_call_client::EndorserCallClient<Channel>,
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
      let endorser_proto::NewLedgerResp { receipt } = new_ledger_with_retry(
        endorser_client,
        endorser_proto::NewLedgerReq {
          handle: handle.to_bytes(),
          block_hash: compute_aggregated_block_hash(
            &ledger_entry.get_block().hash().to_bytes(),
            &ledger_entry.get_nonces().hash().to_bytes(),
          )
          .to_bytes(),
          block: ledger_entry.get_block().to_bytes(),
        },
      )
      .await?
      .into_inner();
      receipt
    } else {
      let endorser_proto::AppendResp { receipt } = append_with_retry(
        endorser_client,
        endorser_proto::AppendReq {
          handle: handle.to_bytes(),
          block_hash: compute_aggregated_block_hash(
            &ledger_entry.get_block().hash().to_bytes(),
            &ledger_entry.get_nonces().hash().to_bytes(),
          )
          .to_bytes(),
          expected_height: idx as u64,
          block: ledger_entry.get_block().to_bytes(),
          nonces: ledger_entry.get_nonces().to_bytes(),
        },
      )
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
  Retry,
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
    Code::ResourceExhausted => CoordinatorAction::Retry,
    Code::Internal | Code::Unknown => CoordinatorAction::RemoveEndorser,
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
    num_grpc_channels_opt: Option<usize>,
  ) -> Result<CoordinatorState, CoordinatorError> {
    let num_grpc_channels = match num_grpc_channels_opt {
      Some(n) => n,
      None => DEFAULT_NUM_GRPC_CHANNELS,
    };
    let coordinator = match ledger_store_type {
      "mongodb_cosmos" => CoordinatorState {
        ledger_store: Arc::new(Box::new(MongoCosmosLedgerStore::new(args).await.unwrap())),
        conn_map: Arc::new(RwLock::new(HashMap::new())),
        verifier_state: Arc::new(RwLock::new(VerifierState::new())),
        num_grpc_channels,
        _used_nonces: Arc::new(RwLock::new(HashSet::new())),
      },
      "table" => CoordinatorState {
        ledger_store: Arc::new(Box::new(TableLedgerStore::new(args).await.unwrap())),
        conn_map: Arc::new(RwLock::new(HashMap::new())),
        verifier_state: Arc::new(RwLock::new(VerifierState::new())),
        num_grpc_channels,
        _used_nonces: Arc::new(RwLock::new(HashSet::new())),
      },
      "filestore" => CoordinatorState {
        ledger_store: Arc::new(Box::new(FileStore::new(args).await.unwrap())),
        conn_map: Arc::new(RwLock::new(HashMap::new())),
        verifier_state: Arc::new(RwLock::new(VerifierState::new())),
        num_grpc_channels,
        _used_nonces: Arc::new(RwLock::new(HashSet::new())),
      },
      _ => CoordinatorState {
        ledger_store: Arc::new(Box::new(InMemoryLedgerStore::new())),
        conn_map: Arc::new(RwLock::new(HashMap::new())),
        verifier_state: Arc::new(RwLock::new(VerifierState::new())),
        num_grpc_channels,
        _used_nonces: Arc::new(RwLock::new(HashSet::new())),
      },
    };

    let res = coordinator.ledger_store.read_view_ledger_tail().await;
    if res.is_err() {
      eprintln!("Failed to read the view ledger tail {:?}", res);
      return Err(CoordinatorError::FailedToReadViewLedger);
    }

    let (view_ledger_tail, tail_height) = res.unwrap();

    if tail_height > 0 {
      let view_ledger_head = if tail_height == 1 {
        view_ledger_tail.clone()
      } else {
        let res = coordinator
          .ledger_store
          .read_view_ledger_by_index(1usize)
          .await;
        match res {
          Ok(l) => l,
          Err(e) => {
            eprintln!("Failed to read the view ledger head {:?}", e);
            return Err(CoordinatorError::FailedToReadViewLedger);
          },
        }
      };
      if let Ok(mut vs) = coordinator.verifier_state.write() {
        vs.set_group_identity(view_ledger_head.get_block().hash());
      } else {
        return Err(CoordinatorError::FailedToAcquireWriteLock);
      }

      // Connect to current endorsers
      let curr_endorsers = coordinator
        .connect_to_existing_endorsers(&view_ledger_tail.get_block().to_bytes())
        .await?;

      // Check if the latest view change was completed
      let res = if let Ok(mut vs) = coordinator.verifier_state.write() {
        vs.apply_view_change(
          &view_ledger_tail.get_block().to_bytes(),
          &view_ledger_tail.get_receipts().to_bytes(),
          Some(ATTESTATION_STR.as_bytes()),
        )
      } else {
        return Err(CoordinatorError::FailedToAcquireWriteLock);
      };
      if let Err(error) = res {
        // Collect receipts again!
        if error == VerificationError::InsufficientReceipts {
          let res = coordinator
            .ledger_store
            .read_view_ledger_by_index(tail_height - 1)
            .await;
          if res.is_err() {
            eprintln!(
              "Failed to read the view ledger entry at index {} ({:?})",
              tail_height - 1,
              res
            );
            return Err(CoordinatorError::FailedToReadViewLedger);
          }
          let prev_view_ledger_entry = res.unwrap();
          let prev_endorsers = coordinator
            .connect_to_existing_endorsers(&prev_view_ledger_entry.get_block().to_bytes())
            .await?;
          let res = coordinator
            .apply_view_change(
              &prev_endorsers,
              &curr_endorsers,
              &prev_view_ledger_entry,
              view_ledger_tail.get_block(),
              tail_height,
            )
            .await;
          if let Err(error) = res {
            eprintln!("Failed to re-apply view change {:?}", error);
            return Err(error);
          }
        } else {
          eprintln!(
            "Failed to apply view change at the tail {} ({:?})",
            tail_height, error
          );
          return Err(CoordinatorError::FailedToActivate);
        }
      }

      // Remove endorsers that don't have the latest view
      let res = coordinator
        .filter_endorsers(&curr_endorsers, tail_height)
        .await;
      if let Err(error) = res {
        eprintln!(
          "Failed to filter the endorsers with the latest view {:?}",
          error
        );
        return Err(error);
      }
    }

    for idx in (1..tail_height).rev() {
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
        // Set group identity
        if idx == 1 {
          vs.set_group_identity(view_ledger_entry.get_block().hash());
        }
        let res = vs.apply_view_change(
          &view_ledger_entry.get_block().to_bytes(),
          &view_ledger_entry.get_receipts().to_bytes(),
          None,
        );
        if res.is_err() {
          eprintln!("Failed to apply view change at index {} ({:?})", idx, res);
          return Err(CoordinatorError::FailedToActivate);
        }
      } else {
        return Err(CoordinatorError::FailedToAcquireWriteLock);
      }
    }

    // let coordinator_clone = coordinator.clone();
    // let mut scheduler = clokwerk::AsyncScheduler::new ();
    // scheduler.every(ENDORSER_REFRESH_PERIOD.seconds()).run( move || {
    //   let value = coordinator_clone.clone();
    //   async move {value.ping_all_endorsers().await}
    // });
    // println!("Started the scheduler");

    Ok(coordinator)
  }

  pub async fn start_auto_scheduler(self: Arc<Self>) {
    let mut scheduler = clokwerk::AsyncScheduler::new();
    scheduler
      .every(PING_INTERVAL.load(SeqCst).seconds())
      .run(move || {
        let value = self.clone();
        async move { value.ping_all_endorsers().await }
      });

    tokio::spawn(async move {
      loop {
        scheduler.run_pending().await;
        tokio::time::sleep(Duration::from_millis(100)).await;
      }
    });
    println!("Started the scheduler");
  }

  async fn connect_to_existing_endorsers(
    &self,
    view_ledger_block: &[u8],
  ) -> Result<EndorserHostnames, CoordinatorError> {
    let res = bincode::deserialize(view_ledger_block);
    if res.is_err() {
      eprintln!(
        "Failed to deserialize the view ledger tail's genesis block {:?}",
        res
      );
      return Err(CoordinatorError::FailedToSerde);
    }
    let endorser_hostnames: EndorserHostnames = res.unwrap();

    let mut endorsers = EndorserHostnames::new();

    for (pk, uri) in &endorser_hostnames {
      let pks = self.connect_endorsers(&[uri.clone()]).await;
      if pks.len() == 1 && pks[0].0 == *pk {
        endorsers.push((pk.clone(), uri.clone()));
      }
    }

    Ok(endorsers)
  }

  fn get_endorser_client(
    &self,
    pk: &[u8],
  ) -> Option<(
    endorser_proto::endorser_call_client::EndorserCallClient<Channel>,
    String,
  )> {
    if let Ok(conn_map_rd) = self.conn_map.read() {
      let e = conn_map_rd.get(pk);
      match e {
        None => {
          eprintln!("No endorser has this public key {:?}", pk);
          None
        },
        Some(v) => Some((
          v.clients[random::<usize>() % self.num_grpc_channels].clone(),
          v.uri.clone(),
        )),
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
        .map(|(pk, _endorser)| pk.clone())
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
        .map(|(_pk, endorser)| endorser.uri.clone())
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
        .map(|(pk, endorser)| (pk.clone(), endorser.uri.clone()))
        .collect::<Vec<(Vec<u8>, String)>>()
    } else {
      eprintln!("Failed to acquire read lock");
      Vec::new()
    }
  }

  pub fn get_endorser_pk(&self, hostname: &str) -> Option<Vec<u8>> {
    if let Ok(conn_map_rd) = self.conn_map.read() {
      for (pk, endorser) in conn_map_rd.iter() {
        if endorser.uri == hostname {
          return Some(pk.clone());
        }
      }
    }
    None
  }

  pub async fn connect_endorsers(&self, hostnames: &[String]) -> EndorserHostnames {
    let (mpsc_tx, mut mpsc_rx) = mpsc::channel(ENDORSER_MPSC_CHANNEL_BUFFER);
    for hostname in hostnames {
      for _idx in 0..self.num_grpc_channels {
        let tx = mpsc_tx.clone();
        let endorser = hostname.clone();

        let _job = tokio::spawn(async move {
          let res = Endpoint::from_shared(endorser.to_string());
          if let Ok(endorser_endpoint) = res {
            let endorser_endpoint = endorser_endpoint
              .connect_timeout(std::time::Duration::from_secs(ENDORSER_CONNECT_TIMEOUT));
            let endorser_endpoint = endorser_endpoint.timeout(std::time::Duration::from_secs(
              ENDORSER_REQUEST_TIMEOUT.load(SeqCst),
            ));
            let res = endorser_endpoint.connect().await;
            if let Ok(channel) = res {
              let mut client =
                endorser_proto::endorser_call_client::EndorserCallClient::new(channel);

              let res =
                get_public_key_with_retry(&mut client, endorser_proto::GetPublicKeyReq {}).await;
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
          let e = conn_map_wr.get_mut(&pk);
          match e {
            None => {
              endorser_hostnames.push((pk.clone(), endorser.clone()));
              let mut endorser_clients = EndorserClients {
                clients: Vec::new(),
                uri: endorser,
                failures: 0,
                usage_state: EndorserUsageState::Uninitialized,
              };
              endorser_clients.clients.push(client);
              conn_map_wr.insert(pk, endorser_clients);
            },
            Some(v) => {
              v.clients.push(client);
            },
          };
        } else {
          eprintln!("Failed to acquire the conn_map write lock");
        }
      }
    }

    endorser_hostnames
  }

  pub async fn disconnect_endorsers(&self, endorsers: &EndorserHostnames) {
    if let Ok(mut conn_map_wr) = self.conn_map.write() {
      for (pk, uri) in endorsers {
        let res = conn_map_wr.remove_entry(pk);
        if let Some((_pk, mut endorser)) = res {
          for _idx in 0..self.num_grpc_channels {
            let client = endorser.clients.pop();
            drop(client);
          }
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
        let res =
          read_state_with_retry(&mut endorser_client, endorser_proto::ReadStateReq {}).await;
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
    group_identity: &NimbleDigest,
    endorsers: &EndorserHostnames,
    ledger_tail_map: Vec<endorser_proto::LedgerTailMapEntry>,
    view_tail_metablock: &MetaBlock,
    block_hash: &NimbleDigest,
    expected_height: usize,
  ) -> Receipts {
    let (mpsc_tx, mut mpsc_rx) = mpsc::channel(ENDORSER_MPSC_CHANNEL_BUFFER);
    let ledger_tail_map_arc = Arc::new(ledger_tail_map);
    for (pk, _uri) in endorsers {
      let (mut endorser_client, endorser) = match self.get_endorser_client(pk) {
        Some((client, endorser)) => (client, endorser),
        None => continue,
      };

      let tx = mpsc_tx.clone();
      let ledger_tail_map_arc_copy = ledger_tail_map_arc.clone();
      let view_tail_metablock_bytes = view_tail_metablock.to_bytes().to_vec();
      let block_hash_copy = block_hash.to_bytes();
      let pk_bytes = pk.clone();
      let group_identity_copy = (*group_identity).to_bytes();
      let _job = tokio::spawn(async move {
        let res = initialize_state_with_retry(
          &mut endorser_client,
          group_identity_copy,
          ledger_tail_map_arc_copy,
          view_tail_metablock_bytes,
          block_hash_copy,
          expected_height,
        )
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
            Ok(receipt_rs) => {
              receipts.add(&receipt_rs);
              if let Ok(mut conn_map_wr) = self.conn_map.write() {
                let e = conn_map_wr.get_mut(&pk_bytes);
                match e {
                  None => eprintln!("Couldn't find Endorser in conn_map"),
                  Some(v) => v.usage_state = EndorserUsageState::Initialized,
                }
              } else {
                eprintln!("Couldn't get write lock on conn_map");
              }
            },
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

    receipts
  }

  async fn endorser_create_ledger(
    &self,
    endorsers: &[Vec<u8>],
    ledger_handle: &Handle,
    ledger_block_hash: &NimbleDigest,
    ledger_block: Block,
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
      let block = ledger_block.clone();
      let pk_bytes = pk.clone();
      let _job = tokio::spawn(async move {
        let res = new_ledger_with_retry(
          &mut endorser_client,
          endorser_proto::NewLedgerReq {
            handle: handle.to_bytes(),
            block_hash: block_hash.to_bytes(),
            block: block.to_bytes(),
          },
        )
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
    block: Block,
    nonces: Nonces,
  ) -> Result<Receipts, CoordinatorError> {
    let (mpsc_tx, mut mpsc_rx) = mpsc::channel(ENDORSER_MPSC_CHANNEL_BUFFER);

    for pk in endorsers {
      let (mut endorser_client, endorser) = match self.get_endorser_client(pk) {
        Some((client, endorser)) => (client, endorser),
        None => continue,
      };

      let tx = mpsc_tx.clone();
      let handle = *ledger_handle;
      let block_hash_copy = *block_hash;
      let block_copy = block.clone();
      let nonces_copy = nonces.clone();
      let pk_bytes = pk.clone();
      let ledger_store = self.ledger_store.clone();
      let _job = tokio::spawn(async move {
        loop {
          let res = append_with_retry(
            &mut endorser_client,
            endorser_proto::AppendReq {
              handle: handle.to_bytes(),
              block_hash: block_hash_copy.to_bytes(),
              expected_height: expected_height as u64,
              block: block_copy.to_bytes(),
              nonces: nonces_copy.to_bytes(),
            },
          )
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
                  &mut endorser_client,
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
      let (mut endorser_client, endorser) = match self.get_endorser_client(pk) {
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
          &mut endorser_client,
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
  ) -> Result<LedgerEntry, CoordinatorError> {
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
        let res = read_latest_with_retry(
          &mut endorser_client,
          endorser_proto::ReadLatestReq {
            handle: handle.to_bytes(),
            nonce: nonce.to_bytes(),
          },
        )
        .await;
        match res {
          Ok(resp) => {
            let endorser_proto::ReadLatestResp {
              receipt,
              block,
              nonces,
            } = resp.into_inner();
            let _ = tx
              .send((endorser, pk_bytes, Ok((receipt, block, nonces))))
              .await;
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
        Ok((receipt, block, nonces)) => match Receipt::from_bytes(&receipt) {
          Ok(receipt_rs) => {
            let height = receipt_rs.get_height();
            endorser_height_map.insert(endorser, height);
            if max_height < height {
              max_height = height;
            }
            receipts.add(&receipt_rs);
            if let Ok(vs) = self.verifier_state.read() {
              if let Ok(_h) = receipts.check_quorum(&vs) {
                if let Ok(block_rs) = Block::from_bytes(&block) {
                  if let Ok(nonces_rs) = Nonces::from_bytes(&nonces) {
                    return Ok(LedgerEntry::new(block_rs, receipts, Some(nonces_rs)));
                  }
                }
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
  ) -> (Receipts, Vec<endorser_proto::LedgerTailMap>) {
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
        let res = finalize_state_with_retry(
          &mut endorser_client,
          endorser_proto::FinalizeStateReq {
            block_hash: block.to_bytes(),
            expected_height: expected_height as u64,
          },
        )
        .await;
        let _ = tx.send((endorser, pk_bytes, res)).await;
      });
    }

    drop(mpsc_tx);

    let mut receipts = Receipts::new();
    let mut ledger_tail_maps = Vec::new();
    let mut state_hashes = HashSet::new();

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
              if let Ok(mut conn_map_wr) = self.conn_map.write() {
                match conn_map_wr.get_mut(&pk_bytes) {
                  None => eprintln!("Endorser wasn't in conn_map during finalization."),
                  Some(e) => e.usage_state = EndorserUsageState::Finalized,
                }
              } else {
                eprint!("Couldn't get write lock on conn_map");
              }
              receipt_rs
            },
            Err(error) => {
              eprintln!("Failed to parse a receipt ({:?})", error);
              continue;
            },
          };
          if !state_hashes.contains(receipt_rs.get_view()) {
            ledger_tail_maps.push(endorser_proto::LedgerTailMap {
              entries: ledger_tail_map,
            });
            state_hashes.insert(*receipt_rs.get_view());
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

    (receipts, ledger_tail_maps)
  }

  async fn endorser_verify_view_change(
    &self,
    endorsers: &EndorserHostnames,
    old_config: Block,
    new_config: Block,
    ledger_tail_maps: Vec<endorser_proto::LedgerTailMap>,
    ledger_chunks: Vec<endorser_proto::LedgerChunkEntry>,
    receipts: &Receipts,
  ) -> usize {
    let (mpsc_tx, mut mpsc_rx) = mpsc::channel(ENDORSER_MPSC_CHANNEL_BUFFER);
    let ledger_tail_maps_arc = Arc::new(ledger_tail_maps);

    for (pk, _uri) in endorsers {
      let (mut endorser_client, endorser) = match self.get_endorser_client(pk) {
        Some((client, endorser)) => (client, endorser),
        None => continue,
      };

      let tx = mpsc_tx.clone();
      let pk_bytes = pk.clone();
      let old_config_copy = old_config.clone();
      let new_config_copy = new_config.clone();
      let ledger_tail_maps_arc_copy = ledger_tail_maps_arc.clone();
      let ledger_chunks_copy = ledger_chunks.clone();
      let receipts_copy = receipts.to_bytes();
      let _job = tokio::spawn(async move {
        let res = activate_with_retry(
          &mut endorser_client,
          old_config_copy.to_bytes(),
          new_config_copy.to_bytes(),
          ledger_tail_maps_arc_copy,
          ledger_chunks_copy,
          receipts_copy,
        )
        .await;
        let _ = tx.send((endorser, pk_bytes, res)).await;
      });
    }

    drop(mpsc_tx);

    let mut num_verified_endorers = 0;

    // TODO: Better error handling here
    while let Some((endorser, pk_bytes, res)) = mpsc_rx.recv().await {
      match res {
        Ok(_resp) => {
          if let Ok(mut conn_map_wr) = self.conn_map.write() {
            let e = conn_map_wr.get_mut(&pk_bytes);
            match e {
              None => {
                eprintln!("Couldn't find endorser in conn_map");
              },
              Some(v) => {
                v.usage_state = EndorserUsageState::Active;
              },
            }
          } else {
            eprintln!("Couldn't get write lock on conn_map");
          }
          num_verified_endorers += 1;
        },
        Err(status) => {
          eprintln!(
            "Failed to prove view change to endorser {} (status={:?})",
            endorser, status
          );
          if let CoordinatorAction::RemoveEndorser = process_error(&endorser, None, &status) {
            self.disconnect_endorsers(&vec![(pk_bytes, endorser)]).await;
          }
        },
      }
    }
    num_verified_endorers
  }

  pub async fn replace_endorsers(&self, hostnames: &[String]) -> Result<(), CoordinatorError> {
    // TODO: Make the new stuff optional
    let existing_endorsers = self.get_endorser_uris();

    // Check if hostnames contains endorsers that are not in existing_endorsers.
    // If yes, connect to those and then continue
    // Once done, select the new endorser quorum from the conn_map and reconfigure

    if !hostnames.is_empty() {
      // Filter out those endorsers which haven't been connected to, yet and connect to them.
      let mut added_endorsers: Vec<String> = hostnames.to_vec();
      added_endorsers.retain(|x| !existing_endorsers.contains(x));

      let added_endorsers = self.connect_endorsers(&added_endorsers).await;
      // After the previous ^ line the new endorsers are in the conn_map as uninitialized
      if added_endorsers.is_empty() {
        // This is not an error as long as there are enough qualified endorsers already connected
        println!("New endorsers couldn't be reached");
      } else {
        println!("Connected to new endorsers");
      }
    }

    // Now all available endorsers are in the conn_map, so we select the new quorum from
    //there

    let mut new_endorsers: EndorserHostnames;
    let old_endorsers: EndorserHostnames;

    if let Ok(conn_map_rd) = self.conn_map.read() {
      new_endorsers = conn_map_rd
        .iter()
        .filter(|(_pk, endorser)| {
          matches!(endorser.usage_state, EndorserUsageState::Uninitialized)
            && endorser.failures == 0
        })
        .map(|(pk, endorser)| (pk.clone(), endorser.uri.clone()))
        .collect();

      old_endorsers = conn_map_rd
        .iter()
        .filter(|(_pk, endorser)| matches!(endorser.usage_state, EndorserUsageState::Active))
        .map(|(pk, endorser)| (pk.clone(), endorser.uri.clone()))
        .collect();
      if new_endorsers.is_empty() {
        eprintln!("No eligible endorsers");
        return Err(CoordinatorError::FailedToObtainQuorum);
      }

      // TODO: Replace with better selection method
      println!("Desired quorum size: {}", DESIRED_QUORUM_SIZE.load(SeqCst));
      new_endorsers.truncate(DESIRED_QUORUM_SIZE.load(SeqCst).try_into().unwrap());
    } else {
      eprintln!("Couldn't get read lock on conn_map");
      return Err(CoordinatorError::FailedToAcquireReadLock);
    }

    for (_pk, uri) in &new_endorsers {
      println!("New endorser URI: {}", uri);
    }

    DEAD_ENDORSERS.store(0, SeqCst);

    // At this point new_endorsers should contain the hostnames of the new quorum
    // and old_endorsers should contain the currently active quorum

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
    println!("created view ledger genesis block");
    // Read the current ledger tail
    let res = self.ledger_store.read_view_ledger_tail().await;

    if res.is_err() {
      eprintln!(
        "Failed to read from the view ledger in the ledger store ({:?})",
        res.unwrap_err()
      );
      return Err(CoordinatorError::FailedToCallLedgerStore);
    }
    println!("read view ledger tail");
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
    println!("appended view ledger genesis block");
    let view_ledger_height = res.unwrap();

    self
      .apply_view_change(
        &old_endorsers,
        &new_endorsers,
        &tail,
        &view_ledger_genesis_block,
        view_ledger_height,
      )
      .await
  }

  async fn apply_view_change(
    &self,
    existing_endorsers: &EndorserHostnames,
    new_endorsers: &EndorserHostnames,
    view_ledger_entry: &LedgerEntry,
    view_ledger_genesis_block: &Block,
    view_ledger_height: usize,
  ) -> Result<(), CoordinatorError> {
    // Retrieve the view tail metablock
    let view_tail_receipts = view_ledger_entry.get_receipts();
    let view_tail_metablock = if view_tail_receipts.is_empty() {
      if view_ledger_height != 1 {
        eprintln!(
          "cannot get view tail metablock from empty receipts (height = {}",
          view_ledger_height
        );
        return Err(CoordinatorError::UnexpectedError);
      } else {
        MetaBlock::default()
      }
    } else {
      let res = view_tail_receipts.get_metablock();
      match res {
        Ok(metablock) => metablock,
        Err(_e) => {
          eprintln!("failed to retrieve metablock from view receipts");
          return Err(CoordinatorError::UnexpectedError);
        },
      }
    };

    let (finalize_receipts, ledger_tail_maps) = if existing_endorsers.is_empty() {
      assert!(view_ledger_height == 1);

      (Receipts::new(), Vec::new())
    } else {
      self
        .endorser_finalize_state(
          existing_endorsers,
          &view_ledger_genesis_block.hash(),
          view_ledger_height,
        )
        .await
    };

    // Compute the max cut
    let max_cut = compute_max_cut(&ledger_tail_maps);

    // Set group identity if necessary
    let group_identity = if view_ledger_height == 1 {
      let id = view_ledger_genesis_block.hash();
      if let Ok(mut vs) = self.verifier_state.write() {
        vs.set_group_identity(id);
        id
      } else {
        return Err(CoordinatorError::FailedToAcquireWriteLock);
      }
    } else if let Ok(vs) = self.verifier_state.read() {
      *vs.get_group_identity()
    } else {
      return Err(CoordinatorError::FailedToAcquireReadLock);
    };

    // Initialize new endorsers
    let initialize_receipts = self
      .endorser_initialize_state(
        &group_identity,
        new_endorsers,
        max_cut,
        &view_tail_metablock,
        &view_ledger_genesis_block.hash(),
        view_ledger_height,
      )
      .await;

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

    // Retrieve blocks that need for verifying the view change
    let cut_diffs = compute_cut_diffs(&ledger_tail_maps);
    let mut ledger_chunks: Vec<endorser_proto::LedgerChunkEntry> = Vec::new();
    for cut_diff in &cut_diffs {
      if cut_diff.low == cut_diff.high {
        continue;
      }
      let mut block_hashes: Vec<Vec<u8>> =
        Vec::with_capacity((cut_diff.high - cut_diff.low) as usize);
      let h = NimbleDigest::from_bytes(&cut_diff.handle).unwrap();
      for index in (cut_diff.low + 1)..=cut_diff.high {
        let res = self
          .ledger_store
          .read_ledger_by_index(&h, index as usize)
          .await;
        if let Err(e) = res {
          eprintln!("Failed to read the ledger store {:?}", e);
          return Err(CoordinatorError::FailedToCallLedgerStore);
        }
        let ledger_entry = res.unwrap();
        let block_hash = compute_aggregated_block_hash(
          &ledger_entry.get_block().hash().to_bytes(),
          &ledger_entry.get_nonces().hash().to_bytes(),
        );
        block_hashes.push(block_hash.to_bytes());
      }
      ledger_chunks.push(endorser_proto::LedgerChunkEntry {
        handle: cut_diff.handle.clone(),
        hash: cut_diff.hash.to_bytes(),
        height: cut_diff.low as u64,
        block_hashes,
      });
    }

    let num_verified_endorsers = self
      .endorser_verify_view_change(
        new_endorsers,
        view_ledger_entry.get_block().clone(),
        view_ledger_genesis_block.clone(),
        ledger_tail_maps,
        ledger_chunks,
        &receipts,
      )
      .await;
    // TODO: Change this line? Would allow to use a smaller quorum if not enough eligble endorsers
    // are available
    if num_verified_endorsers * 2 <= new_endorsers.len() {
      eprintln!(
        "insufficient verified endorsers {} * 2 <= {}",
        num_verified_endorsers,
        new_endorsers.len()
      );
    }

    // Apply view change to the verifier state
    if let Ok(mut vs) = self.verifier_state.write() {
      if let Err(e) = vs.apply_view_change(
        &view_ledger_genesis_block.to_bytes(),
        &receipts.to_bytes(),
        Some(ATTESTATION_STR.as_bytes()),
      ) {
        eprintln!("Failed to apply view change: {:?}", e);
      }
    } else {
      return Err(CoordinatorError::FailedToAcquireWriteLock);
    }

    // Disconnect existing endorsers
    self.disconnect_endorsers(existing_endorsers).await;

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

    let hash_block = genesis_block.hash();
    let hash_nonces = Nonces::new().hash();
    let block_hash = compute_aggregated_block_hash(&hash_block.to_bytes(), &hash_nonces.to_bytes());

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
        .endorser_create_ledger(&endorsers, &handle, &block_hash, genesis_block)
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
        .endorser_append_ledger(
          &endorsers,
          &handle,
          &block_hash,
          actual_height,
          data_block,
          nonces,
        )
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
    self
      .endorser_read_ledger_tail(&endorsers, handle, nonce)
      .await
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

  pub async fn read_view_tail(&self) -> Result<(LedgerEntry, usize, Vec<u8>), CoordinatorError> {
    let res = self.ledger_store.read_view_ledger_tail().await;
    if let Err(error) = res {
      eprintln!(
        "Failed to read the view ledger tail from the ledger store {:?}",
        error,
      );
      return Err(CoordinatorError::FailedToReadViewLedger);
    }

    let (ledger_entry, height) = res.unwrap();
    Ok((ledger_entry, height, ATTESTATION_STR.as_bytes().to_vec()))
  }

  pub async fn ping_all_endorsers(self: Arc<Self>) {
    println!("Pinging all endorsers from coordinator_state");
    let hostnames = self.get_endorser_hostnames();
    let (mpsc_tx, mut mpsc_rx) = mpsc::channel(ENDORSER_MPSC_CHANNEL_BUFFER);

    for (pk, hostname) in hostnames {
      let tx = mpsc_tx.clone();
      let endorser = hostname.clone();
      let endorser_key = pk.clone();
      let conn_map = self.conn_map.clone();
      let self_c = self.clone();

      let _job = tokio::spawn(async move {
        let nonce = generate_secure_nonce_bytes(16); // Nonce is a randomly generated with 16B length
                                                     //TODO Save the nonce for replay protection
                                                     // Create a connection endpoint

        let endpoint = Endpoint::from_shared(endorser.to_string());
        match endpoint {
          Ok(endpoint) => {
            let endpoint = endpoint
              .connect_timeout(Duration::from_secs(ENDORSER_CONNECT_TIMEOUT))
              .timeout(Duration::from_secs(ENDORSER_REQUEST_TIMEOUT.load(SeqCst)));

            match endpoint.connect().await {
              Ok(channel) => {
                let mut client =
                  endorser_proto::endorser_call_client::EndorserCallClient::new(channel);

                // Include the nonce in the request
                let ping_req = endorser_proto::PingReq {
                  nonce: nonce.clone(), // Send the nonce in the request
                  ..Default::default() // Set other fields to their default values (in this case, none)
                };

                // Call the method with retry logic
                let res = get_ping_with_retry(&mut client, ping_req).await;
                match res {
                  Ok(resp) => {
                    let endorser_proto::PingResp { id_sig } = resp.into_inner();
                    match IdSig::from_bytes(&id_sig) {
                      Ok(id_signature) => {
                        let id_pubkey = id_signature.get_id();
                        if *id_pubkey != endorser_key {
                          let error_message = format!(
                            "Endorser public_key mismatch. Expected {:?}, got {:?}",
                            endorser_key, id_pubkey
                          );
                          self_c
                            .endorser_ping_failed(endorser.clone(), &error_message, endorser_key)
                            .await;
                          return;
                        }

                        // Verify the signature with the original nonce
                        if id_signature.verify(&nonce).is_ok() {
                          // TODO: Replace println with info
                          println!("Nonce match for endorser: {}", endorser); //HERE If the nonce matched

                          if let Ok(mut conn_map_wr) = conn_map.write() {
                            if let Some(endorser_clients) = conn_map_wr.get_mut(&endorser_key) {
                              if endorser_clients.failures > 0 {
                                // Only update DEAD_ENDORSERS if endorser_client is part of the
                                // quorum and has previously been marked as unavailable
                                if endorser_clients.failures > MAX_FAILURES.load(SeqCst)
                                  && matches!(
                                    endorser_clients.usage_state,
                                    EndorserUsageState::Active
                                  )
                                {
                                  DEAD_ENDORSERS.fetch_sub(1, SeqCst);
                                }
                                println!(
                                  "Endorser {} reconnected after {} tries",
                                  endorser, endorser_clients.failures
                                );
                                // Reset failures on success
                                endorser_clients.failures = 0;
                                // TODO: Replace println with info
                              }
                            } else {
                              eprintln!("Endorser key not found in conn_map");
                            }
                          } else {
                            eprintln!("Failed to acquire write lock on conn_map");
                          }
                        } else {
                          let error_message = format!(
                            "Nonce did not match. Expected {:?}, got {:?}",
                            nonce, id_signature
                          );
                          self_c
                            .endorser_ping_failed(endorser.clone(), &error_message, endorser_key)
                            .await;
                        }
                      },
                      Err(_) => {
                        let error_message = format!("Failed to decode IdSig.");
                        self_c
                          .endorser_ping_failed(endorser.clone(), &error_message, endorser_key)
                          .await;
                      },
                    }
                  },
                  Err(status) => {
                    let error_message = format!(
                      "Failed to connect to the endorser {}: {:?}.",
                      endorser, status
                    );
                    self_c
                      .endorser_ping_failed(endorser.clone(), &error_message, endorser_key)
                      .await;
                  },
                }
              },
              Err(err) => {
                let error_message =
                  format!("Failed to connect to the endorser {}: {:?}.", endorser, err);
                self_c
                  .endorser_ping_failed(endorser.clone(), &error_message, endorser_key)
                  .await;
              },
            }
          },
          Err(err) => {
            error!(
              "Failed to resolve the endorser host name {}: {:?}",
              endorser, err
            );
            if let Err(_) = tx
              .send((
                endorser.clone(),
                Err::<
                  (
                    endorser_proto::endorser_call_client::EndorserCallClient<Channel>,
                    Vec<u8>,
                  ),
                  CoordinatorError,
                >(CoordinatorError::CannotResolveHostName),
              ))
              .await
            {
              error!("Failed to send failure result for endorser: {}", endorser);
            }
          },
        }
      });
    }

    drop(mpsc_tx);

    // Receive results from the channel and process them
    while let Some((endorser, res)) = mpsc_rx.recv().await {
      match res {
        Ok((_client, _pk)) => {
          // Process the client and public key
        },
        Err(_) => {
          // TODO: Call endorser refresh for "client"
          // Change to error!
          error!("Endorser {} needs to be refreshed", endorser);
        },
      }
    }
  }

  pub async fn endorser_ping_failed(
    self: Arc<Self>,
    endorser: String,
    error_message: &str,
    endorser_key: Vec<u8>,
  ) {
    if let Ok(mut conn_map_wr) = self.conn_map.write() {
      if let Some(endorser_clients) = conn_map_wr.get_mut(&endorser_key) {
        // Increment the failures count
        endorser_clients.failures += 1;
      } else {
        eprintln!("Endorser key not found in conn_map");
      }
    } else {
      eprintln!("Failed to acquire write lock on conn_map");
    }

    let mut alive_endorser_percentage = 100;

    if let Ok(conn_map_r) = self.conn_map.read() {
      if let Some(endorser_clients) = conn_map_r.get(&endorser_key) {
        // Log the failure
        // TODO: Replace with warn!
        println!(
          "Ping failed for endorser {}. {} pings failed.\n{}",
          endorser, endorser_clients.failures, error_message
        );

        // Only count towards allowance if it first crosses the boundary
        if matches!(endorser_clients.usage_state, EndorserUsageState::Active)
          && endorser_clients.failures >= MAX_FAILURES.load(SeqCst) + 1
        {
          // Increment dead endorser count
          if matches!(endorser_clients.usage_state, EndorserUsageState::Active)
          && endorser_clients.failures == MAX_FAILURES.load(SeqCst) + 1 {
            DEAD_ENDORSERS.fetch_add(1, SeqCst);
          }

          println!(
            "Active endorser {} failed more than {} times! Now {} endorsers are dead.",
            endorser,
            MAX_FAILURES.load(SeqCst),
            DEAD_ENDORSERS.load(SeqCst)
          );

          let active_endorsers_count = conn_map_r
            .values()
            .filter(|&e| matches!(e.usage_state, EndorserUsageState::Active))
            .count();
          let dead_endorsers_count = DEAD_ENDORSERS.load(SeqCst);
          println!("Debug: active_endorsers_count = {}", active_endorsers_count);
          println!("Debug: dead_endorsers_count = {}", dead_endorsers_count);
          alive_endorser_percentage = 100 - ((dead_endorsers_count * 100) / active_endorsers_count);
          println!("Debug: {} % alive", alive_endorser_percentage);
        }
      } else {
        eprintln!("Endorser key not found in conn_map");
      }
    } else {
      eprintln!("Failed to acquire read lock on conn_map");
    }

    println!("Debug: {} % alive before replace trigger", alive_endorser_percentage);

    if alive_endorser_percentage < ENDORSER_DEAD_ALLOWANCE.load(SeqCst).try_into().unwrap() {
      println!("Enough Endorsers have failed now. Endorser replacement triggered");
      println!("DESIRED_QUORUM_SIZE: {}", DESIRED_QUORUM_SIZE.load(SeqCst));
      match self.replace_endorsers(&[]).await {
        Ok(_) => (),
        Err(_) => eprintln!("Endorser replacement failed"),
      }
    }
  }

  pub fn get_timeout_map(&self) -> Result<HashMap<String, u64>, CoordinatorError> {
    if let Ok(conn_map_rd) = self.conn_map.read() {
      let mut timeout_map = HashMap::new();
      for (_pk, endorser_clients) in conn_map_rd.iter() {
        // Convert Vec<u8> to String (assuming UTF-8 encoding)
        timeout_map.insert(endorser_clients.uri.clone(), endorser_clients.failures);
      }
      Ok(timeout_map)
    } else {
      eprintln!("Failed to acquire read lock on conn_map");
      Err(CoordinatorError::FailedToGetTimeoutMap)
    }
  }

  pub fn overwrite_variables(
    &mut self,
    max_failures: u64,
    request_timeout: u64,
    min_alive_percentage: u64,
    quorum_size: u64,
    ping_interval: u32,
    deactivate_auto_reconfig: bool,
  ) {
    MAX_FAILURES.store(max_failures, SeqCst);
    ENDORSER_REQUEST_TIMEOUT.store(request_timeout, SeqCst);
    ENDORSER_DEAD_ALLOWANCE.store(min_alive_percentage, SeqCst);
    DESIRED_QUORUM_SIZE.store(quorum_size, SeqCst);
    PING_INTERVAL.store(ping_interval, SeqCst);
    DEACTIVATE_AUTO_RECONFIG.store(deactivate_auto_reconfig, SeqCst);
  }
}

fn generate_secure_nonce_bytes(size: usize) -> Vec<u8> {
  let mut rng = rand::thread_rng();
  let nonce: Vec<u8> = (0..size).map(|_| rng.gen()).collect();
  nonce
}
