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
use store::{
  in_memory::InMemoryLedgerStore, mongodb_cosmos::MongoCosmosLedgerStore, LedgerEntry, LedgerStore,
};
use tokio::sync::mpsc;
use tonic::{
  transport::{Channel, Endpoint},
  Code,
};

pub mod endorser_proto {
  tonic::include_proto!("endorser_proto");
}

use endorser_proto::endorser_call_client::EndorserCallClient;

type EndorserConnMap = HashMap<Vec<u8>, (EndorserCallClient<Channel>, String)>;

type LedgerStoreRef = Arc<Box<dyn LedgerStore + Send + Sync>>;

pub struct CoordinatorState {
  ledger_store: LedgerStoreRef,
  conn_map: Arc<RwLock<EndorserConnMap>>,
}

const ENDORSER_MPSC_CHANNEL_BUFFER: usize = 8; // limited by the number of endorsers

async fn update_endorser(
  ledger_store: LedgerStoreRef,
  mut endorser_client: EndorserCallClient<Channel>,
  handle: NimbleDigest,
  start: usize,
  end: usize,
  ignore_lock: bool,
) -> Result<(), CoordinatorError> {
  for idx in start..=end {
    let ledger_entry = {
      let res = ledger_store.read_ledger_by_index(&handle, idx).await;
      if res.is_err() {
        eprintln!("Failed to read ledger by index {:?}", res);
        return Err(CoordinatorError::FailedToReadLedger);
      }
      res.unwrap()
    };

    let receipt = if idx == 0 {
      let res = endorser_client
        .new_ledger(tonic::Request::new(endorser_proto::NewLedgerReq {
          handle: handle.to_bytes(),
          block_hash: ledger_entry.get_block().hash().to_bytes(),
          ignore_lock,
        }))
        .await;

      if res.is_err() {
        let status = res.unwrap_err();
        match status.code() {
          Code::AlreadyExists => return Ok(()),
          _ => {
            return Err(CoordinatorError::FailedToCreateLedger);
          },
        }
      }
      let endorser_proto::NewLedgerResp { receipt } = res.unwrap().into_inner();
      receipt
    } else {
      let res = endorser_client
        .append(tonic::Request::new(endorser_proto::AppendReq {
          handle: handle.to_bytes(),
          block_hash: ledger_entry.get_receipt().get_block_hash().to_bytes(),
          expected_height: ledger_entry.get_receipt().get_height() as u64,
          ignore_lock,
        }))
        .await;

      if res.is_err() {
        let status = res.unwrap_err();
        match status.code() {
          Code::AlreadyExists => return Ok(()),
          _ => return Err(CoordinatorError::FailedToAppendLedger),
        }
      }
      let endorser_proto::AppendResp { receipt } = res.unwrap().into_inner();
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
    }
  }

  Ok(())
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
      },
      _ => CoordinatorState {
        ledger_store: Arc::new(Box::new(InMemoryLedgerStore::new())),
        conn_map: Arc::new(RwLock::new(HashMap::new())),
      },
    };

    let res = coordinator.ledger_store.read_view_ledger_tail().await;
    if res.is_err() {
      eprintln!("Failed to read the view ledger tail {:?}", res);
      return Err(CoordinatorError::FailedToReadViewLedger);
    }

    let view_ledger_tail = res.unwrap();
    if view_ledger_tail.get_receipt().get_height() > 0 {
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

      let res = coordinator.connect_endorsers(&hostnames).await;
      if res.is_err() {
        eprintln!("Failed to connect to endorsers {:?}", res);
        return Err(CoordinatorError::FailedToConnectToEndorser);
      }
    }
    Ok(coordinator)
  }

  fn get_endorser_client(&self, pk: &[u8]) -> Option<EndorserCallClient<Channel>> {
    if let Ok(conn_map_rd) = self.conn_map.read() {
      if !conn_map_rd.contains_key(pk) {
        eprintln!("No endorser has this public key {:?}", pk);
        None
      } else {
        Some(conn_map_rd[pk].0.clone())
      }
    } else {
      eprintln!("Failed to acquire read lock");
      None
    }
  }

  pub fn get_endorser_pks(&self) -> Vec<Vec<u8>> {
    self
      .conn_map
      .read()
      .expect("Failed to get the read lock")
      .iter()
      .map(|(pk, (_ec, _hostname))| pk.clone())
      .collect::<Vec<Vec<u8>>>()
  }

  fn get_endorser_hostnames(&self) -> EndorserHostnames {
    EndorserHostnames {
      pk_hostnames: self
        .conn_map
        .read()
        .expect("Failed to get the read lock")
        .iter()
        .map(|(pk, (_ec, hostname))| (pk.clone(), hostname.clone()))
        .collect::<Vec<(Vec<u8>, String)>>(),
    }
  }

  async fn connect_endorsers(
    &self,
    hostnames: &[String],
  ) -> Result<Vec<Vec<u8>>, CoordinatorError> {
    let (mpsc_tx, mut mpsc_rx) = mpsc::channel(ENDORSER_MPSC_CHANNEL_BUFFER);
    for hostname in hostnames {
      let tx = mpsc_tx.clone();
      let endorser = hostname.clone();

      let _job = tokio::spawn(async move {
        let res = Endpoint::from_shared(endorser.to_string());
        if res.is_err() {
          eprintln!("Failed to resolve the endorser host name: {:?}", endorser);
          return;
        }
        let endorser_endpoint = res.unwrap();
        let channel = endorser_endpoint.connect_lazy();
        let mut client = EndorserCallClient::new(channel);

        let req = tonic::Request::new(endorser_proto::GetPublicKeyReq {});
        let res = client.get_public_key(req).await;
        tx.send((endorser, client, res)).await.unwrap();
      });
    }

    drop(mpsc_tx);

    let mut pks = Vec::new();
    while let Some((endorser, client, res)) = mpsc_rx.recv().await {
      if res.is_err() {
        eprintln!(
          "Failed to get the public key of an endorser: {:?}",
          endorser
        );
        continue;
      }
      let endorser_proto::GetPublicKeyResp { pk } = res.unwrap().into_inner();
      if PublicKey::from_bytes(&pk).is_err() {
        eprintln!("Public key is invalid from endorser {:?}", endorser);
        continue;
      }
      if let Ok(mut conn_map_wr) = self.conn_map.write() {
        pks.push(pk.clone());
        conn_map_wr.insert(pk, (client, endorser));
      } else {
        eprintln!("Failed to acquire the write lock");
      }
    }

    Ok(pks)
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
      let mut endorser_client = match self.get_endorser_client(pk) {
        Some(client) => client,
        None => {
          continue;
        },
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
        tx.send(res).await.unwrap();
      });
    }

    drop(mpsc_tx);

    let mut receipts: Vec<Receipt> = Vec::new();
    while let Some(res) = mpsc_rx.recv().await {
      if res.is_err() {
        eprintln!("Failed to initialize endorser state");
        continue;
      }
      let endorser_proto::InitializeStateResp { receipt } = res.unwrap().into_inner();
      let res = Receipt::from_bytes(&receipt);
      if res.is_err() {
        eprintln!("Failed to parse a receipt");
        continue;
      }
      let receipt_rs = res.unwrap();
      receipts.push(receipt_rs);
    }

    match Receipt::merge_receipts(&receipts) {
      Ok(receipt) => Ok(receipt),
      Err(_) => Err(CoordinatorError::EndorsersInDifferentViews),
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
      let mut endorser_client = match self.get_endorser_client(pk) {
        Some(client) => client,
        None => {
          continue;
        },
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
        let _ = tx.send(res).await;
      });
    }

    drop(mpsc_tx);

    let quorum_size = (endorsers.len() / 2) + 1;
    let mut receipts: Vec<Receipt> = Vec::new();
    while let Some(res) = mpsc_rx.recv().await {
      if res.is_err() {
        eprintln!("Failed to create a ledger in endorser");
        continue;
      }
      let endorser_proto::NewLedgerResp { receipt } = res.unwrap().into_inner();
      let res = Receipt::from_bytes(&receipt);
      if res.is_err() {
        eprintln!("Failed to parse a receipt");
        continue;
      }
      let receipt_rs = res.unwrap();
      receipts.push(receipt_rs);
      if receipts.len() == quorum_size {
        break;
      }
    }

    match Receipt::merge_receipts(&receipts) {
      Ok(receipt) => Ok(receipt),
      Err(_) => Err(CoordinatorError::EndorsersInDifferentViews),
    }
  }

  pub async fn endorser_append_ledger(
    &self,
    endorsers: &[Vec<u8>],
    ledger_handle: &Handle,
    block_hash: &NimbleDigest,
    expected_height: usize,
    ignore_lock: bool,
  ) -> Result<Receipt, CoordinatorError> {
    let (mpsc_tx, mut mpsc_rx) = mpsc::channel(ENDORSER_MPSC_CHANNEL_BUFFER);

    for pk in endorsers {
      let mut endorser_client = match self.get_endorser_client(pk) {
        Some(client) => client,
        None => {
          continue;
        },
      };
      let tx = mpsc_tx.clone();
      let handle = *ledger_handle;
      let block = *block_hash;
      let ledger_store = self.ledger_store.clone();
      let _job = tokio::spawn(async move {
        let res = endorser_client
          .append(tonic::Request::new(endorser_proto::AppendReq {
            handle: handle.to_bytes(),
            block_hash: block.to_bytes(),
            expected_height: expected_height as u64,
            ignore_lock,
          }))
          .await;
        if let Ok(resp) = res {
          let endorser_proto::AppendResp { receipt } = resp.into_inner();
          let res = Receipt::from_bytes(&receipt);
          if let Ok(receipt_rs) = res {
            let _ = tx.send(receipt_rs).await;
          } else {
            eprintln!("Failed to parse a receipt");
          }
        } else {
          let status = res.unwrap_err();
          if status.code() == Code::NotFound || status.code() == Code::FailedPrecondition {
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
              ledger_store,
              endorser_client.clone(),
              handle,
              height_to_start,
              height_to_end,
              ignore_lock,
            )
            .await;
            if res.is_ok() {
              let res = endorser_client
                .append(tonic::Request::new(endorser_proto::AppendReq {
                  handle: handle.to_bytes(),
                  block_hash: block.to_bytes(),
                  expected_height: expected_height as u64,
                  ignore_lock,
                }))
                .await;
              if let Ok(resp) = res {
                let endorser_proto::AppendResp { receipt } = resp.into_inner();
                let res = Receipt::from_bytes(&receipt);
                if let Ok(receipt_rs) = res {
                  let _ = tx.send(receipt_rs).await;
                } else {
                  eprintln!("Failed to parse a receipt");
                }
              }
            }
          } else {
            eprintln!("Failed to append to a ledger status={:?}", status);
          }
        }
      });
    }

    drop(mpsc_tx);

    let quorum_size = (endorsers.len() / 2) + 1;
    let mut receipts: Vec<Receipt> = Vec::new();
    while let Some(receipt) = mpsc_rx.recv().await {
      receipts.push(receipt);
      if receipts.len() == quorum_size {
        break;
      }
    }

    match Receipt::merge_receipts(&receipts) {
      Ok(receipt) => Ok(receipt),
      Err(_) => Err(CoordinatorError::EndorsersInDifferentViews),
    }
  }

  async fn endorser_read_ledger_tail(
    &self,
    endorsers: &[Vec<u8>],
    ledger_handle: &Handle,
    client_nonce: &Nonce,
  ) -> Result<Receipt, CoordinatorError> {
    let (mpsc_tx, mut mpsc_rx) = mpsc::channel(ENDORSER_MPSC_CHANNEL_BUFFER);

    for pk in endorsers {
      let mut endorser_client = match self.get_endorser_client(pk) {
        Some(client) => client,
        None => {
          continue;
        },
      };
      let tx = mpsc_tx.clone();

      let handle = *ledger_handle;
      let nonce = *client_nonce;
      let _job = tokio::spawn(async move {
        let res = endorser_client
          .read_latest(tonic::Request::new(endorser_proto::ReadLatestReq {
            handle: handle.to_bytes(),
            nonce: nonce.get(),
          }))
          .await;
        let _ = tx.send(res).await;
      });
    }

    drop(mpsc_tx);

    let quorum_size = (endorsers.len() / 2) + 1;
    let mut receipts: Vec<Receipt> = Vec::new();
    while let Some(res) = mpsc_rx.recv().await {
      if res.is_err() {
        eprintln!("Failed to read the ledger tail of an endorser");
        continue;
      }
      let endorser_proto::ReadLatestResp { receipt } = res.unwrap().into_inner();
      let res = Receipt::from_bytes(&receipt);
      if res.is_err() {
        eprintln!("Failed to parse a receipt");
        continue;
      }
      let receipt_rs = res.unwrap();
      receipts.push(receipt_rs);
      if receipts.len() == quorum_size {
        break;
      }
    }

    match Receipt::merge_receipts(&receipts) {
      Ok(receipt) => Ok(receipt),
      Err(_) => Err(CoordinatorError::EndorsersInDifferentViews),
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
      let mut endorser_client = match self.get_endorser_client(pk) {
        Some(client) => client,
        None => {
          continue;
        },
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
        let _ = tx.send(res).await;
      });
    }

    drop(mpsc_tx);

    let quorum_size = (endorsers.len() / 2) + 1;
    let mut receipts: Vec<Receipt> = Vec::new();
    while let Some(res) = mpsc_rx.recv().await {
      if res.is_err() {
        eprintln!("Failed to append to the view ledger of an endorser");
        continue;
      }
      let endorser_proto::AppendViewLedgerResp { receipt } = res.unwrap().into_inner();
      let res = Receipt::from_bytes(&receipt);
      if res.is_err() {
        eprintln!("Failed to parse a receipt");
        continue;
      }
      let receipt_rs = res.unwrap();
      receipts.push(receipt_rs);
      if receipts.len() == quorum_size {
        break;
      }
    }

    match Receipt::merge_receipts(&receipts) {
      Ok(receipt) => Ok(receipt),
      Err(_) => Err(CoordinatorError::EndorsersInDifferentViews),
    }
  }

  async fn endorser_read_latest_state(
    &self,
    endorsers: &[Vec<u8>],
    to_lock: bool,
  ) -> Result<Vec<(PublicKey, LedgerView)>, CoordinatorError> {
    let (mpsc_tx, mut mpsc_rx) = mpsc::channel(ENDORSER_MPSC_CHANNEL_BUFFER);

    for pk in endorsers {
      let mut endorser_client = match self.get_endorser_client(pk) {
        Some(client) => client,
        None => {
          continue;
        },
      };
      let tx = mpsc_tx.clone();

      let pk_bytes = pk.clone();
      let _job = tokio::spawn(async move {
        let res = endorser_client
          .read_latest_state(tonic::Request::new(endorser_proto::ReadLatestStateReq {
            to_lock,
          }))
          .await;
        tx.send((pk_bytes, res)).await.unwrap();
      });
    }

    drop(mpsc_tx);

    let mut ledger_views = Vec::new();
    while let Some((pk, res)) = mpsc_rx.recv().await {
      if res.is_err() {
        eprintln!("Failed to read latest state of an endorser");
        continue;
      }
      let endorser_proto::ReadLatestStateResp {
        ledger_tail_map,
        view_tail_metablock,
      } = res.unwrap().into_inner();
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
    }

    Ok(ledger_views)
  }

  async fn unlock_endorsers(&self, endorsers: &[Vec<u8>]) -> Result<(), CoordinatorError> {
    let (mpsc_tx, mut mpsc_rx) = mpsc::channel(ENDORSER_MPSC_CHANNEL_BUFFER);

    for pk in endorsers {
      let mut endorser_client = match self.get_endorser_client(pk) {
        Some(client) => client,
        None => {
          continue;
        },
      };
      let tx = mpsc_tx.clone();
      let _job = tokio::spawn(async move {
        let res = endorser_client
          .unlock(tonic::Request::new(endorser_proto::UnlockReq {}))
          .await;
        if res.is_err() {
          eprintln!("Failed to unlock an endorser");
          return;
        }
        tx.send(res).await.unwrap();
      });
    }

    drop(mpsc_tx);

    while let Some(res) = mpsc_rx.recv().await {
      if res.is_err() {
        eprintln!("Failed to unlock an endorser");
        continue;
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

    let (mpsc_tx, mut mpsc_rx) = mpsc::channel(32);

    // Update endorsers to the max cut
    for (pk, ledger_view) in ledger_views {
      let client = self.get_endorser_client(&pk.to_bytes()).unwrap();

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
        let ledger_handle = *handle;
        let tx = mpsc_tx.clone();
        let pk_bytes = pk.to_bytes();
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
          tx.send((pk_bytes, res)).await.unwrap();
        });
      }
    }

    drop(mpsc_tx);

    while let Some((pk_bytes, res)) = mpsc_rx.recv().await {
      if res.is_err() {
        eprintln!("failed to update endorser pk={:?} res={:?}", pk_bytes, res);
      }
    }

    Ok(max_cut)
  }

  pub async fn add_endorsers(&self, hostnames: &[String]) -> Result<(), CoordinatorError> {
    let existing_endorsers = self.get_endorser_pks();
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

    // Connect to endorsers
    let res = self.connect_endorsers(hostnames).await;
    if res.is_err() {
      eprintln!("Failed to connect to endorsers {:?}", res);
      return Err(CoordinatorError::FailedToConnectToEndorser);
    }
    let new_endorsers = res.unwrap();

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

    // Store the genesis block of the view ledger in the ledger store
    let res = self
      .ledger_store
      .append_view_ledger(&view_ledger_genesis_block, None)
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
    let handle = NimbleDigest::digest(handle_bytes);
    let data_block = Block::new(block_bytes);
    let hash_of_block = data_block.hash();

    let requested_height = match expected_height {
      0 => None,
      _ => Some(expected_height),
    };

    let res = self
      .ledger_store
      .append_ledger(&handle, &data_block, requested_height)
      .await;
    if res.is_err() {
      eprintln!(
        "Failed to append to the ledger in the ledger store {:?}",
        res.unwrap_err()
      );
      return Err(CoordinatorError::FailedToAppendLedger);
    }

    let actual_height = res.unwrap();
    assert!(expected_height == 0 || actual_height == expected_height);

    let receipt = {
      let endorsers = match endorsers_opt {
        Some(endorsers) => endorsers,
        None => self.get_endorser_pks(),
      };
      let res = self
        .endorser_append_ledger(&endorsers, &handle, &hash_of_block, actual_height, false)
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

    let ledger_entry = {
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
        .endorser_read_ledger_tail(&endorsers, &handle, &nonce)
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

    Ok((ledger_entry.block, receipt))
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
        eprintln!(
          "Failed to read view by index from the ledger store {:?}",
          res.unwrap_err()
        );
        return Err(CoordinatorError::FailedToReadViewLedger);
      }
      res.unwrap()
    };

    Ok(ledger_entry)
  }
}
