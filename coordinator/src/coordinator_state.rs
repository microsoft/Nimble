use crate::errors::CoordinatorError;
use core::cmp::max;
use ledger::{
  signature::{PublicKey, PublicKeyTrait},
  Block, CustomSerde, EndorserHostnames, Handle, LedgerView, MetaBlock, NimbleDigest,
  NimbleHashTrait, Nonce, Receipt,
};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use store::{in_memory::InMemoryLedgerStore, mongodb_cosmos::MongoCosmosLedgerStore, LedgerStore};
use tokio::sync::mpsc;
use tonic::transport::{Channel, Endpoint};

pub mod endorser_proto {
  tonic::include_proto!("endorser_proto");
}

use endorser_proto::endorser_call_client::EndorserCallClient;

type EndorserConnMap = HashMap<Vec<u8>, (EndorserCallClient<Channel>, String)>;

pub struct CoordinatorState {
  ledger_store: Box<dyn LedgerStore + Send + Sync>,
  conn_map: Arc<RwLock<EndorserConnMap>>,
}

const ENDORSER_MPSC_CHANNEL_BUFFER: usize = 8; // limited by the number of endorsers

impl CoordinatorState {
  pub async fn new(
    ledger_store_type: &str,
    args: &HashMap<String, String>,
  ) -> Result<CoordinatorState, CoordinatorError> {
    let coordinator = match ledger_store_type {
      "mongodb_cosmos" => CoordinatorState {
        ledger_store: Box::new(MongoCosmosLedgerStore::new(args).await.unwrap()),
        conn_map: Arc::new(RwLock::new(HashMap::new())),
      },
      _ => CoordinatorState {
        ledger_store: Box::new(InMemoryLedgerStore::new()),
        conn_map: Arc::new(RwLock::new(HashMap::new())),
      },
    };

    let res = coordinator.ledger_store.read_view_ledger_tail().await;
    if res.is_err() {
      eprintln!("Failed to read the view ledger tail {:?}", res);
      return Err(CoordinatorError::FailedToReadViewLedger);
    }

    let view_ledger_tail = res.unwrap();
    if view_ledger_tail.receipt.get_height() > 0 {
      let res = bincode::deserialize(&view_ledger_tail.block.to_bytes());
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

      // TODO: what if endorser's state is not in sync with ledger store?
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
        eprintln!("Failed to create a ledger in endorser");
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

      let _job = tokio::spawn(async move {
        let res = endorser_client
          .new_ledger(tonic::Request::new(endorser_proto::NewLedgerReq {
            handle: handle.to_bytes(),
            ignore_lock,
          }))
          .await;
        tx.send(res).await.unwrap();
      });
    }

    drop(mpsc_tx);

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
      let _job = tokio::spawn(async move {
        let res = endorser_client
          .append(tonic::Request::new(endorser_proto::AppendReq {
            handle: handle.to_bytes(),
            block_hash: block.to_bytes(),
            expected_height: expected_height as u64,
            ignore_lock,
          }))
          .await;
        tx.send(res).await.unwrap();
      });
    }

    drop(mpsc_tx);

    let mut receipts: Vec<Receipt> = Vec::new();
    while let Some(res) = mpsc_rx.recv().await {
      if res.is_err() {
        // TODO: retry
        eprintln!("Failed to append to an endorser");
        continue;
      }
      let endorser_proto::AppendResp { receipt } = res.unwrap().into_inner();
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
        tx.send(res).await.unwrap();
      });
    }

    drop(mpsc_tx);

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
        tx.send(res).await.unwrap();
      });
    }

    drop(mpsc_tx);

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

  async fn update_endorser(
    &self,
    pk: &PublicKey,
    handle: &NimbleDigest,
    start: usize,
    end: usize,
  ) -> Result<(), CoordinatorError> {
    let pk_vec = vec![pk.to_bytes()];
    if start == 0 {
      let res = self.endorser_create_ledger(&pk_vec, handle, true).await;
      if let Err(error) = res {
        return Err(error);
      }
      let receipt = res.unwrap();

      let res = self
        .ledger_store
        .attach_ledger_receipt(handle, &receipt)
        .await;
      if res.is_err() {
        eprintln!(
          "Failed to attach ledger receipt to the ledger store ({:?})",
          res
        );
        return Err(CoordinatorError::FailedToAttachReceipt);
      }
    }

    for idx in max(1, start)..=end {
      let res = self.ledger_store.read_ledger_by_index(handle, idx).await;
      if res.is_err() {
        eprintln!("Failed to read ledger by index {:?}", res);
        return Err(CoordinatorError::FailedToReadLedger);
      }
      let ledger_entry = res.unwrap();

      let res = self
        .endorser_append_ledger(
          &pk_vec,
          handle,
          ledger_entry.receipt.get_block_hash(),
          ledger_entry.receipt.get_height(),
          true,
        )
        .await;
      if let Err(error) = res {
        return Err(error);
      }
      let receipt = res.unwrap();

      let res = self
        .ledger_store
        .attach_ledger_receipt(handle, &receipt)
        .await;
      if res.is_err() {
        eprintln!("Failed to attach ledger receipt {:?}", res);
        return Err(CoordinatorError::FailedToAttachReceipt);
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

    // Update endorsers to the max cut
    for (pk, ledger_view) in ledger_views {
      for (handle, metablock) in max_cut.ledger_tail_map.iter() {
        let res = {
          if !ledger_view.ledger_tail_map.contains_key(handle) {
            self
              .update_endorser(pk, handle, 0, metablock.get_height())
              .await
          } else if ledger_view.ledger_tail_map[handle].get_height() < metablock.get_height() {
            self
              .update_endorser(
                pk,
                handle,
                ledger_view.ledger_tail_map[handle].get_height(),
                metablock.get_height(),
              )
              .await
          } else {
            Ok(())
          }
        };
        if let Err(error) = res {
          return Err(error);
        }
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
      .append_view_ledger(&view_ledger_genesis_block, 0)
      .await;
    if res.is_err() {
      eprintln!(
        "Failed to append to the view ledger in the ledger store ({:?})",
        res.unwrap_err()
      );
      return Err(CoordinatorError::FailedToCallLedgerStore);
    }

    // Initialize new endorsers
    let receipt1 = {
      let res = self
        .endorser_initialize_state(
          &new_endorsers,
          &ledger_view,
          &view_ledger_genesis_block.hash(),
          0,
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
            .endorser_append_view_ledger(&existing_endorsers, &view_ledger_genesis_block.hash(), 0)
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
    let genesis_block = Block::new(handle_bytes);
    let first_block = Block::new(block_bytes);
    let handle = genesis_block.hash();
    let block_hash = first_block.hash();

    let res = self
      .ledger_store
      .create_ledger(&handle, genesis_block, first_block)
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
        .endorser_create_ledger(&endorsers, &handle, false)
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

    // Make a request to the endorsers for the first entry.
    let receipt = {
      let endorsers = match endorsers_opt {
        Some(endorsers) => endorsers,
        None => self.get_endorser_pks(),
      };
      let res = self
        .endorser_append_ledger(&endorsers, &handle, &block_hash, 1usize, false)
        .await;
      if res.is_err() {
        eprintln!("Failed to append to ledger in endorsers ({:?})", res);
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

    let receipt = {
      let endorsers = match endorsers_opt {
        Some(endorsers) => endorsers,
        None => self.get_endorser_pks(),
      };
      let res = self
        .endorser_append_ledger(&endorsers, &handle, &hash_of_block, expected_height, false)
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
  ) -> Result<(Block, Receipt), CoordinatorError> {
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

    Ok((ledger_entry.block, ledger_entry.receipt))
  }

  pub async fn read_view_by_index(
    &self,
    index: usize,
  ) -> Result<(Block, Receipt), CoordinatorError> {
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

    Ok((ledger_entry.block, ledger_entry.receipt))
  }
}
