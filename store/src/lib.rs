use async_trait::async_trait;
use itertools::Itertools;
use ledger::{Block, Handle, LedgerView, MetaBlock, NimbleDigest, NimbleHashTrait, Receipt};
use std::collections::{hash_map, HashMap};
use std::sync::{Arc, RwLock};

mod errors;
use crate::errors::{LedgerStoreError, StorageError};

#[derive(Debug, Default, Clone)]
pub struct LedgerEntry {
  pub block: Block,
  pub metablock: MetaBlock,
  pub receipt: Receipt,
}

/// A trait that defines the interface for a backing storage service.
#[async_trait]
pub trait PersistentLedgerStore {
  async fn new(params: HashMap<String, String>) -> Result<Self, StorageError>
  where
    Self: Sized;
  async fn create_ledger(
    &self,
    handle: &Handle,
    ledger_entry: &LedgerEntry,
  ) -> Result<(), StorageError>;
  async fn append_ledger(
    &self,
    handle: &Handle,
    ledger_entry: &LedgerEntry,
  ) -> Result<(), StorageError>;
  async fn read_by_index(&self, handle: &Handle, index: usize)
    -> Result<LedgerEntry, StorageError>;
  async fn read_latest(&self, handle: &Handle) -> Result<LedgerEntry, StorageError>;
  async fn attach_receipt(
    &self,
    handle: &Handle,
    index: usize,
    receipt: &Receipt,
  ) -> Result<(), StorageError>;
}

mod in_memory;

type LedgerArray = Arc<RwLock<Vec<LedgerEntry>>>;
#[derive(Debug, Default)]
pub struct LedgerStore {
  ledgers: Arc<RwLock<HashMap<Handle, LedgerArray>>>,
  view_ledger: Arc<RwLock<Vec<LedgerEntry>>>,
}

impl LedgerStore {
  pub fn new() -> Self {
    let ledgers = HashMap::new();
    let mut view_ledger = Vec::new();

    let view_ledger_entry = LedgerEntry {
      block: Block::new(&[0; 0]),
      metablock: MetaBlock::new(&NimbleDigest::default(), &NimbleDigest::default(), 0),
      receipt: Receipt::default(),
    };
    view_ledger.push(view_ledger_entry);

    Self {
      ledgers: Arc::new(RwLock::new(ledgers)),
      view_ledger: Arc::new(RwLock::new(view_ledger)),
    }
  }
}

impl LedgerStore {
  pub async fn create_ledger(
    &self,
    block: &Block,
  ) -> Result<(Handle, MetaBlock, NimbleDigest), LedgerStoreError> {
    let handle = block.hash();
    let block_hash = block.hash();
    let metablock = MetaBlock::new(&NimbleDigest::default(), &block_hash, 0);
    let ledger_entry = LedgerEntry {
      block: block.clone(),
      metablock: metablock.clone(),
      receipt: Receipt::default(),
    };
    if let Ok(mut ledgers_map) = self.ledgers.write() {
      if let hash_map::Entry::Vacant(e) = ledgers_map.entry(handle) {
        let tail_hash = ledger_entry.metablock.hash();
        e.insert(Arc::new(RwLock::new(vec![ledger_entry])));
        Ok((handle, metablock, tail_hash))
      } else {
        Err(LedgerStoreError::LedgerError(StorageError::DuplicateKey))
      }
    } else {
      Err(LedgerStoreError::LedgerError(
        StorageError::LedgerMapWriteLockFailed,
      ))
    }
  }

  pub async fn append_ledger(
    &self,
    handle: &Handle,
    block: &Block,
    cond: &NimbleDigest,
  ) -> Result<(MetaBlock, NimbleDigest), LedgerStoreError> {
    if let Ok(ledgers_map) = self.ledgers.read() {
      if ledgers_map.contains_key(handle) {
        if let Ok(mut ledgers) = ledgers_map[handle].write() {
          let last_entry = &ledgers[ledgers.len() - 1].metablock;
          if *cond == NimbleDigest::default() || *cond == last_entry.hash() {
            let block_hash = block.hash();
            let ledger_entry = LedgerEntry {
              block: block.clone(),
              metablock: MetaBlock::new(
                &last_entry.hash(),
                &block_hash,
                last_entry.get_height() + 1,
              ),
              receipt: Receipt::default(),
            };
            let tail_hash = ledger_entry.metablock.hash();
            let metablock = ledger_entry.metablock.clone();
            ledgers.push(ledger_entry);
            Ok((metablock, tail_hash))
          } else {
            Err(LedgerStoreError::LedgerError(
              StorageError::IncorrectConditionalData,
            ))
          }
        } else {
          Err(LedgerStoreError::LedgerError(
            StorageError::LedgerWriteLockFailed,
          ))
        }
      } else {
        Err(LedgerStoreError::LedgerError(StorageError::KeyDoesNotExist))
      }
    } else {
      Err(LedgerStoreError::LedgerError(
        StorageError::LedgerMapReadLockFailed,
      ))
    }
  }

  pub async fn attach_ledger_receipt(
    &self,
    handle: &Handle,
    metablock: &MetaBlock,
    receipt: &Receipt,
  ) -> Result<(), LedgerStoreError> {
    if let Ok(ledgers_map) = self.ledgers.read() {
      if ledgers_map.contains_key(handle) {
        if let Ok(mut ledgers) = ledgers_map[handle].write() {
          if metablock.get_height() < ledgers.len() {
            ledgers[metablock.get_height()].receipt = receipt.clone();
            Ok(())
          } else {
            Err(LedgerStoreError::LedgerError(StorageError::InvalidIndex))
          }
        } else {
          Err(LedgerStoreError::LedgerError(
            StorageError::LedgerWriteLockFailed,
          ))
        }
      } else {
        Err(LedgerStoreError::LedgerError(StorageError::KeyDoesNotExist))
      }
    } else {
      Err(LedgerStoreError::LedgerError(
        StorageError::LedgerMapReadLockFailed,
      ))
    }
  }

  pub async fn read_ledger_tail(&self, handle: &Handle) -> Result<LedgerEntry, LedgerStoreError> {
    if let Ok(ledgers_map) = self.ledgers.read() {
      if ledgers_map.contains_key(handle) {
        if let Ok(ledgers) = ledgers_map[handle].read() {
          Ok(ledgers[ledgers.len() - 1].clone())
        } else {
          Err(LedgerStoreError::LedgerError(
            StorageError::LedgerReadLockFailed,
          ))
        }
      } else {
        Err(LedgerStoreError::LedgerError(StorageError::KeyDoesNotExist))
      }
    } else {
      Err(LedgerStoreError::LedgerError(
        StorageError::LedgerMapReadLockFailed,
      ))
    }
  }

  pub async fn read_ledger_by_index(
    &self,
    handle: &Handle,
    idx: usize,
  ) -> Result<LedgerEntry, LedgerStoreError> {
    if let Ok(ledgers_map) = self.ledgers.read() {
      if ledgers_map.contains_key(handle) {
        if let Ok(ledgers) = ledgers_map[handle].read() {
          if idx < ledgers.len() {
            Ok(ledgers[idx].clone())
          } else {
            Err(LedgerStoreError::LedgerError(StorageError::InvalidIndex))
          }
        } else {
          Err(LedgerStoreError::LedgerError(
            StorageError::LedgerReadLockFailed,
          ))
        }
      } else {
        Err(LedgerStoreError::LedgerError(StorageError::KeyDoesNotExist))
      }
    } else {
      Err(LedgerStoreError::LedgerError(
        StorageError::LedgerMapReadLockFailed,
      ))
    }
  }

  pub async fn append_view_ledger(&self, block: &Block) -> Result<LedgerView, LedgerStoreError> {
    let mut ledger_tail_map = HashMap::new();
    if let Ok(mut view_ledger_array) = self.view_ledger.write() {
      if let Ok(ledger_map) = self.ledgers.read() {
        let last_view_ledger_entry_metablock =
          &view_ledger_array[view_ledger_array.len() - 1].metablock;
        let block_hash = block.hash();

        for handle in ledger_map.keys().sorted() {
          let ledger_array = ledger_map[handle].read().expect("failed to read a ledger");
          let last_ledger_entry_metablock = &ledger_array[ledger_array.len() - 1].metablock;
          let tail = last_ledger_entry_metablock.hash();
          let height = last_ledger_entry_metablock.get_height();
          ledger_tail_map.insert(*handle, (tail, height));
        }

        let ledger_entry = LedgerEntry {
          block: block.clone(),
          metablock: MetaBlock::new(
            &if view_ledger_array.len() == 1 {
              NimbleDigest::default()
            } else {
              last_view_ledger_entry_metablock.hash()
            },
            &block_hash,
            last_view_ledger_entry_metablock.get_height() + 1,
          ),
          receipt: Receipt::default(),
        };
        let metablock = ledger_entry.metablock.clone();
        view_ledger_array.push(ledger_entry);
        Ok(LedgerView {
          view_tail_metablock: metablock,
          ledger_tail_map,
        })
      } else {
        Err(LedgerStoreError::LedgerError(
          StorageError::LedgerMapReadLockFailed,
        ))
      }
    } else {
      Err(LedgerStoreError::LedgerError(
        StorageError::ViewLedgerWriteLockFailed,
      ))
    }
  }

  pub async fn attach_view_ledger_receipt(
    &self,
    metablock: &MetaBlock,
    receipt: &Receipt,
  ) -> Result<(), LedgerStoreError> {
    if let Ok(mut view_ledger_array) = self.view_ledger.write() {
      if metablock.get_height() < view_ledger_array.len() {
        view_ledger_array[metablock.get_height()].receipt = receipt.clone();
        Ok(())
      } else {
        Err(LedgerStoreError::LedgerError(StorageError::InvalidIndex))
      }
    } else {
      Err(LedgerStoreError::LedgerError(
        StorageError::ViewLedgerWriteLockFailed,
      ))
    }
  }

  pub async fn read_view_ledger_tail(&self) -> Result<LedgerEntry, LedgerStoreError> {
    if let Ok(view_ledger_array) = self.view_ledger.read() {
      Ok(view_ledger_array[view_ledger_array.len() - 1].clone())
    } else {
      Err(LedgerStoreError::LedgerError(
        StorageError::ViewLedgerReadLockFailed,
      ))
    }
  }

  pub async fn read_view_ledger_by_index(
    &self,
    idx: usize,
  ) -> Result<LedgerEntry, LedgerStoreError> {
    if let Ok(view_ledger_array) = self.view_ledger.read() {
      if idx < view_ledger_array.len() {
        Ok(view_ledger_array[idx].clone())
      } else {
        Err(LedgerStoreError::LedgerError(StorageError::InvalidIndex))
      }
    } else {
      Err(LedgerStoreError::LedgerError(
        StorageError::ViewLedgerReadLockFailed,
      ))
    }
  }

  pub async fn reset_store(&self) -> Result<(), LedgerStoreError> {
    // not really needed for in-memory since state is already volatile.
    // this API is only for testing persistent storage services.
    // we could implement it here anyway, but choose not to for now.
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use crate::Block;
  use crate::LedgerStore;
  use crate::NimbleDigest;
  use ledger::CustomSerde;

  #[tokio::test]
  pub async fn check_store_creation_and_operations() {
    let state = LedgerStore::new();
    let initial_value: Vec<u8> = vec![
      1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
      1, 2,
    ];

    let block = Block::new(&initial_value);

    let (handle, _, _) = state
      .create_ledger(&block)
      .await
      .expect("failed create ledger");

    let res = state.read_ledger_tail(&handle).await;
    assert!(res.is_ok());

    let current_data = res.unwrap();
    assert_eq!(current_data.block.to_bytes(), initial_value);

    let new_value_appended: Vec<u8> = vec![
      2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1,
      2, 1,
    ];

    let new_block = Block::new(&new_value_appended);

    let res = state
      .append_ledger(&handle, &new_block, &NimbleDigest::default())
      .await;
    assert!(res.is_ok());

    let res = state.read_ledger_tail(&handle).await;
    assert!(res.is_ok());

    let current_tail = res.unwrap();
    assert_eq!(current_tail.block.to_bytes(), new_value_appended);

    let res = state.read_ledger_by_index(&handle, 0).await;
    assert!(res.is_ok());

    let data_at_index = res.unwrap();
    assert_eq!(data_at_index.block.to_bytes(), initial_value);

    let res = state.reset_store().await;
    assert!(res.is_ok());
  }
}
