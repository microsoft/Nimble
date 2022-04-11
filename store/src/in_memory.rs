use super::{Block, Handle, NimbleDigest, Receipt};
use crate::errors::{LedgerStoreError, StorageError};
use crate::{LedgerEntry, LedgerStore};
use async_trait::async_trait;
use std::collections::{hash_map, HashMap};
use std::sync::{Arc, RwLock};

type LedgerArray = Arc<RwLock<Vec<LedgerEntry>>>;

#[derive(Debug, Default)]
pub struct InMemoryLedgerStore {
  ledgers: Arc<RwLock<HashMap<Handle, LedgerArray>>>,
  view_ledger: Arc<RwLock<Vec<LedgerEntry>>>,
}

impl InMemoryLedgerStore {
  pub fn new() -> Self {
    let ledgers = HashMap::new();
    let mut view_ledger = Vec::new();

    let view_ledger_entry = LedgerEntry::new(Block::new(&[0; 0]), Receipt::default());
    view_ledger.push(view_ledger_entry);

    InMemoryLedgerStore {
      ledgers: Arc::new(RwLock::new(ledgers)),
      view_ledger: Arc::new(RwLock::new(view_ledger)),
    }
  }
}

#[async_trait]
impl LedgerStore for InMemoryLedgerStore {
  async fn create_ledger(
    &self,
    handle: &NimbleDigest,
    genesis_block: Block,
    first_block: Block,
  ) -> Result<(), LedgerStoreError> {
    let init_ledger_entry = LedgerEntry::new(genesis_block, Receipt::default());
    let first_ledger_entry = LedgerEntry::new(first_block, Receipt::default());
    if let Ok(mut ledgers_map) = self.ledgers.write() {
      if let hash_map::Entry::Vacant(e) = ledgers_map.entry(*handle) {
        e.insert(Arc::new(RwLock::new(vec![
          init_ledger_entry,
          first_ledger_entry,
        ])));
        Ok(())
      } else {
        Err(LedgerStoreError::LedgerError(StorageError::DuplicateKey))
      }
    } else {
      Err(LedgerStoreError::LedgerError(
        StorageError::LedgerMapWriteLockFailed,
      ))
    }
  }

  async fn append_ledger(
    &self,
    handle: &Handle,
    block: &Block,
    expected_height: Option<usize>,
  ) -> Result<usize, LedgerStoreError> {
    if let Ok(ledgers_map) = self.ledgers.read() {
      if ledgers_map.contains_key(handle) {
        if let Ok(mut ledgers) = ledgers_map[handle].write() {
          if expected_height.is_none() || expected_height.unwrap() == ledgers.len() {
            let ledger_entry = LedgerEntry {
              block: block.clone(),
              receipt: Receipt::default(),
            };
            ledgers.push(ledger_entry);
            Ok(ledgers.len() - 1)
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

  async fn attach_ledger_receipt(
    &self,
    handle: &Handle,
    receipt: &Receipt,
  ) -> Result<(), LedgerStoreError> {
    if let Ok(ledgers_map) = self.ledgers.read() {
      if ledgers_map.contains_key(handle) {
        if let Ok(mut ledgers) = ledgers_map[handle].write() {
          let height = receipt.get_height();
          if height < ledgers.len() {
            let res = ledgers[height].receipt.append(receipt);
            if res.is_err() {
              return Err(LedgerStoreError::LedgerError(
                StorageError::MismatchedReceipts,
              ));
            }
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

  async fn read_ledger_tail(&self, handle: &Handle) -> Result<LedgerEntry, LedgerStoreError> {
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

  async fn read_ledger_by_index(
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

  async fn append_view_ledger(
    &self,
    block: &Block,
    expected_height: Option<usize>,
  ) -> Result<usize, LedgerStoreError> {
    if let Ok(mut view_ledger_array) = self.view_ledger.write() {
      if expected_height.is_none() || expected_height.unwrap() == view_ledger_array.len() {
        let ledger_entry = LedgerEntry::new(block.clone(), Receipt::default());
        view_ledger_array.push(ledger_entry);
        Ok(view_ledger_array.len() - 1)
      } else {
        Err(LedgerStoreError::LedgerError(
          StorageError::IncorrectConditionalData,
        ))
      }
    } else {
      Err(LedgerStoreError::LedgerError(
        StorageError::ViewLedgerWriteLockFailed,
      ))
    }
  }

  async fn attach_view_ledger_receipt(&self, receipt: &Receipt) -> Result<(), LedgerStoreError> {
    if let Ok(mut view_ledger_array) = self.view_ledger.write() {
      let height = receipt.get_height();
      if height < view_ledger_array.len() {
        let res = view_ledger_array[height].receipt.append(receipt);
        if res.is_err() {
          return Err(LedgerStoreError::LedgerError(
            StorageError::MismatchedReceipts,
          ));
        }
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

  async fn read_view_ledger_tail(&self) -> Result<LedgerEntry, LedgerStoreError> {
    if let Ok(view_ledger_array) = self.view_ledger.read() {
      Ok(view_ledger_array[view_ledger_array.len() - 1].clone())
    } else {
      Err(LedgerStoreError::LedgerError(
        StorageError::ViewLedgerReadLockFailed,
      ))
    }
  }

  async fn read_view_ledger_by_index(&self, idx: usize) -> Result<LedgerEntry, LedgerStoreError> {
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

  async fn reset_store(&self) -> Result<(), LedgerStoreError> {
    // not really needed for in-memory since state is already volatile.
    // this API is only for testing persistent storage services.
    // we could implement it here anyway, but choose not to for now.
    Ok(())
  }
}
