use super::{LedgerArray, LedgerEntry, PersistentLedgerStore};
use crate::errors::StorageError;
use async_trait::async_trait;
use ledger::{Handle, Receipt};
use std::collections::{hash_map, HashMap};
use std::sync::{Arc, RwLock};

pub struct InMemoryPersistentLedgerStore {
  ledgers: Arc<RwLock<HashMap<Handle, LedgerArray>>>,
}

#[async_trait]
impl PersistentLedgerStore for InMemoryPersistentLedgerStore {
  async fn new(_params: HashMap<String, String>) -> Result<Self, StorageError> {
    Ok(Self {
      ledgers: Arc::new(RwLock::new(HashMap::new())),
    })
  }

  async fn create_ledger(
    &self,
    handle: &Handle,
    ledger_entry: &LedgerEntry,
  ) -> Result<(), StorageError> {
    if let Ok(mut ledgers_map) = self.ledgers.write() {
      if let hash_map::Entry::Vacant(e) = ledgers_map.entry(*handle) {
        e.insert(Arc::new(RwLock::new(vec![ledger_entry.clone()])));
        Ok(())
      } else {
        Err(StorageError::DuplicateKey)
      }
    } else {
      Err(StorageError::LedgerMapWriteLockFailed)
    }
  }

  async fn append_ledger(
    &self,
    handle: &Handle,
    ledger_entry: &LedgerEntry,
  ) -> Result<(), StorageError> {
    let index = ledger_entry.metablock.get_height();
    if let Ok(ledgers_map) = self.ledgers.read() {
      if ledgers_map.contains_key(handle) {
        if let Ok(mut ledgers) = ledgers_map[handle].write() {
          if index == ledgers.len() {
            ledgers.push(ledger_entry.clone());
            Ok(())
          } else {
            Err(StorageError::InvalidIndex)
          }
        } else {
          Err(StorageError::LedgerWriteLockFailed)
        }
      } else {
        Err(StorageError::KeyDoesNotExist)
      }
    } else {
      Err(StorageError::LedgerMapReadLockFailed)
    }
  }

  async fn read_by_index(
    &self,
    handle: &Handle,
    index: usize,
  ) -> Result<LedgerEntry, StorageError> {
    if let Ok(ledgers_map) = self.ledgers.read() {
      if ledgers_map.contains_key(handle) {
        if let Ok(ledgers) = ledgers_map[handle].read() {
          if index < ledgers.len() {
            Ok(ledgers[index].clone())
          } else {
            Err(StorageError::InvalidIndex)
          }
        } else {
          Err(StorageError::LedgerReadLockFailed)
        }
      } else {
        Err(StorageError::KeyDoesNotExist)
      }
    } else {
      Err(StorageError::LedgerMapReadLockFailed)
    }
  }

  async fn read_latest(&self, handle: &Handle) -> Result<LedgerEntry, StorageError> {
    if let Ok(ledgers_map) = self.ledgers.read() {
      if ledgers_map.contains_key(handle) {
        if let Ok(ledgers) = ledgers_map[handle].read() {
          Ok(ledgers[ledgers.len() - 1].clone())
        } else {
          Err(StorageError::LedgerReadLockFailed)
        }
      } else {
        Err(StorageError::KeyDoesNotExist)
      }
    } else {
      Err(StorageError::LedgerMapReadLockFailed)
    }
  }

  async fn attach_receipt(
    &self,
    handle: &Handle,
    index: usize,
    receipt: &Receipt,
  ) -> Result<(), StorageError> {
    if let Ok(ledgers_map) = self.ledgers.read() {
      if ledgers_map.contains_key(handle) {
        if let Ok(mut ledgers) = ledgers_map[handle].write() {
          if index < ledgers.len() {
            ledgers[index].receipt = receipt.clone();
            Ok(())
          } else {
            Err(StorageError::InvalidIndex)
          }
        } else {
          Err(StorageError::LedgerWriteLockFailed)
        }
      } else {
        Err(StorageError::KeyDoesNotExist)
      }
    } else {
      Err(StorageError::LedgerMapReadLockFailed)
    }
  }
}
