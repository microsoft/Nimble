use super::{Block, Handle, NimbleDigest, Nonce, Nonces, Receipts};
use crate::{
  errors::{LedgerStoreError, StorageError},
  ledger::{LedgerEntry, LedgerStore},
};
use async_trait::async_trait;
use std::{
  collections::{HashMap, hash_map},
  sync::{Arc, RwLock},
};

type LedgerArray = Arc<RwLock<Vec<LedgerEntry>>>;
type NonceArray = Arc<RwLock<Vec<Nonce>>>;

#[derive(Debug, Default)]
pub struct InMemoryLedgerStore {
  ledgers: Arc<RwLock<HashMap<Handle, LedgerArray>>>,
  nonces: Arc<RwLock<HashMap<Handle, NonceArray>>>,
  view_ledger: Arc<RwLock<Vec<LedgerEntry>>>,
}

impl InMemoryLedgerStore {
  pub fn new() -> Self {
    let ledgers = HashMap::new();
    let mut view_ledger = Vec::new();

    let view_ledger_entry = LedgerEntry::new(Block::new(&[0; 0]), Receipts::new(), None);
    view_ledger.push(view_ledger_entry);

    InMemoryLedgerStore {
      ledgers: Arc::new(RwLock::new(ledgers)),
      nonces: Arc::new(RwLock::new(HashMap::new())),
      view_ledger: Arc::new(RwLock::new(view_ledger)),
    }
  }

  fn drain_nonces(&self, handle: &Handle) -> Result<Nonces, LedgerStoreError> {
    if let Ok(nonce_map) = self.nonces.read() {
      if nonce_map.contains_key(handle) {
        if let Ok(mut nonces) = nonce_map[handle].write() {
          Ok(Nonces::from_vec(nonces.drain(..).collect()))
        } else {
          Err(LedgerStoreError::LedgerError(
            StorageError::LedgerWriteLockFailed,
          ))
        }
      } else {
        eprintln!("Unable to drain nonce because key does not exist");
        Err(LedgerStoreError::LedgerError(StorageError::KeyDoesNotExist))
      }
    } else {
      Err(LedgerStoreError::LedgerError(
        StorageError::LedgerMapReadLockFailed,
      ))
    }
  }
}

#[async_trait]
impl LedgerStore for InMemoryLedgerStore {
  async fn create_ledger(
    &self,
    handle: &NimbleDigest,
    genesis_block: Block,
  ) -> Result<(), LedgerStoreError> {
    let genesis_ledger_entry = LedgerEntry::new(genesis_block, Receipts::new(), None);
    if let Ok(mut ledgers_map) = self.ledgers.write() {
      if let Ok(mut nonce_map) = self.nonces.write() {
        if let hash_map::Entry::Vacant(e) = ledgers_map.entry(*handle) {
          e.insert(Arc::new(RwLock::new(vec![genesis_ledger_entry])));

          if let hash_map::Entry::Vacant(n) = nonce_map.entry(*handle) {
            n.insert(Arc::new(RwLock::new(Vec::new())));
            Ok(())
          } else {
            Err(LedgerStoreError::LedgerError(StorageError::DuplicateKey))
          }
        } else {
          Err(LedgerStoreError::LedgerError(StorageError::DuplicateKey))
        }
      } else {
        Err(LedgerStoreError::LedgerError(
          StorageError::LedgerMapWriteLockFailed,
        ))
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
    expected_height: usize,
  ) -> Result<(usize, Nonces), LedgerStoreError> {
    if let Ok(ledgers_map) = self.ledgers.read() {
      if ledgers_map.contains_key(handle) {
        if let Ok(mut ledgers) = ledgers_map[handle].write() {
          if expected_height == ledgers.len() {
            let nonces = self.drain_nonces(handle)?;

            let ledger_entry = LedgerEntry {
              block: block.clone(),
              receipts: Receipts::new(),
              nonces: nonces.clone(),
            };
            ledgers.push(ledger_entry);

            Ok(((ledgers.len() - 1), nonces))
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
        eprintln!("Key does not exist in the ledger map");
        Err(LedgerStoreError::LedgerError(StorageError::KeyDoesNotExist))
      }
    } else {
      Err(LedgerStoreError::LedgerError(
        StorageError::LedgerMapReadLockFailed,
      ))
    }
  }

  async fn attach_ledger_receipts(
    &self,
    handle: &Handle,
    idx: usize,
    receipts: &Receipts,
  ) -> Result<(), LedgerStoreError> {
    if let Ok(ledgers_map) = self.ledgers.read() {
      if ledgers_map.contains_key(handle) {
        if let Ok(mut ledgers) = ledgers_map[handle].write() {
          let height = idx;
          if height < ledgers.len() {
            ledgers[height].receipts.merge_receipts(receipts);
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

  async fn attach_ledger_nonce(
    &self,
    handle: &Handle,
    nonce: &Nonce,
  ) -> Result<usize, LedgerStoreError> {
    if let Ok(ledgers_map) = self.ledgers.read() {
      if ledgers_map.contains_key(handle) {
        if let Ok(ledgers) = ledgers_map[handle].read() {
          let height = ledgers.len();

          if let Ok(nonce_map) = self.nonces.read() {
            if nonce_map.contains_key(handle) {
              if let Ok(mut nonces) = nonce_map[handle].write() {
                // add nonce to the nonces list of this ledger and return the next
                // height at which it should be appended
                nonces.push(nonce.to_owned());
                Ok(height)
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
              StorageError::LedgerReadLockFailed,
            ))
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

  async fn read_ledger_tail(
    &self,
    handle: &Handle,
  ) -> Result<(LedgerEntry, usize), LedgerStoreError> {
    if let Ok(ledgers_map) = self.ledgers.read() {
      if ledgers_map.contains_key(handle) {
        if let Ok(ledgers) = ledgers_map[handle].read() {
          let ledgers_entry = ledgers[ledgers.len() - 1].clone();
          Ok((ledgers_entry, ledgers.len() - 1))
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
    expected_height: usize,
  ) -> Result<usize, LedgerStoreError> {
    if let Ok(mut view_ledger_array) = self.view_ledger.write() {
      if expected_height == view_ledger_array.len() {
        let ledger_entry = LedgerEntry::new(block.clone(), Receipts::new(), None);
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

  async fn attach_view_ledger_receipts(
    &self,
    idx: usize,
    receipts: &Receipts,
  ) -> Result<(), LedgerStoreError> {
    if let Ok(mut view_ledger_array) = self.view_ledger.write() {
      let height = idx;
      if height < view_ledger_array.len() {
        view_ledger_array[height].receipts.merge_receipts(receipts);
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

  async fn read_view_ledger_tail(&self) -> Result<(LedgerEntry, usize), LedgerStoreError> {
    if let Ok(view_ledger_array) = self.view_ledger.read() {
      let ledger_entry = view_ledger_array[view_ledger_array.len() - 1].clone();
      Ok((ledger_entry, view_ledger_array.len() - 1))
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
