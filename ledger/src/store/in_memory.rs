use super::{Block, Handle, MetaBlock, NimbleDigest, NimbleHashTrait, Receipt};
use crate::errors::StorageError;
use crate::store::{LedgerEntry, LedgerStore, LedgerView};
use itertools::Itertools;
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

    let view_ledger_entry = LedgerEntry {
      block: Block::new(&[0; 0]),
      metablock: MetaBlock::new(
        &NimbleDigest::default(),
        &NimbleDigest::default(),
        &NimbleDigest::default(),
        0,
      ),
      receipt: Receipt {
        id_sigs: Vec::new(),
      },
    };
    view_ledger.push(view_ledger_entry);

    InMemoryLedgerStore {
      ledgers: Arc::new(RwLock::new(ledgers)),
      view_ledger: Arc::new(RwLock::new(view_ledger)),
    }
  }
}

impl LedgerStore for InMemoryLedgerStore {
  fn create_ledger(
    &self,
    block: &Block,
  ) -> Result<(Handle, MetaBlock, NimbleDigest), StorageError> {
    if let Ok(view_ledger_array) = self.view_ledger.read() {
      let handle = block.hash();
      let block_hash = block.hash();
      let metablock = MetaBlock::new(
        &view_ledger_array[view_ledger_array.len() - 1]
          .metablock
          .hash(),
        &NimbleDigest::default(),
        &block_hash,
        0,
      );
      let ledger_entry = LedgerEntry {
        block: block.clone(),
        metablock: metablock.clone(),
        receipt: Receipt {
          id_sigs: Vec::new(),
        },
      };
      if let Ok(mut ledgers_map) = self.ledgers.write() {
        if let hash_map::Entry::Vacant(e) = ledgers_map.entry(handle) {
          let tail_hash = ledger_entry.metablock.hash();
          e.insert(Arc::new(RwLock::new(vec![ledger_entry])));
          Ok((handle, metablock, tail_hash))
        } else {
          Err(StorageError::DuplicateKey)
        }
      } else {
        Err(StorageError::LedgerMapWriteLockFailed)
      }
    } else {
      Err(StorageError::ViewLedgerReadLockFailed)
    }
  }

  fn append_ledger(
    &self,
    handle: &Handle,
    block: &Block,
    cond: &NimbleDigest,
  ) -> Result<(MetaBlock, NimbleDigest), StorageError> {
    if let Ok(view_ledger_array) = self.view_ledger.read() {
      if let Ok(ledgers_map) = self.ledgers.read() {
        if ledgers_map.contains_key(handle) {
          if let Ok(mut ledgers) = ledgers_map[handle].write() {
            let last_entry = &ledgers[ledgers.len() - 1].metablock;
            if *cond == NimbleDigest::default() || *cond == last_entry.hash() {
              let block_hash = block.hash();
              let ledger_entry = LedgerEntry {
                block: block.clone(),
                metablock: MetaBlock::new(
                  &view_ledger_array[view_ledger_array.len() - 1]
                    .metablock
                    .hash(),
                  &last_entry.hash(),
                  &block_hash,
                  last_entry.get_height() + 1,
                ),
                receipt: Receipt {
                  id_sigs: Vec::new(),
                },
              };
              let tail_hash = ledger_entry.metablock.hash();
              let metablock = ledger_entry.metablock.clone();
              ledgers.push(ledger_entry);
              Ok((metablock, tail_hash))
            } else {
              Err(StorageError::IncorrectConditionalData)
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
    } else {
      Err(StorageError::ViewLedgerReadLockFailed)
    }
  }

  fn attach_ledger_receipt(
    &self,
    handle: &Handle,
    metablock: &MetaBlock,
    receipt: &Receipt,
  ) -> Result<(), StorageError> {
    if let Ok(ledgers_map) = self.ledgers.read() {
      if ledgers_map.contains_key(handle) {
        if let Ok(mut ledgers) = ledgers_map[handle].write() {
          if metablock.get_height() < ledgers.len() {
            ledgers[metablock.get_height()].receipt = receipt.clone();
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

  fn read_ledger_tail(&self, handle: &Handle) -> Result<LedgerEntry, StorageError> {
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

  fn read_ledger_by_index(&self, handle: &Handle, idx: usize) -> Result<LedgerEntry, StorageError> {
    if let Ok(ledgers_map) = self.ledgers.read() {
      if ledgers_map.contains_key(handle) {
        if let Ok(ledgers) = ledgers_map[handle].read() {
          if idx < ledgers.len() {
            Ok(ledgers[idx].clone())
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

  fn append_view_ledger(&self, block: &Block) -> Result<LedgerView, StorageError> {
    let mut ledger_tail_map = HashMap::new();
    if let Ok(mut view_ledger_array) = self.view_ledger.write() {
      if let Ok(ledger_map) = self.ledgers.read() {
        let last_view_ledger_entry_metablock =
          &view_ledger_array[view_ledger_array.len() - 1].metablock;
        let block_hash = block.hash();

        let state_hash = {
          if ledger_map.is_empty() || view_ledger_array.len() == 1 {
            NimbleDigest::default()
          } else {
            let mut serialized_state = Vec::new();
            for handle in ledger_map.keys().sorted() {
              let ledger_array = ledger_map[handle].read().expect("failed to read a ledger");
              let last_ledger_entry_metablock = &ledger_array[ledger_array.len() - 1].metablock;
              let tail = last_ledger_entry_metablock.hash();
              let height = last_ledger_entry_metablock.get_height();
              serialized_state.extend_from_slice(&handle.to_bytes());
              serialized_state.extend_from_slice(&tail.to_bytes());
              serialized_state.extend_from_slice(&height.to_le_bytes());
              ledger_tail_map.insert(*handle, (tail, height));
            }
            NimbleDigest::digest(&serialized_state)
          }
        };

        let ledger_entry = LedgerEntry {
          block: block.clone(),
          metablock: MetaBlock::new(
            &state_hash,
            &if view_ledger_array.len() == 1 {
              NimbleDigest::default()
            } else {
              last_view_ledger_entry_metablock.hash()
            },
            &block_hash,
            last_view_ledger_entry_metablock.get_height() + 1,
          ),
          receipt: Receipt {
            id_sigs: Vec::new(),
          },
        };
        let tail_hash = ledger_entry.metablock.hash();
        let metablock = ledger_entry.metablock.clone();
        view_ledger_array.push(ledger_entry);
        Ok(LedgerView {
          view_tail_metablock: metablock,
          view_tail_hash: tail_hash,
          ledger_tail_map,
        })
      } else {
        Err(StorageError::LedgerMapReadLockFailed)
      }
    } else {
      Err(StorageError::ViewLedgerWriteLockFailed)
    }
  }

  fn attach_view_ledger_receipt(
    &self,
    metablock: &MetaBlock,
    receipt: &Receipt,
  ) -> Result<(), StorageError> {
    if let Ok(mut view_ledger_array) = self.view_ledger.write() {
      if metablock.get_height() < view_ledger_array.len() {
        view_ledger_array[metablock.get_height()].receipt = receipt.clone();
        Ok(())
      } else {
        Err(StorageError::InvalidIndex)
      }
    } else {
      Err(StorageError::ViewLedgerWriteLockFailed)
    }
  }

  fn read_view_ledger_tail(&self) -> Result<LedgerEntry, StorageError> {
    if let Ok(view_ledger_array) = self.view_ledger.read() {
      Ok(view_ledger_array[view_ledger_array.len() - 1].clone())
    } else {
      Err(StorageError::ViewLedgerReadLockFailed)
    }
  }

  fn read_view_ledger_by_index(&self, idx: usize) -> Result<LedgerEntry, StorageError> {
    if let Ok(view_ledger_array) = self.view_ledger.read() {
      if idx < view_ledger_array.len() {
        Ok(view_ledger_array[idx].clone())
      } else {
        Err(StorageError::InvalidIndex)
      }
    } else {
      Err(StorageError::ViewLedgerReadLockFailed)
    }
  }

  fn reset_store(&self) -> Result<(), StorageError> {
    // not really needed for in-memory since state is already volatile.
    // this API is only for testing persistent storage services.
    // we could implement it here anyway, but choose not to for now.
    Ok(())
  }
}
