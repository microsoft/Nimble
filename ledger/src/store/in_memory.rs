use super::{Block, Handle, MetaBlock, NimbleDigest, NimbleHashTrait, Receipt};
use crate::errors::StorageError;
use crate::store::{LedgerEntry, LedgerStore, LedgerStoreState};
use std::collections::{hash_map, HashMap};
use std::sync::{Arc, RwLock};

type LedgerArray = Arc<RwLock<Vec<LedgerEntry>>>;

#[derive(Debug, Default)]
pub struct InMemoryLedgerStore {
  ledgers: Arc<RwLock<HashMap<Handle, LedgerArray>>>,
  view_ledger: Arc<RwLock<Vec<LedgerEntry>>>,
}

impl LedgerStore for InMemoryLedgerStore {
  fn new() -> Result<Self, StorageError>
  where
    Self: Sized,
  {
    let ledgers = HashMap::new();
    let mut view_ledger = Vec::new();

    let view_ledger_entry = LedgerEntry {
      block: Block::new(&[0; 0]),
      aux: MetaBlock::new(
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

    Ok(InMemoryLedgerStore {
      ledgers: Arc::new(RwLock::new(ledgers)),
      view_ledger: Arc::new(RwLock::new(view_ledger)),
    })
  }

  fn create_ledger(
    &self,
    block: &Block,
  ) -> Result<(Handle, MetaBlock, NimbleDigest), StorageError> {
    if let Ok(view_ledger_array) = self.view_ledger.read() {
      let handle = block.hash();
      let block_hash = block.hash();
      let aux = MetaBlock::new(
        &view_ledger_array[view_ledger_array.len() - 1].aux.hash(),
        &NimbleDigest::default(),
        &block_hash,
        0,
      );
      let ledger_entry = LedgerEntry {
        block: block.clone(),
        aux: aux.clone(),
        receipt: Receipt {
          id_sigs: Vec::new(),
        },
      };
      if let Ok(mut ledgers_map) = self.ledgers.write() {
        if let hash_map::Entry::Vacant(e) = ledgers_map.entry(handle) {
          let tail_hash = ledger_entry.aux.hash();
          e.insert(Arc::new(RwLock::new(vec![ledger_entry])));
          Ok((handle, aux, tail_hash))
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
            let last_entry = &ledgers[ledgers.len() - 1].aux;
            if *cond == NimbleDigest::default() || *cond == last_entry.hash() {
              let block_hash = block.hash();
              let ledger_entry = LedgerEntry {
                block: block.clone(),
                aux: MetaBlock::new(
                  &view_ledger_array[view_ledger_array.len() - 1].aux.hash(),
                  &last_entry.hash(),
                  &block_hash,
                  last_entry.get_height() + 1,
                ),
                receipt: Receipt {
                  id_sigs: Vec::new(),
                },
              };
              let tail_hash = ledger_entry.aux.hash();
              let aux = ledger_entry.aux.clone();
              ledgers.push(ledger_entry);
              Ok((aux, tail_hash))
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
    aux: &MetaBlock,
    receipt: &Receipt,
  ) -> Result<(), StorageError> {
    if let Ok(ledgers_map) = self.ledgers.read() {
      if ledgers_map.contains_key(handle) {
        if let Ok(mut ledgers) = ledgers_map[handle].write() {
          if aux.get_height() < ledgers.len() {
            ledgers[aux.get_height()].receipt = receipt.clone();
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

  fn append_view_ledger(&self, block: &Block) -> Result<(MetaBlock, NimbleDigest), StorageError> {
    if let Ok(mut view_ledger_array) = self.view_ledger.write() {
      if let Ok(ledger_map) = self.ledgers.read() {
        let last_view_ledger_entry_aux = &view_ledger_array[view_ledger_array.len() - 1].aux;
        let block_hash = block.hash();

        let state_hash = {
          if ledger_map.is_empty() || view_ledger_array.len() == 1 {
            NimbleDigest::default()
          } else {
            let ledger_store_state = LedgerStoreState {
              ledger_tail_map: ledger_map
                .iter()
                .map(|(handle, ledger)| {
                  (
                    handle.to_bytes(),
                    ({
                      let ledger_array = ledger.read().expect("failed to read a ledger");
                      let last_ledger_entry_aux = &ledger_array[ledger_array.len() - 1].aux;
                      (
                        last_ledger_entry_aux.hash().to_bytes(),
                        last_ledger_entry_aux.get_height(),
                      )
                    }),
                  )
                })
                .collect(),
              view_ledger_tail: (
                last_view_ledger_entry_aux.hash().to_bytes(),
                last_view_ledger_entry_aux.get_height(),
              ),
            };
            let serialized_ledger_store_state = bincode::serialize(&ledger_store_state).unwrap();
            NimbleDigest::digest(&serialized_ledger_store_state)
          }
        };

        let ledger_entry = LedgerEntry {
          block: block.clone(),
          aux: MetaBlock::new(
            &state_hash,
            &if view_ledger_array.len() == 1 {
              NimbleDigest::default()
            } else {
              last_view_ledger_entry_aux.hash()
            },
            &block_hash,
            last_view_ledger_entry_aux.get_height() + 1,
          ),
          receipt: Receipt {
            id_sigs: Vec::new(),
          },
        };
        let tail_hash = ledger_entry.aux.hash();
        let aux = ledger_entry.aux.clone();
        view_ledger_array.push(ledger_entry);
        Ok((aux, tail_hash))
      } else {
        Err(StorageError::LedgerMapReadLockFailed)
      }
    } else {
      Err(StorageError::ViewLedgerWriteLockFailed)
    }
  }

  fn attach_view_ledger_receipt(
    &self,
    aux: &MetaBlock,
    receipt: &Receipt,
  ) -> Result<(), StorageError> {
    if let Ok(mut view_ledger_array) = self.view_ledger.write() {
      if aux.get_height() < view_ledger_array.len() {
        view_ledger_array[aux.get_height()].receipt = receipt.clone();
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

  #[cfg(test)]
  fn reset_store(&self) -> Result<(), StorageError> {
    // not really needed for in-memory since state is already volatile.
    // this API is only for testing persistent storage services.
    // we could implement it here anyway, but choose not to for now.
    Ok(())
  }
}
