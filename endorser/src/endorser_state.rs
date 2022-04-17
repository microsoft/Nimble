use crate::errors::EndorserError;
use ledger::{
  produce_hash_of_state,
  signature::{PrivateKey, PrivateKeyTrait, PublicKey},
  Handle, IdSig, LedgerTailMap, LedgerView, MetaBlock, NimbleDigest, NimbleHashTrait, Receipt,
};
use std::{
  collections::{hash_map, HashMap},
  sync::{Arc, RwLock},
};

struct ViewLedgerState {
  view_ledger_tail_metablock: MetaBlock,

  view_ledger_tail_hash: NimbleDigest,

  /// whether the endorser is initialized
  is_initialized: bool,

  /// whether the endorser is locked for append operations
  is_locked: bool,
}

type ProtectedMetaBlock = Arc<RwLock<MetaBlock>>;

/// Endorser's internal state
pub struct EndorserState {
  /// a key pair in a digital signature scheme
  private_key: PrivateKey,
  public_key: PublicKey,

  /// a map from fixed-sized labels to a tail hash and a counter
  ledger_tail_map: Arc<RwLock<HashMap<Handle, ProtectedMetaBlock>>>,

  view_ledger_state: Arc<RwLock<ViewLedgerState>>,
}

impl EndorserState {
  pub fn new() -> Self {
    let private_key = PrivateKey::new();
    let public_key = private_key.get_public_key().unwrap();
    EndorserState {
      private_key,
      public_key,
      ledger_tail_map: Arc::new(RwLock::new(HashMap::new())),
      view_ledger_state: Arc::new(RwLock::new(ViewLedgerState {
        view_ledger_tail_metablock: MetaBlock::default(),
        view_ledger_tail_hash: MetaBlock::default().hash(),
        is_initialized: false,
        is_locked: false,
      })),
    }
  }

  pub fn initialize_state(
    &self,
    ledger_tail_map: &LedgerTailMap,
    view_ledger_tail_metablock: &MetaBlock,
    block_hash: &NimbleDigest,
    expected_height: usize,
  ) -> Result<Receipt, EndorserError> {
    if let Ok(mut view_ledger_state) = self.view_ledger_state.write() {
      if view_ledger_state.is_initialized {
        return Err(EndorserError::AlreadyInitialized);
      }

      if let Ok(mut ledger_tail_map_wr) = self.ledger_tail_map.write() {
        for (handle, metablock) in ledger_tail_map {
          ledger_tail_map_wr.insert(*handle, Arc::new(RwLock::new(metablock.clone())));
        }
      }

      view_ledger_state.view_ledger_tail_metablock = view_ledger_tail_metablock.clone();
      view_ledger_state.view_ledger_tail_hash = view_ledger_tail_metablock.hash();
      view_ledger_state.is_initialized = true;
    } else {
      return Err(EndorserError::FailedToAcquireViewLedgerWriteLock);
    }

    self.append_view_ledger(block_hash, expected_height)
  }

  pub fn new_ledger(
    &self,
    handle: &NimbleDigest,
    ignore_lock: bool,
  ) -> Result<Receipt, EndorserError> {
    if let Ok(view_ledger_state) = self.view_ledger_state.read() {
      if !view_ledger_state.is_initialized {
        return Err(EndorserError::NotInitialized);
      }

      if !ignore_lock && view_ledger_state.is_locked {
        return Err(EndorserError::IsLocked);
      }

      // create a genesis metablock that embeds the current tail of the view/membership ledger
      let view = view_ledger_state.view_ledger_tail_hash;
      let metablock = MetaBlock::genesis(handle);
      let message = view.digest_with(&metablock.hash());
      let signature = self
        .private_key
        .sign(message.to_bytes().as_slice())
        .unwrap();

      // check if the handle already exists, if so, return an error
      if let Ok(mut ledger_tail_map) = self.ledger_tail_map.write() {
        if let hash_map::Entry::Vacant(e) = ledger_tail_map.entry(*handle) {
          e.insert(Arc::new(RwLock::new(metablock.clone())));
          Ok(Receipt::new(
            view,
            metablock,
            vec![IdSig::new(self.public_key.clone(), signature)],
          ))
        } else {
          Err(EndorserError::LedgerExists)
        }
      } else {
        Err(EndorserError::FailedToAcquireLedgerMapWriteLock)
      }
    } else {
      Err(EndorserError::FailedToAcquireViewLedgerReadLock)
    }
  }

  pub fn read_latest(&self, handle: &NimbleDigest, nonce: &[u8]) -> Result<Receipt, EndorserError> {
    if let Ok(view_ledger_state) = self.view_ledger_state.read() {
      if !view_ledger_state.is_initialized {
        return Err(EndorserError::NotInitialized);
      }

      if let Ok(ledger_tail_map) = self.ledger_tail_map.read() {
        match ledger_tail_map.get(handle) {
          None => Err(EndorserError::InvalidLedgerName),
          Some(protected_metablock) => {
            if let Ok(metablock) = protected_metablock.read() {
              let view = view_ledger_state.view_ledger_tail_hash;
              let tail_hash = metablock.hash();
              let message = view.digest_with(&tail_hash.digest_with_bytes(nonce));
              let signature = self.private_key.sign(&message.to_bytes()).unwrap();

              Ok(Receipt::new(
                view,
                metablock.clone(),
                vec![IdSig::new(self.public_key.clone(), signature)],
              ))
            } else {
              Err(EndorserError::FailedToAcquireLedgerEntryReadLock)
            }
          },
        }
      } else {
        Err(EndorserError::FailedToAcquireLedgerMapReadLock)
      }
    } else {
      Err(EndorserError::FailedToAcquireViewLedgerReadLock)
    }
  }

  pub fn get_height(&self, handle: &NimbleDigest) -> Result<usize, EndorserError> {
    if let Ok(view_ledger_state) = self.view_ledger_state.read() {
      if !view_ledger_state.is_initialized {
        return Err(EndorserError::NotInitialized);
      }

      if let Ok(ledger_tail_map) = self.ledger_tail_map.read() {
        match ledger_tail_map.get(handle) {
          None => Err(EndorserError::InvalidLedgerName),
          Some(protected_metablock) => {
            if let Ok(metablock) = protected_metablock.read() {
              Ok(metablock.get_height())
            } else {
              Err(EndorserError::FailedToAcquireLedgerEntryReadLock)
            }
          },
        }
      } else {
        Err(EndorserError::FailedToAcquireLedgerMapReadLock)
      }
    } else {
      Err(EndorserError::FailedToAcquireViewLedgerReadLock)
    }
  }

  pub fn append(
    &self,
    handle: &NimbleDigest,
    block_hash: &NimbleDigest,
    expected_height: usize,
    ignore_lock: bool,
  ) -> Result<Receipt, EndorserError> {
    if let Ok(view_ledger_state) = self.view_ledger_state.read() {
      if !view_ledger_state.is_initialized {
        return Err(EndorserError::NotInitialized);
      }

      if !ignore_lock && view_ledger_state.is_locked {
        return Err(EndorserError::IsLocked);
      }

      if let Ok(ledger_tail_map) = self.ledger_tail_map.read() {
        match ledger_tail_map.get(handle) {
          None => Err(EndorserError::InvalidLedgerName),
          Some(protected_metablock) => {
            if let Ok(mut metablock) = protected_metablock.write() {
              // increment height and returning an error in case of overflow
              let height_plus_one = {
                let res = metablock.get_height().checked_add(1);
                if res.is_none() {
                  return Err(EndorserError::LedgerHeightOverflow);
                }
                res.unwrap()
              };

              assert!(expected_height != 0);
              if expected_height < height_plus_one {
                return Err(EndorserError::InvalidTailHeight);
              }

              if expected_height > height_plus_one {
                return Err(EndorserError::OutOfOrderAppend);
              }

              let new_metablock = MetaBlock::new(&metablock.hash(), block_hash, height_plus_one);

              let view = view_ledger_state.view_ledger_tail_hash;
              let signature = self
                .private_key
                .sign(&view.digest_with(&new_metablock.hash()).to_bytes())
                .unwrap();

              *metablock = new_metablock.clone();
              Ok(Receipt::new(
                view,
                new_metablock,
                vec![IdSig::new(self.public_key.clone(), signature)],
              ))
            } else {
              Err(EndorserError::FailedToAcquireLedgerEntryWriteLock)
            }
          },
        }
      } else {
        Err(EndorserError::FailedToAcquireLedgerMapReadLock)
      }
    } else {
      Err(EndorserError::FailedToAcquireViewLedgerReadLock)
    }
  }

  pub fn get_public_key(&self) -> PublicKey {
    self.public_key.clone()
  }

  pub fn append_view_ledger(
    &self,
    block_hash: &NimbleDigest,
    expected_height: usize,
  ) -> Result<Receipt, EndorserError> {
    if let Ok(mut view_ledger_state) = self.view_ledger_state.write() {
      if !view_ledger_state.is_initialized {
        Err(EndorserError::NotInitialized)
      } else {
        let metablock = &view_ledger_state.view_ledger_tail_metablock;

        // perform a checked addition of height with 1
        let height_plus_one = {
          let res = metablock.get_height().checked_add(1);
          if res.is_none() {
            return Err(EndorserError::LedgerHeightOverflow);
          }
          res.unwrap()
        };

        assert!(expected_height != 0);
        if expected_height < height_plus_one {
          return Err(EndorserError::InvalidTailHeight);
        }

        if expected_height > height_plus_one {
          return Err(EndorserError::OutOfOrderAppend);
        }

        let mut ledger_tail_map = HashMap::new();
        if let Ok(ledger_tail_map_rd) = self.ledger_tail_map.read() {
          for (handle, value) in ledger_tail_map_rd.iter() {
            if let Ok(metablock) = value.read() {
              ledger_tail_map.insert(*handle, metablock.clone());
            } else {
              return Err(EndorserError::FailedToAcquireLedgerEntryReadLock);
            }
          }
        } else {
          return Err(EndorserError::FailedToAcquireLedgerMapReadLock);
        }

        // the view embedded in the view ledger is the hash of the current state of the endorser
        let view = produce_hash_of_state(&ledger_tail_map);
        let prev = &view_ledger_state.view_ledger_tail_hash;

        // formulate a metablock for the new entry on the view ledger; and hash it to get the updated tail hash
        let new_metablock = MetaBlock::new(prev, block_hash, height_plus_one);

        // update the internal state
        view_ledger_state.view_ledger_tail_metablock = new_metablock.clone();
        view_ledger_state.view_ledger_tail_hash = new_metablock.hash();

        // sign the hash of the new metablock
        let message = view.digest_with(&view_ledger_state.view_ledger_tail_hash);
        let signature = self.private_key.sign(&message.to_bytes()).unwrap();

        Ok(Receipt::new(
          view,
          new_metablock,
          vec![IdSig::new(self.public_key.clone(), signature)],
        ))
      }
    } else {
      Err(EndorserError::FailedToAcquireViewLedgerReadLock)
    }
  }

  pub fn read_latest_state(&self) -> Result<LedgerView, EndorserError> {
    if let Ok(view_ledger_state) = self.view_ledger_state.read() {
      if !view_ledger_state.is_initialized {
        return Err(EndorserError::NotInitialized);
      }

      let mut ledger_tail_map = HashMap::new();
      if let Ok(ledger_tail_map_rd) = self.ledger_tail_map.read() {
        for (handle, value) in ledger_tail_map_rd.iter() {
          if let Ok(metablock) = value.read() {
            ledger_tail_map.insert(*handle, metablock.clone());
          } else {
            return Err(EndorserError::FailedToAcquireLedgerEntryReadLock);
          }
        }
      } else {
        return Err(EndorserError::FailedToAcquireLedgerMapReadLock);
      }

      let ledger_view = LedgerView {
        view_tail_metablock: view_ledger_state.view_ledger_tail_metablock.clone(),
        ledger_tail_map,
      };

      Ok(ledger_view)
    } else {
      Err(EndorserError::FailedToAcquireViewLedgerReadLock)
    }
  }

  pub fn lock(&self) -> Result<(), EndorserError> {
    if let Ok(mut view_ledger_state) = self.view_ledger_state.write() {
      view_ledger_state.is_locked = true;
      Ok(())
    } else {
      Err(EndorserError::FailedToAcquireViewLedgerWriteLock)
    }
  }

  pub fn unlock(&self) -> Result<(), EndorserError> {
    if let Ok(mut view_ledger_state) = self.view_ledger_state.write() {
      view_ledger_state.is_locked = false;
      Ok(())
    } else {
      Err(EndorserError::FailedToAcquireViewLedgerWriteLock)
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use rand::Rng;

  #[test]
  pub fn check_endorser_new_ledger_and_get_tail() {
    let endorser_state = EndorserState::new();

    // The coordinator sends the hashed contents of the configuration to the endorsers
    // We will pick a dummy view value for testing purposes
    let view_block_hash = {
      let t = rand::thread_rng().gen::<[u8; 32]>();
      let n = NimbleDigest::from_bytes(&t);
      assert!(n.is_ok(), "This should not have occured");
      n.unwrap()
    };

    // perform a checked addition of height with 1
    let height_plus_one = {
      let res = endorser_state
        .view_ledger_state
        .read()
        .expect("failed to read")
        .view_ledger_tail_metablock
        .get_height()
        .checked_add(1);
      assert!(res.is_some());
      res.unwrap()
    };

    // The coordinator initializes the endorser by calling initialize_state
    let res = endorser_state.initialize_state(
      &HashMap::new(),
      &MetaBlock::default(),
      &view_block_hash,
      height_plus_one,
    );
    assert!(res.is_ok());

    // The coordinator sends the hashed contents of the block to the endorsers
    let handle = {
      let t = rand::thread_rng().gen::<[u8; 32]>();
      let n = NimbleDigest::from_bytes(&t);
      assert!(n.is_ok(), "This should not have occured");
      n.unwrap()
    };
    let res = endorser_state.new_ledger(&handle, false);
    assert!(res.is_ok());

    let receipt = res.unwrap();
    let genesis_tail_hash = MetaBlock::genesis(&handle).hash();
    assert_eq!(
      *receipt.get_view(),
      endorser_state
        .view_ledger_state
        .read()
        .expect("failed")
        .view_ledger_tail_hash,
    );
    assert!(receipt
      .verify(
        &genesis_tail_hash.to_bytes(),
        &[endorser_state.public_key.clone()],
      )
      .is_ok());

    // Fetch the value currently in the tail.
    let tail_result = endorser_state.read_latest(&handle, &[0]);
    assert!(tail_result.is_ok());

    let ledger_tail_map = endorser_state.ledger_tail_map.read().expect("failed");

    let metablock = ledger_tail_map
      .get(&handle)
      .unwrap()
      .read()
      .expect("failed");
    assert_eq!(metablock.get_height(), 0usize);
    assert_eq!(metablock.hash(), genesis_tail_hash);
  }

  #[test]
  pub fn check_endorser_append_ledger_tail() {
    let endorser_state = EndorserState::new();

    // The coordinator sends the hashed contents of the configuration to the endorsers
    // We will pick a dummy view value for testing purposes
    let view_block_hash = {
      let t = rand::thread_rng().gen::<[u8; 32]>();
      let n = NimbleDigest::from_bytes(&t);
      assert!(n.is_ok(), "This should not have occured");
      n.unwrap()
    };

    // perform a checked addition of height with 1
    let height_plus_one = {
      let res = endorser_state
        .view_ledger_state
        .read()
        .expect("failed")
        .view_ledger_tail_metablock
        .get_height()
        .checked_add(1);
      assert!(res.is_some());
      res.unwrap()
    };

    // The coordinator initializes the endorser by calling initialize_state
    let res = endorser_state.initialize_state(
      &HashMap::new(),
      &MetaBlock::default(),
      &view_block_hash,
      height_plus_one,
    );
    assert!(res.is_ok());

    // The coordinator sends the hashed contents of the block to the endorsers
    let block = rand::thread_rng().gen::<[u8; 32]>();
    let handle = NimbleDigest::from_bytes(&block).unwrap();
    let res = endorser_state.new_ledger(&handle, false);
    assert!(res.is_ok());

    // Fetch the value currently in the tail.
    let prev_tail = endorser_state
      .ledger_tail_map
      .read()
      .expect("failed")
      .get(&handle)
      .unwrap()
      .read()
      .expect("failed")
      .hash();
    let block_hash_to_append_data = rand::thread_rng().gen::<[u8; 32]>();
    let block_hash_to_append = NimbleDigest::from_bytes(&block_hash_to_append_data).unwrap();

    let height_plus_one = {
      let height = endorser_state
        .ledger_tail_map
        .read()
        .expect("failed")
        .get(&handle)
        .unwrap()
        .read()
        .expect("failed")
        .get_height();
      let res = height.checked_add(1);
      if res.is_none() {
        panic!("Height overflow");
      }
      res.unwrap()
    };

    let receipt = endorser_state
      .append(&handle, &block_hash_to_append, height_plus_one, false)
      .unwrap();
    let new_ledger_height = endorser_state
      .ledger_tail_map
      .read()
      .expect("failed")
      .get(&handle)
      .unwrap()
      .read()
      .expect("failed")
      .get_height();
    assert_eq!(
      *receipt.get_view(),
      endorser_state
        .view_ledger_state
        .read()
        .expect("failed")
        .view_ledger_tail_hash
    );
    assert_eq!(*receipt.get_prev(), prev_tail);
    assert_eq!(new_ledger_height, height_plus_one);

    let metadata = MetaBlock::new(&prev_tail, &block_hash_to_append, new_ledger_height);

    let endorser_tail_expectation = metadata.hash();
    let message = endorser_tail_expectation;
    let tail_signature_verification =
      receipt.verify(&message.to_bytes(), &[endorser_state.public_key.clone()]);

    if tail_signature_verification.is_ok() {
      println!("Verification Passed. Checking Updated Tail");
      let ledger_tail_map = endorser_state.ledger_tail_map.read().expect("failed");
      let metablock = ledger_tail_map
        .get(&handle)
        .unwrap()
        .read()
        .expect("failed");
      assert_eq!(endorser_tail_expectation, metablock.hash());
    } else {
      panic!("Signature verification failed when it should not have failed");
    }
  }
}
