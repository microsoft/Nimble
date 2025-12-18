use crate::errors::EndorserError;

use itertools::Itertools;

use ledger::endorser_proto::{EndorserMode, LedgerChunkEntry, LedgerTailMap, LedgerTailMapEntry};

use ledger::{
  produce_hash_of_state,
  signature::{PrivateKey, PrivateKeyTrait, PublicKey},
  Block, CustomSerde, Handle, IdSig, MetaBlock, NimbleDigest, NimbleHashTrait, Nonces, Receipt,
  Receipts,
};
use std::{
  collections::{hash_map, HashMap},
  ops::{Deref, DerefMut},
  sync::{Arc, RwLock},
};

struct ViewLedgerState {
  view_ledger_tail_metablock: MetaBlock,

  view_ledger_tail_hash: NimbleDigest,

  view_ledger_prev_metablock: MetaBlock,

  /// Endorser has 4 modes: uninitialized, initialized, active, finalized
  endorser_mode: EndorserMode,

  /// Endorser's group identity
  group_identity: NimbleDigest,
}

type ProtectedMetaBlock = Arc<RwLock<(MetaBlock, Block, Nonces)>>;

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
        view_ledger_prev_metablock: MetaBlock::default(),
        endorser_mode: EndorserMode::Uninitialized,
        group_identity: NimbleDigest::default(),
      })),
    }
  }

  pub fn initialize_state(
    &self,
    group_identity: &NimbleDigest,
    ledger_tail_map: &Vec<LedgerTailMapEntry>,
    view_ledger_tail_metablock: &MetaBlock,
    block_hash: &NimbleDigest,
    expected_height: usize,
  ) -> Result<Receipt, EndorserError> {
    if let Ok(mut view_ledger_state) = self.view_ledger_state.write() {
      if view_ledger_state.endorser_mode != EndorserMode::Uninitialized {
        return Err(EndorserError::AlreadyInitialized);
      }

      if let Ok(mut ledger_tail_map_wr) = self.ledger_tail_map.write() {
        for entry in ledger_tail_map {
          ledger_tail_map_wr.insert(
            NimbleDigest::from_bytes(&entry.handle).unwrap(),
            Arc::new(RwLock::new((
              MetaBlock::from_bytes(&entry.metablock).unwrap(),
              Block::from_bytes(&entry.block).unwrap(),
              Nonces::from_bytes(&entry.nonces).unwrap(),
            ))),
          );
        }
      }

      view_ledger_state.view_ledger_prev_metablock =
        view_ledger_state.view_ledger_tail_metablock.clone();
      view_ledger_state.view_ledger_tail_metablock = view_ledger_tail_metablock.clone();
      view_ledger_state.view_ledger_tail_hash = view_ledger_state.view_ledger_tail_metablock.hash();
      view_ledger_state.endorser_mode = EndorserMode::Initialized;
      view_ledger_state.group_identity = *group_identity;

      self.append_view_ledger(
        view_ledger_state.deref_mut(),
        ledger_tail_map,
        block_hash,
        expected_height,
      )
    } else {
      Err(EndorserError::FailedToAcquireViewLedgerWriteLock)
    }
  }

  pub fn new_ledger(
    &self,
    handle: &NimbleDigest,
    block_hash: &NimbleDigest,
    block: &Block,
  ) -> Result<Receipt, EndorserError> {
    if let Ok(view_ledger_state) = self.view_ledger_state.read() {
      match view_ledger_state.endorser_mode {
        EndorserMode::Uninitialized | EndorserMode::Initialized => {
          return Err(EndorserError::NotActive);
        },
        EndorserMode::Finalized => {
          return Err(EndorserError::AlreadyFinalized);
        },
        _ => {},
      }

      // create a genesis metablock that embeds the current tail of the view/membership ledger
      let view = view_ledger_state.view_ledger_tail_hash;
      let metablock = MetaBlock::genesis(block_hash);
      let message = view_ledger_state
        .group_identity
        .digest_with(&view.digest_with(&handle.digest_with(&metablock.hash())));
      let signature = self.private_key.sign(&message.to_bytes()).unwrap();

      // check if the handle already exists, if so, return an error
      if let Ok(mut ledger_tail_map) = self.ledger_tail_map.write() {
        if let hash_map::Entry::Vacant(e) = ledger_tail_map.entry(*handle) {
          e.insert(Arc::new(RwLock::new((
            metablock.clone(),
            block.clone(),
            Nonces::new(),
          ))));
          Ok(Receipt::new(
            view,
            metablock,
            IdSig::new(self.public_key.clone(), signature),
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

  pub fn read_latest(
    &self,
    handle: &NimbleDigest,
    nonce: &[u8],
  ) -> Result<(Receipt, Block, Nonces), EndorserError> {
    if let Ok(view_ledger_state) = self.view_ledger_state.read() {
      match view_ledger_state.endorser_mode {
        EndorserMode::Uninitialized | EndorserMode::Initialized => {
          return Err(EndorserError::NotActive);
        },
        EndorserMode::Finalized => {
          return Err(EndorserError::AlreadyFinalized);
        },
        _ => {},
      }

      if let Ok(ledger_tail_map) = self.ledger_tail_map.read() {
        match ledger_tail_map.get(handle) {
          None => Err(EndorserError::InvalidLedgerName),
          Some(protected_metablock) => {
            if let Ok(e) = protected_metablock.read() {
              let view = view_ledger_state.view_ledger_tail_hash;
              let metablock = &e.0;
              let tail_hash = metablock.hash();
              let message = view_ledger_state.group_identity.digest_with(
                &view.digest_with(&handle.digest_with(&tail_hash.digest_with_bytes(nonce))),
              );
              let signature = self.private_key.sign(&message.to_bytes()).unwrap();

              Ok((
                Receipt::new(
                  view,
                  metablock.clone(),
                  IdSig::new(self.public_key.clone(), signature),
                ),
                e.1.clone(),
                e.2.clone(),
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
      match view_ledger_state.endorser_mode {
        EndorserMode::Uninitialized | EndorserMode::Initialized => {
          return Err(EndorserError::NotActive);
        },
        EndorserMode::Finalized => {
          return Err(EndorserError::AlreadyFinalized);
        },
        _ => {},
      }

      if let Ok(ledger_tail_map) = self.ledger_tail_map.read() {
        match ledger_tail_map.get(handle) {
          None => Err(EndorserError::InvalidLedgerName),
          Some(protected_metablock) => {
            if let Ok(e) = protected_metablock.read() {
              Ok(e.0.get_height())
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
    block: &Block,
    nonces: &Nonces,
  ) -> Result<Receipt, EndorserError> {
    if let Ok(view_ledger_state) = self.view_ledger_state.read() {
      match view_ledger_state.endorser_mode {
        EndorserMode::Uninitialized | EndorserMode::Initialized => {
          return Err(EndorserError::NotActive);
        },
        EndorserMode::Finalized => {
          return Err(EndorserError::AlreadyFinalized);
        },
        _ => {},
      }

      if let Ok(ledger_tail_map) = self.ledger_tail_map.read() {
        match ledger_tail_map.get(handle) {
          None => Err(EndorserError::InvalidLedgerName),
          Some(protected_metablock) => {
            if let Ok(mut e) = protected_metablock.write() {
              let metablock = &e.0;
              // increment height and returning an error in case of overflow
              let height_plus_one = {
                let res = metablock.get_height().checked_add(1);
                if res.is_none() {
                  return Err(EndorserError::LedgerHeightOverflow);
                }
                res.unwrap()
              };

              if expected_height < height_plus_one {
                return Err(EndorserError::LedgerExists);
              }

              if expected_height > height_plus_one {
                return Err(EndorserError::OutOfOrder);
              }

              let new_metablock = MetaBlock::new(&metablock.hash(), block_hash, height_plus_one);

              let view = view_ledger_state.view_ledger_tail_hash;
              let message = view_ledger_state
                .group_identity
                .digest_with(&view.digest_with(&handle.digest_with(&new_metablock.hash())));

              let signature = self.private_key.sign(&message.to_bytes()).unwrap();

              *e = (new_metablock.clone(), block.clone(), nonces.clone());
              Ok(Receipt::new(
                view,
                new_metablock,
                IdSig::new(self.public_key.clone(), signature),
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

  fn append_view_ledger(
    &self,
    view_ledger_state: &mut ViewLedgerState,
    ledger_tail_map: &Vec<LedgerTailMapEntry>,
    block_hash: &NimbleDigest,
    expected_height: usize,
  ) -> Result<Receipt, EndorserError> {
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
      return Err(EndorserError::OutOfOrder);
    }

    // formulate a metablock for the new entry on the view ledger; and hash it to get the updated tail hash
    let prev = view_ledger_state.view_ledger_tail_hash;
    let new_metablock = MetaBlock::new(&prev, block_hash, height_plus_one);

    // update the internal state
    view_ledger_state.view_ledger_prev_metablock =
      view_ledger_state.view_ledger_tail_metablock.clone();
    view_ledger_state.view_ledger_tail_metablock = new_metablock;
    view_ledger_state.view_ledger_tail_hash = view_ledger_state.view_ledger_tail_metablock.hash();

    Ok(self.sign_view_ledger(view_ledger_state, ledger_tail_map))
  }

  fn sign_view_ledger(
    &self,
    view_ledger_state: &ViewLedgerState,
    ledger_tail_map: &Vec<LedgerTailMapEntry>,
  ) -> Receipt {
    // the view embedded in the view ledger is the hash of the current state of the endorser
    let view = produce_hash_of_state(ledger_tail_map);
    let message = view_ledger_state
      .group_identity
      .digest_with(&view.digest_with(&view_ledger_state.view_ledger_tail_hash));
    let signature = self.private_key.sign(&message.to_bytes()).unwrap();

    Receipt::new(
      view,
      view_ledger_state.view_ledger_tail_metablock.clone(),
      IdSig::new(self.public_key.clone(), signature),
    )
  }

  fn construct_ledger_tail_map(&self) -> Result<Vec<LedgerTailMapEntry>, EndorserError> {
    let mut ledger_tail_map = Vec::new();
    if let Ok(ledger_tail_map_rd) = self.ledger_tail_map.read() {
      for (handle, value) in ledger_tail_map_rd.deref().iter().sorted_by_key(|x| x.0) {
        if let Ok(e) = value.read() {
          ledger_tail_map.push(LedgerTailMapEntry {
            handle: handle.to_bytes(),
            height: e.0.get_height() as u64,
            metablock: e.0.to_bytes(),
            block: e.1.to_bytes(),
            nonces: e.2.to_bytes(),
          });
        } else {
          return Err(EndorserError::FailedToAcquireLedgerEntryReadLock);
        }
      }
    } else {
      return Err(EndorserError::FailedToAcquireLedgerMapReadLock);
    }

    Ok(ledger_tail_map)
  }

  pub fn finalize_state(
    &self,
    block_hash: &NimbleDigest,
    expected_height: usize,
  ) -> Result<(Receipt, Vec<LedgerTailMapEntry>), EndorserError> {
    if let Ok(mut view_ledger_state) = self.view_ledger_state.write() {
      if view_ledger_state.endorser_mode == EndorserMode::Uninitialized
        || view_ledger_state.endorser_mode == EndorserMode::Initialized
      {
        return Err(EndorserError::NotActive);
      };

      let ledger_tail_map = self.construct_ledger_tail_map()?;

      let receipt = if view_ledger_state.endorser_mode == EndorserMode::Finalized {
        self.sign_view_ledger(view_ledger_state.deref(), &ledger_tail_map)
      } else {
        view_ledger_state.endorser_mode = EndorserMode::Finalized;

        self.append_view_ledger(
          view_ledger_state.deref_mut(),
          &ledger_tail_map,
          block_hash,
          expected_height,
        )?
      };

      Ok((receipt, ledger_tail_map))
    } else {
      Err(EndorserError::FailedToAcquireViewLedgerReadLock)
    }
  }

  pub fn read_state(
    &self,
  ) -> Result<(Receipt, EndorserMode, Vec<LedgerTailMapEntry>), EndorserError> {
    if let Ok(view_ledger_state) = self.view_ledger_state.read() {
      let ledger_tail_map = self.construct_ledger_tail_map()?;

      Ok((
        self.sign_view_ledger(view_ledger_state.deref(), &ledger_tail_map),
        view_ledger_state.endorser_mode,
        ledger_tail_map,
      ))
    } else {
      Err(EndorserError::FailedToAcquireViewLedgerReadLock)
    }
  }

  pub fn activate(
    &self,
    old_config: &[u8],
    new_config: &[u8],
    ledger_tail_maps: &Vec<LedgerTailMap>,
    ledger_chunks: &Vec<LedgerChunkEntry>,
    receipts: &Receipts,
  ) -> Result<(), EndorserError> {
    if let Ok(mut view_ledger_state) = self.view_ledger_state.write() {
      match view_ledger_state.endorser_mode {
        EndorserMode::Uninitialized => {
          return Err(EndorserError::NotInitialized);
        },
        EndorserMode::Active => {
          return Err(EndorserError::AlreadyActivated);
        },
        EndorserMode::Finalized => {
          return Err(EndorserError::AlreadyFinalized);
        },
        _ => {},
      }

      let res = receipts.verify_view_change(
        old_config,
        new_config,
        &self.public_key,
        &view_ledger_state.group_identity,
        &view_ledger_state.view_ledger_prev_metablock,
        &view_ledger_state.view_ledger_tail_metablock,
        ledger_tail_maps,
        ledger_chunks,
      );

      if let Err(_e) = res {
        Err(EndorserError::FailedToActivate)
      } else {
        view_ledger_state.endorser_mode = EndorserMode::Active;
        Ok(())
      }
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
      let t = rand::thread_rng().r#gen::<[u8; 32]>();
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
      &view_block_hash,
      &Vec::new(),
      &MetaBlock::default(),
      &view_block_hash,
      height_plus_one,
    );
    assert!(res.is_ok());

    // Set the endorser mode directly
    endorser_state
      .view_ledger_state
      .write()
      .expect("failed to acquire write lock")
      .endorser_mode = ledger::endorser_proto::EndorserMode::Active;

    // The coordinator sends the hashed contents of the block to the endorsers
    let handle = {
      let t = rand::thread_rng().r#gen::<[u8; 32]>();
      let n = NimbleDigest::from_bytes(&t);
      assert!(n.is_ok(), "This should not have occured");
      n.unwrap()
    };

    let t = rand::thread_rng().r#gen::<[u8; 32]>();
    let block = Block::new(&t);

    let block_hash = block.hash();

    let res = endorser_state.new_ledger(&handle, &block_hash, &block);
    assert!(res.is_ok());

    let receipt = res.unwrap();
    let genesis_tail_hash = MetaBlock::genesis(&block_hash).hash();
    assert_eq!(
      *receipt.get_view(),
      endorser_state
        .view_ledger_state
        .read()
        .expect("failed")
        .view_ledger_tail_hash,
    );
    assert!(receipt
      .get_id_sig()
      .verify_with_id(
        &endorser_state.public_key,
        &view_block_hash
          .digest_with(
            &receipt
              .get_view()
              .digest_with(&handle.digest_with(&genesis_tail_hash))
          )
          .to_bytes(),
      )
      .is_ok());

    // Fetch the value currently in the tail.
    let tail_result = endorser_state.read_latest(&handle, &[0]);
    assert!(tail_result.is_ok());

    let ledger_tail_map = endorser_state.ledger_tail_map.read().expect("failed");

    let metablock = &ledger_tail_map
      .get(&handle)
      .unwrap()
      .read()
      .expect("failed")
      .0;
    assert_eq!(metablock.get_height(), 0usize);
    assert_eq!(metablock.hash(), genesis_tail_hash);
  }

  #[test]
  pub fn check_endorser_append_ledger_tail() {
    let endorser_state = EndorserState::new();

    // The coordinator sends the hashed contents of the configuration to the endorsers
    // We will pick a dummy view value for testing purposes
    let view_block_hash = {
      let t = rand::thread_rng().r#gen::<[u8; 32]>();
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
      &view_block_hash,
      &Vec::new(),
      &MetaBlock::default(),
      &view_block_hash,
      height_plus_one,
    );
    assert!(res.is_ok());

    // Set the endorser mode directly
    endorser_state
      .view_ledger_state
      .write()
      .expect("failed to acquire write lock")
      .endorser_mode = ledger::endorser_proto::EndorserMode::Active;

    // The coordinator sends the hashed contents of the block to the endorsers
    let block = Block::new(&rand::thread_rng().r#gen::<[u8; 32]>());
    let handle = NimbleDigest::from_bytes(&rand::thread_rng().r#gen::<[u8; 32]>()).unwrap();
    let block_hash = block.hash(); // this need not be the case, but it does not matter for testing
    let res = endorser_state.new_ledger(&handle, &block_hash, &block);
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
      .0
      .hash();
    let block_hash_to_append_data = Block::new(&rand::thread_rng().r#gen::<[u8; 32]>());
    let block_hash_to_append = block_hash_to_append_data.hash();

    let height_plus_one = {
      let height = endorser_state
        .ledger_tail_map
        .read()
        .expect("failed")
        .get(&handle)
        .unwrap()
        .read()
        .expect("failed")
        .0
        .get_height();
      let res = height.checked_add(1);
      if res.is_none() {
        panic!("Height overflow");
      }
      res.unwrap()
    };

    let receipt = endorser_state
      .append(
        &handle,
        &block_hash_to_append,
        height_plus_one,
        &block_hash_to_append_data,
        &Nonces::new(),
      )
      .unwrap();
    let new_ledger_height = endorser_state
      .ledger_tail_map
      .read()
      .expect("failed")
      .get(&handle)
      .unwrap()
      .read()
      .expect("failed")
      .0
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
    let message = handle.digest_with(&endorser_tail_expectation);
    let tail_signature_verification = receipt.get_id_sig().verify_with_id(
      &endorser_state.public_key,
      &view_block_hash
        .digest_with(&receipt.get_view().digest_with_bytes(&message.to_bytes()))
        .to_bytes(),
    );

    if tail_signature_verification.is_ok() {
      println!("Verification Passed. Checking Updated Tail");
      let ledger_tail_map = endorser_state.ledger_tail_map.read().expect("failed");
      let metablock_hash = ledger_tail_map
        .get(&handle)
        .unwrap()
        .read()
        .expect("failed")
        .0
        .hash();
      assert_eq!(endorser_tail_expectation, metablock_hash);
    } else {
      panic!("Signature verification failed when it should not have failed");
    }
  }
}
