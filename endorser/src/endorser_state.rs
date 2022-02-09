use crate::errors::EndorserError;
use itertools::Itertools;
use ledger::{
  signature::{PrivateKey, PrivateKeyTrait, PublicKey, Signature},
  MetaBlock, NimbleDigest, NimbleHashTrait,
};
use std::collections::HashMap;

/// Endorser's internal state
pub struct EndorserState {
  /// a key pair in a digital signature scheme
  keypair: PrivateKey,

  /// a map from fixed-sized labels to a tail hash and a counter
  ledger_tail_map: HashMap<NimbleDigest, (NimbleDigest, usize)>,

  /// the current tail of the view/membership ledger along with a counter
  view_ledger_tail: (NimbleDigest, usize),

  /// whether the endorser is initialized
  is_initialized: bool,
}

impl EndorserState {
  pub fn new() -> Self {
    let keypair = PrivateKey::new();
    EndorserState {
      keypair,
      ledger_tail_map: HashMap::new(),
      view_ledger_tail: (NimbleDigest::default(), 0_usize),
      is_initialized: false,
    }
  }

  fn produce_hash_of_state(&self) -> NimbleDigest {
    // for empty state, hash is a vector of zeros
    if self.ledger_tail_map.is_empty() && self.view_ledger_tail == (NimbleDigest::default(), 0) {
      NimbleDigest::default()
    } else {
      let mut serialized_state = Vec::new();
      for handle in self.ledger_tail_map.keys().sorted() {
        let (tail, height) = self.ledger_tail_map.get(handle).unwrap();
        serialized_state.extend_from_slice(&handle.to_bytes());
        serialized_state.extend_from_slice(&tail.to_bytes());
        serialized_state.extend_from_slice(&height.to_le_bytes());
      }
      NimbleDigest::digest(&serialized_state)
    }
  }

  pub fn initialize_state(
    &mut self,
    ledger_tail_map: &HashMap<NimbleDigest, (NimbleDigest, usize)>,
    view_ledger_tail: &(NimbleDigest, usize),
    block_hash: &NimbleDigest,
    cond_updated_tail_hash: &NimbleDigest,
  ) -> Result<Signature, EndorserError> {
    if self.is_initialized {
      return Err(EndorserError::AlreadyInitialized);
    }
    self.ledger_tail_map = ledger_tail_map.clone();
    self.view_ledger_tail = *view_ledger_tail;
    self.is_initialized = true;

    self.append_view_ledger(block_hash, cond_updated_tail_hash)
  }

  pub fn new_ledger(&mut self, handle: &NimbleDigest) -> Result<Signature, EndorserError> {
    if !self.is_initialized {
      return Err(EndorserError::NotInitialized);
    }

    // check if the handle already exists, if so, return an error
    if self.ledger_tail_map.contains_key(handle) {
      return Err(EndorserError::LedgerExists);
    }

    // create a genesis metablock that embeds the current tail of the view/membership ledger
    let tail_hash = MetaBlock::genesis(&self.view_ledger_tail.0, handle).hash();
    self.ledger_tail_map.insert(*handle, (tail_hash, 0usize));

    let signature = self.keypair.sign(tail_hash.to_bytes().as_slice()).unwrap();
    Ok(signature)
  }

  pub fn read_latest(
    &self,
    handle: &NimbleDigest,
    nonce: &[u8],
  ) -> Result<Signature, EndorserError> {
    if !self.is_initialized {
      return Err(EndorserError::NotInitialized);
    }

    if !self.ledger_tail_map.contains_key(handle) {
      Err(EndorserError::InvalidLedgerName)
    } else {
      let (tail_hash, _height) = self.ledger_tail_map.get(handle).unwrap(); //safe to unwrap here because of the check above
      let message = tail_hash.digest_with_bytes(nonce).to_bytes();
      let signature = self.keypair.sign(&message).unwrap();
      Ok(signature)
    }
  }

  pub fn append(
    &mut self,
    handle: &NimbleDigest,
    block_hash: &NimbleDigest,
    cond_updated_tail_hash: &NimbleDigest,
  ) -> Result<Signature, EndorserError> {
    if !self.is_initialized {
      return Err(EndorserError::NotInitialized);
    }

    // check if the requested ledger exists in the state, if not return an error
    if !self.ledger_tail_map.contains_key(handle) {
      return Err(EndorserError::InvalidLedgerName);
    }

    let (prev, height) = self.ledger_tail_map.get_mut(handle).unwrap();

    // increment height and returning an error in case of overflow
    let height_plus_one = {
      let res = height.checked_add(1);
      if res.is_none() {
        return Err(EndorserError::LedgerHeightOverflow);
      }
      res.unwrap()
    };

    let updated_tail_hash =
      MetaBlock::new(&self.view_ledger_tail.0, prev, block_hash, height_plus_one).hash();

    // check if the updated tail hash of the ledger is the same as the one in the request, if not return an error
    if updated_tail_hash != *cond_updated_tail_hash {
      return Err(EndorserError::InvalidConditionalTail);
    }

    // update the internal state
    *height = height_plus_one;
    *prev = updated_tail_hash;

    let signature = self.keypair.sign(&prev.to_bytes()).unwrap();

    Ok(signature)
  }

  pub fn get_public_key(&self) -> PublicKey {
    self.keypair.get_public_key().unwrap()
  }

  pub fn read_latest_view_ledger(&self, nonce: &[u8]) -> Result<Signature, EndorserError> {
    if !self.is_initialized {
      return Err(EndorserError::NotInitialized);
    }

    let (tail, _height) = &self.view_ledger_tail;
    let message = tail.digest_with_bytes(nonce).to_bytes();
    let signature = self.keypair.sign(&message).unwrap();
    Ok(signature)
  }

  pub fn append_view_ledger(
    &mut self,
    block_hash: &NimbleDigest,
    cond_updated_tail_hash: &NimbleDigest,
  ) -> Result<Signature, EndorserError> {
    if !self.is_initialized {
      return Err(EndorserError::NotInitialized);
    }

    // read the current tail and height of the view ledger
    let (prev, height) = &self.view_ledger_tail;

    // perform a checked addition of height with 1
    let height_plus_one = {
      let res = height.checked_add(1);
      if res.is_none() {
        return Err(EndorserError::LedgerHeightOverflow);
      }
      res.unwrap()
    };

    // the view embedded in the view ledger is the hash of the current state of the endorser
    let view = self.produce_hash_of_state();

    // formulate a metablock for the new entry on the view ledger; and hash it to get the updated tail hash
    let updated_tail_hash = MetaBlock::new(&view, prev, block_hash, height_plus_one).hash();

    // check if the updated tail hash of the view ledger is the same as the one in the request, if not return an error
    if updated_tail_hash != *cond_updated_tail_hash {
      return Err(EndorserError::InvalidConditionalTail);
    }

    // sign the hash of the new metablock
    let signature = self.keypair.sign(&updated_tail_hash.to_bytes()).unwrap();

    // update the internal state
    self.view_ledger_tail = (updated_tail_hash, height_plus_one);

    Ok(signature)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use ledger::signature::SignatureTrait;
  use rand::Rng;

  #[test]
  pub fn check_endorser_new_ledger_and_get_tail() {
    let mut endorser_state = EndorserState::new();

    // The coordinator sends the hashed contents of the configuration to the endorsers
    // We will pick a dummy view value for testing purposes
    let view_block_hash = {
      let t = rand::thread_rng().gen::<[u8; 32]>();
      let n = NimbleDigest::from_bytes(&t);
      assert!(n.is_ok(), "This should not have occured");
      n.unwrap()
    };

    let cond_updated_tail_hash = {
      // read the current tail and height of the view ledger
      let (prev, height) = &endorser_state.view_ledger_tail;

      // perform a checked addition of height with 1
      let height_plus_one = {
        let res = height.checked_add(1);
        assert!(res.is_some());
        res.unwrap()
      };

      // the view embedded in the view ledger is the hash of the current state of the endorser
      let view = endorser_state.produce_hash_of_state();

      // formulate a metablock for the new entry on the view ledger; and hash it to get the updated tail hash
      MetaBlock::new(&view, prev, &view_block_hash, height_plus_one).hash()
    };

    // The coordinator initializes the endorser by calling initialize_state
    let res = endorser_state.initialize_state(
      &HashMap::new(),
      &(NimbleDigest::default(), 0usize),
      &view_block_hash,
      &cond_updated_tail_hash,
    );
    assert!(res.is_ok());

    let view = {
      let view_ledger_metablock = MetaBlock::new(
        &NimbleDigest::default(),
        &NimbleDigest::default(),
        &view_block_hash,
        1_usize,
      );
      view_ledger_metablock.hash()
    };

    // The coordinator sends the hashed contents of the block to the endorsers
    let handle = {
      let t = rand::thread_rng().gen::<[u8; 32]>();
      let n = NimbleDigest::from_bytes(&t);
      assert!(n.is_ok(), "This should not have occured");
      n.unwrap()
    };
    let res = endorser_state.new_ledger(&handle);
    assert!(res.is_ok());

    let signature = res.unwrap();
    let genesis_tail_hash = MetaBlock::genesis(&view, &handle).hash();
    assert!(signature
      .verify(
        &endorser_state.keypair.get_public_key().unwrap(),
        &genesis_tail_hash.to_bytes()
      )
      .is_ok());

    // Fetch the value currently in the tail.
    let tail_result = endorser_state.read_latest(&handle, &[0]);
    assert!(tail_result.is_ok());

    let (tail_hash, height) = endorser_state.ledger_tail_map.get(&handle).unwrap();
    assert_eq!(height, &0usize);
    assert_eq!(tail_hash, &genesis_tail_hash);
  }

  #[test]
  pub fn check_endorser_append_ledger_tail() {
    let mut endorser_state = EndorserState::new();

    // The coordinator sends the hashed contents of the configuration to the endorsers
    // We will pick a dummy view value for testing purposes
    let view_block_hash = {
      let t = rand::thread_rng().gen::<[u8; 32]>();
      let n = NimbleDigest::from_bytes(&t);
      assert!(n.is_ok(), "This should not have occured");
      n.unwrap()
    };

    let cond_updated_tail_hash = {
      // read the current tail and height of the view ledger
      let (prev, height) = &endorser_state.view_ledger_tail;

      // perform a checked addition of height with 1
      let height_plus_one = {
        let res = height.checked_add(1);
        assert!(res.is_some());
        res.unwrap()
      };

      // the view embedded in the view ledger is the hash of the current state of the endorser
      let view = endorser_state.produce_hash_of_state();

      // formulate a metablock for the new entry on the view ledger; and hash it to get the updated tail hash
      MetaBlock::new(&view, prev, &view_block_hash, height_plus_one).hash()
    };

    // The coordinator initializes the endorser by calling initialize_state
    let res = endorser_state.initialize_state(
      &HashMap::new(),
      &(NimbleDigest::default(), 0usize),
      &view_block_hash,
      &cond_updated_tail_hash,
    );
    assert!(res.is_ok());

    let view = {
      let view_ledger_metablock = MetaBlock::new(
        &NimbleDigest::default(),
        &NimbleDigest::default(),
        &view_block_hash,
        1_usize,
      );
      view_ledger_metablock.hash()
    };

    // The coordinator sends the hashed contents of the block to the endorsers
    let block = rand::thread_rng().gen::<[u8; 32]>();
    let handle = NimbleDigest::from_bytes(&block).unwrap();
    let res = endorser_state.new_ledger(&handle);
    assert!(res.is_ok());

    // Fetch the value currently in the tail.
    let (tail_result, height) = {
      let res = endorser_state.ledger_tail_map.get(&handle).unwrap();
      *res
    };
    let block_hash_to_append_data = rand::thread_rng().gen::<[u8; 32]>();
    let block_hash_to_append = NimbleDigest::from_bytes(&block_hash_to_append_data).unwrap();

    let prev_tail = {
      let t = endorser_state.ledger_tail_map.get(&handle).unwrap();
      t.0
    };

    let height_plus_one = {
      let height = endorser_state.ledger_tail_map.get(&handle).unwrap().1;
      let res = height.checked_add(1);
      if res.is_none() {
        panic!("Height overflow");
      }
      res.unwrap()
    };

    let updated_metablock =
      MetaBlock::new(&view, &prev_tail, &block_hash_to_append, height_plus_one);

    let signature = {
      endorser_state
        .append(&handle, &block_hash_to_append, &updated_metablock.hash())
        .unwrap()
    };
    let new_ledger_height = {
      let h = endorser_state.ledger_tail_map.get(&handle).unwrap();
      h.1
    };

    assert_eq!(tail_result, prev_tail);
    assert_eq!(new_ledger_height, height + 1);

    let metadata = MetaBlock::new(&view, &prev_tail, &block_hash_to_append, new_ledger_height);

    let endorser_tail_expectation = metadata.hash();

    let tail_signature_verification = signature.verify(
      &endorser_state.keypair.get_public_key().unwrap(),
      &endorser_tail_expectation.to_bytes(),
    );

    if tail_signature_verification.is_ok() {
      println!("Verification Passed. Checking Updated Tail");
      let (tail_result, _height) = endorser_state.ledger_tail_map.get(&handle).unwrap();
      assert_eq!(&endorser_tail_expectation, tail_result);
    } else {
      panic!("Signature verification failed when it should not have failed");
    }
  }
}
