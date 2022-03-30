use crate::errors::EndorserError;
use ledger::{
  produce_hash_of_state,
  signature::{PrivateKey, PrivateKeyTrait, PublicKey},
  IdSig, LedgerTailMap, LedgerView, MetaBlock, NimbleDigest, NimbleHashTrait, Receipt,
};
use std::collections::HashMap;

/// Endorser's internal state
pub struct EndorserState {
  /// a key pair in a digital signature scheme
  keypair: PrivateKey,

  public_key: PublicKey,

  /// a map from fixed-sized labels to a tail hash and a counter
  ledger_tail_map: LedgerTailMap,

  view_tail_metablock: MetaBlock,

  view_ledger_tail: NimbleDigest,

  /// whether the endorser is initialized
  is_initialized: bool,

  /// whether the endorser is locked for append operations
  is_locked: bool,
}

impl EndorserState {
  pub fn new() -> Self {
    let keypair = PrivateKey::new();
    let public_key = keypair.get_public_key().unwrap();
    EndorserState {
      keypair,
      public_key,
      ledger_tail_map: HashMap::new(),
      view_tail_metablock: MetaBlock::default(),
      view_ledger_tail: MetaBlock::default().hash(),
      is_initialized: false,
      is_locked: false,
    }
  }

  pub fn initialize_state(
    &mut self,
    ledger_tail_map: &LedgerTailMap,
    view_tail_metablock: &MetaBlock,
    block_hash: &NimbleDigest,
    expected_height: usize,
  ) -> Result<Receipt, EndorserError> {
    if self.is_initialized {
      return Err(EndorserError::AlreadyInitialized);
    }
    self.ledger_tail_map = ledger_tail_map.clone();
    self.view_tail_metablock = view_tail_metablock.clone();
    self.view_ledger_tail = view_tail_metablock.hash();
    self.is_initialized = true;

    self.append_view_ledger(block_hash, expected_height)
  }

  pub fn new_ledger(&mut self, handle: &NimbleDigest) -> Result<Receipt, EndorserError> {
    if !self.is_initialized {
      return Err(EndorserError::NotInitialized);
    }

    if self.is_locked {
      return Err(EndorserError::IsLocked);
    }

    // check if the handle already exists, if so, return an error
    if self.ledger_tail_map.contains_key(handle) {
      return Err(EndorserError::LedgerExists);
    }

    // create a genesis metablock that embeds the current tail of the view/membership ledger
    let view = &self.view_ledger_tail;
    let metablock = MetaBlock::genesis(view, handle);
    let tail_hash = metablock.hash();
    self.ledger_tail_map.insert(*handle, metablock.clone());

    let message = tail_hash;
    let signature = self.keypair.sign(message.to_bytes().as_slice()).unwrap();

    Ok(Receipt::new(
      metablock,
      vec![IdSig::new(self.public_key.clone(), signature)],
    ))
  }

  pub fn read_latest(&self, handle: &NimbleDigest, nonce: &[u8]) -> Result<Receipt, EndorserError> {
    if !self.is_initialized {
      return Err(EndorserError::NotInitialized);
    }

    if !self.ledger_tail_map.contains_key(handle) {
      return Err(EndorserError::InvalidLedgerName);
    }

    let metablock = self.ledger_tail_map.get(handle).unwrap(); //safe to unwrap here because of the check above
    let tail_hash = metablock.hash();
    let message = tail_hash.digest_with_bytes(nonce);
    let signature = self.keypair.sign(&message.to_bytes()).unwrap();

    Ok(Receipt::new(
      metablock.clone(),
      vec![IdSig::new(self.public_key.clone(), signature)],
    ))
  }

  pub fn append(
    &mut self,
    handle: &NimbleDigest,
    block_hash: &NimbleDigest,
    expected_height: usize,
  ) -> Result<Receipt, EndorserError> {
    if !self.is_initialized {
      return Err(EndorserError::NotInitialized);
    }

    if self.is_locked {
      return Err(EndorserError::IsLocked);
    }

    // check if the requested ledger exists in the state, if not return an error
    if !self.ledger_tail_map.contains_key(handle) {
      return Err(EndorserError::InvalidLedgerName);
    }

    let metablock = self.ledger_tail_map.get(handle).unwrap();

    // increment height and returning an error in case of overflow
    let height_plus_one = {
      let res = metablock.get_height().checked_add(1);
      if res.is_none() {
        return Err(EndorserError::LedgerHeightOverflow);
      }
      res.unwrap()
    };

    if expected_height != 0 {
      if expected_height < height_plus_one {
        return Err(EndorserError::InvalidTailHeight);
      }

      if expected_height > height_plus_one {
        return Err(EndorserError::OutOfOrderAppend);
      }
    }

    let view = &self.view_ledger_tail;
    let prev = metablock.hash();
    let new_metablock = MetaBlock::new(view, &prev, block_hash, height_plus_one);

    let message = new_metablock.hash();
    let signature = self.keypair.sign(&message.to_bytes()).unwrap();

    self.ledger_tail_map.insert(*handle, new_metablock.clone());

    Ok(Receipt::new(
      new_metablock,
      vec![IdSig::new(self.public_key.clone(), signature)],
    ))
  }

  pub fn get_public_key(&self) -> PublicKey {
    self.public_key.clone()
  }

  pub fn read_latest_view_ledger(&self, nonce: &[u8]) -> Result<Receipt, EndorserError> {
    if !self.is_initialized {
      return Err(EndorserError::NotInitialized);
    }
    let tail = &self.view_ledger_tail;
    let message = tail.digest_with_bytes(nonce).to_bytes();
    let signature = self.keypair.sign(&message).unwrap();

    Ok(Receipt::new(
      self.view_tail_metablock.clone(),
      vec![IdSig::new(self.public_key.clone(), signature)],
    ))
  }

  pub fn append_view_ledger(
    &mut self,
    block_hash: &NimbleDigest,
    expected_height: usize,
  ) -> Result<Receipt, EndorserError> {
    if !self.is_initialized {
      return Err(EndorserError::NotInitialized);
    }

    if self.is_locked {
      return Err(EndorserError::IsLocked);
    }

    let metablock = &self.view_tail_metablock;

    // perform a checked addition of height with 1
    let height_plus_one = {
      let res = metablock.get_height().checked_add(1);
      if res.is_none() {
        return Err(EndorserError::LedgerHeightOverflow);
      }
      res.unwrap()
    };

    if expected_height != 0 {
      if expected_height < height_plus_one {
        return Err(EndorserError::InvalidTailHeight);
      }

      if expected_height > height_plus_one {
        return Err(EndorserError::OutOfOrderAppend);
      }
    }

    // the view embedded in the view ledger is the hash of the current state of the endorser
    let view = produce_hash_of_state(&self.ledger_tail_map);
    let prev = &self.view_ledger_tail;

    // formulate a metablock for the new entry on the view ledger; and hash it to get the updated tail hash
    let new_metablock = MetaBlock::new(&view, prev, block_hash, height_plus_one);

    // update the internal state
    self.view_tail_metablock = new_metablock.clone();
    self.view_ledger_tail = new_metablock.hash();

    // sign the hash of the new metablock
    let message = self.view_ledger_tail;
    let signature = self.keypair.sign(&message.to_bytes()).unwrap();

    Ok(Receipt::new(
      new_metablock,
      vec![IdSig::new(self.public_key.clone(), signature)],
    ))
  }

  pub fn read_latest_state(&self) -> Result<LedgerView, EndorserError> {
    if !self.is_initialized {
      return Err(EndorserError::NotInitialized);
    }

    let ledger_view = LedgerView {
      view_tail_metablock: self.view_tail_metablock.clone(),
      ledger_tail_map: self.ledger_tail_map.clone(),
    };

    Ok(ledger_view)
  }

  pub fn lock(&mut self) {
    self.is_locked = true;
  }

  pub fn unlock(&mut self) {
    self.is_locked = false;
  }
}

#[cfg(test)]
mod tests {
  use super::*;
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

    // perform a checked addition of height with 1
    let height_plus_one = {
      let res = endorser_state
        .view_tail_metablock
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
    let res = endorser_state.new_ledger(&handle);
    assert!(res.is_ok());

    let receipt = res.unwrap();
    let genesis_tail_hash = MetaBlock::genesis(&endorser_state.view_ledger_tail, &handle).hash();
    assert_eq!(*receipt.get_view(), endorser_state.view_ledger_tail);
    assert!(receipt
      .verify(
        &genesis_tail_hash.to_bytes(),
        &[endorser_state.public_key.clone()],
      )
      .is_ok());

    // Fetch the value currently in the tail.
    let tail_result = endorser_state.read_latest(&handle, &[0]);
    assert!(tail_result.is_ok());

    let metablock = endorser_state.ledger_tail_map.get(&handle).unwrap();
    assert_eq!(metablock.get_height(), 0usize);
    assert_eq!(metablock.hash(), genesis_tail_hash);
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

    // perform a checked addition of height with 1
    let height_plus_one = {
      let res = endorser_state
        .view_tail_metablock
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
    let res = endorser_state.new_ledger(&handle);
    assert!(res.is_ok());

    // Fetch the value currently in the tail.
    let prev_tail = endorser_state.ledger_tail_map.get(&handle).unwrap().hash();
    let block_hash_to_append_data = rand::thread_rng().gen::<[u8; 32]>();
    let block_hash_to_append = NimbleDigest::from_bytes(&block_hash_to_append_data).unwrap();

    let height_plus_one = {
      let height = endorser_state
        .ledger_tail_map
        .get(&handle)
        .unwrap()
        .get_height();
      let res = height.checked_add(1);
      if res.is_none() {
        panic!("Height overflow");
      }
      res.unwrap()
    };

    let receipt = endorser_state
      .append(&handle, &block_hash_to_append, height_plus_one)
      .unwrap();
    let new_ledger_height = endorser_state
      .ledger_tail_map
      .get(&handle)
      .unwrap()
      .get_height();
    assert_eq!(*receipt.get_view(), endorser_state.view_ledger_tail);
    assert_eq!(*receipt.get_prev(), prev_tail);
    assert_eq!(new_ledger_height, height_plus_one);

    let metadata = MetaBlock::new(
      &endorser_state.view_ledger_tail,
      &prev_tail,
      &block_hash_to_append,
      new_ledger_height,
    );

    let endorser_tail_expectation = metadata.hash();
    let message = endorser_tail_expectation;
    let tail_signature_verification =
      receipt.verify(&message.to_bytes(), &[endorser_state.public_key.clone()]);

    if tail_signature_verification.is_ok() {
      println!("Verification Passed. Checking Updated Tail");
      let metablock = endorser_state.ledger_tail_map.get(&handle).unwrap();
      assert_eq!(endorser_tail_expectation, metablock.hash());
    } else {
      panic!("Signature verification failed when it should not have failed");
    }
  }
}
