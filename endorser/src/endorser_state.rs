use crate::errors::EndorserError;
use ed25519_dalek::{Keypair, PublicKey, Signature, Signer};
use ledger::{MetaBlock, NimbleDigest, NimbleHashTrait};
use rand::rngs::OsRng;
use std::collections::HashMap;

/// Endorser's internal state
pub struct EndorserState {
  /// a key pair in the ed25519 digital signature scheme
  keypair: Keypair,

  /// a map from fixed-sized labels to a tail hash and a counter
  ledger_tail_map: HashMap<NimbleDigest, (NimbleDigest, usize)>,

  /// the current tail of the view/membership ledger
  view_ledger_tail: NimbleDigest,
}

impl EndorserState {
  pub fn new() -> Self {
    let mut csprng = OsRng {};
    let keypair = Keypair::generate(&mut csprng);
    EndorserState {
      keypair,
      ledger_tail_map: HashMap::new(),
      view_ledger_tail: NimbleDigest::default(),
    }
  }

  pub fn new_ledger(&mut self, handle: &NimbleDigest) -> Result<Signature, EndorserError> {
    // check if the handle already exists, if so, return an error
    if self.ledger_tail_map.contains_key(handle) {
      return Err(EndorserError::LedgerExists);
    }

    // check if the view/membership ledger is initialized, if not, return an error
    if self.view_ledger_tail == NimbleDigest::default() {
      return Err(EndorserError::ViewLedgerNotInitialized);
    }

    // create a genesis metablock that embeds the current tail of the view/membership ledger
    let tail_hash = MetaBlock::genesis(&self.view_ledger_tail, handle).hash();
    self.ledger_tail_map.insert(*handle, (tail_hash, 0usize));

    let signature = self.keypair.sign(tail_hash.to_bytes().as_slice());
    Ok(signature)
  }

  pub fn read_latest(
    &self,
    handle: &NimbleDigest,
    nonce: &[u8],
  ) -> Result<(Vec<u8>, usize, Signature), EndorserError> {
    if !self.ledger_tail_map.contains_key(handle) {
      Err(EndorserError::InvalidLedgerName)
    } else {
      let (tail_hash, height) = self.ledger_tail_map.get(handle).unwrap(); //safe to unwrap here because of the check above
      let message = tail_hash.digest_with_bytes(nonce).to_bytes();
      let signature = self.keypair.sign(&message);
      Ok((tail_hash.to_bytes(), *height, signature))
    }
  }

  pub fn append(
    &mut self,
    handle: &NimbleDigest,
    block_hash: &NimbleDigest,
  ) -> Result<(Vec<u8>, usize, Signature), EndorserError> {
    // check if the requested ledger exists in the state, if not return an error
    if !self.ledger_tail_map.contains_key(handle) {
      return Err(EndorserError::InvalidLedgerName);
    }

    // check if the view/membership ledger is initialized, if not, return an error
    if self.view_ledger_tail == NimbleDigest::default() {
      return Err(EndorserError::ViewLedgerNotInitialized);
    }

    let (tail_hash, height) = self.ledger_tail_map.get_mut(handle).unwrap();

    *height = {
      let res = height.checked_add(1);
      if res.is_none() {
        return Err(EndorserError::LedgerHeightOverflow);
      }
      res.unwrap()
    };

    // save the previous tail
    let prev_tail = *tail_hash;

    let metablock = MetaBlock::new(&self.view_ledger_tail, &prev_tail, block_hash, *height);
    *tail_hash = metablock.hash();

    let signature = self.keypair.sign(&tail_hash.to_bytes());

    Ok((prev_tail.to_bytes(), *height, signature))
  }

  pub fn get_public_key(&self) -> PublicKey {
    self.keypair.public
  }

  pub fn read_latest_view_ledger(
    &self,
    nonce: &[u8],
  ) -> Result<(Vec<u8>, Signature), EndorserError> {
    if self.view_ledger_tail == NimbleDigest::default() {
      Err(EndorserError::ViewLedgerNotInitialized)
    } else {
      let message = self.view_ledger_tail.digest_with_bytes(nonce).to_bytes();
      let signature = self.keypair.sign(&message);
      Ok((self.view_ledger_tail.to_bytes(), signature))
    }
  }

  pub fn append_view_ledger(
    &mut self,
    block_hash: &NimbleDigest,
  ) -> Result<(Vec<u8>, Signature), EndorserError> {
    // save the previous tail
    let prev_tail = self.view_ledger_tail;
    self.view_ledger_tail = self.view_ledger_tail.digest_with(block_hash);

    let signature = self.keypair.sign(&self.view_ledger_tail.to_bytes());

    Ok((prev_tail.to_bytes(), signature))
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use rand::Rng;

  #[test]
  pub fn check_endorser_state_creation() {
    let endorser_state = EndorserState::new();
    let key_information = endorser_state.keypair;
    let public_key = key_information.public.to_bytes();
    let secret_key = key_information.secret.to_bytes();
    assert_eq!(public_key.len(), 32usize);
    assert_eq!(secret_key.len(), 32usize);
  }

  #[test]
  pub fn check_endorser_new_ledger_and_get_tail() {
    let mut endorser_state = EndorserState::new();

    // The coordinator sends the hashed contents of the configuration to the endorsers
    let view_ledger_block_hash = {
      let t = rand::thread_rng().gen::<[u8; 32]>();
      let n = NimbleDigest::from_bytes(&t);
      assert!(!n.is_err(), "This should not have occured");
      n.unwrap()
    };
    let res = endorser_state.append_view_ledger(&view_ledger_block_hash);
    assert!(res.is_ok());

    // the tail hash of the view ledger after the append
    let view = NimbleDigest::default().digest_with(&view_ledger_block_hash);

    // The coordinator sends the hashed contents of the block to the endorsers
    let handle = {
      let t = rand::thread_rng().gen::<[u8; 32]>();
      let n = NimbleDigest::from_bytes(&t);
      assert!(!n.is_err(), "This should not have occured");
      n.unwrap()
    };
    let res = endorser_state.new_ledger(&handle);
    assert!(res.is_ok());

    let signature = res.unwrap();
    let genesis_tail_hash = MetaBlock::genesis(&view, &handle).hash();
    let signature_expected = endorser_state.keypair.sign(&genesis_tail_hash.to_bytes());
    assert_eq!(signature, signature_expected);

    // Fetch the value currently in the tail.
    let tail_result = endorser_state.read_latest(&handle, &[0]);
    assert!(tail_result.is_ok());

    let (tail_hash, height, _signature) = tail_result.unwrap();
    assert_eq!(height, 0usize);
    let tail_hash = NimbleDigest::from_bytes(&tail_hash).unwrap();
    assert_eq!(tail_hash, genesis_tail_hash);
  }

  #[test]
  pub fn check_endorser_append_ledger_tail() {
    let mut endorser_state = EndorserState::new();
    // The coordinator sends the hashed contents of the configuration to the endorsers
    let view_ledger_block_hash = {
      let t = rand::thread_rng().gen::<[u8; 32]>();
      let n = NimbleDigest::from_bytes(&t);
      assert!(!n.is_err(), "This should not have occured");
      n.unwrap()
    };
    let res = endorser_state.append_view_ledger(&view_ledger_block_hash);
    assert!(res.is_ok());

    // the tail hash of the view ledger after the append
    let view = NimbleDigest::default().digest_with(&view_ledger_block_hash);

    // The coordinator sends the hashed contents of the block to the endorsers
    let block = rand::thread_rng().gen::<[u8; 32]>();
    let handle = NimbleDigest::from_bytes(&block).unwrap();
    let res = endorser_state.new_ledger(&handle);
    assert!(res.is_ok());

    // Fetch the value currently in the tail.
    let nonce = rand::thread_rng().gen::<[u8; 16]>();
    let (tail_result_data, height, _signature) =
      endorser_state.read_latest(&handle, &nonce).unwrap();

    let block_hash_to_append_data = rand::thread_rng().gen::<[u8; 32]>();
    let block_hash_to_append = NimbleDigest::from_bytes(&block_hash_to_append_data).unwrap();
    let tail_result = NimbleDigest::from_bytes(&tail_result_data).unwrap();

    let (previous_tail_data, new_ledger_height, signature) = endorser_state
      .append(&handle, &block_hash_to_append)
      .unwrap();

    let previous_tail = NimbleDigest::from_bytes(&previous_tail_data).unwrap();

    assert_eq!(tail_result, previous_tail);
    assert_eq!(new_ledger_height, height + 1);

    let metadata = MetaBlock::new(
      &view,
      &previous_tail,
      &block_hash_to_append,
      new_ledger_height,
    );

    let endorser_tail_expectation = metadata.hash();

    let tail_signature_verification = endorser_state
      .keypair
      .verify(&endorser_tail_expectation.to_bytes(), &signature);

    if tail_signature_verification.is_ok() {
      println!("Verification Passed. Checking Updated Tail");
      let (tail_result_data, _height, _signature) =
        endorser_state.read_latest(&handle, &[0]).unwrap();
      let tail_result = NimbleDigest::from_bytes(&tail_result_data).unwrap();

      assert_eq!(endorser_tail_expectation, tail_result);
    } else {
      panic!("Signature verification failed when it should not have failed");
    }
  }
}
