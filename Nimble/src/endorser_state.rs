use crate::errors::EndorserError;
use crate::helper::hash;
use ed25519_dalek::{Keypair, PublicKey, Signature, Signer};
use rand::rngs::OsRng;
use std::collections::HashMap;

/// Endorser's internal state
pub struct EndorserState {
  /// a key pair in the ed25519 digital signature scheme
  keypair: Keypair,

  /// a map from fixed-sized labels to a tail hash
  ledgers: HashMap<Vec<u8>, (Vec<u8>, usize)>,
}

impl EndorserState {
  pub fn new() -> Self {
    let mut csprng = OsRng {};
    let keypair = Keypair::generate(&mut csprng);
    EndorserState {
      keypair,
      ledgers: HashMap::new(),
    }
  }

  pub fn new_ledger(
    &mut self,
    handle: &Vec<u8>,
    tail_hash: &Vec<u8>,
  ) -> Result<Signature, EndorserError> {
    if self.ledgers.contains_key(handle) {
      Err(EndorserError::LedgerExists)
    } else {
      self
        .ledgers
        .insert(handle.clone(), (tail_hash.to_vec(), 0usize));

      let signature = self.keypair.sign(tail_hash);
      Ok(signature)
    }
  }

  pub fn read_latest(
    &self,
    handle: &Vec<u8>,
    nonce: &Vec<u8>,
  ) -> Result<(Vec<u8>, usize, Signature), EndorserError> {
    if !self.ledgers.contains_key(handle) {
      return Err(EndorserError::InvalidLedgerName);
    }

    let (tail_hash_bytes, height) = self.ledgers.get(handle).unwrap(); //safe to unwrap here because of the check above
    let signature = self
      .keypair
      .sign(&[tail_hash_bytes.as_slice(), nonce.as_slice()].concat());
    return Ok((tail_hash_bytes.to_vec(), *height, signature));
  }

  pub fn append(
    &mut self,
    handle: &Vec<u8>,
    block_hash: &Vec<u8>,
    conditional_tail_hash: &Vec<u8>,
  ) -> Result<(Vec<u8>, usize, Signature), EndorserError> {
    if self.ledgers.contains_key(handle) {
      let (tail_hash, height) = self.ledgers.get_mut(handle).unwrap();
      if tail_hash != conditional_tail_hash {
        Err(EndorserError::TailDoesNotMatch).unwrap()
      }

      *height = *height + 1;

      // save the previous tail
      let prev_tail = tail_hash.clone();

      let mut packed_metadata = Vec::new();
      packed_metadata.extend(tail_hash.clone());
      packed_metadata.extend(block_hash.clone());
      packed_metadata.extend(height.to_be_bytes().to_vec());
      *tail_hash = hash(packed_metadata.as_slice()).to_vec();

      let signature = self.keypair.sign(tail_hash);

      return Ok((prev_tail.to_vec(), *height, signature));
    }
    Err(EndorserError::StateCreationError)
  }

  pub fn get_public_key(&self) -> PublicKey {
    self.keypair.public
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
    // The coordinator sends the hashed contents of the block to the
    let coordinator_handle = rand::thread_rng().gen::<[u8; 32]>();
    let genesis_tail_hash = rand::thread_rng().gen::<[u8; 32]>();
    let create_ledger_endorser_response =
      endorser_state.new_ledger(&coordinator_handle.to_vec(), &genesis_tail_hash.to_vec());
    if create_ledger_endorser_response.is_ok() {
      let signature = create_ledger_endorser_response.unwrap();
      let signature_expected = endorser_state.keypair.sign(&genesis_tail_hash);
      assert_eq!(signature, signature_expected);

      // Fetch the value currently in the tail.
      let tail_result = endorser_state.read_latest(&coordinator_handle.to_vec(), &vec![0]);
      if tail_result.is_ok() {
        let (tail_hash, height, signature) = tail_result.unwrap();
        assert_eq!(height, 0usize);
        assert_eq!(tail_hash, genesis_tail_hash);
      } else {
        panic!("Failed to retrieve correct tail hash on genesis ledger state creation");
      }
    } else {
      panic!("Failed to create ledger using genesis hash at the ledger");
    }
  }

  #[test]
  pub fn check_endorser_append_ledger_tail() {
    let mut endorser_state = EndorserState::new();

    // The coordinator sends the hashed contents of the block to the
    let coordinator_handle = rand::thread_rng().gen::<[u8; 32]>();
    let genesis_tail_hash = rand::thread_rng().gen::<[u8; 32]>();
    let create_ledger_endorser_response =
      endorser_state.new_ledger(&coordinator_handle.to_vec(), &genesis_tail_hash.to_vec());

    let _signature = create_ledger_endorser_response.unwrap();

    // Fetch the value currently in the tail.
    let (tail_result, height, signature) = endorser_state
      .read_latest(&coordinator_handle.to_vec(), &vec![0])
      .unwrap();

    let block_hash_to_append = rand::thread_rng().gen::<[u8; 32]>();
    let zero_block = [0u8; 32].to_vec();

    let (previous_tail, new_ledger_height, signature) = endorser_state
      .append(
        &coordinator_handle.to_vec(),
        &block_hash_to_append.to_vec(),
        &tail_result,
      )
      .unwrap();

    assert_eq!(tail_result, previous_tail);
    assert_eq!(new_ledger_height, height + 1);

    let mut packed_metadata = Vec::new();
    let ledger_height_bytes = new_ledger_height.to_be_bytes().to_vec();
    packed_metadata.extend(previous_tail.clone());
    packed_metadata.extend(block_hash_to_append.clone());
    packed_metadata.extend(ledger_height_bytes);

    let endorser_tail_expectation = hash(&packed_metadata).to_vec();

    let tail_signature_verification = endorser_state
      .keypair
      .verify(&endorser_tail_expectation, &signature);

    if tail_signature_verification.is_ok() {
      println!("Verification Passed. Checking Updated Tail");
      let (tail_result, _height, _signature) = endorser_state
        .read_latest(&coordinator_handle.to_vec(), &vec![0])
        .unwrap();

      assert_eq!(endorser_tail_expectation, tail_result);
    } else {
      panic!("Signature verification failed when it should not have failed");
    }
  }
}
