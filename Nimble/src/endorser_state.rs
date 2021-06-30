use crate::errors::EndorserError;
use crate::helper::{concat_bytes, hash};
use ed25519_dalek::{Keypair, PublicKey, Signature, Signer};
use rand::rngs::OsRng;
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;

pub struct Store {
  pub state: EndorserState,
}

/// Public identity of the endorser
#[derive(Debug, Copy, Clone)]
pub struct EndorserIdentity {
  pubkey: PublicKey,
  sign: Signature,
}

/// Endorser's internal state
pub struct EndorserState {
  /// a key pair in the ed25519 digital signature scheme
  keypair: Keypair,

  /// a map from fixed-sized labels to a tail hash
  ledgers: HashMap<Vec<u8>, (Vec<u8>, u64)>,

  /// Endorser identity
  id: EndorserIdentity,
}

impl EndorserIdentity {
  pub fn new(public_key: PublicKey, signature: Signature) -> Self {
    EndorserIdentity {
      pubkey: public_key,
      sign: signature,
    }
  }

  pub fn get_public_key(&self) -> Vec<u8> {
    self.pubkey.to_bytes().to_vec()
  }

  pub fn get_signature(&self) -> Vec<u8> {
    self.sign.to_bytes().to_vec()
  }
}

impl EndorserState {
  pub fn new() -> Self {
    let mut csprng = OsRng {};
    let keypair = Keypair::generate(&mut csprng);
    let public_key = keypair.public;
    let signature_on_public_key = keypair.sign(public_key.as_bytes());
    println!("Creating new EndorserState with a KeyPair and Signing the Public Key");
    println!("PK : {:?}", hex::encode(public_key.to_bytes()));
    EndorserState {
      keypair,
      ledgers: HashMap::new(),
      id: EndorserIdentity::new(public_key, signature_on_public_key),
    }
  }

  pub fn create_ledger(
    &mut self,
    handle: Vec<u8>,
    tail_hash: Vec<u8>,
    height: u64,
  ) -> Result<(Vec<u8>, Signature), EndorserError> {
    // The first time a ledger is requested with a handle, insert tail_hash and sign it.
    let signature = self.keypair.sign(tail_hash.as_slice());
    println!("Inserting {:?} --> {:?}", handle, tail_hash);
    self
      .ledgers
      .insert(handle.clone(), (tail_hash.to_vec(), height));
    Ok((handle.clone(), signature))
  }

  pub fn get_handles_in_endorser_state(&self) -> Result<Vec<Vec<u8>>, EndorserError> {
    let handles = self.ledgers.keys().cloned().collect();
    Ok(handles)
  }

  pub fn get_tail(&self, endorser_handle: Vec<u8>) -> Result<(Vec<u8>, u64), EndorserError> {
    println!("Handle: {:?}", endorser_handle);
    if self.ledgers.contains_key(&*endorser_handle) {
      let (current_tail, tail_height) = self.ledgers.get(endorser_handle.as_slice()).unwrap();
      return Ok((current_tail.to_vec(), tail_height.clone()));
    }
    Err(EndorserError::StateCreationError)
  }

  pub fn append_ledger(
    &mut self,
    endorser_handle: Vec<u8>,
    block_hash: Vec<u8>,
    conditional_tail_hash: Vec<u8>,
  ) -> Result<(Vec<u8>, u64, Signature), EndorserError> {
    if self.ledgers.contains_key(&*endorser_handle.clone()) {
      let (current_tail, current_ledger_height) = self.get_tail(endorser_handle.clone()).unwrap();
      let current_tail_bytes = current_tail.as_slice();
      let conditional_tail_bytes = conditional_tail_hash.as_slice();
      // TODO: Handle case where conditional tail_bytes aren't provided (treating it as [0u8] array for now)
      if current_tail_bytes != conditional_tail_bytes && conditional_tail_bytes != [0u8; 32] {
        println!("Current: {:?}; Conditional: {:?}", current_tail_bytes, conditional_tail_bytes);
        Err(EndorserError::TailDoesNotMatch).unwrap()
      }
      println!(
        "Current Tail: {:?}, Height: {:?}",
        current_tail, current_ledger_height
      );
      let new_ledger_height = current_ledger_height + 1;
      println!("New Height: {:?}", new_ledger_height);

      let mut packed_metadata = Vec::new();
      let ledger_height_bytes = new_ledger_height.to_be_bytes().to_vec();
      packed_metadata.extend(current_tail.clone());
      packed_metadata.extend(block_hash.clone());
      packed_metadata.extend(ledger_height_bytes);

      println!("m: {:?}", packed_metadata);

      let tail_hash = hash(packed_metadata.as_slice());

      self.ledgers.insert(
        endorser_handle.to_vec(),
        (tail_hash.clone().to_vec(), new_ledger_height),
      );

      let signature = self.keypair.sign(tail_hash.as_slice());

      return Ok((current_tail.clone(), new_ledger_height, signature));
    }
    Err(EndorserError::StateCreationError)
  }

  pub fn get_endorser_key_info_from_endorser_state(&self) -> EndorserIdentity {
    self.id
  }
}

impl Store {
  pub fn new() -> Self {
    Store {
      state: EndorserState::new(),
    }
  }

  // Returns the creation of a new EndorserState and the Signed Key corresponding to it
  // Explicitly refreshes the keys in the keystate for testing purposes.
  pub fn create_new_endorser_state(&mut self) -> Result<(String, EndorserIdentity), EndorserError> {
    let endorser_state = EndorserState::new();
    let identity = endorser_state.id.clone();
    let data = concat_bytes(identity.pubkey.as_bytes(), &identity.sign.to_bytes());
    println!("PK    : {:?}", identity.pubkey.to_bytes());
    println!("Sign  : {:?}", identity.sign.to_bytes());
    println!("Concat: {:?}", data);

    let endorser_handle_index = Sha3_256::digest(&*data).to_vec();
    println!("Hash  : {:?}", endorser_handle_index);

    let response = EndorserIdentity {
      pubkey: identity.pubkey,
      sign: identity.sign,
    };
    let endorser_handle = hex::encode(endorser_handle_index);
    self.state = endorser_state;
    Ok((endorser_handle.to_string(), response))
  }

  pub fn create_new_ledger_in_endorser_state(
    &mut self,
    coordinator_handle: Vec<u8>,
    tail_hash: Vec<u8>,
    tail_index: u64,
  ) -> Result<Signature, EndorserError> {
    println!("Received Coordinator Handle: {:?}", coordinator_handle);
    let (_handle, ledger_response) = self
      .state
      .create_ledger(coordinator_handle, tail_hash, tail_index)
      .expect("Unable to create a Ledger in EndorserState");
    Ok(ledger_response)
  }

  pub fn get_all_available_handles(&self) -> Vec<Vec<u8>> {
    self.state.get_handles_in_endorser_state().unwrap()
  }

  pub fn get_endorser_key_information(&self) -> Result<EndorserIdentity, EndorserError> {
    let id = self.state.get_endorser_key_info_from_endorser_state();
    Ok(id)
  }

  pub fn append_and_update_endorser_state_tail(
    &mut self,
    endorser_handle: Vec<u8>,
    block_hash: Vec<u8>,
    conditional_tail_hash: Vec<u8>,
  ) -> Result<(Vec<u8>, u64, Signature), EndorserError> {
    let handle = &endorser_handle.clone();
    println!(
      "Handle Queried: {:?} with Block Hash: {:?}",
      handle, block_hash
    );
    let (previous_state, tail, signature) = self
      .state
      .append_ledger(handle.clone(), block_hash.to_vec(), conditional_tail_hash.clone())
      .unwrap();
    Ok((previous_state, tail, signature))
  }

  pub fn get_latest_state_for_handle(
    &self,
    handle: Vec<u8>,
    nonce: Vec<u8>,
  ) -> Result<(Vec<u8>, Vec<u8>, Signature), EndorserError> {
    let tail_hash = self.state.get_tail(handle);
    if tail_hash.is_ok() {
      let (tail_hash_bytes, _ledger_height) = tail_hash.unwrap();
      let concat_result = concat_bytes(tail_hash_bytes.as_slice(), nonce.as_slice());
      let content_to_sign = hash(&concat_result);
      let endorser_signature = self.state.keypair.sign(content_to_sign.as_slice());
      return Ok((nonce, tail_hash_bytes, endorser_signature));
    }
    Err(EndorserError::TailDoesNotMatch)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use ed25519_dalek::ed25519::signature::Signature;
  use rand::Rng;

  #[test]
  pub fn check_endorser_identity_methods() {
    let endorser_state = EndorserState::new();
    let endorser_identity = endorser_state.id;
    let public_key = endorser_identity.get_public_key();
    let signature = endorser_identity.get_signature();
    let signature_instance = Signature::from_bytes(&signature.as_slice()).unwrap();
    let sig_verification = endorser_state
      .keypair
      .verify(public_key.as_slice(), &signature_instance);
    if sig_verification.is_ok() {
      let d = sig_verification.unwrap();
      println!("{:?}", d);
      assert_eq!(2, 2);
    }

    // Taken from reference test vectors in ed25519-dalek
    let incorrect_signature_hex: &[u8] = b"98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae4131f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406";
    let incorrect_sig_bytes: Vec<u8> = hex::decode(incorrect_signature_hex).unwrap();
    let incorrect_signature = Signature::from_bytes(&incorrect_sig_bytes[..]).unwrap();

    let wrong_signature_verification = endorser_state
      .keypair
      .verify(public_key.as_slice(), &incorrect_signature);
    if wrong_signature_verification.is_ok() {
      panic!("This should have failed but it did not.")
    } else {
      println!("Succeeded.")
    }
  }

  #[test]
  pub fn check_endorser_state_creation() {
    let endorser_state = EndorserState::new();
    let key_information = endorser_state.keypair;
    let public_key = key_information.public.to_bytes();
    let secret_key = key_information.secret.to_bytes();
    assert_eq!(public_key.len(), 32usize);
    assert_eq!(secret_key.len(), 32usize);

    let endorser_identity = endorser_state.id;
    let endorser_identity_public_key = endorser_identity.pubkey.to_bytes();
    let endorser_identity_signature = endorser_identity.sign.to_bytes();
    // The signature in the SGX will be a sign of PK and measurement parameters of the SGX
    assert_eq!(public_key, endorser_identity_public_key);
    assert_eq!(endorser_identity_signature.len(), 64usize);
    assert_eq!(
      endorser_identity_signature,
      key_information
        .sign(endorser_identity_public_key.to_vec().as_slice())
        .to_bytes()
    );
  }

  #[test]
  pub fn check_endorser_new_ledger_and_get_tail() {
    let mut endorser_state = EndorserState::new();
    // The coordinator sends the hashed contents of the block to the
    let coordinator_handle = rand::thread_rng().gen::<[u8; 32]>();
    let genesis_tail_hash = rand::thread_rng().gen::<[u8; 32]>();
    let ledger_height = 0u64;
    let create_ledger_endorser_response = endorser_state.create_ledger(
      coordinator_handle.to_vec(),
      genesis_tail_hash.to_vec(),
      ledger_height,
    );
    if create_ledger_endorser_response.is_ok() {
      let (handle, signature) = create_ledger_endorser_response.unwrap();
      assert_eq!(handle, coordinator_handle);

      let signature_expected = endorser_state.keypair.sign(&genesis_tail_hash);
      assert_eq!(signature, signature_expected);

      // Fetch the value currently in the tail.
      let tail_result = endorser_state.get_tail(coordinator_handle.to_vec());
      if tail_result.is_ok() {
        let (tail_hash, ledger_height) = tail_result.unwrap();
        assert_eq!(ledger_height, 0u64);
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
    let ledger_height = 0u64;
    let create_ledger_endorser_response = endorser_state.create_ledger(
      coordinator_handle.to_vec(),
      genesis_tail_hash.to_vec(),
      ledger_height,
    );

    let (_handle, _signature) = create_ledger_endorser_response.unwrap();

    // Fetch the value currently in the tail.
    let (tail_result, ledger_height) = endorser_state
      .get_tail(coordinator_handle.to_vec())
      .unwrap();

    let block_hash_to_append = rand::thread_rng().gen::<[u8; 32]>();

    let (previous_tail, new_ledger_height, signature) = endorser_state
      .append_ledger(coordinator_handle.to_vec(), block_hash_to_append.to_vec())
      .unwrap();

    assert_eq!(tail_result, previous_tail);
    assert_eq!(new_ledger_height, ledger_height + 1);

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
      let (tail_result, _ledger_height) = endorser_state
        .get_tail(coordinator_handle.to_vec())
        .unwrap();

      assert_eq!(endorser_tail_expectation, tail_result);
    } else {
      panic!("Signature verification failed when it should not have failed");
    }
  }
}
