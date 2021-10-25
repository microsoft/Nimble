use crate::errors::EndorserError;
use ed25519_dalek::{Keypair, PublicKey, Signature, Signer};
use ledger::{MetaBlock, NimbleDigest, NimbleHashTrait};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize, Serializer};
use std::collections::{BTreeMap, HashMap};

/// Endorser's internal state
pub struct EndorserState {
  /// a key pair in the ed25519 digital signature scheme
  keypair: Keypair,

  /// a map from fixed-sized labels to a tail hash and a counter
  ledger_tail_map: HashMap<NimbleDigest, (NimbleDigest, usize)>,

  /// the current tail of the view/membership ledger along with a counter
  view_ledger_tail: (NimbleDigest, usize),

  /// whether the endorser is initialized
  is_initialized: bool,
}

#[derive(Serialize, Deserialize)]
struct EndorserStatePublic {
  #[serde(serialize_with = "hashmap_serializer")]
  ledger_tail_map: HashMap<Vec<u8>, (Vec<u8>, usize)>,
  view_ledger_tail: (Vec<u8>, usize),
}

fn hashmap_serializer<S>(
  v: &HashMap<Vec<u8>, (Vec<u8>, usize)>,
  serializer: S,
) -> Result<S::Ok, S::Error>
where
  S: Serializer,
{
  let m: BTreeMap<_, _> = v.iter().collect();
  m.serialize(serializer)
}

impl EndorserState {
  pub fn new() -> Self {
    let mut csprng = OsRng {};
    let keypair = Keypair::generate(&mut csprng);
    EndorserState {
      keypair,
      ledger_tail_map: HashMap::new(),
      view_ledger_tail: (NimbleDigest::default(), 0_usize),
      is_initialized: false,
    }
  }

  fn produce_hash_of_state(&self) -> NimbleDigest {
    let endorser_state_public = EndorserStatePublic {
      ledger_tail_map: self
        .ledger_tail_map
        .iter()
        .map(|(handle, (tail, height))| (handle.to_bytes(), (tail.to_bytes(), *height)))
        .collect(),
      view_ledger_tail: (self.view_ledger_tail.0.to_bytes(), self.view_ledger_tail.1),
    };
    let serialized_endorser_state_public = bincode::serialize(&endorser_state_public).unwrap();
    NimbleDigest::digest(&serialized_endorser_state_public)
  }

  pub fn initialize_state(
    &mut self,
    ledger_tail_map: &HashMap<NimbleDigest, (NimbleDigest, usize)>,
    view_ledger_tail: &(NimbleDigest, usize),
  ) -> Result<Signature, EndorserError> {
    if self.is_initialized {
      return Err(EndorserError::AlreadyInitialized);
    }
    self.ledger_tail_map = ledger_tail_map.clone();
    self.view_ledger_tail = *view_ledger_tail;
    self.is_initialized = true;

    let hash_of_state = self.produce_hash_of_state();
    let signature = self.keypair.sign(&hash_of_state.to_bytes());
    Ok(signature)
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

    let signature = self.keypair.sign(tail_hash.to_bytes().as_slice());
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
      let signature = self.keypair.sign(&message);
      Ok(signature)
    }
  }

  pub fn append(
    &mut self,
    handle: &NimbleDigest,
    block_hash: &NimbleDigest,
  ) -> Result<Signature, EndorserError> {
    if !self.is_initialized {
      return Err(EndorserError::NotInitialized);
    }

    // check if the requested ledger exists in the state, if not return an error
    if !self.ledger_tail_map.contains_key(handle) {
      return Err(EndorserError::InvalidLedgerName);
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

    let metablock = MetaBlock::new(&self.view_ledger_tail.0, &prev_tail, block_hash, *height);
    *tail_hash = metablock.hash();

    let signature = self.keypair.sign(&tail_hash.to_bytes());

    Ok(signature)
  }

  pub fn get_public_key(&self) -> PublicKey {
    self.keypair.public
  }

  pub fn read_latest_view_ledger(&self, nonce: &[u8]) -> Result<Signature, EndorserError> {
    if !self.is_initialized {
      return Err(EndorserError::NotInitialized);
    }

    let (tail, _height) = &self.view_ledger_tail;
    let message = tail.digest_with_bytes(nonce).to_bytes();
    let signature = self.keypair.sign(&message);
    Ok(signature)
  }

  pub fn append_view_ledger(
    &mut self,
    block_hash: &NimbleDigest,
  ) -> Result<Signature, EndorserError> {
    if !self.is_initialized {
      return Err(EndorserError::NotInitialized);
    }

    // read the current tail and height of the view ledger
    let (tail, height) = &self.view_ledger_tail;

    // perform a checked addition of height with 1
    let height_plus_one = {
      let res = height.checked_add(1);
      if res.is_none() {
        return Err(EndorserError::LedgerHeightOverflow);
      }
      res.unwrap()
    };

    // formulate a metablock for the new entry on the view ledger;
    // the view embedded in the view ledger is the hash of the current state of the endorser
    let meta_block = MetaBlock::new(
      &self.produce_hash_of_state(),
      tail,
      block_hash,
      height_plus_one,
    );

    // sign the hash of the new metablock
    let signature = self.keypair.sign(&meta_block.hash().to_bytes());

    // update the internal state
    self.view_ledger_tail = (meta_block.hash(), height_plus_one);

    Ok(signature)
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
    // We will pick a dummy view value for testing purposes
    let view = {
      let t = rand::thread_rng().gen::<[u8; 32]>();
      let n = NimbleDigest::from_bytes(&t);
      assert!(!n.is_err(), "This should not have occured");
      n.unwrap()
    };

    // The coordinator initializes the endorser by calling initialize_state
    let res = endorser_state.initialize_state(&HashMap::new(), &(view, 0usize));
    assert!(res.is_ok());

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

    let (tail_hash, height) = endorser_state.ledger_tail_map.get(&handle).unwrap();
    assert_eq!(height, &0usize);
    assert_eq!(tail_hash, &genesis_tail_hash);
  }

  #[test]
  pub fn check_endorser_append_ledger_tail() {
    let mut endorser_state = EndorserState::new();

    // The coordinator sends the hashed contents of the configuration to the endorsers
    // We will pick a dummy view value for testing purposes
    let view = {
      let t = rand::thread_rng().gen::<[u8; 32]>();
      let n = NimbleDigest::from_bytes(&t);
      assert!(!n.is_err(), "This should not have occured");
      n.unwrap()
    };

    // The coordinator initializes the endorser by calling initialize_state
    let res = endorser_state.initialize_state(&HashMap::new(), &(view, 0usize));
    assert!(res.is_ok());

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
    let signature = {
      endorser_state
        .append(&handle, &block_hash_to_append)
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

    let tail_signature_verification = endorser_state
      .keypair
      .verify(&endorser_tail_expectation.to_bytes(), &signature);

    if tail_signature_verification.is_ok() {
      println!("Verification Passed. Checking Updated Tail");
      let (tail_result, _height) = endorser_state.ledger_tail_map.get(&handle).unwrap();
      assert_eq!(&endorser_tail_expectation, tail_result);
    } else {
      panic!("Signature verification failed when it should not have failed");
    }
  }
}
