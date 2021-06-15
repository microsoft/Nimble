use super::digest::Output;
use super::ed25519_dalek::{Keypair, PublicKey, Signature, Signer};
use super::errors::EndorserError;
use rand::rngs::OsRng;
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;

/// Endorser's internal state
pub struct EndorserState {
  /// a key pair in the ed25519 digital signature scheme
  keypair: Keypair,

  /// a map from fixed-sized labels to a tail hash
  ledgers: HashMap<Output<Sha3_256>, Output<Sha3_256>>,
}

/// Public identity of the endorser
pub struct EndorserIdentity {
  pubkey: PublicKey,
}

impl EndorserState {
  pub fn new() -> (Self, EndorserIdentity) {
    // initialize a random number generator
    let mut csprng = OsRng {};

    // generate a fresh ed25519 key pair
    let keypair = Keypair::generate(&mut csprng);

    // extract the public key component
    let pubkey = keypair.public;

    // return a new (EndorserState, EndorserIdentity) object
    (
      EndorserState {
        keypair,
        ledgers: HashMap::new(),
      },
      EndorserIdentity { pubkey },
    )
  }

  pub fn create(&mut self, genesis_hash: &Output<Sha3_256>) -> Result<bool, EndorserError> {
    // `genesis_hash` is the hash of the first block in the ledger and a ledger is named
    // by the first block's hashe, so we first check if there's already a ledger with
    // the same name
    if self.ledgers.contains_key(genesis_hash) {
      return Err(EndorserError::LedgerExists);
    }

    // The internal state for this ledger is initialized to Hash(NULL, block_hash)
    // since this is the first entry in the ledger
    let tail = {
      let mut hasher = Sha3_256::new();
      hasher.update(b"NULL");
      hasher.update(genesis_hash);
      hasher.finalize()
    };

    self.ledgers.insert(genesis_hash.clone(), tail);

    return Ok(true);
  }

  pub fn append(
    &mut self,
    genesis_hash: &Output<Sha3_256>,
    block_hash: &Output<Sha3_256>,
    cond_block_hash: &Output<Sha3_256>,
  ) -> Result<Signature, EndorserError> {
    // We first check if there's a ledger with the name `genesis_hash`
    if !self.ledgers.contains_key(genesis_hash) {
      return Err(EndorserError::InvalidLedgerName);
    }

    // check if the provided `cond_block_hash` matches the tail hash stored internally
    if self.ledgers[genesis_hash] != *cond_block_hash {
      return Err(EndorserError::TailDoesNotMatch);
    }

    // compute the new tail as Hash(tail, block_hash)
    let tail = {
      let mut hasher = Sha3_256::new();
      hasher.update(self.ledgers[genesis_hash]);
      hasher.update(block_hash);
      hasher.finalize()
    };

    // update the value associated with the key `genesis_hash`
    self.ledgers.insert(*genesis_hash, tail);

    // produce a signature on the updated tail
    let sig = self.keypair.sign(&self.ledgers[genesis_hash]);

    return Ok(sig);
  }

  pub fn read(
    &self,
    genesis_hash: &Output<Sha3_256>,
    nonce: &Output<Sha3_256>,
  ) -> Result<(Output<Sha3_256>, Signature), EndorserError> {
    // We first check if there's a ledger with the name `genesis_hash`
    if !self.ledgers.contains_key(genesis_hash) {
      return Err(EndorserError::InvalidLedgerName);
    }

    // Compute a signature on Hash(tail, nonce)
    let sig = {
      // compute a nonced tail, which is Hash(tail, nonce)
      let nonced_tail = {
        let mut hasher = Sha3_256::new();
        hasher.update(self.ledgers[genesis_hash]);
        hasher.update(nonce);
        hasher.finalize()
      };

      // produce a signature on the nonced tail
      self.keypair.sign(&nonced_tail)
    };

    return Ok((self.ledgers[genesis_hash], sig));
  }
}

mod tests {
  use super::*;
  use crate::ed25519_dalek::Verifier;

  #[test]
  pub fn check_endorser_end_to_end() {
    let (mut endorser_handle, endorser_id) = EndorserState::new();

    let genesis_hash = {
      let mut hasher = Sha3_256::new();
      hasher.update(b"gensis_hash");
      hasher.finalize()
    };

    // create a new ledger by calling create method
    let res = endorser_handle.create(&genesis_hash);

    // check that create returns a success
    assert!(res.is_ok());

    // now let's append an entry to the ledger
    let block_hash = {
      let mut hasher = Sha3_256::new();
      hasher.update(b"some_entry");
      hasher.finalize()
    };

    let cond_block_hash = {
      let mut hasher = Sha3_256::new();
      hasher.update(b"NULL");
      hasher.update(genesis_hash);
      hasher.finalize()
    };

    let res = endorser_handle.append(&genesis_hash, &block_hash, &cond_block_hash);
    assert!(res.is_ok());

    // verify the signature on the appended entry
    let res_sig = {
      let message = {
        let mut hasher = Sha3_256::new();
        hasher.update(cond_block_hash);
        hasher.update(block_hash);
        hasher.finalize()
      };
      endorser_id.pubkey.verify(&message, &res.clone().unwrap())
    };
    assert!(res_sig.is_ok());

    // verify the signature on a wrong entry and the check should fail
    let res_sig_wrong = {
      let wrong_message = {
        let mut hasher = Sha3_256::new();
        hasher.update(cond_block_hash);
        hasher.update(b"some_bits");
        hasher.update(block_hash);
        hasher.finalize()
      };
      endorser_id.pubkey.verify(&wrong_message, &res.unwrap())
    };
    assert!(res_sig_wrong.is_err());

    // now read the appended entry with a nonce
    let nonce = {
      let mut hasher = Sha3_256::new();
      hasher.update(b"some_nonce");
      hasher.finalize()
    };

    let res = endorser_handle.read(&genesis_hash, &nonce);
    assert!(res.is_ok());
    // verify the signature on the returned entry
    let res_sig = {
      let (tail, sig) = res.unwrap();
      let message = {
        let mut hasher = Sha3_256::new();
        hasher.update(tail);
        hasher.update(nonce);
        hasher.finalize()
      };
      endorser_id.pubkey.verify(&message, &sig)
    };
    assert!(res_sig.is_ok());
  }
}
