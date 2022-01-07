mod errors;

use crate::errors::VerificationError;
use ledger::{
  signature::{CryptoError, PublicKey, PublicKeyTrait},
  Block, MetaBlock, NimbleDigest, NimbleHashTrait, Receipt,
};

const NONCE_IN_BYTES: usize = 16;
const NUM_ENDORSERS_IN_BYTES: usize = 1;
const MIN_NUM_ENDORSERS: usize = 1;

#[derive(Debug, Clone, Default)]
pub struct VerificationKey {
  pk_vec: Vec<PublicKey>,
}

impl VerificationKey {
  fn from_bytes(pk_vec_bytes: &[u8]) -> Result<VerificationKey, VerificationError> {
    let public_key_in_bytes = PublicKey::num_bytes();
    // parse the public keys into a vector and the code panics if a public key is invalid
    let res = (0..pk_vec_bytes.len() / public_key_in_bytes)
      .map(|i| {
        PublicKey::from_bytes(&pk_vec_bytes[i * public_key_in_bytes..(i + 1) * public_key_in_bytes])
      })
      .collect::<Result<Vec<PublicKey>, CryptoError>>();

    if let Ok(pk_vec) = res {
      Ok(VerificationKey { pk_vec })
    } else {
      Err(VerificationError::InvalidGenesisBlock)
    }
  }

  pub fn get_public_keys(&self) -> &Vec<PublicKey> {
    &self.pk_vec
  }

  fn get_current_view(&self) -> NimbleDigest {
    // In the absence of reconfigurations, the view can be computed from the list of public keys.
    // For now, we use the public keys included in the genesis block to construct the view
    let view_ledger_genesis_block = {
      let pk_vec_bytes = (0..self.pk_vec.len())
        .map(|i| self.pk_vec[i].to_bytes().to_vec())
        .collect::<Vec<Vec<u8>>>()
        .into_iter()
        .flatten()
        .collect::<Vec<u8>>();
      Block::new(&pk_vec_bytes)
    };
    let view_ledger_metablock = MetaBlock::new(
      &NimbleDigest::default(),
      &NimbleDigest::default(),
      &view_ledger_genesis_block.hash(),
      1_usize,
    );
    view_ledger_metablock.hash()
  }
}

///
/// The parameters of the VerifyNewLedger() are:
/// 1. The Block Data
/// 2. A receipt
/// 3. A nonce
pub fn verify_new_ledger(
  view_bytes: &[u8],
  block_bytes: &[u8],
  receipt_bytes: &[(usize, Vec<u8>)],
  nonce: &[u8],
) -> Result<(Vec<u8>, VerificationKey, Vec<u8>), VerificationError> {
  if receipt_bytes.len() < MIN_NUM_ENDORSERS {
    return Err(VerificationError::InsufficientReceipts);
  }

  let (vk, app_bytes) = {
    // check there is at least one public key for an endorser
    let public_key_in_bytes = PublicKey::num_bytes();
    if block_bytes.len()
      < (public_key_in_bytes + NONCE_IN_BYTES + NONCE_IN_BYTES + NUM_ENDORSERS_IN_BYTES)
    {
      return Err(VerificationError::InvalidGenesisBlock);
    } else {
      // parse the genesis block and extract the endorser's public key to form a verification key
      // the first `NONCE_IN_BYTES` bytes are the service chosen nonce, followed by the client nonce,
      // so the rest are a set of public keys and application-provided data
      let client_nonce = &block_bytes[NONCE_IN_BYTES..(NONCE_IN_BYTES + NONCE_IN_BYTES)];
      if client_nonce != nonce {
        return Err(VerificationError::InvalidGenesisBlock);
      }

      // extract the public keys of endorsers as well as app data
      let block_bytes_tail = &block_bytes[(NONCE_IN_BYTES + NONCE_IN_BYTES)..];
      let (pk_vec_bytes, app_bytes) = {
        let num_endorsers = block_bytes_tail[0] as usize;

        if num_endorsers < MIN_NUM_ENDORSERS {
          return Err(VerificationError::InvalidGenesisBlock);
        }

        if block_bytes_tail.len() < (num_endorsers * public_key_in_bytes) + NUM_ENDORSERS_IN_BYTES {
          return Err(VerificationError::InvalidGenesisBlock);
        }

        let pk_vec_bytes = &block_bytes_tail[1..(1 + num_endorsers * public_key_in_bytes)];
        let app_bytes = if block_bytes_tail.len()
          > (num_endorsers * public_key_in_bytes) + NUM_ENDORSERS_IN_BYTES
        {
          block_bytes_tail[(1 + num_endorsers * public_key_in_bytes)..].to_vec()
        } else {
          vec![]
        };

        (pk_vec_bytes, app_bytes)
      };

      (VerificationKey::from_bytes(pk_vec_bytes)?, app_bytes)
    }
  };

  // produce a view hash using the current configuration
  let view = {
    let res = NimbleDigest::from_bytes(view_bytes);
    if res.is_err() {
      return Err(VerificationError::InvalidView);
    }
    res.unwrap()
  };

  if view != vk.get_current_view() {
    return Err(VerificationError::InvalidView);
  }

  // compute a handle as hash of the block
  let handle = {
    let block = Block::new(block_bytes);
    block.hash()
  };

  // verify the signature on the genesis metablock with `handle` as the genesis block's hash
  let genesis_metablock = MetaBlock::genesis(&view, &handle);
  let hash = genesis_metablock.hash().to_bytes();

  // construct a receipt object from the provided bytes
  let receipt = Receipt::from_bytes(receipt_bytes);

  let res = receipt.verify(&hash, vk.get_public_keys());

  if res.is_err() {
    Err(VerificationError::InvalidGenesisBlock)
  } else {
    Ok((handle.to_bytes(), vk, app_bytes))
  }
}

pub fn get_tail_hash(
  view_bytes: &[u8],
  block_bytes: &[u8],
  prev_bytes: &[u8],
  height: usize,
) -> Result<Vec<u8>, VerificationError> {
  let view = {
    let res = NimbleDigest::from_bytes(view_bytes);
    if res.is_err() {
      return Err(VerificationError::IncorrectLength);
    }
    res.unwrap()
  };
  let block = Block::new(block_bytes);
  let prev = {
    let res = NimbleDigest::from_bytes(prev_bytes);
    if res.is_err() {
      return Err(VerificationError::IncorrectLength);
    }
    res.unwrap()
  };
  let metablock = MetaBlock::new(&view, &prev, &block.hash(), height);
  Ok(metablock.hash().to_bytes())
}

pub fn verify_read_latest(
  vk: &VerificationKey,
  view_bytes: &[u8],
  block_bytes: &[u8],
  prev_bytes: &[u8],
  height: usize,
  nonce_bytes: &[u8],
  receipt_bytes: &[(usize, Vec<u8>)],
) -> Result<(Vec<u8>, Vec<u8>), VerificationError> {
  if receipt_bytes.len() < MIN_NUM_ENDORSERS {
    return Err(VerificationError::InsufficientReceipts);
  }

  let block = Block::new(block_bytes);

  // construct a tail hash from `prev_bytes`
  let prev = {
    let res = NimbleDigest::from_bytes(prev_bytes);
    if res.is_err() {
      return Err(VerificationError::IncorrectLength);
    }
    res.unwrap()
  };

  let view = {
    let res = NimbleDigest::from_bytes(view_bytes);
    if res.is_err() {
      return Err(VerificationError::IncorrectLength);
    }
    res.unwrap()
  };

  if view != vk.get_current_view() {
    return Err(VerificationError::InvalidView);
  }

  let metablock = MetaBlock::new(&view, &prev, &block.hash(), height);
  let tail_hash_prime = metablock.hash();
  let hash_nonced_tail_hash_prime =
    NimbleDigest::digest(&([tail_hash_prime.to_bytes(), nonce_bytes.to_vec()]).concat()).to_bytes();

  // parse the receipt to construct a Receipt object
  let receipt = Receipt::from_bytes(receipt_bytes);

  // verify the receipt against the nonced tail hash
  let res = receipt.verify(&hash_nonced_tail_hash_prime, vk.get_public_keys());

  if res.is_err() {
    return Err(VerificationError::InvalidReceipt);
  }

  let filtered_block_data = if height == 0 {
    vec![]
  } else {
    block_bytes.to_vec()
  };
  Ok((tail_hash_prime.to_bytes(), filtered_block_data))
}

pub fn verify_read_by_index(
  vk: &VerificationKey,
  view_bytes: &[u8],
  block_bytes: &[u8],
  prev_bytes: &[u8],
  idx: usize,
  receipt_bytes: &[(usize, Vec<u8>)],
) -> Result<(), VerificationError> {
  if receipt_bytes.len() < MIN_NUM_ENDORSERS {
    return Err(VerificationError::InsufficientReceipts);
  }

  let block_hash = Block::new(block_bytes).hash();
  let prev = {
    let res = NimbleDigest::from_bytes(prev_bytes);
    if res.is_err() {
      return Err(VerificationError::IncorrectLength);
    }
    res.unwrap()
  };
  let view = {
    let res = NimbleDigest::from_bytes(view_bytes);
    if res.is_err() {
      return Err(VerificationError::IncorrectLength);
    }
    res.unwrap()
  };

  if view != vk.get_current_view() {
    return Err(VerificationError::InvalidView);
  }

  let metablock = MetaBlock::new(&view, &prev, &block_hash, idx);
  let tail_hash_prime = metablock.hash();

  // parse the receipt to construct a Receipt object
  let receipt = Receipt::from_bytes(receipt_bytes);

  // verify the receipt against the nonced tail hash
  let res = receipt.verify(&tail_hash_prime.to_bytes(), vk.get_public_keys());

  if res.is_err() {
    Err(VerificationError::InvalidReceipt)
  } else {
    Ok(())
  }
}

pub fn verify_append(
  vk: &VerificationKey,
  view_bytes: &[u8],
  block_bytes: &[u8],
  prev: &[u8],
  height: usize,
  receipt_bytes: &[(usize, Vec<u8>)],
) -> Result<Vec<u8>, VerificationError> {
  if receipt_bytes.len() < MIN_NUM_ENDORSERS {
    return Err(VerificationError::InsufficientReceipts);
  }

  let block_hash = Block::new(block_bytes).hash();
  let prev = {
    let res = NimbleDigest::from_bytes(prev);
    if res.is_err() {
      return Err(VerificationError::IncorrectLength);
    }
    res.unwrap()
  };
  let view = {
    let res = NimbleDigest::from_bytes(view_bytes);
    if res.is_err() {
      return Err(VerificationError::IncorrectLength);
    }
    res.unwrap()
  };

  if view != vk.get_current_view() {
    return Err(VerificationError::InvalidView);
  }

  let metablock = MetaBlock::new(&view, &prev, &block_hash, height);
  let tail_hash_prime = metablock.hash();

  // parse the receipt to construct a Receipt object
  let receipt = Receipt::from_bytes(receipt_bytes);

  // verify the receipt against the nonced tail hash
  let res = receipt.verify(&tail_hash_prime.to_bytes(), vk.get_public_keys());

  if res.is_err() {
    Err(VerificationError::InvalidReceipt)
  } else {
    Ok(tail_hash_prime.to_bytes())
  }
}
