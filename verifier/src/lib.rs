mod errors;

use crate::errors::VerificationError;
use ed25519_dalek::{PublicKey, SignatureError};
use ledger::{Block, MetaBlock, NimbleDigest, NimbleHashTrait, Receipt};

const PUBLIC_KEY_IN_BYTES: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;
const NONCE_IN_BYTES: usize = 16;

#[derive(Debug, Clone, Default)]
pub struct VerificationKey {
  pk_vec: Vec<PublicKey>,
}

impl VerificationKey {
  fn from_bytes(pk_vec_bytes: &[u8]) -> Result<VerificationKey, VerificationError> {
    // parse the public keys into a vector and the code panics if a public key is invalid
    let pk_vec = {
      let res = (0..pk_vec_bytes.len() / PUBLIC_KEY_IN_BYTES)
        .map(|i| {
          PublicKey::from_bytes(
            &pk_vec_bytes[i * PUBLIC_KEY_IN_BYTES..(i + 1) * PUBLIC_KEY_IN_BYTES],
          )
        })
        .collect::<Result<Vec<PublicKey>, SignatureError>>();
      if res.is_err() {
        return Err(VerificationError::InvalidGenesisBlock);
      }

      res.unwrap()
    };
    Ok(VerificationKey { pk_vec })
  }

  pub fn get_public_keys(&self) -> &Vec<PublicKey> {
    &self.pk_vec
  }

  fn get_current_view(&self) -> NimbleDigest {
    // In the absence of reconfigurations, the view can be computed from the list of public keys.
    // For now, we use the public keys included in the genesis block to construct the view
    let view_block_bytes = (0..self.pk_vec.len())
      .map(|i| self.pk_vec[i].to_bytes().to_vec())
      .collect::<Vec<Vec<u8>>>()
      .into_iter()
      .flatten()
      .collect::<Vec<u8>>();

    // the tail hash of the view ledger is the hash of the default NimbleDigest with the view block
    NimbleDigest::default().digest_with(&NimbleDigest::digest(&view_block_bytes))
  }
}

///
/// The parameters of the VerifyNewLedger() are:
/// 1. The Block Data
/// 2. A receipt
/// 3. A nonce
pub fn verify_new_ledger(
  block_bytes: &[u8],
  receipt_bytes: &[(usize, Vec<u8>)],
  nonce: &[u8],
) -> Result<(Vec<u8>, VerificationKey), VerificationError> {
  let vk = {
    // check there is at least one public key for an endorser
    if block_bytes.len() < (PUBLIC_KEY_IN_BYTES + NONCE_IN_BYTES + NONCE_IN_BYTES)
      || (block_bytes.len() - NONCE_IN_BYTES - NONCE_IN_BYTES) % PUBLIC_KEY_IN_BYTES != 0
    {
      Err(VerificationError::InvalidGenesisBlock)
    } else {
      // parse the genesis block and extract the endorser's public key to form a verification key
      // the first `NONCE_IN_BYTES` bytes are the service chosen nonce, followed by the client nonce,
      // so the rest are a set of public keys.
      let client_nonce = &block_bytes[NONCE_IN_BYTES..(NONCE_IN_BYTES + NONCE_IN_BYTES)];
      if client_nonce != nonce {
        return Err(VerificationError::InvalidGenesisBlock);
      }
      VerificationKey::from_bytes(&block_bytes[(NONCE_IN_BYTES + NONCE_IN_BYTES)..])
    }
  }?;

  // produce a view hash using the current configuration
  let view = vk.get_current_view();

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
    Ok((handle.to_bytes(), vk))
  }
}

pub fn verify_read_latest(
  vk: &VerificationKey,
  block_bytes: &[u8],
  tail_hash_bytes: &[u8],
  height: usize,
  nonce_bytes: &[u8],
  receipt_bytes: &[(usize, Vec<u8>)],
) -> Result<(Vec<u8>, Vec<u8>), VerificationError> {
  let block = Block::new(block_bytes);

  // construct a tail hash from `tail_hash_bytes`
  let res = NimbleDigest::from_bytes(tail_hash_bytes);
  if res.is_err() {
    return Err(VerificationError::IncorrectLength);
  }
  let tail_hash = res.unwrap();

  let metablock = MetaBlock::new(&vk.get_current_view(), &tail_hash, &block.hash(), height);
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
  block_bytes: &[u8],
  tail_hash_bytes: &[u8],
  idx: usize,
  receipt_bytes: &[(usize, Vec<u8>)],
) -> Result<(), VerificationError> {
  let block = Block::new(block_bytes);
  let block_hash = block.hash();
  let res = NimbleDigest::from_bytes(tail_hash_bytes);
  if res.is_err() {
    return Err(VerificationError::IncorrectLength);
  }
  let tail_hash = res.unwrap();

  let metablock = MetaBlock::new(&vk.get_current_view(), &tail_hash, &block_hash, idx);
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
  block_bytes: &[u8],
  tail_hash_bytes: &[u8],
  height: usize,
  receipt_bytes: &[(usize, Vec<u8>)],
) -> Result<Vec<u8>, VerificationError> {
  let block = Block::new(block_bytes);
  let block_hash = block.hash();
  let res = NimbleDigest::from_bytes(tail_hash_bytes);
  if res.is_err() {
    return Err(VerificationError::IncorrectLength);
  }
  let tail_hash = res.unwrap();

  let metablock = MetaBlock::new(&vk.get_current_view(), &tail_hash, &block_hash, height);
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
