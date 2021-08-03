use crate::errors::VerificationError;
use crate::ledger::{Block, MetaBlock, NimbleDigest, NimbleHashTrait, Receipt};
use ed25519_dalek::PublicKey;

const PUBLIC_KEY_IN_BYTES: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;
const NONCE_IN_BYTES: usize = 16;

#[derive(Debug, Clone, Default)]
pub struct VerificationKey {
  pk_vec: Vec<PublicKey>,
}

impl VerificationKey {
  fn from_bytes(pk_vec_bytes: &[u8]) -> VerificationKey {
    // parse the public keys into a vector and the code panics if a public key is invalid
    let pk_vec = (0..pk_vec_bytes.len() / PUBLIC_KEY_IN_BYTES)
      .map(|i| {
        PublicKey::from_bytes(&pk_vec_bytes[i * PUBLIC_KEY_IN_BYTES..(i + 1) * PUBLIC_KEY_IN_BYTES])
          .unwrap()
      })
      .collect::<Vec<PublicKey>>();
    VerificationKey { pk_vec }
  }

  pub fn get_public_keys(&self) -> &Vec<PublicKey> {
    &self.pk_vec
  }
}

///
/// The parameters of the VerifyNewLedger() are:
/// 1. The Block Data
/// 2. A receipt
pub fn verify_new_ledger(
  block_bytes: &[u8],
  receipt_bytes: &[(usize, Vec<u8>)],
) -> Result<(Vec<u8>, VerificationKey), VerificationError> {
  // check there is at least one public key for an endorser
  if block_bytes.len() < (PUBLIC_KEY_IN_BYTES + NONCE_IN_BYTES)
    || (block_bytes.len() - NONCE_IN_BYTES) % PUBLIC_KEY_IN_BYTES != 0
  {
    return Err(VerificationError::InvalidGenesisBlock);
  }

  // parse the genesis block and extract the endorser's public key to form a verification key
  // the first `NONCE_IN_BYTES` bytes are the nonce, so the rest are a set of public keys
  let vk = VerificationKey::from_bytes(&block_bytes[NONCE_IN_BYTES..]);

  // compute a handle as hash of the block
  let handle = {
    let block = Block::new(block_bytes);
    block.hash()
  };

  // verify the signature on the genesis metablock with `handle` as the genesis block's hash
  let genesis_metablock = MetaBlock::genesis(&handle);
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
) -> Result<Vec<u8>, VerificationError> {
  let block = Block::new(block_bytes);

  // construct a tail hash from `tail_hash_bytes`
  let res = NimbleDigest::from_bytes(tail_hash_bytes);
  if res.is_err() {
    return Err(VerificationError::IncorrectLength);
  }
  let tail_hash = res.unwrap();

  let metablock = MetaBlock::new(&tail_hash, &block.hash(), height);
  let tail_hash_prime = metablock.hash();
  let nonced_tail_hash_prime = [tail_hash_prime.to_bytes(), nonce_bytes.to_vec()].concat();

  // parse the receipt to construct a Receipt object
  let receipt = Receipt::from_bytes(receipt_bytes);

  // verify the receipt against the nonced tail hash
  let res = receipt.verify(&nonced_tail_hash_prime, vk.get_public_keys());
  if res.is_err() {
    Err(VerificationError::InvalidReceipt)
  } else {
    Ok(tail_hash_prime.to_bytes())
  }
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

  let metablock = MetaBlock::new(&tail_hash, &block_hash, idx);
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

  let metablock = MetaBlock::new(&tail_hash, &block_hash, height);
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
