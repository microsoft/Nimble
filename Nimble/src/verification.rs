use crate::errors::VerificationError;
use crate::ledger::{Block, MetaBlock, NimbleDigest, NimbleHashTrait};
use ed25519_dalek::{PublicKey, Signature, Verifier};

#[derive(Debug, Clone, Default)]
pub struct VerificationKey {
  pk: PublicKey,
}

///
/// The parameters of the VerifyNewLedger() are:
/// 1. The Block Data
/// 2. A signature from an endorser (the code currently assumes a single endorser)
pub fn verify_new_ledger(
  block_bytes: &[u8],
  signature: &Signature,
) -> Result<(Vec<u8>, VerificationKey), VerificationError> {
  // check the length of block_bytes
  if block_bytes.len() != 48 {
    return Err(VerificationError::InvalidGenesisBlock);
  }

  // parse the genesis block and extract the endorser's public key
  let pk = {
    let public_key_bytes = &block_bytes[0..32usize];
    let _nonce_bytes = &block_bytes[32usize..(32usize + 16usize)];
    PublicKey::from_bytes(public_key_bytes).unwrap()
  };

  // compute a handle as hash of the block
  let handle = {
    let block = Block::new(block_bytes);
    block.hash()
  };

  // verify the signature on the genesis metablock with `handle` as the genesis block's hash
  let genesis_metablock = MetaBlock::genesis(&handle);
  let res = {
    let hash = genesis_metablock.hash().to_bytes();
    pk.verify(&hash, signature)
  };

  if res.is_err() {
    return Err(VerificationError::InvalidGenesisBlock);
  }

  Ok((handle.to_bytes(), VerificationKey { pk }))
}

pub fn verify_read_latest(
  vk: &VerificationKey,
  block_bytes: &[u8],
  tail_hash_bytes: &[u8],
  height: usize,
  nonce_bytes: &[u8],
  signature: &Signature,
) -> Result<Vec<u8>, VerificationError> {
  let block = Block::new(block_bytes);

  // construct a tail hash from `tail_hash_bytes`
  // TODO: simplify error handling
  let res = NimbleDigest::from_bytes(tail_hash_bytes);
  if res.is_err() {
    return Err(VerificationError::IncorrectLength);
  }
  let tail_hash = res.unwrap();

  let metablock = MetaBlock::new(&tail_hash, &block.hash(), height);
  let tail_hash_prime = metablock.hash();
  let nonced_tail_hash_prime = [tail_hash_prime.to_bytes(), nonce_bytes.to_vec()].concat();
  let res = vk.pk.verify(&nonced_tail_hash_prime, signature);
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
  signature: &Signature,
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

  let res = vk.pk.verify(&tail_hash_prime.to_bytes(), signature);
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
  signature: &Signature,
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

  let res = vk.pk.verify(&tail_hash_prime.to_bytes(), signature);
  if res.is_err() {
    Err(VerificationError::InvalidReceipt)
  } else {
    Ok(tail_hash_prime.to_bytes())
  }
}
