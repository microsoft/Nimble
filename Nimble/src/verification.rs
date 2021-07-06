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
  block_bytes: &Vec<u8>,
  signature: &Signature,
) -> Result<(Vec<u8>, VerificationKey), VerificationError> {
  // check the length of block_bytes
  if block_bytes.len() != 112 {
    return Err(VerificationError::InvalidGenesisBlock);
  }

  // parse the genesis block
  let (pk, sig) = {
    let public_key_bytes = &block_bytes[0..32usize];
    let sig_bytes = &block_bytes[32usize..(32usize + 64usize)];
    let _nonce_bytes = &block_bytes[(32usize + 64usize)..((32usize + 64usize) + 16usize)];
    (
      PublicKey::from_bytes(public_key_bytes).unwrap(),
      ed25519_dalek::ed25519::signature::Signature::from_bytes(sig_bytes).unwrap(),
    )
  };

  // Verify the contents of the genesis block
  let res = pk.verify(pk.as_bytes(), &sig);
  if res.is_err() {
    return Err(VerificationError::InvalidEndorserAttestation);
  }

  // compute a handle as hash of the block
  let handle = {
    let block = Block::new(block_bytes);
    block.hash()
  };

  // verify the signature on the genesis metablock with `handle` as the genesis block's hash
  let genesis_metablock = MetaBlock::genesis(&handle);
  let res = {
    let hash = genesis_metablock.hash().to_bytes();
    pk.verify(&hash, &signature)
  };

  if res.is_err() {
    return Err(VerificationError::InvalidGenesisBlock);
  }

  Ok((handle.to_bytes(), VerificationKey { pk }))
}

pub fn verify_read_latest(
  vk: &VerificationKey,
  block_bytes: &Vec<u8>,
  tail_hash_bytes: &Vec<u8>,
  height: usize,
  nonce_bytes: &Vec<u8>,
  signature: &Signature,
) -> Result<(), VerificationError> {
  let block = Block::new(&block_bytes);

  // construct a tail hash from `tail_hash_bytes`
  // TODO: simplify error handling
  let res = NimbleDigest::from_bytes(tail_hash_bytes);
  if res.is_err() {
    return Err(VerificationError::IncorrectLength);
  }
  let tail_hash = res.unwrap();

  let metablock = MetaBlock::new(&tail_hash, &block.hash(), height);
  let tail_hash_prime = metablock.hash();
  let nonced_tail_hash_prime = [tail_hash_prime.to_bytes(), nonce_bytes.clone()].concat();
  let res = vk.pk.verify(&nonced_tail_hash_prime, &signature);
  if res.is_err() {
    Err(VerificationError::InvalidReceipt)
  } else {
    Ok(())
  }
}

pub fn verify_read_by_index(
  vk: &VerificationKey,
  block_bytes: &Vec<u8>,
  tail_hash_bytes: &Vec<u8>,
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

  let res = vk.pk.verify(&tail_hash_prime.to_bytes(), &signature);
  if res.is_err() {
    Err(VerificationError::InvalidReceipt)
  } else {
    Ok(())
  }
}

pub fn verify_append(
  vk: &VerificationKey,
  block_bytes: &Vec<u8>,
  tail_hash_bytes: &Vec<u8>,
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

  let res = vk.pk.verify(&tail_hash_prime.to_bytes(), &signature);
  if res.is_err() {
    Err(VerificationError::InvalidReceipt)
  } else {
    Ok(tail_hash_prime.to_bytes())
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use ed25519_dalek::ed25519::signature::Signature;

  #[test]
  pub fn test_verify_new_ledger() {
    let block_data = {
      let block_data_hex = "4b2dd24314c098717dfdcbf04e2bd9a2ed6f580ad4e444fed30f736d6f273e60eab295f4aff4a7d5eb83c776e6f5cff233219bad8798ea500a7cde2776037e4849188184479e019712a55d1d91a3b9678f6288d02816baced4de555ec81f4f0cf413e33cb2444824bdbd93b06958c8ba";
      hex::decode(block_data_hex).unwrap()
    };

    let signature = {
      let signature_data_hex = "1c48864bc5f164375f175ace328b1e9b373cf8001b959c5cf80c71ef8f73a196eba677a54e06d16818bf461e49e6376082fc00845101e79da968434715eefa06";
      let signature_data = hex::decode(signature_data_hex).unwrap();
      Signature::from_bytes(&signature_data).unwrap()
    };

    let res = verify_new_ledger(&block_data, &signature);
    assert!(res.is_ok());
  }
}
