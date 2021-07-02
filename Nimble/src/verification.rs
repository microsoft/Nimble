use crate::errors::VerificationError;
use crate::helper;
use crate::helper::concat_bytes;
use ed25519_dalek::{PublicKey, Signature, Verifier};

#[derive(Debug, Clone, Default)]
pub struct VerificationKey {
  handle: Vec<u8>,
  public_key: PublicKey,
}

pub type Block = Vec<u8>;
pub type TailHash = Vec<u8>;
pub type Nonce = Vec<u8>;

///
/// The parameters of the VerifyNewLedger() are:
/// 1. The Block Data
/// 2. A signature from an endorser (the code currently assumes a single endorser)
pub fn verify_new_ledger(
  data: &Block,
  signature: &Signature,
) -> Result<VerificationKey, VerificationError> {
  // Parse the genesis block
  let (pk, sig, _nonce) = {
    let block_data_buffer = data.as_slice();
    let public_key_bytes = &block_data_buffer[0..32usize];
    let sig_bytes = &block_data_buffer[32usize..(32usize + 64usize)];
    let nonce_bytes = &block_data_buffer[(32usize + 64usize)..((32usize + 64usize) + 16usize)];
    (
      PublicKey::from_bytes(public_key_bytes).unwrap(),
      ed25519_dalek::ed25519::signature::Signature::from_bytes(sig_bytes).unwrap(),
      nonce_bytes.to_vec(),
    )
  };
  // Verify the contents of the genesis block
  let res = pk.verify(pk.as_bytes(), &sig);
  if res.is_err() {
    return Err(VerificationError::UnableToVerifyEndorser);
  }

  // compute a handle as hash of the block
  let handle = helper::hash(&data).to_vec();

  let genesis_metadata = {
    // genesis metadata has three entries
    let mut metadata: Vec<u8> = vec![];
    metadata.extend([0u8; 32].to_vec()); // canonical previous hash pointer in the genesis block
    metadata.extend(handle.clone());
    metadata.extend(0u64.to_be_bytes().to_vec()); // canonical ledger height for the genesis block
    metadata
  };
  let hash = helper::hash(&genesis_metadata).to_vec();
  let res = pk.verify(&hash, &signature);
  if res.is_err() {
    return Err(VerificationError::InvalidGenesisBlock);
  }

  Ok(VerificationKey {
    handle,
    public_key: pk,
  })
}

pub fn verify_read_latest(
  vk: &VerificationKey,
  data: &Block,
  tail: &TailHash,
  counter: usize,
  nonce: &Nonce,
  signature: &Signature,
) -> Result<(), VerificationError> {
  let block_hash = helper::hash(&data).to_vec();
  let metadata = helper::pack_metadata_information(tail.to_vec(), block_hash, counter);
  let tail_hash_prime = helper::hash(&metadata).to_vec();
  let hashed_message = {
    let verification_message = concat_bytes(tail_hash_prime.as_slice(), &nonce);
    helper::hash(&verification_message).to_vec()
  };

  let res = vk.public_key.verify(hashed_message.as_slice(), &signature);
  if res.is_err() {
    Err(VerificationError::UnableToVerifyEndorser)
  } else {
    Ok(())
  }
}

pub fn verify_read_by_index(
  vk: &VerificationKey,
  data: &Block,
  tail_hash: &TailHash,
  idx: usize,
  signature: &Signature,
) -> Result<(), VerificationError> {
  let block_hash = helper::hash(&data).to_vec();
  let metadata = helper::pack_metadata_information(tail_hash.clone(), block_hash, idx);
  let tail_hash_prime = helper::hash(&metadata).to_vec();

  let res = vk.public_key.verify(tail_hash_prime.as_slice(), &signature);
  if res.is_err() {
    Err(VerificationError::UnableToVerifyEndorser)
  } else {
    Ok(())
  }
}

pub fn verify_append(
  vk: &VerificationKey,
  block_data: &Block,
  tail_hash: &TailHash,
  ledger_height: usize,
  signature: &Signature,
) -> Result<(), VerificationError> {
  let block_hash = helper::hash(block_data).to_vec();
  let metadata = helper::pack_metadata_information(tail_hash.clone(), block_hash, ledger_height);
  let tail_hash_prime = helper::hash(&metadata).to_vec();

  let res = vk.public_key.verify(tail_hash_prime.as_slice(), &signature);
  if res.is_err() {
    Err(VerificationError::UnableToVerifyEndorser)
  } else {
    Ok(())
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
