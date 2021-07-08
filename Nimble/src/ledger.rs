#![allow(dead_code)]
use core::fmt::Debug;
use digest::Output;
use ed25519_dalek::Signature;
use generic_array::typenum::U32;
use generic_array::GenericArray;
use sha3::{Digest, Sha3_256};
use std::convert::TryInto;

/// A cryptographic digest
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct NimbleDigest {
  digest: Output<Sha3_256>,
}

impl NimbleDigest {
  pub fn num_bytes() -> usize {
    <Sha3_256 as Digest>::output_size()
  }

  pub fn to_bytes(&self) -> Vec<u8> {
    self.digest.as_slice().to_vec()
  }

  pub fn from_bytes(bytes: &[u8]) -> Result<NimbleDigest, CustomSerdeError> {
    let digest_len = NimbleDigest::num_bytes();
    if bytes.len() != digest_len {
      Err(CustomSerdeError::IncorrectLength)
    } else {
      let digest = GenericArray::<u8, U32>::from_slice(&bytes[0..digest_len]);
      Ok(NimbleDigest { digest: *digest })
    }
  }

  pub fn digest(bytes: &[u8]) -> Self {
    NimbleDigest {
      digest: Sha3_256::digest(bytes),
    }
  }
}

/// A block in a ledger is a byte array
#[derive(Clone, Debug, Default)]
pub struct Block {
  block: Vec<u8>,
}

impl Block {
  pub fn new(bytes: &[u8]) -> Self {
    Block {
      block: bytes.to_vec(),
    }
  }
}

/// `MetaBlock` has three entries: (i) hash of the previous metadata,
/// (ii) a hash of the current block, and (iii) a counter denoting the height
/// of the current block in the ledger
#[derive(Clone, Debug, Default)]
pub struct MetaBlock {
  prev: NimbleDigest,
  block_hash: NimbleDigest,
  height: usize,
}

/// An `EndorsedMetaBlock` has two components: (1) a Metadata and (2) a set of signatures
#[derive(Clone, Debug, Default)]
pub struct EndorsedMetaBlock {
  metablock: MetaBlock,
  receipt: Vec<Signature>,
}

impl EndorsedMetaBlock {
  pub fn new(metablock: &MetaBlock, receipt: &[Signature]) -> Self {
    EndorsedMetaBlock {
      metablock: metablock.clone(),
      receipt: receipt.to_vec(),
    }
  }

  pub fn get_tail_hash(&self) -> NimbleDigest {
    self.metablock.prev.clone()
  }

  pub fn get_height(&self) -> usize {
    self.metablock.height
  }

  pub fn get_receipts(&self) -> Vec<Signature> {
    self.receipt.clone()
  }
}

impl MetaBlock {
  pub fn new(prev: &NimbleDigest, block_hash: &NimbleDigest, height: usize) -> Self {
    MetaBlock {
      prev: prev.clone(),
      block_hash: block_hash.clone(),
      height,
    }
  }

  pub fn genesis(block_hash: &NimbleDigest) -> Self {
    // unwrap is okay here since it will not fail
    let prev = NimbleDigest::from_bytes(&vec![0u8; NimbleDigest::num_bytes()]).unwrap();
    let height = 0usize;
    MetaBlock {
      prev,
      block_hash: block_hash.clone(),
      height,
    }
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CustomSerdeError {
  /// returned if the supplied byte array is of incorrect length
  IncorrectLength,
  /// returned if deserializing any byte entry into the Rust type fails
  InternalError,
}

pub trait CustomSerde
where
  Self: Sized,
{
  fn to_bytes(&self) -> Vec<u8>;
  fn from_bytes(bytes: Vec<u8>) -> Result<Self, CustomSerdeError>;
}

impl CustomSerde for Block {
  fn to_bytes(&self) -> Vec<u8> {
    self.block.clone()
  }

  fn from_bytes(bytes: Vec<u8>) -> Result<Block, CustomSerdeError> {
    Ok(Block { block: bytes })
  }
}

impl CustomSerde for MetaBlock {
  fn to_bytes(&self) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend(&self.prev.to_bytes());
    bytes.extend(&self.block_hash.to_bytes());
    bytes.extend(&self.height.to_be_bytes().to_vec());
    bytes
  }

  fn from_bytes(bytes: Vec<u8>) -> Result<MetaBlock, CustomSerdeError> {
    let usize_len = 0usize.to_be_bytes().to_vec().len();
    let digest_len = NimbleDigest::num_bytes();

    if bytes.len() != 2 * digest_len + usize_len {
      Err(CustomSerdeError::IncorrectLength)
    } else {
      // unwrap is okay to call here given the error check above
      let prev = NimbleDigest::from_bytes(&bytes[0..digest_len]).unwrap();
      let block_hash = NimbleDigest::from_bytes(&bytes[digest_len..2 * digest_len]).unwrap();
      let height = {
        let res = bytes[2 * digest_len..].try_into();
        if res.is_err() {
          return Err(CustomSerdeError::InternalError);
        }

        usize::from_be_bytes(res.unwrap())
      };

      Ok(MetaBlock {
        prev,
        block_hash,
        height,
      })
    }
  }
}

pub trait NimbleHashTrait
where
  Self: Sized,
{
  fn hash(&self) -> NimbleDigest;
}

impl NimbleHashTrait for Block {
  fn hash(&self) -> NimbleDigest {
    NimbleDigest::digest(&self.block)
  }
}

impl NimbleHashTrait for MetaBlock {
  fn hash(&self) -> NimbleDigest {
    NimbleDigest::digest(&self.to_bytes())
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use rand::Rng;

  #[test]
  pub fn test_nimble_digest_equality() {
    let hash_bytes_1 = rand::thread_rng().gen::<[u8; 32]>();
    let hash_bytes_2 = rand::thread_rng().gen::<[u8; 32]>();
    let duplicate_hash_bytes_1 = hash_bytes_1.clone();
    let nimble_digest_1 = NimbleDigest::from_bytes(&hash_bytes_1);
    let nimble_digest_2 = NimbleDigest::from_bytes(&hash_bytes_2);
    let nimble_digest_1_dupe = NimbleDigest::from_bytes(&duplicate_hash_bytes_1);
    assert_ne!(nimble_digest_1, nimble_digest_2);
    assert_eq!(nimble_digest_1, nimble_digest_1_dupe);
  }

  #[test]
  pub fn test_nimble_digest_hash_correctness_and_equality() {
    let message_1 = "1".as_bytes();
    let message_2 = "2".as_bytes();

    let expected_hash_message_1_hex =
      "67b176705b46206614219f47a05aee7ae6a3edbe850bbbe214c536b989aea4d2";
    let expected_hash_message_2_hex =
      "b1b1bd1ed240b1496c81ccf19ceccf2af6fd24fac10ae42023628abbe2687310";

    let expected_hash_message_1_op = hex::decode(expected_hash_message_1_hex);
    let expected_hash_message_2_op = hex::decode(expected_hash_message_2_hex);
    assert!(expected_hash_message_1_op.is_ok());
    assert!(expected_hash_message_2_op.is_ok());

    let nimble_digest_1 = NimbleDigest::digest(message_1);
    let nimble_digest_2 = NimbleDigest::digest(message_2);

    assert_eq!(
      nimble_digest_1.to_bytes(),
      expected_hash_message_1_op.unwrap()
    );
    assert_eq!(
      nimble_digest_2.to_bytes(),
      expected_hash_message_2_op.unwrap()
    );
  }

  #[test]
  pub fn test_block_hash_results() {
    let message_1 = "1".as_bytes();

    let expected_hash_message_1_hex =
      "67b176705b46206614219f47a05aee7ae6a3edbe850bbbe214c536b989aea4d2";

    let expected_hash_message_1_op = hex::decode(expected_hash_message_1_hex);
    assert!(expected_hash_message_1_op.is_ok());

    let block_1 = Block::new(message_1);
    let block_1_hash = block_1.hash();

    assert_eq!(block_1_hash.to_bytes(), expected_hash_message_1_op.unwrap());
  }
}
