use core::fmt::Debug;
use digest::Output;
use ed25519_dalek::Signature;
use generic_array::typenum::U32;
use generic_array::GenericArray;
use sha3::{Digest, Sha3_256};
use std::convert::TryInto;

/// A cryptographic digest
#[derive(Clone, Debug)]
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
pub struct Block {
  block: Vec<u8>,
}

impl Block {
  pub fn new(bytes: &Vec<u8>) -> Self {
    Block {
      block: bytes.clone(),
    }
  }
}

/// `MetaBlock` has three entries: (i) hash of the previous metadata,
/// (ii) a hash of the current block, and (iii) a counter denoting the height
/// of the current block in the ledger
pub struct MetaBlock {
  prev: NimbleDigest,
  block_hash: NimbleDigest,
  height: usize,
}

/// An `EndorsedMetaBlock` has two components: (1) a Metadata and (2) a set of signatures
pub struct EndorsedMetaBlock {
  metablock: MetaBlock,
  receipt: Vec<Signature>,
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
