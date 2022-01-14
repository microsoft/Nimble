mod errors;
pub mod signature;
pub mod store;
use crate::errors::VerificationError;
use crate::signature::{PublicKey, PublicKeyTrait, Signature, SignatureTrait};
use digest::Output;
use generic_array::typenum::U32;
use generic_array::GenericArray;
use itertools::concat;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::convert::TryInto;

/// A cryptographic digest
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq, Copy)]
pub struct NimbleDigest {
  digest: Output<Sha256>,
}

impl NimbleDigest {
  pub fn num_bytes() -> usize {
    <Sha256 as Digest>::output_size()
  }

  pub fn to_bytes(self) -> Vec<u8> {
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
      digest: Sha256::digest(bytes),
    }
  }

  /// concatenates `self` and `other` and computes a hash of the two
  pub fn digest_with(&self, other: &NimbleDigest) -> Self {
    NimbleDigest::digest(&[self.to_bytes(), other.to_bytes()].concat())
  }

  /// concatenates `self` and `other` bytes and computes a hash of the two
  pub fn digest_with_bytes(&self, other: &[u8]) -> Self {
    NimbleDigest::digest(&[self.to_bytes(), other.to_vec()].concat())
  }
}

pub type Handle = NimbleDigest;

/// A cryptographic Nonce
#[derive(Clone, Debug, Copy)]
pub struct Nonce {
  data: [u8; 16],
}

impl Nonce {
  pub fn new(nonce: &[u8]) -> Result<Nonce, CustomSerdeError> {
    if nonce.len() != 16 {
      Err(CustomSerdeError::IncorrectLength)
    } else {
      Ok(Nonce {
        data: nonce.try_into().unwrap(),
      })
    }
  }

  pub fn get(&self) -> Vec<u8> {
    self.data.to_vec()
  }
}

#[derive(Debug, Clone)]
pub struct IdSig {
  id: usize,
  sig: Signature,
}

impl IdSig {
  pub fn get_id_and_sig(&self) -> (usize, &Signature) {
    (self.id, &self.sig)
  }

  pub fn get_id(&self) -> usize {
    self.id
  }

  pub fn get_sig(&self) -> &Signature {
    &self.sig
  }
}

#[derive(Debug, Clone, Default)]
pub struct Receipt {
  id_sigs: Vec<IdSig>,
}

impl Receipt {
  // TODO: return error in case `from_bytes` fails
  pub fn from_bytes(receipt_bytes: &[(usize, Vec<u8>)]) -> Receipt {
    Receipt {
      id_sigs: (0..receipt_bytes.len())
        .map(|i| {
          let (id, sig_bytes) = receipt_bytes[i].clone();
          IdSig {
            id,
            sig: Signature::from_bytes(&sig_bytes).unwrap(),
          }
        })
        .collect::<Vec<IdSig>>(),
    }
  }

  pub fn to_bytes(&self) -> Vec<(usize, Vec<u8>)> {
    self
      .id_sigs
      .iter()
      .map(|x| (x.id, x.sig.to_bytes().to_vec()))
      .collect()
  }

  pub fn verify(&self, msg: &[u8], pk_vec: &[PublicKey]) -> Result<(), VerificationError> {
    // check if the indexes in the receipt are unique
    let id_sigs = &self.id_sigs;
    let unique_ids = {
      let mut uniq = HashSet::new();
      (0..id_sigs.len())
        .map(|i| id_sigs[i].get_id())
        .collect::<Vec<usize>>()
        .into_iter()
        .all(|x| uniq.insert(x));
      uniq
    };

    if id_sigs.len() != unique_ids.len() {
      return Err(VerificationError::DuplicateIds);
    }

    // verify the signatures in the receipt by indexing into the public keys in self.pk
    let res = (0..id_sigs.len()).try_for_each(|i| {
      let id = id_sigs[i].get_id();
      let sig = id_sigs[i].get_sig();
      if id < pk_vec.len() {
        let pk = &pk_vec[id];
        let res = sig.verify(pk, msg);
        if res.is_err() {
          Err(VerificationError::InvalidSignature)
        } else {
          Ok(())
        }
      } else {
        Err(VerificationError::IndexOutofBounds)
      }
    });

    if res.is_err() {
      Err(VerificationError::InvalidReceipt)
    } else {
      Ok(())
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

  pub fn genesis(
    pk_vec: &[PublicKey],
    service_nonce_bytes: &[u8],
    client_nonce_bytes: &[u8],
    app_bytes: &[u8],
  ) -> Result<Self, VerificationError> {
    let (nonce, client_nonce) = {
      let nonce_res = Nonce::new(service_nonce_bytes);
      let client_res = Nonce::new(client_nonce_bytes);
      if nonce_res.is_err() || client_res.is_err() {
        return Err(VerificationError::InvalidNonceSize);
      }
      (nonce_res.unwrap(), client_res.unwrap())
    };
    let pk_vec_bytes = (0..pk_vec.len())
      .map(|i| pk_vec[i].to_bytes().to_vec())
      .collect::<Vec<Vec<u8>>>();

    Ok(Block {
      block: concat(vec![
        nonce.get(),
        client_nonce.get(),
        vec![pk_vec.len() as u8],
        concat(pk_vec_bytes),
        app_bytes.to_vec(),
      ]),
    })
  }
}

/// `MetaBlock` has four entries: (i) a hash pointer to the view in the membership ledger,
/// (ii) hash of the previous metadata,
/// (iii) a hash of the current block, and (iv) a counter denoting the height
/// of the current block in the ledger
#[derive(Clone, Debug, Default)]
pub struct MetaBlock {
  view: NimbleDigest,
  prev: NimbleDigest,
  block_hash: NimbleDigest,
  height: usize,
}

impl MetaBlock {
  pub fn new(
    view: &NimbleDigest,
    prev: &NimbleDigest,
    block_hash: &NimbleDigest,
    height: usize,
  ) -> Self {
    MetaBlock {
      view: *view,
      prev: *prev,
      block_hash: *block_hash,
      height,
    }
  }

  pub fn genesis(view: &NimbleDigest, block_hash: &NimbleDigest) -> Self {
    // unwrap is okay here since it will not fail
    let prev = NimbleDigest::from_bytes(&vec![0u8; NimbleDigest::num_bytes()]).unwrap();
    let height = 0usize;
    MetaBlock {
      view: *view,
      prev,
      block_hash: *block_hash,
      height,
    }
  }

  pub fn get_height(&self) -> usize {
    self.height
  }

  pub fn get_prev(&self) -> &NimbleDigest {
    &self.prev
  }

  pub fn get_view(&self) -> &NimbleDigest {
    &self.view
  }
}

/// An `EndorsedMetaBlock` has two components: (1) a MetaBlock and (2) a set of signatures
#[derive(Clone, Debug, Default)]
pub struct EndorsedMetaBlock {
  metablock: MetaBlock,
  receipt: Receipt,
}

impl EndorsedMetaBlock {
  pub fn new(metablock: &MetaBlock, receipt: &Receipt) -> Self {
    EndorsedMetaBlock {
      metablock: metablock.clone(),
      receipt: receipt.clone(),
    }
  }

  pub fn get_metablock(&self) -> &MetaBlock {
    &self.metablock
  }

  pub fn get_receipt(&self) -> &Receipt {
    &self.receipt
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
    bytes.extend(&self.view.to_bytes());
    bytes.extend(&self.prev.to_bytes());
    bytes.extend(&self.block_hash.to_bytes());
    bytes.extend(&self.height.to_le_bytes().to_vec());
    bytes
  }

  fn from_bytes(bytes: Vec<u8>) -> Result<MetaBlock, CustomSerdeError> {
    let usize_len = 0usize.to_le_bytes().to_vec().len();
    let digest_len = NimbleDigest::num_bytes();

    if bytes.len() != 3 * digest_len + usize_len {
      Err(CustomSerdeError::IncorrectLength)
    } else {
      // unwrap is okay to call here given the error check above
      let view = NimbleDigest::from_bytes(&bytes[..digest_len]).unwrap();
      let prev = NimbleDigest::from_bytes(&bytes[digest_len..2 * digest_len]).unwrap();
      let block_hash = NimbleDigest::from_bytes(&bytes[2 * digest_len..3 * digest_len]).unwrap();
      let height = {
        let res = bytes[3 * digest_len..].try_into();
        if res.is_err() {
          return Err(CustomSerdeError::InternalError);
        }

        usize::from_le_bytes(res.unwrap())
      };

      Ok(MetaBlock {
        view,
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
    let duplicate_hash_bytes_1 = hash_bytes_1;
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
      "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b";
    let expected_hash_message_2_hex =
      "d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35";

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
      "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b";

    let expected_hash_message_1_op = hex::decode(expected_hash_message_1_hex);
    assert!(expected_hash_message_1_op.is_ok());

    let block_1 = Block::new(message_1);
    let block_1_hash = block_1.hash();

    assert_eq!(block_1_hash.to_bytes(), expected_hash_message_1_op.unwrap());
  }
}
