mod errors;
pub mod signature;
use crate::{
  errors::VerificationError,
  signature::{PublicKey, PublicKeyTrait, Signature, SignatureTrait},
};
use digest::Output;
use generic_array::{typenum::U32, GenericArray};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
  collections::{HashMap, HashSet},
  convert::TryInto,
};

/// A cryptographic digest
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq, Copy, Ord, PartialOrd)]
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

pub type LedgerTailMap = HashMap<NimbleDigest, MetaBlock>;

pub fn produce_hash_of_state(ledger_tail_map: &LedgerTailMap) -> NimbleDigest {
  // for empty state, hash is a vector of zeros
  if ledger_tail_map.is_empty() {
    NimbleDigest::default()
  } else {
    let mut serialized_state = Vec::new();
    for handle in ledger_tail_map.keys().sorted() {
      let metablock = ledger_tail_map.get(handle).unwrap();
      serialized_state.extend_from_slice(&handle.to_bytes());
      serialized_state.extend_from_slice(&metablock.hash().to_bytes());
      serialized_state.extend_from_slice(&metablock.get_height().to_le_bytes());
    }
    NimbleDigest::digest(&serialized_state)
  }
}

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

impl MetaBlock {
  pub fn new(prev: &NimbleDigest, block_hash: &NimbleDigest, height: usize) -> Self {
    MetaBlock {
      prev: *prev,
      block_hash: *block_hash,
      height,
    }
  }

  pub fn num_bytes() -> usize {
    NimbleDigest::num_bytes() * 2 + 0_u64.to_le_bytes().to_vec().len()
  }

  pub fn genesis(block_hash: &NimbleDigest) -> Self {
    MetaBlock {
      prev: NimbleDigest::default(),
      block_hash: *block_hash,
      height: 0usize,
    }
  }

  pub fn get_height(&self) -> usize {
    self.height
  }

  pub fn get_prev(&self) -> &NimbleDigest {
    &self.prev
  }

  pub fn get_block_hash(&self) -> &NimbleDigest {
    &self.block_hash
  }
}

#[derive(Debug, Clone)]
pub struct IdSig {
  id: PublicKey,
  sig: Signature,
}

impl IdSig {
  pub fn new(id: PublicKey, sig: Signature) -> Self {
    Self { id, sig }
  }

  pub fn get(&self) -> (&PublicKey, &Signature) {
    (&self.id, &self.sig)
  }

  pub fn get_id(&self) -> &PublicKey {
    &self.id
  }

  pub fn get_sig(&self) -> &Signature {
    &self.sig
  }

  pub fn num_bytes() -> usize {
    PublicKey::num_bytes() + Signature::num_bytes()
  }
}

#[derive(Debug, Clone, Default)]
pub struct Receipt {
  view: NimbleDigest,
  metablock: MetaBlock,
  id_sigs: Vec<IdSig>,
}

impl Receipt {
  pub fn new(view: NimbleDigest, metablock: MetaBlock, id_sigs: Vec<IdSig>) -> Self {
    Self {
      view,
      metablock,
      id_sigs,
    }
  }

  pub fn get_view(&self) -> &NimbleDigest {
    &self.view
  }

  pub fn get_prev(&self) -> &NimbleDigest {
    self.metablock.get_prev()
  }

  pub fn get_block_hash(&self) -> &NimbleDigest {
    self.metablock.get_block_hash()
  }

  pub fn get_height(&self) -> usize {
    self.metablock.get_height()
  }

  pub fn get_metablock_hash(&self) -> NimbleDigest {
    self.metablock.hash()
  }

  pub fn get_id_sigs(&self) -> &Vec<IdSig> {
    &self.id_sigs
  }

  pub fn get_metablock(&self) -> &MetaBlock {
    &self.metablock
  }

  fn extend_id_sigs(&mut self, id_sigs: &[IdSig]) {
    for new_id_sig in id_sigs {
      let id_sig = self.id_sigs.iter().find(|existing_id_sig| {
        existing_id_sig.get_id().to_bytes() == new_id_sig.get_id().to_bytes()
      });
      if id_sig.is_none() {
        self.id_sigs.push(new_id_sig.clone());
      }
    }
  }

  pub fn append(&mut self, receipt: &Receipt) -> Result<(), VerificationError> {
    if self.get_metablock_hash() == MetaBlock::default().hash() {
      assert!(self.id_sigs.is_empty());
      self.view = *receipt.get_view();
      self.metablock = receipt.get_metablock().clone();
      self.id_sigs = receipt.get_id_sigs().clone();
    } else if self.view == *receipt.get_view()
      && self.get_metablock_hash() == receipt.get_metablock_hash()
    {
      self.extend_id_sigs(receipt.get_id_sigs());
    } else {
      eprintln!("receipt1: {:?}", self);
      eprintln!("receipt2: {:?}", receipt);
      return Err(VerificationError::InvalidReceipt);
    }
    Ok(())
  }

  pub fn merge_receipts(receipts: &[Receipt]) -> Result<Receipt, VerificationError> {
    let mut new_receipt = Receipt::new(NimbleDigest::default(), MetaBlock::default(), Vec::new());

    for receipt in receipts.iter() {
      let res = new_receipt.append(receipt);
      res?
    }

    Ok(new_receipt)
  }

  pub fn verify(&self, msg: &[u8], pk_vec: &[PublicKey]) -> Result<(), VerificationError> {
    // check if the provided public keys in the receipt are unique
    let id_sigs = &self.id_sigs;

    let unique_ids = {
      let mut uniq = HashSet::new();
      (0..id_sigs.len())
        .map(|i| id_sigs[i].get_id().to_bytes().to_vec())
        .collect::<Vec<Vec<u8>>>()
        .into_iter()
        .all(|x| uniq.insert(x));
      uniq
    };

    if id_sigs.len() != unique_ids.len() {
      return Err(VerificationError::DuplicateIds);
    }

    let view_msg = self.get_view().digest_with_bytes(msg).to_bytes();
    let num_accepted_sigs = (0..id_sigs.len())
      .map(|i| {
        let id = id_sigs[i].get_id();
        let sig = id_sigs[i].get_sig();
        let pk = pk_vec.iter().find(|pk| pk.to_bytes() == id.to_bytes());
        if pk.is_none() {
          Err(VerificationError::InvalidPublicKey)
        } else if sig.verify(pk.unwrap(), &view_msg).is_err() {
          Err(VerificationError::InvalidSignature)
        } else {
          Ok(())
        }
      })
      .filter(|x| x.is_ok())
      .count();

    // check if we have the simple majority
    if num_accepted_sigs < pk_vec.len() / 2 + 1 {
      return Err(VerificationError::InsufficientQuorum);
    }

    Ok(())
  }

  pub fn verify_view_change(
    &self,
    msg: &[u8],
    pk_vec_existing: &[PublicKey],
    _pk_vec_proposed: &[PublicKey],
  ) -> Result<(), VerificationError> {
    // check if the provided public keys in the receipt are unique
    let unique_ids = {
      let mut uniq = HashSet::new();
      (0..self.id_sigs.len())
        .map(|i| self.id_sigs[i].get_id().to_bytes().to_vec())
        .collect::<Vec<Vec<u8>>>()
        .into_iter()
        .all(|x| uniq.insert(x));
      uniq
    };

    if self.id_sigs.len() != unique_ids.len() {
      return Err(VerificationError::DuplicateIds);
    }

    // we require a majority of endorsers in the latest view to have signed the provided message
    // we also require all new endorsers in the proposed latest view to have signed the provided metblock
    // (the latter check ensures that the new endorsers are initialized with the right state)

    let num_sigs_from_pk_vec_existing = (0..pk_vec_existing.len())
      .filter(|&i| {
        let id = pk_vec_existing[i].to_bytes();
        self.id_sigs.iter().any(|x| x.get_id().to_bytes() == id)
      })
      .count();

    // check if we have the simple majority
    if num_sigs_from_pk_vec_existing < pk_vec_existing.len() / 2 + 1 {
      return Err(VerificationError::InsufficientQuorum);
    }

    let view_msg = self.get_view().digest_with_bytes(msg).to_bytes();
    // verify the signatures in the receipt and ensure that the provided public keys are in pk_vec
    let res = (0..self.id_sigs.len()).try_for_each(|i| {
      let id = self.id_sigs[i].get_id();
      let sig = self.id_sigs[i].get_sig();
      let res = sig.verify(id, &view_msg);
      if res.is_err() {
        Err(VerificationError::InvalidSignature)
      } else {
        Ok(())
      }
    });

    if res.is_err() {
      Err(VerificationError::InvalidReceipt)
    } else {
      Ok(())
    }
  }
}

#[derive(Debug, Default, Clone)]
pub struct LedgerView {
  pub view_tail_metablock: MetaBlock,
  pub ledger_tail_map: LedgerTailMap,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndorserHostnames {
  pub pk_hostnames: Vec<(Vec<u8>, String)>,
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
  fn from_bytes(bytes: &[u8]) -> Result<Self, CustomSerdeError>;
}

impl CustomSerde for Block {
  fn to_bytes(&self) -> Vec<u8> {
    self.block.clone()
  }

  fn from_bytes(bytes: &[u8]) -> Result<Block, CustomSerdeError> {
    Ok(Block {
      block: bytes.to_vec(),
    })
  }
}

impl CustomSerde for NimbleDigest {
  fn to_bytes(&self) -> Vec<u8> {
    self.digest.as_slice().to_vec()
  }

  fn from_bytes(bytes: &[u8]) -> Result<NimbleDigest, CustomSerdeError> {
    let digest_len = NimbleDigest::num_bytes();
    if bytes.len() != digest_len {
      Err(CustomSerdeError::IncorrectLength)
    } else {
      let digest = GenericArray::<u8, U32>::from_slice(&bytes[0..digest_len]);
      Ok(NimbleDigest { digest: *digest })
    }
  }
}

impl CustomSerde for MetaBlock {
  fn to_bytes(&self) -> Vec<u8> {
    let mut bytes = Vec::new();
    let height_u64 = self.height as u64;
    bytes.extend(&self.prev.to_bytes());
    bytes.extend(&self.block_hash.to_bytes());
    bytes.extend(&height_u64.to_le_bytes().to_vec());
    bytes
  }

  fn from_bytes(bytes: &[u8]) -> Result<MetaBlock, CustomSerdeError> {
    let digest_len = NimbleDigest::num_bytes();

    if bytes.len() != MetaBlock::num_bytes() {
      eprintln!(
        "bytes len={} but MetaBlock expects {}",
        bytes.len(),
        MetaBlock::num_bytes()
      );
      Err(CustomSerdeError::IncorrectLength)
    } else {
      let prev = NimbleDigest::from_bytes(&bytes[0..digest_len])?;
      let block_hash = NimbleDigest::from_bytes(&bytes[digest_len..2 * digest_len])?;
      let height = u64::from_le_bytes(
        bytes[2 * digest_len..]
          .try_into()
          .map_err(|_| CustomSerdeError::IncorrectLength)?,
      ) as usize;
      Ok(MetaBlock {
        prev,
        block_hash,
        height,
      })
    }
  }
}

impl CustomSerde for IdSig {
  fn to_bytes(&self) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend(&self.id.to_bytes());
    bytes.extend(&self.sig.to_bytes());
    bytes
  }

  fn from_bytes(bytes: &[u8]) -> Result<IdSig, CustomSerdeError> {
    if bytes.len() != IdSig::num_bytes() {
      eprintln!(
        "bytes len={} but IdSig expects {}",
        bytes.len(),
        IdSig::num_bytes()
      );
      return Err(CustomSerdeError::IncorrectLength);
    }
    let id = PublicKey::from_bytes(&bytes[0..PublicKey::num_bytes()])
      .map_err(|_| CustomSerdeError::InternalError)?;
    let sig = Signature::from_bytes(&bytes[PublicKey::num_bytes()..])
      .map_err(|_| CustomSerdeError::InternalError)?;

    Ok(IdSig { id, sig })
  }
}

impl CustomSerde for Receipt {
  fn to_bytes(&self) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend(&self.view.to_bytes());
    bytes.extend(&self.metablock.to_bytes());
    for id_sig in &self.id_sigs {
      bytes.extend(&id_sig.to_bytes());
    }
    bytes
  }

  fn from_bytes(bytes: &[u8]) -> Result<Receipt, CustomSerdeError> {
    if bytes.len() < NimbleDigest::num_bytes() + MetaBlock::num_bytes() {
      eprintln!("bytes len {} is too short", bytes.len());
      return Err(CustomSerdeError::IncorrectLength);
    }

    if (bytes.len() - NimbleDigest::num_bytes() - MetaBlock::num_bytes()) % IdSig::num_bytes() != 0
    {
      eprintln!("bytes len {} is not a multiple of IdSig", bytes.len());
      return Err(CustomSerdeError::IncorrectLength);
    }

    let view = NimbleDigest::from_bytes(&bytes[0..NimbleDigest::num_bytes()])?;
    let metablock = MetaBlock::from_bytes(
      &bytes[NimbleDigest::num_bytes()..NimbleDigest::num_bytes() + MetaBlock::num_bytes()],
    )?;
    let mut id_sigs = Vec::new();
    let mut pos = NimbleDigest::num_bytes() + MetaBlock::num_bytes();
    while pos < bytes.len() {
      let id_sig = IdSig::from_bytes(&bytes[pos..pos + IdSig::num_bytes()])?;
      id_sigs.push(id_sig);
      pos += IdSig::num_bytes();
    }

    Ok(Receipt {
      view,
      metablock,
      id_sigs,
    })
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
