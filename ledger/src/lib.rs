pub mod errors;
pub mod signature;
use crate::signature::{PublicKey, PublicKeyTrait, Signature, SignatureTrait};
use digest::Output;
use errors::VerificationError;
use generic_array::{typenum::U32, GenericArray};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
  collections::{hash_map, HashMap, HashSet},
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
    if bytes.is_empty() {
      NimbleDigest::default()
    } else {
      NimbleDigest {
        digest: Sha256::digest(bytes),
      }
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
#[derive(Clone, Debug, Copy, Default, PartialEq, Eq)]
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

  pub fn num_bytes() -> usize {
    16
  }
}

#[derive(Clone, Debug, Default)]
pub struct Nonces {
  nonces: Vec<Nonce>,
}

impl Nonces {
  pub fn new() -> Self {
    Nonces { nonces: Vec::new() }
  }

  pub fn from_vec(nonces: Vec<Nonce>) -> Self {
    Nonces { nonces }
  }

  pub fn get(&self) -> &Vec<Nonce> {
    &self.nonces
  }

  pub fn add(&mut self, nonce: Nonce) {
    self.nonces.push(nonce)
  }

  pub fn contains(&self, nonce: &Nonce) -> bool {
    self.nonces.iter().any(|nonce_iter| *nonce_iter == *nonce)
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
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
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

#[derive(Hash, Eq, PartialEq, Debug, Clone)]
pub struct ExtendedMetaBlock {
  view: NimbleDigest,
  metablock: MetaBlock,
}

impl ExtendedMetaBlock {
  pub fn new(view: &NimbleDigest, metablock: &MetaBlock) -> Self {
    Self {
      view: *view,
      metablock: metablock.clone(),
    }
  }

  pub fn get_view(&self) -> &NimbleDigest {
    &self.view
  }

  pub fn get_metablock(&self) -> &MetaBlock {
    &self.metablock
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

#[derive(Debug, Clone)]
pub struct Receipt {
  view: NimbleDigest,
  metablock: MetaBlock,
  id_sig: IdSig,
}

impl Receipt {
  pub fn new(view: NimbleDigest, metablock: MetaBlock, id_sig: IdSig) -> Self {
    Self {
      view,
      metablock,
      id_sig,
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

  pub fn get_id_sig(&self) -> &IdSig {
    &self.id_sig
  }

  pub fn get_metablock(&self) -> &MetaBlock {
    &self.metablock
  }

  pub fn num_bytes() -> usize {
    NimbleDigest::num_bytes() + MetaBlock::num_bytes() + IdSig::num_bytes()
  }
}

const MIN_NUM_ENDORSERS: usize = 1;

pub fn compute_aggregated_block_hash(
  hash_block_bytes: &[u8],
  hash_nonces_bytes: &[u8],
) -> NimbleDigest {
  NimbleDigest::digest(hash_block_bytes).digest_with_bytes(hash_nonces_bytes)
}

#[derive(Debug, Clone, Default)]
pub struct Receipts {
  receipts: HashMap<ExtendedMetaBlock, Vec<IdSig>>,
}

impl Receipts {
  pub fn new() -> Self {
    Receipts {
      receipts: HashMap::new(),
    }
  }

  pub fn get(&self) -> &HashMap<ExtendedMetaBlock, Vec<IdSig>> {
    &self.receipts
  }

  pub fn add(&mut self, receipt: &Receipt) {
    let ex_meta_block = ExtendedMetaBlock::new(receipt.get_view(), receipt.get_metablock());
    if let hash_map::Entry::Occupied(mut e) = self.receipts.entry(ex_meta_block.clone()) {
      let new_id_sig = receipt.get_id_sig();
      let id_sig = e.get().iter().find(|existing_id_sig| {
        existing_id_sig.get_id().to_bytes() == new_id_sig.get_id().to_bytes()
      });
      if id_sig.is_none() {
        e.get_mut().push(receipt.get_id_sig().clone());
      }
    } else {
      self
        .receipts
        .insert(ex_meta_block, vec![receipt.get_id_sig().clone()]);
    }
  }

  pub fn merge_receipts(&mut self, receipts: &Receipts) {
    for (ex_meta_block, id_sigs) in receipts.get() {
      for id_sig in id_sigs {
        let receipt = Receipt::new(
          *ex_meta_block.get_view(),
          ex_meta_block.get_metablock().clone(),
          id_sig.clone(),
        );
        self.add(&receipt);
      }
    }
  }

  pub fn check_quorum(&self, verifier_state: &VerifierState) -> Result<usize, VerificationError> {
    for (ex_meta_block, id_sigs) in &self.receipts {
      let view = ex_meta_block.get_view();
      let pks = verifier_state.get_pks_for_view(view)?;
      if id_sigs.len() < pks.len() / 2 + 1 {
        continue;
      }

      let mut num_receipts = 0;
      for id_sig in id_sigs {
        let id = id_sig.get_id();
        if pks.contains(&id.to_bytes()) {
          num_receipts += 1;
        }
      }

      if num_receipts > pks.len() / 2 {
        return Ok(ex_meta_block.get_metablock().get_height());
      }
    }

    Err(VerificationError::InsufficientReceipts)
  }

  pub fn verify_read_latest(
    &self,
    verifier_state: &VerifierState,
    handle_bytes: &[u8],
    block_bytes: &[u8],
    nonces_bytes: &[u8],
    nonce_bytes: &[u8],
  ) -> Result<usize, VerificationError> {
    let hash_nonces = NimbleDigest::digest(nonces_bytes);

    let res = self.verify(
      verifier_state,
      handle_bytes,
      block_bytes,
      &hash_nonces.to_bytes(),
      None,
      Some(nonce_bytes),
    );
    if let Ok(h) = res {
      return Ok(h);
    }

    let height = self.verify(
      verifier_state,
      handle_bytes,
      block_bytes,
      &hash_nonces.to_bytes(),
      None,
      None,
    )?;

    // verify if the nonce is in the nonces
    let nonces = Nonces::from_bytes(nonces_bytes).map_err(|_e| VerificationError::InvalidNonces)?;
    let nonce = Nonce::from_bytes(nonce_bytes).map_err(|_e| VerificationError::InvalidNonce)?;
    if nonces.contains(&nonce) {
      Ok(height)
    } else {
      Err(VerificationError::InvalidReceipt)
    }
  }

  pub fn verify(
    &self,
    verifier_state: &VerifierState,
    handle_bytes: &[u8],
    block_bytes: &[u8],
    hash_nonces_bytes: &[u8],
    expected_height: Option<usize>,
    nonce_bytes: Option<&[u8]>,
  ) -> Result<usize, VerificationError> {
    let block_hash = compute_aggregated_block_hash(
      &NimbleDigest::digest(block_bytes).to_bytes(),
      hash_nonces_bytes,
    );

    for (ex_meta_block, id_sigs) in &self.receipts {
      let pks = verifier_state.get_pks_for_view(ex_meta_block.get_view())?;
      if id_sigs.len() < pks.len() / 2 + 1 {
        continue;
      }

      // check the block hash matches with the block
      if block_hash != *ex_meta_block.get_metablock().get_block_hash() {
        return Err(VerificationError::InvalidBlockHash);
      }
      // check the height matches with the expected height
      if let Some(h) = expected_height {
        if h != ex_meta_block.get_metablock().get_height() {
          return Err(VerificationError::InvalidHeight);
        }
      }
      // update the message
      let tail_hash = match nonce_bytes {
        Some(n) => ex_meta_block.get_metablock().hash().digest_with_bytes(n),
        None => ex_meta_block.get_metablock().hash(),
      };
      let message = ex_meta_block
        .get_view()
        .digest_with(&NimbleDigest::digest(handle_bytes).digest_with(&tail_hash));

      let mut num_receipts = 0;
      for id_sig in id_sigs {
        let id = id_sig.get_id();
        id_sig
          .get_sig()
          .verify(id, &message.to_bytes())
          .map_err(|_e| VerificationError::InvalidSignature)?;
        if pks.contains(&id.to_bytes()) {
          num_receipts += 1;
        }
      }

      if num_receipts > pks.len() / 2 {
        return Ok(ex_meta_block.get_metablock().get_height());
      }
    }

    Err(VerificationError::InvalidReceipt)
  }

  pub fn verify_view_change(
    &self,
    verifier_state: &VerifierState,
    block_bytes: &[u8],
  ) -> Result<(NimbleDigest, HashSet<Vec<u8>>), VerificationError> {
    // retrieve public keys of endorsers in the new configuration
    let endorsers: EndorserHostnames = bincode::deserialize(block_bytes).map_err(|e| {
      eprintln!("Failed to deserialize the view genesis block {:?}", e);
      VerificationError::InvalidGenesisBlock
    })?;
    let mut new_pk_vec = Vec::new();
    for idx in 0..endorsers.pk_hostnames.len() {
      let pk = PublicKey::from_bytes(&endorsers.pk_hostnames[idx].0)
        .map_err(|_e| VerificationError::InvalidPublicKey)?;
      new_pk_vec.push(pk.to_bytes());
    }

    let new_pks = new_pk_vec.iter().cloned().collect::<HashSet<_>>();

    // check that the public keys are unique and there are at least `MIN_NUM_ENDORSERS`
    if new_pk_vec.len() != new_pks.len() || new_pk_vec.len() < MIN_NUM_ENDORSERS {}

    // retrieve public keys of endorsers in current view
    let current_pks = verifier_state.get_current_pks();
    assert!(current_pks.len() >= MIN_NUM_ENDORSERS || verifier_state.get_view_ledger_height() == 0);

    let mut num_receipts_for_current_pks = 0;
    let mut num_receipts_for_new_pks = 0;
    let current_view = verifier_state.get_current_view();
    let mut new_view = NimbleDigest::default();

    for (ex_meta_block, id_sigs) in &self.receipts {
      let metablock_hash = ex_meta_block.get_metablock().hash();
      // check the block hash matches with the block
      if NimbleDigest::digest(block_bytes) != *ex_meta_block.get_metablock().get_block_hash() {
        return Err(VerificationError::InvalidBlockHash);
      }
      if *current_view != NimbleDigest::default()
        && *current_view != *ex_meta_block.get_metablock().get_prev()
      {
        return Err(VerificationError::InvalidView);
      }
      let message = ex_meta_block.get_view().digest_with(&metablock_hash);

      if new_view == NimbleDigest::default() {
        new_view = metablock_hash;
      } else if new_view != metablock_hash {
        return Err(VerificationError::InvalidViewChangeReceipt);
      }

      for id_sig in id_sigs {
        let id = id_sig.get_id();
        id_sig
          .get_sig()
          .verify(id, &message.to_bytes())
          .map_err(|_e| VerificationError::InvalidSignature)?;
        if new_pks.contains(&id.to_bytes()) {
          num_receipts_for_new_pks += 1;
        }
        if current_pks.contains(&id.to_bytes()) {
          num_receipts_for_current_pks += 1;
        }
      }
    }

    if verifier_state.get_view_ledger_height() > 0
      && num_receipts_for_current_pks < current_pks.len() / 2 + 1
    {
      return Err(VerificationError::InsufficientReceipts);
    }

    if num_receipts_for_new_pks < new_pks.len() / 2 + 1 {
      return Err(VerificationError::InsufficientReceipts);
    }

    Ok((new_view, new_pks))
  }
}

/// VerifierState keeps track of public keys of any valid view
#[derive(Debug, Default)]
pub struct VerifierState {
  // The state is a hashmap from the view (a NimbleDigest) to a list of public keys
  // In our context, we don't need views to be ordered, so we use a HashMap
  // However, we require that a new view is "authorized" by the latest view, so we keep track of the latest_view in a separate variable
  vk_map: HashMap<NimbleDigest, HashSet<Vec<u8>>>,
  current_view: NimbleDigest,    // latest view
  current_pks: HashSet<Vec<u8>>, // pk vec in the latest view
}

impl VerifierState {
  pub fn new() -> Self {
    VerifierState {
      vk_map: HashMap::new(),
      current_view: NimbleDigest::default(),
      current_pks: HashSet::new(),
    }
  }

  pub fn get_view_ledger_height(&self) -> usize {
    self.vk_map.len()
  }

  pub fn get_current_pks(&self) -> &HashSet<Vec<u8>> {
    &self.current_pks
  }

  pub fn get_current_view(&self) -> &NimbleDigest {
    &self.current_view
  }

  pub fn get_pks_for_view(
    &self,
    view: &NimbleDigest,
  ) -> Result<&HashSet<Vec<u8>>, VerificationError> {
    let res = self.vk_map.get(view);
    match res {
      Some(pks) => Ok(pks),
      None => Err(VerificationError::ViewNotFound),
    }
  }

  pub fn apply_view_change(
    &mut self,
    block_bytes: &[u8],
    receipts_bytes: &[u8],
  ) -> Result<(), VerificationError> {
    let receipts =
      Receipts::from_bytes(receipts_bytes).map_err(|_e| VerificationError::InvalidReceipt)?;
    let res = receipts.verify_view_change(self, block_bytes);
    match res {
      Ok((new_view, new_pks)) => {
        self.vk_map.insert(new_view, new_pks.clone());
        self.current_pks = new_pks;
        self.current_view = new_view;
        Ok(())
      },
      Err(error) => Err(error),
    }
  }

  pub fn verify_new_ledger(
    &self,
    handle_bytes: &[u8],
    block_bytes: &[u8],
    receipts_bytes: &[u8],
  ) -> Result<(), VerificationError> {
    let receipts =
      Receipts::from_bytes(receipts_bytes).map_err(|_e| VerificationError::InvalidReceipt)?;
    let res = receipts.verify(
      self,
      handle_bytes,
      block_bytes,
      &NimbleDigest::default().to_bytes(),
      Some(0),
      None,
    );
    match res {
      Ok(_h) => Ok(()),
      Err(e) => Err(e),
    }
  }

  pub fn verify_append(
    &self,
    handle_bytes: &[u8],
    block_bytes: &[u8],
    hash_nonces_bytes: &[u8],
    expected_height: usize,
    receipts_bytes: &[u8],
  ) -> Result<(), VerificationError> {
    let receipts =
      Receipts::from_bytes(receipts_bytes).map_err(|_e| VerificationError::InvalidReceipt)?;
    let res = receipts.verify(
      self,
      handle_bytes,
      block_bytes,
      hash_nonces_bytes,
      Some(expected_height),
      None,
    );
    match res {
      Ok(_h) => Ok(()),
      Err(e) => Err(e),
    }
  }

  pub fn verify_read_latest(
    &self,
    handle_bytes: &[u8],
    block_bytes: &[u8],
    nonces_bytes: &[u8],
    nonce_bytes: &[u8],
    receipts_bytes: &[u8],
  ) -> Result<usize, VerificationError> {
    let receipts =
      Receipts::from_bytes(receipts_bytes).map_err(|_e| VerificationError::InvalidReceipt)?;
    receipts.verify_read_latest(self, handle_bytes, block_bytes, nonces_bytes, nonce_bytes)
  }

  pub fn verify_read_by_index(
    &self,
    handle_bytes: &[u8],
    block_bytes: &[u8],
    nonces_bytes: &[u8],
    idx: usize,
    receipts_bytes: &[u8],
  ) -> Result<(), VerificationError> {
    let receipts =
      Receipts::from_bytes(receipts_bytes).map_err(|_e| VerificationError::InvalidReceipt)?;
    let hash_nonces_bytes = NimbleDigest::digest(nonces_bytes).to_bytes();
    let res = receipts.verify(
      self,
      handle_bytes,
      block_bytes,
      &hash_nonces_bytes,
      Some(idx),
      None,
    );
    match res {
      Ok(_h) => Ok(()),
      Err(e) => Err(e),
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

impl CustomSerde for Nonce {
  fn to_bytes(&self) -> Vec<u8> {
    self.data.to_vec()
  }

  fn from_bytes(bytes: &[u8]) -> Result<Nonce, CustomSerdeError> {
    match Nonce::new(bytes) {
      Ok(nonce) => Ok(nonce),
      Err(_) => Err(CustomSerdeError::IncorrectLength),
    }
  }
}
impl CustomSerde for Nonces {
  fn to_bytes(&self) -> Vec<u8> {
    let mut data = Vec::with_capacity(self.nonces.len() * Nonce::num_bytes());
    for nonce in self.get() {
      data.extend(nonce.to_bytes());
    }
    data
  }

  fn from_bytes(bytes: &[u8]) -> Result<Nonces, CustomSerdeError> {
    if bytes.len() % Nonce::num_bytes() != 0 {
      Err(CustomSerdeError::IncorrectLength)
    } else {
      let mut nonces = Nonces::new();
      let mut pos = 0;
      while pos < bytes.len() {
        let nonce = Nonce::from_bytes(&bytes[pos..pos + Nonce::num_bytes()])?;
        nonces.add(nonce);
        pos += Nonce::num_bytes();
      }
      Ok(nonces)
    }
  }
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
    bytes.extend(&self.id_sig.to_bytes());
    bytes
  }

  fn from_bytes(bytes: &[u8]) -> Result<Receipt, CustomSerdeError> {
    if bytes.len() != Receipt::num_bytes() {
      eprintln!("bytes len {} is incorrect for receipt", bytes.len());
      return Err(CustomSerdeError::IncorrectLength);
    }

    let view = NimbleDigest::from_bytes(&bytes[0..NimbleDigest::num_bytes()])?;
    let metablock = MetaBlock::from_bytes(
      &bytes[NimbleDigest::num_bytes()..NimbleDigest::num_bytes() + MetaBlock::num_bytes()],
    )?;
    let id_sig = IdSig::from_bytes(
      &bytes[NimbleDigest::num_bytes() + MetaBlock::num_bytes()
        ..NimbleDigest::num_bytes() + MetaBlock::num_bytes() + IdSig::num_bytes()],
    )?;

    Ok(Receipt {
      view,
      metablock,
      id_sig,
    })
  }
}

impl CustomSerde for Receipts {
  fn to_bytes(&self) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (ex_meta_block, id_sigs) in &self.receipts {
      for id_sig in id_sigs {
        bytes.extend(
          Receipt::new(
            *ex_meta_block.get_view(),
            ex_meta_block.get_metablock().clone(),
            id_sig.clone(),
          )
          .to_bytes(),
        );
      }
    }
    bytes
  }

  fn from_bytes(bytes: &[u8]) -> Result<Receipts, CustomSerdeError> {
    if bytes.len() % Receipt::num_bytes() != 0 {
      return Err(CustomSerdeError::IncorrectLength);
    }
    let mut pos = 0;
    let mut receipts = Receipts::new();
    while pos < bytes.len() {
      let receipt = Receipt::from_bytes(&bytes[pos..pos + Receipt::num_bytes()])?;
      receipts.add(&receipt);
      pos += Receipt::num_bytes();
    }
    Ok(receipts)
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

impl NimbleHashTrait for Nonces {
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
