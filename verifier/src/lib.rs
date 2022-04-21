pub mod errors;

use crate::errors::VerificationError;
use ledger::{
  signature::{PublicKey, PublicKeyTrait},
  Block, CustomSerde, EndorserHostnames, MetaBlock, NimbleDigest, NimbleHashTrait, Receipt,
};
use std::collections::{HashMap, HashSet};

const MIN_NUM_ENDORSERS: usize = 1;

/// VerifierState keeps track of public keys of any valid view
#[derive(Debug, Default)]
pub struct VerifierState {
  // The state is a hashmap from the view (a NimbleDigest) to a list of public keys
  // In our context, we don't need views to be ordered, so we use a HashMap
  // However, we require that a new view is "authorized" by the latest view, so we keep track of the latest_view in a separate variable
  vk_map: HashMap<NimbleDigest, Vec<PublicKey>>,
  latest_view: NimbleDigest, // the latest view in vk_map (helps with verifying the addition of new entries to `vk_map`)
}

impl VerifierState {
  pub fn new() -> Self {
    VerifierState::default()
  }

  pub fn get_view_ledger_height(&self) -> usize {
    self.vk_map.len()
  }

  /// Allows obtaining the list of public keys of endorsers for a given view
  pub fn get_pk_for_view(&self, view: &NimbleDigest) -> Result<&Vec<PublicKey>, VerificationError> {
    let res = self.vk_map.get(view);
    match res {
      Some(pks) => Ok(pks),
      None => Err(VerificationError::ViewNotFound),
    }
  }

  pub fn apply_view_change(
    &mut self,
    block_bytes: &[u8],
    receipt_bytes: &[u8],
  ) -> Result<(), VerificationError> {
    // parse the block to obtain the full list of the public keys for the proposed latest view
    let endorsers: EndorserHostnames = bincode::deserialize(block_bytes).map_err(|e| {
      eprintln!("Failed to deserialize the view genesis block {:?}", e);
      VerificationError::InvalidGenesisBlock
    })?;
    let mut pk_vec_for_proposed_latest_view = Vec::new();
    for idx in 0..endorsers.pk_hostnames.len() {
      pk_vec_for_proposed_latest_view
        .push(PublicKey::from_bytes(&endorsers.pk_hostnames[idx].0).unwrap());
    }

    // check that the public keys are unique and there are at least `MIN_NUM_ENDORSERS`
    if pk_vec_for_proposed_latest_view.len()
      != pk_vec_for_proposed_latest_view
        .iter()
        .map(|pk| pk.to_bytes())
        .collect::<HashSet<_>>()
        .len()
      || pk_vec_for_proposed_latest_view.len() < MIN_NUM_ENDORSERS
    {
      return Err(VerificationError::DuplicateIds);
    }

    let receipt =
      Receipt::from_bytes(receipt_bytes).map_err(|_e| VerificationError::InvalidReceipt)?;

    // check if this is the first view change
    if self.latest_view == NimbleDigest::default() {
      // check that the metablock is well formed
      if receipt.get_prev() != &MetaBlock::default().hash() {
        eprintln!("prev is not default: prev = {:?}", receipt.get_prev());
        return Err(VerificationError::InvalidView);
      }

      if receipt.get_height() != 1 {
        eprintln!("height is not 1");
        return Err(VerificationError::InvalidView);
      }

      // check if the provided view ledger entry has the correct view
      if receipt.get_view() != &NimbleDigest::default() {
        eprintln!("view is not default");
        return Err(VerificationError::InvalidView);
      }

      let res = receipt.verify(
        &receipt.get_metablock_hash().to_bytes(),
        &pk_vec_for_proposed_latest_view,
      );
      if res.is_err() {
        return Err(VerificationError::InvalidViewChangeReceipt);
      }
    } else {
      // check that metablock points to the latest view (i.e., the `prev` pointer must equal `self.latest_view`)
      if receipt.get_prev() != &self.latest_view {
        return Err(VerificationError::ViewInMetaBlockNotLatest);
      }

      // obtain the list of public keys of the latest view
      let pk_vec_for_latest_view = self.get_pk_for_view(&self.latest_view)?;

      // we require a majority of endorsers in the latest view to have signed the provided metablock
      // we also require all new endorsers in the proposed latest view to have signed the provided metblock
      // (the latter check ensures that the new endorsers are initialized with the right state)
      let res = receipt.verify_view_change(
        &receipt.get_metablock_hash().to_bytes(),
        pk_vec_for_latest_view,
        &pk_vec_for_proposed_latest_view,
      );
      if res.is_err() {
        return Err(VerificationError::InvalidViewChangeReceipt);
      }
    }

    // declare the view represented by metablock as valid and update the latest view
    self.latest_view = receipt.get_metablock_hash();
    self
      .vk_map
      .insert(self.latest_view, pk_vec_for_proposed_latest_view);

    Ok(())
  }
}

///
/// The parameters of the VerifyNewLedger() are:
/// 1. The Block Data
/// 2. A receipt
/// 3. A nonce
pub fn verify_new_ledger(
  vs: &VerifierState,
  handle_bytes: &[u8],
  block_bytes: &[u8],
  receipt_bytes: &[u8],
) -> Result<(), VerificationError> {
  let receipt =
    Receipt::from_bytes(receipt_bytes).map_err(|_e| VerificationError::InvalidReceipt)?;

  if receipt.get_id_sigs().len() < MIN_NUM_ENDORSERS {
    return Err(VerificationError::InsufficientReceipts);
  }

  let pk_vec = vs.get_pk_for_view(receipt.get_view())?;
  let message = {
    let genesis_metablock = MetaBlock::genesis(&NimbleDigest::digest(block_bytes));
    NimbleDigest::digest(handle_bytes)
      .digest_with(&genesis_metablock.hash())
      .to_bytes()
  };

  let res = receipt.verify(&message, pk_vec);

  if res.is_err() {
    eprintln!("receipt verification failed: {:?}", res);
    Err(VerificationError::InvalidGenesisBlock)
  } else {
    Ok(())
  }
}

pub fn verify_read_latest(
  vs: &VerifierState,
  handle_bytes: &[u8],
  block_bytes: &[u8],
  nonce_bytes: &[u8],
  receipt_bytes: &[u8],
) -> Result<usize, VerificationError> {
  let receipt =
    Receipt::from_bytes(receipt_bytes).map_err(|_e| VerificationError::InvalidReceipt)?;

  if receipt.get_id_sigs().len() < MIN_NUM_ENDORSERS {
    return Err(VerificationError::InsufficientReceipts);
  }

  let pk_vec = vs.get_pk_for_view(receipt.get_view())?;

  let block_hash = Block::from_bytes(block_bytes).unwrap().hash();
  if block_hash != *receipt.get_block_hash() {
    return Err(VerificationError::InvalidBlockHash);
  }

  let tail_hash_prime = receipt.get_metablock_hash();
  let hash_nonced_tail_hash_prime =
    NimbleDigest::digest(&([tail_hash_prime.to_bytes(), nonce_bytes.to_vec()]).concat());
  let message = NimbleDigest::digest(handle_bytes).digest_with(&hash_nonced_tail_hash_prime);

  // verify the receipt against the nonced tail hash
  receipt.verify(&message.to_bytes(), pk_vec).map_err(|e| {
    eprintln!("receipt verify: {:?}", e);
    VerificationError::InvalidReceipt
  })?;

  Ok(receipt.get_height())
}

pub fn verify_read_by_index(
  vs: &VerifierState,
  handle_bytes: &[u8],
  block_bytes: &[u8],
  idx: usize,
  receipt_bytes: &[u8],
) -> Result<(), VerificationError> {
  let receipt =
    Receipt::from_bytes(receipt_bytes).map_err(|_e| VerificationError::InvalidReceipt)?;

  if receipt.get_id_sigs().len() < MIN_NUM_ENDORSERS {
    return Err(VerificationError::InsufficientReceipts);
  }

  if receipt.get_height() != idx {
    return Err(VerificationError::InvalidReceipt);
  }

  let pk_vec = vs.get_pk_for_view(receipt.get_view())?;

  let block_hash = Block::from_bytes(block_bytes).unwrap().hash();
  if block_hash != *receipt.get_block_hash() {
    return Err(VerificationError::InvalidBlockHash);
  }

  let message = {
    let tail_hash_prime = receipt.get_metablock_hash();
    NimbleDigest::digest(handle_bytes).digest_with(&tail_hash_prime)
  };

  let res = receipt.verify(&message.to_bytes(), pk_vec);
  if res.is_err() {
    Err(VerificationError::InvalidReceipt)
  } else {
    Ok(())
  }
}

pub fn verify_append(
  vs: &VerifierState,
  handle_bytes: &[u8],
  block_bytes: &[u8],
  expected_height: usize,
  receipt_bytes: &[u8],
) -> Result<usize, VerificationError> {
  let receipt =
    Receipt::from_bytes(receipt_bytes).map_err(|_e| VerificationError::InvalidReceipt)?;

  if receipt.get_id_sigs().len() < MIN_NUM_ENDORSERS {
    return Err(VerificationError::InsufficientReceipts);
  }

  let pk_vec = vs.get_pk_for_view(receipt.get_view())?;

  let block_hash = Block::from_bytes(block_bytes).unwrap().hash();
  if block_hash != *receipt.get_block_hash() {
    eprintln!(
      "original_block_hash={:?}, receipt_block_hash={:?}",
      block_hash,
      receipt.get_block_hash()
    );
    return Err(VerificationError::InvalidBlockHash);
  }

  if expected_height != 0 && expected_height != receipt.get_height() {
    return Err(VerificationError::InvalidHeight);
  }

  let message = {
    let tail_hash_prime = receipt.get_metablock_hash();
    NimbleDigest::digest(handle_bytes).digest_with(&tail_hash_prime)
  };
  let res = receipt.verify(&message.to_bytes(), pk_vec);

  if res.is_err() {
    Err(VerificationError::InvalidReceipt)
  } else {
    Ok(receipt.get_height())
  }
}
