mod errors;

use crate::errors::VerificationError;
use ledger::{
  produce_hash_of_state,
  signature::{CryptoError, PublicKey, PublicKeyTrait},
  Block, IdSigBytes, LedgerView, MetaBlock, NimbleDigest, NimbleHashTrait, Receipt,
  ViewChangeReceipt,
};
use std::collections::{HashMap, HashSet};

const NONCE_IN_BYTES: usize = 16;
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
    prev_bytes: &[u8],
    height: usize,
    receipt_bytes: &(Vec<u8>, IdSigBytes),
  ) -> Result<(), VerificationError> {
    // parse the block to obtain the full list of the public keys for the proposed latest view
    let pk_vec_for_proposed_latest_view = {
      let pk_in_bytes = PublicKey::num_bytes();
      let pk_vec_bytes = block_bytes;

      // check that there is at least one public key
      if pk_vec_bytes.len() < pk_in_bytes || pk_vec_bytes.len() % pk_in_bytes != 0 {
        Err(VerificationError::IncorrectLength)
      } else {
        // parse the public keys into a vector collecting an error if parsing fails
        let res = (0..pk_vec_bytes.len() / pk_in_bytes)
          .map(|i| PublicKey::from_bytes(&pk_vec_bytes[i * pk_in_bytes..(i + 1) * pk_in_bytes]))
          .collect::<Result<Vec<PublicKey>, CryptoError>>();

        if let Ok(pk_vec) = res {
          // check that the public keys are unique and there are at least `MIN_NUM_ENDORSERS`
          if pk_vec.len()
            != pk_vec
              .iter()
              .map(|pk| pk.to_bytes())
              .collect::<HashSet<_>>()
              .len()
            || pk_vec.len() < MIN_NUM_ENDORSERS
          {
            Err(VerificationError::DuplicateIds)
          } else {
            Ok(pk_vec)
          }
        } else {
          Err(VerificationError::InvalidGenesisBlock)
        }
      }
    }?;

    let metablock = {
      let prev = {
        let res = NimbleDigest::from_bytes(prev_bytes);
        if res.is_err() {
          return Err(VerificationError::InvalidView);
        }
        res.unwrap()
      };
      let block_hash = Block::new(block_bytes).hash();

      MetaBlock::new(&prev, &block_hash, height)
    };

    // check if this is the first view change
    if self.latest_view == NimbleDigest::default() {
      // check that the metablock is well formed
      if metablock.get_prev() != &NimbleDigest::default() || metablock.get_height() != 1 {
        return Err(VerificationError::InvalidView);
      }

      let receipt = Receipt::from_bytes(receipt_bytes);

      // check if the provided view ledger entry has the correct view
      if receipt.get_view() != &NimbleDigest::default() {
        return Err(VerificationError::InvalidView);
      }

      let res = receipt.verify(
        &metablock.hash().to_bytes(),
        &pk_vec_for_proposed_latest_view,
      );
      if res.is_err() {
        return Err(VerificationError::InvalidViewChangeReceipt);
      }
    } else {
      // check that metablock points to the latest view (i.e., the `prev` pointer must equal `self.latest_view`)
      if metablock.get_prev() != &self.latest_view {
        return Err(VerificationError::ViewInMetaBlockNotLatest);
      }

      // obtain the list of public keys of the latest view
      let pk_vec_for_latest_view = self.get_pk_for_view(&self.latest_view)?;

      // we require a majority of endorsers in the latest view to have signed the provided metablock
      // we also require all new endorsers in the proposed latest view to have signed the provided metblock
      // (the latter check ensures that the new endorsers are initialized with the right state)
      let receipt = ViewChangeReceipt::from_bytes(receipt_bytes);
      let res = receipt.verify(
        &metablock.hash().to_bytes(),
        pk_vec_for_latest_view,
        &pk_vec_for_proposed_latest_view,
      );
      if res.is_err() {
        return Err(VerificationError::InvalidViewChangeReceipt);
      }
    }

    // declare the view represented by metablock as valid and update the latest view
    self.latest_view = metablock.hash();
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
  block_bytes: &[u8],
  receipt_bytes: &(Vec<u8>, IdSigBytes),
  nonce: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), VerificationError> {
  if receipt_bytes.1.len() < MIN_NUM_ENDORSERS {
    return Err(VerificationError::InsufficientReceipts);
  }

  if block_bytes.len() < 2 * NONCE_IN_BYTES {
    return Err(VerificationError::InvalidGenesisBlock);
  } else {
    // parse the genesis block and extract the endorser's public key to form a verification key
    // the first `NONCE_IN_BYTES` bytes are the service chosen nonce, followed by the client nonce,
    // so the rest is application-provided data
    let client_nonce = &block_bytes[NONCE_IN_BYTES..(NONCE_IN_BYTES + NONCE_IN_BYTES)];
    if client_nonce != nonce {
      return Err(VerificationError::InvalidGenesisBlock);
    }
  }

  let app_bytes = &block_bytes[(2 * NONCE_IN_BYTES)..];

  // construct a receipt object from the provided bytes
  let receipt = Receipt::from_bytes(receipt_bytes);

  let view = receipt.get_view();

  let pk_vec = vs.get_pk_for_view(view)?;

  // compute a handle as hash of the block
  let handle = {
    let block = Block::new(block_bytes);
    block.hash()
  };

  // verify the signature on the genesis metablock with `handle` as the genesis block's hash
  let genesis_metablock = MetaBlock::genesis(&handle);
  let hash = genesis_metablock.hash().to_bytes();

  let res = receipt.verify(&hash, pk_vec);

  if res.is_err() {
    Err(VerificationError::InvalidGenesisBlock)
  } else {
    Ok((handle.to_bytes(), app_bytes.to_vec()))
  }
}

pub fn get_tail_hash(
  block_bytes: &[u8],
  prev_bytes: &[u8],
  height: usize,
) -> Result<Vec<u8>, VerificationError> {
  let block = Block::new(block_bytes);
  let prev = {
    let res = NimbleDigest::from_bytes(prev_bytes);
    if res.is_err() {
      return Err(VerificationError::IncorrectLength);
    }
    res.unwrap()
  };
  let metablock = MetaBlock::new(&prev, &block.hash(), height);
  Ok(metablock.hash().to_bytes())
}

pub fn verify_read_latest(
  vs: &VerifierState,
  block_bytes: &[u8],
  prev_bytes: &[u8],
  height: usize,
  nonce_bytes: &[u8],
  receipt_bytes: &(Vec<u8>, IdSigBytes),
) -> Result<(Vec<u8>, Vec<u8>), VerificationError> {
  if receipt_bytes.1.len() < MIN_NUM_ENDORSERS {
    return Err(VerificationError::InsufficientReceipts);
  }

  let block = Block::new(block_bytes);

  // construct a tail hash from `prev_bytes`
  let prev = {
    let res = NimbleDigest::from_bytes(prev_bytes);
    if res.is_err() {
      return Err(VerificationError::IncorrectLength);
    }
    res.unwrap()
  };

  // parse the receipt to construct a Receipt object
  let receipt = Receipt::from_bytes(receipt_bytes);

  let pk_vec = vs.get_pk_for_view(receipt.get_view())?;

  let metablock = MetaBlock::new(&prev, &block.hash(), height);
  let tail_hash_prime = metablock.hash();
  let hash_nonced_tail_hash_prime =
    NimbleDigest::digest(&([tail_hash_prime.to_bytes(), nonce_bytes.to_vec()]).concat()).to_bytes();

  // verify the receipt against the nonced tail hash
  let res = receipt.verify(&hash_nonced_tail_hash_prime, pk_vec);

  if res.is_err() {
    return Err(VerificationError::InvalidReceipt);
  }

  let filtered_block_data = if height == 0 {
    vec![]
  } else {
    block_bytes.to_vec()
  };
  Ok((tail_hash_prime.to_bytes(), filtered_block_data))
}

pub fn verify_read_by_index(
  vs: &VerifierState,
  block_bytes: &[u8],
  prev_bytes: &[u8],
  idx: usize,
  receipt_bytes: &(Vec<u8>, IdSigBytes),
) -> Result<(), VerificationError> {
  if receipt_bytes.1.len() < MIN_NUM_ENDORSERS {
    return Err(VerificationError::InsufficientReceipts);
  }

  let block_hash = Block::new(block_bytes).hash();
  let prev = {
    let res = NimbleDigest::from_bytes(prev_bytes);
    if res.is_err() {
      return Err(VerificationError::IncorrectLength);
    }
    res.unwrap()
  };

  // parse the receipt to construct a Receipt object
  let receipt = Receipt::from_bytes(receipt_bytes);

  let pk_vec = vs.get_pk_for_view(receipt.get_view())?;

  let metablock = MetaBlock::new(&prev, &block_hash, idx);
  let tail_hash_prime = metablock.hash();

  // verify the receipt against the nonced tail hash
  let res = receipt.verify(&tail_hash_prime.to_bytes(), pk_vec);

  if res.is_err() {
    Err(VerificationError::InvalidReceipt)
  } else {
    Ok(())
  }
}

pub fn verify_append(
  vs: &VerifierState,
  block_bytes: &[u8],
  prev: &[u8],
  height: usize,
  receipt_bytes: &(Vec<u8>, IdSigBytes),
) -> Result<Vec<u8>, VerificationError> {
  if receipt_bytes.1.len() < MIN_NUM_ENDORSERS {
    return Err(VerificationError::InsufficientReceipts);
  }

  let block_hash = Block::new(block_bytes).hash();
  let prev = {
    let res = NimbleDigest::from_bytes(prev);
    if res.is_err() {
      return Err(VerificationError::IncorrectLength);
    }
    res.unwrap()
  };

  // parse the receipt to construct a Receipt object
  let receipt = Receipt::from_bytes(receipt_bytes);

  let pk_vec = vs.get_pk_for_view(receipt.get_view())?;

  let metablock = MetaBlock::new(&prev, &block_hash, height);
  let tail_hash_prime = metablock.hash();

  // verify the receipt against the nonced tail hash
  let res = receipt.verify(&tail_hash_prime.to_bytes(), pk_vec);

  if res.is_err() {
    Err(VerificationError::InvalidReceipt)
  } else {
    Ok(tail_hash_prime.to_bytes())
  }
}

pub fn verify_query_endorsers(
  nonce_bytes: &[u8],
  ledger_views: &[(Vec<u8>, LedgerView, bool)],
  receipt_bytes: &(Vec<u8>, IdSigBytes),
) -> Result<(), VerificationError> {
  let mut receipt_map = HashMap::<Vec<u8>, Receipt>::new();
  let view = &receipt_bytes.0;
  for (pk, signature) in &receipt_bytes.1 {
    receipt_map.insert(
      pk.clone(),
      Receipt::from_bytes(&(view.clone(), vec![(pk.clone(), signature.clone())])),
    );
  }
  for (pk, ledger_view, _is_locked) in ledger_views {
    if !receipt_map.contains_key(pk) {
      return Err(VerificationError::InvalidePublicKey);
    }
    let receipt = &receipt_map[&pk.clone()];
    let state_hash = produce_hash_of_state(&ledger_view.ledger_tail_map);
    let nonced_hash =
      NimbleDigest::digest(&([state_hash.to_bytes(), nonce_bytes.to_vec()]).concat()).to_bytes();
    let pub_key = PublicKey::from_bytes(pk).unwrap();
    let res = receipt.verify(&nonced_hash, &[pub_key]);
    if res.is_err() {
      return Err(VerificationError::InvalidReceipt);
    }
  }
  Ok(())
}
