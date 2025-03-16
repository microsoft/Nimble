#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerificationError {
  /// returned if the supplied genesis block is not well formed
  InvalidGenesisBlock,
  /// returned if the endorser's attestion is invalid
  InvalidEndorserAttestation,
  /// returned if the supplied byte array is not of the correct length
  IncorrectLength,
  /// returned if the supplied receipt is invalid
  InvalidReceipt,
  /// returned if the supplied signature is invalid
  InvalidSignature,
  /// returned if the index is out of bounds
  IndexOutofBounds,
  /// returned if the identities are not unique
  DuplicateIds,
  /// returned if the supplied view is not well formed
  InvalidView,
  /// returned if the number of provided receipts is zero
  InsufficientReceipts,
  /// returned if the receipt provided to prove view change is invalid
  InvalidViewChangeReceipt,
  /// returned if the purported view is not in the verifier's state
  ViewNotFound,
  /// returned if the supplied metablock of the view ledger does not point to the tail in the verifier's state
  ViewInMetaBlockNotLatest,
  /// returned if a public key is not found in a receipt
  InvalidPublicKey,
  /// returned if the block hash does not match the block
  InvalidBlockHash,
  /// returned if the height does not match the expected height
  InvalidHeight,
  /// returned if the supplied handle bytes cannot be deserialized
  InvalidHandle,
  /// returned if the supplied nonces cannot be deserialized
  InvalidNonces,
  /// returned if the supplied nonce cannot be deserialized
  InvalidNonce,
  /// returned if the supplied hash nonces cannot be deserialized
  InvalidNoncesHash,
  /// returned if the supplied group identity doesn't match the config
  InvalidGroupIdentity,
  /// returned if the metablock doesn't match
  InvalidMetaBlock,
  /// returned if the max cut is incorrect
  InvalidMaxCut,
  /// returned if a ledger tail map is incorrect
  InvalidLedgerTailMap,
  /// returned if a ledger tail map is missing
  MissingLedgerTailMap,
  /// returned if there exists redundant ledger tail map
  RedundantLedgerTailMap,
  /// returned if the config is invalid
  InvalidConfig,
  /// returnef if the number of endorsers is too few
  InsufficentEndorsers,
  /// returned if the ledger tail maps are inconsistent
  InconsistentLedgerTailMaps,
}
