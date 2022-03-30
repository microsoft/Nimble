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
  InvalidePublicKey,
  /// returned if the block hash does not match the block
  InvalidBlockHash,
  /// returned if the height does not match the expected height
  InvalidHeight,
}
