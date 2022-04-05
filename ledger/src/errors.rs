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
  /// returned if the supplied views are not unique
  InvalidView,
  /// returned when the nonce is of an incorrect length
  InvalidNonceSize,
  /// returned when the purported public key is not in the view ledger
  InvalidPublicKey,
  /// returned when the provided receipt does not contain signatures from a valid quorum
  InsufficientQuorum,
  /// returned when the supplied list of metablocks does not have a unique metablock
  NonUniqueMetablocks,
}
