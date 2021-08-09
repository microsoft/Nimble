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
}
