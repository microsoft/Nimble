#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StorageError {
  /// returned if the supplied key does not exist in the storage service
  InvalidKey,
  /// returned if one attempts to insert a key that is already in the storage service
  DuplicateKey,
  /// returned if the requested index is not in the vector associated with a key
  InvalidIndex,
  /// returned if the latest value does not match the conditional value provided
  IncorrectConditionalData,
  /// returned if the key does not exist
  KeyDoesNotExist,
}

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
  /// returned when the nonce is of an incorrect length
  InvalidNonceSize,
}
