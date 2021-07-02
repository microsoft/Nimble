use core::fmt::Debug;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EndorserError {
  /// returned if the supplied ledger name is invalid
  InvalidLedgerName,
  /// returned if one attempts to create a ledger that already exists
  LedgerExists,
  /// returned if one attempts to perform a conditional append and the condition check fails
  TailDoesNotMatch,
  /// returned if the creation of the endorser state fails
  StateCreationError,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerificationError {
  /// returned if the supplied genesis block is not well formed
  InvalidGenesisBlock,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StorageError {
  /// returned if the supplied key does not exist in the storage service
  InvalidKey,
  /// returned if one attempts to insert a key that is already in the storage service
  DuplicateKey,
  /// returned if the requested index is not in the vector associated with a key
  InvalidIndex,
}
