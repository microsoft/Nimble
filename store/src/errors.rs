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
  /// return if view ledger read lock cannot be acquired
  ViewLedgerReadLockFailed,
  /// return if view ledger write lock cannot be acquired
  ViewLedgerWriteLockFailed,
  /// return if ledger map read lock cannot be acquired
  LedgerMapReadLockFailed,
  /// return if ledger map write lock cannot be acquired
  LedgerMapWriteLockFailed,
  /// return if ledger read lock cannot be acquired
  LedgerReadLockFailed,
  /// return if ledger write lock cannot be acquired
  LedgerWriteLockFailed,
  /// return if required arguments are missing
  MissingArguments,
  /// return if the DB URL is invalid
  InvalidDBUri,
  /// return if failed to initialize the view ledger
  FailedToInitializeViewLedger,
  /// return if the ledger height overflows
  LedgerHeightOverflow,
  /// return if receipts are mismatch
  MismatchedReceipts,
}

use std::fmt::Display;

#[derive(Clone, Debug)]
pub enum LedgerStoreError {
  LedgerError(StorageError),
  MongoDBError(mongodb::error::Error),
}

impl Display for LedgerStoreError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      LedgerStoreError::LedgerError(storage_error) => write!(f, "{:?}", storage_error),
      LedgerStoreError::MongoDBError(mongodb_error) => write!(f, "{:?}", mongodb_error),
    }
  }
}

impl std::error::Error for LedgerStoreError {}

impl From<StorageError> for LedgerStoreError {
  fn from(err: StorageError) -> Self {
    LedgerStoreError::LedgerError(err)
  }
}

impl From<mongodb::error::Error> for LedgerStoreError {
  fn from(err: mongodb::error::Error) -> Self {
    LedgerStoreError::MongoDBError(err)
  }
}
