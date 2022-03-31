#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoordinatorError {
  /// returned if the connection clients to the endorser cannot be made by the coordinator
  FailedToConnectToEndorser,
  /// returned if the host name is not correct
  CannotResolveHostName,
  /// returned if the public key returned is invalid
  UnableToRetrievePublicKey,
  /// returned if the call to initialize the endorser state fails
  FailedToInitializeEndorser,
  /// returned if the call to create ledger fails
  FailedToCreateLedger,
  /// returned if the call to append ledger fails
  FailedToAppendLedger,
  /// returned if the call to read ledger fails
  FailedToReadLedger,
  /// returned if the call to append view ledger fails
  FailedToAppendViewLedger,
  /// returned if the call to read view ledger fails
  FailedToReadViewLedger,
  /// returned if a call to the ledger store fails
  FailedToCallLedgerStore,
  /// returned if the endorser public key does not exist
  InvalidEndorserPublicKey,
  /// returned if the read lock cannot be acquired
  FailedToAcquireReadLock,
  /// returned if the write lock cannot be acquired
  FailedToAcquireWriteLock,
  /// returned if the call to read latest state fails
  FailedToReadLatestState,
  /// returned if the cooordinator cannot assemble a receipt with a unique view
  EndorsersInDifferentViews,
  /// returned if the returned receipt is invalid
  InvalidReceipt,
  /// returned if the call to unlock fails
  FailedToUnlock,
  /// returned if the views of endorsers are different
  NonUniqueViews,
  /// returned if the ledger views are empty
  EmptyLedgerViews,
  /// returned if failed to attach receipt
  FailedToAttachReceipt,
  /// returned if genesis op fails
  FailedToCreateGenesis,
  /// returned if the provided handle is invalid
  InvalidHandle,
}
