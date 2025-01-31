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
  /// returned if the endorser uri does not exist
  InvalidEndorserUri,
  /// returned if the read lock cannot be acquired
  FailedToAcquireReadLock,
  /// returned if the write lock cannot be acquired
  FailedToAcquireWriteLock,
  /// returned if the call to read latest state fails
  FailedToReadLatestState,
  /// returned if the cooordinator cannot assemble a receipt
  EndorsersNotInSync,
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
  /// returned if the provided next height is invalid
  InvalidHeight,
  /// returned if failed to (de)serialize endorser hostnames
  FailedToSerde,
  /// returned if the provided nonce is invalid
  InvalidNonce,
  /// returned if no new endorsers added
  NoNewEndorsers,
  /// returned if a ledger or an entry already exists
  LedgerAlreadyExists,
  /// returned if hit unexpected error
  UnexpectedError,
  /// returned if failed to attach nonce into the ledger store
  FailedToAttachNonce,
  /// returned if failed to obtain a quorum
  FailedToObtainQuorum,
  /// returned if failed to verify view change
  FailedToActivate,
  /// returned if get timeout map fails
  FailedToGetTimeoutMap,
}
