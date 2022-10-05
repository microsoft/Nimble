#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EndorserError {
  /// returned if the supplied ledger name is invalid
  InvalidLedgerName,
  /// returned if one attempts to create a ledger that already exists
  LedgerExists,
  /// returned if the increment results in overflow of ledger height
  LedgerHeightOverflow,
  /// returned if the state of the endorser is not initialized
  NotInitialized,
  /// returned if the state of the endorser is already initialized
  AlreadyInitialized,
  /// returned if the requested tail height is less than the expected height
  InvalidTailHeight,
  /// returned if the requested tail height is more than the expected height
  OutOfOrder,
  /// returned if failed to acquire view ledger read lock
  FailedToAcquireViewLedgerReadLock,
  /// returned if failed to acquire view ledger write lock
  FailedToAcquireViewLedgerWriteLock,
  /// returned if failed to acquire ledger map read lock
  FailedToAcquireLedgerMapReadLock,
  /// returned if failed to acquire ledger map write lock
  FailedToAcquireLedgerMapWriteLock,
  /// returned if failed to acquire ledger entry read lock
  FailedToAcquireLedgerEntryReadLock,
  /// returned if failed to acquire ledger entry write lock
  FailedToAcquireLedgerEntryWriteLock,
  /// returned if the endorser is already finalized
  AlreadyFinalized,
}
