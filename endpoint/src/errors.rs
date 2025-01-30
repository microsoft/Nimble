#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EndpointError {
  /// returned if the endpoint uses as InvalidUri as Coordinator hostname
  CoordinatorHostNameNotFound,
  /// returned if the endpoint fails to connect to the Coordinator while creating a channel
  UnableToConnectToCoordinator,
  /// returned if the endpoint fails to create a new counter
  FailedToCreateNewCounter,
  /// returned if the endpoint fails to verify a new counter
  FailedToVerifyNewCounter,
  /// returned if the endpoint fails to conver the u64 counter to usize
  FailedToConvertCounter,
  /// returned if the endpoint fails to increment the counter
  FailedToIncrementCounter,
  /// returned if the endpoint fails to verify the incremented counter
  FailedToVerifyIncrementedCounter,
  /// returned if the endpoint fails to read the counter
  FailedToReadCounter,
  /// returned if the endpoint fails to verify the read counter
  FaieldToVerifyReadCounter,
  /// returned if the endpoint fails to read the view ledger
  FailedToReadViewLedger,
  /// returned if the endpoint fails to acquire the read lock
  FailedToAcquireReadLock,
  /// returned if the endpoint fails to acquire the write lock
  FailedToAcquireWriteLock,
  /// returned if the endpoint fails to apply view change
  FailedToApplyViewChange,
  /// returned if the endpoint fails to get the timeout map
  FailedToGetTimeoutMap,
  /// returned if failed to ping all endorsers
  FailedToPingAllEndorsers,
  /// returned if failed to add endorsers
  FailedToAddEndorsers,
}
