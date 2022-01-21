#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoordinatorError {
  /// returned if the connection clients to the endorser cannot be made by the coordinator
  FailedToConnectToEndorser,
  /// returned if the host name is not correct
  CannotResolveHostName,
  /// returned if the public key returned is invalid
  UnableToRetrievePublicKey,
}
