#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoordinatorError {
  /// returned if the coordinator does not have the handle
  UnableToFindHandle,
  /// returned if the coordinator fails to find the index of the endorser key
  UnableToFindPublicKeyIndex,
  /// returned if the Endorser Connection Client already exists in the Connection Store
  EndorserAlreadyExists,
  /// returned if the connection clients to the endorser cannot be made by the coordinator
  UnableToConnectToEndorser,
  /// returned if the multi-get fails to return any endorser client.
  UnableToFindEndorserClient,
  /// returned if the handle managed by Endorsers already exists
  HandleAlreadyExists,
}
