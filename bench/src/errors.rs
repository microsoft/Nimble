#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClientError {
  /// returned if the client uses as InvalidUri as Coordinator hostname
  CoordinatorHostNameNotFound,
  /// returned if the client fails to connect to the Coordinator while creating a channel
  UnableToConnectToCoordinator,
  /// returned if the client inserts/updates the local state of endorser keys and finds existing key
  ConflictingEndorserPublicKeyToInsert,
  /// returned if the client requests a PublicKey from local state and does not find it
  EndorserKeyDoesnotExist,
}
