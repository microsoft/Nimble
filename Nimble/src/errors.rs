#![allow(dead_code)]
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
  /// returned if the increment results in overflow of ledger height
  LedgerHeightOverflow,
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
}

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
