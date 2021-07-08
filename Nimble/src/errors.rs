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
