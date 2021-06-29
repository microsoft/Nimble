mod endorser_state;
mod errors;
mod helper;

use crate::endorser_state::{EndorserIdentity, EndorserState, Store};
use crate::errors::EndorserError;
use crate::helper::concat_bytes;
use digest::Output;
use ed25519_dalek::{Keypair, PublicKey, Signature, Signer};
use endorserprotocol::endorser_call_server::{EndorserCall, EndorserCallServer};
use endorserprotocol::{
  Empty, EndorserAppendRequest, EndorserAppendResponse, EndorserLedgerHandles,
  EndorserLedgerResponse, EndorserPublicKey, EndorserQuery, EndorserQueryResponse,
  EndorserStateResponse, Handle,
};
use hex::encode;
use rand::rngs::OsRng;
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use uuid::Uuid;

pub mod endorserprotocol {
  tonic::include_proto!("endorserprotocol");
}

pub struct EndorserServiceState {
  state: Arc<RwLock<Store>>,
}

impl EndorserServiceState {
  pub fn new() -> Self {
    EndorserServiceState {
      state: Arc::new(RwLock::new(Store::new())),
    }
  }
}

#[tonic::async_trait]
impl EndorserCall for EndorserServiceState {
  async fn new_endorser(
    &self,
    request: Request<Empty>,
  ) -> Result<Response<EndorserStateResponse>, Status> {
    println!("Received a NewLedger Request. Generating Handle and creating new EndorserState");

    let mut state_instance = self
      .state
      .write()
      .expect("Unable to acquire write lock on the state");
    let endorser_create_status = state_instance.create_new_endorser_state();
    if !endorser_create_status.is_ok() {
      panic!("Failed. Should not have failed");
    }
    let (handle, endorser_id) = endorser_create_status.unwrap();
    let reply = endorserprotocol::EndorserStateResponse {
      handle,
      keyinfo: Some(EndorserPublicKey {
        publickey: endorser_id.get_public_key(),
        signature: endorser_id.get_signature(),
      }),
    };
    Ok(Response::new(reply))
  }

  async fn get_endorser_public_key(
    &self,
    request: Request<Empty>,
  ) -> Result<Response<EndorserPublicKey>, Status> {
    let state_instance = self
      .state
      .read()
      .expect("Failed to acquire read lock")
      .get_endorser_key_information();

    if !state_instance.is_ok() {
      Err(EndorserError::InvalidLedgerName).unwrap()
    }
    let public_key = state_instance.unwrap();
    let reply = EndorserPublicKey {
      publickey: public_key.get_public_key(),
      signature: public_key.get_signature(),
    };

    Ok(Response::new(reply))
  }

  async fn new_ledger(
    &self,
    request: Request<Handle>,
  ) -> Result<Response<EndorserLedgerResponse>, Status> {
    println!("Received NewLedger Request to create a ledger by an endorser");

    // The handle is the byte array of information sent by the Nimble Coordinator to the Endorser
    let Handle { handle } = request.into_inner();
    println!("Network read handle: {:?}", handle);

    let zero_entry = [0u8; 32].to_vec();
    let ledger_height = 0u64;
    let ledger_height_bytes = ledger_height.to_be_bytes().to_vec();
    let mut message: Vec<u8> = vec![];
    message.extend(zero_entry);
    message.extend(handle.to_vec());
    message.extend(ledger_height_bytes);

    let tail_hash = helper::hash(&message).to_vec();

    let mut state_instance = self
      .state
      .write()
      .expect("Unable to get a write lock on EndorserState");

    let signature = state_instance
      .create_new_ledger_in_endorser_state(handle, tail_hash, ledger_height)
      .expect("Unable to get the signature on genesis handle");

    let reply = EndorserLedgerResponse {
      signature: signature.to_bytes().to_vec(),
    };
    Ok(Response::new(reply))
  }

  async fn get_all_ledgers(
    &self,
    request: Request<Empty>,
  ) -> Result<Response<EndorserLedgerHandles>, Status> {
    let available_handles_in_state = self
      .state
      .read()
      .expect("Failed to acquire read lock")
      .get_all_available_handles();
    println!("Available Handles: {:?}", available_handles_in_state);
    let reply = EndorserLedgerHandles {
      handles: available_handles_in_state,
    };
    Ok(Response::new(reply))
  }

  async fn append_to_ledger(
    &self,
    request: Request<EndorserAppendRequest>,
  ) -> Result<Response<EndorserAppendResponse>, Status> {
    let EndorserAppendRequest {
      endorser_handle,
      data,
    } = request.into_inner();
    println!("Network read handle: {:?}", endorser_handle);
    let mut endorser_state = self.state.write().expect("Unable to obtain write lock");
    let append_status =
        endorser_state
            .append_and_update_endorser_state_tail(endorser_handle, data);
    if append_status.is_ok() {
      let (tail_hash, ledger_height, signature) = append_status.unwrap();
      let signature_bytes = signature.to_bytes().to_vec();
      let reply = EndorserAppendResponse {
        tail_hash,
        ledger_height,
        signature: signature_bytes,
      };
      return Ok(Response::new(reply));
    }
    Err(Status::aborted("Failed to Append"))
  }

  async fn read_latest(
    &self,
    request: Request<EndorserQuery>,
  ) -> Result<Response<EndorserQueryResponse>, Status> {
    let EndorserQuery { handle, nonce } = request.into_inner();
    println!("Received ReadLatest Query: {:?} {:?}", handle, nonce);
    let latest_state = self.state.read().expect("Failed to acquire read lock");
    let (nonce_bytes, tail_hash, endorser_signature) = latest_state
      .get_latest_state_for_handle(handle, nonce)
      .unwrap();
    let reply = EndorserQueryResponse {
      nonce: nonce_bytes,
      tail_hash,
      signature: endorser_signature.to_bytes().to_vec(),
    };
    Ok(Response::new(reply))
  }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  #[rustfmt::skip]
      let addr = "[::1]:9090".parse()?;
  let server = EndorserServiceState::new();

  println!("Running gRPC Endorser Service at {:?}", addr);

  Server::builder()
    .add_service(EndorserCallServer::new(server))
    .serve(addr)
    .await?;

  Ok(())
}
