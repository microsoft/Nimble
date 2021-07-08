mod endorser_state;
mod errors;
mod ledger;

use crate::endorser_state::EndorserState;
use crate::ledger::{MetaBlock, NimbleDigest, NimbleHashTrait};
use endorser_proto::endorser_call_server::{EndorserCall, EndorserCallServer};
use endorser_proto::{
  AppendReq, AppendResp, GetPublicKeyReq, GetPublicKeyResp, NewLedgerReq, NewLedgerResp,
  ReadLatestReq, ReadLatestResp,
};
use std::sync::{Arc, RwLock};
use tonic::transport::Server;
use tonic::{Request, Response, Status};

pub mod endorser_proto {
  tonic::include_proto!("endorser_proto");
}

pub struct EndorserServiceState {
  state: Arc<RwLock<EndorserState>>,
}

impl EndorserServiceState {
  pub fn new() -> Self {
    EndorserServiceState {
      state: Arc::new(RwLock::new(EndorserState::new())),
    }
  }
}

impl Default for EndorserServiceState {
  fn default() -> Self {
    Self::new()
  }
}

#[tonic::async_trait]
impl EndorserCall for EndorserServiceState {
  async fn get_public_key(
    &self,
    _req: Request<GetPublicKeyReq>,
  ) -> Result<Response<GetPublicKeyResp>, Status> {
    let pk = self
      .state
      .read()
      .expect("Failed to acquire read lock")
      .get_public_key();

    let reply = GetPublicKeyResp {
      pk: pk.as_bytes().to_vec(),
    };

    Ok(Response::new(reply))
  }

  async fn new_ledger(
    &self,
    req: Request<NewLedgerReq>,
  ) -> Result<Response<NewLedgerResp>, Status> {
    // The handle is the byte array of information sent by the Nimble Coordinator to the Endorser
    let NewLedgerReq { handle } = req.into_inner();

    let handle_instance = NimbleDigest::from_bytes(&handle);
    if handle_instance.is_err() {
      return Err(Status::invalid_argument("Handle size is invalid"));
    }
    let handle = handle_instance.unwrap();
    let metadata = MetaBlock::genesis(&handle);
    let tail_hash = metadata.hash();

    let mut endorser = self
      .state
      .write()
      .expect("Unable to get a write lock on EndorserState");

    let signature = endorser
      .new_ledger(&handle, &tail_hash)
      .expect("Unable to get the signature on genesis handle");

    let reply = NewLedgerResp {
      signature: signature.to_bytes().to_vec(),
    };
    Ok(Response::new(reply))
  }

  async fn append(&self, req: Request<AppendReq>) -> Result<Response<AppendResp>, Status> {
    let AppendReq {
      handle,
      block_hash,
      cond_tail_hash,
    } = req.into_inner();

    let handle_instance = NimbleDigest::from_bytes(&handle);
    let block_hash_instance = NimbleDigest::from_bytes(&block_hash);
    let cond_tail_hash_instance = NimbleDigest::from_bytes(&cond_tail_hash);

    if handle_instance.is_err() || block_hash_instance.is_err() || cond_tail_hash_instance.is_err()
    {
      return Err(Status::invalid_argument("Invalid input sizes"));
    }

    let mut endorser_state = self.state.write().expect("Unable to obtain write lock");
    let res = endorser_state.append(
      &handle_instance.unwrap(),
      &block_hash_instance.unwrap(),
      &cond_tail_hash_instance.unwrap(),
    );

    match res {
      Ok((tail_hash, height, signature)) => {
        let reply = AppendResp {
          tail_hash,
          height: height as u64,
          signature: signature.to_bytes().to_vec(),
        };
        Ok(Response::new(reply))
      },

      Err(_) => Err(Status::aborted("Failed to append")),
    }
  }

  async fn read_latest(
    &self,
    request: Request<ReadLatestReq>,
  ) -> Result<Response<ReadLatestResp>, Status> {
    let ReadLatestReq { handle, nonce } = request.into_inner();
    let handle_instance = {
      let h = NimbleDigest::from_bytes(&handle);
      if h.is_err() {
        return Err(Status::invalid_argument("Invalid handle size"));
      }
      h.unwrap()
    };
    let latest_state = self.state.read().expect("Failed to acquire read lock");
    let res = latest_state.read_latest(&handle_instance, &nonce);

    match res {
      Ok((tail_hash, height, signature)) => {
        let reply = ReadLatestResp {
          tail_hash,
          height: height as u64,
          signature: signature.to_bytes().to_vec(),
        };
        Ok(Response::new(reply))
      },
      Err(_) => Err(Status::aborted("Failed to process read_latest")),
    }
  }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let addr = "[::1]:9090".parse()?;
  let server = EndorserServiceState::new();

  println!("Running gRPC Endorser Service at {:?}", addr);

  Server::builder()
    .add_service(EndorserCallServer::new(server))
    .serve(addr)
    .await?;

  Ok(())
}
