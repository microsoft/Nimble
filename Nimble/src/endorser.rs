mod endorser_state;
mod errors;
mod helper;

use crate::endorser_state::EndorserState;
use endorser_proto::endorser_call_server::{EndorserCall, EndorserCallServer};
use endorser_proto::{
  AppendReq, AppendResp, GetEndorserPublicKeyReq, GetEndorserPublicKeyResp, NewLedgerReq,
  NewLedgerResp, ReadLatestReq, ReadLatestResp,
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

#[tonic::async_trait]
impl EndorserCall for EndorserServiceState {
  async fn get_endorser_public_key(
    &self,
    _req: Request<GetEndorserPublicKeyReq>,
  ) -> Result<Response<GetEndorserPublicKeyResp>, Status> {
    let id = self
      .state
      .read()
      .expect("Failed to acquire read lock")
      .get_public_key();

    let reply = GetEndorserPublicKeyResp {
      publickey: id.as_bytes().to_vec(),
    };

    Ok(Response::new(reply))
  }

  async fn new_ledger(
    &self,
    req: Request<NewLedgerReq>,
  ) -> Result<Response<NewLedgerResp>, Status> {
    // The handle is the byte array of information sent by the Nimble Coordinator to the Endorser
    let NewLedgerReq { handle } = req.into_inner();

    let zero_entry = [0u8; 32].to_vec();
    let ledger_height = 0u64;
    let ledger_height_bytes = ledger_height.to_be_bytes().to_vec();
    let mut message: Vec<u8> = vec![];
    message.extend(zero_entry);
    message.extend(handle.to_vec());
    message.extend(ledger_height_bytes);

    let tail_hash = helper::hash(&message).to_vec();

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
    let mut endorser_state = self.state.write().expect("Unable to obtain write lock");
    let res = endorser_state.append(&handle, &block_hash, &cond_tail_hash);

    if res.is_ok() {
      let (tail_hash, height, signature) = res.unwrap();
      let reply = AppendResp {
        tail_hash,
        height: height as u64,
        signature: signature.to_bytes().to_vec(),
      };
      return Ok(Response::new(reply));
    }
    Err(Status::aborted("Failed to Append"))
  }

  async fn read_latest(
    &self,
    request: Request<ReadLatestReq>,
  ) -> Result<Response<ReadLatestResp>, Status> {
    let ReadLatestReq { handle, nonce } = request.into_inner();
    let latest_state = self.state.read().expect("Failed to acquire read lock");
    let (tail_hash, height, endorser_signature) =
      latest_state.read_latest(&handle, &nonce).unwrap();
    let reply = ReadLatestResp {
      tail_hash,
      height: height as u64,
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
