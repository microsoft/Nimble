use crate::endorser_state::EndorserState;
use clap::{App, Arg};
use ledger::NimbleDigest;
use std::sync::{Arc, RwLock};
use tonic::transport::Server;
use tonic::{Request, Response, Status};

mod endorser_state;
mod errors;

pub mod endorser_proto {
  tonic::include_proto!("endorser_proto");
}

use endorser_proto::endorser_call_server::{EndorserCall, EndorserCallServer};
use endorser_proto::{
  AppendReq, AppendResp, AppendViewLedgerReq, AppendViewLedgerResp, GetPublicKeyReq,
  GetPublicKeyResp, NewLedgerReq, NewLedgerResp, ReadLatestReq, ReadLatestResp,
  ReadLatestViewLedgerReq, ReadLatestViewLedgerResp,
};

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
    let NewLedgerReq { handle } = req.into_inner();
    let handle = {
      let handle_instance = NimbleDigest::from_bytes(&handle);
      if handle_instance.is_err() {
        return Err(Status::invalid_argument("Handle size is invalid"));
      }
      handle_instance.unwrap()
    };

    let mut endorser = self
      .state
      .write()
      .expect("Unable to get a write lock on EndorserState");

    let signature = endorser
      .new_ledger(&handle)
      .expect("Unable to get the signature on genesis handle");

    let reply = NewLedgerResp {
      signature: signature.to_bytes().to_vec(),
    };
    Ok(Response::new(reply))
  }

  async fn append(&self, req: Request<AppendReq>) -> Result<Response<AppendResp>, Status> {
    let AppendReq { handle, block_hash } = req.into_inner();

    let handle_instance = NimbleDigest::from_bytes(&handle);
    let block_hash_instance = NimbleDigest::from_bytes(&block_hash);

    if handle_instance.is_err() || block_hash_instance.is_err() {
      return Err(Status::invalid_argument("Invalid input sizes"));
    }

    let mut endorser_state = self.state.write().expect("Unable to obtain write lock");
    let res = endorser_state.append(&handle_instance.unwrap(), &block_hash_instance.unwrap());

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
    let handle = {
      let res = NimbleDigest::from_bytes(&handle);
      if res.is_err() {
        return Err(Status::invalid_argument("Invalid handle size"));
      }
      res.unwrap()
    };
    let latest_state = self.state.read().expect("Failed to acquire read lock");
    let res = latest_state.read_latest(&handle, &nonce);

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

  async fn append_view_ledger(
    &self,
    req: Request<AppendViewLedgerReq>,
  ) -> Result<Response<AppendViewLedgerResp>, Status> {
    let AppendViewLedgerReq { block_hash } = req.into_inner();

    let block_hash_instance = NimbleDigest::from_bytes(&block_hash);

    if block_hash_instance.is_err() {
      return Err(Status::invalid_argument("Invalid input sizes"));
    }

    let mut endorser_state = self.state.write().expect("Unable to obtain write lock");
    let res = endorser_state.append_view_ledger(&block_hash_instance.unwrap());

    match res {
      Ok((tail_hash, signature)) => {
        let reply = AppendViewLedgerResp {
          tail_hash,
          signature: signature.to_bytes().to_vec(),
        };
        Ok(Response::new(reply))
      },

      Err(_) => Err(Status::aborted("Failed to append_view_ledger")),
    }
  }

  async fn read_latest_view_ledger(
    &self,
    request: Request<ReadLatestViewLedgerReq>,
  ) -> Result<Response<ReadLatestViewLedgerResp>, Status> {
    let ReadLatestViewLedgerReq { nonce } = request.into_inner();
    let endorser = self.state.read().expect("Failed to acquire read lock");
    let res = endorser.read_latest_view_ledger(&nonce);

    match res {
      Ok((tail_hash, signature)) => {
        let reply = ReadLatestViewLedgerResp {
          tail_hash,
          signature: signature.to_bytes().to_vec(),
        };
        Ok(Response::new(reply))
      },
      Err(_) => Err(Status::aborted("Failed to process read_latest_view_ledger")),
    }
  }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let config = App::new("endorser")
    .arg(
      Arg::with_name("host")
        .help("The hostname to run the Service On. Default: [::1]")
        .default_value("[::1]")
        .index(2),
    )
    .arg(
      Arg::with_name("port")
        .help("The port number to run the Service On. Default: 9090")
        .default_value("9090")
        .index(1),
    );
  let cli_matches = config.get_matches();
  let hostname = cli_matches.value_of("host").unwrap();
  let port_number = cli_matches.value_of("port").unwrap();
  let addr = format!("{}:{}", hostname, port_number).parse()?;
  let server = EndorserServiceState::new();

  println!("Running gRPC Endorser Service at {:?}", addr);

  Server::builder()
    .add_service(EndorserCallServer::new(server))
    .serve(addr)
    .await?;

  Ok(())
}
