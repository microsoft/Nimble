use crate::{endorser_state::EndorserState, errors::EndorserError};
use clap::{App, Arg};
use ledger::{
  signature::PublicKeyTrait, Block, CustomSerde, MetaBlock, NimbleDigest, Nonces, Receipts,
};
use tonic::{transport::Server, Code, Request, Response, Status};

mod endorser_state;
mod errors;

use ledger::endorser_proto::{
  endorser_call_server::{EndorserCall, EndorserCallServer},
  ActivateReq, ActivateResp, AppendReq, AppendResp, FinalizeStateReq, FinalizeStateResp,
  GetPublicKeyReq, GetPublicKeyResp, InitializeStateReq, InitializeStateResp, NewLedgerReq,
  NewLedgerResp, ReadLatestReq, ReadLatestResp, ReadStateReq, ReadStateResp, GetPing,
};

pub struct EndorserServiceState {
  state: EndorserState,
}

impl EndorserServiceState {
  pub fn new() -> Self {
    EndorserServiceState {
      state: EndorserState::new(),
    }
  }

  fn process_error(
    &self,
    error: EndorserError,
    handle: Option<&NimbleDigest>,
    default_msg: impl Into<String>,
  ) -> Status {
    match error {
      EndorserError::OutOfOrder => {
        if let Some(h) = handle {
          let height = self.state.get_height(h).unwrap();
          Status::with_details(
            Code::FailedPrecondition,
            "Out of order",
            bytes::Bytes::copy_from_slice(&(height as u64).to_le_bytes()),
          )
        } else {
          Status::failed_precondition("View ledger height is out of order")
        }
      },
      EndorserError::LedgerExists => Status::already_exists("Ledger exists"),
      EndorserError::InvalidLedgerName => Status::not_found("Ledger handle not found"),
      EndorserError::LedgerHeightOverflow => Status::out_of_range("Ledger height overflow"),
      EndorserError::InvalidTailHeight => Status::invalid_argument("Invalid ledger height"),
      EndorserError::AlreadyInitialized => {
        Status::already_exists("Enodrser is already initialized")
      },
      EndorserError::NotInitialized => Status::unimplemented("Endorser is not initialized"),
      EndorserError::AlreadyFinalized => Status::unavailable("Endorser is already finalized"),
      EndorserError::SigningFailed => Status::internal("Failed to sign the nonce"),
      _ => Status::internal(default_msg),
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
    let pk = self.state.get_public_key();

    let reply = GetPublicKeyResp {
      pk: pk.to_bytes().to_vec(),
    };

    Ok(Response::new(reply))
  }

//This function should sent a ping request and return the keyed ping
  async fn get_ping(
    &self,
    req: Request<GetPing>,
  ) -> Result<Response<GetPing>, Status> {

    let ping_req = req.into_inner();
    let received_nonce = ping_req.nonce;

    if received_nonce.is_empty() {
      return Err(Status::internal("Received nonce is empty"));
    }

  let signature = self
      .state
      .sign_with_private_key(&received_nonce)
      .map_err(|_| EndorserError::SigningFailed) ?;


    let reply = GetPing {
      nonce: received_nonce, // Echo back the nonce
      signature, // Sign the nonce
    };

    Ok(Response::new(reply))
  }

  async fn new_ledger(
    &self,
    req: Request<NewLedgerReq>,
  ) -> Result<Response<NewLedgerResp>, Status> {
    let NewLedgerReq {
      handle,
      block_hash,
      block,
    } = req.into_inner();
    let handle = {
      let res = NimbleDigest::from_bytes(&handle);
      if res.is_err() {
        return Err(Status::invalid_argument("Handle size is invalid"));
      }
      res.unwrap()
    };

    let block_hash = {
      let res = NimbleDigest::from_bytes(&block_hash);
      if res.is_err() {
        return Err(Status::invalid_argument("Block hash size is invalid"));
      }
      res.unwrap()
    };

    let block = {
      let res = Block::from_bytes(&block);
      if res.is_err() {
        return Err(Status::invalid_argument("Block is invalid"));
      }
      res.unwrap()
    };

    let res = self.state.new_ledger(&handle, &block_hash, &block);

    match res {
      Ok(receipt) => {
        let reply = NewLedgerResp {
          receipt: receipt.to_bytes().to_vec(),
        };
        Ok(Response::new(reply))
      },
      Err(error) => {
        let status = self.process_error(
          error,
          None,
          "Failed to create a new ledger due to an internal error",
        );
        Err(status)
      },
    }
  }

  async fn append(&self, req: Request<AppendReq>) -> Result<Response<AppendResp>, Status> {
    let AppendReq {
      handle,
      block_hash,
      expected_height,
      block,
      nonces,
    } = req.into_inner();

    let handle_instance = NimbleDigest::from_bytes(&handle);
    let block_hash_instance = NimbleDigest::from_bytes(&block_hash);
    let block_instance = Block::from_bytes(&block);
    let nonces_instance = Nonces::from_bytes(&nonces);

    if handle_instance.is_err()
      || block_hash_instance.is_err()
      || block_instance.is_err()
      || nonces_instance.is_err()
    {
      return Err(Status::invalid_argument("Invalid input sizes"));
    }

    if expected_height == 0 {
      return Err(Status::invalid_argument("Invalid expected height"));
    }

    let handle = handle_instance.unwrap();
    let block_hash = block_hash_instance.unwrap();
    let block = block_instance.unwrap();
    let nonces = nonces_instance.unwrap();

    let res = self.state.append(
      &handle,
      &block_hash,
      expected_height as usize,
      &block,
      &nonces,
    );

    match res {
      Ok(receipt) => {
        let reply = AppendResp {
          receipt: receipt.to_bytes().to_vec(),
        };
        Ok(Response::new(reply))
      },

      Err(error) => {
        let status = self.process_error(
          error,
          Some(&handle),
          "Failed to append to a ledger due to an internal error",
        );
        Err(status)
      },
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
    let res = self.state.read_latest(&handle, &nonce);

    match res {
      Ok((receipt, block, nonces)) => {
        let reply = ReadLatestResp {
          receipt: receipt.to_bytes().to_vec(),
          block: block.to_bytes().to_vec(),
          nonces: nonces.to_bytes().to_vec(),
        };
        Ok(Response::new(reply))
      },
      Err(error) => {
        let status = self.process_error(
          error,
          Some(&handle),
          "Failed to read a ledger due to an internal error",
        );
        Err(status)
      },
    }
  }

  async fn finalize_state(
    &self,
    req: Request<FinalizeStateReq>,
  ) -> Result<Response<FinalizeStateResp>, Status> {
    let FinalizeStateReq {
      block_hash,
      expected_height,
    } = req.into_inner();

    let block_hash_instance = NimbleDigest::from_bytes(&block_hash);

    if block_hash_instance.is_err() {
      return Err(Status::invalid_argument("Invalid input sizes"));
    }

    let res = self
      .state
      .finalize_state(&block_hash_instance.unwrap(), expected_height as usize);

    match res {
      Ok((receipt, ledger_tail_map)) => {
        let reply = FinalizeStateResp {
          receipt: receipt.to_bytes().to_vec(),
          ledger_tail_map,
        };
        Ok(Response::new(reply))
      },
      Err(error) => {
        let status = self.process_error(
          error,
          None,
          "Failed to finalize the endorser due to an internal error",
        );
        Err(status)
      },
    }
  }

  async fn initialize_state(
    &self,
    req: Request<InitializeStateReq>,
  ) -> Result<Response<InitializeStateResp>, Status> {
    let InitializeStateReq {
      group_identity,
      ledger_tail_map,
      view_tail_metablock,
      block_hash,
      expected_height,
    } = req.into_inner();
    let group_identity_rs = NimbleDigest::from_bytes(&group_identity).unwrap();
    let view_tail_metablock_rs = MetaBlock::from_bytes(&view_tail_metablock).unwrap();
    let block_hash_rs = NimbleDigest::from_bytes(&block_hash).unwrap();
    let res = self.state.initialize_state(
      &group_identity_rs,
      &ledger_tail_map,
      &view_tail_metablock_rs,
      &block_hash_rs,
      expected_height as usize,
    );

    match res {
      Ok(receipt) => {
        let reply = InitializeStateResp {
          receipt: receipt.to_bytes().to_vec(),
        };
        Ok(Response::new(reply))
      },
      Err(error) => {
        let status = self.process_error(
          error,
          None,
          "Failed to initialize an endorser due to an internal error",
        );
        Err(status)
      },
    }
  }

  async fn read_state(
    &self,
    _req: Request<ReadStateReq>,
  ) -> Result<Response<ReadStateResp>, Status> {
    let res = self.state.read_state();

    match res {
      Ok((receipt, endorser_mode, ledger_tail_map)) => {
        let reply = ReadStateResp {
          receipt: receipt.to_bytes().to_vec(),
          mode: endorser_mode as i32,
          ledger_tail_map,
        };
        Ok(Response::new(reply))
      },
      Err(error) => {
        let status = self.process_error(
          error,
          None,
          "Failed to finalize the endorser due to an internal error",
        );
        Err(status)
      },
    }
  }

  async fn activate(&self, req: Request<ActivateReq>) -> Result<Response<ActivateResp>, Status> {
    let ActivateReq {
      old_config,
      new_config,
      ledger_tail_maps,
      ledger_chunks,
      receipts,
    } = req.into_inner();
    let receipts_rs = Receipts::from_bytes(&receipts).unwrap();
    let res = self.state.activate(
      &old_config,
      &new_config,
      &ledger_tail_maps,
      &ledger_chunks,
      &receipts_rs,
    );

    match res {
      Ok(()) => {
        let reply = ActivateResp {};
        Ok(Response::new(reply))
      },
      Err(error) => {
        let status = self.process_error(
          error,
          None,
          "Failed to verify the view change due to an internal error",
        );
        Err(status)
      },
    }
  }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let config = App::new("endorser")
    .arg(
      Arg::with_name("host")
        .short("t")
        .long("host")
        .help("The hostname to run the Service On. Default: [::1]")
        .default_value("[::1]"),
    )
    .arg(
      Arg::with_name("port")
        .short("p")
        .long("port")
        .help("The port number to run the Service On. Default: 9096")
        .default_value("9090"),
    );
  let cli_matches = config.get_matches();
  let hostname = cli_matches.value_of("host").unwrap();
  let port_number = cli_matches.value_of("port").unwrap();
  let addr = format!("{}:{}", hostname, port_number).parse()?;
  let server = EndorserServiceState::new();

  let job = tokio::spawn(async move {
    println!("Endorser host listening on {:?}", addr);

    let _ = Server::builder()
      .add_service(EndorserCallServer::new(server))
      .serve(addr)
      .await;
  });

  job.await?;

  Ok(())
}
