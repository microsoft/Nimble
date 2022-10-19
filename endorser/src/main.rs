use crate::{endorser_state::EndorserState, errors::EndorserError};
use clap::{App, Arg};
use ledger::{
  produce_hash_of_state, signature::PublicKeyTrait, CustomSerde, LedgerChunk, LedgerTailMap,
  MetaBlock, NimbleDigest, Receipts,
};
use std::collections::HashMap;
use tonic::{transport::Server, Code, Request, Response, Status};

mod endorser_state;
mod errors;

#[allow(clippy::derive_partial_eq_without_eq)]
pub mod endorser_proto {
  tonic::include_proto!("endorser_proto");
}

use endorser_proto::{
  endorser_call_server::{EndorserCall, EndorserCallServer},
  ActivateReq, ActivateResp, AppendReq, AppendResp, FinalizeStateReq, FinalizeStateResp,
  GetPublicKeyReq, GetPublicKeyResp, InitializeStateReq, InitializeStateResp, LedgerTailMapEntry,
  NewLedgerReq, NewLedgerResp, ReadLatestReq, ReadLatestResp, ReadStateReq, ReadStateResp,
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

  async fn new_ledger(
    &self,
    req: Request<NewLedgerReq>,
  ) -> Result<Response<NewLedgerResp>, Status> {
    let NewLedgerReq { handle, block_hash } = req.into_inner();
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

    let res = self.state.new_ledger(&handle, &block_hash);

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
    } = req.into_inner();

    let handle_instance = NimbleDigest::from_bytes(&handle);
    let block_hash_instance = NimbleDigest::from_bytes(&block_hash);

    if handle_instance.is_err() || block_hash_instance.is_err() {
      return Err(Status::invalid_argument("Invalid input sizes"));
    }

    if expected_height == 0 {
      return Err(Status::invalid_argument("Invalid expected height"));
    }

    let handle = handle_instance.unwrap();
    let block_hash = block_hash_instance.unwrap();

    let res = self
      .state
      .append(&handle, &block_hash, expected_height as usize);

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
      Ok(receipt) => {
        let reply = ReadLatestResp {
          receipt: receipt.to_bytes().to_vec(),
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
        let ledger_tail_map_proto: Vec<LedgerTailMapEntry> = ledger_tail_map
          .iter()
          .map(|(handle, metablock)| LedgerTailMapEntry {
            handle: handle.to_bytes(),
            metablock: metablock.to_bytes(),
          })
          .collect();
        let reply = FinalizeStateResp {
          receipt: receipt.to_bytes().to_vec(),
          ledger_tail_map: ledger_tail_map_proto,
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
    let ledger_tail_map_rs: HashMap<NimbleDigest, MetaBlock> = ledger_tail_map
      .into_iter()
      .map(|e| {
        (
          NimbleDigest::from_bytes(&e.handle).unwrap(),
          MetaBlock::from_bytes(&e.metablock).unwrap(),
        )
      })
      .collect();
    let group_identity_rs = NimbleDigest::from_bytes(&group_identity).unwrap();
    let view_tail_metablock_rs = MetaBlock::from_bytes(&view_tail_metablock).unwrap();
    let block_hash_rs = NimbleDigest::from_bytes(&block_hash).unwrap();
    let res = self.state.initialize_state(
      &group_identity_rs,
      &ledger_tail_map_rs,
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
        let ledger_tail_map_proto: Vec<LedgerTailMapEntry> = ledger_tail_map
          .iter()
          .map(|(handle, metablock)| LedgerTailMapEntry {
            handle: handle.to_bytes(),
            metablock: metablock.to_bytes(),
          })
          .collect();
        let reply = ReadStateResp {
          receipt: receipt.to_bytes().to_vec(),
          mode: endorser_mode as i32,
          ledger_tail_map: ledger_tail_map_proto,
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
    let ledger_tail_maps_rs: HashMap<NimbleDigest, LedgerTailMap> = ledger_tail_maps
      .into_iter()
      .map(|m| {
        let ledger_tail_map_rs = m
          .entries
          .into_iter()
          .map(|e| {
            (
              NimbleDigest::from_bytes(&e.handle).unwrap(),
              MetaBlock::from_bytes(&e.metablock).unwrap(),
            )
          })
          .collect();
        (
          produce_hash_of_state(&ledger_tail_map_rs),
          ledger_tail_map_rs,
        )
      })
      .collect();
    let ledger_chunks_rs: Vec<LedgerChunk> = ledger_chunks
      .into_iter()
      .map(|e| LedgerChunk {
        handle: NimbleDigest::from_bytes(&e.handle).unwrap(),
        hash: NimbleDigest::from_bytes(&e.hash).unwrap(),
        height: e.height as usize,
        block_hashes: e
          .block_hashes
          .iter()
          .map(|b| NimbleDigest::from_bytes(b).unwrap())
          .collect(),
      })
      .collect();
    let receipts_rs = Receipts::from_bytes(&receipts).unwrap();

    let res = self.state.activate(
      &old_config,
      &new_config,
      &ledger_tail_maps_rs,
      &ledger_chunks_rs,
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

  println!("Endorser host listening on {:?}", addr);

  Server::builder()
    .add_service(EndorserCallServer::new(server))
    .serve(addr)
    .await?;

  Ok(())
}
