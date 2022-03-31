use crate::endorser_state::EndorserState;
use crate::errors::EndorserError;
use clap::{App, Arg};
use ledger::{signature::PublicKeyTrait, CustomSerde, MetaBlock, NimbleDigest};
use std::collections::HashMap;
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
  GetPublicKeyResp, InitializeStateReq, InitializeStateResp, LedgerTailMapEntry, NewLedgerReq,
  NewLedgerResp, ReadLatestReq, ReadLatestResp, ReadLatestStateReq, ReadLatestStateResp,
  ReadLatestViewLedgerReq, ReadLatestViewLedgerResp, UnlockReq, UnlockResp,
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
      pk: pk.to_bytes().to_vec(),
    };

    Ok(Response::new(reply))
  }

  async fn new_ledger(
    &self,
    req: Request<NewLedgerReq>,
  ) -> Result<Response<NewLedgerResp>, Status> {
    let NewLedgerReq {
      handle,
      ignore_lock,
    } = req.into_inner();
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

    let receipt = endorser
      .new_ledger(&handle, ignore_lock)
      .expect("Unable to get the signature on genesis handle");

    let reply = NewLedgerResp {
      receipt: receipt.to_bytes().to_vec(),
    };
    Ok(Response::new(reply))
  }

  async fn append(&self, req: Request<AppendReq>) -> Result<Response<AppendResp>, Status> {
    let AppendReq {
      handle,
      block_hash,
      expected_height,
      ignore_lock,
    } = req.into_inner();

    let handle_instance = NimbleDigest::from_bytes(&handle);
    let block_hash_instance = NimbleDigest::from_bytes(&block_hash);

    if handle_instance.is_err() || block_hash_instance.is_err() {
      return Err(Status::invalid_argument("Invalid input sizes"));
    }

    let mut endorser_state = self.state.write().expect("Unable to obtain write lock");
    let res = endorser_state.append(
      &handle_instance.unwrap(),
      &block_hash_instance.unwrap(),
      expected_height as usize,
      ignore_lock,
    );

    match res {
      Ok(receipt) => {
        let reply = AppendResp {
          receipt: receipt.to_bytes().to_vec(),
        };
        Ok(Response::new(reply))
      },

      Err(error) => match error {
        EndorserError::OutOfOrderAppend => Err(Status::failed_precondition("Out of order append")),
        EndorserError::InvalidLedgerName => Err(Status::not_found("Ledger handle not found")),
        EndorserError::LedgerHeightOverflow => Err(Status::out_of_range("Ledger height overflow")),
        EndorserError::InvalidTailHeight => Err(Status::already_exists("Invalid ledgher height")),
        _ => Err(Status::aborted("Failed to append")),
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
    let latest_state = self.state.read().expect("Failed to acquire read lock");
    let res = latest_state.read_latest(&handle, &nonce);

    match res {
      Ok(receipt) => {
        let reply = ReadLatestResp {
          receipt: receipt.to_bytes().to_vec(),
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
    let AppendViewLedgerReq {
      block_hash,
      expected_height,
    } = req.into_inner();

    let block_hash_instance = NimbleDigest::from_bytes(&block_hash);

    if block_hash_instance.is_err() {
      return Err(Status::invalid_argument("Invalid input sizes"));
    }

    let mut endorser_state = self.state.write().expect("Unable to obtain write lock");
    let res =
      endorser_state.append_view_ledger(&block_hash_instance.unwrap(), expected_height as usize);

    match res {
      Ok(receipt) => {
        let reply = AppendViewLedgerResp {
          receipt: receipt.to_bytes().to_vec(),
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
      Ok(receipt) => {
        let reply = ReadLatestViewLedgerResp {
          receipt: receipt.to_bytes().to_vec(),
        };
        Ok(Response::new(reply))
      },
      Err(_) => Err(Status::aborted("Failed to process read_latest_view_ledger")),
    }
  }

  async fn initialize_state(
    &self,
    req: Request<InitializeStateReq>,
  ) -> Result<Response<InitializeStateResp>, Status> {
    let InitializeStateReq {
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
    let view_tail_metablock_rs = MetaBlock::from_bytes(&view_tail_metablock).unwrap();
    let block_hash_rs = NimbleDigest::from_bytes(&block_hash).unwrap();
    let res = self
      .state
      .write()
      .expect("Failed to acquire write lock")
      .initialize_state(
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
      Err(_) => Err(Status::aborted("Failed to endorse_state")),
    }
  }

  async fn read_latest_state(
    &self,
    request: Request<ReadLatestStateReq>,
  ) -> Result<Response<ReadLatestStateResp>, Status> {
    let ReadLatestStateReq { to_lock } = request.into_inner();

    if to_lock {
      self
        .state
        .write()
        .expect("Failed to acquire write lock")
        .lock();
    }

    let res = self
      .state
      .read()
      .expect("Failed to acquire read lock")
      .read_latest_state();

    if res.is_err() {
      return Err(Status::aborted("Failed to read latest state"));
    }

    let ledger_view = res.unwrap();
    let ledger_tail_map: Vec<LedgerTailMapEntry> = ledger_view
      .ledger_tail_map
      .iter()
      .map(|(handle, metablock)| LedgerTailMapEntry {
        handle: handle.to_bytes(),
        metablock: metablock.to_bytes(),
      })
      .collect();
    let reply = ReadLatestStateResp {
      ledger_tail_map,
      view_tail_metablock: ledger_view.view_tail_metablock.to_bytes().to_vec(),
    };
    Ok(Response::new(reply))
  }

  async fn unlock(&self, _req: Request<UnlockReq>) -> Result<Response<UnlockResp>, Status> {
    self
      .state
      .write()
      .expect("Failed to acquire write lock")
      .unlock();

    let reply = UnlockResp {};
    Ok(Response::new(reply))
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
        .help("The port number to run the Service On. Default: 9096")
        .default_value("9090")
        .index(1),
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
