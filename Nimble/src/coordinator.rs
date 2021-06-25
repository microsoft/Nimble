mod store;

use crate::store::Store;
use protocol::call_server::{Call, CallServer};
use protocol::{Data, LedgerRequest, LedgerResponse, Query, UpdateQuery};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use uuid::Uuid;

pub mod protocol {
  tonic::include_proto!("protocol");
}

#[derive(Debug, Default)]
pub struct CoordinatorState {
  state: Arc<RwLock<Store>>,
}

#[derive(Debug, Default)]
pub struct CallServiceStub {}

impl CoordinatorState {
  pub fn new() -> Self {
    CoordinatorState {
      state: Arc::new(RwLock::new(Store {
        ledgers: HashMap::new(),
      })),
    }
  }
}

#[tonic::async_trait]
impl Call for CoordinatorState {
  async fn new_ledger(
    &self,
    request: Request<LedgerRequest>,
  ) -> Result<Response<LedgerResponse>, Status> {
    let LedgerRequest { name } = request.into_inner();

    println!("Received a NewLedger Request : {:?}", name);
    let unique_ledger_id = Uuid::new_v4();
    println!("{:?}", unique_ledger_id.to_string());
    let reply = protocol::LedgerResponse {
      handle: unique_ledger_id.to_string(),
    };
    let value: Vec<u8> = name.as_bytes().to_vec();

    let mut store = self.state.write().expect("Failed to acquire lock on state");
    store.set(unique_ledger_id.to_string(), value);

    let r = store.get(unique_ledger_id.to_string());
    println!("Something in state: {:?}", r);

    let ledgers_available = store.get_all_ledgers_handles();
    println!("Ledgers in State: {:?}", ledgers_available);

    Ok(Response::new(reply))
  }

  async fn append_to_ledger(
    &self,
    request: Request<UpdateQuery>,
  ) -> Result<Response<protocol::Status>, Status> {
    let UpdateQuery { handle, value } = request.into_inner();
    println!(
      "Received a AppendToLedger Request : {:?} {:?}",
      handle, value
    );

    let mut store = self.state.write().expect("Failed to acquire lock on state");
    let content: Vec<u8> = value.unwrap().content;
    store.set(handle, content.to_vec());

    let reply = protocol::Status { status: true };

    Ok(Response::new(reply))
  }

  async fn read_latest(
    &self,
    request: Request<Query>,
  ) -> Result<Response<protocol::Response>, Status> {
    let Query { handle, index: _ } = request.into_inner();
    // index has to ideally not exist in the query, TODO: explore "optional"
    println!("Received a ReadLatest Request : {:?}", handle);

    let value = self
      .state
      .read()
      .expect("Failed to acquire read lock")
      .get_latest_state_of_ledger(handle);

    let reply = protocol::Response {
      value: Some(Data { content: value }),
    };

    Ok(Response::new(reply))
  }

  async fn read_at_index(
    &self,
    request: Request<Query>,
  ) -> Result<Response<protocol::Response>, Status> {
    println!("Received a ReadAtIndex Request : {:?}", request);

    let Query { handle, index } = request.into_inner();
    // index has to ideally not exist in the query, TODO: explore "optional"
    println!("Received a ReadLatest Request : {:?}", handle);

    let value = self
      .state
      .read()
      .expect("Failed to acquire read lock")
      .get_ledger_state_at_index(handle, index);

    let reply = protocol::Response {
      value: Some(Data { content: value }),
    };

    Ok(Response::new(reply))
  }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  #[rustfmt::skip]
    let addr = "[::1]:8080".parse()?;
  let server = CoordinatorState::new();

  println!("Running gRPC Coordinator Service at {:?}", addr);

  Server::builder()
    .add_service(CallServer::new(server))
    .serve(addr)
    .await?;

  Ok(())
}
