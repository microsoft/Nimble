mod helper;
mod network;
mod store;

use crate::network::EndorserConnection;
use crate::store::Store;
use protocol::call_server::{Call, CallServer};
use protocol::{LedgerResponse, Query, UpdateQuery};
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
  endorser_connections: Vec<EndorserConnection>,
}

#[derive(Debug, Default)]
pub struct CallServiceStub {}

impl CoordinatorState {
  pub async fn new() -> Self {
    // Ideally read this information from a configuration file.
    let available_endorsers: Vec<&str> = vec!["http://[::1]:9090"];
    // Create EndorserConnections from here
    let mut endorsers: Vec<EndorserConnection> = vec![];
    for endorser_connection_address in available_endorsers.iter() {
      let connection = EndorserConnection::new(endorser_connection_address.to_string())
        .await
        .unwrap();
      endorsers.push(connection);
    }
    CoordinatorState {
      state: Arc::new(RwLock::new(Store::new())),
      endorser_connections: endorsers,
    }
  }

  pub fn get_random_endorser_connection(&self) -> EndorserConnection {
    // TODO(@sudheesh): Read from the actual size of the array and pick at random.
    // This is a debug only method, testing purposes.
    self.endorser_connections.get(0).unwrap().clone()
  }
}

#[tonic::async_trait]
impl Call for CoordinatorState {
  async fn new_ledger(
    &self,
    _request: Request<protocol::Empty>,
  ) -> Result<Response<LedgerResponse>, Status> {
    println!("Received a NewLedger Request");

    // 1. Generate a Unique Value
    let unique_ledger_id = Uuid::new_v4();
    let value = unique_ledger_id.as_bytes().to_vec();
    println!("N: {:?}, size: {:?}", value, value.len());

    // 2. Package the contents into a Block, TODO(@sudheesh): Enhance as needed. Currently bytes
    let mut conn = self.get_random_endorser_connection();
    let (endorser_pk, endorser_attestation) = conn.get_endorser_keyinformation().unwrap();
    let mut genesis_block_bytes: Vec<u8> = Vec::new();
    genesis_block_bytes.append(&mut endorser_pk.clone().to_bytes().to_vec());
    genesis_block_bytes.append(&mut endorser_attestation.clone().to_bytes().to_vec());
    genesis_block_bytes.append(&mut value.clone().to_vec());
    println!(
      "Genesis Block: {:?}, size: {:?}",
      genesis_block_bytes,
      genesis_block_bytes.len()
    );

    // 3. Hash the contents of the block to use as the handle.
    let handle = helper::hash(genesis_block_bytes.as_slice()).to_vec();

    // Make a request to the endorser for NewLedger using the handle which returns a signature.
    let ledger_response = conn
      .call_endorser_new_ledger(handle.to_vec())
      .await
      .unwrap();
    println!("Endorser Signature: {:?}", ledger_response);

    let zero_entry = [0u8; 32].to_vec();
    let ledger_height = 0u64.to_be_bytes().to_vec();
    let mut message: Vec<u8> = vec![];
    message.extend(zero_entry);
    message.extend(handle.to_vec());
    message.extend(ledger_height);
    println!("Message: {:?}, size: {:?}", message, message.len());

    let mut store = self.state.write().expect("Failed to acquire lock on state");
    store.set(handle.to_vec(), genesis_block_bytes.clone());
    // TODO(@sudheesh): LATER (Retrieve signatures from all/quorum of endorsers)
    let all_signatures = vec![ledger_response.clone()];
    store.set_metadata(&handle, &message, &all_signatures);

    let reply = protocol::LedgerResponse {
      block_data: genesis_block_bytes.clone().to_vec(),
      signature: ledger_response.to_bytes().to_vec(),
    };
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

    let content: Vec<u8> = value.unwrap().content;
    let hash_of_block = helper::hash(&content).to_vec();

    {
      let mut store = self.state.write().expect("Failed to acquire lock on state");
      store.set(handle.clone(), content.to_vec());
    }

    // Ideally need to run multiple times for multiple endorsers.
    let mut conn = self.get_random_endorser_connection();
    let (tail_hash, ledger_height, signature) = conn
      .call_endorser_append(handle.clone(), hash_of_block.clone())
      .await
      .unwrap();

    {
      let metadata =
        helper::pack_metadata_information(tail_hash.clone(), hash_of_block, ledger_height);
      let metadata_signatures = vec![signature.clone()];
      let mut store = self.state.write().expect("Failed to acquire lock on state");
      store.set_metadata(&handle.clone(), &metadata, &metadata_signatures);
    }

    let reply = protocol::Status {
      tail_hash,
      ledger_height,
      signature: signature.to_bytes().to_vec(),
    };

    Ok(Response::new(reply))
  }

  async fn read_latest(
    &self,
    request: Request<Query>,
  ) -> Result<Response<protocol::Response>, Status> {
    let Query {
      handle,
      index: _,
      nonce,
    } = request.into_inner();
    // index has to ideally not exist in the query, TODO: explore "optional"
    println!("Received a ReadLatest Request : {:?} {:?}", handle, nonce);

    // 1. Read the information from the Endorser
    let mut conn = self.get_random_endorser_connection();
    let freshness_signature = conn
      .call_endorser_read_latest(handle.clone(), nonce)
      .await
      .unwrap();

    let read_lock_state = self.state.read().expect("Failed to acquire read lock");
    // 2. ReadLatest Block data from the Data structure.
    let value = read_lock_state.get_latest_state_of_ledger(handle.clone());

    // 3. Read latest metablock and signatures from Metadata structure
    let metavalue = read_lock_state.get_latest_state_of_metadata_ledger(handle.clone());
    let (tail_hash, _block_hash, ledger_height) =
      helper::unpack_metadata_information(metavalue.message_data);

    // 4. Pack the response structure (m, \sigma) from metadata structure
    //    to m = (T, b, c)
    let reply = protocol::Response {
      // Update the value as necessary.
      block_data: value,
      tail_hash,
      ledger_height,
      endorser_signature: freshness_signature.to_bytes().to_vec(),
    };

    Ok(Response::new(reply))
  }

  async fn read_at_index(
    &self,
    request: Request<Query>,
  ) -> Result<Response<protocol::Response>, Status> {
    println!("Received a ReadAtIndex Request : {:?}", request);

    let Query {
      handle,
      index,
      nonce: _,
    } = request.into_inner();
    // index has to ideally not exist in the query, TODO: explore "optional"
    println!("Received a ReadLatest Request : {:?}", handle);

    let read_state_instance = self.state.read().expect("Failed to acquire read lock");

    // 1. Retrieve the block data information from the main datastructure
    let value_at_index =
      read_state_instance.get_ledger_state_at_index(handle.clone(), index.clone());
    let metadata_at_index =
      read_state_instance.get_metadata_ledger_state_at_index(handle.clone(), index.clone());

    println!("Block Data at index: {:?}", value_at_index);
    println!("Metadata at index: {:?}", metadata_at_index);

    // 2. Retrieve the information from the metadata structure.
    let (tail_hash, _block_hash, ledger_height) =
      helper::unpack_metadata_information(metadata_at_index.message_data);

    // Force only one for now. TODO(@sudheesh): Multiple endorser case.
    let endorser_signature = metadata_at_index
      .signatures
      .get(0)
      .unwrap()
      .to_bytes()
      .to_vec();
    // 3. TODO(@sudheesh): Pack the information as necessary and submit the response.
    let reply = protocol::Response {
      block_data: value_at_index,
      tail_hash,
      ledger_height, // TODO: Ideally optional.
      endorser_signature,
    };

    Ok(Response::new(reply))
  }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  #[rustfmt::skip]
    let addr = "[::1]:8080".parse()?;
  let server = CoordinatorState::new().await;

  println!("Running gRPC Coordinator Service at {:?}", addr);

  Server::builder()
    .add_service(CallServer::new(server))
    .serve(addr)
    .await?;

  Ok(())
}
