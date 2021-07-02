mod errors;
mod helper;
mod network;
mod store;

use crate::network::EndorserConnection;
use crate::store::AppendOnlyStore;
use ed25519_dalek::Signature;
use std::sync::{Arc, RwLock};
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use uuid::Uuid;

pub mod coordinator_proto {
  tonic::include_proto!("coordinator_proto");
}

use coordinator_proto::call_server::{Call, CallServer};
use coordinator_proto::{
  AppendReq, AppendResp, NewLedgerReq, NewLedgerResp, ReadByIndexReq, ReadByIndexResp,
  ReadLatestReq, ReadLatestResp,
};

type Handle = Vec<u8>;
type Block = Vec<u8>;

//#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
//pub struct Handle {
//  handle: Vec<u8>, // TODO: make this a typed digest
//}

//#[derive(Clone, Debug, Default)]
//pub struct Block {
//  block: Vec<u8>,
//}

#[derive(Clone, Debug, Default)]
pub struct MetaBlock {
  pub metadata: Vec<u8>, // TODO: make this a typed tuple
  pub signatures: Vec<Signature>,
}

pub type DataStore = AppendOnlyStore<Handle, Block>;
pub type MetadataStore = AppendOnlyStore<Handle, MetaBlock>;

#[derive(Debug, Default)]
pub struct CoordinatorState {
  data_store: Arc<RwLock<DataStore>>,
  metadata_store: Arc<RwLock<MetadataStore>>,
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
      data_store: Arc::new(RwLock::new(DataStore::new())),
      metadata_store: Arc::new(RwLock::new(MetadataStore::new())),
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
    _request: Request<NewLedgerReq>,
  ) -> Result<Response<NewLedgerResp>, Status> {
    // Generate a Unique Value
    let nonce = {
      let unique_ledger_id = Uuid::new_v4();
      let value = unique_ledger_id.as_bytes().to_vec();
      value
    };

    // Pick an endorser for the new ledger
    let mut conn = self.get_random_endorser_connection();
    let (endorser_pk, endorser_attestation) = conn.get_endorser_keyinformation().unwrap();

    // Package the contents into a Block, TODO(@sudheesh): Enhance as needed. Currently bytes
    let genesis_block = {
      let mut genesis_block_bytes: Vec<u8> = Vec::new();
      genesis_block_bytes.append(&mut endorser_pk.clone().to_bytes().to_vec());
      genesis_block_bytes.append(&mut endorser_attestation.clone().to_bytes().to_vec());
      genesis_block_bytes.append(&mut nonce.clone().to_vec());
      genesis_block_bytes
    };

    // Hash the contents of the block to use as the handle.
    let handle = helper::hash(genesis_block.as_slice()).to_vec();

    {
      // Write the genesis block to data store
      let mut data_store_handle = self
        .data_store
        .write()
        .expect("Failed to acquire lock on the data store");
      let res = data_store_handle.insert(&handle, &genesis_block);
      assert!(res.is_ok());
    }

    // Make a request to the endorser for NewLedger using the handle which returns a signature.
    let endorser_response = conn
      .call_endorser_new_ledger(handle.to_vec())
      .await
      .unwrap();

    // Prepare a metadata block
    let meta_block = {
      let metadata = {
        let zero_entry = [0u8; 32].to_vec();
        let ledger_height = 0u64.to_be_bytes().to_vec();
        let mut message: Vec<u8> = vec![];
        message.extend(zero_entry);
        message.extend(handle.to_vec());
        message.extend(ledger_height);
        message
      };

      // TODO(@sudheesh): LATER (Retrieve signatures from all/quorum of endorsers)
      let signatures = vec![endorser_response.clone()];

      MetaBlock {
        metadata,
        signatures,
      }
    };

    {
      // Store the metadata block in the metadata store
      let mut metadata_store_handle = self
        .metadata_store
        .write()
        .expect("Failed to acquire lock on the data store");
      let res = metadata_store_handle.insert(&handle, &meta_block);
      assert!(res.is_ok()); // TODO: do error handling
    }

    let reply = NewLedgerResp {
      block: genesis_block.clone().to_vec(),
      signature: endorser_response.to_bytes().to_vec(),
    };
    Ok(Response::new(reply))
  }

  async fn append(&self, request: Request<AppendReq>) -> Result<Response<AppendResp>, Status> {
    let AppendReq {
      handle,
      block,
      cond_tail_hash,
    } = request.into_inner();

    let hash_of_block = helper::hash(&block).to_vec();

    // Write the block to the data store
    {
      let mut data_store_handle = self
        .data_store
        .write()
        .expect("Failed to acquire lock on state");
      let res = data_store_handle.append(&handle, &block);
      assert!(res.is_ok());
    }

    // Ideally need to run multiple times for multiple endorsers.
    let mut conn = self.get_random_endorser_connection();
    let (tail_hash, height, signature) = conn
      .call_endorser_append(
        handle.clone(),
        hash_of_block.clone(),
        cond_tail_hash.clone(),
      )
      .await
      .unwrap();

    {
      let meta_block = {
        let metadata =
          helper::pack_metadata_information(tail_hash.clone(), hash_of_block, height as usize);
        let signatures = vec![signature.clone()];
        MetaBlock {
          metadata,
          signatures,
        }
      };

      let mut metadata_store_handle = self
        .metadata_store
        .write()
        .expect("Failed to acquire lock on state");
      let res = metadata_store_handle.append(&handle, &meta_block);
      assert!(res.is_ok());
    }

    let reply = AppendResp {
      tail_hash,
      height,
      signature: signature.to_bytes().to_vec(),
    };

    Ok(Response::new(reply))
  }

  async fn read_latest(
    &self,
    request: Request<ReadLatestReq>,
  ) -> Result<Response<ReadLatestResp>, Status> {
    let ReadLatestReq { handle, nonce } = request.into_inner();

    // 1. Read the information from the Endorser
    let mut conn = self.get_random_endorser_connection();
    let signature = conn
      .call_endorser_read_latest(handle.clone(), nonce)
      .await
      .unwrap();

    // 2. ReadLatest Block data from the Data structure.
    let read_lock_state_data = self
      .data_store
      .read()
      .expect("Failed to acquire read lock on the data store");
    let block = read_lock_state_data.read_latest(&handle).unwrap(); // TODO: do error handling

    // 3. Read latest metablock and signatures from Metadata structure
    let read_lock_state_metadata = self
      .metadata_store
      .read()
      .expect("Failed to acquire read lock on the metadata store");
    let metavalue = read_lock_state_metadata.read_latest(&handle).unwrap(); // TODO: do error handling
    let (tail_hash, _block_hash, height) = helper::unpack_metadata_information(metavalue.metadata);

    // 4. Pack the response structure (m, \sigma) from metadata structure
    //    to m = (T, b, c)
    let reply = ReadLatestResp {
      block,
      tail_hash,
      height,
      signature: signature.to_bytes().to_vec(),
    };

    Ok(Response::new(reply))
  }

  async fn read_by_index(
    &self,
    request: Request<ReadByIndexReq>,
  ) -> Result<Response<ReadByIndexResp>, Status> {
    let ReadByIndexReq { handle, index } = request.into_inner();

    // 1. Retrieve the block data information from the main datastructure
    let block = {
      let read_data_instance = self.data_store.read().expect("Failed to acquire read lock");
      read_data_instance
        .read_by_index(&handle, index as usize)
        .unwrap() // TODO: perform error handling
    };

    let metadata = {
      let read_metadata_instance = self
        .metadata_store
        .read()
        .expect("Failed to acquire read lock");
      read_metadata_instance
        .read_by_index(&handle, index as usize)
        .unwrap() // TODO: perform error handling
    };

    // 2. Retrieve the information from the metadata structure.
    let (tail_hash, _block_hash, _height) = helper::unpack_metadata_information(metadata.metadata);

    // Force only one for now. TODO(@sudheesh): Multiple endorser case.
    let signature = metadata.signatures.get(0).unwrap().to_bytes().to_vec();
    // 3. TODO(@sudheesh): Pack the information as necessary and submit the response.
    let reply = ReadByIndexResp {
      block,
      tail_hash,
      signature,
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
