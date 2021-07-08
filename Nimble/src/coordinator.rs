mod errors;
mod ledger;
mod network;
mod store;

use crate::ledger::{
  Block, CustomSerde, EndorsedMetaBlock, MetaBlock, NimbleDigest, NimbleHashTrait,
};
use crate::network::EndorserConnection;
use crate::store::AppendOnlyStore;
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

type Handle = NimbleDigest;

pub type DataStore = AppendOnlyStore<Handle, Block>;
pub type MetadataStore = AppendOnlyStore<Handle, EndorsedMetaBlock>;

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
    _req: Request<NewLedgerReq>,
  ) -> Result<Response<NewLedgerResp>, Status> {
    // Generate a Unique Value
    let nonce = Uuid::new_v4().as_bytes().to_vec();

    // Pick an endorser for the new ledger
    let mut conn = self.get_random_endorser_connection();
    let pk = conn.get_public_key().unwrap();

    // Package the contents into a Block
    let genesis_block = Block::new(&[pk.to_bytes().to_vec(), nonce.to_vec()].concat());

    // Hash the contents of the block to use as the handle.
    let handle = genesis_block.hash();

    // Write the genesis block to data store
    {
      let mut data_store_handle = self
        .data_store
        .write()
        .expect("Failed to acquire lock on the data store");
      let res = data_store_handle.insert(&handle, &genesis_block);
      assert!(res.is_ok());
    }

    // Make a request to the endorser for NewLedger using the handle which returns a signature.
    let endorser_response = conn.new_ledger(handle.to_bytes()).await.unwrap();

    // Prepare a metadata block
    let endorsed_meta_block =
      EndorsedMetaBlock::new(&MetaBlock::genesis(&handle), &[endorser_response]);

    {
      // Store the metadata block in the metadata store
      let mut metadata_store_handle = self
        .metadata_store
        .write()
        .expect("Failed to acquire lock on the data store");
      let res = metadata_store_handle.insert(&handle, &endorsed_meta_block);
      assert!(res.is_ok()); // TODO: do error handling
    }

    let reply = NewLedgerResp {
      block: genesis_block.to_bytes(),
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

    let handle_instance = NimbleDigest::from_bytes(&handle);
    if handle_instance.is_err() {
      return Err(Status::invalid_argument("Incorrect Handle Provided"));
    }
    let handle_info = handle_instance.unwrap();
    let data_block = Block::new(&block);
    let hash_of_block = data_block.hash();

    // Write the block to the data store
    {
      let mut data_store_handle = self
        .data_store
        .write()
        .expect("Failed to acquire lock on state");
      let res = data_store_handle.append(&handle_info, &data_block);
      assert!(res.is_ok());
    }

    let mut conn = self.get_random_endorser_connection();
    let (tail_hash, height, signature) = conn
      .append(
        handle_info.to_bytes(),
        hash_of_block.to_bytes(),
        cond_tail_hash.clone(),
      )
      .await
      .unwrap();

    {
      let endorsed_metablock = {
        let prev_hash = {
          let d = NimbleDigest::from_bytes(&tail_hash);
          if d.is_err() {
            return Err(Status::invalid_argument(
              "Incorrect tail hash size from Endorser",
            ));
          }
          d.unwrap()
        };
        let metadata = MetaBlock::new(&prev_hash, &hash_of_block, height as usize);
        let signatures = vec![signature];
        EndorsedMetaBlock::new(&metadata, &signatures)
      };

      let mut metadata_store_handle = self
        .metadata_store
        .write()
        .expect("Failed to acquire lock on state");
      let res = metadata_store_handle.append(&handle_info, &endorsed_metablock);
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

    let handle_instance = NimbleDigest::from_bytes(&handle);
    if handle_instance.is_err() {
      return Err(Status::invalid_argument("Incorrect Handle Provided"));
    }
    let handle_info = handle_instance.unwrap();

    // 1. Read the information from the Endorser
    let mut conn = self.get_random_endorser_connection();
    let signature = conn
      .read_latest(handle_info.to_bytes(), nonce)
      .await
      .unwrap();

    // 2. ReadLatest Block data from the Data structure.
    let read_lock_state_data = self
      .data_store
      .read()
      .expect("Failed to acquire read lock on the data store");
    let block_op = read_lock_state_data.read_latest(&handle_info);
    if block_op.is_err() {
      return Err(Status::invalid_argument(
        "No data exists for the given handle",
      ));
    }
    let block = block_op.unwrap();

    // 3. Read latest metablock and signatures from Metadata structure
    let read_lock_state_metadata = self
      .metadata_store
      .read()
      .expect("Failed to acquire read lock on the metadata store");
    let metavalue = read_lock_state_metadata.read_latest(&handle_info);

    if metavalue.is_err() {
      return Err(Status::invalid_argument(
        "No metadata exists for the given handle",
      ));
    }
    let metadata = metavalue.unwrap();
    // 4. Pack the response structure (m, \sigma) from metadata structure
    //    to m = (T, b, c)
    let reply = ReadLatestResp {
      block: block.to_bytes(),
      tail_hash: metadata.get_tail_hash().to_bytes(),
      height: metadata.get_height() as u64,
      signature: signature.to_bytes().to_vec(), // Ideally collected signatures from majority endorsers
    };

    Ok(Response::new(reply))
  }

  async fn read_by_index(
    &self,
    request: Request<ReadByIndexReq>,
  ) -> Result<Response<ReadByIndexResp>, Status> {
    let ReadByIndexReq { handle, index } = request.into_inner();

    let handle_instance = NimbleDigest::from_bytes(&handle);
    if handle_instance.is_err() {
      return Err(Status::invalid_argument("Incorrect Handle Provided"));
    }
    let handle_info = handle_instance.unwrap();

    // 1. Retrieve the block data information from the main datastructure
    let block = {
      let read_data_instance = self.data_store.read().expect("Failed to acquire read lock");
      read_data_instance
        .read_by_index(&handle_info, index as usize)
        .unwrap() // TODO: perform error handling
    };

    let metadata = {
      let read_metadata_instance = self
        .metadata_store
        .read()
        .expect("Failed to acquire read lock");
      read_metadata_instance
        .read_by_index(&handle_info, index as usize)
        .unwrap() // TODO: perform error handling
    };

    // 2. Retrieve the information from the metadata structure.
    let tail_hash = metadata.get_tail_hash();

    // Force only one for now. TODO(@sudheesh): Multiple endorser case.
    let signatures = metadata.get_receipts();
    // TEMP: There's only one signature for now until multiple endorsers are available
    let signature = signatures.get(0).unwrap().to_bytes().to_vec();
    // 3. TODO(@sudheesh): Pack the information as necessary and submit the response.
    let reply = ReadByIndexResp {
      block: block.to_bytes(),
      tail_hash: tail_hash.to_bytes(),
      signature,
    };

    Ok(Response::new(reply))
  }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let addr = "[::1]:8080".parse()?;
  let server = CoordinatorState::new().await;

  println!("Running gRPC Coordinator Service at {:?}", addr);

  Server::builder()
    .add_service(CallServer::new(server))
    .serve(addr)
    .await?;

  Ok(())
}
