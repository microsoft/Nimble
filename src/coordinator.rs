mod errors;
mod ledger;
mod network;
mod store;

use crate::ledger::{
  Block, CustomSerde, EndorsedMetaBlock, MetaBlock, NimbleDigest, NimbleHashTrait, Nonce,
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

use crate::errors::CoordinatorError;
use clap::{App, Arg};
use coordinator_proto::call_server::{Call, CallServer};
use coordinator_proto::{
  AppendReq, AppendResp, IdSig, NewLedgerReq, NewLedgerResp, ReadByIndexReq, ReadByIndexResp,
  ReadLatestReq, ReadLatestResp, Receipt,
};
use ed25519_dalek::PublicKey;
use std::collections::HashMap;

type Handle = NimbleDigest;

pub type DataStore = AppendOnlyStore<Handle, Block>;
pub type MetadataStore = AppendOnlyStore<Handle, EndorsedMetaBlock>;

#[derive(Debug, Default)]
pub struct ConnectionStore {
  store: HashMap<Vec<u8>, EndorserConnection>,
}

impl ConnectionStore {
  pub fn new() -> ConnectionStore {
    ConnectionStore {
      store: HashMap::new(),
    }
  }

  pub fn insert(&mut self, key: &[u8], val: &EndorserConnection) -> Result<(), CoordinatorError> {
    if self.store.contains_key(key) {
      return Err(CoordinatorError::EndorserAlreadyExists);
    }

    self.store.insert(key.to_owned(), val.clone());
    Ok(())
  }

  pub fn multi_get(
    &self,
    pk_vec: &[PublicKey],
  ) -> Result<Vec<EndorserConnection>, CoordinatorError> {
    let ec_vec = (0..pk_vec.len())
      .map(|i| self.store.get(&pk_vec[i].to_bytes().to_vec()))
      .filter(|e| e.is_some())
      .map(|e| e.unwrap().clone())
      .collect::<Vec<EndorserConnection>>();

    // if we encountered any public keys that don't exist in the store
    // return an error
    if ec_vec.len() != pk_vec.len() {
      Err(CoordinatorError::UnableToFindEndorserClient)
    } else {
      Ok(ec_vec)
    }
  }

  fn get_all_keys(&self) -> Vec<PublicKey> {
    // TODO: we can avoid ec.get_public_key() if keys are PublicKey objects
    self
      .store
      .iter()
      .map(|(_pk, ec)| ec.get_public_key().unwrap())
      .collect::<Vec<PublicKey>>()
  }
}

#[derive(Debug, Default)]
pub struct CommitteeStore {
  store: HashMap<Handle, Vec<PublicKey>>,
}

impl CommitteeStore {
  pub fn new() -> Self {
    CommitteeStore {
      store: HashMap::new(),
    }
  }

  pub fn insert(&mut self, key: &Handle, val: &[PublicKey]) -> Result<(), CoordinatorError> {
    if self.store.contains_key(key) {
      return Err(CoordinatorError::HandleAlreadyExists);
    }

    self.store.insert(*key, val.to_vec());
    Ok(())
  }

  pub fn get(&self, key: &Handle) -> Result<Vec<PublicKey>, CoordinatorError> {
    if !self.store.contains_key(key) {
      return Err(CoordinatorError::UnableToFindHandle);
    }

    Ok(self.store.get(key).unwrap().to_vec())
  }
}

#[derive(Debug, Default)]
pub struct CoordinatorState {
  data: Arc<RwLock<DataStore>>,
  metadata: Arc<RwLock<MetadataStore>>,
  committee: Arc<RwLock<CommitteeStore>>, // a map from a handle to a vector of public keys
  connections: Arc<RwLock<ConnectionStore>>, // a map from a public key to a connection object
}

#[derive(Debug, Default)]
pub struct CallServiceStub {}

impl CoordinatorState {
  pub async fn new(hostnames: Vec<&str>) -> Self {
    let mut connections = ConnectionStore::new();

    // Connect in series. TODO: Make these requests async and concurrent and read from a config file.
    for hostname in hostnames {
      let conn = EndorserConnection::new(hostname.to_string()).await;
      if conn.is_err() {
        panic!(
          "Unable to connect to an endorser service at {:?} with err: {:?}",
          hostname.to_string(),
          conn
        );
      }
      println!("Connected Successfully to {:?}", &hostname);

      let conn = conn.unwrap();
      let pk = conn.get_public_key().unwrap();
      let res = connections.insert(&pk.to_bytes().to_vec(), &conn);
      if res.is_err() {
        panic!(
          "Error inserting the public key of {:?} into a map",
          hostname.to_string()
        );
      }
    }

    CoordinatorState {
      data: Arc::new(RwLock::new(DataStore::new())),
      metadata: Arc::new(RwLock::new(MetadataStore::new())),
      committee: Arc::new(RwLock::new(CommitteeStore::new())),
      connections: Arc::new(RwLock::new(connections)),
    }
  }

  pub fn get_endorser_connections(
    &self,
    pk_vec: &[PublicKey],
  ) -> Result<Vec<EndorserConnection>, CoordinatorError> {
    self
      .connections
      .read()
      .expect("Unable to get read lock")
      .multi_get(pk_vec)
  }
}

fn reformat_receipt(receipt: &[(usize, Vec<u8>)]) -> Receipt {
  let id_sigs = receipt
    .iter()
    .map(|(id, sig)| IdSig {
      pk_idx: *id as u64,
      sig: sig.clone(),
    })
    .collect();
  Receipt { id_sigs }
}

#[tonic::async_trait]
impl Call for CoordinatorState {
  async fn new_ledger(
    &self,
    _req: Request<NewLedgerReq>,
  ) -> Result<Response<NewLedgerResp>, Status> {
    // Generate a Unique Value
    let nonce = Uuid::new_v4().as_bytes().to_vec();

    // Retrieve all PublicKeys for endorsers
    // Ideally, the coordinator randomly chooses Quorum from the set of active endorsers
    // and uses those values in the genesis block for the creation of a new handle.
    // For now: All endorsers are used, so get_all_public_keys() is being used.
    // TODO: Later replace this with get_random_quorum_public_keys()
    let chosen_public_keys = self
      .connections
      .read()
      .expect("Unable to obtain read lock on connections")
      .get_all_keys();

    let endorser_connections: Vec<EndorserConnection> = {
      let ec_res = self.get_endorser_connections(&chosen_public_keys);
      if ec_res.is_err() {
        return Err(Status::aborted("Failed to Obtain Endorser Connection"));
      }
      ec_res.unwrap()
    };

    // Package the contents into a Block
    let genesis_block = Block::genesis(&chosen_public_keys, &nonce);

    // Hash the contents of the block to use as the handle.
    let handle = genesis_block.hash();

    {
      let mut handle_committee = self
        .committee
        .write()
        .expect("Failed to acquire lock on handle connections map");
      let handle_ins_op = handle_committee.insert(&handle, &chosen_public_keys);
      if handle_ins_op.is_err() {
        return Err(Status::aborted("Aborted due to Handle Already Existing"));
      }
    }

    // Write the genesis block to data store
    {
      let res = self
        .data
        .write()
        .expect("Failed to acquire lock on the data store")
        .insert(&handle, &genesis_block);
      assert!(res.is_ok());
    }

    // Make a request to the endorsers for NewLedger using the handle which returns a signature.
    let mut receipt_bytes: Vec<(usize, Vec<u8>)> = Vec::new();

    let mut responses = Vec::with_capacity(endorser_connections.len());
    for (index, ec) in endorser_connections.iter().enumerate() {
      let mut conn = ec.clone();

      responses.push(tokio::spawn(async move {
        (index, conn.new_ledger(&handle).await)
      }));
    }

    for resp in responses {
      let res = resp.await;
      if let Ok((index, Ok(sig))) = res {
        receipt_bytes.push((index, sig))
      }
    }

    // Prepare a metadata block
    let receipt = ledger::Receipt::from_bytes(&receipt_bytes);
    let endorsed_metablock = EndorsedMetaBlock::new(&MetaBlock::genesis(&handle), &receipt);

    // Store the metadata block in the metadata store
    {
      let res = self
        .metadata
        .write()
        .expect("Failed to acquire lock on the data store")
        .insert(&handle, &endorsed_metablock);
      assert!(res.is_ok()); // TODO: do error handling
    }

    let reply = NewLedgerResp {
      block: genesis_block.to_bytes(),
      receipt: Some(reformat_receipt(&receipt_bytes)),
    };
    Ok(Response::new(reply))
  }

  async fn append(&self, request: Request<AppendReq>) -> Result<Response<AppendResp>, Status> {
    let AppendReq {
      handle,
      block,
      cond_tail_hash,
    } = request.into_inner();

    let handle = {
      let h = NimbleDigest::from_bytes(&handle);
      if h.is_err() {
        return Err(Status::invalid_argument("Incorrect Handle Provided"));
      }
      h.unwrap()
    };
    let data_block = Block::new(&block);
    let hash_of_block = data_block.hash();

    let cond_tail_hash_info = {
      let d = NimbleDigest::from_bytes(&cond_tail_hash);
      if d.is_err() {
        return Err(Status::invalid_argument("Incorrect tail hash provided"));
      }
      d.unwrap()
    };
    // TODO: Compare the Conditional Tail Hash in CheckLatest()

    // Write the block to the data store
    {
      let res = self
        .data
        .write()
        .expect("Failed to acquire lock on state")
        .append(&handle, &data_block);
      assert!(res.is_ok());
    }

    let committee_public_keys = {
      let handle_committee = self.committee.read().expect("Unable to obtain Readlock");
      let res = handle_committee.get(&handle);
      if res.is_err() {
        return Err(Status::invalid_argument("Unknown Handle"));
      }
      res.unwrap()
    };

    let connections: Vec<EndorserConnection> = {
      let res = self.get_endorser_connections(&committee_public_keys);
      if res.is_err() {
        return Err(Status::aborted("Failed to Obtain Endorser Connection"));
      }
      res.unwrap()
    };

    let mut receipt = Vec::new();
    let mut height: u64 = 0;
    let mut prev_hash = NimbleDigest::default();

    let mut responses = Vec::with_capacity(connections.len());

    for (index, ec) in connections.iter().enumerate() {
      let mut conn = ec.clone();

      responses.push(tokio::spawn(async move {
        (
          index,
          conn
            .append(
              handle.to_bytes(),
              hash_of_block.to_bytes(),
              cond_tail_hash_info.to_bytes(),
            )
            .await,
        )
      }));
    }

    for resp in responses {
      let endorser_append_op = resp.await;
      if let Ok((index, Ok((tail_hash_data, height_data, signature)))) = endorser_append_op {
        prev_hash = NimbleDigest::from_bytes(&tail_hash_data).unwrap();
        height = height_data;
        // TODO: Error Checking.
        receipt.push((index, signature));
      }
    }

    let metablock = MetaBlock::new(&prev_hash, &hash_of_block, height as usize);
    let receipt = ledger::Receipt::from_bytes(&receipt);
    let endorsed_metablock = EndorsedMetaBlock::new(&metablock, &receipt);

    {
      let res = self
        .metadata
        .write()
        .expect("Failed to acquire lock on state")
        .append(&handle, &endorsed_metablock);
      assert!(res.is_ok());
    }

    let reply = AppendResp {
      tail_hash: prev_hash.to_bytes(),
      height,
      receipt: Some(reformat_receipt(&receipt.to_bytes())),
    };

    Ok(Response::new(reply))
  }

  async fn read_latest(
    &self,
    request: Request<ReadLatestReq>,
  ) -> Result<Response<ReadLatestResp>, Status> {
    let ReadLatestReq { handle, nonce } = request.into_inner();

    let nonce_data = {
      let nonce_op = Nonce::new(&nonce);
      if nonce_op.is_err() {
        return Err(Status::invalid_argument("Nonce Invalid"));
      }
      nonce_op.unwrap().to_owned()
    };

    let handle = {
      let h = NimbleDigest::from_bytes(&handle);
      if h.is_err() {
        return Err(Status::invalid_argument("Incorrect Handle Provided"));
      }
      h.unwrap()
    };

    let committee_public_keys = {
      let handle_committee = self.committee.read().expect("Unable to obtain Readlock");
      let res = handle_committee.get(&handle);
      if res.is_err() {
        return Err(Status::invalid_argument("Unknown Handle"));
      }
      res.unwrap()
    };

    let connections: Vec<EndorserConnection> = {
      let res = self.get_endorser_connections(&committee_public_keys);
      if res.is_err() {
        return Err(Status::aborted("Failed to Obtain Endorser Connection"));
      }
      res.unwrap()
    };

    // 1. Read the information from the Endorsers
    let mut receipt_bytes = Vec::new();
    let mut responses = Vec::with_capacity(connections.len());

    for (index, ec) in connections.iter().enumerate() {
      let mut conn = ec.clone();

      responses.push(tokio::spawn(async move {
        (
          index,
          conn.read_latest(handle.to_bytes(), &nonce_data).await,
        )
      }));
    }

    for resp in responses {
      let sig_op = resp.await;
      if let Ok((index, Ok(sig))) = sig_op {
        receipt_bytes.push((index, sig));
      }
    }

    // 2. ReadLatest Block data from the Data structure.
    let block = {
      let res = self
        .data
        .read()
        .expect("Failed to acquire read lock on the data store")
        .read_latest(&handle);
      if res.is_err() {
        return Err(Status::invalid_argument(
          "No data exists for the given handle",
        ));
      }
      res.unwrap()
    };

    // 3. Read latest metablock and signatures from Metadata structure
    let metadata = {
      let res = self
        .metadata
        .read()
        .expect("Failed to acquire read lock on the metadata store")
        .read_latest(&handle);

      if res.is_err() {
        return Err(Status::invalid_argument(
          "No metadata exists for the given handle",
        ));
      }
      res.unwrap()
    };

    // 4. Pack the response structure (m, \sigma) from metadata structure
    //    to m = (T, b, c)
    let reply = ReadLatestResp {
      block: block.to_bytes(),
      tail_hash: metadata.get_metablock().get_prev().to_bytes(),
      height: metadata.get_metablock().get_height() as u64,
      receipt: Some(reformat_receipt(
        &ledger::Receipt::from_bytes(&receipt_bytes).to_bytes(),
      )), // Ideally collected signatures from majority endorsers
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
    let block = self
      .data
      .read()
      .expect("Failed to acquire read lock")
      .read_by_index(&handle_info, index as usize)
      .unwrap(); // TODO: perform error handling

    let metadata = self
      .metadata
      .read()
      .expect("Failed to acquire read lock")
      .read_by_index(&handle_info, index as usize)
      .unwrap(); // TODO: perform error handling

    // 2. Retrieve the information from the metadata structure.
    let tail_hash = metadata.get_metablock().get_prev();

    let reply = ReadByIndexResp {
      block: block.to_bytes(),
      tail_hash: tail_hash.to_bytes(),
      receipt: Some(reformat_receipt(&metadata.get_receipt().to_bytes())),
    };

    Ok(Response::new(reply))
  }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let config = App::new("coordinator")
      .arg(Arg::with_name("host").help("The hostname to run the service on. Default: [::1]")
          .default_value("[::1]")
          .index(2),
      )
      .arg(Arg::with_name("port").help("The port number to run the coordinator service on. Default: 8080")
          .default_value("8080").index(1),)
      .arg(Arg::with_name("endorser")
          .short("e")
          .long("endorser")
          .help("List of URLs to Endorser Services")
          .use_delimiter(true)
          .default_value("http://[::1]:9090,http://[::1]:9091,http://[::1]:9092,http://[::1]:9093,http://[::1]:9094")
          .required(true));
  let cli_matches = config.get_matches();
  let hostname = cli_matches.value_of("host").unwrap();
  let port_number = cli_matches.value_of("port").unwrap();
  let addr = format!("{}:{}", hostname, port_number).parse()?;
  let endorser_hostnames: Vec<&str> = cli_matches.values_of("endorser").unwrap().collect();
  println!("Endorser_hostnames: {:?}", endorser_hostnames);
  let server = CoordinatorState::new(endorser_hostnames).await;

  println!("Running gRPC Coordinator Service at {:?}", addr);

  Server::builder()
    .add_service(CallServer::new(server))
    .serve(addr)
    .await?;

  Ok(())
}
