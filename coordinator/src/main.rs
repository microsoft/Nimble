mod errors;
mod network;

use crate::errors::CoordinatorError;
use crate::network::EndorserConnection;
use ed25519_dalek::PublicKey;
use ledger::store::AppendOnlyStore;
use ledger::{
  Block, CustomSerde, EndorsedMetaBlock, MetaBlock, NimbleDigest, NimbleHashTrait, Nonce,
};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use uuid::Uuid;

pub mod coordinator_proto {
  tonic::include_proto!("coordinator_proto");
}

use clap::{App, Arg};
use coordinator_proto::call_server::{Call, CallServer};
use coordinator_proto::{
  AppendReq, AppendResp, IdSig, NewLedgerReq, NewLedgerResp, ReadByIndexReq, ReadByIndexResp,
  ReadLatestReq, ReadLatestResp, Receipt,
};

type Handle = NimbleDigest;
type DataStore = AppendOnlyStore<Handle, Block>;
type MetadataStore = AppendOnlyStore<Handle, EndorsedMetaBlock>;

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

  fn get_all(&self) -> (Vec<PublicKey>, Vec<EndorserConnection>) {
    let pk_vec = self
      .store
      .iter()
      .map(|(pk, _ec)| PublicKey::from_bytes(pk).unwrap())
      .collect::<Vec<PublicKey>>();

    let conn_vec = self
      .store
      .iter()
      .map(|(_pk, ec)| ec.clone())
      .collect::<Vec<EndorserConnection>>();

    (pk_vec, conn_vec)
  }
}

#[derive(Debug, Default)]
pub struct CoordinatorState {
  data: Arc<RwLock<DataStore>>,
  metadata: Arc<RwLock<MetadataStore>>,
  connections: Arc<RwLock<ConnectionStore>>, // a map from a public key to a connection object
}

#[derive(Debug, Default)]
pub struct CallServiceStub {}

impl CoordinatorState {
  pub async fn new(hostnames: Vec<&str>) -> Self {
    let mut connections = ConnectionStore::new();

    // Connect in series. TODO: Make these requests async and concurrent
    for hostname in hostnames {
      let conn = EndorserConnection::new(hostname.to_string()).await;
      assert!(
        !conn.is_err(),
        "Unable to connect to an endorser service at {:?} with err: {:?}",
        hostname.to_string(),
        conn
      );
      println!("Connected Successfully to {:?}", &hostname);

      let conn = conn.unwrap();
      let pk = conn.get_public_key().unwrap();
      let res = connections.insert(&pk.to_bytes().to_vec(), &conn);
      assert!(
        !res.is_err(),
        "Error inserting the public key of {:?} into a map",
        hostname.to_string()
      );
    }

    // Call the endorsers to initialize the view/membership ledger

    // (1) Retrieve all public keys of current active endorsers and connections to them
    let (endorser_pk_vec, endorser_conn_vec) = connections.get_all();

    // (2) Package the list of endorsers into a genesis block of the view ledger
    let view_ledger_genesis_block = {
      let endorser_pk_vec_bytes = (0..endorser_pk_vec.len())
        .map(|i| endorser_pk_vec[i].to_bytes().to_vec())
        .collect::<Vec<Vec<u8>>>()
        .into_iter()
        .flatten()
        .collect::<Vec<u8>>();
      Block::new(&endorser_pk_vec_bytes)
    };

    // (3) Store the genesis block of the view ledger in the data store
    // We will use NimbleDigest::default() as the handle for the view ledger
    let data_store = {
      let mut v = DataStore::new();
      let res = v.insert(&NimbleDigest::default(), &view_ledger_genesis_block);
      assert!(res.is_ok());
      v
    };

    // (4) Make a request to the endorsers for initializing the view ledger
    let mut receipt_bytes: Vec<(usize, Vec<u8>)> = Vec::new();
    let mut responses = Vec::with_capacity(endorser_conn_vec.len());
    let view_ledger_block_hash = view_ledger_genesis_block.hash();
    for (index, ec) in endorser_conn_vec.iter().enumerate() {
      let mut conn = ec.clone();
      responses.push(tokio::spawn(async move {
        (
          index,
          conn
            .initialize_state(
              &HashMap::new(),
              &(NimbleDigest::default(), 0usize),
              &view_ledger_block_hash,
            )
            .await,
        )
      }));
    }

    for resp in responses {
      let res = resp.await;
      if let Ok((index, Ok(sig))) = res {
        receipt_bytes.push((index, sig))
      }
    }
    let receipt = ledger::Receipt::from_bytes(&receipt_bytes);

    // (5) Store the returned responses in the metadata store
    // We will use NimbleDigest::default() as the handle for the view ledger
    let metadata_store = {
      let view_ledger_metablock = MetaBlock::new(
        &NimbleDigest::default(),
        &NimbleDigest::default(),
        &view_ledger_genesis_block.hash(),
        1_usize,
      );

      let mut v = MetadataStore::new();
      let res = v.insert(
        &NimbleDigest::default(),
        &EndorsedMetaBlock::new(&view_ledger_metablock, &receipt),
      );
      assert!(res.is_ok());
      v
    };

    CoordinatorState {
      data: Arc::new(RwLock::new(data_store)),
      metadata: Arc::new(RwLock::new(metadata_store)),
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
    req: Request<NewLedgerReq>,
  ) -> Result<Response<NewLedgerResp>, Status> {
    let NewLedgerReq {
      nonce: client_nonce,
      app_bytes,
    } = req.into_inner();
    // Generate a Unique Value, this is the coordinator chosen nonce.
    let service_nonce = Uuid::new_v4().as_bytes().to_vec();

    // Retrieve all public keys of current active endorsers and connections to them
    let (endorser_pk_vec, endorser_conn_vec) = self
      .connections
      .read()
      .expect("Unable to obtain read lock on connections")
      .get_all();

    // Package the contents into a Block
    let genesis_block = {
      let genesis_op = Block::genesis(&endorser_pk_vec, &service_nonce, &client_nonce, &app_bytes);
      if genesis_op.is_err() {
        return Err(Status::aborted("Failed to create a genesis block"));
      }
      genesis_op.unwrap()
    };

    // Hash the contents of the block to use as the handle.
    let handle = genesis_block.hash();

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

    let mut responses = Vec::with_capacity(endorser_conn_vec.len());
    for (index, ec) in endorser_conn_vec.iter().enumerate() {
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

    // Prepare an endorsed metadata block for the view ledger
    let view = {
      let res = self
        .metadata
        .read()
        .expect("Failed to acquire read lock on the metadata store")
        .read_latest(&NimbleDigest::default());

      if res.is_err() {
        return Err(Status::invalid_argument(
          "Internal server error, this should not have occured",
        ));
      }
      let endorsed_metablock = res.unwrap();
      endorsed_metablock.get_metablock().hash()
    };

    let receipt = ledger::Receipt::from_bytes(&receipt_bytes);
    let endorsed_metablock = EndorsedMetaBlock::new(&MetaBlock::genesis(&view, &handle), &receipt);

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
      view: view.to_bytes(),
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

    // Compare the Conditional Tail Hash in CheckLatest()
    {
      let cond_tail_hash_info = {
        let d = NimbleDigest::from_bytes(&cond_tail_hash);
        if d.is_err() {
          return Err(Status::invalid_argument("Incorrect tail hash provided"));
        }
        d.unwrap()
      };

      // we will perform the conditional hash check only if the provided tail is not the default
      if cond_tail_hash_info != NimbleDigest::default() {
        // read the current tail endorsed metablock from state
        let res = self
          .metadata
          .read()
          .expect("Failed to acquire lock on state")
          .read_latest(&handle);
        assert!(res.is_ok());

        if cond_tail_hash_info != res.unwrap().get_metablock().hash() {
          return Err(Status::invalid_argument(
            "Incorrect/stale tail hash provided",
          ));
        }
      }
    }

    // Write the block to the data store
    {
      let res = self
        .data
        .write()
        .expect("Failed to acquire lock on state")
        .append(&handle, &data_block);
      assert!(res.is_ok());
    }

    // Retrieve all public keys of current active endorsers and connections to them
    let (_endorser_pk_vec, endorser_conn_vec) = self
      .connections
      .read()
      .expect("Unable to obtain read lock on connections")
      .get_all();

    let mut receipt = Vec::new();
    let mut responses = Vec::with_capacity(endorser_conn_vec.len());

    for (index, ec) in endorser_conn_vec.iter().enumerate() {
      let mut conn = ec.clone();

      responses.push(tokio::spawn(async move {
        (
          index,
          conn
            .append(handle.to_bytes(), hash_of_block.to_bytes())
            .await,
        )
      }));
    }

    for resp in responses {
      let endorser_append_op = resp.await;
      if let Ok((index, Ok(signature))) = endorser_append_op {
        receipt.push((index, signature));
      }
    }

    let view = {
      let res = self
        .metadata
        .read()
        .expect("Failed to acquire read lock on the metadata store")
        .read_latest(&NimbleDigest::default());

      if res.is_err() {
        return Err(Status::invalid_argument(
          "Internal server error, this should not have occured",
        ));
      }
      let endorsed_metablock = res.unwrap();
      endorsed_metablock.get_metablock().hash()
    };

    let prev_metablock = {
      let res = self
        .metadata
        .read()
        .expect("Failed to acquire lock on state")
        .read_latest(&handle);
      assert!(res.is_ok());
      let e_metablock = res.unwrap();
      e_metablock.get_metablock().clone()
    };

    let metablock = MetaBlock::new(
      &view,
      &prev_metablock.hash(),
      &hash_of_block,
      prev_metablock.get_height() + 1,
    );
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
      view: view.to_bytes(),
      prev: prev_metablock.hash().to_bytes(),
      height: (prev_metablock.get_height() + 1) as u64,
      receipt: Some(reformat_receipt(&receipt.to_bytes())),
    };

    Ok(Response::new(reply))
  }

  async fn read_latest(
    &self,
    request: Request<ReadLatestReq>,
  ) -> Result<Response<ReadLatestResp>, Status> {
    let ReadLatestReq { handle, nonce } = request.into_inner();

    let nonce = {
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

    // Retrieve all public keys of current active endorsers and connections to them
    let (_endorser_pk_vec, endorser_conn_vec) = self
      .connections
      .read()
      .expect("Unable to obtain read lock on connections")
      .get_all();

    // 1. Read the information from the Endorsers
    let mut receipt_bytes = Vec::new();
    let mut responses = Vec::with_capacity(endorser_conn_vec.len());

    for (index, ec) in endorser_conn_vec.iter().enumerate() {
      let mut conn = ec.clone();

      responses.push(tokio::spawn(async move {
        (index, conn.read_latest(handle.to_bytes(), &nonce).await)
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
      view: metadata.get_metablock().get_view().to_bytes(),
      block: block.to_bytes(),
      prev: metadata.get_metablock().get_prev().to_bytes(),
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
    let handle = {
      let res = NimbleDigest::from_bytes(&handle);
      if res.is_err() {
        return Err(Status::invalid_argument("Incorrect Handle Provided"));
      }
      res.unwrap()
    };

    // 1. Retrieve the block data information from the main datastructure
    let block = self
      .data
      .read()
      .expect("Failed to acquire read lock")
      .read_by_index(&handle, index as usize)
      .unwrap(); // TODO: perform error handling

    let metadata = self
      .metadata
      .read()
      .expect("Failed to acquire read lock")
      .read_by_index(&handle, index as usize)
      .unwrap(); // TODO: perform error handling

    // 2. Retrieve the information from the metadata structure.
    let prev = metadata.get_metablock().get_prev();
    let view = metadata.get_metablock().get_view();
    let reply = ReadByIndexResp {
      view: view.to_bytes(),
      block: block.to_bytes(),
      prev: prev.to_bytes(),
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
