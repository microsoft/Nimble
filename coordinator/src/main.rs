mod errors;
mod network;

use crate::errors::CoordinatorError;
use crate::network::EndorserConnection;
use ledger::store::{InMemoryLedgerStore, LedgerStore};
use ledger::{
  signature::{PublicKey, PublicKeyTrait},
  Block, CustomSerde, NimbleDigest, NimbleHashTrait, Nonce,
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
  ledger_store: InMemoryLedgerStore,
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
        conn.is_ok(),
        "Unable to connect to an endorser service at {:?} with err: {:?}",
        hostname.to_string(),
        conn
      );
      println!("Connected Successfully to {:?}", &hostname);

      let conn = conn.unwrap();
      let pk = conn.get_public_key().unwrap();
      let res = connections.insert(&pk.to_bytes().to_vec(), &conn);
      assert!(
        res.is_ok(),
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
    let ledger_store = {
      let res = InMemoryLedgerStore::new();
      assert!(res.is_ok());
      res.unwrap()
    };

    let (view_ledger_meta_block, view_ledger_tail_hash) = {
      let res = ledger_store.append_view_ledger(&view_ledger_genesis_block);
      assert!(res.is_ok());
      res.unwrap()
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
              &view_ledger_tail_hash,
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

    // (5) Store the receipt in the view ledger
    let res = ledger_store.attach_view_leger_receipt(&view_ledger_meta_block, &receipt);
    assert!(res.is_ok());

    CoordinatorState {
      connections: Arc::new(RwLock::new(connections)),
      ledger_store,
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

    let (handle, ledger_meta_block, _) = {
      let res = self.ledger_store.create_ledger(&genesis_block);
      assert!(res.is_ok());
      res.unwrap()
    };

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

    let receipt = ledger::Receipt::from_bytes(&receipt_bytes);
    // Store the receipt
    let res = self
      .ledger_store
      .attach_ledger_receipt(&handle, &ledger_meta_block, &receipt);
    assert!(res.is_ok());

    let reply = NewLedgerResp {
      view: ledger_meta_block.get_view().to_bytes(),
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

    let (ledger_meta_block, ledger_tail_hash) = {
      // TODO: shall we *move* the block?
      let res = self
        .ledger_store
        .append_ledger(&handle, &data_block, &cond_tail_hash_info);
      assert!(res.is_ok());
      res.unwrap()
    };

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
            .append(
              handle.to_bytes(),
              hash_of_block.to_bytes(),
              ledger_tail_hash.to_bytes(),
            )
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
    let receipt = ledger::Receipt::from_bytes(&receipt);
    let res = self
      .ledger_store
      .attach_ledger_receipt(&handle, &ledger_meta_block, &receipt);
    assert!(res.is_ok());

    let reply = AppendResp {
      view: ledger_meta_block.get_view().to_bytes(),
      prev: ledger_meta_block.get_prev().to_bytes(),
      height: ledger_meta_block.get_height() as u64,
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

    let ledger_entry = {
      let res = self.ledger_store.read_ledger_tail(&handle);
      assert!(res.is_ok());
      res.unwrap()
    };

    // Retrieve all public keys of current active endorsers and connections to them
    let (_endorser_pk_vec, endorser_conn_vec) = self
      .connections
      .read()
      .expect("Unable to obtain read lock on connections")
      .get_all();

    // Read the information from the Endorsers
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

    // Pack the response structure (m, \sigma) from metadata structure
    //    to m = (T, b, c)
    let reply = ReadLatestResp {
      view: ledger_entry.aux.get_view().to_bytes(),
      block: ledger_entry.block.to_bytes(),
      prev: ledger_entry.aux.get_prev().to_bytes(),
      height: ledger_entry.aux.get_height() as u64,
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

    let ledger_entry = {
      let res = self
        .ledger_store
        .read_leger_by_index(&handle, index as usize);
      assert!(res.is_ok());
      res.unwrap()
    };
    let reply = ReadByIndexResp {
      view: ledger_entry.aux.get_view().to_bytes(),
      block: ledger_entry.block.to_bytes(),
      prev: ledger_entry.aux.get_prev().to_bytes(),
      receipt: Some(reformat_receipt(&ledger_entry.receipt.to_bytes())),
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
