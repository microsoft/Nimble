mod errors;
mod network;

use crate::errors::CoordinatorError;
use crate::network::ConnectionStore;
use ledger::store::{
  in_memory::InMemoryLedgerStore, mongodb_cosmos::MongoCosmosLedgerStore, LedgerStore,
};
use ledger::{Block, CustomSerde, NimbleDigest, NimbleHashTrait, Nonce};
use std::collections::HashMap;
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
  ReadLatestReq, ReadLatestResp, ReadViewByIndexReq, ReadViewByIndexResp, Receipt,
};

pub struct CoordinatorState<S>
where
  S: LedgerStore + Send + Sync,
{
  ledger_store: S,
  connections: ConnectionStore, // a map from a public key to a connection object
}

#[derive(Debug, Default)]
pub struct CallServiceStub {}

impl<S> CoordinatorState<S>
where
  S: LedgerStore + Send + Sync,
{
  pub async fn new(hostnames: Vec<&str>, ledger_store: S) -> Result<Self, CoordinatorError> {
    let mut connections = ConnectionStore::new();

    // Connect in series. TODO: Make these requests async and concurrent
    for hostname in hostnames {
      let res = connections.connect_endorser(hostname.to_string()).await;
      if res.is_err() {
        eprintln!("Failed to connect to {} ({:?})", hostname, res.unwrap_err());
        return Err(CoordinatorError::FailedToConnectToEndorser);
      }
    }

    let endorser_pk_vec = connections.get_all();
    // Package the list of endorsers into a genesis block of the view ledger
    let view_ledger_genesis_block = {
      let block_vec = endorser_pk_vec.into_iter().flatten().collect::<Vec<u8>>();
      Block::new(&block_vec)
    };

    // Store the genesis block of the view ledger in the ledger store
    let (view_ledger_meta_block, view_ledger_tail_hash) = {
      let res = ledger_store.append_view_ledger(&view_ledger_genesis_block);
      if res.is_err() {
        eprintln!(
          "Failed to append to the view ledger in the ledger store ({:?})",
          res.unwrap_err()
        );
        return Err(CoordinatorError::FailedToCallLedgerStore);
      }
      res.unwrap()
    };

    // Initialize endorsers
    let receipt = {
      let res = connections
        .initialize_state(
          &HashMap::new(),
          &(NimbleDigest::default(), 0usize),
          &view_ledger_genesis_block.hash(),
          &view_ledger_tail_hash,
        )
        .await;
      if res.is_err() {
        eprintln!(
          "Failed to initialize the endorser state ({:?})",
          res.unwrap_err()
        );
        return Err(CoordinatorError::FailedToInitializeEndorser);
      }
      res.unwrap()
    };

    // (5) Store the receipt in the view ledger
    let res = ledger_store.attach_view_ledger_receipt(&view_ledger_meta_block, &receipt);
    if res.is_err() {
      eprintln!(
        "Failed to attach view ledger receipt in the ledger store ({:?})",
        res.unwrap_err()
      );
      return Err(CoordinatorError::FailedToCallLedgerStore);
    }

    Ok(CoordinatorState {
      connections,
      ledger_store,
    })
  }
}

fn reformat_receipt(receipt: &[(Vec<u8>, Vec<u8>)]) -> Receipt {
  let id_sigs = receipt
    .iter()
    .map(|(id, sig)| IdSig {
      id: id.clone(),
      sig: sig.clone(),
    })
    .collect();
  Receipt { id_sigs }
}

#[tonic::async_trait]
impl<S> Call for CoordinatorState<S>
where
  S: LedgerStore + Send + Sync + 'static,
{
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

    // Package the contents into a Block
    let genesis_block = {
      let genesis_op = Block::genesis(&service_nonce, &client_nonce, &app_bytes);
      if genesis_op.is_err() {
        eprintln!("Failed to create a genesis block for a new ledger");
        return Err(Status::aborted("Failed to create a genesis block"));
      }
      genesis_op.unwrap()
    };

    let (handle, ledger_meta_block, _) = {
      let res = self.ledger_store.create_ledger(&genesis_block);
      if res.is_err() {
        eprintln!(
          "Failed to create ledger in the ledger store ({:?})",
          res.unwrap_err()
        );
        return Err(Status::aborted(
          "Failed to create ledger in the ledger store",
        ));
      }
      res.unwrap()
    };

    // Make a request to the endorsers for NewLedger using the handle which returns a signature.
    let receipt = {
      let res = self.connections.create_ledger(&handle).await;
      if res.is_err() {
        eprintln!(
          "Failed to create ledger in endorsers ({:?})",
          res.unwrap_err()
        );
        return Err(Status::aborted("Failed to create ledger in endorsers"));
      }
      res.unwrap()
    };

    // Store the receipt
    let res = self
      .ledger_store
      .attach_ledger_receipt(&handle, &ledger_meta_block, &receipt);
    if res.is_err() {
      eprintln!(
        "Failed to attach ledger receipt to the ledger store ({:?})",
        res.unwrap_err()
      );
      return Err(Status::aborted(
        "Failed to attach ledger receipt to the ledger store",
      ));
    }

    let reply = NewLedgerResp {
      view: ledger_meta_block.get_view().to_bytes(),
      block: genesis_block.to_bytes(),
      receipt: Some(reformat_receipt(&receipt.to_bytes())),
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
        eprintln!("Incorrect ledger handle for append");
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
      if res.is_err() {
        eprintln!(
          "Failed to append to the ledger in the ledger store {:?}",
          res.unwrap_err()
        );
        return Err(Status::aborted(
          "Failed to append to the ledger in the ledger store",
        ));
      }
      res.unwrap()
    };

    let receipt = {
      let res = self
        .connections
        .append_ledger(&handle, &hash_of_block, &ledger_tail_hash)
        .await;
      if res.is_err() {
        eprintln!(
          "Failed to append to the ledger in endorsers {:?}",
          res.unwrap_err()
        );
        return Err(Status::aborted(
          "Failed to append to the ledger in endorsers",
        ));
      }
      res.unwrap()
    };

    let res = self
      .ledger_store
      .attach_ledger_receipt(&handle, &ledger_meta_block, &receipt);
    if res.is_err() {
      eprintln!(
        "Failed to attach ledger receipt to the ledger store ({:?})",
        res.unwrap_err()
      );
      return Err(Status::aborted(
        "Failed to attach ledger receipt to the ledger store",
      ));
    }

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
        eprintln!("Nonce is invalide");
        return Err(Status::invalid_argument("Nonce Invalid"));
      }
      nonce_op.unwrap().to_owned()
    };

    let handle = {
      let h = NimbleDigest::from_bytes(&handle);
      if h.is_err() {
        eprintln!("Incorrect handle provided");
        return Err(Status::invalid_argument("Incorrect Handle Provided"));
      }
      h.unwrap()
    };

    let ledger_entry = {
      let res = self.ledger_store.read_ledger_tail(&handle);
      if res.is_err() {
        eprintln!(
          "Failed to read the ledger tail from the ledger store {:?}",
          res.unwrap_err()
        );
        return Err(Status::aborted(
          "Failed to read the ledger tail from the ledger store",
        ));
      }
      res.unwrap()
    };

    let receipt = {
      let res = self.connections.read_ledger_tail(&handle, &nonce).await;
      if res.is_err() {
        eprintln!(
          "Failed to read the ledger tail from endorsers {:?}",
          res.unwrap_err()
        );
        return Err(Status::aborted(
          "Failed to read the ledger tail from endorsers",
        ));
      }
      res.unwrap()
    };

    // Pack the response structure (m, \sigma) from metadata structure
    //    to m = (T, b, c)
    let reply = ReadLatestResp {
      view: ledger_entry.aux.get_view().to_bytes(),
      block: ledger_entry.block.to_bytes(),
      prev: ledger_entry.aux.get_prev().to_bytes(),
      height: ledger_entry.aux.get_height() as u64,
      receipt: Some(reformat_receipt(&receipt.to_bytes())),
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
        eprintln!("Incorrect handle provided");
        return Err(Status::invalid_argument("Incorrect Handle Provided"));
      }
      res.unwrap()
    };

    let ledger_entry = {
      let res = self
        .ledger_store
        .read_ledger_by_index(&handle, index as usize);
      if res.is_err() {
        eprintln!(
          "Failed to read ledger by index from the ledger store {:?}",
          res.unwrap_err()
        );
        return Err(Status::aborted(
          "Failed to read ledger by index from the ledger store",
        ));
      }
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

  async fn read_view_by_index(
    &self,
    request: Request<ReadViewByIndexReq>,
  ) -> Result<Response<ReadViewByIndexResp>, Status> {
    let ReadViewByIndexReq { index } = request.into_inner();
    let ledger_entry = {
      let res = self.ledger_store.read_view_ledger_by_index(index as usize);
      if res.is_err() {
        eprintln!(
          "Failed to read view by index from the ledger store {:?}",
          res.unwrap_err()
        );
        return Err(Status::aborted(
          "Failed to read view by index from the ledger store",
        ));
      }
      res.unwrap()
    };
    let reply = ReadViewByIndexResp {
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
    .arg(
      Arg::with_name("store")
        .help("The type of store used by the service. Default: InMemory")
        .default_value("memory")
        .index(3),
    )
    .arg(
      Arg::with_name("host")
        .help("The hostname to run the service on. Default: [::1]")
        .default_value("[::1]")
        .index(2),
    )
    .arg(
      Arg::with_name("port")
        .help("The port number to run the coordinator service on. Default: 8080")
        .default_value("8080")
        .index(1),
    )
    .arg(
      Arg::with_name("endorser")
        .short("e")
        .long("endorser")
        .help("List of URLs to Endorser Services")
        .use_delimiter(true)
        .default_value("http://[::1]:9090")
        .required(true),
    );

  let cli_matches = config.get_matches();
  let hostname = cli_matches.value_of("host").unwrap();
  let port_number = cli_matches.value_of("port").unwrap();
  let store = cli_matches.value_of("store").unwrap();
  let addr = format!("{}:{}", hostname, port_number).parse()?;
  let endorser_hostnames: Vec<&str> = cli_matches.values_of("endorser").unwrap().collect();
  println!("Endorser_hostnames: {:?}", endorser_hostnames);

  match store {
    "mongodb_cosmos" => {
      let ledger_store = MongoCosmosLedgerStore::new().unwrap();
      let server = CoordinatorState::new(endorser_hostnames, ledger_store)
        .await
        .unwrap();
      println!("Running gRPC Coordinator Service at {:?}", addr);

      Server::builder()
        .add_service(CallServer::new(server))
        .serve(addr)
        .await?;
    },
    _ => {
      // in memory is default
      let ledger_store = InMemoryLedgerStore::new().unwrap();
      let server = CoordinatorState::new(endorser_hostnames, ledger_store)
        .await
        .unwrap();
      println!("Running gRPC Coordinator Service at {:?}", addr);

      Server::builder()
        .add_service(CallServer::new(server))
        .serve(addr)
        .await?;
    },
  };

  Ok(())
}
