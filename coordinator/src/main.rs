mod errors;
mod network;

use crate::errors::CoordinatorError;
use crate::network::ConnectionStore;
use ledger::{
  signature::PublicKey,
  store::{in_memory::InMemoryLedgerStore, mongodb_cosmos::MongoCosmosLedgerStore, LedgerStore},
};
use ledger::{
  Block, CustomSerde, LedgerView, MetaBlock, NimbleDigest, NimbleHashTrait, Nonce, Receipt,
};
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
  AppendReq, AppendResp, NewLedgerReq, NewLedgerResp, ReadByIndexReq, ReadByIndexResp,
  ReadLatestReq, ReadLatestResp, ReadViewByIndexReq, ReadViewByIndexResp,
};

pub struct CoordinatorState {
  ledger_store: Box<dyn LedgerStore + Send + Sync>,
  connections: ConnectionStore, // a map from a public key to a connection object
}

#[derive(Debug, Default)]
pub struct CallServiceStub {}

impl CoordinatorState {
  pub async fn new(ledger_store_type: &str, args: &HashMap<String, String>) -> Self {
    match ledger_store_type {
      "mongodb_cosmos" => CoordinatorState {
        connections: ConnectionStore::new(),
        ledger_store: Box::new(MongoCosmosLedgerStore::new(args).await.unwrap()),
      },
      _ => CoordinatorState {
        connections: ConnectionStore::new(),
        ledger_store: Box::new(InMemoryLedgerStore::new()),
      },
    }
  }

  pub async fn add_endorsers(&mut self, hostnames: Vec<&str>) -> Result<(), CoordinatorError> {
    let existing_endorsers = self.connections.get_all();

    let mut new_endorsers = Vec::new();
    // Connect to endorsers in series. TODO: Make these requests async and concurrent
    for hostname in hostnames {
      let res = self
        .connections
        .connect_endorser(hostname.to_string())
        .await;
      if res.is_err() {
        eprintln!("Failed to connect to {} ({:?})", hostname, res.unwrap_err());
        return Err(CoordinatorError::FailedToConnectToEndorser);
      }
      new_endorsers.push(res.unwrap());
    }

    let endorser_pk_vec = self.connections.get_all();
    // Package the list of endorsers into a genesis block of the view ledger
    let view_ledger_genesis_block = {
      let block_vec = endorser_pk_vec.into_iter().flatten().collect::<Vec<u8>>();
      Block::new(&block_vec)
    };

    // Store the genesis block of the view ledger in the ledger store
    let res = self
      .ledger_store
      .append_view_ledger(&view_ledger_genesis_block, 0)
      .await;
    if res.is_err() {
      eprintln!(
        "Failed to append to the view ledger in the ledger store ({:?})",
        res.unwrap_err()
      );
      return Err(CoordinatorError::FailedToCallLedgerStore);
    }

    let ledger_view = {
      if existing_endorsers.is_empty() {
        LedgerView {
          view_tail_metablock: MetaBlock::default(),
          ledger_tail_map: HashMap::new(),
        }
      } else {
        let res = self
          .connections
          .read_latest_state(&existing_endorsers, false)
          .await;
        if res.is_err() {
          eprintln!(
            "Failed to read the latest state of endorsers ({:?})",
            res.unwrap_err()
          );
          return Err(CoordinatorError::FailedToReadLatestState);
        }
        res.unwrap().into_iter().next().unwrap().1
      }
    };

    // Initialize new endorsers
    let receipt1 = {
      let res = self
        .connections
        .initialize_state(
          &new_endorsers,
          &ledger_view,
          &view_ledger_genesis_block.hash(),
          0,
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

    let receipt = {
      if !existing_endorsers.is_empty() {
        // Update existing endorsers
        let receipt2 = {
          let res = self
            .connections
            .append_view_ledger(&existing_endorsers, &view_ledger_genesis_block.hash(), 0)
            .await;
          if res.is_err() {
            eprintln!(
              "Failed to append to the view ledger ({:?})",
              res.unwrap_err()
            );
            return Err(CoordinatorError::FailedToInitializeEndorser);
          }
          res.unwrap()
        };

        Receipt::merge_receipts(&[receipt1, receipt2]).unwrap()
      } else {
        receipt1
      }
    };

    // Store the receipt in the view ledger
    let res = self.ledger_store.attach_view_ledger_receipt(&receipt).await;
    if res.is_err() {
      eprintln!(
        "Failed to attach view ledger receipt in the ledger store ({:?})",
        res.unwrap_err()
      );
      return Err(CoordinatorError::FailedToCallLedgerStore);
    }

    Ok(())
  }

  pub async fn reset_ledger_store(&self) {
    let res = self.ledger_store.reset_store().await;
    assert!(res.is_ok());
  }

  pub async fn query_endorsers(&self) -> Result<Vec<(PublicKey, LedgerView)>, CoordinatorError> {
    self
      .connections
      .read_latest_state(&self.connections.get_all(), false)
      .await
  }
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

    // Package the contents into a Block
    let genesis_block = {
      let genesis_op = Block::genesis(&service_nonce, &client_nonce, &app_bytes);
      if genesis_op.is_err() {
        eprintln!("Failed to create a genesis block for a new ledger");
        return Err(Status::aborted("Failed to create a genesis block"));
      }
      genesis_op.unwrap()
    };

    let handle = {
      let res = self.ledger_store.create_ledger(&genesis_block).await;
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
      .attach_ledger_receipt(&handle, &receipt)
      .await;
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
      block: genesis_block.to_bytes(),
      receipt: receipt.to_bytes(),
    };
    Ok(Response::new(reply))
  }

  async fn append(&self, request: Request<AppendReq>) -> Result<Response<AppendResp>, Status> {
    let AppendReq {
      handle,
      block,
      expected_height,
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

    let res = self
      .ledger_store
      .append_ledger(&handle, &data_block, expected_height as usize)
      .await;
    if res.is_err() {
      eprintln!(
        "Failed to append to the ledger in the ledger store {:?}",
        res.unwrap_err()
      );
      return Err(Status::aborted(
        "Failed to append to the ledger in the ledger store",
      ));
    }

    let receipt = {
      let res = self
        .connections
        .append_ledger(&handle, &hash_of_block, expected_height as usize)
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
      .attach_ledger_receipt(&handle, &receipt)
      .await;
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
      receipt: receipt.to_bytes(),
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
      let res = self.ledger_store.read_ledger_tail(&handle).await;
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
      block: ledger_entry.block.to_bytes(),
      receipt: receipt.to_bytes(),
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
        .read_ledger_by_index(&handle, index as usize)
        .await;
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
      block: ledger_entry.block.to_bytes(),
      receipt: ledger_entry.receipt.to_bytes(),
    };

    Ok(Response::new(reply))
  }

  async fn read_view_by_index(
    &self,
    request: Request<ReadViewByIndexReq>,
  ) -> Result<Response<ReadViewByIndexResp>, Status> {
    let ReadViewByIndexReq { index } = request.into_inner();
    let ledger_entry = {
      let res = self
        .ledger_store
        .read_view_ledger_by_index(index as usize)
        .await;
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
      block: ledger_entry.block.to_bytes(),
      receipt: ledger_entry.receipt.to_bytes(),
    };

    Ok(Response::new(reply))
  }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let config = App::new("coordinator")
    .arg(
      Arg::with_name("nimbledb")
        .short("n")
        .long("nimbledb")
        .help("The database name")
        .default_value("nimble_cosmosdb"),
    )
    .arg(
      Arg::with_name("cosmosurl")
        .short("c")
        .long("cosmosurl")
        .takes_value(true)
        .help("The COSMOS URL"),
    )
    .arg(
      Arg::with_name("store")
        .short("s")
        .long("store")
        .help("The type of store used by the service.")
        .default_value("memory"),
    )
    .arg(
      Arg::with_name("host")
        .short("t")
        .long("host")
        .help("The hostname to run the service on.")
        .default_value("[::1]"),
    )
    .arg(
      Arg::with_name("port")
        .short("p")
        .long("port")
        .help("The port number to run the coordinator service on.")
        .default_value("8080"),
    )
    .arg(
      Arg::with_name("endorser")
        .short("e")
        .long("endorser")
        .help("List of URLs to Endorser Services")
        .use_delimiter(true)
        .default_value("http://[::1]:9090"),
    );

  let cli_matches = config.get_matches();
  let hostname = cli_matches.value_of("host").unwrap();
  let port_number = cli_matches.value_of("port").unwrap();
  let store = cli_matches.value_of("store").unwrap();
  let addr = format!("{}:{}", hostname, port_number).parse()?;
  let endorser_hostnames: Vec<&str> = cli_matches.values_of("endorser").unwrap().collect();
  println!("Endorser_hostnames: {:?}", endorser_hostnames);

  let mut ledger_store_args = HashMap::<String, String>::new();
  if let Some(x) = cli_matches.value_of("cosmosurl") {
    ledger_store_args.insert(String::from("COSMOS_URL"), x.to_string());
  }
  if let Some(x) = cli_matches.value_of("nimbledb") {
    ledger_store_args.insert(String::from("NIMBLE_DB"), x.to_string());
  }
  let mut server = CoordinatorState::new(store, &ledger_store_args).await;
  let res = server.add_endorsers(endorser_hostnames).await;
  assert!(res.is_ok());
  println!("Running gRPC Coordinator Service at {:?}", addr);

  Server::builder()
    .add_service(CallServer::new(server))
    .serve(addr)
    .await?;

  Ok(())
}

#[cfg(test)]
mod tests {
  use crate::coordinator_proto::call_server::Call;
  use crate::coordinator_proto::{
    AppendReq, AppendResp, NewLedgerReq, NewLedgerResp, ReadByIndexReq, ReadByIndexResp,
    ReadLatestReq, ReadLatestResp, ReadViewByIndexReq, ReadViewByIndexResp,
  };
  use crate::CoordinatorState;
  use rand::Rng;
  use std::collections::HashMap;
  use std::io::{BufRead, BufReader};
  use std::process::{Child, Command, Stdio};
  use verifier::{
    verify_append, verify_new_ledger, verify_read_by_index, verify_read_latest, VerifierState,
  };

  struct BoxChild {
    pub child: Child,
  }

  impl Drop for BoxChild {
    fn drop(&mut self) {
      self.child.kill().expect("failed to kill a child process");
    }
  }

  struct BoxCoordinator {
    pub coordinator: CoordinatorState,
  }

  #[tokio::test]
  #[ignore]
  async fn test_coordinator() {
    if std::env::var_os("ENDORSER_CMD").is_none() {
      panic!("The ENDORSER_CMD environment variable is not specified");
    }
    let endorser_cmd = {
      match std::env::var_os("ENDORSER_CMD") {
        None => panic!("The ENDORSER_CMD environment variable is not specified"),
        Some(x) => x,
      }
    };

    let endorser_args = {
      match std::env::var_os("ENDORSER_ARGS") {
        None => panic!("The ENDORSER_ARGS environment variable is not specified"),
        Some(x) => x.into_string().unwrap(),
      }
    };

    let store = {
      match std::env::var_os("LEDGER_STORE") {
        None => String::from("memory"),
        Some(x) => x.into_string().unwrap(),
      }
    };

    let mut ledger_store_args = HashMap::<String, String>::new();
    if std::env::var_os("COSMOS_URL").is_some() {
      ledger_store_args.insert(
        String::from("COSMOS_URL"),
        std::env::var_os("COSMOS_URL")
          .unwrap()
          .into_string()
          .unwrap(),
      );
    }
    if std::env::var_os("NIMBLE_DB").is_some() {
      ledger_store_args.insert(
        String::from("NIMBLE_DB"),
        std::env::var_os("NIMBLE_DB")
          .unwrap()
          .into_string()
          .unwrap(),
      );
    }

    // Launch the endorser
    let mut endorser = BoxChild {
      child: Command::new(endorser_cmd.clone())
        .args(endorser_args.clone().split_whitespace())
        .stdout(Stdio::piped())
        .spawn()
        .expect("endorser failed to start"),
    };

    // Wait for the endorser to be ready
    let mut buf_reader = BufReader::new(endorser.child.stdout.take().unwrap());
    let mut endorser_output = String::new();
    while let Ok(buflen) = buf_reader.read_line(&mut endorser_output) {
      if buflen == 0 {
        break;
      }
      if endorser_output.contains("listening on") {
        break;
      }
    }

    // Create the coordinator
    let mut box_coordinator = BoxCoordinator {
      coordinator: CoordinatorState::new(&store, &ledger_store_args).await,
    };
    let coordinator = &mut box_coordinator.coordinator;
    let res = coordinator.add_endorsers(vec!["http://[::1]:9090"]).await;
    assert!(res.is_ok());

    // Initialization: Fetch view ledger to build VerifierState
    let mut vs = VerifierState::new();

    let req = tonic::Request::new(ReadViewByIndexReq {
      index: 1, // the first entry on the view ledger starts at 1
    });

    let ReadViewByIndexResp { block, receipt } = coordinator
      .read_view_by_index(req)
      .await
      .unwrap()
      .into_inner();

    let res = vs.apply_view_change(&block, &receipt);
    println!("Applying ReadViewByIndexResp Response: {:?}", res);
    assert!(res.is_ok());

    // Step 0: Create some app data
    let app_bytes: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

    // Step 1: NewLedger Request (With Application Data Embedded)
    let client_nonce = rand::thread_rng().gen::<[u8; 16]>();
    let request = tonic::Request::new(NewLedgerReq {
      nonce: client_nonce.to_vec(),
      app_bytes: app_bytes.to_vec(),
    });
    let NewLedgerResp { block, receipt } =
      coordinator.new_ledger(request).await.unwrap().into_inner();
    let res = verify_new_ledger(&vs, &block, &receipt, &client_nonce);
    println!("NewLedger (WithAppData) : {:?}", res.is_ok());
    assert!(res.is_ok());

    let (_handle, ret_app_bytes) = res.unwrap();
    assert_eq!(ret_app_bytes, app_bytes.to_vec());

    // Step 1a. NewLedger Request with No Application Data Embedded
    let client_nonce = rand::thread_rng().gen::<[u8; 16]>();
    let request = tonic::Request::new(NewLedgerReq {
      nonce: client_nonce.to_vec(),
      app_bytes: vec![],
    });
    let NewLedgerResp { block, receipt } =
      coordinator.new_ledger(request).await.unwrap().into_inner();

    let res = verify_new_ledger(&vs, &block, &receipt, &client_nonce);
    println!("NewLedger (NoAppData) : {:?}", res.is_ok());
    assert!(res.is_ok());

    let (handle, app_bytes) = res.unwrap();
    assert_eq!(app_bytes.len(), 0);

    // Step 2: Read At Index
    let req = tonic::Request::new(ReadByIndexReq {
      handle: handle.clone(),
      index: 0,
    });

    let ReadByIndexResp { block, receipt } =
      coordinator.read_by_index(req).await.unwrap().into_inner();

    let res = verify_read_by_index(&vs, &block, 0, &receipt);
    println!("ReadByIndex: {:?}", res.is_ok());
    assert!(res.is_ok());

    // Step 3: Read Latest with the Nonce generated
    let nonce = rand::thread_rng().gen::<[u8; 16]>();
    let req = tonic::Request::new(ReadLatestReq {
      handle: handle.clone(),
      nonce: nonce.to_vec(),
    });

    let ReadLatestResp { block, receipt } =
      coordinator.read_latest(req).await.unwrap().into_inner();

    let res = verify_read_latest(&vs, &block, nonce.as_ref(), &receipt);
    println!("Read Latest : {:?}", res.is_ok());
    assert!(res.is_ok());

    // Step 4: Append
    let b1: Vec<u8> = "data_block_example_1".as_bytes().to_vec();
    let b2: Vec<u8> = "data_block_example_2".as_bytes().to_vec();
    let b3: Vec<u8> = "data_block_example_3".as_bytes().to_vec();
    let blocks = vec![&b1, &b2, &b3].to_vec();

    let mut expected_height = 0;
    for block_to_append in blocks {
      expected_height += 1;
      let req = tonic::Request::new(AppendReq {
        handle: handle.clone(),
        block: block_to_append.to_vec(),
        expected_height: expected_height as u64,
      });

      let AppendResp { receipt } = coordinator.append(req).await.unwrap().into_inner();

      let res = verify_append(&vs, block_to_append.as_ref(), expected_height, &receipt);
      println!("Append verification: {:?}", res);
      assert!(res.is_ok());
    }

    // Step 4: Read Latest with the Nonce generated and check for new data
    let nonce = rand::thread_rng().gen::<[u8; 16]>();
    let latest_state_query = tonic::Request::new(ReadLatestReq {
      handle: handle.clone(),
      nonce: nonce.to_vec(),
    });

    let ReadLatestResp { block, receipt } = coordinator
      .read_latest(latest_state_query)
      .await
      .unwrap()
      .into_inner();
    assert_eq!(block, b3.clone());

    let is_latest_valid = verify_read_latest(&vs, &block, nonce.as_ref(), &receipt);
    println!(
      "Verifying ReadLatest Response : {:?}",
      is_latest_valid.is_ok()
    );
    assert!(is_latest_valid.is_ok());

    // Step 5: Read At Index
    let req = tonic::Request::new(ReadByIndexReq {
      handle: handle.clone(),
      index: 2,
    });

    let ReadByIndexResp { block, receipt } =
      coordinator.read_by_index(req).await.unwrap().into_inner();
    assert_eq!(block, b2.clone());

    let res = verify_read_by_index(&vs, &block, 2, &receipt);
    println!("Verifying ReadByIndex Response: {:?}", res.is_ok());
    assert!(res.is_ok());

    // Step 6: change the view by adding a new endorser
    let endorser_args2 = endorser_args.clone() + " 9091";
    let mut endorser2 = BoxChild {
      child: Command::new(endorser_cmd.clone())
        .args(endorser_args2.split_whitespace())
        .stdout(Stdio::piped())
        .spawn()
        .expect("endorser failed to start"),
    };

    let mut buf_reader2 = BufReader::new(endorser2.child.stdout.take().unwrap());
    let mut endorser2_output = String::new();
    while let Ok(buflen) = buf_reader2.read_line(&mut endorser2_output) {
      if buflen == 0 {
        break;
      }
      if endorser2_output.contains("listening on") {
        break;
      }
    }

    let res = coordinator.add_endorsers(vec!["http://[::1]:9091"]).await;
    println!("Added a new endorser: {:?}", res);
    assert!(res.is_ok());

    let req = tonic::Request::new(ReadViewByIndexReq {
      index: 2, // the first entry on the view ledger starts at 1
    });

    let ReadViewByIndexResp { block, receipt } = coordinator
      .read_view_by_index(req)
      .await
      .unwrap()
      .into_inner();

    let res = vs.apply_view_change(&block, &receipt);
    println!("Applying ReadViewByIndexResp Response: {:?}", res);
    assert!(res.is_ok());

    // Step 7: Append without a condition
    let message = "no_condition_data_block_append".as_bytes();
    let req = tonic::Request::new(AppendReq {
      handle: handle.clone(),
      block: message.to_vec(),
      expected_height: 0_u64,
    });

    let AppendResp { receipt } = coordinator.append(req).await.unwrap().into_inner();

    let res = verify_append(&vs, message, 0, &receipt);
    println!("Append verification no condition: {:?}", res.is_ok());
    assert!(res.is_ok());

    // Step 8: Read Latest with the Nonce generated and check for new data appended without condition
    let nonce = rand::thread_rng().gen::<[u8; 16]>();
    let latest_state_query = tonic::Request::new(ReadLatestReq {
      handle: handle.clone(),
      nonce: nonce.to_vec(),
    });

    let ReadLatestResp { block, receipt } = coordinator
      .read_latest(latest_state_query)
      .await
      .unwrap()
      .into_inner();
    assert_eq!(block, message);

    let is_latest_valid = verify_read_latest(&vs, &block, nonce.as_ref(), &receipt);
    println!(
      "Verifying ReadLatest Response : {:?}",
      is_latest_valid.is_ok()
    );
    assert!(is_latest_valid.is_ok());

    // Step 9: query the state of endorsers
    let _pk_ledger_views = coordinator.query_endorsers().await.unwrap();

    // We access endorser and endorser2 below
    // to stop them from being dropped earlier
    println!("endorser1 process ID is {}", endorser.child.id());
    println!("endorser2 process ID is {}", endorser2.child.id());
    coordinator.reset_ledger_store().await;
  }
}
