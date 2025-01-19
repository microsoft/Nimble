mod coordinator_state;
mod errors;

use crate::coordinator_state::CoordinatorState;
use ledger::CustomSerde;
use std::{collections::HashMap, sync::Arc};
use tonic::{transport::Server, Request, Response, Status};
use ledger::{IdSig, signature::{PublicKey, PublicKeyTrait, Signature}};
#[allow(clippy::derive_partial_eq_without_eq)]
pub mod coordinator_proto {
  tonic::include_proto!("coordinator_proto");
}

use clap::{App, Arg};
use coordinator_proto::{
  call_server::{Call, CallServer},
  AppendReq, AppendResp, NewLedgerReq, NewLedgerResp, ReadByIndexReq, ReadByIndexResp,
  ReadLatestReq, ReadLatestResp, ReadViewByIndexReq, ReadViewByIndexResp, ReadViewTailReq,
  ReadViewTailResp, PingAllReq, PingAllResp, GetTimeoutMapReq, GetTimeoutMapResp,
};

use axum::{
  extract::{Extension, Path},
  http::StatusCode,
  response::IntoResponse,
  routing::get,
  Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tower::ServiceBuilder;

use rand::Rng;

pub struct CoordinatorServiceState {
  state: Arc<CoordinatorState>,
}

impl CoordinatorServiceState {
  pub fn new(coordinator: Arc<CoordinatorState>) -> Self {
    CoordinatorServiceState { state: coordinator }
  }

  #[cfg(test)]
  pub fn get_state(&self) -> &CoordinatorState {
    &self.state
  }
}

#[tonic::async_trait]
impl Call for CoordinatorServiceState {
  async fn new_ledger(
    &self,
    req: Request<NewLedgerReq>,
  ) -> Result<Response<NewLedgerResp>, Status> {
    let NewLedgerReq {
      handle: handle_bytes,
      block: block_bytes,
    } = req.into_inner();

    let res = self
        .state
        .create_ledger(None, &handle_bytes, &block_bytes)
        .await;
    if res.is_err() {
      return Err(Status::aborted("Failed to create a new ledger"));
    }

    let receipts = res.unwrap();
    let reply = NewLedgerResp {
      receipts: receipts.to_bytes(),
    };
    Ok(Response::new(reply))
  }

  async fn append(&self, request: Request<AppendReq>) -> Result<Response<AppendResp>, Status> {
    let AppendReq {
      handle: handle_bytes,
      block: block_bytes,
      expected_height,
    } = request.into_inner();

    let res = self
        .state
        .append_ledger(None, &handle_bytes, &block_bytes, expected_height as usize)
        .await;
    if res.is_err() {
      return Err(Status::aborted("Failed to append to a ledger"));
    }

    let (hash_nonces, receipts) = res.unwrap();
    let reply = AppendResp {
      hash_nonces: hash_nonces.to_bytes(),
      receipts: receipts.to_bytes(),
    };

    Ok(Response::new(reply))
  }

  async fn read_latest(
    &self,
    request: Request<ReadLatestReq>,
  ) -> Result<Response<ReadLatestResp>, Status> {
    let ReadLatestReq {
      handle: handle_bytes,
      nonce: nonce_bytes,
    } = request.into_inner();

    let res = self
        .state
        .read_ledger_tail(&handle_bytes, &nonce_bytes)
        .await;
    if res.is_err() {
      return Err(Status::aborted("Failed to read a ledger tail"));
    }

    let ledger_entry = res.unwrap();
    let reply = ReadLatestResp {
      block: ledger_entry.get_block().to_bytes(),
      nonces: ledger_entry.get_nonces().to_bytes(),
      receipts: ledger_entry.get_receipts().to_bytes(),
    };

    Ok(Response::new(reply))
  }

  async fn read_by_index(
    &self,
    request: Request<ReadByIndexReq>,
  ) -> Result<Response<ReadByIndexResp>, Status> {
    let ReadByIndexReq {
      handle: handle_bytes,
      index,
    } = request.into_inner();

    match self
        .state
        .read_ledger_by_index(&handle_bytes, index as usize)
        .await
    {
      Ok(ledger_entry) => {
        let reply = ReadByIndexResp {
          block: ledger_entry.get_block().to_bytes(),
          nonces: ledger_entry.get_nonces().to_bytes(),
          receipts: ledger_entry.get_receipts().to_bytes(),
        };
        Ok(Response::new(reply))
      },
      Err(_) => return Err(Status::aborted("Failed to read a ledger")),
    }
  }

  async fn read_view_by_index(
    &self,
    request: Request<ReadViewByIndexReq>,
  ) -> Result<Response<ReadViewByIndexResp>, Status> {
    let ReadViewByIndexReq { index } = request.into_inner();

    let res = self.state.read_view_by_index(index as usize).await;
    if res.is_err() {
      return Err(Status::aborted("Failed to read the view ledger"));
    }

    let ledger_entry = res.unwrap();
    let reply = ReadViewByIndexResp {
      block: ledger_entry.get_block().to_bytes(),
      receipts: ledger_entry.get_receipts().to_bytes(),
    };

    Ok(Response::new(reply))
  }

  async fn read_view_tail(
    &self,
    _request: Request<ReadViewTailReq>,
  ) -> Result<Response<ReadViewTailResp>, Status> {
    let res = self.state.read_view_tail().await;
    if res.is_err() {
      return Err(Status::aborted("Failed to read the view ledger tail"));
    }

    let (ledger_entry, height, attestation_reports) = res.unwrap();
    let reply = ReadViewTailResp {
      block: ledger_entry.get_block().to_bytes(),
      receipts: ledger_entry.get_receipts().to_bytes(),
      height: height as u64,
      attestations: attestation_reports,
    };

    Ok(Response::new(reply))
  }



  async fn ping_all_endorsers(
    &self,
    _request: Request<coordinator_proto::PingAllReq>,  // Accept the gRPC request
) -> Result<Response<coordinator_proto::PingAllResp>, Status> {
    // Call the state method to perform the ping task (no return value)
    println!("Pining all endorsers now from main.rs");
    self.state.ping_all_endorsers().await;

    // Here, create the PingAllResp with a dummy id_sig (or generate it if necessary)
    // let id_sig =   // Replace with actual logic to generate IdSig if needed

    // Construct and return the PingAllResp with the id_sig
    let reply = PingAllResp {
        id_sig: rand::thread_rng().gen::<[u8; 16]>().to_vec(),  // Make sure id_sig is serialized to bytes
    };

    // Return the response
    Ok(Response::new(reply))
  }

  async fn get_timeout_map(
    &self,
    request: Request<GetTimeoutMapReq>,
  ) -> Result<Response<GetTimeoutMapResp>, Status> {
    let GetTimeoutMapReq {
      nonce,
    } = request.into_inner();

    let res = self
        .state
        .get_timeout_map();

    let reply = GetTimeoutMapResp {
      signature: nonce,
      timeout_map: res,
    };

    Ok(Response::new(reply))
  }
}

#[derive(Debug, Serialize, Deserialize)]
struct EndorserOpResponse {
  #[serde(rename = "PublicKey")]
  pub pk: String,
}

async fn get_endorser(
  Path(uri): Path<String>,
  Extension(state): Extension<Arc<CoordinatorState>>,
) -> impl IntoResponse {
  let res = base64_url::decode(&uri);
  if res.is_err() {
    eprintln!("received a bad endorser uri {:?}", res);
    return (StatusCode::BAD_REQUEST, Json(json!({})));
  }
  let endorser_uri = res.unwrap();

  let res = std::str::from_utf8(&endorser_uri);
  if res.is_err() {
    eprintln!(
      "cannot convert the endorser uri {:?} to string {:?}",
      endorser_uri, res
    );
    return (StatusCode::BAD_REQUEST, Json(json!({})));
  }
  let endorser_uri_str = res.unwrap();

  let res = state.get_endorser_pk(endorser_uri_str);
  match res {
    None => {
      eprintln!(
        "failed to delete the endorser {} ({:?})",
        endorser_uri_str, res
      );
      (StatusCode::BAD_REQUEST, Json(json!({})))
    },
    Some(pk) => {
      let resp = EndorserOpResponse {
        pk: base64_url::encode(&pk),
      };
      (StatusCode::OK, Json(json!(resp)))
    },
  }
}

async fn new_endorser(
  Path(uri): Path<String>,
  Extension(state): Extension<Arc<CoordinatorState>>,
) -> impl IntoResponse {
  let res = base64_url::decode(&uri);
  if res.is_err() {
    eprintln!("received a bad endorser uri {:?}", res);
    return (StatusCode::BAD_REQUEST, Json(json!({})));
  }
  let endorser_uri = res.unwrap();

  let res = String::from_utf8(endorser_uri.clone());
  if res.is_err() {
    eprintln!(
      "cannot convert the endorser uri {:?} to string {:?}",
      endorser_uri, res
    );
    return (StatusCode::BAD_REQUEST, Json(json!({})));
  }
  let endorser_uri_string = res.unwrap();

  let endorsers = endorser_uri_string
    .split(';')
    .filter(|e| !e.is_empty())
    .map(|e| e.to_string())
    .collect::<Vec<String>>();

  let res = state.replace_endorsers(&endorsers).await;
  if res.is_err() {
    eprintln!("failed to add the endorser ({:?})", res);
    return (StatusCode::BAD_REQUEST, Json(json!({})));
  }

  let pks = state.get_endorser_pks();
  let mut pks_vec = Vec::new();
  for pk in pks {
    pks_vec.extend(pk);
  }
  let resp = EndorserOpResponse {
    pk: base64_url::encode(&pks_vec),
  };
  (StatusCode::OK, Json(json!(resp)))
}

async fn delete_endorser(
  Path(uri): Path<String>,
  Extension(state): Extension<Arc<CoordinatorState>>,
) -> impl IntoResponse {
  let res = base64_url::decode(&uri);
  if res.is_err() {
    eprintln!("received a bad endorser uri {:?}", res);
    return (StatusCode::BAD_REQUEST, Json(json!({})));
  }
  let endorser_uri = res.unwrap();

  let res = std::str::from_utf8(&endorser_uri);
  if res.is_err() {
    eprintln!(
      "cannot convert the endorser uri {:?} to string {:?}",
      endorser_uri, res
    );
    return (StatusCode::BAD_REQUEST, Json(json!({})));
  }
  let endorser_uri_str = res.unwrap();

  let res = state.get_endorser_pk(endorser_uri_str);
  let pk = match res {
    None => {
      eprintln!(
        "failed to find the endorser {} ({:?})",
        endorser_uri_str, res
      );
      return (StatusCode::BAD_REQUEST, Json(json!({})));
    },
    Some(pk) => pk,
  };

  let resp = EndorserOpResponse {
    pk: base64_url::encode(&pk),
  };

  state
    .disconnect_endorsers(&vec![(pk, endorser_uri_str.to_string())])
    .await;

  (StatusCode::OK, Json(json!(resp)))
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
      Arg::with_name("storage_account")
        .short("a")
        .long("storage_account")
        .takes_value(true)
        .help("The storage account name"),
    )
    .arg(
      Arg::with_name("storage_master_key")
        .short("k")
        .long("storage_master_key")
        .takes_value(true)
        .help("The storage master key"),
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
      Arg::with_name("ctrl")
        .short("r")
        .long("ctrl")
        .help("The port number to run the coordinator control service on.")
        .default_value("8090"),
    )
    .arg(
      Arg::with_name("endorser")
        .short("e")
        .long("endorser")
        .help("List of URLs to Endorser Services")
        .use_delimiter(true)
        .default_value("http://[::1]:9090"),
    )
    .arg(
      Arg::with_name("channels")
        .short("l")
        .long("channels")
        .takes_value(true)
        .help("The number of grpc channels"),
    );

  let cli_matches = config.get_matches();
  let hostname = cli_matches.value_of("host").unwrap();
  let port_number = cli_matches.value_of("port").unwrap();
  let ctrl_port = cli_matches.value_of("ctrl").unwrap();
  let store = cli_matches.value_of("store").unwrap();
  let addr = format!("{}:{}", hostname, port_number).parse()?;
  let str_vec: Vec<&str> = cli_matches.values_of("endorser").unwrap().collect();
  let endorser_hostnames = str_vec
    .iter()
    .filter(|e| !e.is_empty())
    .map(|e| e.to_string())
    .collect::<Vec<String>>();

  let mut ledger_store_args = HashMap::<String, String>::new();
  if let Some(x) = cli_matches.value_of("cosmosurl") {
    ledger_store_args.insert(String::from("COSMOS_URL"), x.to_string());
  }
  if let Some(x) = cli_matches.value_of("nimbledb") {
    ledger_store_args.insert(String::from("NIMBLE_DB"), x.to_string());
  }
  if let Some(x) = cli_matches.value_of("storage_account") {
    ledger_store_args.insert(String::from("STORAGE_ACCOUNT"), x.to_string());
  }
  if let Some(x) = cli_matches.value_of("storage_master_key") {
    ledger_store_args.insert(String::from("STORAGE_MASTER_KEY"), x.to_string());
  }
  let num_grpc_channels: Option<usize> = if let Some(x) = cli_matches.value_of("channels") {
    match x.to_string().parse() {
      Ok(v) => Some(v),
      Err(_) => panic!("Failed to parse the number of grpc channels"),
    }
  } else {
    None
  };
  let res = CoordinatorState::new(store, &ledger_store_args, num_grpc_channels).await;
  assert!(res.is_ok());
  let coordinator = res.unwrap();

  if !endorser_hostnames.is_empty() {
    let _ = coordinator.replace_endorsers(&endorser_hostnames).await;
  }
  if coordinator.get_endorser_pks().is_empty() {
    panic!("No endorsers are available!");
  }
  println!("Endorser URIs: {:?}", coordinator.get_endorser_uris());

  coordinator.start_auto_scheduler().await;
  println!("Pinging all Endorsers method called from main.rs");
  coordinator.ping_all_endorsers().await;
  let coordinator_ref = Arc::new(coordinator);
  
  let server = CoordinatorServiceState::new(coordinator_ref.clone());

  // Start the REST server for management
  let control_server = Router::new()
      .route("/endorsers/:uri", get(get_endorser).put(new_endorser).delete(delete_endorser))
      // Add middleware to all routes
      .layer(
          ServiceBuilder::new()
              // Handle errors from middleware
              .layer(Extension(coordinator_ref.clone()))
              .into_inner(),
      );

  let ctrl_addr = format!("{}:{}", hostname, ctrl_port).parse()?;
  let _job = tokio::spawn(async move {
    println!("Running control service at {}", ctrl_addr);
    let _res = axum::Server::bind(&ctrl_addr)
      .serve(control_server.into_make_service())
      .await;
  });

  let job2 = tokio::spawn(async move {
    println!("Running gRPC Coordinator Service at {:?}", addr);
    let _ = Server::builder()
      .add_service(CallServer::new(server))
      .serve(addr)
      .await;
  });

  job2.await?;
  
  Ok(())
}

#[cfg(test)]
mod tests {
  use crate::{
    coordinator_proto::{
      call_server::Call, AppendReq, AppendResp, NewLedgerReq, NewLedgerResp, ReadByIndexReq,
      ReadByIndexResp, ReadLatestReq, ReadLatestResp, ReadViewTailReq, ReadViewTailResp, PingAllReq, PingAllResp,
    },
    CoordinatorServiceState, CoordinatorState,
  };
  use ledger::{Block, CustomSerde, NimbleDigest, VerifierState};
  use rand::Rng;
  use std::{
    collections::HashMap,
    ffi::OsString,
    io::{BufRead, BufReader},
    process::{Child, Command, Stdio},
    sync::Arc,
  };

  struct BoxChild {
    pub child: Child,
  }

  impl Drop for BoxChild {
    fn drop(&mut self) {
      self.child.kill().expect("failed to kill a child process");
    }
  }

  fn launch_endorser(cmd: &OsString, args: String) -> BoxChild {
    let mut endorser = BoxChild {
      child: Command::new(cmd)
        .args(args.split_whitespace())
        .stdout(Stdio::piped())
        .spawn()
        .expect("endorser failed to start"),
    };

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

    endorser
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
        None => String::from(""),
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

    if std::env::var_os("STORAGE_ACCOUNT").is_some() {
      ledger_store_args.insert(
        String::from("STORAGE_ACCOUNT"),
        std::env::var_os("STORAGE_ACCOUNT")
          .unwrap()
          .into_string()
          .unwrap(),
      );
    }

    if std::env::var_os("STORAGE_MASTER_KEY").is_some() {
      ledger_store_args.insert(
        String::from("STORAGE_MASTER_KEY"),
        std::env::var_os("STORAGE_MASTER_KEY")
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

    if std::env::var_os("NIMBLE_FSTORE_DIR").is_some() {
      ledger_store_args.insert(
        String::from("NIMBLE_FSTORE_DIR"),
        std::env::var_os("NIMBLE_FSTORE_DIR")
          .unwrap()
          .into_string()
          .unwrap(),
      );
    }

    // Launch the endorser
    let endorser = launch_endorser(&endorser_cmd, endorser_args.clone());
    println!("Endorser started");
    // Create the coordinator
    let coordinator = Arc::new(
      CoordinatorState::new(&store, &ledger_store_args, None)
        .await
        .unwrap(),
    );
    println!("Coordinator started");
    let res = coordinator
      .replace_endorsers(&["http://[::1]:9090".to_string()])
      .await;
    assert!(res.is_ok());
    println!("Endorser replaced");
    let server = CoordinatorServiceState::new(coordinator);

    // Initialization: Fetch view ledger to build VerifierState
    let mut vs = VerifierState::new();

    let req = tonic::Request::new(ReadViewTailReq {});
    let res = server.read_view_tail(req).await;
    assert!(res.is_ok());
    let ReadViewTailResp {
      block,
      receipts,
      height: view_height,
      attestations,
    } = res.unwrap().into_inner();

    assert!(view_height == 1);
    vs.set_group_identity(NimbleDigest::digest(&block));

    let res = vs.apply_view_change(&block, &receipts, Some(&attestations));
    assert!(res.is_ok());

    // Step 0: Create some app data
    let block_bytes: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

    // Step 1: NewLedger Request (With Application Data Embedded)
    let handle_bytes = rand::thread_rng().gen::<[u8; 16]>();
    let request = tonic::Request::new(NewLedgerReq {
      handle: handle_bytes.to_vec(),
      block: block_bytes.to_vec(),
    });
    let NewLedgerResp { receipts } = server.new_ledger(request).await.unwrap().into_inner();
    let res = vs.verify_new_ledger(&handle_bytes, block_bytes.as_ref(), &receipts);
    println!("NewLedger (WithAppData) : {:?}", res);
    assert!(res.is_ok());

    let handle = handle_bytes.to_vec();

    // Step 2: Read At Index
    let req = tonic::Request::new(ReadByIndexReq {
      handle: handle.clone(),
      index: 0,
    });

    let ReadByIndexResp {
      block,
      nonces,
      receipts,
    } = server.read_by_index(req).await.unwrap().into_inner();

    let res = vs.verify_read_by_index(&handle, &block, &nonces, 0, &receipts);
    println!("ReadByIndex: {:?}", res.is_ok());
    assert!(res.is_ok());

    // Step 3: Read Latest with the Nonce generated
    let nonce = rand::thread_rng().gen::<[u8; 16]>();
    let req = tonic::Request::new(ReadLatestReq {
      handle: handle.clone(),
      nonce: nonce.to_vec(),
    });

    let ReadLatestResp {
      block,
      nonces,
      receipts,
    } = server.read_latest(req).await.unwrap().into_inner();

    let res = vs.verify_read_latest(&handle, &block, &nonces, nonce.as_ref(), &receipts);
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

      let AppendResp {
        hash_nonces,
        receipts,
      } = server.append(req).await.unwrap().into_inner();

      let res = vs.verify_append(
        &handle,
        block_to_append.as_ref(),
        &hash_nonces,
        expected_height,
        &receipts,
      );
      println!("Append verification: {:?} {:?}", block_to_append, res);
      assert!(res.is_ok());
    }

    // Step 4: Read Latest with the Nonce generated and check for new data
    let nonce = rand::thread_rng().gen::<[u8; 16]>();
    let latest_state_query = tonic::Request::new(ReadLatestReq {
      handle: handle.clone(),
      nonce: nonce.to_vec(),
    });

    let ReadLatestResp {
      block,
      nonces,
      receipts,
    } = server
      .read_latest(latest_state_query)
      .await
      .unwrap()
      .into_inner();
    assert_eq!(block, b3.clone());

    let is_latest_valid =
      vs.verify_read_latest(&handle, &block, &nonces, nonce.as_ref(), &receipts);
    println!(
      "Verifying ReadLatest Response : {:?}",
      is_latest_valid.is_ok()
    );
    assert!(is_latest_valid.is_ok());

    // Step 5: Read At Index
    let req = tonic::Request::new(ReadByIndexReq {
      handle: handle.clone(),
      index: 1,
    });

    let ReadByIndexResp {
      block,
      nonces,
      receipts,
    } = server.read_by_index(req).await.unwrap().into_inner();
    assert_eq!(block, b1.clone());

    let res = vs.verify_read_by_index(&handle, &block, &nonces, 1, &receipts);
    println!("Verifying ReadByIndex Response: {:?}", res.is_ok());
    assert!(res.is_ok());

    // Step 6: change the view by adding two new endorsers
    let endorser_args2 = endorser_args.clone() + " -p 9092";
    let endorser2 = launch_endorser(&endorser_cmd, endorser_args2);
    let endorser_args3 = endorser_args.clone() + " -p 9093";
    let endorser3 = launch_endorser(&endorser_cmd, endorser_args3);

    println!("2 more Endorsers started");

    let res = server
      .get_state()
      .replace_endorsers(&[
        "http://[::1]:9092".to_string(),
        "http://[::1]:9093".to_string(),
      ])
      .await;
    println!("new config with 2 endorsers: {:?}", res);
    assert!(res.is_ok());

    let req = tonic::Request::new(ReadViewTailReq {});
    let res = server.read_view_tail(req).await;
    assert!(res.is_ok());
    let ReadViewTailResp {
      block,
      receipts,
      height: _view_height,
      attestations,
    } = res.unwrap().into_inner();

    let res = vs.apply_view_change(&block, &receipts, Some(&attestations));
    println!("Applying ReadViewByIndexResp Response: {:?}", res);
    assert!(res.is_ok());

    // Step 7: Append after view change
    expected_height += 1;

    let message = "data_block_append".as_bytes();
    let req = tonic::Request::new(AppendReq {
      handle: handle.clone(),
      block: message.to_vec(),
      expected_height: expected_height as u64,
    });

    let AppendResp {
      hash_nonces,
      receipts,
    } = server.append(req).await.unwrap().into_inner();

    let res = vs.verify_append(&handle, message, &hash_nonces, expected_height, &receipts);
    println!("Append verification: {:?}", res.is_ok());
    assert!(res.is_ok());

    // Step 8: Read Latest with the Nonce generated and check for new data appended without condition
    let nonce = rand::thread_rng().gen::<[u8; 16]>();
    let latest_state_query = tonic::Request::new(ReadLatestReq {
      handle: handle.clone(),
      nonce: nonce.to_vec(),
    });

    let ReadLatestResp {
      block,
      nonces,
      receipts,
    } = server
      .read_latest(latest_state_query)
      .await
      .unwrap()
      .into_inner();
    assert_eq!(block, message);

    let is_latest_valid =
      vs.verify_read_latest(&handle, &block, &nonces, nonce.as_ref(), &receipts);
    println!(
      "Verifying ReadLatest Response : {:?}",
      is_latest_valid.is_ok()
    );
    assert!(is_latest_valid.is_ok());

    // Step 9: create a ledger and append to it only on the first endorser
    let mut endorsers = server.get_state().get_endorser_pks();
    endorsers.remove(1);

    let handle_bytes = rand::thread_rng().gen::<[u8; 16]>();
    let res = server
      .get_state()
      .create_ledger(Some(endorsers.clone()), handle_bytes.as_ref(), &[])
      .await;
    println!("create_ledger with first endorser: {:?}", res);
    assert!(res.is_ok());

    let new_handle = handle_bytes.to_vec();

    let message = "data_block_append 2".as_bytes();
    let res = server
      .get_state()
      .append_ledger(
        Some(endorsers.clone()),
        &new_handle.clone(),
        message,
        1usize,
      )
      .await;
    println!("append_ledger with first endorser: {:?}", res);
    assert!(res.is_ok());

    let handle2_bytes = rand::thread_rng().gen::<[u8; 16]>();
    let res = server
      .get_state()
      .create_ledger(None, handle2_bytes.as_ref(), &[])
      .await;
    println!("create_ledger with first endorser: {:?}", res);
    assert!(res.is_ok());

    let new_handle2 = handle2_bytes.to_vec();

    let message2 = "data_block_append 3".as_bytes();
    let res = server
      .get_state()
      .append_ledger(
        Some(endorsers.clone()),
        &new_handle2.clone(),
        message2,
        1usize,
      )
      .await;
    println!("append_ledger with first endorser: {:?}", res);
    assert!(res.is_ok());

    let nonce1 = rand::thread_rng().gen::<[u8; 16]>();
    let res = server
      .get_state()
      .read_ledger_tail(&new_handle2, &nonce1)
      .await;
    assert!(res.is_ok());

    let res = server
      .get_state()
      .append_ledger(
        Some(endorsers.clone()),
        &new_handle2.clone(),
        message2,
        2usize,
      )
      .await;
    println!("append_ledger with first endorser again: {:?}", res);
    assert!(res.is_ok());

    let message3 = "data_block_append 4".as_bytes();
    let res = server
      .get_state()
      .append_ledger(None, &new_handle2.clone(), message3, 3usize)
      .await;
    assert!(res.is_ok());

    let nonce2 = rand::thread_rng().gen::<[u8; 16]>();
    let res = server
      .get_state()
      .read_ledger_tail(&new_handle2, &nonce2)
      .await;
    assert!(res.is_ok());

    let ledger_entry = res.unwrap();
    assert_eq!(ledger_entry.get_block().to_bytes(), message3.to_vec());
    let is_latest_valid = vs.verify_read_latest(
      &new_handle2,
      &ledger_entry.get_block().to_bytes(),
      &ledger_entry.get_nonces().to_bytes(),
      nonce2.as_ref(),
      &ledger_entry.get_receipts().to_bytes(),
    );
    println!("Verifying ReadLatest Response : {:?}", is_latest_valid,);
    assert!(is_latest_valid.is_ok());

    let res = server
      .get_state()
      .read_ledger_by_index(&new_handle2, 2usize)
      .await;
    assert!(res.is_ok());

    let ledger_entry = res.unwrap();
    assert_eq!(ledger_entry.get_block().to_bytes(), message2.to_vec());
    let is_latest_valid = vs.verify_read_latest(
      &new_handle2,
      &ledger_entry.get_block().to_bytes(),
      &ledger_entry.get_nonces().to_bytes(),
      nonce1.as_ref(),
      &ledger_entry.get_receipts().to_bytes(),
    );
    println!("Verifying ReadLatest Response : {:?}", is_latest_valid,);
    assert!(is_latest_valid.is_ok());

    // Step 10: replace the view with three endorsers
    let endorser_args4 = endorser_args.clone() + " -p 9094";
    let endorser4 = launch_endorser(&endorser_cmd, endorser_args4);
    let endorser_args5 = endorser_args.clone() + " -p 9095";
    let endorser5 = launch_endorser(&endorser_cmd, endorser_args5);
    let endorser_args6 = endorser_args.clone() + " -p 9096";
    let endorser6 = launch_endorser(&endorser_cmd, endorser_args6);

    println!("3 more Endorsers started");

    let res = server
      .get_state()
      .replace_endorsers(&[
        "http://[::1]:9094".to_string(),
        "http://[::1]:9095".to_string(),
        "http://[::1]:9096".to_string(),
      ])
      .await;
    println!("new config with 3 endorsers: {:?}", res);
    assert!(res.is_ok());

    let req = tonic::Request::new(ReadViewTailReq {});
    let res = server.read_view_tail(req).await;
    assert!(res.is_ok());
    let ReadViewTailResp {
      block,
      receipts,
      height: _view_height,
      attestations,
    } = res.unwrap().into_inner();

    let res = vs.apply_view_change(&block, &receipts, Some(&attestations));
    println!("Applying ReadViewByIndexResp Response: {:?}", res);
    assert!(res.is_ok());

    // Step 11: read the latest of the new ledger
    let nonce = rand::thread_rng().gen::<[u8; 16]>();
    let latest_state_query = tonic::Request::new(ReadLatestReq {
      handle: new_handle.clone(),
      nonce: nonce.to_vec(),
    });

    let ReadLatestResp {
      block,
      nonces,
      receipts,
    } = server
      .read_latest(latest_state_query)
      .await
      .unwrap()
      .into_inner();
    assert_eq!(block, message);

    let is_latest_valid =
      vs.verify_read_latest(&new_handle, &block, &nonces, nonce.as_ref(), &receipts);
    println!("Verifying ReadLatest Response : {:?}", is_latest_valid,);
    assert!(is_latest_valid.is_ok());

    // Step 12: Append data
    let message = "data_block_append 3".as_bytes();
    let req = tonic::Request::new(AppendReq {
      handle: new_handle.clone(),
      block: message.to_vec(),
      expected_height: 2_u64,
    });

    let AppendResp {
      hash_nonces,
      receipts,
    } = server.append(req).await.unwrap().into_inner();

    let res = vs.verify_append(&new_handle, message, &hash_nonces, 2, &receipts);
    println!("Append verification: {:?}", res.is_ok());
    assert!(res.is_ok());

    if store != "memory" {
      // set up the endorsers to be at different heights
      let mut endorsers = server.get_state().get_endorser_pks();
      endorsers.remove(1);

      let handle_bytes = rand::thread_rng().gen::<[u8; 16]>();
      let res = server
        .get_state()
        .create_ledger(Some(endorsers.clone()), handle_bytes.as_ref(), &[])
        .await;
      println!("create_ledger with the first two endorser: {:?}", res);
      assert!(res.is_ok());

      let new_handle = handle_bytes.to_vec();

      let message = "data_block_append 2".as_bytes();
      let res = server
        .get_state()
        .append_ledger(
          Some(endorsers.clone()),
          &new_handle.clone(),
          message,
          1usize,
        )
        .await;
      println!(
        "append_ledger new handle1 with the first two endorsers: {:?}",
        res
      );
      assert!(res.is_ok());

      let handle2_bytes = rand::thread_rng().gen::<[u8; 16]>();
      let res = server
        .get_state()
        .create_ledger(None, handle2_bytes.as_ref(), &[])
        .await;
      println!("create_ledger with all three endorser: {:?}", res);
      assert!(res.is_ok());

      let new_handle2 = handle2_bytes.to_vec();

      let message2 = "data_block_append 3".as_bytes();
      let res = server
        .get_state()
        .append_ledger(
          Some(endorsers.clone()),
          &new_handle2.clone(),
          message2,
          1usize,
        )
        .await;
      println!(
        "append_ledger new handle2 with the first two endorsers: {:?}",
        res
      );
      assert!(res.is_ok());

      // Launch three new endorsers
      let endorser_args7 = endorser_args.clone() + " -p 9097";
      let endorser7 = launch_endorser(&endorser_cmd, endorser_args7);
      let endorser_args8 = endorser_args.clone() + " -p 9098";
      let endorser8 = launch_endorser(&endorser_cmd, endorser_args8);
      let endorser_args9 = endorser_args.clone() + " -p 9099";
      let endorser9 = launch_endorser(&endorser_cmd, endorser_args9);

      // Connect to new endorsers
      let new_endorsers = server
        .state
        .connect_endorsers(&[
          "http://[::1]:9097".to_string(),
          "http://[::1]:9098".to_string(),
          "http://[::1]:9099".to_string(),
        ])
        .await;
      assert!(new_endorsers.len() == 3);

      // Package the list of endorsers into a genesis block of the view ledger
      let view_ledger_genesis_block = bincode::serialize(&new_endorsers).unwrap();

      // Store the genesis block of the view ledger in the ledger store
      let res = server
        .state
        .ledger_store
        .append_view_ledger(&Block::new(&view_ledger_genesis_block), 4usize)
        .await;
      assert!(res.is_ok());

      // Step 13: drop old coordinator and start a new coordinator
      drop(server);

      let coordinator2 = Arc::new(
        CoordinatorState::new(&store, &ledger_store_args, None)
          .await
          .unwrap(),
      );

      let server2 = CoordinatorServiceState::new(coordinator2);
      println!("Started a new coordinator");

      let req = tonic::Request::new(ReadViewTailReq {});
      let res = server2.read_view_tail(req).await;
      assert!(res.is_ok());
      let ReadViewTailResp {
        block,
        receipts,
        height: _view_height,
        attestations,
      } = res.unwrap().into_inner();

      let res = vs.apply_view_change(&block, &receipts, Some(&attestations));
      println!("Applying ReadViewByIndexResp Response: {:?}", res);
      assert!(res.is_ok());

      // Step 14: Append via the new coordinator
      let message = "data_block_append 4".as_bytes();
      let req = tonic::Request::new(AppendReq {
        handle: new_handle.clone(),
        block: message.to_vec(),
        expected_height: 2_u64,
      });

      let AppendResp {
        hash_nonces,
        receipts,
      } = server2.append(req).await.unwrap().into_inner();
      let res = vs.verify_append(&new_handle, message, &hash_nonces, 2, &receipts);
      println!("Append verification: {:?}", res.is_ok());
      assert!(res.is_ok());

      // Step 14: Append without a condition via the new coordinator
      let message = "data_block_append 4".as_bytes();
      let req = tonic::Request::new(AppendReq {
        handle: new_handle2.clone(),
        block: message.to_vec(),
        expected_height: 2_u64,
      });

      let AppendResp {
        hash_nonces,
        receipts,
      } = server2.append(req).await.unwrap().into_inner();
      let res = vs.verify_append(&new_handle2, message, &hash_nonces, 2, &receipts);
      println!("Append verification: {:?}", res.is_ok());
      assert!(res.is_ok());

      server2.get_state().reset_ledger_store().await;

      println!("endorser7 process ID is {}", endorser7.child.id());
      println!("endorser8 process ID is {}", endorser8.child.id());
      println!("endorser9 process ID is {}", endorser9.child.id());
    }

    // We access endorser and endorser2 below
    // to stop them from being dropped earlier
    println!("endorser1 process ID is {}", endorser.child.id());
    println!("endorser2 process ID is {}", endorser2.child.id());
    println!("endorser3 process ID is {}", endorser3.child.id());
    println!("endorser4 process ID is {}", endorser4.child.id());
    println!("endorser5 process ID is {}", endorser5.child.id());
    println!("endorser6 process ID is {}", endorser6.child.id());
  }

  #[tokio::test]
  async fn test_ping() {
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
        None => String::from(""),
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

    if std::env::var_os("STORAGE_ACCOUNT").is_some() {
      ledger_store_args.insert(
        String::from("STORAGE_ACCOUNT"),
        std::env::var_os("STORAGE_ACCOUNT")
          .unwrap()
          .into_string()
          .unwrap(),
      );
    }

    if std::env::var_os("STORAGE_MASTER_KEY").is_some() {
      ledger_store_args.insert(
        String::from("STORAGE_MASTER_KEY"),
        std::env::var_os("STORAGE_MASTER_KEY")
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

    if std::env::var_os("NIMBLE_FSTORE_DIR").is_some() {
      ledger_store_args.insert(
        String::from("NIMBLE_FSTORE_DIR"),
        std::env::var_os("NIMBLE_FSTORE_DIR")
          .unwrap()
          .into_string()
          .unwrap(),
      );
    }

    // Launch the endorser
    let endorser = launch_endorser(&endorser_cmd, endorser_args.clone());
    println!("Endorser started");
    // Create the coordinator
    let coordinator = Arc::new(
      CoordinatorState::new(&store, &ledger_store_args, None)
        .await
        .unwrap(),
    );
    println!("Coordinator started");
    let res = coordinator
      .replace_endorsers(&["http://[::1]:9090".to_string()])
      .await;
    assert!(res.is_ok());
    println!("Endorser replaced");
    let server = CoordinatorServiceState::new(coordinator);

    // Print the whole timeout_map from the coordinator state
    let timeout_map = server.get_state().get_timeout_map();
    println!("Timeout Map: {:?}", timeout_map);

    // Print the whole timeout_map from the coordinator state again
    let req = tonic::Request::new(PingAllReq {
      nonce: rand::thread_rng().gen::<[u8; 16]>().to_vec(),
    });
    let res = server.ping_all_endorsers(req).await;
    assert!(res.is_ok());
    let timeout_map = server.get_state().get_timeout_map();
    println!("Timeout Map after waiting: {:?}", timeout_map);

    let _ = Command::new("pkill").arg("-f").arg("endorser").status().expect("failed to execute process");


    let req1 = tonic::Request::new(PingAllReq {
      nonce: rand::thread_rng().gen::<[u8; 16]>().to_vec(),
    });
    let res1 = server.ping_all_endorsers(req1).await;
    assert!(res1.is_ok());
    let timeout_map = server.get_state().get_timeout_map();
    println!("Timeout Map after waiting and killing process: {:?}", timeout_map);

  }
}
