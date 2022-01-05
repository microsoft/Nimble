mod errors;

use tonic::transport::{Channel, Endpoint};

pub mod coordinator_proto {
  tonic::include_proto!("coordinator_proto");
}

use crate::errors::ClientError;
use clap::{App, Arg};
use coordinator_proto::call_client::CallClient;
use coordinator_proto::{AppendReq, NewLedgerReq, NewLedgerResp, Receipt};
use ledger::NimbleDigest;
use rand::Rng;
use std::time::Instant;
use verifier::verify_new_ledger;

#[derive(Debug, Clone)]
pub struct CoordinatorConnection {
  client: CallClient<Channel>,
}

impl CoordinatorConnection {
  pub async fn new(coordinator_endpoint_address: String) -> Result<Self, errors::ClientError> {
    let connection_attempt = Endpoint::from_shared(coordinator_endpoint_address);
    let connection = match connection_attempt {
      Ok(connection) => connection,
      Err(_err) => return Err(ClientError::CoordinatorHostNameNotFound),
    };
    let channel_attempt = connection.connect_lazy();
    let channel = match channel_attempt {
      Ok(channel) => channel,
      Err(_err) => return Err(ClientError::UnableToConnectToCoordinator),
    };
    let client = CallClient::new(channel);
    Ok(CoordinatorConnection { client })
  }
}

fn reformat_receipt(receipt: &Option<Receipt>) -> Vec<(usize, Vec<u8>)> {
  assert!(receipt.is_some());
  let id_sigs = receipt.clone().unwrap().id_sigs;
  (0..id_sigs.len())
    .map(|i| (id_sigs[i].pk_idx as usize, id_sigs[i].sig.clone()))
    .collect::<Vec<(usize, Vec<u8>)>>()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let config = App::new("client").arg(
    Arg::with_name("coordinator")
      .help("The hostname of the coordinator")
      .default_value("http://[::1]:8080")
      .index(1),
  );
  let cli_matches = config.get_matches();
  let coordinator_endpoint_addr = cli_matches.value_of("coordinator").unwrap();

  let coordinator_connection_attempt =
    CoordinatorConnection::new(coordinator_endpoint_addr.to_string()).await;
  let mut coordinator_connection = match coordinator_connection_attempt {
    Ok(coordinator_connection) => coordinator_connection,
    Err(e) => {
      panic!("Client Error: {:?}", e);
    },
  };

  // Step 1: NewLedger Request (With Application Data Embedded)
  let app_bytes: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
  let client_nonce = rand::thread_rng().gen::<[u8; 16]>();
  let request = tonic::Request::new(NewLedgerReq {
    nonce: client_nonce.to_vec(),
    app_bytes: app_bytes.to_vec(),
  });
  let NewLedgerResp {
    view,
    block,
    receipt,
  } = coordinator_connection
    .client
    .new_ledger(request)
    .await?
    .into_inner();

  let res = verify_new_ledger(&view, &block, &reformat_receipt(&receipt), &client_nonce);
  println!("NewLedger (WithAppData) : {:?}", res.is_ok());
  assert!(res.is_ok());

  let (handle, _vk, ret_app_bytes) = res.unwrap();
  assert_eq!(ret_app_bytes, app_bytes.to_vec());

  let num_concurrent_clients = 10;
  let num_reqs_per_client = 1000;

  println!(
    "Starting the append benchmark with {} clients each sending {} requests...",
    num_concurrent_clients, num_reqs_per_client
  );

  let mut conn_pool = Vec::new();
  for _ in 0..num_concurrent_clients {
    let c = CoordinatorConnection::new(coordinator_endpoint_addr.to_string()).await;
    if c.is_err() {
      panic!("Client Error: {:?}", c.err().unwrap());
    }
    conn_pool.push(c.unwrap());
  }

  let num_total_reqs = num_concurrent_clients * num_reqs_per_client;
  let block = "sample_block".as_bytes().to_vec();
  let mut i = 0;

  let mut responses = Vec::new();
  let start = Instant::now();
  for conn_state in &conn_pool {
    for _ in 0..num_reqs_per_client {
      let mut conn = conn_state.clone();
      let q = tonic::Request::new(AppendReq {
        handle: handle.clone(),
        block: block.clone(),
        cond_tail_hash: NimbleDigest::default().to_bytes().to_vec(),
      });
      i += 1;
      responses.push(tokio::spawn(
        async move { (i, conn.client.append(q).await) },
      ))
    }
  }

  let req_end = Instant::now();
  println!(
    "Time to fire all requests: {:?}",
    req_end.duration_since(start)
  );

  let mut results = Vec::new();
  for resp in responses {
    let res = resp.await;
    results.push(res);
    if results.len() % 1000 == 0 {
      println!(
        "Received: {} responses in {:?}",
        results.len(),
        Instant::now().duration_since(start)
      );
    }
  }

  let end = Instant::now();
  println!(
    "{:?} seconds for {} requests.",
    end.duration_since(start),
    num_total_reqs,
  );

  Ok(())
}
