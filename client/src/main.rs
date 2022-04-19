mod errors;

use tonic::transport::{Channel, Endpoint};

pub mod coordinator_proto {
  tonic::include_proto!("coordinator_proto");
}

use crate::errors::ClientError;
use clap::{App, Arg};
use coordinator_proto::{
  call_client::CallClient, AppendReq, AppendResp, NewLedgerReq, NewLedgerResp, ReadByIndexReq,
  ReadByIndexResp, ReadLatestReq, ReadLatestResp, ReadViewByIndexReq, ReadViewByIndexResp,
};
use rand::Rng;
use verifier::{
  verify_append, verify_new_ledger, verify_read_by_index, verify_read_latest, VerifierState,
};

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
    let channel = connection.connect_lazy();
    let client = CallClient::new(channel);
    Ok(CoordinatorConnection { client })
  }
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

  // Initialization: Fetch view ledger to build VerifierState
  let mut vs = VerifierState::new();

  let req = tonic::Request::new(ReadViewByIndexReq {
    index: 1, // the first entry on the view ledger starts at 1
  });

  let ReadViewByIndexResp { block, receipt } = coordinator_connection
    .client
    .read_view_by_index(req)
    .await?
    .into_inner();

  let res = vs.apply_view_change(&block, &receipt);
  println!("Applying ReadViewByIndexResp Response: {:?}", res.is_ok());
  assert!(res.is_ok());

  // Step 0: Create some app data
  let block_bytes: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

  // Step 1: NewLedger Request (With Application Data Embedded)
  let handle_bytes = rand::thread_rng().gen::<[u8; 16]>();
  let request = tonic::Request::new(NewLedgerReq {
    handle: handle_bytes.to_vec(),
    block: block_bytes.to_vec(),
  });
  let NewLedgerResp { receipt } = coordinator_connection
    .client
    .new_ledger(request)
    .await?
    .into_inner();

  let res = verify_new_ledger(&vs, handle_bytes.as_ref(), block_bytes.as_ref(), &receipt);
  println!("NewLedger (WithAppData) : {:?}", res.is_ok());
  assert!(res.is_ok());

  let handle = handle_bytes.to_vec();

  // Step 2: Read At Index
  let req = tonic::Request::new(ReadByIndexReq {
    handle: handle.clone(),
    index: 0,
  });

  let ReadByIndexResp { block, receipt } = coordinator_connection
    .client
    .read_by_index(req)
    .await?
    .into_inner();

  let res = verify_read_by_index(&vs, &handle, &block, 0, &receipt);
  println!("ReadByIndex: {:?}", res.is_ok());
  assert!(res.is_ok());

  // Step 3: Read Latest with the Nonce generated
  let nonce = rand::thread_rng().gen::<[u8; 16]>();
  let req = tonic::Request::new(ReadLatestReq {
    handle: handle.clone(),
    nonce: nonce.to_vec(),
  });

  let ReadLatestResp { block, receipt } = coordinator_connection
    .client
    .read_latest(req)
    .await?
    .into_inner();

  let res = verify_read_latest(&vs, &handle, &block, nonce.as_ref(), &receipt);
  println!("Read Latest : {:?}", res.is_ok());
  assert!(res.is_ok());

  // Step 4: Append
  let b1: Vec<u8> = "data_block_example_1".as_bytes().to_vec();
  let b2: Vec<u8> = "data_block_example_2".as_bytes().to_vec();
  let b3: Vec<u8> = "data_block_example_3".as_bytes().to_vec();
  let blocks = vec![&b1, &b2, &b3].to_vec();

  let mut expected_height: usize = 1;
  for block_to_append in blocks {
    expected_height += 1;
    let req = tonic::Request::new(AppendReq {
      handle: handle.clone(),
      block: block_to_append.to_vec(),
      expected_height: expected_height as u64,
    });

    let AppendResp { receipt } = coordinator_connection
      .client
      .append(req)
      .await?
      .into_inner();

    let res = verify_append(
      &vs,
      &handle,
      block_to_append.as_ref(),
      expected_height,
      &receipt,
    );
    println!("Append verification: {:?}", res.is_ok());
    assert!(res.is_ok());
  }

  // Step 4: Read Latest with the Nonce generated and check for new data
  let nonce = rand::thread_rng().gen::<[u8; 16]>();
  let latest_state_query = tonic::Request::new(ReadLatestReq {
    handle: handle.clone(),
    nonce: nonce.to_vec(),
  });

  let ReadLatestResp { block, receipt } = coordinator_connection
    .client
    .read_latest(latest_state_query)
    .await?
    .into_inner();
  assert_eq!(block, b3.clone());

  let is_latest_valid = verify_read_latest(&vs, &handle, &block, nonce.as_ref(), &receipt);
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

  let ReadByIndexResp { block, receipt } = coordinator_connection
    .client
    .read_by_index(req)
    .await?
    .into_inner();
  assert_eq!(block, b1.clone());

  let res = verify_read_by_index(&vs, &handle, &block, 2, &receipt);
  println!("Verifying ReadByIndex Response: {:?}", res.is_ok());
  assert!(res.is_ok());

  // Step 6: Append without a condition
  let message = "no_condition_data_block_append".as_bytes();
  let req = tonic::Request::new(AppendReq {
    handle: handle.clone(),
    block: message.to_vec(),
    expected_height: 0_u64,
  });

  let AppendResp { receipt } = coordinator_connection
    .client
    .append(req)
    .await?
    .into_inner();

  let res = verify_append(&vs, &handle, message, 0, &receipt);
  println!("Append verification no condition: {:?}", res.is_ok());
  assert!(res.is_ok());

  // Step 7: Read Latest with the Nonce generated and check for new data appended without condition
  let nonce = rand::thread_rng().gen::<[u8; 16]>();
  let latest_state_query = tonic::Request::new(ReadLatestReq {
    handle: handle.clone(),
    nonce: nonce.to_vec(),
  });

  let ReadLatestResp { block, receipt } = coordinator_connection
    .client
    .read_latest(latest_state_query)
    .await?
    .into_inner();
  assert_eq!(block, message);

  let is_latest_valid = verify_read_latest(&vs, &handle, &block, nonce.as_ref(), &receipt);
  println!(
    "Verifying ReadLatest Response : {:?}",
    is_latest_valid.is_ok()
  );
  assert!(is_latest_valid.is_ok());

  Ok(())
}
