mod errors;

use tonic::transport::{Channel, Endpoint};

pub mod coordinator_proto {
  tonic::include_proto!("coordinator_proto");
}

use crate::errors::ClientError;
use clap::{App, Arg};
use coordinator_proto::call_client::CallClient;
use coordinator_proto::{
  AppendReq, AppendResp, NewLedgerReq, NewLedgerResp, ReadByIndexReq, ReadByIndexResp,
  ReadLatestReq, ReadLatestResp, ReadViewByIndexReq, ReadViewByIndexResp, Receipt,
};
use rand::Rng;
use verifier::{
  get_tail_hash, verify_append, verify_new_ledger, verify_read_by_index, verify_read_latest,
  VerifierState,
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

fn reformat_receipt(receipt: &Option<Receipt>) -> Vec<(Vec<u8>, Vec<u8>)> {
  assert!(receipt.is_some());
  let id_sigs = receipt.clone().unwrap().id_sigs;
  (0..id_sigs.len())
    .map(|i| (id_sigs[i].id.clone(), id_sigs[i].sig.clone()))
    .collect::<Vec<(Vec<u8>, Vec<u8>)>>()
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

  let ReadViewByIndexResp {
    view,
    block,
    prev,
    receipt,
  } = coordinator_connection
    .client
    .read_view_by_index(req)
    .await?
    .into_inner();

  let res = vs.apply_view_change(&view, &block, &prev, 1usize, &reformat_receipt(&receipt));
  println!("Applying ReadViewByIndexResp Response: {:?}", res.is_ok());
  assert!(res.is_ok());

  // Step 0: Create some app data
  let app_bytes: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

  // Step 1: NewLedger Request (With Application Data Embedded)
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

  let res = verify_new_ledger(
    &vs,
    &view,
    &block,
    &reformat_receipt(&receipt),
    &client_nonce,
  );
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
  let NewLedgerResp {
    view,
    block,
    receipt,
  } = coordinator_connection
    .client
    .new_ledger(request)
    .await?
    .into_inner();

  let res = verify_new_ledger(
    &vs,
    &view,
    &block,
    &reformat_receipt(&receipt),
    &client_nonce,
  );
  println!("NewLedger (NoAppData) : {:?}", res.is_ok());
  assert!(res.is_ok());

  let (handle, app_bytes) = res.unwrap();
  assert_eq!(app_bytes.len(), 0);

  // Step 2: Read At Index
  let req = tonic::Request::new(ReadByIndexReq {
    handle: handle.clone(),
    index: 0,
  });

  let ReadByIndexResp {
    view,
    block,
    prev,
    receipt,
  } = coordinator_connection
    .client
    .read_by_index(req)
    .await?
    .into_inner();

  let res = verify_read_by_index(
    &vs,
    &view,
    &block,
    &prev,
    0usize,
    &reformat_receipt(&receipt),
  );
  println!("ReadByIndex: {:?}", res.is_ok());
  assert!(res.is_ok());

  // Step 3: Read Latest with the Nonce generated
  let nonce = rand::thread_rng().gen::<[u8; 16]>();
  let req = tonic::Request::new(ReadLatestReq {
    handle: handle.clone(),
    nonce: nonce.to_vec(),
  });

  let ReadLatestResp {
    view,
    block,
    prev,
    height,
    receipt,
  } = coordinator_connection
    .client
    .read_latest(req)
    .await?
    .into_inner();

  let res = verify_read_latest(
    &vs,
    &view,
    &block,
    &prev,
    height as usize,
    nonce.as_ref(),
    &reformat_receipt(&receipt),
  );
  println!("Read Latest : {:?}", res.is_ok());
  assert!(res.is_ok());

  let (mut last_known_tail, block_data_verified): (Vec<u8>, Vec<u8>) = res.unwrap();
  assert_eq!(block_data_verified, Vec::<u8>::new()); // This is empty since the block is genesis.

  // Step 4: Append
  let b1: Vec<u8> = "data_block_example_1".as_bytes().to_vec();
  let b2: Vec<u8> = "data_block_example_2".as_bytes().to_vec();
  let b3: Vec<u8> = "data_block_example_3".as_bytes().to_vec();
  let blocks = vec![&b1, &b2, &b3].to_vec();

  for block_to_append in blocks {
    let req = tonic::Request::new(AppendReq {
      handle: handle.clone(),
      block: block_to_append.to_vec(),
      cond_tail_hash: last_known_tail.to_vec(),
    });

    let AppendResp {
      view,
      prev,
      height,
      receipt,
    } = coordinator_connection
      .client
      .append(req)
      .await?
      .into_inner();

    if last_known_tail != [0u8; 32] {
      assert_eq!(prev, last_known_tail);
    }

    let res = verify_append(
      &vs,
      &view,
      block_to_append.as_ref(),
      &prev,
      height as usize,
      &reformat_receipt(&receipt),
    );
    println!("Append verification: {:?}", res.is_ok());
    assert!(res.is_ok());
    last_known_tail = res.unwrap();
  }

  // Step 4: Read Latest with the Nonce generated and check for new data
  let nonce = rand::thread_rng().gen::<[u8; 16]>();
  let latest_state_query = tonic::Request::new(ReadLatestReq {
    handle: handle.clone(),
    nonce: nonce.to_vec(),
  });

  let ReadLatestResp {
    view,
    block,
    prev,
    height,
    receipt,
  } = coordinator_connection
    .client
    .read_latest(latest_state_query)
    .await?
    .into_inner();
  assert_eq!(block, b3.clone());

  let is_latest_valid = verify_read_latest(
    &vs,
    &view,
    &block,
    &prev,
    height as usize,
    nonce.as_ref(),
    &reformat_receipt(&receipt),
  );
  println!(
    "Verifying ReadLatest Response : {:?}",
    is_latest_valid.is_ok()
  );
  assert!(is_latest_valid.is_ok());
  let (latest_tail_hash, latest_block_verified) = is_latest_valid.unwrap();
  // Check the tail hash generation from the read_latest response
  let conditional_tail_hash_expected = get_tail_hash(&view, &block, &prev, height as usize);
  assert!(conditional_tail_hash_expected.is_ok());
  assert_eq!(conditional_tail_hash_expected.unwrap(), latest_tail_hash);
  assert_ne!(latest_block_verified, Vec::<u8>::new()); // This should not be empty since the block is returned

  // Step 5: Read At Index
  let req = tonic::Request::new(ReadByIndexReq {
    handle: handle.clone(),
    index: 2,
  });

  let ReadByIndexResp {
    view,
    block,
    prev,
    receipt,
  } = coordinator_connection
    .client
    .read_by_index(req)
    .await?
    .into_inner();
  assert_eq!(block, b2.clone());

  let res = verify_read_by_index(
    &vs,
    &view,
    &block,
    &prev,
    2usize,
    &reformat_receipt(&receipt),
  );
  println!("Verifying ReadByIndex Response: {:?}", res.is_ok());
  assert!(res.is_ok());

  // Step 6: Append without a condition
  let message = "no_condition_data_block_append".as_bytes();
  let req = tonic::Request::new(AppendReq {
    handle: handle.clone(),
    block: message.to_vec(),
    cond_tail_hash: [0u8; 32].to_vec(),
  });

  let AppendResp {
    view,
    prev,
    height,
    receipt,
  } = coordinator_connection
    .client
    .append(req)
    .await?
    .into_inner();

  let res = verify_append(
    &vs,
    &view,
    message,
    &prev,
    height as usize,
    &reformat_receipt(&receipt),
  );
  println!("Append verification no condition: {:?}", res.is_ok());
  assert!(res.is_ok());

  // Step 7: Read Latest with the Nonce generated and check for new data appended without condition
  let nonce = rand::thread_rng().gen::<[u8; 16]>();
  let latest_state_query = tonic::Request::new(ReadLatestReq {
    handle: handle.clone(),
    nonce: nonce.to_vec(),
  });

  let ReadLatestResp {
    view,
    block,
    prev,
    height,
    receipt,
  } = coordinator_connection
    .client
    .read_latest(latest_state_query)
    .await?
    .into_inner();
  assert_eq!(block, message);

  let is_latest_valid = verify_read_latest(
    &vs,
    &view,
    &block,
    &prev,
    height as usize,
    nonce.as_ref(),
    &reformat_receipt(&receipt),
  );
  println!(
    "Verifying ReadLatest Response : {:?}",
    is_latest_valid.is_ok()
  );
  assert!(is_latest_valid.is_ok());

  Ok(())
}
