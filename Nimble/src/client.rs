mod errors;
mod ledger;
mod verification;

use crate::errors::ClientError;
use crate::verification::{
  verify_append, verify_new_ledger, verify_read_by_index, verify_read_latest,
};
use ed25519_dalek::ed25519::signature::Signature;
use rand::Rng;
use tonic::transport::{Channel, Endpoint};

pub mod coordinator_proto {
  tonic::include_proto!("coordinator_proto");
}

use coordinator_proto::call_client::CallClient;
use coordinator_proto::{
  AppendReq, AppendResp, NewLedgerReq, NewLedgerResp, ReadByIndexReq, ReadByIndexResp,
  ReadLatestReq, ReadLatestResp,
};

#[derive(Debug, Clone)]
pub struct CoordinatorConnection {
  client: CallClient<Channel>,
}

impl CoordinatorConnection {
  pub async fn new(coordinator_endpoint_address: String) -> Result<Self, errors::ClientError> {
    let connection_attempt = Endpoint::from_shared(coordinator_endpoint_address.clone());
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let coordinator_connection_attempt =
    CoordinatorConnection::new("http://[::1]:8080".to_string()).await;
  let mut coordinator_connection = match coordinator_connection_attempt {
    Ok(coordinator_connection) => coordinator_connection,
    Err(e) => {
      panic!("Client Error: {:?}", e);
    },
  };

  // Step 1: NewLedger Request
  let request = tonic::Request::new(NewLedgerReq {});
  let NewLedgerResp { block, signature } = coordinator_connection
    .client
    .new_ledger(request)
    .await?
    .into_inner();

  let res = verify_new_ledger(&block, &Signature::from_bytes(&signature).unwrap());
  assert!(res.is_ok());

  // store the handle and verification key
  let (handle, vk) = res.unwrap();

  // Step 2: Read At Index
  let req = tonic::Request::new(ReadByIndexReq {
    handle: handle.clone(),
    index: 0,
  });

  let ReadByIndexResp {
    block,
    tail_hash,
    signature,
  } = coordinator_connection
    .client
    .read_by_index(req)
    .await?
    .into_inner();

  let res = verify_read_by_index(
    &vk,
    &block,
    &tail_hash,
    0usize,
    &Signature::from_bytes(&signature).unwrap(),
  );
  println!("Verifying ReadByIndex Response: {:?}", res);
  assert!(res.is_ok());

  // Step 3: Read Latest with the Nonce generated
  let nonce = rand::thread_rng().gen::<[u8; 16]>();
  let req = tonic::Request::new(ReadLatestReq {
    handle: handle.clone(),
    nonce: nonce.to_vec(),
  });

  let ReadLatestResp {
    block,
    tail_hash,
    height,
    signature,
  } = coordinator_connection
    .client
    .read_latest(req)
    .await?
    .into_inner();
  let res = verify_read_latest(
    &vk,
    &block,
    &tail_hash,
    height as usize,
    &nonce.to_vec(),
    &Signature::from_bytes(&signature).unwrap(),
  );
  println!("Verifying ReadLatest Response : {:?}", res.is_ok());
  assert!(res.is_ok());
  let mut last_known_tail = res.unwrap();

  // Step 4: Append
  let m1: Vec<u8> = "data_block_example_1".as_bytes().to_vec();
  let m2: Vec<u8> = "data_block_example_2".as_bytes().to_vec();
  let m3: Vec<u8> = "data_block_example_3".as_bytes().to_vec();
  let messages = vec![&m1, &m2, &m3].to_vec();

  for message in messages {
    let req = tonic::Request::new(AppendReq {
      handle: handle.clone(),
      block: message.to_vec(),
      cond_tail_hash: last_known_tail.to_vec(),
    });

    let AppendResp {
      tail_hash,
      height,
      signature,
    } = coordinator_connection
      .client
      .append(req)
      .await?
      .into_inner();

    if last_known_tail != [0u8; 32] {
      assert_eq!(tail_hash, last_known_tail);
    }

    let res = verify_append(
      &vk,
      &message.to_vec(),
      &tail_hash,
      height as usize,
      &Signature::from_bytes(&signature).unwrap(),
    );
    println!("Append verification: {:?}", res.is_ok());
    assert_eq!(res.is_ok(), true);

    last_known_tail = res.unwrap();
  }

  // Step 4: Read Latest with the Nonce generated and check for new data
  let nonce = rand::thread_rng().gen::<[u8; 16]>();
  let latest_state_query = tonic::Request::new(ReadLatestReq {
    handle: handle.clone(),
    nonce: nonce.to_vec(),
  });

  let ReadLatestResp {
    block,
    tail_hash,
    height,
    signature,
  } = coordinator_connection
    .client
    .read_latest(latest_state_query)
    .await?
    .into_inner();
  assert_eq!(block, m3.clone());
  let is_latest_valid = verify_read_latest(
    &vk,
    &block,
    &tail_hash,
    height as usize,
    &nonce.to_vec(),
    &Signature::from_bytes(&signature).unwrap(),
  );
  println!(
    "Verifying ReadLatest Response : {:?}",
    is_latest_valid.is_ok()
  );
  assert_eq!(is_latest_valid.is_ok(), true);

  // Step 5: Read At Index
  let req = tonic::Request::new(ReadByIndexReq {
    handle: handle.clone(),
    index: 2,
  });

  let ReadByIndexResp {
    block,
    tail_hash,
    signature,
  } = coordinator_connection
    .client
    .read_by_index(req)
    .await?
    .into_inner();
  assert_eq!(block, m2.clone());
  let res = verify_read_by_index(
    &vk,
    &block,
    &tail_hash,
    2usize,
    &Signature::from_bytes(&signature).unwrap(),
  );
  println!("Verifying ReadByIndex Response: {:?}", res.is_ok());
  assert!(res.is_ok());
  Ok(())
}
