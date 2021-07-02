mod errors;
mod helper;
mod verification;

use crate::helper::pack_metadata_information;
use crate::verification::{
  verify_append, verify_new_ledger, verify_read_by_index, verify_read_latest, VerificationKey,
};
use coordinator_proto::call_client::CallClient;
use coordinator_proto::{Data, Empty, LedgerResponse, Query, UpdateQuery};
use ed25519_dalek::ed25519::signature::Signature;

use crate::errors::ClientError;
use ed25519_dalek::PublicKey;
use rand::seq::SliceRandom;
use rand::Rng;
use tonic::transport::{Channel, Endpoint};

pub mod coordinator_proto {
  tonic::include_proto!("coordinator_proto");
}

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
  let request = tonic::Request::new(Empty {});
  let LedgerResponse {
    block_data,
    signature,
  } = coordinator_connection
    .client
    .new_ledger(request)
    .await?
    .into_inner();
  println!(
    "Received Response - Ledger Handle: {:?} {:?}",
    block_data, signature
  );

  let res = verify_new_ledger(&block_data, &Signature::from_bytes(&signature).unwrap());
  assert!(res.is_ok());

  // store the verification key
  let vk = res.unwrap();

  // Step 2: Read Latest with the Nonce generated:
  let handle = helper::hash(&block_data).to_vec();
  println!("Handle : {:?}", handle);

  let client_generated_nonce = rand::thread_rng().gen::<[u8; 16]>();
  let latest_state_query = tonic::Request::new(Query {
    handle: handle.clone(),
    index: 0, // Should be marked optional ideally.
    nonce: client_generated_nonce.to_vec(),
  });

  let coordinator_proto::Response {
    block_data,
    tail_hash,
    ledger_height,
    endorser_signature,
  } = coordinator_connection
    .client
    .read_latest(latest_state_query)
    .await?
    .into_inner();
  let res = verify_read_latest(
    &vk,
    &block_data,
    &tail_hash,
    ledger_height as usize,
    &client_generated_nonce.to_vec(),
    &Signature::from_bytes(&endorser_signature).unwrap(),
  );
  println!("Verifying ReadLatest Response : {:?}", res);
  assert!(res.is_ok());

  // Step 3: Read At Index
  let read_at_index_query = tonic::Request::new(Query {
    handle: handle.clone(),
    index: 0,
    nonce: vec![],
  });

  let coordinator_proto::Response {
    block_data,
    tail_hash,
    ledger_height,
    endorser_signature,
  } = coordinator_connection
    .client
    .read_at_index(read_at_index_query)
    .await?
    .into_inner();

  let res = verify_read_by_index(
    &vk,
    &block_data,
    &tail_hash,
    0usize,
    &Signature::from_bytes(&endorser_signature).unwrap(),
  );
  println!("Verifying ReadAtIndex Response: {:?}", res);
  assert!(res.is_ok());

  // Step 4: Append
  let m1: Vec<u8> = "data_block_example_1".as_bytes().to_vec();
  let m2: Vec<u8> = "data_block_example_2".as_bytes().to_vec();
  let m3: Vec<u8> = "data_block_example_3".as_bytes().to_vec();
  let messages = vec![&m1, &m2, &m3].to_vec();

  let mut last_known_tail = tail_hash.clone();

  for message in messages {
    let update_query = tonic::Request::new(UpdateQuery {
      handle: handle.clone(),
      value: Some(Data {
        content: message.to_vec(),
      }),
      conditional_tail_hash: last_known_tail.to_vec(),
    });

    let coordinator_proto::Status {
      tail_hash,
      ledger_height,
      signature,
    } = coordinator_connection
      .client
      .append_to_ledger(update_query)
      .await?
      .into_inner();

    if last_known_tail != [0u8; 32] {
      println!("Asserting returned tail hash is the conditional expectation");
      assert_eq!(tail_hash, last_known_tail);
    }

    let res = verify_append(
      &vk,
      &message.to_vec(),
      &tail_hash,
      ledger_height as usize,
      &Signature::from_bytes(&signature).unwrap(),
    );
    println!("Appended {:?} and Verification: {:?}", message, res.is_ok());
    assert_eq!(res.is_ok(), true);

    // Coordinator returns previous Tail Hash State prior to append, use the information to
    // construct T' which is the known tail or the expectation for the client.
    let block_hash = helper::hash(&message).to_vec();
    let tail_content = pack_metadata_information(tail_hash, block_hash, ledger_height as usize);
    let tail_hash_expectation = helper::hash(&tail_content).to_vec();
    let zero_state = [0u8; 32].to_vec();
    let test_with_expected_tail_or_none = vec![&tail_hash_expectation, &zero_state];
    last_known_tail = test_with_expected_tail_or_none
      .choose(&mut rand::thread_rng())
      .unwrap()
      .to_vec();
  }

  // Step 4: Read Latest with the Nonce generated and check for new data
  let client_generated_nonce = rand::thread_rng().gen::<[u8; 16]>();
  let latest_state_query = tonic::Request::new(Query {
    handle: handle.clone(),
    index: 0, // Should be marked optional ideally.
    nonce: client_generated_nonce.to_vec(),
  });

  let coordinator_proto::Response {
    block_data,
    tail_hash,
    ledger_height,
    endorser_signature,
  } = coordinator_connection
    .client
    .read_latest(latest_state_query)
    .await?
    .into_inner();
  println!("Latest information is read by the client matching third message");
  assert_eq!(block_data, m3.clone());
  let is_latest_valid = verify_read_latest(
    &vk,
    &block_data,
    &tail_hash,
    ledger_height as usize,
    &client_generated_nonce.to_vec(),
    &Signature::from_bytes(&endorser_signature).unwrap(),
  );
  println!(
    "Verifying ReadLatest Response : {:?}",
    is_latest_valid.is_ok()
  );
  assert_eq!(is_latest_valid.is_ok(), true);

  // Step 5: Read At Index
  let read_at_index_query = tonic::Request::new(Query {
    handle: handle.clone(),
    index: 2,
    nonce: vec![],
  });

  let coordinator_proto::Response {
    block_data,
    tail_hash,
    ledger_height,
    endorser_signature,
  } = coordinator_connection
    .client
    .read_at_index(read_at_index_query)
    .await?
    .into_inner();
  println!("Verifying returned Index for Block at Index 2 Specified");
  assert_eq!(block_data, m2.clone());
  let res = verify_read_by_index(
    &vk,
    &block_data,
    &tail_hash,
    2usize,
    &Signature::from_bytes(&endorser_signature).unwrap(),
  );
  println!("Verifying ReadAtIndex Response: {:?}", res.is_ok());
  assert!(res.is_ok());
  Ok(())
}
