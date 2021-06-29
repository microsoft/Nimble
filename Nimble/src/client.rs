mod helper;
mod verification;

use protocol::call_client::CallClient;
use protocol::{Data, LedgerResponse, Query, Response, Status, UpdateQuery, Empty};
use rand::Rng;
use crate::verification::{verify_ledger_response, verify_read_latest_response, verify_read_at_index_response, verify_append_to_ledger};

pub mod protocol {
  tonic::include_proto!("protocol");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let mut client = CallClient::connect("http://[::1]:8080").await?;

  // Step 1: NewLedger Request
  let request = tonic::Request::new(Empty {});
  let LedgerResponse { block_data, signature } = client.new_ledger(request).await?.into_inner();
  println!("Received Response - Ledger Handle: {:?} {:?}", block_data, signature);

  let handle = helper::hash(&block_data).to_vec();
  println!("Handle : {:?}", handle);

  let (pk, is_valid) = verify_ledger_response(block_data, signature);
  println!("Verification NewLedger: {:?}", is_valid);
  assert_eq!(is_valid, true);

  // Step 2: Read Latest with the Nonce generated:
  let client_generated_nonce = rand::thread_rng().gen::<[u8; 16]>();
  let latest_state_query = tonic::Request::new(Query {
    handle: handle.clone(),
    index: 0, // Should be marked optional ideally.
    nonce: client_generated_nonce.to_vec(),
  });

  let protocol::Response { block_data, tail_hash, ledger_height, endorser_signature } =
      client.read_latest(latest_state_query).await?.into_inner();
  let is_latest_valid =
      verify_read_latest_response(&block_data, &tail_hash, &ledger_height, endorser_signature,
      &client_generated_nonce.to_vec(), &pk);
  println!("Verifying ReadLatest Response : {:?}", is_latest_valid);
  assert_eq!(is_latest_valid, true);

  // Step 3: Read At Index
  let read_at_index_query = tonic::Request::new(Query {
    handle: handle.clone(),
    index: 0,
    nonce: vec![],
  });

  let protocol::Response { block_data, tail_hash, ledger_height, endorser_signature } =
      client.read_at_index(read_at_index_query).await?.into_inner();
  let is_read_at_index_valid =
      verify_read_at_index_response(&block_data, &tail_hash, &ledger_height,
                                    endorser_signature, &pk);
  println!("Verifying ReadAtIndex Response: {:?}", is_read_at_index_valid);
  assert_eq!(is_read_at_index_valid, true);

  // Step 4: Append
  let m1: Vec<u8> = "data_block_example_1".as_bytes().to_vec();
  let m2: Vec<u8> = "data_block_example_2".as_bytes().to_vec();
  let m3: Vec<u8> = "data_block_example_3".as_bytes().to_vec();
  let messages = vec![&m1, &m2, &m3].to_vec();

  for message in messages {
    let update_query = tonic::Request::new(UpdateQuery {
      handle: handle.clone(),
      value: Some(Data {
        content: message.to_vec(),
      }),
    });

    let protocol::Status { tail_hash, ledger_height, signature } =
        client.append_to_ledger(update_query).await?.into_inner();

    let is_verify_append_valid = verify_append_to_ledger(&message.to_vec(),
                                                         &tail_hash,
                                                         &ledger_height,
                                                         signature,
                                                         &pk);
    println!("Appended {:?} and Verification: {:?}", message, is_verify_append_valid);
  }

  // Step 4: Read Latest with the Nonce generated and check for new data
  let client_generated_nonce = rand::thread_rng().gen::<[u8; 16]>();
  let latest_state_query = tonic::Request::new(Query {
    handle: handle.clone(),
    index: 0, // Should be marked optional ideally.
    nonce: client_generated_nonce.to_vec(),
  });

  let protocol::Response { block_data, tail_hash, ledger_height, endorser_signature } =
      client.read_latest(latest_state_query).await?.into_inner();
  println!("Latest information is read by the client matching third message");
  assert_eq!(block_data, m3.clone());
  let is_latest_valid =
      verify_read_latest_response(&block_data, &tail_hash, &ledger_height, endorser_signature,
                                  &client_generated_nonce.to_vec(), &pk);
  println!("Verifying ReadLatest Response : {:?}", is_latest_valid);
  assert_eq!(is_latest_valid, true);

  // Step 5: Read At Index
  let read_at_index_query = tonic::Request::new(Query {
    handle: handle.clone(),
    index: 2,
    nonce: vec![],
  });

  let protocol::Response { block_data, tail_hash, ledger_height, endorser_signature } =
      client.read_at_index(read_at_index_query).await?.into_inner();
  println!("Verifying returned Index for Block at Index 2 Specified");
  assert_eq!(block_data, m2.clone());
  let is_read_at_index_valid =
      verify_read_at_index_response(&block_data, &tail_hash, &ledger_height,
                                    endorser_signature, &pk);
  println!("Verifying ReadAtIndex Response: {:?}", is_read_at_index_valid);
  assert_eq!(is_read_at_index_valid, true);
  Ok(())
}
