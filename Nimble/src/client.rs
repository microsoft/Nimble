mod helper;
mod verification;

use protocol::call_client::CallClient;
use protocol::{Data, LedgerResponse, Query, Response, Status, UpdateQuery, Empty};
use rand::Rng;
use crate::verification::verify_ledger_response;

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

  let is_valid = verify_ledger_response(block_data, signature);
  println!("Verification NewLedger: {:?}", is_valid);

  // Step 2: Send a series of messages to be appended
  // let m1: Vec<u8> = "first_message".as_bytes().to_vec();
  // let m2: Vec<u8> = "second_message".as_bytes().to_vec();
  // let m3: Vec<u8> = "third_message".as_bytes().to_vec();
  // let messages = vec![&m1, &m2, &m3].to_vec();
  //
  // for message in messages {
  //   let update_query = tonic::Request::new(UpdateQuery {
  //     handle: handle.clone(),
  //     value: Some(Data {
  //       content: message.to_vec(),
  //     }),
  //   });
  //   let Status { tail_hash, ledger_height, signature } =
  //       client.append_to_ledger(update_query).await?.into_inner();
  //   println!(
  //     "Received Response: {:?} at height {:?} with signature {:?} for appending {:?}",
  //     tail_hash,
  //     ledger_height,
  //     signature,
  //     message.to_vec()
  //   )
  // }
  //
  // // Step 3: Get Tail/Latest State of Ledger
  // let random_bytes = rand::thread_rng().gen::<[u8; 16]>();
  // let latest_state_query = tonic::Request::new(Query {
  //   handle: handle.clone(),
  //   index: 0, // Should be marked optional ideally.
  //   nonce: random_bytes.to_vec(),
  // });
  // let Response { value } = client.read_latest(latest_state_query).await?.into_inner();
  // let latest_message_data = value.unwrap();
  // let latest_message = latest_message_data.content;
  // assert_eq!(latest_message.clone(), m3.clone());
  //
  // // Step 4: Get Ledger value at index
  // let index_read_state_query = tonic::Request::new(Query {
  //   handle: handle.clone(),
  //   index: 2, // Should be marked optional ideally.
  //   nonce: vec![]
  // });
  // let Response { value } = client
  //   .read_at_index(index_read_state_query)
  //   .await?
  //   .into_inner();
  // let latest_message_data = value.unwrap();
  // let latest_message = latest_message_data.content;
  // assert_eq!(latest_message.clone(), m2.clone()); // Checking with m2

  Ok(())
}
