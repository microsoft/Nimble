use protocol::call_client::CallClient;
use protocol::{Data, LedgerRequest, LedgerResponse, Query, Response, Status, UpdateQuery};

pub mod protocol {
  tonic::include_proto!("protocol");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let mut client = CallClient::connect("http://[::1]:8080").await?;

  let new_ledger = "example_ledger";
  // Step 1: NewLedger Request
  let request = tonic::Request::new(LedgerRequest {
    name: new_ledger.to_string(),
  });
  let LedgerResponse { handle } = client.new_ledger(request).await?.into_inner();
  println!("Received Response - Ledger Handle: {:?}", handle);

  // Step 2: Send a series of messages to be appended
  let m1: Vec<u8> = "first_message".as_bytes().to_vec();
  let m2: Vec<u8> = "second_message".as_bytes().to_vec();
  let m3: Vec<u8> = "third_message".as_bytes().to_vec();
  let messages = vec![&m1, &m2, &m3].to_vec();

  for message in messages {
    let update_query = tonic::Request::new(UpdateQuery {
      handle: handle.clone(),
      value: Some(Data {
        content: message.to_vec(),
      }),
    });
    let Status { status } = client.append_to_ledger(update_query).await?.into_inner();
    println!(
      "Received Response: {:?} for appending {:?}",
      status,
      message.to_vec()
    )
  }

  // Step 3: Get Tail/Latest State of Ledger
  let latest_state_query = tonic::Request::new(Query {
    handle: handle.clone(),
    index: 0, // Should be marked optional ideally.
  });
  let Response { value } = client.read_latest(latest_state_query).await?.into_inner();
  let latest_message_data = value.unwrap();
  let latest_message = latest_message_data.content;
  assert_eq!(latest_message.clone(), m3.clone());

  // Step 4: Get Ledger value at index
  let index_read_state_query = tonic::Request::new(Query {
    handle: handle.clone(),
    index: 2, // Should be marked optional ideally.
  });
  let Response { value } = client
    .read_at_index(index_read_state_query)
    .await?
    .into_inner();
  let latest_message_data = value.unwrap();
  let latest_message = latest_message_data.content;
  assert_eq!(latest_message.clone(), m2.clone()); // Checking with m2

  Ok(())
}
