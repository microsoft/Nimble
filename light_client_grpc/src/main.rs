mod errors;

use ledger::{
  signature::{PublicKey, PublicKeyTrait, Signature, SignatureTrait},
  NimbleDigest,
};
use tonic::transport::{Channel, Endpoint};

mod endpoint_proto {
  tonic::include_proto!("endpoint_proto");
}

use crate::errors::ClientError;
use clap::{App, Arg};
use endpoint_proto::{
  call_client::CallClient, GetIdentityReq, GetIdentityResp, IncrementCounterReq,
  IncrementCounterResp, NewCounterReq, NewCounterResp, ReadCounterReq, ReadCounterResp,
};
use rand::Rng;

#[derive(Debug, Clone)]
pub struct EndpointConnection {
  client: CallClient<Channel>,
}

impl EndpointConnection {
  pub async fn new(coordinator_endpoint_address: String) -> Result<Self, errors::ClientError> {
    let res = Endpoint::from_shared(coordinator_endpoint_address);
    let connection = match res {
      Ok(connection) => connection,
      Err(_err) => return Err(ClientError::EndpointHostNameNotFound),
    };
    let channel = connection.connect_lazy();
    let client = CallClient::new(channel);
    Ok(EndpointConnection { client })
  }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let config = App::new("client").arg(
    Arg::with_name("endpoint")
      .help("The hostname of the endpoint")
      .default_value("http://[::1]:8081")
      .index(1),
  );
  let cli_matches = config.get_matches();
  let endpoint_addr = cli_matches.value_of("endpoint").unwrap();

  let res = EndpointConnection::new(endpoint_addr.to_string()).await;
  let mut conn = match res {
    Ok(conn) => conn,
    Err(e) => {
      panic!("Client Error: {:?}", e);
    },
  };

  // Step 0: Obtain the identity and public key of the instance
  let GetIdentityResp { id, pk } = conn
    .client
    .get_identity(GetIdentityReq {})
    .await?
    .into_inner();
  let id = NimbleDigest::from_bytes(&id).unwrap();
  let pk = PublicKey::from_bytes(&pk).unwrap();

  // Step 1: NewCounter Request
  let tag_bytes: Vec<u8> = NimbleDigest::digest(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]).to_bytes();
  let handle_bytes = rand::thread_rng().gen::<[u8; 16]>();
  let req = tonic::Request::new(NewCounterReq {
    handle: handle_bytes.to_vec(),
    tag: tag_bytes.to_vec(),
  });
  let NewCounterResp { signature } = conn.client.new_counter(req).await?.into_inner();

  // verify a message that unequivocally identifies the counter and tag
  let msg = {
    let s = format!(
      "NewCounter id: {:?}, handle = {:?}, tag = {:?}, counter = {:?}",
      id.to_bytes(),
      handle_bytes,
      tag_bytes,
      1_usize
    );
    NimbleDigest::digest(s.as_bytes())
  };

  let signature = Signature::from_bytes(&signature).unwrap();
  let res = signature.verify(&pk, &msg.to_bytes());
  println!("NewCounter: {:?}", res.is_ok());
  assert!(res.is_ok());

  let handle = handle_bytes.to_vec();

  // Step 2: Read Latest with the Nonce generated
  let nonce = rand::thread_rng().gen::<[u8; 16]>();
  let req = tonic::Request::new(ReadCounterReq {
    handle: handle.clone(),
    nonce: nonce.to_vec(),
  });

  let ReadCounterResp {
    tag,
    counter,
    signature,
  } = conn.client.read_counter(req).await?.into_inner();

  // verify a message that unequivocally identifies the counter and tag
  let msg = {
    let s = format!(
      "ReadCounter id: {:?}, handle = {:?}, tag = {:?}, counter = {:?}, nonce = {:?}",
      id.to_bytes(),
      handle,
      tag,
      counter,
      nonce
    );
    NimbleDigest::digest(s.as_bytes())
  };

  let signature = Signature::from_bytes(&signature).unwrap();
  let res = signature.verify(&pk, &msg.to_bytes());
  println!("ReadCounter: {:?}", res.is_ok());
  assert!(res.is_ok());

  // Step 3: IncrementCounter
  let t1: Vec<u8> = NimbleDigest::digest("tag_example_1".as_bytes()).to_bytes();
  let t2: Vec<u8> = NimbleDigest::digest("tag_example_2".as_bytes()).to_bytes();
  let t3: Vec<u8> = NimbleDigest::digest("tag_example_3".as_bytes()).to_bytes();

  let mut expected_counter: usize = 1;
  for tag in [t1.clone(), t2.clone(), t3.clone()].iter() {
    expected_counter += 1;
    let req = tonic::Request::new(IncrementCounterReq {
      handle: handle.clone(),
      tag: tag.to_vec(),
      expected_counter: expected_counter as u64,
    });

    let IncrementCounterResp { signature } = conn.client.increment_counter(req).await?.into_inner();

    // verify a message that unequivocally identifies the counter and tag
    let msg = {
      let s = format!(
        "IncrementCounter id: {:?}, handle = {:?}, tag = {:?}, counter = {:?}",
        id.to_bytes(),
        handle,
        tag,
        expected_counter
      );
      NimbleDigest::digest(s.as_bytes())
    };

    let signature = Signature::from_bytes(&signature).unwrap();
    let res = signature.verify(&pk, &msg.to_bytes());
    println!("IncrementCounter: {:?}", res.is_ok());
    assert!(res.is_ok());
  }

  // Step 4: ReadCounter with the Nonce generated and check for new data
  let nonce = rand::thread_rng().gen::<[u8; 16]>();
  let req = tonic::Request::new(ReadCounterReq {
    handle: handle.clone(),
    nonce: nonce.to_vec(),
  });

  let ReadCounterResp {
    tag,
    counter,
    signature,
  } = conn.client.read_counter(req).await?.into_inner();
  assert_eq!(tag, t3.clone());
  assert_eq!(counter, expected_counter as u64);

  // verify a message that unequivocally identifies the counter and tag
  let msg = {
    let s = format!(
      "ReadCounter id: {:?}, handle = {:?}, tag = {:?}, counter = {:?}, nonce = {:?}",
      id.to_bytes(),
      handle_bytes,
      tag,
      counter,
      nonce
    );
    NimbleDigest::digest(s.as_bytes())
  };
  let signature = Signature::from_bytes(&signature).unwrap();
  let res = signature.verify(&pk, &msg.to_bytes());
  println!("ReadCounter: {:?}", res.is_ok());
  assert!(res.is_ok());

  Ok(())
}
