use clap::{App, Arg};

use serde::{Deserialize, Serialize};

use rand::Rng;

use ledger::{
  NimbleDigest,
  signature::{PublicKey, PublicKeyTrait, Signature, SignatureTrait},
};

#[derive(Debug, Serialize, Deserialize)]
struct GetIdentityResponse {
  #[serde(rename = "Identity")]
  pub id: String,
  #[serde(rename = "PublicKey")]
  pub pk: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct NewCounterRequest {
  #[serde(rename = "Tag")]
  pub tag: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct NewCounterResponse {
  #[serde(rename = "Signature")]
  pub signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct IncrementCounterRequest {
  #[serde(rename = "Tag")]
  pub tag: String,
  #[serde(rename = "ExpectedCounter")]
  pub expected_counter: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct IncrementCounterResponse {
  #[serde(rename = "Signature")]
  pub signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ReadCounterResponse {
  #[serde(rename = "Tag")]
  pub tag: String,
  #[serde(rename = "Counter")]
  pub counter: u64,
  #[serde(rename = "Signature")]
  pub signature: String,
}

#[allow(dead_code)]
enum MessageType {
  NewCounterReq,
  NewCounterResp,
  IncrementCounterReq,
  IncrementCounterResp,
  ReadCounterReq,
  ReadCounterResp,
}

#[tokio::main]
async fn main() {
  let config = App::new("client")
    .arg(
      Arg::with_name("endpoint")
        .long("endpoint")
        .short("e")
        .help("The hostname of the endpoint")
        .default_value("http://[::1]:8082"),
    )
    .arg(
      Arg::with_name("num")
        .long("num")
        .short("n")
        .help("The number of ledgers")
        .default_value("0"),
    );
  let cli_matches = config.get_matches();
  let endpoint_addr = cli_matches.value_of("endpoint").unwrap();
  let num_ledgers = cli_matches
    .value_of("num")
    .unwrap()
    .to_string()
    .parse::<usize>()
    .unwrap();

  let client = reqwest::ClientBuilder::new()
    .danger_accept_invalid_certs(true)
    .danger_accept_invalid_hostnames(true)
    .use_rustls_tls()
    .build()
    .unwrap();

  // Step 0: Obtain the identity and public key of the instance
  let get_identity_url = reqwest::Url::parse_with_params(
    &format!("{}/serviceid", endpoint_addr),
    &[("pkformat", "compressed")],
  )
  .unwrap();
  let res = client.get(get_identity_url).send().await;

  if res.is_err() {
    eprintln!("get_identity failed: {:?}", res);
    return;
  }
  let resp = res.unwrap();
  assert!(resp.status() == reqwest::StatusCode::OK);

  let get_identity_resp: GetIdentityResponse = resp.json().await.unwrap();
  let id_bytes = base64_url::decode(&get_identity_resp.id).unwrap();
  let pk_bytes = base64_url::decode(&get_identity_resp.pk).unwrap();
  let id = NimbleDigest::from_bytes(&id_bytes).unwrap();
  let pk = PublicKey::from_bytes(&pk_bytes).unwrap();

  println!("id={:?}", id);
  println!("pk={:?}", pk);

  // Step 1: NewCounter Request
  let tag_bytes: Vec<u8> = NimbleDigest::digest(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]).to_bytes();
  let handle_bytes = rand::thread_rng().r#gen::<[u8; 16]>();
  let handle = base64_url::encode(&handle_bytes);
  let new_counter_req = NewCounterRequest {
    tag: base64_url::encode(&tag_bytes),
  };
  let new_counter_url =
    reqwest::Url::parse(&format!("{}/counters/{}", endpoint_addr, handle)).unwrap();
  let res = client
    .put(new_counter_url)
    .json(&new_counter_req)
    .send()
    .await;
  if res.is_err() {
    eprintln!("new_counter failed: {:?}", res);
  }

  let resp = res.unwrap();
  assert!(resp.status() == reqwest::StatusCode::OK);

  let new_counter_resp: NewCounterResponse = resp.json().await.unwrap();
  let signature = base64_url::decode(&new_counter_resp.signature).unwrap();

  // verify a message that unequivocally identifies the counter and tag
  let msg = {
    let s = format!(
      "{}.{}.{}.{}.{}",
      base64_url::encode(&(MessageType::NewCounterResp as u64).to_le_bytes()),
      base64_url::encode(&id.to_bytes()),
      base64_url::encode(&handle_bytes),
      base64_url::encode(&0_u64.to_le_bytes()),
      base64_url::encode(&tag_bytes),
    );
    NimbleDigest::digest(s.as_bytes())
  };

  let signature = Signature::from_bytes(&signature).unwrap();
  let res = signature.verify(&pk, &msg.to_bytes());
  println!("NewCounter: {:?}", res.is_ok());
  assert!(res.is_ok());

  // Step 2: Read Latest with the Nonce generated
  let nonce_bytes = rand::thread_rng().r#gen::<[u8; 16]>();
  let nonce = base64_url::encode(&nonce_bytes);
  let read_counter_url = reqwest::Url::parse_with_params(
    &format!("{}/counters/{}", endpoint_addr, handle),
    &[("nonce", nonce)],
  )
  .unwrap();
  let res = client.get(read_counter_url).send().await;
  if res.is_err() {
    eprintln!("read_counter failed: {:?}", res);
  }

  let resp = res.unwrap();
  assert!(resp.status() == reqwest::StatusCode::OK);

  let read_counter_resp: ReadCounterResponse = resp.json().await.unwrap();
  let tag = base64_url::decode(&read_counter_resp.tag).unwrap();
  let counter = read_counter_resp.counter;
  let signature = base64_url::decode(&read_counter_resp.signature).unwrap();

  // verify a message that unequivocally identifies the counter and tag
  let msg = {
    let s = format!(
      "{}.{}.{}.{}.{}.{}",
      base64_url::encode(&(MessageType::ReadCounterResp as u64).to_le_bytes()),
      base64_url::encode(&id.to_bytes()),
      base64_url::encode(&handle_bytes),
      base64_url::encode(&counter.to_le_bytes()),
      base64_url::encode(&tag),
      base64_url::encode(&nonce_bytes),
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

  let mut expected_counter: usize = 0;
  for tag in [t1.clone(), t2.clone(), t3.clone()].iter() {
    expected_counter += 1;
    let increment_counter_req = IncrementCounterRequest {
      tag: base64_url::encode(&tag),
      expected_counter: expected_counter as u64,
    };

    let increment_counter_url =
      reqwest::Url::parse(&format!("{}/counters/{}", endpoint_addr, handle)).unwrap();
    let res = client
      .post(increment_counter_url)
      .json(&increment_counter_req)
      .send()
      .await;
    if res.is_err() {
      eprintln!("increment_counter failed: {:?}", res);
    }

    let resp = res.unwrap();
    assert!(resp.status() == reqwest::StatusCode::OK);

    let increment_counter_resp: IncrementCounterResponse = resp.json().await.unwrap();
    let signature = base64_url::decode(&increment_counter_resp.signature).unwrap();

    // verify a message that unequivocally identifies the counter and tag
    let msg = {
      let s = format!(
        "{}.{}.{}.{}.{}",
        base64_url::encode(&(MessageType::IncrementCounterResp as u64).to_le_bytes()),
        base64_url::encode(&id.to_bytes()),
        base64_url::encode(&handle_bytes),
        base64_url::encode(&(expected_counter as u64).to_le_bytes()),
        base64_url::encode(&tag),
      );
      NimbleDigest::digest(s.as_bytes())
    };

    let signature = Signature::from_bytes(&signature).unwrap();
    let res = signature.verify(&pk, &msg.to_bytes());
    println!("IncrementCounter: {:?}", res.is_ok());
    assert!(res.is_ok());
  }

  // Step 4: ReadCounter with the Nonce generated and check for new data
  let nonce_bytes = rand::thread_rng().r#gen::<[u8; 16]>();
  let nonce = base64_url::encode(&nonce_bytes);
  let read_counter_url = reqwest::Url::parse_with_params(
    &format!("{}/counters/{}", endpoint_addr, handle),
    &[("nonce", nonce)],
  )
  .unwrap();
  let res = client.get(read_counter_url).send().await;
  if res.is_err() {
    eprintln!("read_counter failed: {:?}", res);
  }

  let resp = res.unwrap();
  assert!(resp.status() == reqwest::StatusCode::OK);

  let read_counter_resp: ReadCounterResponse = resp.json().await.unwrap();
  let tag = base64_url::decode(&read_counter_resp.tag).unwrap();
  assert_eq!(tag, t3.clone());
  let counter = read_counter_resp.counter;
  assert_eq!(counter, expected_counter as u64);
  let signature = base64_url::decode(&read_counter_resp.signature).unwrap();

  // verify a message that unequivocally identifies the counter and tag
  let msg = {
    let s = format!(
      "{}.{}.{}.{}.{}.{}",
      base64_url::encode(&(MessageType::ReadCounterResp as u64).to_le_bytes()),
      base64_url::encode(&id.to_bytes()),
      base64_url::encode(&handle_bytes),
      base64_url::encode(&counter.to_le_bytes()),
      base64_url::encode(&tag),
      base64_url::encode(&nonce_bytes),
    );
    NimbleDigest::digest(s.as_bytes())
  };

  let signature = Signature::from_bytes(&signature).unwrap();
  let res = signature.verify(&pk, &msg.to_bytes());
  println!("ReadCounter: {:?}", res.is_ok());
  assert!(res.is_ok());

  if num_ledgers == 0 {
    return;
  }

  let tag_bytes: Vec<u8> = NimbleDigest::digest(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]).to_bytes();
  let new_counter_req = NewCounterRequest {
    tag: base64_url::encode(&tag_bytes),
  };
  for _idx in 0..num_ledgers {
    let handle_bytes = rand::thread_rng().r#gen::<[u8; 16]>();
    let handle = base64_url::encode(&handle_bytes);
    let new_counter_url =
      reqwest::Url::parse(&format!("{}/counters/{}", endpoint_addr, handle)).unwrap();
    let _ = client
      .put(new_counter_url)
      .json(&new_counter_req)
      .send()
      .await;
  }
}
