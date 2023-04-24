use clap::{App, Arg};

use serde::{Deserialize, Serialize};
use std::time::Instant;

#[derive(Debug, Serialize, Deserialize)]
struct EndorserOpResponse {
  #[serde(rename = "PublicKey")]
  pub pk: String,
}

#[tokio::main]
async fn main() {
  let config = App::new("client")
    .arg(
      Arg::with_name("coordinator")
        .short("c")
        .long("coordinator")
        .help("The hostname of the coordinator")
        .default_value("http://127.0.0.1:8090"),
    )
    .arg(
      Arg::with_name("add")
        .short("a")
        .long("add")
        .takes_value(true)
        .help("Endorser to add"),
    )
    .arg(
      Arg::with_name("delete")
        .short("d")
        .long("delete")
        .takes_value(true)
        .help("Endorser to delete"),
    )
    .arg(
      Arg::with_name("get")
        .short("g")
        .long("get")
        .takes_value(true)
        .help("Endorser to read"),
    );
  let cli_matches = config.get_matches();
  let coordinator_addr = cli_matches.value_of("coordinator").unwrap();

  let client = reqwest::Client::new();

  if let Some(x) = cli_matches.value_of("add") {
    let uri = base64_url::encode(&x);
    let endorser_url =
      reqwest::Url::parse(&format!("{}/endorsers/{}", coordinator_addr, uri)).unwrap();

    let now = Instant::now();
    let res = client.put(endorser_url).send().await;
    println!("Reconfiguration time: {} ms", now.elapsed().as_millis());

    match res {
      Ok(resp) => {
        assert!(resp.status() == reqwest::StatusCode::OK);
        let endorser_op_resp: EndorserOpResponse = resp.json().await.unwrap();
        let pk = base64_url::decode(&endorser_op_resp.pk).unwrap();
        println!("add_endorser: {} {:?}", x, pk);
      },
      Err(error) => {
        eprintln!("add_endorser failed: {:?}", error);
      },
    }
  }
  if let Some(x) = cli_matches.value_of("delete") {
    let uri = base64_url::encode(&x);
    let endorser_url =
      reqwest::Url::parse(&format!("{}/endorsers/{}", coordinator_addr, uri)).unwrap();
    let res = client.delete(endorser_url).send().await;
    match res {
      Ok(resp) => {
        assert!(resp.status() == reqwest::StatusCode::OK);
        let endorser_op_resp: EndorserOpResponse = resp.json().await.unwrap();
        let pk = base64_url::decode(&endorser_op_resp.pk).unwrap();
        println!("delete_endorser: {} {:?}", x, pk);
      },
      Err(error) => {
        eprintln!("delete_endorser failed: {:?}", error);
      },
    }
  }
  if let Some(x) = cli_matches.value_of("get") {
    let uri = base64_url::encode(&x);
    let endorser_url =
      reqwest::Url::parse(&format!("{}/endorsers/{}", coordinator_addr, uri)).unwrap();
    let res = client.get(endorser_url).send().await;
    match res {
      Ok(resp) => {
        assert!(resp.status() == reqwest::StatusCode::OK);
        let endorser_op_resp: EndorserOpResponse = resp.json().await.unwrap();
        let pk = base64_url::decode(&endorser_op_resp.pk).unwrap();
        println!("get_endorser: {} {:?}", x, pk);
      },
      Err(error) => {
        eprintln!("get_endorser failed: {:?}", error);
      },
    }
  }
}
