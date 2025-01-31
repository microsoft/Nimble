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
        .default_value("http://localhost:8090"),
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
    )
    .arg(
      Arg::with_name("gettimeoutmap")
      .long("gettimeoutmap")
      .help("Get the timeout map of endorsers")
      .takes_value(false),
    )
    .arg(
      Arg::with_name("pingallendorsers")
      .long("pingallendorsers")
      .help("Ping all endorsers")
      .takes_value(false),
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
  if cli_matches.is_present("gettimeoutmap") {
    let endorser_url = reqwest::Url::parse(&format!("{}/timeoutmap", coordinator_addr)).unwrap();
    let res = client.get(endorser_url).send().await;
    match res {
      Ok(resp) => {
        assert!(resp.status() == reqwest::StatusCode::OK);
        let timeout_map: serde_json::Value = resp.json().await.unwrap();
        println!("Timeout map: {:?}", timeout_map);
      },
      Err(error) => {
        eprintln!("get_timeout_map failed: {:?}", error);
      },
    }
  }
  if cli_matches.is_present("pingallendorsers") {
    let endorser_url = reqwest::Url::parse(&format!("{}/pingallendorsers", coordinator_addr)).unwrap();
    let res = client.get(endorser_url).send().await;
    match res {
      Ok(resp) => {
        assert!(resp.status() == reqwest::StatusCode::OK);
        let ping_results: serde_json::Value = resp.json().await.unwrap();
        println!("Ping all endorsers: {:?}", ping_results);
      },
      Err(error) => {
        eprintln!("ping_all_endorsers failed: {:?}", error);
      },
    }
  }
}
