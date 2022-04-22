use clap::{App, Arg};
use mongodb::Client;
use serde::{Deserialize, Serialize};
use std::time::Instant;

async fn reset_cosmosdb(conn_string: &str, dbname: &str) {
  let res = Client::with_uri_str(conn_string).await;
  if res.is_err() {
    eprintln!("Connection with cosmosdb failed");
    return;
  }
  let cosmos_client = res.unwrap();

  cosmos_client
    .database(dbname)
    .drop(None)
    .await
    .expect("failed to delete ledgers");

  println!("reset database {}", dbname);
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct DBEntry {
  index: i64,
  value: String,
}

async fn perf_test(conn_string: &str, dbname: &str) {
  let res = Client::with_uri_str(conn_string).await;
  if res.is_err() {
    eprintln!("Connection with cosmosdb failed");
    return;
  }
  let cosmos_client = res.unwrap();

  let mut value = String::new();
  for _ in 1..900 {
    value.push('a');
  }
  let total: i64 = 100;
  let now = Instant::now();
  for i in 1..total {
    let ledger = cosmos_client
      .database(dbname)
      .collection::<DBEntry>(&format!("perftest{}", i));
    ledger
      .insert_one(
        DBEntry {
          index: i,
          value: value.clone(),
        },
        None,
      )
      .await
      .expect("this should work");
  }
  println!(
    "Average time over 100 operations is {} ms",
    now.elapsed().as_millis() / (total as u128)
  );
  cosmos_client
    .database(dbname)
    .drop(None)
    .await
    .expect("failed to delete ledgers");
  println!("reset database {}", dbname);
}

#[tokio::main]
async fn main() {
  let config = App::new("helper")
    .arg(
      Arg::with_name("action")
        .short("a")
        .long("action")
        .takes_value(true)
        .help("The action to take"),
    )
    .arg(
      Arg::with_name("nimbledb")
        .short("n")
        .long("nimbledb")
        .takes_value(true)
        .help("The database name"),
    )
    .arg(
      Arg::with_name("cosmosurl")
        .short("c")
        .long("cosmosurl")
        .takes_value(true)
        .help("The COSMOS URL"),
    );
  let cli_matches = config.get_matches();
  let action = cli_matches.value_of("action").unwrap();
  let cosmos = cli_matches.value_of("cosmosurl").unwrap();
  let dbname = cli_matches.value_of("nimbledb").unwrap();

  match action {
    "reset" => {
      reset_cosmosdb(cosmos, dbname).await;
    },
    "perf" => {
      perf_test(cosmos, dbname).await;
    },
    _ => {
      panic!("Unknown action {}", action);
    },
  }
}
