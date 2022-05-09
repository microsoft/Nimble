use clap::{App, Arg};
use mongodb::{bson::doc, Client};
use serde::{Deserialize, Serialize};
use std::time::Instant;

use azure_data_tables::{prelude::*, responses::GetEntityResponse};
use azure_storage::core::prelude::*;
use azure_storage_blobs::{prelude::*, BA512Range};
use std::time::Duration;

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

async fn reset_pageblob(storage_name: &str, key: &str, dbname: &str) {
  let http_client = azure_core::new_http_client();
  let storage_client = StorageAccountClient::new_access_key(http_client.clone(), storage_name, key);
  let container_client = storage_client.as_container_client(dbname);

  container_client
    .delete()
    .execute()
    .await
    .expect("failed to delete ledgers");
}

async fn reset_table(storage_name: &str, key: &str, dbname: &str) {
  let http_client = azure_core::new_http_client();
  let storage_client = StorageAccountClient::new_access_key(http_client.clone(), storage_name, key);
  let table_service = storage_client
    .as_storage_client()
    .as_table_service_client()
    .expect("failed to initialize table service");

  let table_client = table_service.as_table_client(dbname);
  table_client.delete().execute().await.expect("should work");
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct DBEntry {
  #[serde(rename = "_id")]
  index: i64,
  value: String,
}

async fn perf_test_cosmosdb(conn_string: &str, dbname: &str) {
  let res = Client::with_uri_str(conn_string).await;
  if res.is_err() {
    eprintln!("Connection with cosmosdb failed");
    return;
  }
  let cosmos_client = res.unwrap();

  let mut value = String::new();
  for _ in 0..900 {
    value.push('a');
  }
  let total: i64 = 100;

  // Measure create collection + insert (collection creation is lazy so
  // we need at least one insert to make it happen)

  let now = Instant::now();
  for i in 0..total {
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
    "[COSMOSDB] Create collection + 1 insert takes {} ms",
    now.elapsed().as_millis() / (total as u128)
  );

  // Measure insert
  let ledger = cosmos_client
    .database(dbname)
    .collection::<DBEntry>("perftest0");

  let now = Instant::now();
  for i in 0..total {
    ledger
      .insert_one(
        DBEntry {
          index: i + 1,
          value: value.clone(),
        },
        None,
      )
      .await
      .expect("this should work");
  }

  println!(
    "[COSMOSDB] Inserting an entry takes {} ms",
    now.elapsed().as_millis() / (total as u128)
  );

  // Measure read
  let now = Instant::now();
  for i in 0..total {
    let _res = ledger
      .find_one(
        doc! {
            "_id": i,
        },
        None,
      )
      .await
      .expect("this should work");
  }

  println!(
    "[COSMOSDB] Read an entry takes {} ms",
    now.elapsed().as_millis() / (total as u128)
  );

  cosmos_client
    .database(dbname)
    .drop(None)
    .await
    .expect("failed to delete ledgers");
  println!("[COSMOSDB] resetting database {}", dbname);
}

const CREATE_TIMEOUT: u64 = 10; // seconds
const PAGE_BLOB_SIZE: u128 = 1024 * 1000;
const LOGICAL_PAGE_SIZE: usize = 1024;

fn index_to_page_range(index: u64) -> BA512Range {
  BA512Range::new(
    index * LOGICAL_PAGE_SIZE as u64,
    (index + 1) * LOGICAL_PAGE_SIZE as u64 - 1,
  )
  .unwrap()
}

async fn perf_test_pageblob(storage_name: &str, key: &str, dbname: &str) {
  let http_client = azure_core::new_http_client();
  let storage_client = StorageAccountClient::new_access_key(http_client.clone(), storage_name, key);
  let container_client = storage_client.as_container_client(dbname);

  container_client
    .create()
    .public_access(PublicAccess::None)
    .timeout(Duration::from_secs(CREATE_TIMEOUT))
    .execute()
    .await
    .expect("this should work");

  let mut value = String::new();
  for _ in 0..900 {
    value.push('a');
  }

  let mut serialized_value = bincode::serialize(&value).unwrap();
  serialized_value.resize(LOGICAL_PAGE_SIZE, 0);
  let digest = md5::compute(serialized_value.clone());

  let total: u64 = 100;

  // Measure create collection + insert (collection creation is lazy so
  // we need at least one insert to make it happen)

  let now = Instant::now();
  for i in 0..total {
    let ledger = container_client.as_blob_client(&format!("perftest{}", i));
    ledger
      .put_page_blob(PAGE_BLOB_SIZE)
      .content_type("binary")
      .execute()
      .await
      .expect("this should work");

    let range = index_to_page_range(i);

    ledger
      .update_page(range, serialized_value.clone())
      .hash(&digest.into())
      .execute()
      .await
      .expect("this should work");
  }

  println!(
    "[PAGEBLOB] Create blob + 1 page update takes {} ms",
    now.elapsed().as_millis() / (total as u128)
  );

  // Measure update

  let ledger = container_client.as_blob_client("perftest0");
  let now = Instant::now();
  for i in 0..total {
    let range = index_to_page_range(i);

    ledger
      .update_page(range, serialized_value.clone())
      .hash(&digest.into())
      .execute()
      .await
      .expect("this should work");
  }

  println!(
    "[PAGEBLOB] Updating a page takes {} ms",
    now.elapsed().as_millis() / (total as u128)
  );

  // Measure get
  let now = Instant::now();

  for i in 0..total {
    let range = index_to_page_range(i);
    let _res = ledger.get().range(range).execute().await;
  }

  println!(
    "[PAGEBLOB] Getting a page takes {} ms",
    now.elapsed().as_millis() / (total as u128)
  );

  container_client
    .delete()
    .execute()
    .await
    .expect("failed to delete ledgers");

  println!("[PAGEBLOB] resetting database {}", dbname);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TableEntry {
  #[serde(rename = "PartitionKey")]
  pub ledger: String,
  #[serde(rename = "RowKey")]
  pub key: String,
  pub value: String,
}

async fn perf_test_table(storage_name: &str, key: &str, dbname: &str) {
  let http_client = azure_core::new_http_client();
  let storage_client = StorageAccountClient::new_access_key(http_client.clone(), storage_name, key);
  let table_service = storage_client
    .as_storage_client()
    .as_table_service_client()
    .expect("failed to initialize table service");

  let table_client = table_service.as_table_client(dbname);

  // Create table
  table_client
    .create()
    .execute()
    .await
    .expect("this should work");

  let mut value = String::new();
  for _ in 0..900 {
    value.push('a');
  }

  let total: u64 = 100;

  let mut tail_entity = TableEntry {
    ledger: "nimble123".to_owned(),
    key: "TAIL".to_owned(),
    value: value.clone(),
  };

  let mut entity = TableEntry {
    ledger: "nimble123".to_owned(),
    key: "0".to_owned(),
    value: value.clone(),
  };

  // Insert TAIL first
  table_client
    .insert()
    .execute(&tail_entity)
    .await
    .expect("should work");

  // Measure insert time
  let now = Instant::now();
  for i in 0..total {
    entity.key = format!("test{}", i).to_owned();
    table_client
      .insert()
      .execute(&entity)
      .await
      .expect("should work");
  }
  println!(
    "[TABLE] Inserting one row takes {} ms",
    now.elapsed().as_millis() / (total as u128)
  );

  let partition_client = table_client.as_partition_key_client("nimble123");
  let tail_client = partition_client
    .as_entity_client("TAIL")
    .expect("should work");

  // Measure update + insert transaction
  let now = Instant::now();
  for i in 0..total {
    entity.key = i.to_string();
    entity.value = value.clone() + &i.to_string();
    tail_entity.value = entity.value.clone();

    let mut transaction = Transaction::default();
    // Update the tail
    transaction.add(
      tail_client
        .update()
        .to_transaction_operation(&tail_entity, &IfMatchCondition::Any)
        .expect("should work"),
    );

    // Add row
    transaction.add(
      table_client
        .insert()
        .to_transaction_operation(&entity)
        .expect("should work"),
    );
    partition_client
      .submit_transaction()
      .execute(&transaction)
      .await
      .expect("should work");
  }

  println!(
    "[TABLE] Updating tail and inserting row takes {} ms",
    now.elapsed().as_millis() / (total as u128)
  );

  // Measure get
  let now = Instant::now();

  for i in 0..total {
    let client = partition_client
      .as_entity_client(&i.to_string())
      .expect("should work");
    let _res: GetEntityResponse<TableEntry> = client.get().execute().await.expect("should work");
  }

  println!(
    "[TABLE] Getting a row takes {} ms",
    now.elapsed().as_millis() / (total as u128)
  );

  table_client.delete().execute().await.expect("should work");
  println!("[TABLE] resetting database {}", dbname);
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
    )
    .arg(
      Arg::with_name("storagename")
        .short("s")
        .long("storagename")
        .takes_value(true)
        .help("The pageblob storage name"),
    )
    .arg(
      Arg::with_name("key")
        .short("k")
        .long("key")
        .takes_value(true)
        .help("The pageblob primary key"),
    );

  let cli_matches = config.get_matches();
  let action = cli_matches.value_of("action").unwrap();
  let dbname = cli_matches.value_of("nimbledb").unwrap();

  match action {
    "reset_cosmos" => {
      let cosmos = cli_matches.value_of("cosmosurl").unwrap();

      reset_cosmosdb(cosmos, dbname).await;
    },
    "perf_cosmos" => {
      let cosmos = cli_matches.value_of("cosmosurl").unwrap();

      perf_test_cosmosdb(cosmos, dbname).await;
    },
    "reset_pageblob" => {
      let storage_name = cli_matches.value_of("storagename").unwrap();
      let primary_key = cli_matches.value_of("key").unwrap();

      reset_pageblob(storage_name, primary_key, dbname).await;
    },
    "perf_pageblob" => {
      let storage_name = cli_matches.value_of("storagename").unwrap();
      let primary_key = cli_matches.value_of("key").unwrap();

      perf_test_pageblob(storage_name, primary_key, dbname).await;
    },
    "perf_table" => {
      let storage_name = cli_matches.value_of("storagename").unwrap();
      let primary_key = cli_matches.value_of("key").unwrap();

      perf_test_table(storage_name, primary_key, dbname).await;
    },
    "reset_table" => {
      let storage_name = cli_matches.value_of("storagename").unwrap();
      let primary_key = cli_matches.value_of("key").unwrap();

      reset_table(storage_name, primary_key, dbname).await;
    },
    _ => {
      panic!("Unknown action {}", action);
    },
  }
}
