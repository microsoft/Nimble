use crate::{
  errors::{LedgerStoreError, StorageError},
  LedgerEntry, LedgerStore,
};
use async_trait::async_trait;
use azure_data_tables::{clients::TableClient, prelude::*};

use azure_core::Etag;
use azure_storage::core::prelude::*;
use base64_url;
use ledger::{Block, CustomSerde, Handle, NimbleDigest, Receipt};
use serde::{Deserialize, Serialize};
use std::{
  collections::HashMap,
  convert::TryFrom,
  fmt::Debug,
  sync::{Arc, RwLock},
};

use http::{self, StatusCode};

const TAIL: &str = "TAIL";

/*
  StatusCode::BAD_REQUEST, // Code 400, thrown when request is invalid (bad size, bad name)
  StatusCode::NOT_FOUND,   // Code 404, blob not found
  StatusCode::CONFLICT,    // Code 409, container already exists
  StatusCode::PRECONDITION_FAILED, // Code 412, thrown when etag does not match
  StatusCode::RANGE_NOT_SATISFIABLE, // Code 416, thrown when the range is out of bounds
*/

macro_rules! checked_increment {
  ($x:expr) => {
    match $x.checked_add(1) {
      None => {
        return Err(LedgerStoreError::LedgerError(
          StorageError::LedgerHeightOverflow,
        ));
      },
      Some(e) => e,
    }
  };
}

macro_rules! checked_conversion {
  ($x:expr, $type:tt) => {
    match $type::try_from($x) {
      Err(_) => {
        return Err(LedgerStoreError::LedgerError(StorageError::IntegerOverflow));
      },
      Ok(v) => v,
    }
  };
}

macro_rules! get_error_status {
  ($x:expr) => {
    match $x.downcast_ref::<azure_core::HttpError>() {
      Some(e) => match e {
        azure_core::HttpError::StatusCode { status, body: _ } => *status,
        _ => {
          eprintln!("Error is {:?}", e);
          return Err(LedgerStoreError::LedgerError(StorageError::UnhandledError));
        },
      },
      None => {
        eprintln!("Error is {:?}", $x);
        return Err(LedgerStoreError::LedgerError(StorageError::UnhandledError));
      },
    }
  };
}

type CacheEntry = Arc<RwLock<i64>>; // offset
type CacheMap = Arc<RwLock<HashMap<String, CacheEntry>>>;

#[derive(Clone, Serialize, Deserialize, Debug)]
struct DBEntry {
  #[serde(rename = "PartitionKey")]
  pub handle: String,
  #[serde(rename = "RowKey")]
  pub row: String,
  pub height: i64,
  pub block: String,
  pub receipt: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct MergeDBEntry {
  #[serde(rename = "PartitionKey")]
  pub handle: String,
  #[serde(rename = "RowKey")]
  pub row: String,
  pub receipt: String,
}

#[derive(Debug)]
pub struct TableLedgerStore {
  client: Arc<TableClient>,
  view_handle: Handle,
  cache: CacheMap,
}

impl TableLedgerStore {
  pub async fn new(args: &HashMap<String, String>) -> Result<Self, LedgerStoreError> {
    if !args.contains_key("STORAGE_ACCOUNT") || !args.contains_key("STORAGE_MASTER_KEY") {
      return Err(LedgerStoreError::LedgerError(
        StorageError::MissingArguments,
      ));
    }
    let account = args["STORAGE_ACCOUNT"].clone();
    let master_key = args["STORAGE_MASTER_KEY"].clone();

    // Below is the desired name of the container that will hold the blobs
    // (it can be anything initially, but afterwards, it needs to be the same
    // so you access the same container and recover the stored data)
    let mut nimble_db_name = String::from("nimbletablestore");
    if args.contains_key("NIMBLE_DB") {
      nimble_db_name = args["NIMBLE_DB"].clone();
    }

    let http_client = azure_core::new_http_client();
    let storage_client =
      StorageAccountClient::new_access_key(http_client.clone(), &account, &master_key);
    let table_service = match storage_client.as_storage_client().as_table_service_client() {
      Ok(v) => v,
      Err(e) => {
        eprintln!("Unable to convert to table service client: {:?}", e);
        return Err(LedgerStoreError::LedgerError(StorageError::InvalidDBUri));
      },
    };

    let table_client = table_service.as_table_client(nimble_db_name);

    let view_handle = match NimbleDigest::from_bytes(&vec![0u8; NimbleDigest::num_bytes()]) {
      Ok(e) => e,
      Err(_) => {
        return Err(LedgerStoreError::LedgerError(
          StorageError::DeserializationError,
        ));
      },
    };

    let cache = Arc::new(RwLock::new(HashMap::new()));

    let ledger_store = TableLedgerStore {
      client: table_client,
      view_handle,
      cache,
    };

    // Try to create table. If it exists that's fine.
    let res = ledger_store.client.create().execute().await;

    if let Err(err) = res {
      match get_error_status!(err) {
        StatusCode::CONFLICT => (), // table already exists which is fine
        StatusCode::BAD_REQUEST => {
          return Err(LedgerStoreError::LedgerError(StorageError::InvalidDBName));
        },
        _ => {
          eprintln!("Error is {:?}", err);
          return Err(LedgerStoreError::LedgerError(StorageError::UnhandledError));
        },
      }
    }

    let view_handle_string = base64_url::encode(&view_handle.to_bytes());

    // Check if the view ledger exists, if not, create a new one
    let res = ledger_store.read_view_ledger_tail().await;
    match res {
      Err(error) => {
        match error {
          // Ledger does not exist ERROR
          LedgerStoreError::LedgerError(StorageError::KeyDoesNotExist) => {
            // Initialized view ledger's entry
            let entry = DBEntry {
              handle: view_handle_string.clone(),
              row: 0.to_string(),
              height: 0,
              block: base64_url::encode(&Block::new(&[0; 0]).to_bytes()),
              receipt: base64_url::encode(&Receipt::default().to_bytes()),
            };

            insert_row(ledger_store.client.clone(), &view_handle_string, entry).await?;
            update_cache_entry(&view_handle_string, &ledger_store.cache, 0)?;
          },
          _ => {
            eprintln!("Error is {:?}", error);
            return Err(LedgerStoreError::LedgerError(StorageError::UnhandledError));
          },
        };
      },
      Ok(v) => {
        // Since view ledger exists, update the cache height with the latest height
        update_cache_entry(
          &view_handle_string,
          &ledger_store.cache,
          checked_conversion!(v.1, i64),
        )?;
      },
    };

    Ok(ledger_store)
  }
}

async fn insert_row(
  table_client: Arc<TableClient>,
  handle: &str,
  entry: DBEntry,
) -> Result<(), LedgerStoreError> {
  let partition_client = table_client.as_partition_key_client(handle);
  let tail_client = match partition_client.as_entity_client(TAIL) {
    Ok(v) => v,
    Err(e) => {
      eprintln!("Error in insert row: {:?}", e);
      return Err(LedgerStoreError::LedgerError(StorageError::UnhandledError));
    },
  };

  let mut tail_entry = entry.clone();
  tail_entry.row = TAIL.to_owned();

  let tail_update = match tail_client
    .insert_or_replace()
    .to_transaction_operation(&tail_entry)
  {
    Ok(v) => v,
    Err(e) => {
      eprintln!("Cannot create transaction operation due to error: {:?}", e);
      return Err(LedgerStoreError::LedgerError(StorageError::UnhandledError));
    },
  };

  let row_insert = match table_client.insert().to_transaction_operation(&entry) {
    Ok(v) => v,
    Err(e) => {
      eprintln!("Cannot create transaction operation due to error: {:?}", e);
      return Err(LedgerStoreError::LedgerError(StorageError::UnhandledError));
    },
  };

  // construct transaction
  let mut transaction = Transaction::default();
  transaction.add(row_insert);
  transaction.add(tail_update);
  let res = partition_client
    .submit_transaction()
    .execute(&transaction)
    .await;

  if let Err(err) = res {
    match get_error_status!(err) {
      StatusCode::RANGE_NOT_SATISFIABLE => {
        return Err(LedgerStoreError::LedgerError(StorageError::InvalidIndex));
      },
      StatusCode::NOT_FOUND => {
        return Err(LedgerStoreError::LedgerError(StorageError::KeyDoesNotExist));
      },
      StatusCode::PRECONDITION_FAILED => {
        return Err(LedgerStoreError::LedgerError(
          StorageError::ConcurrentOperation,
        ));
      },
      _ => {
        eprintln!("Error is {:?}", err);
        return Err(LedgerStoreError::LedgerError(StorageError::UnhandledError));
      },
    }
  }

  let res = res.unwrap();

  // For each of the operation in the transaction, check they completed.

  for r in res.operation_responses {
    if r.status_code.is_client_error() || r.status_code.is_server_error() {
      match r.status_code {
        StatusCode::BAD_REQUEST => {
          eprintln!("The request in insert row was invalid.");
          return Err(LedgerStoreError::LedgerError(StorageError::InvalidIndex));
        },
        _ => {
          eprintln!("Some other status code {:?}", r);
          return Err(LedgerStoreError::LedgerError(StorageError::UnhandledError));
        },
      }
    }
  }

  Ok(())
}

async fn find_db_entry(
  ledger: Arc<TableClient>,
  handle: &str,
  row: &str,
) -> Result<(DBEntry, Etag), LedgerStoreError> {
  let partition_client = ledger.as_partition_key_client(handle);
  let row_client = match partition_client.as_entity_client(row) {
    Ok(v) => v,
    Err(e) => {
      eprintln!("Error in find_db_entry: {:?}", e);
      return Err(LedgerStoreError::LedgerError(StorageError::UnhandledError));
    },
  };

  let res = row_client.get().execute().await;

  if let Err(err) = res {
    match get_error_status!(err) {
      StatusCode::RANGE_NOT_SATISFIABLE => {
        return Err(LedgerStoreError::LedgerError(StorageError::InvalidIndex));
      },
      StatusCode::NOT_FOUND => {
        return Err(LedgerStoreError::LedgerError(StorageError::KeyDoesNotExist));
      },
      StatusCode::PRECONDITION_FAILED => {
        return Err(LedgerStoreError::LedgerError(
          StorageError::ConcurrentOperation,
        ));
      },
      _ => {
        eprintln!("Error is {:?}", err);
        return Err(LedgerStoreError::LedgerError(StorageError::UnhandledError));
      },
    }
  }

  let res = res.unwrap();
  Ok((res.entity, res.etag))
}

async fn append_ledger_op(
  handle: &str,
  block: &Block,
  expected_height: Option<usize>,
  ledger: Arc<TableClient>,
  cache: &CacheMap,
) -> Result<usize, LedgerStoreError> {
  // Get current height and then increments it
  let height = get_cached_entry(handle, cache, ledger.clone()).await?;
  let height_plus_one = checked_increment!(height);

  // 2. If it is a conditional update, check if condition still holds
  if let Some(h) = expected_height {
    let checked_h = checked_conversion!(h, i64);

    if checked_h != height_plus_one {
      // Either condition no longer holds or cache is stale for some reason
      // Get latest height and double check
      let height = find_ledger_height(ledger.clone(), handle).await?;
      let height_plus_one = checked_increment!(height);

      // Might as well update the cache
      update_cache_entry(handle, cache, height)?;

      // Condition no longer holds
      if checked_h != height_plus_one {
        eprintln!(
          "Expected height {};  Height-plus-one: {}",
          expected_height.unwrap(),
          height_plus_one
        );

        return Err(LedgerStoreError::LedgerError(
          StorageError::IncorrectConditionalData,
        ));
      }
    }
  }

  // 3. Construct the new entry we are going to append to the ledger
  let new_entry = DBEntry {
    handle: handle.to_owned(),
    row: height_plus_one.to_string(),
    height: height_plus_one,
    block: base64_url::encode(&block.to_bytes()),
    receipt: base64_url::encode(&Receipt::default().to_bytes()),
  };

  // 4. Try to insert the new entry into the ledger.
  insert_row(ledger, handle, new_entry).await?;

  // Update the cached height and etag for this ledger
  update_cache_entry(handle, cache, height_plus_one)?;

  let res = match usize::try_from(height_plus_one) {
    Err(_) => {
      return Err(LedgerStoreError::LedgerError(StorageError::IntegerOverflow));
    },
    Ok(v) => v,
  };

  Ok(res)
}

async fn attach_ledger_receipt_op(
  handle: &str,
  receipt: &Receipt,
  ledger: Arc<TableClient>,
) -> Result<(), LedgerStoreError> {
  // 1. Get the desired index.
  let index = receipt.get_height().to_string();

  // 2. Update the row with the new receipt
  let merge_entry = MergeDBEntry {
    handle: handle.to_owned(),
    row: index.clone(),
    receipt: base64_url::encode(&receipt.to_bytes()),
  };

  let partition_client = ledger.as_partition_key_client(handle);
  let row_client = match partition_client.as_entity_client(&index) {
    Ok(v) => v,
    Err(e) => {
      eprintln!("Unable to get row client in attach ledger receipt: {:?}", e);
      return Err(LedgerStoreError::LedgerError(StorageError::UnhandledError));
    },
  };

  //XXX: WE ARE NOT PERFORMING ANY CHECKS (see the above condition being ANY).
  //This could lead to the receipt being overwritten by another coordinator.
  let res = row_client
    .merge()
    .execute(&merge_entry, &IfMatchCondition::Any)
    .await;

  if let Err(err) = res {
    match get_error_status!(err) {
      StatusCode::RANGE_NOT_SATISFIABLE => {
        return Err(LedgerStoreError::LedgerError(StorageError::InvalidIndex));
      },
      StatusCode::NOT_FOUND => {
        return Err(LedgerStoreError::LedgerError(StorageError::KeyDoesNotExist));
      },
      StatusCode::PRECONDITION_FAILED => {
        return Err(LedgerStoreError::LedgerError(
          StorageError::ConcurrentOperation,
        ));
      },
      _ => {
        eprintln!("Error is {:?}", err);
        return Err(LedgerStoreError::LedgerError(StorageError::UnhandledError));
      },
    }
  }

  Ok(())
}

async fn read_ledger_op(
  handle: &str,
  req_idx: Option<usize>,
  ledger: Arc<TableClient>,
  cache: &CacheMap,
) -> Result<(LedgerEntry, usize), LedgerStoreError> {
  let cached_index = get_cached_entry(handle, cache, ledger.clone()).await?;

  let index = if req_idx.is_some() {
    let req_idx = checked_conversion!(req_idx.unwrap(), i64);

    // Index requested is higher than cached index. Either the row does not exist or the cache is stale.
    if req_idx > cached_index {
      let latest_index = find_ledger_height(ledger.clone(), handle).await?;

      // Cache is stale. Update the cache
      if cached_index < latest_index {
        update_cache_entry(handle, cache, latest_index)?;

        // Case 1. Cache is stale AND the requested index is valid after all. Proceed.
        if req_idx <= latest_index {
          req_idx.to_string()
        } else {
          // Case 2. Cache is stale but the requested row is invalid
          return Err(LedgerStoreError::LedgerError(StorageError::InvalidIndex));
        }
      } else {
        // Case 3. Cache is fine and therefore the requested row is invalid
        return Err(LedgerStoreError::LedgerError(StorageError::InvalidIndex));
      }
    } else {
      // Case 4. Requested index is within cached range. Let's use that instead of the one in the cache.
      req_idx.to_string()
    }
  } else {
    // No index was requested, get the TAIL
    TAIL.to_owned()
  };

  let (entry, _etag) = find_db_entry(ledger, handle, &index).await?;

  let entry_bytes = match base64_url::decode(&entry.block) {
    Ok(v) => v,
    Err(e) => {
      eprintln!("Unable to decode entry in read_ledger_op {:?}", e);
      return Err(LedgerStoreError::LedgerError(
        StorageError::DeserializationError,
      ));
    },
  };

  let receipt_bytes = match base64_url::decode(&entry.receipt) {
    Ok(v) => v,
    Err(e) => {
      eprintln!("Unable to decode entry in read_ledger_op, {:?}", e);
      return Err(LedgerStoreError::LedgerError(
        StorageError::DeserializationError,
      ));
    },
  };

  // 2. Return ledger entry by deserializing its contents
  Ok((
    LedgerEntry::new(
      Block::from_bytes(&entry_bytes).unwrap(),
      Receipt::from_bytes(&receipt_bytes).unwrap(),
    ),
    checked_conversion!(entry.height, usize),
  ))
}

async fn get_cached_entry(
  handle: &str,
  cache: &CacheMap,
  ledger: Arc<TableClient>,
) -> Result<i64, LedgerStoreError> {
  if let Ok(read_map) = cache.read() {
    if let Some(cache_entry) = read_map.get(handle) {
      if let Ok(height) = cache_entry.read() {
        return Ok(*height);
      } else {
        return Err(LedgerStoreError::LedgerError(
          StorageError::LedgerReadLockFailed,
        ));
      }
    }
  } else {
    return Err(LedgerStoreError::LedgerError(
      StorageError::LedgerReadLockFailed,
    ));
  }

  // If above doesn't return, it means the entry isn't around and we need to populate it.
  let entry = find_ledger_height(ledger, handle).await?;

  if let Ok(mut write_map) = cache.write() {
    write_map
      .entry(handle.to_owned())
      .or_insert_with(|| Arc::new(RwLock::new(entry)));
    Ok(entry)
  } else {
    Err(LedgerStoreError::LedgerError(
      StorageError::LedgerWriteLockFailed,
    ))
  }
}

// This is called when the cache height is incorrect (e.g., concurrent appends)
async fn fix_cached_entry(
  handle: &str,
  cache: &CacheMap,
  ledger: Arc<TableClient>,
) -> Result<(), LedgerStoreError> {
  // find the correct height and etag
  let height = find_ledger_height(ledger, handle).await?;
  update_cache_entry(handle, cache, height)?;

  Ok(())
}

fn update_cache_entry(
  handle: &str,
  cache: &CacheMap,
  new_height: i64,
) -> Result<(), LedgerStoreError> {
  if let Ok(cache_map) = cache.read() {
    if let Some(cache_entry) = cache_map.get(handle) {
      if let Ok(mut entry) = cache_entry.write() {
        *entry = new_height;
        return Ok(());
      } else {
        return Err(LedgerStoreError::LedgerError(
          StorageError::LedgerWriteLockFailed,
        ));
      };
    }
  } else {
    return Err(LedgerStoreError::LedgerError(
      StorageError::LedgerReadLockFailed,
    ));
  }

  // If above doesn't return, it means the entry isn't around and we need to populate it.
  if let Ok(mut write_map) = cache.write() {
    write_map.insert(handle.to_owned(), Arc::new(RwLock::new(new_height)));
  } else {
    return Err(LedgerStoreError::LedgerError(
      StorageError::LedgerWriteLockFailed,
    ));
  }

  Ok(())
}

async fn find_ledger_height(
  ledger: Arc<TableClient>,
  handle: &str,
) -> Result<i64, LedgerStoreError> {
  // Find the tail, then figure out its height (the tail always contains the latest height).
  let (entry, _etag) = find_db_entry(ledger, handle, TAIL).await?;
  Ok(entry.height)
}

#[async_trait]
impl LedgerStore for TableLedgerStore {
  async fn create_ledger(
    &self,
    handle: &Handle,
    genesis_block: Block,
  ) -> Result<(), LedgerStoreError> {
    let ledger = self.client.clone();
    let handle_string = base64_url::encode(&handle.to_bytes());

    let entry = DBEntry {
      handle: handle_string.clone(),
      row: 0.to_string(),
      height: 0,
      block: base64_url::encode(&genesis_block.to_bytes()),
      receipt: base64_url::encode(&Receipt::default().to_bytes()),
    };

    insert_row(ledger, &handle_string, entry).await?;
    update_cache_entry(&handle_string, &self.cache, 0)?;

    Ok(())
  }

  async fn append_ledger(
    &self,
    handle: &Handle,
    block: &Block,
    expected_height: Option<usize>,
  ) -> Result<usize, LedgerStoreError> {
    let ledger = self.client.clone();
    let handle_string = base64_url::encode(&handle.to_bytes());

    loop {
      let res = append_ledger_op(
        &handle_string,
        block,
        expected_height,
        ledger.clone(),
        &self.cache,
      )
      .await;
      match res {
        Ok(v) => {
          return Ok(v);
        },
        Err(e) => {
          match e {
            LedgerStoreError::LedgerError(StorageError::ConcurrentOperation) => {
              fix_cached_entry(&handle_string, &self.cache, ledger.clone()).await?;

              if expected_height.is_some() {
                // conditional write cannot be retried
                return Err(LedgerStoreError::LedgerError(
                  StorageError::IncorrectConditionalData,
                ));
              }
            },
            _ => {
              return Err(e);
            },
          }
        },
      }
    }
  }

  async fn attach_ledger_receipt(
    &self,
    handle: &Handle,
    receipt: &Receipt,
  ) -> Result<(), LedgerStoreError> {
    let ledger = self.client.clone();
    let handle_string = base64_url::encode(&handle.to_bytes());

    loop {
      let res = attach_ledger_receipt_op(&handle_string, receipt, ledger.clone()).await;

      match res {
        Ok(v) => {
          return Ok(v);
        },
        Err(e) => {
          match e {
            LedgerStoreError::LedgerError(StorageError::ConcurrentOperation) => {
              // fix cache and retry since there was some concurrent op that prevented
              // this attach ledger
              fix_cached_entry(&handle_string, &self.cache, ledger.clone()).await?;
            },
            _ => {
              return Err(e);
            },
          }
        },
      }
    }
  }

  async fn read_ledger_tail(&self, handle: &Handle) -> Result<(Block, usize), LedgerStoreError> {
    let ledger = self.client.clone();
    let handle_string = base64_url::encode(&handle.to_bytes());
    let (ledger_entry, height) = read_ledger_op(&handle_string, None, ledger, &self.cache).await?;
    Ok((ledger_entry.block, height))
  }

  async fn read_ledger_by_index(
    &self,
    handle: &Handle,
    index: usize,
  ) -> Result<LedgerEntry, LedgerStoreError> {
    let ledger = self.client.clone();
    let handle_string = base64_url::encode(&handle.to_bytes());
    let (ledger_entry, _height) =
      read_ledger_op(&handle_string, Some(index), ledger, &self.cache).await?;
    Ok(ledger_entry)
  }

  async fn read_view_ledger_tail(&self) -> Result<(Block, usize), LedgerStoreError> {
    self.read_ledger_tail(&self.view_handle).await
  }

  async fn read_view_ledger_by_index(&self, idx: usize) -> Result<LedgerEntry, LedgerStoreError> {
    self.read_ledger_by_index(&self.view_handle, idx).await
  }

  async fn attach_view_ledger_receipt(&self, receipt: &Receipt) -> Result<(), LedgerStoreError> {
    self.attach_ledger_receipt(&self.view_handle, receipt).await
  }

  async fn append_view_ledger(
    &self,
    block: &Block,
    expected_height: Option<usize>,
  ) -> Result<usize, LedgerStoreError> {
    self
      .append_ledger(&self.view_handle, block, expected_height)
      .await
  }

  async fn reset_store(&self) -> Result<(), LedgerStoreError> {
    let ledger = self.client.clone();
    ledger
      .delete()
      .execute()
      .await
      .expect("failed to delete ledgers");

    Ok(())
  }
}
