use crate::{
  errors::{LedgerStoreError, StorageError},
  ledger::{LedgerEntry, LedgerStore},
};
use async_trait::async_trait;
use azure_data_tables::{clients::TableClient, prelude::*};

use azure_core::Etag;
use azure_storage::core::prelude::*;
use base64_url;
use ledger::{Block, CustomSerde, Handle, NimbleDigest, Nonce, Receipt};
use serde::{Deserialize, Serialize};
use std::{
  cmp::Ordering,
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
            // Initialize view ledger's entry
            let entry = DBEntry {
              handle: view_handle_string.clone(),
              row: 0.to_string(),
              height: 0,
              block: base64_url::encode(&Block::new(&[0; 0]).to_bytes()),
              receipt: base64_url::encode(&Receipt::default().to_bytes()),
            };

            insert_row(
              ledger_store.client.clone(),
              &view_handle_string,
              entry,
              None, // No need to add an entry at the given index
            )
            .await?;
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
  mut tail_entry: DBEntry,
  indexed_entry: Option<DBEntry>,
) -> Result<(), LedgerStoreError> {
  let partition_client = table_client.as_partition_key_client(handle);
  let tail_client = match partition_client.as_entity_client(TAIL) {
    Ok(v) => v,
    Err(e) => {
      eprintln!("Error in insert row: {:?}", e);
      return Err(LedgerStoreError::LedgerError(StorageError::UnhandledError));
    },
  };

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

  // construct transaction
  let mut transaction = Transaction::default();
  transaction.add(tail_update);

  // If the caller specifies a row to add at a particular index, add that to
  // the ongoing transaction
  if let Some(entry) = indexed_entry {
    let row_insert = match table_client.insert().to_transaction_operation(&entry) {
      Ok(v) => v,
      Err(e) => {
        eprintln!("Cannot create transaction operation due to error: {:?}", e);
        return Err(LedgerStoreError::LedgerError(StorageError::UnhandledError));
      },
    };

    transaction.add(row_insert);
  }

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

async fn attach_ledger_receipt_internal(
  ledger: Arc<TableClient>,
  handle_string: &str,
  cache: &CacheMap,
  receipt: &Receipt,
  index: &str,
) -> Result<(), LedgerStoreError> {
  loop {
    let res = attach_ledger_receipt_op(handle_string, receipt, ledger.clone(), index).await;

    match res {
      Ok(v) => {
        return Ok(v);
      },
      Err(e) => {
        match e {
          LedgerStoreError::LedgerError(StorageError::ConcurrentOperation) => {
            // fix cache and retry since there was some concurrent op that prevented
            // this attach ledger
            fix_cached_entry(handle_string, cache, ledger.clone()).await?;
          },
          _ => {
            return Err(e);
          },
        }
      },
    }
  }
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
  expected_height: usize,
  ledger: Arc<TableClient>,
  cache: &CacheMap,
) -> Result<usize, LedgerStoreError> {
  // Get current height and then increments it
  let height = get_cached_entry(handle, cache, ledger.clone()).await?;
  let height_plus_one = checked_increment!(height);

  // 2. Check if condition holds
  let expected_height_c = checked_conversion!(expected_height, i64);

  match expected_height_c.cmp(&height_plus_one) {
    Ordering::Less => {
      // Condition no longer holds. Cache may be stale but it doesn't matter

      eprintln!(
        "Expected height {};  Height-plus-one: {}",
        expected_height_c, height_plus_one
      );

      return Err(LedgerStoreError::LedgerError(
        StorageError::IncorrectConditionalData,
      ));
    },
    Ordering::Greater => {
      // Either condition does not hold or cache is stale for some reason
      // Get latest height and double check
      let height = find_ledger_height(ledger.clone(), handle).await?;
      let height_plus_one = checked_increment!(height);

      // Update the cache
      update_cache_entry(handle, cache, height)?;

      // Condition no longer holds
      if expected_height_c != height_plus_one {
        eprintln!(
          "Expected height {};  Height-plus-one: {}",
          expected_height_c, height_plus_one
        );

        return Err(LedgerStoreError::LedgerError(
          StorageError::IncorrectConditionalData,
        ));
      }
    },
    Ordering::Equal => {}, // all is good
  };

  // 3. Construct the new entry we are going to append to the ledger
  let new_entry = DBEntry {
    handle: handle.to_owned(),
    row: height_plus_one.to_string(),
    height: height_plus_one,
    block: base64_url::encode(&block.to_bytes()),
    receipt: base64_url::encode(&Receipt::default().to_bytes()),
  };

  // 4. Try to insert the new entry into the ledger (also set as tail)
  insert_row(ledger, handle, new_entry.clone(), Some(new_entry)).await?;

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
  index: &str,
) -> Result<(), LedgerStoreError> {
  // 1. Fetch the receipt at this index
  let (entry, etag) = find_db_entry(ledger.clone(), handle, index).await?;

  // Compare the height of the provided receipt with the height of the fetched
  // entry. They should be the same.
  // We need this check because default receipts have no height themselves,
  // so we must rely on the entry's height and not just the receipt's height..
  let height = checked_conversion!(entry.height, usize);
  if receipt.get_height() != height {
    return Err(LedgerStoreError::LedgerError(StorageError::InvalidIndex));
  }

  let receipt_bytes = match base64_url::decode(&entry.receipt) {
    Ok(v) => v,
    Err(e) => {
      eprintln!("Unable to decode entry in attach_ledger_receipt {:?}", e);
      return Err(LedgerStoreError::LedgerError(
        StorageError::DeserializationError,
      ));
    },
  };

  // 2. Append the receipt to the fetched receipt
  let mut fetched_receipt = match Receipt::from_bytes(&receipt_bytes) {
    Ok(r) => r,
    Err(e) => {
      eprintln!("Unable to decode receipt bytes in attach_ledger_op {:?}", e);
      return Err(LedgerStoreError::LedgerError(
        StorageError::DeserializationError,
      ));
    },
  };

  let res = fetched_receipt.append(receipt);
  if res.is_err() {
    return Err(LedgerStoreError::LedgerError(
      StorageError::MismatchedReceipts,
    ));
  }

  // 3. Update the row with the updated receipt
  let merge_entry = MergeDBEntry {
    handle: handle.to_owned(),
    row: index.to_owned(),
    receipt: base64_url::encode(&fetched_receipt.to_bytes()),
  };

  let partition_client = ledger.as_partition_key_client(handle);
  let row_client = match partition_client.as_entity_client(index) {
    Ok(v) => v,
    Err(e) => {
      eprintln!("Unable to get row client in attach ledger receipt: {:?}", e);
      return Err(LedgerStoreError::LedgerError(StorageError::UnhandledError));
    },
  };

  let res = row_client
    .merge()
    .execute(&merge_entry, &IfMatchCondition::Etag(etag))
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

  let ret_block = match base64_url::decode(&entry.block) {
    Ok(v) => match Block::from_bytes(&v) {
      Ok(b) => b,
      Err(e) => {
        eprintln!("Unable to decode block bytes in read_ledger_op {:?}", e);
        return Err(LedgerStoreError::LedgerError(
          StorageError::DeserializationError,
        ));
      },
    },
    Err(e) => {
      eprintln!("Unable to decode entry.block in read_ledger_op {:?}", e);
      return Err(LedgerStoreError::LedgerError(
        StorageError::DeserializationError,
      ));
    },
  };

  let ret_receipt = match base64_url::decode(&entry.receipt) {
    Ok(v) => match Receipt::from_bytes(&v) {
      Ok(r) => r,
      Err(e) => {
        eprintln!("Unable to decode receipt bytes in read_ledger_op {:?}", e);
        return Err(LedgerStoreError::LedgerError(
          StorageError::DeserializationError,
        ));
      },
    },
    Err(e) => {
      eprintln!("Unable to decode entry.receipt in read_ledger_op, {:?}", e);
      return Err(LedgerStoreError::LedgerError(
        StorageError::DeserializationError,
      ));
    },
  };

  Ok((
    LedgerEntry::new(ret_block, ret_receipt, None),
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

    insert_row(ledger, &handle_string, entry.clone(), Some(entry)).await?;
    update_cache_entry(&handle_string, &self.cache, 0)?;

    Ok(())
  }

  async fn append_ledger(
    &self,
    handle: &Handle,
    block: &Block,
    expected_height: usize,
  ) -> Result<(usize, Vec<Nonce>), LedgerStoreError> {
    let ledger = self.client.clone();
    let handle_string = base64_url::encode(&handle.to_bytes());

    let res = append_ledger_op(
      &handle_string,
      block,
      expected_height,
      ledger.clone(),
      &self.cache,
    )
    .await;

    match res {
      Ok(v) => Ok((v, Vec::new())),
      Err(e) => {
        match e {
          LedgerStoreError::LedgerError(StorageError::ConcurrentOperation) => {
            fix_cached_entry(&handle_string, &self.cache, ledger.clone()).await?;
            // conditional write cannot be retried
            Err(LedgerStoreError::LedgerError(
              StorageError::IncorrectConditionalData,
            ))
          },
          _ => Err(e),
        }
      },
    }
  }

  async fn attach_ledger_receipt(
    &self,
    handle: &Handle,
    receipt: &Receipt,
  ) -> Result<(), LedgerStoreError> {
    let ledger = self.client.clone();
    let handle_string = base64_url::encode(&handle.to_bytes());
    let index = receipt.get_height().to_string();

    attach_ledger_receipt_internal(ledger, &handle_string, &self.cache, receipt, &index).await
  }

  #[allow(unused_variables)]
  async fn attach_ledger_nonce(
    &self,
    handle: &Handle,
    nonces: &Nonce,
  ) -> Result<usize, LedgerStoreError> {
    unimplemented!()
  }

  async fn read_ledger_tail(
    &self,
    handle: &Handle,
  ) -> Result<(LedgerEntry, usize), LedgerStoreError> {
    let ledger = self.client.clone();
    let handle_string = base64_url::encode(&handle.to_bytes());
    read_ledger_op(&handle_string, None, ledger, &self.cache).await
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

  async fn read_view_ledger_tail(&self) -> Result<(LedgerEntry, usize), LedgerStoreError> {
    self.read_ledger_tail(&self.view_handle).await
  }

  async fn read_view_ledger_by_index(&self, idx: usize) -> Result<LedgerEntry, LedgerStoreError> {
    let res = self.read_ledger_by_index(&self.view_handle, idx).await;

    if let Ok(v) = res {
      Ok(v)
    } else {
      // Check the TAIL row as well just in case it is there. Recall that unlike regular
      // ledgers, in the view ledger the TAIL contains the latest entry and it has not yet
      // been inserted to a dedicated row. This is safe due to syncrhonous appends in view change.
      let (entry, height) = self.read_view_ledger_tail().await?;
      if height == idx {
        Ok(entry)
      } else {
        Err(LedgerStoreError::LedgerError(StorageError::InvalidIndex))
      }
    }
  }

  async fn attach_view_ledger_receipt(&self, receipt: &Receipt) -> Result<(), LedgerStoreError> {
    let ledger = self.client.clone();
    let handle_string = base64_url::encode(&self.view_handle.to_bytes());
    attach_ledger_receipt_internal(ledger, &handle_string, &self.cache, receipt, TAIL).await
  }

  async fn append_view_ledger(
    &self,
    block: &Block,
    expected_height: usize,
  ) -> Result<usize, LedgerStoreError> {
    // 1. Get current entry at TAIL row
    let (current_tail_entry, height) = self.read_view_ledger_tail().await?;
    let height_plus_one = checked_increment!(height);

    // 2. Ensure condition holds
    if expected_height != height_plus_one {
      return Err(LedgerStoreError::LedgerError(
        StorageError::IncorrectConditionalData,
      ));
    }

    let height_c = checked_conversion!(height, i64);
    let expected_height_c = checked_conversion!(expected_height, i64);

    let ledger = self.client.clone();
    let handle_string = base64_url::encode(&self.view_handle.to_bytes());

    // 3. Construct the entry we are going to bump from the TAIL row to an entry in the
    // ledger at position height
    let bump_entry = DBEntry {
      handle: handle_string.to_owned(),
      row: height_c.to_string(),
      height: height_c,
      block: base64_url::encode(&current_tail_entry.get_block().to_bytes()),
      receipt: base64_url::encode(&current_tail_entry.get_receipt().to_bytes()),
    };

    // 4. Construct the entry that should go in the tail
    let tail_entry = DBEntry {
      handle: handle_string.to_owned(),
      row: expected_height_c.to_string(),
      height: expected_height_c,
      block: base64_url::encode(&block.to_bytes()),
      receipt: base64_url::encode(&Receipt::default().to_bytes()),
    };

    // 4. Try to insert the bumped entry into the ledger.
    insert_row(ledger, &handle_string, tail_entry, Some(bump_entry)).await?;

    // Update the cached height and etag for this ledger
    update_cache_entry(&handle_string, &self.cache, expected_height_c)?;

    Ok(expected_height)
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
