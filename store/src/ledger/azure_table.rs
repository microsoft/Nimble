use crate::{
  errors::{LedgerStoreError, StorageError},
  ledger::{LedgerEntry, LedgerStore},
};
use async_trait::async_trait;
use azure_data_tables::{clients::TableClient, prelude::*};

use azure_core::Etag;
use azure_storage::core::prelude::*;
use base64_url;
use ledger::{Block, CustomSerde, Handle, NimbleDigest, Nonce, Nonces, Receipt};
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

enum AzureOp {
  Append,
  Create,
}

/*
  StatusCode::BAD_REQUEST, // Code 400, thrown when request is invalid (bad size, bad name)
  StatusCode::NOT_FOUND,   // Code 404, blob not found
  StatusCode::CONFLICT,    // Code 409, entity already exists
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

fn parse_error_status(code: StatusCode) -> LedgerStoreError {
  match code {
    StatusCode::BAD_REQUEST => LedgerStoreError::LedgerError(StorageError::InvalidIndex),
    StatusCode::RANGE_NOT_SATISFIABLE => LedgerStoreError::LedgerError(StorageError::InvalidIndex),
    StatusCode::NOT_FOUND => LedgerStoreError::LedgerError(StorageError::KeyDoesNotExist),
    StatusCode::PRECONDITION_FAILED => {
      LedgerStoreError::LedgerError(StorageError::ConcurrentOperation)
    },
    StatusCode::CONFLICT => LedgerStoreError::LedgerError(StorageError::DuplicateKey),
    _ => LedgerStoreError::LedgerError(StorageError::UnhandledError),
  }
}

fn string_decode(s: &str) -> Result<Vec<u8>, LedgerStoreError> {
  match base64_url::decode(s) {
    Ok(v) => Ok(v),
    Err(e) => {
      eprintln!("Unable to decode string: {:?}", e);
      Err(LedgerStoreError::LedgerError(
        StorageError::DeserializationError,
      ))
    },
  }
}

#[derive(Clone, Debug)]
struct CacheEntry {
  height: i64,
  etag: Etag,
  nonce_list: Nonces,
}

impl CacheEntry {
  pub fn get_nonces(&self) -> Nonces {
    self.nonce_list.clone()
  }
}

type CacheLockEntry = Arc<RwLock<CacheEntry>>;
type CacheMap = Arc<RwLock<HashMap<String, CacheLockEntry>>>;

#[derive(Clone, Serialize, Deserialize, Debug)]
struct DBEntry {
  #[serde(rename = "PartitionKey")]
  pub handle: String,
  #[serde(rename = "RowKey")]
  pub row: String,
  pub height: i64,
  pub block: String,
  pub receipt: String,
  pub nonces: String,
}

// This is a projection so you only modify the receipt, not the rest
#[derive(Clone, Serialize, Deserialize, Debug)]
struct DBEntryReceiptProjection {
  #[serde(rename = "PartitionKey")]
  pub handle: String,
  #[serde(rename = "RowKey")]
  pub row: String,
  pub receipt: String,
}

// This is a projection so you only modify the nonces, not the rest
#[derive(Clone, Serialize, Deserialize, Debug)]
struct DBEntryNonceProjection {
  #[serde(rename = "PartitionKey")]
  pub handle: String,
  #[serde(rename = "RowKey")]
  pub row: String,
  pub nonces: String,
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
      eprintln!("Error trying to create table in the first place. {:?}", err);
      let status = get_error_status!(err);

      match status {
        StatusCode::CONFLICT => (), // table already exists which is fine
        _ => {
          return Err(parse_error_status(status));
        },
      }
    }

    let view_handle_string = base64_url::encode(&view_handle.to_bytes());

    // Check if the view ledger exists, if not, create a new one
    let res = find_db_entry(ledger_store.client.clone(), &view_handle_string, TAIL).await;
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
              nonces: base64_url::encode(&Nonces::new().to_bytes()),
            };

            azure_op(
              ledger_store.client.clone(),
              &view_handle_string,
              entry.clone(),
              entry,
              &ledger_store.cache,
              AzureOp::Create,
              None,
            )
            .await?;
          },
          _ => {
            eprintln!("Error is {:?}", error);
            return Err(LedgerStoreError::LedgerError(StorageError::UnhandledError));
          },
        };
      },
      Ok((db_entry, etag)) => {
        let nonces = decode_nonces_string(&db_entry.nonces)?;

        // Since view ledger exists, update the cache with the latest information
        update_cache_entry(
          &view_handle_string,
          &ledger_store.cache,
          db_entry.height,
          etag,
          nonces,
        )?;
      },
    };

    Ok(ledger_store)
  }
}

fn decode_nonces_string(nonces: &str) -> Result<Nonces, LedgerStoreError> {
  match Nonces::from_bytes(&string_decode(nonces)?) {
    Ok(b) => Ok(b),
    Err(e) => {
      eprintln!("Unable to decode nonces {:?}", e);
      Err(LedgerStoreError::LedgerError(
        StorageError::DeserializationError,
      ))
    },
  }
}

async fn azure_op(
  table_client: Arc<TableClient>,
  handle: &str,
  mut tail_entry: DBEntry,
  indexed_entry: DBEntry,
  cache: &CacheMap,
  op: AzureOp,
  etag: Option<Etag>,
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

  // construct transaction
  let mut transaction = Transaction::default();

  match op {
    AzureOp::Create => {
      // We are creating the ledger so we need to insert the TAIL entry instead of updating it
      let tail_create = match table_client.insert().to_transaction_operation(&tail_entry) {
        Ok(v) => v,
        Err(e) => {
          eprintln!("Cannot create transaction operation due to error: {:?}", e);
          return Err(LedgerStoreError::LedgerError(StorageError::UnhandledError));
        },
      };

      transaction.add(tail_create);
    },
    AzureOp::Append => {
      assert!(etag.is_some()); // by definition if operaiton is Append and etag must be provided.

      // This updates the tail and uses etag to detect concurrent accesses
      let tail_update = match tail_client
        .update()
        .to_transaction_operation(&tail_entry, &IfMatchCondition::Etag(etag.unwrap()))
      {
        Ok(v) => v,
        Err(e) => {
          eprintln!("Cannot create transaction operation due to error: {:?}", e);
          return Err(LedgerStoreError::LedgerError(StorageError::UnhandledError));
        },
      };

      transaction.add(tail_update);
    },
  }

  // This inserts a row at the desired index and detects concurrent operations
  // by failing with CONFLICT
  let row_insert = match table_client
    .insert()
    .to_transaction_operation(&indexed_entry)
  {
    Ok(v) => v,
    Err(e) => {
      eprintln!("Cannot create transaction operation due to error: {:?}", e);
      return Err(LedgerStoreError::LedgerError(StorageError::UnhandledError));
    },
  };

  transaction.add(row_insert);

  let res = partition_client
    .submit_transaction()
    .execute(&transaction)
    .await;

  // We need to perform 2 checks. The first check basically asks whether Azure was OK with the
  // way we constructed the transaction (a sort of well-formenedness check). If not, Azure will return
  // an error from the transaction itself.
  // To see whether the transaction actually completed correctly, we have to inspect each operation
  // and see if the operation completed. If all operations completed, then the transaction
  // completed. Otherwise the transaction failed (and none of the operations were performed).

  if let Err(err) = res {
    eprintln!("Error inserting row in azure table: {:?}", err);
    return Err(parse_error_status(get_error_status!(err)));
  }

  let res = res.unwrap();

  let mut etags = Vec::new();

  // For each of the operation in the transaction, check they completed and get their etags
  for r in res.operation_responses {
    if r.status_code.is_client_error() || r.status_code.is_server_error() {
      return Err(parse_error_status(r.status_code));
    }

    if let Some(e) = r.etag {
      etags.push(e.clone());
    }
  }

  // etags[0] is the etag for the first operation in transaction, which corresponds to the tail
  update_cache_entry(
    handle,
    cache,
    tail_entry.height,
    etags[0].clone(),
    Nonces::new(),
  )?;

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
    return Err(parse_error_status(get_error_status!(err)));
  }

  let res = res.unwrap();
  Ok((res.entity, res.etag))
}

async fn append_ledger_internal(
  handle: &str,
  block: &Block,
  expected_height: usize,
  ledger: Arc<TableClient>,
  cache: &CacheMap,
) -> Result<(usize, Nonces), LedgerStoreError> {
  // Get current height and then increment it
  let mut cache_entry = get_cached_entry(handle, cache, ledger.clone()).await?;
  let height_plus_one = checked_increment!(cache_entry.height);

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
      // Get latest value of the tail and double check
      cache_entry = fix_cached_entry(handle, cache, ledger.clone()).await?;

      let height_plus_one = checked_increment!(cache_entry.height);

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
  let tail_entry = DBEntry {
    handle: handle.to_owned(),
    row: height_plus_one.to_string(),
    height: height_plus_one,
    block: base64_url::encode(&block.to_bytes()),
    receipt: base64_url::encode(&Receipt::default().to_bytes()),
    nonces: base64_url::encode(&Nonces::new().to_bytes()), // clear out the nonces in tail
  };

  let indexed_entry = DBEntry {
    handle: handle.to_owned(),
    row: height_plus_one.to_string(),
    height: height_plus_one,
    block: base64_url::encode(&block.to_bytes()),
    receipt: base64_url::encode(&Receipt::default().to_bytes()),
    nonces: base64_url::encode(&cache_entry.get_nonces().to_bytes()),
  };

  // 4. Try to insert the new entry into the ledger and set the tail

  let cached_entry = get_cached_entry(handle, cache, ledger.clone()).await?;

  azure_op(
    ledger,
    handle,
    tail_entry,
    indexed_entry,
    cache,
    AzureOp::Append,
    Some(cached_entry.etag),
  )
  .await?;

  let res = checked_conversion!(height_plus_one, usize);
  Ok((res, cache_entry.get_nonces()))
}

async fn attach_ledger_nonce_internal(
  handle: &str,
  nonce: &Nonce,
  ledger: Arc<TableClient>,
  cache: &CacheMap,
) -> Result<usize, LedgerStoreError> {
  // 1. Fetch the nonce list at the tail
  let entry = get_cached_entry(handle, cache, ledger.clone()).await?;

  let mut nonce_list = entry.nonce_list;
  nonce_list.add(*nonce);

  // 2. Update the tail row with the updated nonce list
  let merge_entry = DBEntryNonceProjection {
    handle: handle.to_owned(),
    row: TAIL.to_owned(),
    nonces: base64_url::encode(&nonce_list.to_bytes()),
  };

  let partition_client = ledger.as_partition_key_client(handle);
  let row_client = match partition_client.as_entity_client(TAIL) {
    Ok(v) => v,
    Err(e) => {
      eprintln!("Unable to get row client in attach ledger receipt: {:?}", e);
      return Err(LedgerStoreError::LedgerError(StorageError::UnhandledError));
    },
  };

  let res = row_client
    .merge()
    .execute(&merge_entry, &IfMatchCondition::Etag(entry.etag))
    .await;

  if let Err(err) = res {
    return Err(parse_error_status(get_error_status!(err)));
  }

  let res = res.unwrap();

  update_cache_entry(handle, cache, entry.height, res.etag, nonce_list)?;

  let height = checked_conversion!(entry.height, usize);
  Ok(checked_increment!(height))
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

  // 2. Append the receipt to the fetched receipt
  let mut fetched_receipt = match Receipt::from_bytes(&string_decode(&entry.receipt)?) {
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
  let merge_entry = DBEntryReceiptProjection {
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
    return Err(parse_error_status(get_error_status!(err)));
  }

  Ok(())
}

async fn read_ledger_internal(
  handle: &str,
  req_idx: Option<usize>,
  ledger: Arc<TableClient>,
) -> Result<(LedgerEntry, usize), LedgerStoreError> {
  let index = if req_idx.is_some() {
    checked_conversion!(req_idx.unwrap(), i64).to_string()
  } else {
    TAIL.to_owned() // No index was requested, get the TAIL
  };

  let (entry, _etag) = find_db_entry(ledger, handle, &index).await?;

  let ret_block = match Block::from_bytes(&string_decode(&entry.block)?) {
    Ok(b) => b,
    Err(e) => {
      eprintln!(
        "Unable to decode block bytes in read_ledger_internal {:?}",
        e
      );
      return Err(LedgerStoreError::LedgerError(
        StorageError::DeserializationError,
      ));
    },
  };

  let ret_receipt = match Receipt::from_bytes(&string_decode(&entry.receipt)?) {
    Ok(r) => r,
    Err(e) => {
      eprintln!("Unable to decode receipt bytes in read_ledger_op {:?}", e);
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
) -> Result<CacheEntry, LedgerStoreError> {
  if let Ok(read_map) = cache.read() {
    if let Some(cache_entry) = read_map.get(handle) {
      if let Ok(entry) = cache_entry.read() {
        return Ok(entry.to_owned());
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
  fix_cached_entry(handle, cache, ledger).await
}

// This is called when the cache is incorrect (e.g., concurrent appends)
async fn fix_cached_entry(
  handle: &str,
  cache: &CacheMap,
  ledger: Arc<TableClient>,
) -> Result<CacheEntry, LedgerStoreError> {
  // Find the tail, then figure out its height and nonces
  let (entry, etag) = find_db_entry(ledger, handle, TAIL).await?;

  let nonces = decode_nonces_string(&entry.nonces)?;

  update_cache_entry(handle, cache, entry.height, etag.clone(), nonces.clone())?;

  let res = CacheEntry {
    height: entry.height,
    etag,
    nonce_list: nonces,
  };

  Ok(res)
}

fn update_cache_entry(
  handle: &str,
  cache: &CacheMap,
  new_height: i64,
  new_etag: Etag,
  new_nonces: Nonces,
) -> Result<(), LedgerStoreError> {
  if let Ok(cache_map) = cache.read() {
    if let Some(cache_entry) = cache_map.get(handle) {
      if let Ok(mut entry) = cache_entry.write() {
        *entry = CacheEntry {
          height: new_height,
          etag: new_etag,
          nonce_list: new_nonces,
        };
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
    let new_entry = CacheEntry {
      height: new_height,
      etag: new_etag,
      nonce_list: new_nonces,
    };

    write_map.insert(handle.to_owned(), Arc::new(RwLock::new(new_entry)));
  } else {
    return Err(LedgerStoreError::LedgerError(
      StorageError::LedgerWriteLockFailed,
    ));
  }

  Ok(())
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
    let nonces = base64_url::encode(&Nonces::new().to_bytes());

    let entry = DBEntry {
      handle: handle_string.clone(),
      row: 0.to_string(),
      height: 0,
      block: base64_url::encode(&genesis_block.to_bytes()),
      receipt: base64_url::encode(&Receipt::default().to_bytes()),
      nonces,
    };

    azure_op(
      ledger,
      &handle_string,
      entry.clone(),
      entry,
      &self.cache,
      AzureOp::Create,
      None,
    )
    .await
  }

  async fn append_ledger(
    &self,
    handle: &Handle,
    block: &Block,
    expected_height: usize,
  ) -> Result<(usize, Nonces), LedgerStoreError> {
    let ledger = self.client.clone();
    let handle_string = base64_url::encode(&handle.to_bytes());

    loop {
      let res = append_ledger_internal(
        &handle_string,
        block,
        expected_height,
        ledger.clone(),
        &self.cache,
      )
      .await;

      match res {
        Ok(v) => return Ok(v),
        Err(e) => match e {
          LedgerStoreError::LedgerError(StorageError::ConcurrentOperation) => {
            fix_cached_entry(&handle_string, &self.cache, ledger.clone()).await?;
          },
          LedgerStoreError::LedgerError(StorageError::IncorrectConditionalData) => {
            return Err(LedgerStoreError::LedgerError(
              StorageError::IncorrectConditionalData,
            ))
          },
          _ => return Err(e),
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
    let index = receipt.get_height().to_string();

    attach_ledger_receipt_internal(ledger, &handle_string, &self.cache, receipt, &index).await
  }

  async fn attach_ledger_nonce(
    &self,
    handle: &Handle,
    nonce: &Nonce,
  ) -> Result<usize, LedgerStoreError> {
    let ledger = self.client.clone();
    let handle_string = base64_url::encode(&handle.to_bytes());

    loop {
      let res =
        attach_ledger_nonce_internal(&handle_string, nonce, ledger.clone(), &self.cache).await;

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

  async fn read_ledger_tail(
    &self,
    handle: &Handle,
  ) -> Result<(LedgerEntry, usize), LedgerStoreError> {
    let ledger = self.client.clone();
    let handle_string = base64_url::encode(&handle.to_bytes());
    read_ledger_internal(&handle_string, None, ledger).await
  }

  async fn read_ledger_by_index(
    &self,
    handle: &Handle,
    index: usize,
  ) -> Result<LedgerEntry, LedgerStoreError> {
    let ledger = self.client.clone();
    let handle_string = base64_url::encode(&handle.to_bytes());
    let (ledger_entry, _height) = read_ledger_internal(&handle_string, Some(index), ledger).await?;
    Ok(ledger_entry)
  }

  async fn read_view_ledger_tail(&self) -> Result<(LedgerEntry, usize), LedgerStoreError> {
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
    expected_height: usize,
  ) -> Result<usize, LedgerStoreError> {
    let (height, _nonces) = self
      .append_ledger(&self.view_handle, block, expected_height)
      .await?;
    Ok(height)
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
