use crate::{
  errors::{LedgerStoreError, StorageError},
  ledger::{LedgerEntry, LedgerStore},
};
use async_trait::async_trait;
use azure_core::prelude::*;
use azure_storage::core::prelude::*;
use azure_storage_blobs::{blob::responses::UpdatePageResponse, prelude::*, BA512Range};
use bincode;
use hex;
use ledger::{Block, CustomSerde, Handle, NimbleDigest, Receipt};
use md5;
use serde::{Deserialize, Serialize};
use std::{
  collections::HashMap,
  convert::TryFrom,
  fmt::Debug,
  sync::{Arc, RwLock},
  time::Duration,
};

use http::{self, StatusCode};

/*
  StatusCode::BAD_REQUEST, // Code 400, thrown when request is invalid (bad size, bad name)
  StatusCode::NOT_FOUND,   // Code 404, blob not found
  StatusCode::CONFLICT,    // Code 409, container already exists
  StatusCode::PRECONDITION_FAILED, // Code 412, thrown when etag does not match
  StatusCode::RANGE_NOT_SATISFIABLE, // Code 416, thrown when the range is out of bounds
*/

const CREATE_TIMEOUT: u64 = 10; // secs
const LOGICAL_PAGE_SIZE: usize = 512 * 2; // pages are fixed at 512 bytes; this is for a "logical pages"
const PAGE_BLOB_SIZE: u128 = 1024 * 1000000; // total bytes in a page blob (across all pages)

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

type CacheEntry = Arc<RwLock<(u64, String)>>; // offset and latest etag
type CacheMap = Arc<RwLock<HashMap<Handle, CacheEntry>>>;

#[derive(Clone, Serialize, Deserialize, Debug)]
struct DBEntry {
  pub block: Vec<u8>,
  pub receipt: Vec<u8>,
}

#[derive(Debug)]
pub struct PageBlobLedgerStore {
  client: Arc<ContainerClient>,
  view_handle: Handle,
  cache: CacheMap,
}

impl PageBlobLedgerStore {
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
    let mut nimble_db_name = String::from("nimble-pageblob");
    if args.contains_key("NIMBLE_DB") {
      nimble_db_name = args["NIMBLE_DB"].clone();
    }

    let http_client = azure_core::new_http_client();
    let storage_client =
      StorageAccountClient::new_access_key(http_client.clone(), &account, &master_key);
    let container_client = storage_client.as_container_client(&nimble_db_name);

    let view_handle = match NimbleDigest::from_bytes(&vec![0u8; NimbleDigest::num_bytes()]) {
      Ok(e) => e,
      Err(_) => {
        return Err(LedgerStoreError::LedgerError(
          StorageError::DeserializationError,
        ));
      },
    };

    let cache = Arc::new(RwLock::new(HashMap::new()));

    let ledger_store = PageBlobLedgerStore {
      client: container_client,
      view_handle,
      cache,
    };

    // Try to create container. If it exists that's fine.
    let res = ledger_store
      .client
      .create()
      .public_access(PublicAccess::None)
      .timeout(Duration::from_secs(CREATE_TIMEOUT))
      .execute()
      .await;

    if let Err(err) = res {
      match get_error_status!(err) {
        StatusCode::CONFLICT => (), // container already exists which is fine
        StatusCode::BAD_REQUEST => {
          return Err(LedgerStoreError::LedgerError(StorageError::InvalidDBName));
        },
        _ => {
          eprintln!("Error is {:?}", err);
          return Err(LedgerStoreError::LedgerError(StorageError::UnhandledError));
        },
      }
    }

    // Check if the view ledger exists, if not, create a new one
    if let Err(error) = ledger_store.read_view_ledger_tail().await {
      match error {
        // Blob does not exist ERROR
        LedgerStoreError::LedgerError(StorageError::KeyDoesNotExist) => {
          // Create new page blob
          let blob_client = ledger_store
            .client
            .as_blob_client(&hex::encode(&view_handle.to_bytes()));

          let res = blob_client
              .put_page_blob(PAGE_BLOB_SIZE) // total size of the blob
              .content_type("binary") // this is just an arbitrary string
              .execute()
              .await;

          if let Err(err) = res {
            match get_error_status!(err) {
              StatusCode::BAD_REQUEST => {
                panic!("PAGE_BLOB_SIZE is wrong")
              }, // this should never happen
              _ => {
                eprintln!("Error is {:?}", err);
                return Err(LedgerStoreError::LedgerError(StorageError::UnhandledError));
              },
            }
          }

          let res = res.unwrap();
          let etag = res.etag;
          let range = index_to_page_range(0)?;

          // Initialized view ledger's entry
          let entry = DBEntry {
            block: Block::new(&[0; 0]).to_bytes(),
            receipt: Receipt::default().to_bytes(),
          };

          // Guaranteed to be the size of 1 logical page
          let ser_entry = serialize_entry(&entry)?;

          let res = update_page(&blob_client, range, ser_entry, etag).await?;

          update_cache_entry(&view_handle, &ledger_store.cache, Some(0), res.etag)?;
        },
        _ => {
          eprintln!("Error is {:?}", error);
          return Err(LedgerStoreError::LedgerError(StorageError::UnhandledError));
        },
      };
    } else {
      // Since view ledger exists, update the cache height with the latest height
      let blob_client = ledger_store
        .client
        .as_blob_client(&hex::encode(&view_handle.to_bytes()));
      fix_cached_entry(&ledger_store.view_handle, &ledger_store.cache, &blob_client).await?;
    }

    Ok(ledger_store)
  }
}

async fn update_page(
  ledger: &BlobClient,
  range: BA512Range,
  ser_entry: Vec<u8>,
  etag: String,
) -> Result<UpdatePageResponse, LedgerStoreError> {
  let digest = md5::compute(ser_entry.clone()); // this is required by blob store

  let res = ledger
    .update_page(range, ser_entry)
    .if_match_condition(IfMatchCondition::Match(etag))
    .hash(&digest.into())
    .execute()
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

  Ok(res.unwrap())
}

fn index_to_page_range(index: u64) -> Result<BA512Range, LedgerStoreError> {
  match BA512Range::new(
    index * LOGICAL_PAGE_SIZE as u64,
    (index + 1) * LOGICAL_PAGE_SIZE as u64 - 1,
  ) {
    Ok(res) => Ok(res),
    Err(_) => Err(LedgerStoreError::LedgerError(StorageError::InvalidIndex)),
  }
}

fn serialize_entry(entry: &DBEntry) -> Result<Vec<u8>, LedgerStoreError> {
  match bincode::serialize(&entry) {
    Ok(mut e) => {
      if e.len() < LOGICAL_PAGE_SIZE {
        e.resize(LOGICAL_PAGE_SIZE, 0);
        Ok(e)
      } else {
        Err(LedgerStoreError::LedgerError(StorageError::DataTooLarge))
      }
    },

    Err(_) => Err(LedgerStoreError::LedgerError(
      StorageError::SerializationError,
    )),
  }
}

async fn find_db_entry(
  ledger: &BlobClient,
  index: u64,
) -> Result<(DBEntry, String), LedgerStoreError> {
  let range = index_to_page_range(index)?;

  let res = ledger.get().range(range).execute().await;

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

  let db_entry: DBEntry = match bincode::deserialize(&res.data) {
    Ok(e) => e,
    Err(_) => {
      return Err(LedgerStoreError::LedgerError(
        StorageError::DeserializationError,
      ));
    },
  };

  Ok((db_entry, res.blob.properties.etag.to_string()))
}

async fn append_ledger_op(
  handle: &Handle,
  block: &Block,
  expected_height: usize,
  ledger: &BlobClient,
  cache: &CacheMap,
) -> Result<usize, LedgerStoreError> {
  // Get current height + etag and then increment height
  let (height, etag) = get_cached_entry(handle, cache, ledger).await?;
  let height_plus_one = checked_increment!(height);

  // 2. check if condition still holds
  if expected_height as u64 != height_plus_one {
    eprintln!(
      "Expected height {};  Height-plus-one: {}",
      expected_height, height_plus_one
    );

    return Err(LedgerStoreError::LedgerError(
      StorageError::IncorrectConditionalData,
    ));
  }

  // 3. Construct the new entry we are going to append to the ledger
  let new_entry = DBEntry {
    block: block.to_bytes(),
    receipt: Receipt::default().to_bytes(),
  };

  let ser_entry = serialize_entry(&new_entry)?;
  let range = index_to_page_range(height_plus_one)?;

  // 4. Try to insert the new entry into the ledger.
  // If it fails, caller must retry.

  let res = update_page(ledger, range, ser_entry, etag).await?;

  // Update the cached height and etag for this ledger
  update_cache_entry(handle, cache, Some(height_plus_one), res.etag)?;
  Ok(height_plus_one as usize)
}

async fn attach_ledger_receipt_op(
  handle: &Handle,
  receipt: &Receipt,
  ledger: &BlobClient,
  cache: &CacheMap,
) -> Result<(), LedgerStoreError> {
  // 1. Get the desired index.
  let index = receipt.get_height() as u64;

  // 2. Find the appropriate entry in the ledger
  let (mut ledger_entry, etag) = find_db_entry(ledger, index).await?;

  // 3. Recover the contents of the ledger entry
  let mut ledger_entry_receipt =
    Receipt::from_bytes(&ledger_entry.receipt).expect("failed to deserialize receipt");

  // 4. Update receipt
  let res = ledger_entry_receipt.append(receipt);

  if res.is_err() {
    return Err(LedgerStoreError::LedgerError(
      StorageError::MismatchedReceipts,
    ));
  }
  ledger_entry.receipt = ledger_entry_receipt.to_bytes();

  // 5. Re-serialize
  let ser_entry = serialize_entry(&ledger_entry)?;

  // 6. Update page
  let range = index_to_page_range(index)?;

  let res = update_page(ledger, range, ser_entry, etag).await?;

  // Update the ledger's cache height with the latest etag
  update_cache_entry(handle, cache, None, res.etag)?;
  Ok(())
}

async fn read_ledger_op(
  handle: &Handle,
  req_idx: Option<usize>,
  ledger: &BlobClient,
  cache: &CacheMap,
) -> Result<(LedgerEntry, usize), LedgerStoreError> {
  let (cached_index, cached_etag) = get_cached_entry(handle, cache, ledger).await?;

  let mut index = if req_idx.is_some() {
    let req_idx = req_idx.unwrap() as u64;

    // Index requested is higher than cached index. Either the page does not exist or the cache is stale.
    if req_idx > cached_index {
      let (latest_index, etag) = find_ledger_height(ledger).await?;

      // Cache is stale. Update the cache
      if cached_index < latest_index {
        update_cache_entry(handle, cache, Some(latest_index), etag)?;

        // Case 1. Cache is stale AND the requested index is valid after all. Proceed.
        if req_idx <= latest_index {
          req_idx
        } else {
          // Case 2. Cache is stale but the requested index is invalid
          return Err(LedgerStoreError::LedgerError(StorageError::KeyDoesNotExist));
        }
      } else {
        // Case 3. Cache is fine and therefore the requested index is invalid
        return Err(LedgerStoreError::LedgerError(StorageError::KeyDoesNotExist));
      }
    } else {
      // Case 4. Requested index is within cached range. Let's use that instead of the one in the cache.
      req_idx
    }
  } else {
    // No index was requested, use the cache index (will be correct in common case)
    cached_index
  };

  let (mut entry, etag) = find_db_entry(ledger, index).await?;

  // 2. If we are reading the tail and the etags don't match, it means that our cache was stale
  if req_idx.is_none() && cached_etag != etag {
    // Get new height, fetch element, and update cache
    let index_and_etag = find_ledger_height(ledger).await?;
    index = index_and_etag.0;
    let entry_and_etag = find_db_entry(ledger, index).await?;
    entry = entry_and_etag.0;
    update_cache_entry(handle, cache, Some(index), entry_and_etag.1)?;
  }

  // 3. Return ledger entry by deserializing its contents
  Ok((
    LedgerEntry::new(
      Block::from_bytes(&entry.block).unwrap(),
      Receipt::from_bytes(&entry.receipt).unwrap(),
    ),
    checked_conversion!(index, usize),
  ))
}

async fn get_cached_entry(
  handle: &Handle,
  cache: &CacheMap,
  ledger: &BlobClient,
) -> Result<(u64, String), LedgerStoreError> {
  if let Ok(read_map) = cache.read() {
    if let Some(cache_entry) = read_map.get(handle) {
      if let Ok(entry) = cache_entry.read() {
        return Ok(entry.clone());
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
  let entry = find_ledger_height(ledger).await?;

  if let Ok(mut write_map) = cache.write() {
    write_map
      .entry(*handle)
      .or_insert_with(|| Arc::new(RwLock::new(entry.clone())));
    Ok(entry)
  } else {
    Err(LedgerStoreError::LedgerError(
      StorageError::LedgerWriteLockFailed,
    ))
  }
}

// This is called when the cache height is incorrect (e.g., concurrent appends)
async fn fix_cached_entry(
  handle: &Handle,
  cache: &CacheMap,
  ledger: &BlobClient,
) -> Result<(), LedgerStoreError> {
  // find the correct height and etag
  let (height, etag) = find_ledger_height(ledger).await?;
  update_cache_entry(handle, cache, Some(height), etag)?;

  Ok(())
}

fn update_cache_entry(
  handle: &Handle,
  cache: &CacheMap,
  new_height: Option<u64>, // None when you only want to update etag
  new_etag: String,
) -> Result<(), LedgerStoreError> {
  if let Ok(cache_map) = cache.read() {
    if let Some(cache_entry) = cache_map.get(handle) {
      if let Ok(mut entry) = cache_entry.write() {
        if let Some(height) = new_height {
          *entry = (height, new_etag);
        } else {
          *entry = (entry.0, new_etag);
        }
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
    if let Some(height) = new_height {
      write_map.insert(*handle, Arc::new(RwLock::new((height, new_etag))));
    } else {
      return Err(LedgerStoreError::LedgerError(
        StorageError::CacheMissingHeight,
      ));
    }
  } else {
    return Err(LedgerStoreError::LedgerError(
      StorageError::LedgerWriteLockFailed,
    ));
  }

  Ok(())
}

async fn find_ledger_height(ledger: &BlobClient) -> Result<(u64, String), LedgerStoreError> {
  let res = ledger.get_page_ranges().execute().await;

  if let Err(err) = res {
    match get_error_status!(err) {
      StatusCode::NOT_FOUND => {
        return Err(LedgerStoreError::LedgerError(StorageError::KeyDoesNotExist));
      },
      _ => {
        eprintln!("Error is {:?}", err);
        return Err(LedgerStoreError::LedgerError(StorageError::UnhandledError));
      },
    }
  }

  let res = res.unwrap();

  // extract latest page range and convert to index.
  let page_list = res.page_list;

  if page_list.ranges.is_empty() {
    return Err(LedgerStoreError::LedgerError(StorageError::KeyDoesNotExist));
  }

  // If this is not true, there is a hole in the ledger... this should never happen
  assert_eq!(page_list.ranges.len(), 1);

  let end: u64 = page_list.ranges[0].end;
  assert_eq!((end + 1) % (LOGICAL_PAGE_SIZE as u64), 0);

  let height = (end + 1) / (LOGICAL_PAGE_SIZE as u64);
  assert!(height > 0);

  Ok((height - 1, res.etag))
}

#[async_trait]
impl LedgerStore for PageBlobLedgerStore {
  async fn create_ledger(
    &self,
    handle: &Handle,
    genesis_block: Block,
  ) -> Result<(), LedgerStoreError> {
    let client = self.client.clone();

    let ledger = client.as_blob_client(&hex::encode(&handle.to_bytes()));

    let res = ledger
      .put_page_blob(PAGE_BLOB_SIZE) // total size of the blob
      .content_type("binary") // this is just an arbitrary string
      .execute()
      .await;

    if let Err(err) = res {
      match get_error_status!(err) {
        StatusCode::BAD_REQUEST => {
          panic!("PAGE_BLOB_SIZE is wrong")
        }, // this should never happen
        _ => {
          eprintln!("Error is {:?}", err);
          return Err(LedgerStoreError::LedgerError(StorageError::UnhandledError));
        },
      }
    }

    let res = res.unwrap();

    // 1. Create the ledger entry that we will add to the brand new ledger
    let init_entry = DBEntry {
      block: genesis_block.to_bytes(),
      receipt: Receipt::default().to_bytes(),
    };

    // Serialize the entries
    let ser_init_entry = serialize_entry(&init_entry)?;
    let init_range = index_to_page_range(0)?;

    // 3. Update
    let res = update_page(&ledger, init_range, ser_init_entry, res.etag).await?;

    // Update the ledger's cache height with the the latest height (which is 0)
    update_cache_entry(handle, &self.cache, Some(0), res.etag)?;
    Ok(())
  }

  async fn append_ledger(
    &self,
    handle: &Handle,
    block: &Block,
    expected_height: usize,
  ) -> Result<usize, LedgerStoreError> {
    let client = self.client.clone();

    let ledger = client.as_blob_client(&hex::encode(&handle.to_bytes()));

    let res = append_ledger_op(handle, block, expected_height, &ledger, &self.cache).await;
    match res {
      Ok(v) => Ok(v),
      Err(e) => match e {
        LedgerStoreError::LedgerError(StorageError::ConcurrentOperation) => {
          fix_cached_entry(handle, &self.cache, &ledger).await?;
          Err(LedgerStoreError::LedgerError(
            StorageError::IncorrectConditionalData,
          ))
        },
        _ => Err(e),
      },
    }
  }

  async fn attach_ledger_receipt(
    &self,
    handle: &Handle,
    receipt: &Receipt,
  ) -> Result<(), LedgerStoreError> {
    let client = self.client.clone();

    let ledger = client.as_blob_client(&hex::encode(&handle.to_bytes()));

    loop {
      let res = attach_ledger_receipt_op(handle, receipt, &ledger, &self.cache).await;

      match res {
        Ok(v) => {
          return Ok(v);
        },
        Err(e) => {
          match e {
            LedgerStoreError::LedgerError(StorageError::ConcurrentOperation) => {
              // fix cache and retry since there was some concurrent op that prevented
              // this attach ledger
              fix_cached_entry(handle, &self.cache, &ledger).await?;
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
    let client = self.client.clone();

    let ledger = client.as_blob_client(&hex::encode(&handle.to_bytes()));
    let (ledger_entry, height) = read_ledger_op(handle, None, &ledger, &self.cache).await?;
    Ok((ledger_entry.block, height))
  }

  async fn read_ledger_by_index(
    &self,
    handle: &Handle,
    index: usize,
  ) -> Result<LedgerEntry, LedgerStoreError> {
    let client = self.client.clone();

    let ledger = client.as_blob_client(&hex::encode(&handle.to_bytes()));

    let (ledger_entry, _height) = read_ledger_op(handle, Some(index), &ledger, &self.cache).await?;
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
    expected_height: usize,
  ) -> Result<usize, LedgerStoreError> {
    self
      .append_ledger(&self.view_handle, block, expected_height)
      .await
  }

  async fn reset_store(&self) -> Result<(), LedgerStoreError> {
    let client = self.client.clone();
    client
      .delete()
      .execute()
      .await
      .expect("failed to delete ledgers");

    Ok(())
  }
}
