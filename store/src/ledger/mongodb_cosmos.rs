use crate::{
  errors::{LedgerStoreError, StorageError},
  ledger::{LedgerEntry, LedgerStore},
};
use async_trait::async_trait;
use bincode;
use hex;
use ledger::{Block, CustomSerde, Handle, NimbleDigest, Nonce, Receipt};
use mongodb::{
  bson::{doc, spec::BinarySubtype, Binary},
  error::WriteFailure::WriteError,
  Client, Collection,
};
use serde::{Deserialize, Serialize};
use std::{
  collections::HashMap,
  convert::TryFrom,
  fmt::Debug,
  sync::{Arc, RwLock},
};

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
      Ok(e) => e,
    }
  };
}

macro_rules! with_retry {
  ($x:expr, $handle:expr, $cache:expr, $ledger:expr) => {
    match $x {
      Err(error) => match error {
        LedgerStoreError::MongoDBError(mongodb_error) => {
          match mongodb_error.kind.as_ref() {
            mongodb::error::ErrorKind::Command(cmd_err) => {
              if cmd_err.code == WRITE_CONFLICT_CODE {
                continue;
              } else if cmd_err.code == REQUEST_RATE_TOO_HIGH_CODE {
                std::thread::sleep(std::time::Duration::from_millis(RETRY_SLEEP));
                continue;
              } else {
                return Err(LedgerStoreError::MongoDBError(mongodb_error));
              }
            },
            mongodb::error::ErrorKind::Write(WriteError(write_error)) => {
              if write_error.code == DUPLICATE_KEY_CODE {
                fix_cached_height($handle, $cache, $ledger).await?;
                return Err(LedgerStoreError::LedgerError(StorageError::DuplicateKey));
              }
            },
            _ => {
              return Err(LedgerStoreError::MongoDBError(mongodb_error));
            },
          };
        },
        _ => {
          return Err(error);
        },
      },
      Ok(r) => {
        return Ok(r);
      },
    }
  };
}

pub trait BsonBinaryData {
  fn to_bson_binary(&self) -> Binary;
}

impl BsonBinaryData for Vec<u8> {
  fn to_bson_binary(&self) -> Binary {
    Binary {
      subtype: BinarySubtype::Generic,
      bytes: self.clone(),
    }
  }
}

impl BsonBinaryData for Handle {
  fn to_bson_binary(&self) -> Binary {
    Binary {
      subtype: BinarySubtype::Generic,
      bytes: self.to_bytes(),
    }
  }
}

type CacheEntry = Arc<RwLock<i64>>;
type CacheMap = Arc<RwLock<HashMap<Handle, CacheEntry>>>;

#[derive(Serialize, Deserialize, Clone, Debug)]
struct SerializedLedgerEntry {
  pub block: Vec<u8>,
  pub receipt: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct DBEntry {
  #[serde(rename = "_id")]
  index: i64,
  value: Binary, // SerializedLedgerEntry
}

#[derive(Debug)]
pub struct MongoCosmosLedgerStore {
  client: Client,
  view_handle: Handle,
  dbname: String,
  cache: CacheMap,
}

impl MongoCosmosLedgerStore {
  pub async fn new(args: &HashMap<String, String>) -> Result<Self, LedgerStoreError> {
    if !args.contains_key("COSMOS_URL") {
      return Err(LedgerStoreError::LedgerError(
        StorageError::MissingArguments,
      ));
    }
    let conn_string = args["COSMOS_URL"].clone();

    // Below are the desired name of the db and the name of the collection
    // (they can be anything initially, but afterwards, they need to be the same
    // so you access the same db/collection and recover the stored data)
    let mut nimble_db_name = String::from("nimble_cosmosdb");
    if args.contains_key("NIMBLE_DB") {
      nimble_db_name = args["NIMBLE_DB"].clone();
    }

    let res = Client::with_uri_str(&conn_string).await;
    if res.is_err() {
      eprintln!("Connection with cosmosdb failed");
      return Err(LedgerStoreError::LedgerError(StorageError::InvalidDBUri));
    }
    let cosmos_client = res.unwrap();

    let view_handle = match NimbleDigest::from_bytes(&vec![0u8; NimbleDigest::num_bytes()]) {
      Ok(e) => e,
      Err(_) => {
        return Err(LedgerStoreError::LedgerError(
          StorageError::DeserializationError,
        ));
      },
    };

    let cache = Arc::new(RwLock::new(HashMap::new()));

    let ledger_store = MongoCosmosLedgerStore {
      client: cosmos_client,
      dbname: nimble_db_name.clone(),
      view_handle,
      cache,
    };

    // Check if the view ledger exists, if not, create a new one
    if let Err(error) = ledger_store.read_view_ledger_tail().await {
      match error {
        LedgerStoreError::LedgerError(StorageError::KeyDoesNotExist) => {
          // Initialized view ledger's entry
          let entry = SerializedLedgerEntry {
            block: Block::new(&[0; 0]).to_bytes(),
            receipt: Receipt::default().to_bytes(),
          };

          let bson_entry: Binary = match bincode::serialize(&entry) {
            Ok(e) => e.to_bson_binary(),
            Err(_) => {
              return Err(LedgerStoreError::LedgerError(
                StorageError::SerializationError,
              ));
            },
          };

          let tail_entry = DBEntry {
            index: 0_i64,
            value: bson_entry.clone(),
          };

          ledger_store
            .client
            .database(&nimble_db_name)
            .collection::<DBEntry>(&hex::encode(&view_handle.to_bytes()))
            .insert_one(tail_entry, None)
            .await?;

          update_cache_entry(&view_handle, &ledger_store.cache, 0)?;
        },
        _ => {
          return Err(error);
        },
      };
    } else {
      // Since view ledger exists, update the cache height with the latest height
      let ledger = ledger_store
        .client
        .database(&nimble_db_name)
        .collection::<DBEntry>(&hex::encode(&view_handle.to_bytes()));
      fix_cached_height(&ledger_store.view_handle, &ledger_store.cache, &ledger).await?;
    }

    Ok(ledger_store)
  }
}

async fn find_db_entry(
  ledger: &Collection<DBEntry>,
  index: i64,
) -> Result<DBEntry, LedgerStoreError> {
  let res = ledger
    .find_one(
      doc! {
          "_id": index,
      },
      None,
    )
    .await;
  if let Err(error) = res {
    return Err(LedgerStoreError::MongoDBError(error));
  }
  let db_entry: DBEntry = match res.unwrap() {
    None => {
      return Err(LedgerStoreError::LedgerError(StorageError::KeyDoesNotExist));
    },
    Some(x) => x,
  };
  Ok(db_entry)
}

async fn append_ledger_op(
  handle: &Handle,
  block: &Block,
  expected_height: usize,
  ledger: &Collection<DBEntry>,
  cache: &CacheMap,
) -> Result<(usize, Vec<Nonce>), LedgerStoreError> {
  let height = get_cached_height(handle, cache, ledger).await?;
  let height_plus_one = checked_increment!(height);

  // 2. If it is a conditional update, check if condition still holds
  if checked_conversion!(expected_height, i64) != height_plus_one {
    eprintln!(
      "Expected height {};  Height-plus-one: {}",
      expected_height, height_plus_one
    );

    return Err(LedgerStoreError::LedgerError(
      StorageError::IncorrectConditionalData,
    ));
  }

  // 3. Construct the new entry we are going to append to the ledger
  let new_ledger_entry = SerializedLedgerEntry {
    block: block.to_bytes(),
    receipt: Receipt::default().to_bytes(),
  };

  let bson_new_ledger_entry: Binary = bincode::serialize(&new_ledger_entry)
    .expect("failed to serialized new ledger entry")
    .to_bson_binary();

  let new_entry = DBEntry {
    index: height_plus_one,
    value: bson_new_ledger_entry,
  };

  // 4. Try to insert the new entry into the ledger.
  // If it fails, caller must retry.
  ledger.insert_one(new_entry, None).await?;

  // Update the cached height for this ledger
  update_cache_entry(handle, cache, height_plus_one)?;
  Ok((height_plus_one as usize, Vec::new()))
}

async fn attach_ledger_receipt_op(
  receipt: &Receipt,
  ledger: &Collection<DBEntry>,
) -> Result<(), LedgerStoreError> {
  // 1. Get the desired index.
  let index = checked_conversion!(receipt.get_height(), i64);

  // 2. Find the appropriate entry in the ledger
  let ledger_entry: DBEntry = find_db_entry(ledger, index).await?;

  // 3. Recover the contents of the ledger entry
  let read_bson_ledger_entry: &Binary = &ledger_entry.value; // only entry due to unique handles
  let mut ledger_entry: SerializedLedgerEntry = bincode::deserialize(&read_bson_ledger_entry.bytes)
    .expect("failed to deserialize ledger entry");

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

  // 5. Re-serialize into bson binary
  let write_bson_ledger_entry: Binary = bincode::serialize(&ledger_entry)
    .expect("failed to serialized ledger entry")
    .to_bson_binary();

  ledger
    .update_one(
      doc! {
          "_id": index,
      },
      doc! {
          "$set": {"value": write_bson_ledger_entry},
      },
      None,
    )
    .await?;

  Ok(())
}

async fn create_ledger_op(
  handle: &Handle,
  genesis_block: &Block,
  ledger: &Collection<DBEntry>,
  cache: &CacheMap,
) -> Result<(), LedgerStoreError> {
  // 1. Create the ledger entry that we will add to the brand new ledger
  let genesis_data_ledger_entry = SerializedLedgerEntry {
    block: genesis_block.to_bytes(),
    receipt: Receipt::default().to_bytes(),
  };

  let bson_init_data_ledger_entry: Binary = bincode::serialize(&genesis_data_ledger_entry)
    .expect("failed to serialize data ledger entry")
    .to_bson_binary();

  // 2. init data entry
  let genesis_entry = DBEntry {
    index: 0,
    value: bson_init_data_ledger_entry,
  };

  ledger.insert_one(&genesis_entry, None).await?;

  // Update the ledger's cache height with the the latest height (which is 0)
  update_cache_entry(handle, cache, 0)?;

  Ok(())
}

async fn read_ledger_op(
  idx: Option<usize>,
  ledger: &Collection<DBEntry>,
) -> Result<(LedgerEntry, usize), LedgerStoreError> {
  let index = match idx {
    None => find_ledger_height(ledger).await?,
    Some(i) => {
      checked_conversion!(i, i64)
    },
  };

  let res = ledger
    .find_one(
      doc! {
          "_id": index,
      },
      None,
    )
    .await;

  if let Err(error) = res {
    return Err(LedgerStoreError::MongoDBError(error));
  }

  let ledger_entry = match res.unwrap() {
    None => {
      return Err(LedgerStoreError::LedgerError(StorageError::KeyDoesNotExist));
    },
    Some(s) => s,
  };

  // 2. Recover the contents of the ledger entry
  let bson_entry: &Binary = &ledger_entry.value;
  let entry: SerializedLedgerEntry =
    bincode::deserialize(&bson_entry.bytes).expect("failed to deserialize entry");

  let res = LedgerEntry::new(
    Block::from_bytes(&entry.block).unwrap(),
    Receipt::from_bytes(&entry.receipt).unwrap(),
    None, //TODO
  );

  Ok((res, checked_conversion!(index, usize)))
}

async fn get_cached_height(
  handle: &Handle,
  cache: &CacheMap,
  ledger: &Collection<DBEntry>,
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
  let height = find_ledger_height(ledger).await?;

  if let Ok(mut write_map) = cache.write() {
    write_map
      .entry(*handle)
      .or_insert_with(|| Arc::new(RwLock::new(height)));
    Ok(height)
  } else {
    Err(LedgerStoreError::LedgerError(
      StorageError::LedgerWriteLockFailed,
    ))
  }
}

// This is called when the cache height is incorrect (e.g., concurrent appends)
async fn fix_cached_height(
  handle: &Handle,
  cache: &CacheMap,
  ledger: &Collection<DBEntry>,
) -> Result<(), LedgerStoreError> {
  // find the correct height
  let height = find_ledger_height(ledger).await?;
  update_cache_entry(handle, cache, height)?;

  Ok(())
}

fn update_cache_entry(
  handle: &Handle,
  cache: &CacheMap,
  new_height: i64,
) -> Result<(), LedgerStoreError> {
  if let Ok(cache_map) = cache.read() {
    if let Some(cache_entry) = cache_map.get(handle) {
      if let Ok(mut height) = cache_entry.write() {
        *height = new_height;
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
    write_map.insert(*handle, Arc::new(RwLock::new(new_height)));
  } else {
    return Err(LedgerStoreError::LedgerError(
      StorageError::LedgerWriteLockFailed,
    ));
  }

  Ok(())
}

async fn find_ledger_height(ledger: &Collection<DBEntry>) -> Result<i64, LedgerStoreError> {
  // There are two methods for computing height estimated_document_count returns
  // height from metadata stored in mongodb. This is an estimate in the sense
  // that it might return a stale count the if the database shutdown in an unclean way and restarted.
  // In contrast, count_documents returns an accurate count but requires scanning all docs.
  let count = checked_conversion!(ledger.estimated_document_count(None).await?, i64);

  // The height or offset is count - 1 since we index from 0.
  if count > 0 {
    Ok(count - 1)
  } else {
    Err(LedgerStoreError::LedgerError(StorageError::KeyDoesNotExist))
  }
}

async fn loop_and_read(
  handle: &Handle,
  index: Option<usize>,
  ledger: &Collection<DBEntry>,
  cache: &CacheMap,
) -> Result<(LedgerEntry, usize), LedgerStoreError> {
  loop {
    with_retry!(read_ledger_op(index, ledger).await, handle, cache, ledger);
  }
}

const RETRY_SLEEP: u64 = 50; // ms
const WRITE_CONFLICT_CODE: i32 = 112;
const DUPLICATE_KEY_CODE: i32 = 11000;
const REQUEST_RATE_TOO_HIGH_CODE: i32 = 16500;

#[async_trait]
impl LedgerStore for MongoCosmosLedgerStore {
  async fn create_ledger(
    &self,
    handle: &Handle,
    genesis_block: Block,
  ) -> Result<(), LedgerStoreError> {
    let client = self.client.clone();
    let ledger = client
      .database(&self.dbname)
      .collection::<DBEntry>(&hex::encode(&handle.to_bytes()));

    loop {
      with_retry!(
        create_ledger_op(handle, &genesis_block, &ledger, &self.cache).await,
        handle,
        &self.cache,
        &ledger
      );
    }
  }

  async fn append_ledger(
    &self,
    handle: &Handle,
    block: &Block,
    expected_height: usize,
  ) -> Result<(usize, Vec<Nonce>), LedgerStoreError> {
    let client = self.client.clone();
    let ledger = client
      .database(&self.dbname)
      .collection::<DBEntry>(&hex::encode(handle.to_bytes()));

    loop {
      with_retry!(
        append_ledger_op(handle, block, expected_height, &ledger, &self.cache).await,
        handle,
        &self.cache,
        &ledger
      );
    }
  }

  async fn attach_ledger_receipt(
    &self,
    handle: &Handle,
    receipt: &Receipt,
  ) -> Result<(), LedgerStoreError> {
    let client = self.client.clone();
    let ledger = client
      .database(&self.dbname)
      .collection::<DBEntry>(&hex::encode(&handle.to_bytes()));

    loop {
      with_retry!(
        attach_ledger_receipt_op(receipt, &ledger).await,
        handle,
        &self.cache,
        &ledger
      );
    }
  }

  #[allow(unused_variables)]
  async fn attach_ledger_nonce(
    &self,
    handle: &Handle,
    nonce: &Nonce,
  ) -> Result<usize, LedgerStoreError> {
    unimplemented!()
  }

  async fn read_ledger_tail(
    &self,
    handle: &Handle,
  ) -> Result<(LedgerEntry, usize), LedgerStoreError> {
    let client = self.client.clone();
    let ledger = client
      .database(&self.dbname)
      .collection::<DBEntry>(&hex::encode(&handle.to_bytes()));

    loop_and_read(handle, None, &ledger, &self.cache).await
  }

  async fn read_ledger_by_index(
    &self,
    handle: &Handle,
    index: usize,
  ) -> Result<LedgerEntry, LedgerStoreError> {
    let client = self.client.clone();
    let ledger = client
      .database(&self.dbname)
      .collection::<DBEntry>(&hex::encode(&handle.to_bytes()));

    let (entry, _height) = loop_and_read(handle, Some(index), &ledger, &self.cache).await?;
    Ok(entry)
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
    let res = self
      .append_ledger(&self.view_handle, block, expected_height)
      .await?;
    Ok(res.0)
  }

  async fn reset_store(&self) -> Result<(), LedgerStoreError> {
    let client = self.client.clone();
    client
      .database(&self.dbname)
      .drop(None)
      .await
      .expect("failed to delete ledgers");

    Ok(())
  }
}
