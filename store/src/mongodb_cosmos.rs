use crate::errors::{LedgerStoreError, StorageError};
use crate::{LedgerEntry, LedgerStore};
use async_trait::async_trait;
use bincode;
use hex;
use ledger::{Block, CustomSerde, Handle, NimbleDigest, Receipt};
use mongodb::bson::doc;
use mongodb::bson::{spec::BinarySubtype, Binary};
use mongodb::error::WriteFailure::WriteError;
use mongodb::{Client, Collection};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt::Debug;

macro_rules! with_retry {
  ($x:expr, $write_retry:expr) => {
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
                if $write_retry {
                  continue;
                } else {
                  return Err(LedgerStoreError::LedgerError(StorageError::DuplicateKey));
                }
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

    let view_handle: Handle = NimbleDigest::from_bytes(&vec![0u8; NimbleDigest::num_bytes()])
      .expect(
        "unable
          to deserialize view ledger handle",
      );

    let ledger_store = MongoCosmosLedgerStore {
      client: cosmos_client,
      dbname: nimble_db_name.clone(),
      view_handle,
    };

    // Check if the view ledger exists
    let res = ledger_store.read_view_ledger_tail().await;
    if let Err(error) = res {
      match error {
        LedgerStoreError::LedgerError(StorageError::KeyDoesNotExist) => {
          // Initialized view ledger's entry
          let entry = SerializedLedgerEntry {
            block: Block::new(&[0; 0]).to_bytes(),
            receipt: Receipt::default().to_bytes(),
          };

          let bson_entry: Binary = bincode::serialize(&entry)
            .expect("failed to serialize entry")
            .to_bson_binary();

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
        },
        _ => {
          return Err(error);
        },
      }
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
  block: &Block,
  expected_height: Option<usize>,
  ledger: &Collection<DBEntry>,
) -> Result<(), LedgerStoreError> {
  let height = find_ledger_height(ledger).await?;

  let height_plus_one = {
    let res = height.checked_add(1);
    if res.is_none() {
      return Err(LedgerStoreError::LedgerError(
        StorageError::LedgerHeightOverflow,
      ));
    }
    res.unwrap()
  };

  // 2. If it is a conditional update, check if condition still holds
  if expected_height.is_some()
    && i64::try_from(expected_height.unwrap()).expect("potential integer overflow")
      != height_plus_one
  {
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

  Ok(())
}

async fn attach_ledger_receipt_op(
  index: i64,
  receipt: &Receipt,
  ledger: &Collection<DBEntry>,
) -> Result<(), LedgerStoreError> {
  // 1. Find the appropriate entry in the ledger
  let ledger_entry: DBEntry = find_db_entry(ledger, index).await?;

  // 2. Recover the contents of the ledger entry
  let read_bson_ledger_entry: &Binary = &ledger_entry.value; // only entry due to unique handles
  let mut ledger_entry: SerializedLedgerEntry = bincode::deserialize(&read_bson_ledger_entry.bytes)
    .expect("failed to deserialize ledger entry");

  // 3. Assert the fetched block is the right one
  let entry_height = i64::try_from(receipt.get_height()).expect("Potential integer overflow");
  assert_eq!(index, entry_height);

  // 4. Update receipt
  let mut new_receipt =
    Receipt::from_bytes(&ledger_entry.receipt).expect("failed to deserialize receipt");
  let res = new_receipt.append(receipt);
  if res.is_err() {
    return Err(LedgerStoreError::LedgerError(
      StorageError::MismatchedReceipts,
    ));
  }
  ledger_entry.receipt = new_receipt.to_bytes();

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
  genesis_block: &Block,
  first_block: &Block,
  ledger: &Collection<DBEntry>,
) -> Result<(), LedgerStoreError> {
  // 1. Create the ledger entry that we will add to the brand new ledger
  let init_data_ledger_entry = SerializedLedgerEntry {
    block: genesis_block.to_bytes(),
    receipt: Receipt::default().to_bytes(),
  };

  let first_data_ledger_entry = SerializedLedgerEntry {
    block: first_block.to_bytes(),
    receipt: Receipt::default().to_bytes(),
  };

  let bson_init_data_ledger_entry: Binary = bincode::serialize(&init_data_ledger_entry)
    .expect("failed to serialize data ledger entry")
    .to_bson_binary();

  let bson_first_data_ledger_entry: Binary = bincode::serialize(&first_data_ledger_entry)
    .expect("failed to serialize data ledger entry")
    .to_bson_binary();

  // 2. init data entry
  let init_entry = DBEntry {
    index: 0,
    value: bson_init_data_ledger_entry,
  };

  // 3. first data entry
  let first_entry = DBEntry {
    index: 1,
    value: bson_first_data_ledger_entry,
  };

  ledger
    .insert_many(&vec![first_entry, init_entry], None)
    .await?;
  Ok(())
}

async fn read_ledger_op(
  index: i64,
  ledger: &Collection<DBEntry>,
) -> Result<LedgerEntry, LedgerStoreError> {
  // Find the latest value of view associated with the provided index.
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

  let res = LedgerEntry {
    block: Block::from_bytes(&entry.block).unwrap(),
    receipt: Receipt::from_bytes(&entry.receipt).unwrap(),
  };

  Ok(res)
}

async fn find_ledger_height(ledger: &Collection<DBEntry>) -> Result<i64, LedgerStoreError> {
  // There are two methods for computing height estimated_document_count returns
  // height from metadata stored in mongodb. This is an estimate in the sense
  // that it might return a stale count the if the database shutdown in an unclean way and restarted.
  // In contrast, count_documents returns an accurate count but requires scanning all docs.
  let res = ledger.estimated_document_count(None).await;

  if let Err(error) = res {
    return Err(LedgerStoreError::MongoDBError(error));
  }

  Ok(i64::try_from(res.unwrap()).expect("potential integer overflow"))
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
    first_block: Block,
  ) -> Result<(), LedgerStoreError> {
    let client = self.client.clone();
    let ledger = client
      .database(&self.dbname)
      .collection::<DBEntry>(&hex::encode(&handle.to_bytes()));

    loop {
      with_retry!(
        create_ledger_op(&genesis_block, &first_block, &ledger).await,
        false
      );
    }
  }

  async fn append_ledger(
    &self,
    handle: &Handle,
    block: &Block,
    expected_height: usize,
  ) -> Result<(), LedgerStoreError> {
    let client = self.client.clone();
    let ledger = client
      .database(&self.dbname)
      .collection::<DBEntry>(&hex::encode(handle.to_bytes()));

    loop {
      with_retry!(
        append_ledger_op(block, Some(expected_height), &ledger).await,
        true
      );
    }
  }

  async fn attach_ledger_receipt(
    &self,
    handle: &Handle,
    receipt: &Receipt,
  ) -> Result<(), LedgerStoreError> {
    let index = i64::try_from(receipt.get_height()).expect("Potential integer overflow");

    let client = self.client.clone();
    let ledger = client
      .database(&self.dbname)
      .collection::<DBEntry>(&hex::encode(&handle.to_bytes()));

    loop {
      with_retry!(
        attach_ledger_receipt_op(index, receipt, &ledger).await,
        false
      );
    }
  }

  async fn read_ledger_tail(&self, handle: &Handle) -> Result<LedgerEntry, LedgerStoreError> {
    let client = self.client.clone();
    let ledger = client
      .database(&self.dbname)
      .collection::<DBEntry>(&hex::encode(&handle.to_bytes()));

    loop {
      let index = find_ledger_height(&ledger).await?;
      with_retry!(read_ledger_op(index, &ledger).await, false);
    }
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

    let index_i64 = i64::try_from(index).expect("potential integer overflow");

    loop {
      with_retry!(read_ledger_op(index_i64, &ledger).await, false);
    }
  }

  async fn read_view_ledger_tail(&self) -> Result<LedgerEntry, LedgerStoreError> {
    let client = self.client.clone();
    let ledger = client
      .database(&self.dbname)
      .collection::<DBEntry>(&hex::encode(&self.view_handle.to_bytes()));

    let index = find_ledger_height(&ledger).await?;
    self
      .read_ledger_by_index(
        &self.view_handle,
        usize::try_from(index).expect("integer overflow"),
      )
      .await
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
  ) -> Result<(), LedgerStoreError> {
    let client = self.client.clone();
    let ledger = client
      .database(&self.dbname)
      .collection::<DBEntry>(&hex::encode(&self.view_handle.to_bytes()));

    loop {
      with_retry!(
        append_ledger_op(block, Some(expected_height), &ledger,).await,
        true
      );
    }
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
