use crate::errors::{LedgerStoreError, StorageError};
use crate::store::{LedgerEntry, LedgerStore};
use crate::{Block, CustomSerde, Handle, NimbleDigest, NimbleHashTrait, Receipt};
use async_trait::async_trait;
use bincode;
use mongodb::bson::doc;
use mongodb::bson::{spec::BinarySubtype, Binary};
use mongodb::error::{TRANSIENT_TRANSACTION_ERROR, UNKNOWN_TRANSACTION_COMMIT_RESULT};
use mongodb::options::{Acknowledgment, ReadConcern, TransactionOptions, WriteConcern};
use mongodb::{Client, ClientSession, Collection};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;

macro_rules! with_retry {
  ($x:expr) => {
    match $x {
      Err(error) => match error {
        LedgerStoreError::MongoDBError(mongodb_error) => {
          if mongodb_error.contains_label(TRANSIENT_TRANSACTION_ERROR) {
            continue;
          } else {
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
              _ => {
                return Err(LedgerStoreError::MongoDBError(mongodb_error));
              },
            };
          }
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
  pub index: u64,
  pub receipt: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct DBEntry {
  #[serde(rename = "_id")]
  key: Binary,
  value: Binary, // SerializedLedgerEntry
  tail: bool,
}

#[derive(Debug)]
pub struct MongoCosmosLedgerStore {
  view_handle: Handle,
  client: Client,
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
      view_handle,
      client: cosmos_client,
      dbname: nimble_db_name.clone(),
    };

    // Check if the view ledger exists
    let res = ledger_store.read_view_ledger_tail().await;
    if let Err(error) = res {
      match error {
        LedgerStoreError::LedgerError(StorageError::KeyDoesNotExist) => {
          // Initialized view ledger's entry
          let entry = SerializedLedgerEntry {
            block: Block::new(&[0; 0]).to_bytes(),
            index: 0_u64,
            receipt: Receipt::default().to_bytes(),
          };

          let bson_entry: Binary = bincode::serialize(&entry)
            .expect("failed to serialize entry")
            .to_bson_binary();

          let tail_entry = DBEntry {
            key: view_handle.to_bson_binary(),
            value: bson_entry.clone(),
            tail: true,
          };

          // This is the same as above, but this is basically the copy that will be stored
          // at index 0, whereas the above is stored at the tail (referenced by the view_handle)
          let mut view_handle_with_index = view_handle.to_bytes();
          view_handle_with_index.extend(0usize.to_le_bytes()); // "to_le" converts to little endian

          let first_entry = DBEntry {
            key: view_handle_with_index.to_bson_binary(),
            value: bson_entry,
            tail: false,
          };

          ledger_store
            .client
            .database(&nimble_db_name)
            .collection::<DBEntry>("ledgers")
            .insert_many(vec![first_entry, tail_entry], None)
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
  session: &mut ClientSession,
  ledgers: &Collection<DBEntry>,
  id: Binary,
) -> Result<DBEntry, LedgerStoreError> {
  let res = ledgers
    .find_one_with_session(
      doc! {
          "_id": id,
      },
      None,
      session,
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

async fn commit_with_retry(session: &mut ClientSession) -> Result<(), LedgerStoreError> {
  while let Err(err) = session.commit_transaction().await {
    if err.contains_label(UNKNOWN_TRANSACTION_COMMIT_RESULT) {
      println!("Encountered UnknownTransactionCommitResult, retrying commit operation.");
      continue;
    } else {
      return Err(LedgerStoreError::MongoDBError(err));
    }
  }
  Ok(())
}

async fn append_ledger_transaction(
  handle: &Handle,
  block: &Block,
  expected_height: usize,
  session: &mut ClientSession,
  ledgers: &Collection<DBEntry>,
) -> Result<(), LedgerStoreError> {
  // 1. Check to see if the ledgers contain the handle and get last entry
  let last_data_entry: DBEntry = find_db_entry(session, ledgers, handle.to_bson_binary()).await?;

  // 2. Recover the contents of the ledger entry and check condition
  let bson_last_data_entry: &Binary = &last_data_entry.value;
  let last_data_entry: SerializedLedgerEntry = bincode::deserialize(&bson_last_data_entry.bytes)
    .expect("failed to deserialize last data entry");

  let height_plus_one = {
    let res = last_data_entry.index.checked_add(1);
    if res.is_none() {
      return Err(LedgerStoreError::LedgerError(
        StorageError::LedgerHeightOverflow,
      ));
    }
    res.unwrap()
  };

  if expected_height != 0 && expected_height as u64 != height_plus_one {
    return Err(LedgerStoreError::LedgerError(
      StorageError::IncorrectConditionalData,
    ));
  }

  // 3. Construct the new entry we are going to append to data ledger
  let new_ledger_entry = SerializedLedgerEntry {
    block: block.to_bytes(),
    index: height_plus_one,
    receipt: Receipt::default().to_bytes(),
  };

  let bson_new_ledger_entry: Binary = bincode::serialize(&new_ledger_entry)
    .expect("failed to serialized new ledger entry")
    .to_bson_binary();

  // 4. Pushes the value new_ledger_entry to the end of the ledger (array) named with handle.
  ledgers
    .update_one_with_session(
      doc! {
         "_id": handle.to_bson_binary(),
      },
      doc! {
          "$set": {"value": bson_new_ledger_entry.clone()}
      },
      None,
      session,
    )
    .await?;

  // 4b. If we want to keep intermediate state, then insert it under appropriate index
  // This is the same as above, but this is basically the copy that will be stored
  // at index 0, whereas the above is stored at the tail (referenced by the view_handle)
  let mut handle_with_index = handle.to_bytes();
  handle_with_index.extend(height_plus_one.to_le_bytes());

  let new_entry = DBEntry {
    key: handle_with_index.to_bson_binary(), // handle = handle || idx
    value: bson_new_ledger_entry,
    tail: false,
  };

  ledgers
    .insert_one_with_session(new_entry, None, session)
    .await?;

  // 5. Commit transactions
  commit_with_retry(session).await?;
  Ok(())
}

async fn attach_ledger_receipt_transaction(
  handle_with_index: &[u8],
  receipt: &Receipt,
  session: &mut ClientSession,
  ledgers: &Collection<DBEntry>,
) -> Result<(), LedgerStoreError> {
  // 1. Get the ledger's latest entry

  // 1a. Find the appropriate entry in the ledger if the ledger is full
  let ledger_entry: DBEntry = find_db_entry(
    session,
    ledgers,
    handle_with_index.to_vec().to_bson_binary(),
  )
  .await?;

  // 2. Recover the contents of the ledger entry
  let read_bson_ledger_entry: &Binary = &ledger_entry.value; // only entry due to unique handles
  let mut ledger_entry: SerializedLedgerEntry = bincode::deserialize(&read_bson_ledger_entry.bytes)
    .expect("failed to deserialize ledger entry");

  // 3. Assert the fetched block is the right one
  assert_eq!(ledger_entry.index, receipt.get_height() as u64);

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

  ledgers
    .update_one_with_session(
      doc! {
          "_id": handle_with_index.to_vec().to_bson_binary(),
      },
      doc! {
          "$set": {"value": write_bson_ledger_entry},
      },
      None,
      session,
    )
    .await?;

  // 4. Commit transactions
  commit_with_retry(session).await?;
  Ok(())
}

async fn create_ledger_transaction(
  block: &Block,
  session: &mut ClientSession,
  ledgers: &Collection<DBEntry>,
) -> Result<Handle, LedgerStoreError> {
  // 1. Use view ledger's entry and input block to get information we need for origin of new ledger
  let handle = block.hash();

  // 2. Create the ledger entry that we will add to the brand new ledger
  let data_ledger_entry = SerializedLedgerEntry {
    block: block.to_bytes(),
    index: 0_u64,
    receipt: Receipt::default().to_bytes(),
  };

  let bson_data_ledger_entry: Binary = bincode::serialize(&data_ledger_entry)
    .expect("failed to serialize data ledger entry")
    .to_bson_binary();

  // 3. Add new ledger tail to database under its handle
  let tail_entry = DBEntry {
    key: handle.to_bson_binary(),
    value: bson_data_ledger_entry.clone(),
    tail: true,
  };

  // 4. If we are keeping the full state of the ledger (including intermediaries)
  let mut handle_with_index = handle.to_bytes();
  handle_with_index.extend(0_u64.to_le_bytes()); // to_le is little endian

  let new_entry = DBEntry {
    key: handle_with_index.to_bson_binary(), // handle = handle || idx (which is 0)
    value: bson_data_ledger_entry,
    tail: false,
  };

  ledgers
    .insert_many_with_session(&vec![tail_entry, new_entry], None, session)
    .await?;

  // 5. Commit transactions
  commit_with_retry(session).await?;
  Ok(handle)
}

async fn read_ledger_op(
  id: Binary,
  ledgers: &Collection<DBEntry>,
) -> Result<LedgerEntry, LedgerStoreError> {
  // Find the latest value of view associated with the provided key.
  let res = ledgers
    .find_one(
      doc! {
          "_id": id,
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

async fn find_ledger_height(
  id: Binary,
  ledgers: &Collection<DBEntry>,
) -> Result<usize, LedgerStoreError> {
  let res = ledgers
    .find_one(
      doc! {
          "_id": id,
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

  Ok(entry.index as usize)
}

const RETRY_SLEEP: u64 = 10; // ms
const WRITE_CONFLICT_CODE: i32 = 112;
const REQUEST_RATE_TOO_HIGH_CODE: i32 = 16500;

#[async_trait]
impl LedgerStore for MongoCosmosLedgerStore {
  async fn create_ledger(&self, block: &Block) -> Result<Handle, LedgerStoreError> {
    let client = self.client.clone();
    let ledgers = client
      .database(&self.dbname)
      .collection::<DBEntry>("ledgers");

    loop {
      // transaction session
      let res = client.start_session(None).await;
      if let Err(error) = res {
        return Err(LedgerStoreError::MongoDBError(error));
      }
      let mut session = res.unwrap();

      // transaction properties: below is for serializability
      let options = TransactionOptions::builder()
        .read_concern(ReadConcern::majority())
        .write_concern(WriteConcern::builder().w(Acknowledgment::Majority).build())
        .build();

      session.start_transaction(options).await?;

      with_retry!(create_ledger_transaction(block, &mut session, &ledgers).await);
    }
  }

  async fn append_ledger(
    &self,
    handle: &Handle,
    block: &Block,
    expected_height: usize,
  ) -> Result<(), LedgerStoreError> {
    let client = self.client.clone();
    let ledgers = client
      .database(&self.dbname)
      .collection::<DBEntry>("ledgers");

    loop {
      // transaction session
      let res = client.start_session(None).await;
      if let Err(error) = res {
        return Err(LedgerStoreError::MongoDBError(error));
      }
      let mut session = res.unwrap();

      // transaction properties: below is for serializability
      let options = TransactionOptions::builder()
        .read_concern(ReadConcern::majority())
        .write_concern(WriteConcern::builder().w(Acknowledgment::Majority).build())
        .build();

      session.start_transaction(options).await?;

      with_retry!(
        append_ledger_transaction(handle, block, expected_height, &mut session, &ledgers).await
      );
    }
  }

  async fn attach_ledger_receipt(
    &self,
    handle: &Handle,
    receipt: &Receipt,
  ) -> Result<(), LedgerStoreError> {
    let mut handle_with_index = handle.to_bytes();
    handle_with_index.extend(receipt.metablock.get_height().to_le_bytes()); // "to_le" converts to little endian

    let client = self.client.clone();
    let ledgers = client
      .database(&self.dbname)
      .collection::<DBEntry>("ledgers");

    loop {
      // transaction session
      let res = client.start_session(None).await;
      if let Err(error) = res {
        return Err(LedgerStoreError::MongoDBError(error));
      }
      let mut session = res.unwrap();

      // transaction properties: below is for serializability
      let options = TransactionOptions::builder()
        .read_concern(ReadConcern::majority())
        .write_concern(WriteConcern::builder().w(Acknowledgment::Majority).build())
        .build();

      session.start_transaction(options).await?;

      with_retry!(
        attach_ledger_receipt_transaction(&handle_with_index, receipt, &mut session, &ledgers,)
          .await
      );
    }
  }

  async fn read_ledger_tail(&self, handle: &Handle) -> Result<LedgerEntry, LedgerStoreError> {
    let client = self.client.clone();
    let ledgers = client
      .database(&self.dbname)
      .collection::<DBEntry>("ledgers");

    loop {
      with_retry!(read_ledger_op(handle.to_bson_binary(), &ledgers,).await);
    }
  }

  async fn read_ledger_by_index(
    &self,
    handle: &Handle,
    idx: usize,
  ) -> Result<LedgerEntry, LedgerStoreError> {
    if !cfg!(feature = "full_ledger") && handle != &self.view_handle {
      panic!("Calling read_ledger_by_index without support for full ledger");
    }

    let client = self.client.clone();
    let ledgers = client
      .database(&self.dbname)
      .collection::<DBEntry>("ledgers");

    let mut handle_with_index = handle.to_bytes();
    let idx_u64 = idx as u64;
    handle_with_index.extend(idx_u64.to_le_bytes()); // "to_le" converts to little endian

    loop {
      with_retry!(read_ledger_op(handle_with_index.to_bson_binary(), &ledgers,).await);
    }
  }

  async fn read_view_ledger_tail(&self) -> Result<LedgerEntry, LedgerStoreError> {
    let client = self.client.clone();
    let ledgers = client
      .database(&self.dbname)
      .collection::<DBEntry>("ledgers");

    let res = find_ledger_height(self.view_handle.to_bson_binary(), &ledgers).await;
    if let Err(error) = res {
      return Err(error);
    }
    let index = res.unwrap();
    self.read_ledger_by_index(&self.view_handle, index).await
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
    let ledgers = client
      .database(&self.dbname)
      .collection::<DBEntry>("ledgers");

    loop {
      // transaction session
      let res = client.start_session(None).await;
      if let Err(error) = res {
        return Err(LedgerStoreError::MongoDBError(error));
      }
      let mut session = res.unwrap();

      // transaction properties: below is for serializability
      let options = TransactionOptions::builder()
        .read_concern(ReadConcern::majority())
        .write_concern(WriteConcern::builder().w(Acknowledgment::Majority).build())
        .build();

      session.start_transaction(options).await?;

      with_retry!(
        append_ledger_transaction(
          &self.view_handle,
          block,
          expected_height,
          &mut session,
          &ledgers,
        )
        .await
      );
    }
  }

  async fn reset_store(&self) -> Result<(), LedgerStoreError> {
    let client = self.client.clone();
    let ledgers = client
      .database(&self.dbname)
      .collection::<DBEntry>("ledgers");
    ledgers
      .delete_many(doc! {}, None)
      .await
      .expect("failed to delete ledgers");

    Ok(())
  }
}
