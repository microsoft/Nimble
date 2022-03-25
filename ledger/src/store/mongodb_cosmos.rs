use crate::errors::{LedgerStoreError, StorageError};
use crate::store::{LedgerEntry, LedgerStore, LedgerView};
use crate::{Block, CustomSerde, Handle, MetaBlock, NimbleDigest, NimbleHashTrait, Receipt};
use async_trait::async_trait;
use bincode;
use mongodb::bson::doc;
use mongodb::bson::{spec::BinarySubtype, Binary};
use mongodb::error::{TRANSIENT_TRANSACTION_ERROR, UNKNOWN_TRANSACTION_COMMIT_RESULT};
use mongodb::options::{Acknowledgment, ReadConcern, TransactionOptions, WriteConcern};
use mongodb::{Client, ClientSession, Collection, SessionCursor};
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

pub type IdSigBytes = Vec<(Vec<u8>, Vec<u8>)>;

#[derive(Serialize, Deserialize, Clone, Debug)]
struct SerializedLedgerEntry {
  pub block: Vec<u8>,
  pub metablock: Vec<u8>,
  pub receipt: (Vec<u8>, IdSigBytes),
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
    let ledger_collection = "ledgers";

    let res = Client::with_uri_str(&conn_string).await;
    if res.is_err() {
      eprintln!("Connection with cosmosdb failed");
      return Err(LedgerStoreError::LedgerError(StorageError::InvalidDBUri));
    }
    let cosmos_client = res.unwrap();
    let ledgers = cosmos_client
      .database(&nimble_db_name)
      .collection::<DBEntry>(ledger_collection);

    // Initialized view ledger's entry
    let entry = SerializedLedgerEntry {
      block: Block::new(&[0; 0]).to_bytes(),
      metablock: MetaBlock::new(&NimbleDigest::default(), &NimbleDigest::default(), 0).to_bytes(),
      receipt: Receipt {
        view: NimbleDigest::default(),
        id_sigs: Vec::new(),
      }
      .to_bytes(),
    };

    let bson_entry: Binary = bincode::serialize(&entry)
      .expect("failed to serialize entry")
      .to_bson_binary();

    let view_handle: Handle = NimbleDigest::from_bytes(&vec![0u8; NimbleDigest::num_bytes()])
      .expect(
        "unable
            to deserialize view ledger handle",
      );

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

    ledgers
      .insert_many(vec![first_entry, tail_entry], None)
      .await?;

    Ok(MongoCosmosLedgerStore {
      view_handle,
      client: cosmos_client,
      dbname: nimble_db_name,
    })
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
  cond: &NimbleDigest,
  session: &mut ClientSession,
  ledgers: &Collection<DBEntry>,
) -> Result<(MetaBlock, NimbleDigest), LedgerStoreError> {
  // 1. Check to see if the ledgers contain the handle and get last entry
  let last_data_entry: DBEntry = find_db_entry(session, ledgers, handle.to_bson_binary()).await?;

  // 2. Recover the contents of the ledger entry and check condition
  let bson_last_data_entry: &Binary = &last_data_entry.value;
  let last_data_entry: SerializedLedgerEntry = bincode::deserialize(&bson_last_data_entry.bytes)
    .expect("failed to deserialize last data entry");
  let last_data_metablock =
    MetaBlock::from_bytes(last_data_entry.metablock).expect("deserialize error");

  if *cond != NimbleDigest::default() && *cond != last_data_metablock.hash() {
    return Err(LedgerStoreError::LedgerError(
      StorageError::IncorrectConditionalData,
    ));
  }

  // 3. Construct the new entry we are going to append to data ledger
  let metablock = MetaBlock::new(
    &last_data_metablock.hash(),
    &block.hash(),
    last_data_metablock.get_height() + 1,
  );

  let new_ledger_entry = SerializedLedgerEntry {
    block: block.to_bytes(),
    metablock: metablock.to_bytes(),
    receipt: Receipt {
      view: NimbleDigest::default(),
      id_sigs: Vec::new(),
    }
    .to_bytes(),
  };

  let bson_new_ledger_entry: Binary = bincode::serialize(&new_ledger_entry)
    .expect("failed to serialized new ledger entry")
    .to_bson_binary();

  let tail_hash = metablock.hash();

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
  if cfg!(feature = "full_ledger") {
    // This is the same as above, but this is basically the copy that will be stored
    // at index 0, whereas the above is stored at the tail (referenced by the view_handle)
    let mut handle_with_index = handle.to_bytes();
    handle_with_index.extend((last_data_metablock.get_height() + 1).to_le_bytes());

    let new_entry = DBEntry {
      key: handle_with_index.to_bson_binary(), // handle = handle || idx
      value: bson_new_ledger_entry,
      tail: false,
    };

    ledgers
      .insert_one_with_session(new_entry, None, session)
      .await?;
  }

  // 5. Commit transactions
  commit_with_retry(session).await?;
  Ok((metablock, tail_hash))
}

async fn attach_ledger_receipt_transaction(
  handle_with_index: &[u8],
  metablock: &MetaBlock,
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
  let ledger_metablock =
    MetaBlock::from_bytes(ledger_entry.metablock.clone()).expect("failed to deserailize metablock");
  assert_eq!(ledger_metablock.get_height(), metablock.get_height());

  // 4. Update receipt
  ledger_entry.receipt = receipt.to_bytes();

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
) -> Result<(Handle, MetaBlock, NimbleDigest), LedgerStoreError> {
  // 1. Use view ledger's entry and input block to get information we need for origin of new ledger
  let handle = block.hash();
  let block_hash = block.hash();
  let metablock = MetaBlock::new(&NimbleDigest::default(), &block_hash, 0);

  // 2. Create the ledger entry that we will add to the brand new ledger
  let data_ledger_entry = SerializedLedgerEntry {
    block: block.to_bytes(),
    metablock: metablock.to_bytes(),
    receipt: Receipt {
      id_sigs: Vec::new(),
      view: NimbleDigest::default(),
    }
    .to_bytes(),
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
  if cfg!(feature = "full_ledger") {
    let mut handle_with_index = handle.to_bytes();
    handle_with_index.extend(0usize.to_le_bytes()); // to_le is little endian

    let new_entry = DBEntry {
      key: handle_with_index.to_bson_binary(), // handle = handle || idx (which is 0)
      value: bson_data_ledger_entry,
      tail: false,
    };

    ledgers
      .insert_many_with_session(&vec![tail_entry, new_entry], None, session)
      .await?;
  } else {
    ledgers
      .insert_one_with_session(&tail_entry, None, session)
      .await?;
  };

  // 5. Commit transactions
  commit_with_retry(session).await?;
  let tail_hash = metablock.hash();
  Ok((handle, metablock, tail_hash))
}

async fn append_view_ledger_transaction(
  block: &Block,
  view_handle: &Handle,
  session: &mut ClientSession,
  ledgers: &Collection<DBEntry>,
) -> Result<LedgerView, LedgerStoreError> {
  // 1. Read the last value of all ledgers (including view ledger)

  // Probe cosmosdb for all ledgers that are tail
  let res = ledgers
    .find_with_session(
      doc! {
          "tail": true,
      },
      None,
      session,
    )
    .await;
  if let Err(error) = res {
    return Err(LedgerStoreError::MongoDBError(error));
  }
  let mut all_ledgers: SessionCursor<DBEntry> = res.unwrap();

  // Initial LedgerStoreState
  let mut ledger_tail_map: HashMap<NimbleDigest, (NimbleDigest, usize)> = HashMap::new();
  let mut view_ledger_tail: (Vec<u8>, usize) = (vec![], 0);

  // 2. Iterate through all non_view ledgers to update LedgerStoreState
  while let Some(res_ledger_entry) = all_ledgers.next(session).await {
    if res_ledger_entry.is_err() {
      eprintln!("failed to get a tail");
      return Err(LedgerStoreError::LedgerError(StorageError::KeyDoesNotExist));
    }
    let ledger_entry = res_ledger_entry.unwrap();
    // If ledger_entry is the view ledger
    if ledger_entry.key.bytes == view_handle.to_bytes() {
      // get the tail of view ledger
      let entry_val: SerializedLedgerEntry = {
        let bson_entry: &Binary = &ledger_entry.value;
        bincode::deserialize(&bson_entry.bytes).expect("failed to deserialize entry")
      };

      view_ledger_tail = {
        let view_ledger_metablock = MetaBlock::from_bytes(entry_val.metablock.clone())
          .expect("failed to deserialize ledger metablock");
        (
          view_ledger_metablock.hash().to_bytes(),
          view_ledger_metablock.get_height(),
        )
      };
    } else {
      // ledger_entry is not view ledger

      // get the tail of ledger
      let entry_val: SerializedLedgerEntry = {
        let bson_entry: &Binary = &ledger_entry.value; // only entry due to projection
        bincode::deserialize(&bson_entry.bytes).expect("failed to deserialize entry")
      };

      let ledger_metablock = MetaBlock::from_bytes(entry_val.metablock.clone())
        .expect("failed to deserialize ledger metablock");

      let res = ledger_tail_map.insert(
        NimbleDigest::from_bytes(&ledger_entry.key.bytes).unwrap(),
        (ledger_metablock.hash(), ledger_metablock.get_height()),
      );
      assert!(res.is_none()); // since the key (ledger_handle) shouldn't exist.
    }
  }

  // 3. Compute new ledger entry
  let new_ledger_entry = LedgerEntry {
    block: block.clone(),
    metablock: MetaBlock::new(
      &if view_ledger_tail.1 == 0 {
        NimbleDigest::default()
      } else {
        NimbleDigest::from_bytes(&view_ledger_tail.0).expect("failed to deserialize")
      },
      &block.hash(),
      view_ledger_tail.1 + 1,
    ),
    receipt: Receipt {
      id_sigs: Vec::new(),
      view: NimbleDigest::default(),
    },
  };

  let metablock = new_ledger_entry.metablock.clone();

  // 4. Serialize new ledger entry
  let serialized_new_ledger_entry = SerializedLedgerEntry {
    block: new_ledger_entry.block.to_bytes(),
    metablock: new_ledger_entry.metablock.to_bytes(),
    receipt: new_ledger_entry.receipt.to_bytes(),
  };

  let bson_new_ledger_entry: Binary = bincode::serialize(&serialized_new_ledger_entry)
    .expect("failed to serialized new ledger entry")
    .to_bson_binary();

  // 5. Updates the value new_ledger_entry to the tail named with handle.
  ledgers
    .update_one_with_session(
      doc! {
          "_id": view_handle.to_bson_binary(),
      },
      doc! {
          "$set": {"value": bson_new_ledger_entry.clone()},
      },
      None,
      session,
    )
    .await?;

  // 6. Also stores new_ledger_entry as an entry at its corresponding index
  let mut view_handle_with_index = view_handle.to_bytes();
  view_handle_with_index.extend(new_ledger_entry.metablock.get_height().to_le_bytes()); // "to_le" converts to little endian

  let index_entry = DBEntry {
    key: view_handle_with_index.to_bson_binary(),
    value: bson_new_ledger_entry,
    tail: false,
  };

  ledgers
    .insert_one_with_session(&index_entry, None, session)
    .await?;

  // 7. Commit transactions
  commit_with_retry(session).await?;
  Ok(LedgerView {
    view_tail_metablock: metablock,
    ledger_tail_map,
  })
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
    block: Block::from_bytes(entry.block.clone()).expect("failed to deserialize block"),
    metablock: MetaBlock::from_bytes(entry.metablock.clone())
      .expect("failed to deserialized metablock"),
    receipt: Receipt::from_bytes(&entry.receipt),
  };

  Ok(res)
}

const RETRY_SLEEP: u64 = 10; // ms
const WRITE_CONFLICT_CODE: i32 = 112;
const REQUEST_RATE_TOO_HIGH_CODE: i32 = 16500;

#[async_trait]
impl LedgerStore for MongoCosmosLedgerStore {
  async fn create_ledger(
    &self,
    block: &Block,
  ) -> Result<(Handle, MetaBlock, NimbleDigest), LedgerStoreError> {
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
    cond: &NimbleDigest,
  ) -> Result<(MetaBlock, NimbleDigest), LedgerStoreError> {
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

      with_retry!(append_ledger_transaction(handle, block, cond, &mut session, &ledgers).await);
    }
  }

  async fn attach_ledger_receipt(
    &self,
    handle: &Handle,
    metablock: &MetaBlock,
    receipt: &Receipt,
  ) -> Result<(), LedgerStoreError> {
    if !cfg!(feature = "full_ledger") && handle != &self.view_handle {
      panic!("Calling attach_ledger_receipt without support for full ledger");
    }

    let mut handle_with_index = handle.to_bytes();
    handle_with_index.extend(metablock.get_height().to_le_bytes()); // "to_le" converts to little endian

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
        attach_ledger_receipt_transaction(
          &handle_with_index,
          metablock,
          receipt,
          &mut session,
          &ledgers,
        )
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
    handle_with_index.extend(idx.to_le_bytes()); // "to_le" converts to little endian

    loop {
      with_retry!(read_ledger_op(handle_with_index.to_bson_binary(), &ledgers,).await);
    }
  }

  async fn read_view_ledger_tail(&self) -> Result<LedgerEntry, LedgerStoreError> {
    self.read_ledger_tail(&self.view_handle).await
  }

  async fn read_view_ledger_by_index(&self, idx: usize) -> Result<LedgerEntry, LedgerStoreError> {
    self.read_ledger_by_index(&self.view_handle, idx).await
  }

  async fn attach_view_ledger_receipt(
    &self,
    metablock: &MetaBlock,
    receipt: &Receipt,
  ) -> Result<(), LedgerStoreError> {
    self
      .attach_ledger_receipt(&self.view_handle, metablock, receipt)
      .await
  }

  async fn append_view_ledger(&self, block: &Block) -> Result<LedgerView, LedgerStoreError> {
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
        append_view_ledger_transaction(block, &self.view_handle, &mut session, &ledgers,).await
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
