use crate::errors::StorageError;
use crate::store::{LedgerEntry, LedgerStore, LedgerView};
use crate::{Block, CustomSerde, Handle, MetaBlock, NimbleDigest, NimbleHashTrait, Receipt};
use bincode;
use itertools::Itertools;
use mongodb::bson::doc;
use mongodb::bson::{spec::BinarySubtype, Binary};
use mongodb::error::UNKNOWN_TRANSACTION_COMMIT_RESULT;
use mongodb::options::{Acknowledgment, ReadConcern, TransactionOptions, WriteConcern};
use mongodb::sync::{Client, Collection, SessionCursor};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;

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
  pub metablock: Vec<u8>,
  pub receipt: Vec<(Vec<u8>, Vec<u8>)>,
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
  ledgers: Collection<DBEntry>,
}

impl MongoCosmosLedgerStore {
  pub fn new(args: &HashMap<String, String>) -> Result<Self, StorageError> {
    if !args.contains_key("COSMOS_URL") {
      return Err(StorageError::MissingArguments);
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

    let cosmos_client =
      Client::with_uri_str(&conn_string).expect("Connection with cosmosdb failed");
    let ledgers = cosmos_client
      .database(&nimble_db_name)
      .collection(ledger_collection);

    // Initialized view ledger's entry
    let entry = SerializedLedgerEntry {
      block: Block::new(&[0; 0]).to_bytes(),
      metablock: MetaBlock::new(
        &NimbleDigest::default(),
        &NimbleDigest::default(),
        &NimbleDigest::default(),
        0,
      )
      .to_bytes(),
      receipt: Receipt {
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
      .insert_many(&vec![first_entry, tail_entry], None)
      .expect("failed to add view ledger");

    Ok(MongoCosmosLedgerStore {
      view_handle,
      client: cosmos_client,
      ledgers,
    })
  }
}

impl LedgerStore for MongoCosmosLedgerStore {
  fn create_ledger(
    &self,
    block: &Block,
  ) -> Result<(Handle, MetaBlock, NimbleDigest), StorageError> {
    let client = self.client.clone();
    let ledgers = self.ledgers.clone();

    // transaction session
    let mut session = client
      .start_session(None)
      .expect("unable to get client session");

    // transaction properties: below is for serializability
    let options = TransactionOptions::builder()
      .read_concern(ReadConcern::majority())
      .write_concern(WriteConcern::builder().w(Acknowledgment::Majority).build())
      .build();

    session
      .start_transaction(options)
      .expect("unable to start transaction");

    // 1. Get the view_ledger's latest entry (which is located at handle self.view_handle)

    // 1b. Find the latest entry in the view ledger
    let view_entry: DBEntry = ledgers
      .find_one_with_session(
        doc! {
            "_id": self.view_handle.to_bson_binary(),
        },
        None,
        &mut session,
      )
      .expect("failed to read view ledger")
      .expect("view ledger's entry is None");

    // 2. Recover the contents of the view ledgevaluery
    let bson_view_entry: &Binary = &view_entry.value;
    let view_entry: SerializedLedgerEntry =
      bincode::deserialize(&bson_view_entry.bytes).expect("failed to deserialized view entry");

    let view_metablock = MetaBlock::from_bytes(view_entry.metablock).expect("deserialize error");

    // 3. Use view ledger's entry and input block to get information we need for origin of new ledger
    let handle = block.hash();
    let block_hash = block.hash();
    let metablock = MetaBlock::new(
      &view_metablock.hash(),
      &NimbleDigest::default(),
      &block_hash,
      0,
    );

    // 4. Create the ledger entry that we will add to the brand new ledger
    let data_ledger_entry = SerializedLedgerEntry {
      block: block.to_bytes(),
      metablock: metablock.to_bytes(),
      receipt: Receipt {
        id_sigs: Vec::new(),
      }
      .to_bytes(),
    };

    let bson_data_ledger_entry: Binary = bincode::serialize(&data_ledger_entry)
      .expect("failed to serialize data ledger entry")
      .to_bson_binary();

    // 5. Add new ledger tail to database under its handle
    let tail_entry = DBEntry {
      key: handle.to_bson_binary(),
      value: bson_data_ledger_entry.clone(),
      tail: true,
    };

    // 6. If we are keeping the full state of the ledger (including intermediaries)
    if cfg!(feature = "full_ledger") {
      let mut handle_with_index = handle.to_bytes();
      handle_with_index.extend(0usize.to_le_bytes()); // to_le is little endian

      let new_entry = DBEntry {
        key: handle_with_index.to_bson_binary(), // handle = handle || idx (which is 0)
        value: bson_data_ledger_entry,
        tail: false,
      };

      ledgers
        .insert_many_with_session(&vec![tail_entry, new_entry], None, &mut session)
        .expect("failed to add new entry to ledgers");
    } else {
      ledgers
        .insert_one_with_session(&tail_entry, None, &mut session)
        .expect("failed to add new entry to ledgers");
    };

    // 6. Commit transactions
    loop {
      let result = session.commit_transaction();

      if let Err(ref error) = result {
        println!("Error processing transaction: {:?}. Retrying.", error);
        if error.contains_label(UNKNOWN_TRANSACTION_COMMIT_RESULT) {
          continue;
        }
      }
      result.expect("Transaction failed to commit");
      break;
    }

    let tail_hash = metablock.hash();
    Ok((handle, metablock, tail_hash))
  }

  fn append_ledger(
    &self,
    handle: &Handle,
    block: &Block,
    cond: &NimbleDigest,
  ) -> Result<(MetaBlock, NimbleDigest), StorageError> {
    let client = self.client.clone();
    let ledgers = self.ledgers.clone();

    // transaction session
    let mut session = client
      .start_session(None)
      .expect("unable to get client session");

    // transaction properties: below is for serializability
    let options = TransactionOptions::builder()
      .read_concern(ReadConcern::majority())
      .write_concern(WriteConcern::builder().w(Acknowledgment::Majority).build())
      .build();

    session
      .start_transaction(options)
      .expect("unable to start transaction");

    // 1. Get the view_ledger's latest entry

    // 1b. Find the latest entry in the view ledger
    let view_entry: DBEntry = ledgers
      .find_one_with_session(
        doc! {
            "_id": self.view_handle.to_bson_binary(),
        },
        None,
        &mut session,
      )
      .expect("failed to read view ledger")
      .expect("view ledger's entry is None");

    // 2. Recover the contents of the view ledger entry
    let bson_view_entry: &Binary = &view_entry.value; // only entry due to projection and above None check
    let view_entry: SerializedLedgerEntry =
      bincode::deserialize(&bson_view_entry.bytes).expect("failed to deserialize view entry");
    let view_metablock = MetaBlock::from_bytes(view_entry.metablock).expect("deserialize error");

    // 3. Check to see if the ledgers contain the handle and get last entry
    let last_data_entry: DBEntry = match ledgers
      .find_one_with_session(
        doc! {
            "_id": handle.to_bson_binary(),
        },
        None,
        &mut session,
      )
      .expect("failed to read data ledger")
    {
      None => {
        return Err(StorageError::KeyDoesNotExist);
      },
      Some(s) => s,
    };

    // 4. Recover the contents of the ledger entry and check condition
    let bson_last_data_entry: &Binary = &last_data_entry.value;
    let last_data_entry: SerializedLedgerEntry = bincode::deserialize(&bson_last_data_entry.bytes)
      .expect("failed to deserialize last data entry");
    let last_data_metablock =
      MetaBlock::from_bytes(last_data_entry.metablock).expect("deserialize error");

    if *cond != NimbleDigest::default() && *cond != last_data_metablock.hash() {
      return Err(StorageError::IncorrectConditionalData);
    }

    // 5. Construct the new entry we are going to append to data ledger
    let metablock = MetaBlock::new(
      &view_metablock.hash(),
      &last_data_metablock.hash(),
      &block.hash(),
      last_data_metablock.get_height() + 1,
    );

    let new_ledger_entry = SerializedLedgerEntry {
      block: block.to_bytes(),
      metablock: metablock.to_bytes(),
      receipt: Receipt {
        id_sigs: Vec::new(),
      }
      .to_bytes(),
    };

    let bson_new_ledger_entry: Binary = bincode::serialize(&new_ledger_entry)
      .expect("failed to serialized new ledger entry")
      .to_bson_binary();

    let tail_hash = metablock.hash();

    // 6. Pushes the value new_ledger_entry to the end of the ledger (array) named with handle.
    ledgers
      .update_one_with_session(
        doc! {
           "_id": handle.to_bson_binary(),
        },
        doc! {
            "$set": {"value": bson_new_ledger_entry.clone()}
        },
        None,
        &mut session,
      )
      .expect("failed to append element");

    // 6b. If we want to keep intermediate state, then insert it under appropriate index
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
        .insert_one_with_session(new_entry, None, &mut session)
        .expect("failed to insert element");
    }

    // 7. Commit transactions
    loop {
      let result = session.commit_transaction();

      if let Err(ref error) = result {
        println!("Error processing transaction: {:?}. Retrying.", error);
        if error.contains_label(UNKNOWN_TRANSACTION_COMMIT_RESULT) {
          continue;
        }
      }
      result.expect("Transaction failed to commit");
      break;
    }

    Ok((metablock, tail_hash))
  }

  fn attach_ledger_receipt(
    &self,
    handle: &Handle,
    metablock: &MetaBlock,
    receipt: &Receipt,
  ) -> Result<(), StorageError> {
    if cfg!(feature = "full_ledger") || handle == &self.view_handle {
      let mut handle_with_index = handle.to_bytes();
      handle_with_index.extend(metablock.get_height().to_le_bytes()); // "to_le" converts to little endian

      let client = self.client.clone();
      let ledgers = self.ledgers.clone();

      // transaction session
      let mut session = client
        .start_session(None)
        .expect("unable to get client session");

      // transaction properties: below is for serializability
      let options = TransactionOptions::builder()
        .read_concern(ReadConcern::majority())
        .write_concern(WriteConcern::builder().w(Acknowledgment::Majority).build())
        .build();

      session
        .start_transaction(options)
        .expect("unable to start transaction");

      // 1. Get the ledger's latest entry

      // 1a. Find the appropriate entry in the ledger if the ledger is full
      let ledger_entry: DBEntry = match ledgers
        .find_one_with_session(
          doc! {
              "_id": handle_with_index.to_bson_binary(),
          },
          None,
          &mut session,
        )
        .expect("failed to read data ledger")
      {
        None => {
          return Err(StorageError::KeyDoesNotExist);
        },
        //XXX: also another possible error is InvalidIndex. See if there is a way to
        //dissambiguate
        Some(s) => s,
      };

      // 2. Recover the contents of the ledger entry
      let read_bson_ledger_entry: &Binary = &ledger_entry.value; // only entry due to unique handles
      let mut ledger_entry: SerializedLedgerEntry =
        bincode::deserialize(&read_bson_ledger_entry.bytes)
          .expect("failed to deserialize ledger entry");

      // 3. Assert the fetched block is the right one
      let ledger_metablock = MetaBlock::from_bytes(ledger_entry.metablock.clone())
        .expect("failed to deserailize metablock");
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
             "_id": handle_with_index.to_bson_binary(),
          },
          doc! {
              "$set": {"value": write_bson_ledger_entry},
          },
          None,
          &mut session,
        )
        .expect("failed to update receipt");

      // 4. Commit transactions
      loop {
        let result = session.commit_transaction();

        if let Err(ref error) = result {
          println!("Error processing transaction: {:?}. Retrying.", error);
          if error.contains_label(UNKNOWN_TRANSACTION_COMMIT_RESULT) {
            continue;
          }
        }
        result.expect("Transaction failed to commit");
        break;
      }

      Ok(())
    } else {
      panic!("Calling attach_ledger_receipt without support for full ledger");
    }
  }

  fn read_ledger_tail(&self, handle: &Handle) -> Result<LedgerEntry, StorageError> {
    let ledgers = self.ledgers.clone();

    // Find the latest value of view associated with the provided key.
    let ledger_entry = match ledgers
      .find_one(
        doc! {
            "_id": handle.to_bson_binary(),
        },
        None,
      )
      .expect("failed to read ledger")
    {
      None => {
        return Err(StorageError::KeyDoesNotExist);
      },
      //XXX: also another possible error is InvalidIndex. See if there is a way to
      //dissambiguate
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

  fn read_ledger_by_index(&self, handle: &Handle, idx: usize) -> Result<LedgerEntry, StorageError> {
    if cfg!(feature = "full_ledger") || handle == &self.view_handle {
      let ledgers = self.ledgers.clone();

      let mut handle_with_index = handle.to_bytes();
      handle_with_index.extend(idx.to_le_bytes()); // "to_le" converts to little endian

      // Find the latest value of view associated with the provided key.
      let ledger_entry = match ledgers
        .find_one(
          doc! {
              "_id": handle_with_index.to_bson_binary(),
          },
          None,
        )
        .expect("failed to read ledger")
      {
        None => {
          return Err(StorageError::KeyDoesNotExist);
        },
        //XXX: also another possible error is InvalidIndex. See if there is a way to
        //dissambiguate
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
    } else {
      panic!("Calling read_ledger_by_index without support for full ledger");
    }
  }

  fn read_view_ledger_tail(&self) -> Result<LedgerEntry, StorageError> {
    self.read_ledger_tail(&self.view_handle)
  }

  fn read_view_ledger_by_index(&self, idx: usize) -> Result<LedgerEntry, StorageError> {
    self.read_ledger_by_index(&self.view_handle, idx)
  }

  fn attach_view_ledger_receipt(
    &self,
    metablock: &MetaBlock,
    receipt: &Receipt,
  ) -> Result<(), StorageError> {
    self.attach_ledger_receipt(&self.view_handle, metablock, receipt)
  }

  fn append_view_ledger(&self, block: &Block) -> Result<LedgerView, StorageError> {
    let client = self.client.clone();
    let ledgers = self.ledgers.clone();

    // transaction session
    let mut session = client
      .start_session(None)
      .expect("unable to get client session");

    // transaction properties: below is for serializability
    let options = TransactionOptions::builder()
      .read_concern(ReadConcern::majority())
      .write_concern(WriteConcern::builder().w(Acknowledgment::Majority).build())
      .build();

    session
      .start_transaction(options)
      .expect("unable to start transaction");

    // 1. Read the last value of all ledgers (including view ledger)

    // Probe cosmosdb for all ledgers that are tail
    let mut all_ledgers: SessionCursor<DBEntry> = ledgers
      .find_with_session(
        doc! {
            "tail": true,
        },
        None,
        &mut session,
      )
      .expect("failed to read all ledgers");

    // Initial LedgerStoreState
    let mut ledger_tail_map: HashMap<NimbleDigest, (NimbleDigest, usize)> = HashMap::new();
    let mut view_ledger_tail: (Vec<u8>, usize) = (vec![], 0);

    // 2. Iterate through all non_view ledgers to update LedgerStoreState
    for res_ledger_entry in all_ledgers.iter(&mut session) {
      let ledger_entry = res_ledger_entry.expect("failed to read one of the ledger entries");

      // If ledger_entry is the view ledger
      if ledger_entry.key.bytes == self.view_handle.to_bytes() {
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

    // 3. Compute state hash
    let state_hash = if ledger_tail_map.is_empty() || view_ledger_tail.1 == 0 {
      NimbleDigest::default()
    } else {
      let mut serialized_state = Vec::new();
      for handle in ledger_tail_map.keys().sorted() {
        let (tail, height) = ledger_tail_map.get(handle).unwrap();
        serialized_state.extend_from_slice(&handle.to_bytes());
        serialized_state.extend_from_slice(&tail.to_bytes());
        serialized_state.extend_from_slice(&height.to_le_bytes());
      }
      NimbleDigest::digest(&serialized_state)
    };

    // 4. Compute new ledger entry
    let new_ledger_entry = LedgerEntry {
      block: block.clone(),
      metablock: MetaBlock::new(
        &state_hash,
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
      },
    };

    let tail_hash = new_ledger_entry.metablock.hash();
    let metablock = new_ledger_entry.metablock.clone();

    // 5. Serialize new ledger entry
    let serialized_new_ledger_entry = SerializedLedgerEntry {
      block: new_ledger_entry.block.to_bytes(),
      metablock: new_ledger_entry.metablock.to_bytes(),
      receipt: new_ledger_entry.receipt.to_bytes(),
    };

    let bson_new_ledger_entry: Binary = bincode::serialize(&serialized_new_ledger_entry)
      .expect("failed to serialized new ledger entry")
      .to_bson_binary();

    // 4. Updates the value new_ledger_entry to the tail named with handle.
    ledgers
      .update_one_with_session(
        doc! {
           "_id": self.view_handle.to_bson_binary(),
        },
        doc! {
            "$set": {"value": bson_new_ledger_entry.clone()},
        },
        None,
        &mut session,
      )
      .expect("failed to append element");

    // 5. Also stores new_ledger_entry as an entry at its corresponding index
    let mut view_handle_with_index = self.view_handle.to_bytes();
    view_handle_with_index.extend(new_ledger_entry.metablock.get_height().to_le_bytes()); // "to_le" converts to little endian

    let index_entry = DBEntry {
      key: view_handle_with_index.to_bson_binary(),
      value: bson_new_ledger_entry,
      tail: false,
    };

    ledgers
      .insert_one_with_session(&index_entry, None, &mut session)
      .expect("failed to add view ledger");

    // 6. Commit transactions
    loop {
      let result = session.commit_transaction();

      if let Err(ref error) = result {
        println!("Error processing transaction: {:?}. Retrying.", error);
        if error.contains_label(UNKNOWN_TRANSACTION_COMMIT_RESULT) {
          continue;
        }
      }
      result.expect("Transaction failed to commit");
      break;
    }

    Ok(LedgerView {
      view_tail_metablock: metablock,
      view_tail_hash: tail_hash,
      ledger_tail_map,
    })
  }

  fn reset_store(&self) -> Result<(), StorageError> {
    self
      .ledgers
      .delete_many(doc! {}, None)
      .expect("failed to delete ledgers");

    Ok(())
  }
}
