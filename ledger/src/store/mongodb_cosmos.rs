use crate::errors::StorageError;
use crate::store::{LedgerEntry, LedgerStore, LedgerStoreState};
use crate::{Block, CustomSerde, Handle, MetaBlock, NimbleDigest, NimbleHashTrait, Receipt};
use bincode;
use mongodb::bson::doc;
use mongodb::bson::{spec::BinarySubtype, Binary};
use mongodb::error::UNKNOWN_TRANSACTION_COMMIT_RESULT;
use mongodb::options::{Acknowledgment, ReadConcern, TransactionOptions, WriteConcern};
use mongodb::options::{FindOneOptions, FindOptions};
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
  pub aux: Vec<u8>,
  pub receipt: Vec<(Vec<u8>, Vec<u8>)>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct DBEntry {
  #[serde(rename = "_id")]
  key: Binary,
  value: Vec<Binary>, // array of SerializedLedgerEntries (each entry is converted to Binary first)
}

#[derive(Debug)]
pub struct MongoCosmosLedgerStore {
  view_handle: Handle,
  client: Client,
  ledgers: Collection<DBEntry>,
}

impl LedgerStore for MongoCosmosLedgerStore {
  fn new() -> Result<Self, StorageError> {
    let conn_string = std::env::var_os("COSMOS_URL")
      .expect(
        "missing environment variable
            //COSMOS_URL",
      )
      .to_str()
      .expect("failed to get COSMOS_URL")
      .to_owned();

    // Below are the desired name of the db and the name of the collection
    // (they can be anything initially, but afterwards, they need to be the same
    // so you access the same db/collection and recover the stored data)
    let nimble_db_name = "nimble_cosmosdb";
    let ledger_collection = "ledgers";

    let cosmos_client =
      Client::with_uri_str(&conn_string).expect("Connection with cosmosdb failed");
    let ledgers = cosmos_client
      .database(nimble_db_name)
      .collection(ledger_collection);

    // Initialized view ledger's entry
    let entry = SerializedLedgerEntry {
      block: Block::new(&[0; 0]).to_bytes(),
      aux: MetaBlock::new(
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

    let new_entry = DBEntry {
      key: view_handle.to_bson_binary(),
      value: vec![bson_entry],
    };

    ledgers
      .insert_one(&new_entry, None)
      .expect("failed to add view ledger");

    Ok(MongoCosmosLedgerStore {
      view_handle,
      client: cosmos_client,
      ledgers,
    })
  }

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

    // 1. Get the view_ledger's latest entry

    // 1a. Create a projection at the database so we get the latest value without
    // having to fetch en entire array of blobs. "-1" means latest.
    let read_options = FindOneOptions::builder()
      .projection(doc! {
          "value": {"$slice": -1},
      })
      .build();

    // 1b. Find the latest entry in the view ledger
    let view_entry: DBEntry = ledgers
      .find_one_with_session(
        doc! {
            "_id": self.view_handle.to_bson_binary(),
        },
        Some(read_options),
        &mut session,
      )
      .expect("failed to read view ledger")
      .expect("view ledger's entry is None");

    // 2. Recover the contents of the view ledger entry
    let bson_view_entry: &Binary = &view_entry.value[0]; // only entry due to projection and above None check
    let view_entry: SerializedLedgerEntry =
      bincode::deserialize(&bson_view_entry.bytes).expect("failed to deserialized view entry");

    let view_aux = MetaBlock::from_bytes(view_entry.aux).expect("deserialize error");

    // 3. Use view ledger's entry and input block to get information we need for origin of new ledger
    let handle = block.hash();
    let block_hash = block.hash();
    let aux = MetaBlock::new(&view_aux.hash(), &NimbleDigest::default(), &block_hash, 0);

    // 4. Create the ledger entry that we will add to the brand new ledger
    let data_ledger_entry = SerializedLedgerEntry {
      block: block.to_bytes(),
      aux: aux.to_bytes(),
      receipt: Receipt {
        id_sigs: Vec::new(),
      }
      .to_bytes(),
    };

    let bson_data_ledger_entry: Binary = bincode::serialize(&data_ledger_entry)
      .expect("failed to serialize data ledger entry")
      .to_bson_binary();

    // 5. Add new ledger to database
    let new_entry = DBEntry {
      key: handle.to_bson_binary(),
      value: vec![bson_data_ledger_entry],
    };

    ledgers
      .insert_one_with_session(&new_entry, None, &mut session)
      .expect("failed to add new entry to ledgers");

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

    let tail_hash = aux.hash();
    Ok((handle, aux, tail_hash))
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

    // 1a. Create a projection at the database so we get the latest value without
    // having to fetch en entire array of blobs. "-1" means latest.
    let read_options = FindOneOptions::builder()
      .projection(doc! {
          "value": {"$slice": -1},
      })
      .build();

    // 1b. Find the latest entry in the view ledger
    let view_entry: DBEntry = ledgers
      .find_one_with_session(
        doc! {
            "_id": self.view_handle.to_bson_binary(),
        },
        Some(read_options.clone()),
        &mut session,
      )
      .expect("failed to read view ledger")
      .expect("view ledger's entry is None");

    // 2. Recover the contents of the view ledger entry
    let bson_view_entry: &Binary = &view_entry.value[0]; // only entry due to projection and above None check
    let view_entry: SerializedLedgerEntry =
      bincode::deserialize(&bson_view_entry.bytes).expect("failed to deserialize view entry");
    let view_aux = MetaBlock::from_bytes(view_entry.aux).expect("deserialize error");

    // 3. Check to see if the ledgers contain the handle and get last entry
    let last_data_entry: DBEntry = match ledgers
      .find_one_with_session(
        doc! {
            "_id": handle.to_bson_binary(),
        },
        Some(read_options),
        &mut session,
      )
      .expect("failed to read data ledger")
    {
      None => {
        return Err(StorageError::KeyDoesNotExist);
      },
      Some(s) => s,
    };

    // 2. Recover the contents of the ledger entry and check condition
    let bson_last_data_entry: &Binary = &last_data_entry.value[0]; // only entry due to projection and above None check
    let last_data_entry: SerializedLedgerEntry = bincode::deserialize(&bson_last_data_entry.bytes)
      .expect("failed to deserialize last data entry");
    let last_data_aux = MetaBlock::from_bytes(last_data_entry.aux).expect("deserialize error");

    if *cond != NimbleDigest::default() && *cond != last_data_aux.hash() {
      return Err(StorageError::IncorrectConditionalData);
    }

    // 3. Construct the new entry we are going to append to data ledger
    let aux = MetaBlock::new(
      &view_aux.hash(),
      &last_data_aux.hash(),
      &block.hash(),
      last_data_aux.get_height() + 1,
    );

    let new_ledger_entry = SerializedLedgerEntry {
      block: block.to_bytes(),
      aux: aux.to_bytes(),
      receipt: Receipt {
        id_sigs: Vec::new(),
      }
      .to_bytes(),
    };

    let bson_new_ledger_entry: Binary = bincode::serialize(&new_ledger_entry)
      .expect("failed to serialized new ledger entry")
      .to_bson_binary();

    let tail_hash = aux.hash();

    // 4. Pushes the value new_ledger_entry to the end of the ledger (array) named with handle.
    ledgers
      .update_one_with_session(
        doc! {
           "_id": handle.to_bson_binary(),
        },
        doc! {
            "$push": { "value": bson_new_ledger_entry }
        },
        None,
        &mut session,
      )
      .expect("failed to append element");

    // 5. Commit transactions
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

    Ok((aux, tail_hash))
  }

  fn attach_ledger_receipt(
    &self,
    handle: &Handle,
    aux: &MetaBlock,
    receipt: &Receipt,
  ) -> Result<(), StorageError> {
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

    // 1a. Create a projection at the database so we get the value at idx without
    // having to fetch en entire array of blobs. The notation "$slice": [idx, 1] means 1
    // element after skipping the first idx elements in the array.

    let read_options = FindOneOptions::builder()
      .projection(doc! {
          "value": {"$slice": [aux.get_height() as u32, 1]},
      })
      .build();

    // 1b. Find the appropriate entry in the ledger
    let ledger_entry: DBEntry = match ledgers
      .find_one_with_session(
        doc! {
            "_id": handle.to_bson_binary(),
        },
        Some(read_options),
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
    let read_bson_ledger_entry: &Binary = &ledger_entry.value[0]; // only entry due to projection and check
    let mut ledger_entry: SerializedLedgerEntry =
      bincode::deserialize(&read_bson_ledger_entry.bytes)
        .expect("failed to deserialize ledger entry");

    // update receipt
    ledger_entry.receipt = receipt.to_bytes();

    // re-serialize into bson binary
    let write_bson_ledger_entry: Binary = bincode::serialize(&ledger_entry)
      .expect("failed to serialized ledger entry")
      .to_bson_binary();

    // 3. Edit the value at index aux.get_height() in the ledger (array) named with handle.
    let val = format!("value.{}", aux.get_height());

    ledgers
      .update_one_with_session(
        doc! {
           "_id": handle.to_bson_binary(),
        },
        doc! {
            "$set": { val: write_bson_ledger_entry }
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
  }

  fn read_ledger_tail(&self, handle: &Handle) -> Result<LedgerEntry, StorageError> {
    let ledgers = self.ledgers.clone();

    // Create a projection at the database so we get the latest value without
    // having to fetch en entire array of blobs. "-1" means latest.
    let read_options = FindOneOptions::builder()
      .projection(doc! {
          "value": {"$slice": -1},
      })
      .build();

    // Find the latest value of view associated with the provided key.
    // XXX: not in transaction, see if this is OK. Couldn't find in any documentation
    let ledger_entry = match ledgers
      .find_one(
        doc! {
            "_id": handle.to_bson_binary(),
        },
        Some(read_options),
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
    let bson_entry: &Binary = &ledger_entry.value[0]; // only entry due to projection and check
    let entry: SerializedLedgerEntry =
      bincode::deserialize(&bson_entry.bytes).expect("failed to deserialize entry");

    let res = LedgerEntry {
      block: Block::from_bytes(entry.block.clone()).expect("failed to deserialize block"),
      aux: MetaBlock::from_bytes(entry.aux.clone()).expect("failed to deserialized aux"),
      receipt: Receipt::from_bytes(&entry.receipt),
    };

    Ok(res)
  }

  fn read_ledger_by_index(&self, handle: &Handle, idx: usize) -> Result<LedgerEntry, StorageError> {
    let ledgers = self.ledgers.clone();

    // Create a projection at the database so we get the value at idx without
    // having to fetch en entire array of blobs. The notation [idx, 1] means 1
    // element after skipping the first idx elements in the array.
    let read_options = FindOneOptions::builder()
      .projection(doc! {
          "value": {"$slice": [idx as u32, 1]},
      })
      .build();

    // Find the latest value of view associated with the provided key.
    // XXX: not in transaction, see if this is OK. Couldn't find in any documentation
    let ledger_entry = match ledgers
      .find_one(
        doc! {
            "_id": handle.to_bson_binary(),
        },
        Some(read_options),
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
    let bson_entry: &Binary = &ledger_entry.value[0]; // only entry due to projection and check
    let entry: SerializedLedgerEntry =
      bincode::deserialize(&bson_entry.bytes).expect("failed to deserialize entry");

    let res = LedgerEntry {
      block: Block::from_bytes(entry.block.clone()).expect("failed to deserialize block"),
      aux: MetaBlock::from_bytes(entry.aux.clone()).expect("failed to deserialized aux"),
      receipt: Receipt::from_bytes(&entry.receipt),
    };

    Ok(res)
  }

  fn read_view_ledger_tail(&self) -> Result<LedgerEntry, StorageError> {
    self.read_ledger_tail(&self.view_handle)
  }

  fn read_view_ledger_by_index(&self, idx: usize) -> Result<LedgerEntry, StorageError> {
    self.read_ledger_by_index(&self.view_handle, idx)
  }

  fn attach_view_ledger_receipt(
    &self,
    aux: &MetaBlock,
    receipt: &Receipt,
  ) -> Result<(), StorageError> {
    self.attach_ledger_receipt(&self.view_handle, aux, receipt)
  }

  fn append_view_ledger(&self, block: &Block) -> Result<(MetaBlock, NimbleDigest), StorageError> {
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

    // 1a. Create a projection at the database so we get the latest value without
    // having to fetch en entire array of blobs for each ledger. "-1" means latest.
    let read_options = FindOptions::builder()
      .projection(doc! {
          "value": {"$slice": -1},
      })
      .build();

    // 1b. Probe cosmosdb for all ledgers
    let mut all_ledgers: SessionCursor<DBEntry> = ledgers
      .find_with_session(doc! {}, Some(read_options), &mut session)
      .expect("failed to read all ledgers");

    // Initial LedgerStoreState
    let mut ledger_tail_map: HashMap<Vec<u8>, (Vec<u8>, usize)> = HashMap::new();
    let mut view_ledger_tail: (Vec<u8>, usize) = (vec![], 0);

    // 2. Iterate through all non_view ledgers to update LedgerStoreState
    for res_ledger_entry in all_ledgers.iter(&mut session) {
      let ledger_entry = res_ledger_entry.expect("failed to read one of the ledger entries");

      // If ledger_entry is the view ledger
      if ledger_entry.key.bytes == self.view_handle.to_bytes() {
        // get the tail of view ledger
        let entry_val: SerializedLedgerEntry = {
          let bson_entry: &Binary = &ledger_entry.value[0]; // only entry due to projection
          bincode::deserialize(&bson_entry.bytes).expect("failed to deserialize entry")
        };

        view_ledger_tail = {
          let view_ledger_aux =
            MetaBlock::from_bytes(entry_val.aux.clone()).expect("failed to deserialize ledger aux");
          (
            view_ledger_aux.hash().to_bytes(),
            view_ledger_aux.get_height(),
          )
        };
      } else {
        // ledger_entry is not view ledger
        let ledger_handle = ledger_entry.key.bytes.clone();

        // get the tail of ledger
        let entry_val: SerializedLedgerEntry = {
          let bson_entry: &Binary = &ledger_entry.value[0]; // only entry due to projection
          bincode::deserialize(&bson_entry.bytes).expect("failed to deserialize entry")
        };

        let ledger_aux =
          MetaBlock::from_bytes(entry_val.aux.clone()).expect("failed to deserialize ledger aux");

        let res = ledger_tail_map.insert(
          ledger_handle,
          (
            ledger_aux.hash().to_bytes().clone(),
            ledger_aux.get_height(),
          ),
        );
        assert!(res.is_none()); // since the key (ledger_handle) shouldn't exist.
      }
    }

    // 3. Compute state hash
    let state_hash = if ledger_tail_map.is_empty() || view_ledger_tail.1 == 1 {
      NimbleDigest::default()
    } else {
      let ledger_store_state = LedgerStoreState {
        ledger_tail_map: ledger_tail_map.clone(),
        view_ledger_tail: view_ledger_tail.clone(),
      };

      let serialized_ledger_store_state = bincode::serialize(&ledger_store_state).unwrap();
      NimbleDigest::digest(&serialized_ledger_store_state)
    };

    // 4. Compute new ledger entry
    let new_ledger_entry = LedgerEntry {
      block: block.clone(),
      aux: MetaBlock::new(
        &state_hash,
        &if view_ledger_tail.1 == 1 {
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

    let tail_hash = new_ledger_entry.aux.hash();
    let aux = new_ledger_entry.aux.clone();

    // 5. Serialize new ledger entry
    let serialized_new_ledger_entry = SerializedLedgerEntry {
      block: new_ledger_entry.block.to_bytes(),
      aux: new_ledger_entry.aux.to_bytes(),
      receipt: new_ledger_entry.receipt.to_bytes(),
    };

    let bson_new_ledger_entry: Binary = bincode::serialize(&serialized_new_ledger_entry)
      .expect("failed to serialized new ledger entry")
      .to_bson_binary();

    // 4. Pushes the value new_ledger_entry to the end of the ledger (array) named with handle.
    ledgers
      .update_one_with_session(
        doc! {
           "_id": self.view_handle.to_bson_binary(),
        },
        doc! {
            "$push": { "value": bson_new_ledger_entry }
        },
        None,
        &mut session,
      )
      .expect("failed to append element");

    // 5. Commit transactions
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

    Ok((aux, tail_hash))
  }

  #[cfg(test)]
  fn reset_store(&self) -> Result<(), StorageError> {
    self
      .ledgers
      .delete_many(doc! {}, None)
      .expect("failed to delete ledgers");

    Ok(())
  }
}
