use super::{Block, Handle, MetaBlock, NimbleDigest, NimbleHashTrait, Receipt};
use crate::errors::StorageError;

pub mod in_memory;
pub mod mongodb_cosmos;

#[derive(Debug, Default, Clone)]
pub struct LedgerEntry {
  pub block: Block,
  pub aux: MetaBlock,
  pub receipt: Receipt,
}

pub trait LedgerStore {
  fn new() -> Result<Self, StorageError>
  where
    Self: Sized;
  fn create_ledger(&self, block: &Block)
    -> Result<(Handle, MetaBlock, NimbleDigest), StorageError>;
  fn append_ledger(
    // TODO: should self be mutable?
    &self,
    handle: &Handle,
    block: &Block,
    cond: &NimbleDigest,
  ) -> Result<(MetaBlock, NimbleDigest), StorageError>;
  fn attach_ledger_receipt(
    &self,
    handle: &Handle,
    aux: &MetaBlock,
    receipt: &Receipt,
  ) -> Result<(), StorageError>;
  fn read_ledger_tail(&self, handle: &Handle) -> Result<LedgerEntry, StorageError>;
  fn read_ledger_by_index(&self, handle: &Handle, idx: usize) -> Result<LedgerEntry, StorageError>;
  fn append_view_ledger(&self, block: &Block) -> Result<(MetaBlock, NimbleDigest), StorageError>;
  fn attach_view_ledger_receipt(
    &self,
    aux: &MetaBlock,
    receipt: &Receipt,
  ) -> Result<(), StorageError>;
  fn read_view_ledger_tail(&self) -> Result<LedgerEntry, StorageError>;
  fn read_view_ledger_by_index(&self, idx: usize) -> Result<LedgerEntry, StorageError>;

  #[cfg(test)]
  fn reset_store(&self) -> Result<(), StorageError>; // only used for testing
}

#[cfg(test)]
mod tests {
  use crate::store::in_memory::InMemoryLedgerStore;
  use crate::store::mongodb_cosmos::MongoCosmosLedgerStore;
  use crate::store::LedgerStore;
  use crate::Block;
  use crate::NimbleDigest;

  pub fn check_store_creation_and_operations(state: &dyn LedgerStore) {
    let initial_value: Vec<u8> = vec![
      1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
      1, 2,
    ];

    let block = Block::new(&initial_value);

    let (handle, _, _) = state.create_ledger(&block).expect("failed create ledger");

    let res = state.read_ledger_tail(&handle);
    assert!(res.is_ok());

    let current_data = res.unwrap();
    assert_eq!(current_data.block.block, initial_value);

    let new_value_appended: Vec<u8> = vec![
      2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1,
      2, 1,
    ];

    let new_block = Block::new(&new_value_appended);

    let res = state.append_ledger(&handle, &new_block, &NimbleDigest::default());
    assert!(res.is_ok());

    let res = state.read_ledger_tail(&handle);
    assert!(res.is_ok());

    let current_tail = res.unwrap();
    assert_eq!(current_tail.block.block, new_value_appended);

    let res = state.read_ledger_by_index(&handle, 0);
    assert!(res.is_ok());

    let data_at_index = res.unwrap();
    assert_eq!(data_at_index.block.block, initial_value);

    let res = state.reset_store();
    assert!(res.is_ok());
  }

  #[test]
  pub fn check_in_memory_store() {
    let state = InMemoryLedgerStore::new().unwrap();
    check_store_creation_and_operations(&state);
  }

  #[test]
  pub fn check_mongo_cosmos_store() {
    if std::env::var_os("COSMOS_URL").is_none() {
      // The right env variable is not available so let's skip tests
      return;
    }

    let state = MongoCosmosLedgerStore::new().unwrap();
    check_store_creation_and_operations(&state);
  }
}
