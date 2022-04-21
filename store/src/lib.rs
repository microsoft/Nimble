use async_trait::async_trait;
use ledger::{Block, Handle, NimbleDigest, Receipt};

pub mod azure_pageblob;
mod errors;
pub mod in_memory;
pub mod mongodb_cosmos;

use crate::errors::LedgerStoreError;

#[derive(Debug, Default, Clone)]
pub struct LedgerEntry {
  pub block: Block,
  receipt: Receipt,
}

impl LedgerEntry {
  pub fn new(block: Block, receipt: Receipt) -> Self {
    Self { block, receipt }
  }

  pub fn get_block(&self) -> &Block {
    &self.block
  }

  pub fn get_receipt(&self) -> &Receipt {
    &self.receipt
  }
}

#[async_trait]
pub trait LedgerStore {
  async fn create_ledger(
    &self,
    handle: &NimbleDigest,
    genesis_block: Block,
  ) -> Result<(), LedgerStoreError>;
  async fn append_ledger(
    &self,
    handle: &Handle,
    block: &Block,
    expected_height: Option<usize>,
  ) -> Result<usize, LedgerStoreError>;
  async fn attach_ledger_receipt(
    &self,
    handle: &Handle,
    receipt: &Receipt,
  ) -> Result<(), LedgerStoreError>;
  async fn read_ledger_tail(&self, handle: &Handle) -> Result<LedgerEntry, LedgerStoreError>;
  async fn read_ledger_by_index(
    &self,
    handle: &Handle,
    idx: usize,
  ) -> Result<LedgerEntry, LedgerStoreError>;
  async fn append_view_ledger(
    &self,
    block: &Block,
    expected_height: Option<usize>,
  ) -> Result<usize, LedgerStoreError>;
  async fn attach_view_ledger_receipt(&self, receipt: &Receipt) -> Result<(), LedgerStoreError>;
  async fn read_view_ledger_tail(&self) -> Result<LedgerEntry, LedgerStoreError>;
  async fn read_view_ledger_by_index(&self, idx: usize) -> Result<LedgerEntry, LedgerStoreError>;

  async fn reset_store(&self) -> Result<(), LedgerStoreError>; // only used for testing
}

#[cfg(test)]
mod tests {
  use crate::{
    azure_pageblob::PageBlobLedgerStore, in_memory::InMemoryLedgerStore,
    mongodb_cosmos::MongoCosmosLedgerStore, LedgerStore,
  };
  use ledger::{Block, CustomSerde, NimbleHashTrait};
  use std::collections::HashMap;

  pub async fn check_store_creation_and_operations(state: &dyn LedgerStore) {
    let initial_value: Vec<u8> = vec![
      1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
      1, 2,
    ];

    let genesis_block = Block::new(&initial_value);
    let handle = genesis_block.hash();

    state
      .create_ledger(&handle, genesis_block)
      .await
      .expect("failed create ledger");

    let res = state.read_ledger_tail(&handle).await;
    assert!(res.is_ok());

    let current_data = res.unwrap();
    assert_eq!(current_data.block.to_bytes(), initial_value);

    let new_value_appended: Vec<u8> = vec![
      2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1,
      2, 1,
    ];

    let new_block = Block::new(&new_value_appended);

    let res = state.append_ledger(&handle, &new_block, None).await;
    assert!(res.is_ok());

    let res = state.read_ledger_tail(&handle).await;
    assert!(res.is_ok());

    let current_tail = res.unwrap();
    assert_eq!(current_tail.block.to_bytes(), new_value_appended);

    let res = state.read_ledger_by_index(&handle, 0).await;
    assert!(res.is_ok());

    let data_at_index = res.unwrap();
    assert_eq!(data_at_index.block.to_bytes(), initial_value);

    let res = state.reset_store().await;
    assert!(res.is_ok());
  }

  #[tokio::test]
  pub async fn check_in_memory_store() {
    let state = InMemoryLedgerStore::new();
    check_store_creation_and_operations(&state).await;
  }

  #[tokio::test]
  pub async fn check_mongo_cosmos_store() {
    if std::env::var_os("COSMOS_URL").is_none() {
      // The right env variable is not available so let's skip tests
      return;
    }
    let mut args = HashMap::<String, String>::new();
    args.insert(
      String::from("COSMOS_URL"),
      std::env::var_os("COSMOS_URL")
        .unwrap()
        .into_string()
        .unwrap(),
    );

    let state = MongoCosmosLedgerStore::new(&args).await.unwrap();
    check_store_creation_and_operations(&state).await;
  }

  #[tokio::test]
  pub async fn check_azure_pageblob_store() {
    if std::env::var_os("STORAGE_ACCOUNT").is_none()
      || std::env::var_os("STORAGE_MASTER_KEY").is_none()
    {
      // The right env variables are not available so let's skip tests
      return;
    }

    let mut args = HashMap::<String, String>::new();
    args.insert(
      String::from("STORAGE_ACCOUNT"),
      std::env::var_os("STORAGE_ACCOUNT")
        .unwrap()
        .into_string()
        .unwrap(),
    );

    args.insert(
      String::from("STORAGE_MASTER_KEY"),
      std::env::var_os("STORAGE_MASTER_KEY")
        .unwrap()
        .into_string()
        .unwrap(),
    );

    let state = PageBlobLedgerStore::new(&args).await.unwrap();
    check_store_creation_and_operations(&state).await;
  }
}
