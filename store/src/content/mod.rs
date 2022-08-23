use crate::errors::StorageError;
use async_trait::async_trait;
use ledger::Handle;

pub mod in_memory;

#[async_trait]
pub trait ContentStore {
  async fn put(&self, data: &[u8]) -> Result<Handle, StorageError>;
  async fn get(&self, handle: &Handle) -> Result<Vec<u8>, StorageError>;
  async fn reset_store(&self) -> Result<(), StorageError>; // only used for testing
}
