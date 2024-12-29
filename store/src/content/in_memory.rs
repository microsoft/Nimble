use super::Handle;
use crate::{content::ContentStore, errors::StorageError};
use async_trait::async_trait;
use std::{
  collections::HashMap,
  sync::{Arc, RwLock},
};

#[derive(Debug, Default)]
pub struct InMemoryContentStore {
  data: Arc<RwLock<HashMap<Handle, Vec<u8>>>>,
}

impl InMemoryContentStore {
  pub fn new() -> Self {
    InMemoryContentStore {
      data: Arc::new(RwLock::new(HashMap::new())),
    }
  }
}

#[async_trait]
impl ContentStore for InMemoryContentStore {
  async fn put(&self, data: &[u8]) -> Result<Handle, StorageError> {
    // 1. Compute hash of data
    // 2. Store content under this hash (collison = same data so operation is idempotent)

    let handle = Handle::digest(data);

    if let Ok(mut map) = self.data.write() {
      map.insert(handle, data.to_vec());
      Ok(handle)
    } else {
      Err(StorageError::LedgerWriteLockFailed)
    }
  }

  async fn get(&self, handle: &Handle) -> Result<Vec<u8>, StorageError> {
    if let Ok(map) = self.data.read() {
      match map.get(handle) {
        None => Err(StorageError::KeyDoesNotExist),
        Some(v) => Ok(v.to_vec()),
      }
    } else {
      Err(StorageError::LedgerReadLockFailed)
    }
  }

  async fn reset_store(&self) -> Result<(), StorageError> {
    // not really needed for in-memory since state is already volatile.
    // this API is only for testing persistent storage services.
    // we could implement it here anyway, but choose not to for now.
    Ok(())
  }
}
