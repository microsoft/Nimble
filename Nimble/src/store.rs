use core::cmp::Eq;
use std::collections::HashMap;
use std::hash::Hash;

use crate::errors::StorageError;

#[derive(Debug, Default)]
pub struct AppendOnlyStore<K, V> {
  map: HashMap<K, Vec<V>>,
}

impl<K, V> AppendOnlyStore<K, V>
where
  K: Clone + Eq + Hash,
  V: Clone,
{
  pub fn new() -> Self {
    AppendOnlyStore {
      map: HashMap::new(),
    }
  }

  pub fn insert(&mut self, key: &K, val: &V) -> Result<(), StorageError> {
    // check if `map` already contains an entry for the supplied `key`
    if self.map.contains_key(key) {
      return Err(StorageError::DuplicateKey);
    }

    // store `val` as the first entry associated with `key` in `map`
    self.map.insert(key.clone(), vec![val.clone()]);
    Ok(())
  }

  pub fn append(&mut self, key: &K, val: &V) -> Result<(), StorageError> {
    let cur_val_opt = self.map.get_mut(key);
    match cur_val_opt {
      // if the supplied `key` does not exist in `map` return an error
      None => Err(StorageError::InvalidKey),
      // if the supplied `key` exists in `map` append `val` to the vector associated with `key` in `map`
      Some(cur_val) => {
        cur_val.push(val.clone());
        Ok(())
      },
    }
  }

  pub fn read_latest(&self, key: &K) -> Result<V, StorageError> {
    let cur_val_opt = self.map.get(key);
    match cur_val_opt {
      // if the supplied `key` does not exist in `map` return an error
      None => Err(StorageError::InvalidKey),
      // if the supplied `key` exists in `map` return the last entry in the vector associated with `key` in `map`
      Some(cur_val) => {
        Ok(cur_val[cur_val.len() - 1].clone()) // TODO: use last method
      },
    }
  }

  pub fn read_by_index(&self, key: &K, idx: usize) -> Result<V, StorageError> {
    let cur_val_opt = self.map.get(key);
    match cur_val_opt {
      // if the supplied `key` does not exist in `map` return an error
      None => Err(StorageError::InvalidKey),
      // if the supplied `key` exists in `map` return the entry at index `idx` in the vector associated with `key` in `map`
      Some(cur_val) => {
        if idx < cur_val.len() {
          Ok(cur_val[idx].clone())
        } else {
          Err(StorageError::InvalidIndex)
        }
      },
    }
  }
}

#[cfg(test)]
mod tests {
  use crate::store::AppendOnlyStore;

  #[test]
  pub fn check_store_creation_and_operations() {
    let mut state = AppendOnlyStore::<Vec<u8>, Vec<u8>>::new();

    let key = b"endorser_issued_handle".to_vec();
    let initial_value: Vec<u8> = vec![
      1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
      1, 2,
    ];

    // [TEST]: Testing Coordinator insert and read_latest
    let res = state.insert(&key, &initial_value);
    assert!(res.is_ok());

    let res = state.read_latest(&key);
    assert!(res.is_ok());

    let current_data = res.unwrap();
    assert_eq!(current_data, initial_value);

    let new_value_appended: Vec<u8> = vec![
      2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1,
      2, 1,
    ];

    let res = state.append(&key, &new_value_appended);
    assert!(res.is_ok());

    let res = state.read_latest(&key);
    assert!(res.is_ok());

    let current_tail = res.unwrap();
    assert_eq!(current_tail, new_value_appended);

    let res = state.read_by_index(&key, 0);
    assert!(res.is_ok());
    let data_at_index = res.unwrap();
    assert_eq!(data_at_index, initial_value)
  }
}
