use std::collections::HashMap;
use std::convert::TryFrom;

#[derive(Debug, Default)]
pub struct Store {
  pub ledgers: HashMap<String, Vec<Vec<u8>>>,
}

impl Store {
  pub fn new() -> Self {
    Store {
      ledgers: HashMap::new(),
    }
  }

  pub fn set(&mut self, key: String, value: Vec<u8>) {
    println!("Setting State : {:?} {:?}", key, value);
    if self.ledgers.contains_key(&*key) {
      let ledgers = self.ledgers.clone();
      let (state_k, state_v) = ledgers.get_key_value(&*key).unwrap();
      let mut updated_state = Vec::new();
      updated_state.append(&mut state_v.to_vec());
      updated_state.push(value);
      println!("Updated State: {:?} --> {:?}", state_v, updated_state);
      self.ledgers.insert(state_k.to_string(), updated_state);
    } else {
      self.ledgers.entry(key).or_default().push(value);
    }
  }

  pub fn get(&self, key: String) -> Vec<Vec<u8>> {
    self.ledgers.get(&*key).unwrap().to_vec()
  }

  pub fn get_latest_state_of_ledger(&self, key: String) -> Vec<u8> {
    self.get(key).last().unwrap().to_vec()
  }

  pub fn get_ledger_state_at_index(&self, key: String, mut index: u64) -> Vec<u8> {
    let ledger = self.get(key);

    if !(index < ledger.len() as u64) {
      index = 0
    }
    let usize_index = usize::try_from(index).unwrap();
    ledger[usize_index].to_vec()
  }

  pub fn get_all_ledgers_handles(&self) -> Vec<String> {
    self.ledgers.keys().cloned().collect()
  }
}

mod tests {
  use super::*;
  use crate::store::Store;

  #[test]
  pub fn check_coordinator_state_creation_and_operations() {
    let mut coordinator_state = Store::new();
    let key = "endorser_issued_handle".to_string();
    let initial_value: Vec<u8> = vec![
      1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
      1, 2,
    ];

    // [TEST]: Testing Coordinator Set and Get
    coordinator_state.set(key.clone(), initial_value.clone());
    let current_data = coordinator_state.get(key.clone());
    assert_eq!(current_data.len(), 1);
    let expected_current_data = vec![initial_value];
    assert_eq!(current_data, expected_current_data);

    // [TEST]: Testing Coordinator GetLatest and GetLedgerAtIndex
    let new_value_appended: Vec<u8> = vec![
      2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1,
      2, 1,
    ];
    coordinator_state.set(key.clone(), new_value_appended.clone());
    let current_tail = coordinator_state.get_latest_state_of_ledger(key.clone());
    assert_eq!(current_tail, new_value_appended);
    let ledger_data = coordinator_state.get(key.clone());
    assert_eq!(ledger_data.len(), 2);
    let index_query = 0u64;
    let data_at_index =
      coordinator_state.get_ledger_state_at_index(key.clone(), index_query.clone());
    assert_eq!(
      data_at_index,
      ledger_data.get(index_query as usize).unwrap().to_vec()
    )
  }
}
