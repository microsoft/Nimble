use std::collections::HashMap;
use std::convert::TryFrom;

#[derive(Debug, Default)]
pub struct Store {
  pub ledgers: HashMap<String, Vec<Vec<u8>>>,
}

impl Store {
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
