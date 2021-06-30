use ed25519_dalek::Signature;
use std::collections::HashMap;
use std::convert::TryFrom;

#[derive(Debug, Default)]
pub struct Store {
  pub ledgers: HashMap<Vec<u8>, Vec<Vec<u8>>>,
  pub metadata: HashMap<Vec<u8>, Vec<MetaBlock>>,
}

#[derive(Clone, Debug, Default)]
pub struct MetaBlock {
  pub message_data: Vec<u8>,
  pub signatures: Vec<Signature>,
}

impl MetaBlock {
  pub fn new(message_data: &Vec<u8>, signatures: &Vec<Signature>) -> Self {
    MetaBlock {
      message_data: message_data.clone(),
      signatures: signatures.clone(),
    }
  }
}

impl Store {
  pub fn new() -> Self {
    Store {
      ledgers: HashMap::new(),
      metadata: HashMap::new(),
    }
  }

  pub fn set(&mut self, key: Vec<u8>, value: Vec<u8>) {
    println!("Setting State : {:?} {:?}", key, value);
    if self.ledgers.contains_key(&*key) {
      let ledgers = self.ledgers.clone();
      let (state_k, state_v) = ledgers.get_key_value(&*key).unwrap();
      let mut updated_state = Vec::new();
      updated_state.append(&mut state_v.to_vec());
      updated_state.push(value);
      println!("Updated State: {:?} --> {:?}", state_v, updated_state);
      self.ledgers.insert(state_k.clone(), updated_state);
    } else {
      self.ledgers.entry(key).or_default().push(value);
    }
  }

  pub fn set_metadata(&mut self, key: &Vec<u8>, metadata: &Vec<u8>, signatures: &Vec<Signature>) {
    println!(
      "Setting Metadata State: {:?} --> ({:?}, {:?})",
      key, metadata, signatures
    );
    let value = MetaBlock::new(metadata, signatures);
    if self.metadata.contains_key(key) {
      let (_k, metadata_ledger) = self.metadata.get_key_value(key).unwrap();
      let mut existing_ledger = metadata_ledger.clone();
      existing_ledger.push(value);
      println!("Updated State: {:?} --> {:?}", key, existing_ledger);
      self.metadata.insert(key.to_vec(), existing_ledger);
    } else {
      self
        .metadata
        .entry(key.to_vec())
        .or_default()
        .push(value.clone());
      println!("Updated State: {:?} --> {:?}", key, value.clone());
    }
  }

  pub fn get(&self, key: Vec<u8>) -> Vec<Vec<u8>> {
    self.ledgers.get(&*key).unwrap().to_vec()
  }

  pub fn get_metadata(&self, key: Vec<u8>) -> Vec<MetaBlock> {
    self.metadata.get(&*key).unwrap().to_vec()
  }

  pub fn get_latest_state_of_ledger(&self, key: Vec<u8>) -> Vec<u8> {
    self.get(key).last().unwrap().to_vec()
  }

  pub fn get_latest_state_of_metadata_ledger(&self, key: Vec<u8>) -> MetaBlock {
    self.get_metadata(key).last().unwrap().clone()
  }

  pub fn get_ledger_state_at_index(&self, key: Vec<u8>, mut index: u64) -> Vec<u8> {
    let ledger = self.get(key);

    if !(index < ledger.len() as u64) {
      index = 0
    }
    // This might cause an issue down the line ...
    let usize_index = usize::try_from(index).unwrap();
    ledger[usize_index].to_vec()
  }

  pub fn get_metadata_ledger_state_at_index(&self, key: Vec<u8>, mut index: u64) -> MetaBlock {
    let metadata_ledger = self.get_metadata(key);
    if !(index < metadata_ledger.len() as u64) {
      index = 0
    }
    // This might cause an issue down the line ...
    let usize_index = usize::try_from(index).unwrap();
    metadata_ledger[usize_index].clone()
  }
}

#[cfg(test)]
mod tests {
  use crate::store::Store;

  #[test]
  pub fn check_coordinator_state_creation_and_operations() {
    let mut coordinator_state = Store::new();
    let key = b"endorser_issued_handle".to_vec();
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
