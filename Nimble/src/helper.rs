use sha3::digest::Output;
use sha3::{Digest, Sha3_256};
use std::convert::TryInto;

pub fn hash(bytes: &[u8]) -> Output<Sha3_256> {
  let mut hasher = Sha3_256::new();
  hasher.update(bytes);
  let result = hasher.finalize();
  result
}

pub fn unpack_metadata_information(metadata_bytes: Vec<u8>) -> (Vec<u8>, Vec<u8>, u64) {
  let tail_hash_size = 32usize;
  let block_hash_size = 32usize;
  let ledger_count_size = 8usize;
  let metadata_buffer = metadata_bytes.as_slice();
  let tail_hash_bytes = &metadata_buffer[0..tail_hash_size];
  let block_hash_bytes = &metadata_buffer[tail_hash_size..(tail_hash_size + block_hash_size)];
  let ledger_height_bytes = &metadata_buffer
    [(tail_hash_size + block_hash_size)..(tail_hash_size + block_hash_size + ledger_count_size)];
  let ledger_buffer = ledger_height_bytes.try_into().unwrap();
  let tail_hash = tail_hash_bytes.to_vec();
  let block_hash = block_hash_bytes.to_vec();
  let ledger_height = u64::from_be_bytes(ledger_buffer);
  (tail_hash, block_hash, ledger_height)
}

pub fn pack_metadata_information(
  tail_hash: Vec<u8>,
  block_hash: Vec<u8>,
  ledger_height: usize,
) -> Vec<u8> {
  let mut packed_metadata = Vec::new();
  let ledger_height_bytes = ledger_height.to_be_bytes().to_vec();
  packed_metadata.extend(tail_hash.clone());
  packed_metadata.extend(block_hash.clone());
  packed_metadata.extend(ledger_height_bytes);
  packed_metadata
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  pub fn check_hash_correctness() {
    let data_to_hash = [b"1", b"2", b"3", b"4"];
    let match_hash_result = [
      "67b176705b46206614219f47a05aee7ae6a3edbe850bbbe214c536b989aea4d2",
      "b1b1bd1ed240b1496c81ccf19ceccf2af6fd24fac10ae42023628abbe2687310",
      "1bf0b26eb2090599dd68cbb42c86a674cb07ab7adc103ad3ccdf521bb79056b9",
      "b410677b84ed73fac43fcf1abd933151dd417d932a0ef9b0260ecf8b7b72ecb9",
    ];

    for (i, data) in data_to_hash.iter().enumerate() {
      let t = data.clone();
      let r = hash(t);
      let hex_r = hex::encode(r);
      assert_eq!(hex_r, match_hash_result[i])
    }
  }
}
