use sha3::digest::Output;
use sha3::{Digest, Sha3_256};

pub fn concat_bytes(first: &[u8], second: &[u8]) -> Vec<u8> {
  [first, second].concat()
}

pub fn hash(bytes: &[u8]) -> Output<Sha3_256> {
  let mut hasher = Sha3_256::new();
  hasher.update(bytes);
  let result = hasher.finalize();
  result
}

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

  #[test]
  pub fn check_concat_correctness() {
    let message_1 = "this_is_a_message_".as_bytes();
    let message_2 = "this_is_not_a_message".as_bytes();
    let concat_message = concat_bytes(message_1, message_2);
    assert_eq!(
      concat_message.to_vec(),
      "this_is_a_message_this_is_not_a_message".as_bytes()
    );
    assert_ne!(
      concat_message.to_vec(),
      "this_is_not_message_this_is_not_a_message".as_bytes()
    );
  }

  #[test]
  pub fn check_hash_concat_correctness() {
    let message_1 = "1".as_bytes();
    let message_2 = "2".as_bytes();

    let hash_genesis = hash(message_1).to_vec();
    let hash_sample_handle = hash(message_2).to_vec();

    // Hash Update operation involves, the previous hash, in this case, hash_genesis || new_content_hash
    // which results in a new tail
    let tail_content_expectation =
            "67b176705b46206614219f47a05aee7ae6a3edbe850bbbe214c536b989aea4d2b1b1bd1ed240b1496c81ccf19ceccf2af6fd24fac10ae42023628abbe2687310";
    let tail_content_to_hash = concat_bytes(hash_genesis.as_slice(), hash_sample_handle.as_slice());
    let tail_content = tail_content_to_hash.clone();
    assert_eq!(hex::encode(tail_content_to_hash), tail_content_expectation);

    let tail_hash = hash(tail_content.as_slice());
    let tail_hash_expectation = "817e5971993254b8a057cdd87eb1e79698a582f99a76cd7d2641468df130db00";
    assert_eq!(hex::encode(tail_hash), tail_hash_expectation);
  }
}
