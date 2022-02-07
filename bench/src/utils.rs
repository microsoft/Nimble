use crate::coordinator_proto::Receipt;
use std::time::Duration;

pub fn reformat_receipt(receipt: &Option<Receipt>) -> Vec<(Vec<u8>, Vec<u8>)> {
  assert!(receipt.is_some());
  let id_sigs = receipt.clone().unwrap().id_sigs;
  (0..id_sigs.len())
    .map(|i| (id_sigs[i].id.clone(), id_sigs[i].sig.clone()))
    .collect::<Vec<(Vec<u8>, Vec<u8>)>>()
}

pub fn generate_random_bytes(buffer_size: usize) -> Vec<u8> {
  (0..buffer_size).map(|_| rand::random::<u8>()).collect()
}

pub fn compute_average(times: &[Duration]) -> Duration {
  let mut sum_container = Duration::new(0, 0);
  for t in times {
    sum_container = sum_container.checked_add(t.to_owned()).unwrap()
  }
  sum_container / times.len() as u32
}

pub fn compute_throughput_per_second(total_time: &Duration, iters: usize) -> f64 {
  let total_ns = total_time.as_secs_f64();
  let second = Duration::new(1, 000_000_000).as_secs_f64();

  iters as f64 / total_ns * second
}
