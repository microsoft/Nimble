use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, HashMap};
use std::convert::TryFrom;

use clap::Parser;
use rand::Rng;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use tokio::time::Instant;
use tonic::transport::{Channel, Endpoint};

use coordinator_proto::call_client::CallClient;
use coordinator_proto::{AppendReq, NewLedgerReq, NewLedgerResp};
use ledger::NimbleDigest;
use verifier::{verify_append, verify_new_ledger, VerificationKey};

use crate::cli::Args;
use crate::errors::ClientError;
use crate::log::{check_file_path_and_setup_dirs_necessary, BenchmarkLog};
use crate::timer::Timer;
use crate::utils::{
  compute_average, compute_throughput_per_second, generate_random_bytes, reformat_receipt,
};

mod cli;
mod errors;
mod log;
mod timer;
mod utils;

pub mod coordinator_proto {
  tonic::include_proto!("coordinator_proto");
}

#[derive(Debug, Clone)]
pub struct CoordinatorConnection {
  client: CallClient<Channel>,
}

impl CoordinatorConnection {
  pub async fn new(coordinator_endpoint_address: String) -> Result<Self, errors::ClientError> {
    let connection_attempt = Endpoint::from_shared(coordinator_endpoint_address);
    let connection = match connection_attempt {
      Ok(connection) => connection,
      Err(_err) => return Err(ClientError::CoordinatorHostNameNotFound),
    };
    let channel_attempt = connection.connect_lazy();
    let channel = match channel_attempt {
      Ok(channel) => channel,
      Err(_err) => return Err(ClientError::UnableToConnectToCoordinator),
    };
    let client = CallClient::new(channel);
    Ok(CoordinatorConnection { client })
  }
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum BenchmarkRequestType {
  BenchmarkNewLedger = 1,
  BenchmarkAppend = 2,
  BenchmarkReadLatest = 3,
  BenchmarkReadByIndex = 4,
}

impl From<usize> for BenchmarkRequestType {
  // The `from` call will not receive a number other than the values of the enum because of clap's sanitization.
  fn from(val: usize) -> Self {
    if val == BenchmarkRequestType::BenchmarkNewLedger as usize {
      return BenchmarkRequestType::BenchmarkNewLedger;
    } else if val == BenchmarkRequestType::BenchmarkAppend as usize {
      return BenchmarkRequestType::BenchmarkAppend;
    } else if val == BenchmarkRequestType::BenchmarkReadLatest as usize {
      return BenchmarkRequestType::BenchmarkReadLatest;
    }
    BenchmarkRequestType::BenchmarkReadByIndex
  }
}

async fn prepare_concurrent_clients(
  num_concurrent_clients: usize,
  coordinator_addr: &str,
) -> Result<Vec<CoordinatorConnection>, Box<dyn std::error::Error>> {
  let t = Timer::new(&format!(
    "Initializing {:?} Clients",
    num_concurrent_clients
  ));
  let mut conn_pool = Vec::new();
  for _ in 0..num_concurrent_clients {
    let c = CoordinatorConnection::new(coordinator_addr.to_string()).await;
    if c.is_err() {
      panic!("Client Error: {:?}", c.err().unwrap());
    }
    conn_pool.push(c.unwrap());
  }
  t.stop();

  Ok(conn_pool.clone())
}

async fn benchmark_newledger(
  conn_pool: &[CoordinatorConnection],
  num_concurrent_clients: usize,
  num_reqs_per_client: usize,
  app_bytes_size: usize,
) -> Result<BenchmarkLog, Box<dyn std::error::Error>> {
  println!(
    "Starting the NewLedger benchmark with {} clients each sending {} requests...",
    num_concurrent_clients, num_reqs_per_client
  );

  let benchmark_start = Timer::new("Benchmark::NewLedger");

  let num_total_reqs = num_concurrent_clients * num_reqs_per_client;
  let clients_initialize_start =
    Timer::new(&format!("NewLedger_CreateClients C={}", num_total_reqs));

  let mut nonce_app_bytes = Vec::with_capacity(num_total_reqs);
  for _gen_nonce_id in 0..num_total_reqs {
    let client_nonce = rand::thread_rng().gen::<[u8; 16]>();
    // TODO: Make this variable and configurable.
    let random_app_bytes = generate_random_bytes(app_bytes_size);
    nonce_app_bytes.push((client_nonce, random_app_bytes));
  }

  clients_initialize_start.stop();

  let mut req_counter = 0;
  let mut responses = Vec::new();
  let mut client_nonce_to_request_map = HashMap::new();

  let mut timer_map = HashMap::new();

  let req_start = Timer::new(&format!("NewLedger_Requests R={}", num_total_reqs));

  let req_create_start = Timer::new(&format!("NewLedger_Requests_Create R={}", num_total_reqs));
  for conn_state in conn_pool {
    for _ in 0..num_reqs_per_client {
      let mut conn = conn_state.clone();
      let (nonce, app_bytes) = &nonce_app_bytes[req_counter];
      let q = tonic::Request::new(NewLedgerReq {
        nonce: nonce.to_vec(),
        app_bytes: app_bytes.to_vec(),
      });
      req_counter += 1;
      client_nonce_to_request_map.insert(req_counter, nonce.to_vec());

      timer_map.insert(req_counter, Instant::now());

      responses.push(tokio::spawn(async move {
        (req_counter, conn.client.new_ledger(q).await)
      }))
    }
  }
  req_create_start.stop();

  let mut results = Vec::new();
  for resp in responses {
    let res = resp.await;
    results.push((res, Instant::now()));
  }

  let results_end = req_start.stop();
  let telemetry_service_throughput = compute_throughput_per_second(&results_end, num_total_reqs);
  Timer::print(&format!(
    "NewLedger_Response_Throughput: {:?} req/s",
    telemetry_service_throughput
  ));

  let mut client_latencies = BTreeMap::new();

  let mut responses = Vec::new();
  for (r, recv_time) in results {
    if r.is_ok() {
      let (index, res) = r.unwrap();
      let returned_resp = res.unwrap().into_inner();
      responses.push((returned_resp, &client_nonce_to_request_map[&index]));

      // Insert latencies for responses to the client latencies map, Number of keys = number of clients, size of value = len(requests per client)
      let req_elapsed_t = recv_time.duration_since(timer_map[&index]);
      match client_latencies.entry(index / num_reqs_per_client) {
        Entry::Vacant(e) => {
          e.insert(vec![req_elapsed_t]);
        },
        Entry::Occupied(mut e) => {
          e.get_mut().push(req_elapsed_t);
        },
      }
    } else {
      println!("Request Failed: {:?}", r.unwrap());
    }
  }

  let mut client_averages = Vec::new();
  for (client_index, response_times) in client_latencies {
    let client_average_t = compute_average(&response_times);
    client_averages.push(client_average_t);
    // TODO: How to selectively enable this? Maybe a verbose flag?
    Timer::print(&format!(
      "NewLedger_Client_{}_AvgLatency: {:?}",
      client_index, client_average_t
    ));
  }
  let telemetry_avg_service_latency = compute_average(&client_averages);
  Timer::print(&format!(
    "NewLedger_AllClients_AvgLatency: {:?}",
    telemetry_avg_service_latency
  ));

  let seq_verification_start = Timer::new("Sequential Verification");

  for (newledger_res, client_nonce) in &responses {
    // NOTE: Every NewLedger response is individually verified and MUST pass.
    let res = verify_new_ledger(
      &newledger_res.view,
      &newledger_res.block,
      &reformat_receipt(&newledger_res.receipt),
      client_nonce,
    );
    assert!(res.is_ok());
  }
  let seq_verification_end = seq_verification_start.stop();
  let telemetry_verification_throughput =
    compute_throughput_per_second(&seq_verification_end, num_total_reqs);
  Timer::print(&format!(
    "NewLedger_Verification_Throughput: {} ver/s",
    telemetry_verification_throughput
  ));

  let par_verification_start = Timer::new("Parallel Verification");
  let _parallel_verification_results: Vec<_> = (0..responses.len())
    .into_par_iter()
    .map(|i: usize| {
      verify_new_ledger(
        &responses[i].0.view,
        &responses[i].0.block,
        &reformat_receipt(&responses[i].0.receipt),
        responses[i].1,
      )
      .is_ok()
    })
    .collect();

  par_verification_start.stop();

  benchmark_start.stop();

  let telemetry_resp = BenchmarkLog::new(
    num_concurrent_clients,
    num_total_reqs,
    num_reqs_per_client,
    BenchmarkRequestType::BenchmarkNewLedger as usize,
    telemetry_avg_service_latency.as_secs_f64(),
    telemetry_service_throughput,
    telemetry_verification_throughput,
  );

  Ok(telemetry_resp)
}

async fn benchmark_append(
  conn_pool: &[CoordinatorConnection],
  vk: &VerificationKey,
  num_concurrent_clients: usize,
  num_reqs_per_client: usize,
  block_size: usize,
  handle: &[u8],
) -> Result<BenchmarkLog, Box<dyn std::error::Error>> {
  println!(
    "Starting the Append benchmark with {} clients each sending {} requests...",
    num_concurrent_clients, num_reqs_per_client
  );

  let num_total_reqs = num_concurrent_clients * num_reqs_per_client;
  let block = generate_random_bytes(block_size);
  let mut i = 0;

  let mut responses = Vec::new();

  let mut timer_map = HashMap::new();

  let benchmark_start = Timer::new("Benchmark::Append");

  let req_start = Timer::new(&format!("Append_Requests R={}", num_total_reqs));
  let req_create_start = Timer::new(&format!("Append_Requests_Create R={}", num_total_reqs));
  for conn_state in conn_pool {
    for _ in 0..num_reqs_per_client {
      let mut conn = conn_state.clone();
      let q = tonic::Request::new(AppendReq {
        handle: handle.to_owned(),
        block: block.clone(),
        cond_tail_hash: NimbleDigest::default().to_bytes().to_vec(),
      });
      i += 1;

      timer_map.insert(i, Instant::now());

      responses.push(tokio::spawn(
        async move { (i, conn.client.append(q).await) },
      ))
    }
  }
  req_create_start.stop();

  let mut results = Vec::new();
  for resp in responses {
    let res = resp.await;
    results.push((res, Instant::now()));
  }

  let results_end = req_start.stop();
  let telemetry_service_throughput = compute_throughput_per_second(&results_end, num_total_reqs);
  Timer::print(&format!(
    "Append_Response_Throughput: {:?} req/s",
    telemetry_service_throughput
  ));

  let mut client_latencies = BTreeMap::new();

  let mut responses = Vec::new();
  for (r, recv_time) in results {
    if r.is_ok() {
      let (index, res) = r.unwrap();
      let returned_resp = res.unwrap().into_inner();
      responses.push(returned_resp);

      // Insert latencies
      let req_elapsed_t = recv_time.duration_since(timer_map[&index]);
      match client_latencies.entry(index / num_reqs_per_client) {
        Entry::Vacant(e) => {
          e.insert(vec![req_elapsed_t]);
        },
        Entry::Occupied(mut e) => {
          e.get_mut().push(req_elapsed_t);
        },
      }
    } else {
      println!("Request Failed: {:?}", r.unwrap());
    }
  }

  let mut client_averages = Vec::new();
  for (client_index, response_times) in client_latencies {
    let client_average_t = compute_average(&response_times);
    client_averages.push(client_average_t);
    // TODO: How to selectively enable this? Maybe a verbose flag?
    Timer::print(&format!(
      "Append_Client_{}_AvgLatency: {:?}",
      client_index, client_average_t
    ));
  }
  let telemetry_service_latency = compute_average(&client_averages);
  Timer::print(&format!(
    "Append_AllClients_AvgLatency: {:?}",
    telemetry_service_latency
  ));

  let seq_verification_start = Timer::new("Sequential Verification");

  for append_res in &responses {
    // NOTE: Not every append is verified since we don't know the order they were received and processed.
    let _res = verify_append(
      vk,
      &append_res.view,
      &block.to_vec(),
      &append_res.prev,
      append_res.height as usize,
      &reformat_receipt(&append_res.receipt),
    );
  }

  let seq_verification_end = seq_verification_start.stop();
  let telemetry_verification_throughput =
    compute_throughput_per_second(&seq_verification_end, num_total_reqs);
  Timer::print(&format!(
    "Append_Verification_Throughput: {} ver/s",
    telemetry_verification_throughput
  ));

  let par_verification_start = Timer::new("Parallel Verification");
  let _parallel_verification_results: Vec<_> = (0..responses.len())
    .into_par_iter()
    .map(|i: usize| {
      verify_append(
        vk,
        &responses[i].view,
        &block.to_vec(),
        &responses[i].prev,
        responses[i].height as usize,
        &reformat_receipt(&responses[i].receipt),
      )
      .is_ok()
    })
    .collect();
  par_verification_start.stop();

  benchmark_start.stop();

  let telemetry = BenchmarkLog::new(
    num_concurrent_clients,
    num_total_reqs,
    num_reqs_per_client,
    BenchmarkRequestType::BenchmarkAppend as usize,
    telemetry_service_latency.as_secs_f64(),
    telemetry_service_throughput,
    telemetry_verification_throughput,
  );

  Ok(telemetry)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let config: Args = Args::parse();
  let coordinator_endpoint_addr = config.coordinator;
  let mut benchmarks_to_run = config.methods;
  let app_byte_size = config.app_or_block_byte_size;
  let file_out_path_str = config.write_file_out;

  let mut writer = check_file_path_and_setup_dirs_necessary(&file_out_path_str).unwrap();

  benchmarks_to_run.sort_unstable();

  let coordinator_connection_attempt =
    CoordinatorConnection::new(coordinator_endpoint_addr.to_string()).await;
  let mut coordinator_connection = match coordinator_connection_attempt {
    Ok(coordinator_connection) => coordinator_connection,
    Err(e) => {
      panic!("Client Error: {:?}", e);
    },
  };

  // Step 1: NewLedger Request (With Application Data Embedded)
  let app_bytes: Vec<u8> = generate_random_bytes(app_byte_size);
  let client_nonce = rand::thread_rng().gen::<[u8; 16]>();
  let request = tonic::Request::new(NewLedgerReq {
    nonce: client_nonce.to_vec(),
    app_bytes: app_bytes.to_vec(),
  });
  let NewLedgerResp {
    view,
    block,
    receipt,
  } = coordinator_connection
    .client
    .new_ledger(request)
    .await?
    .into_inner();

  let res = verify_new_ledger(&view, &block, &reformat_receipt(&receipt), &client_nonce);
  println!("NewLedger (WithAppData) : {:?}", res.is_ok());
  assert!(res.is_ok());

  let (handle, vk, ret_app_bytes) = res.unwrap();
  assert_eq!(ret_app_bytes, app_bytes.to_vec());

  let num_concurrent_clients = config.clients;
  let num_reqs_per_client = config.requests;

  let conn_pool =
    prepare_concurrent_clients(num_concurrent_clients, &coordinator_endpoint_addr).await?;

  for benchmark_id in benchmarks_to_run {
    let benchmark_type = BenchmarkRequestType::try_from(benchmark_id).unwrap();
    match benchmark_type {
      BenchmarkRequestType::BenchmarkNewLedger => {
        let newledger_benchmark_ok = benchmark_newledger(
          &conn_pool,
          num_concurrent_clients,
          num_reqs_per_client,
          app_byte_size,
        )
        .await;
        assert!(newledger_benchmark_ok.is_ok());
        let _write_op = writer.write(&newledger_benchmark_ok.unwrap());
      },
      BenchmarkRequestType::BenchmarkAppend => {
        let append_benchmark_ok = benchmark_append(
          &conn_pool,
          &vk,
          num_concurrent_clients,
          num_reqs_per_client,
          app_byte_size,
          &handle,
        )
        .await;
        assert!(append_benchmark_ok.is_ok());
        let _write_op = writer.write(&append_benchmark_ok.unwrap());
      },
      BenchmarkRequestType::BenchmarkReadLatest => {
        unimplemented!("Benchmarking Read Latest API isn't implemented yet.");
      },
      BenchmarkRequestType::BenchmarkReadByIndex => {
        unimplemented!("Benchmarking Read By Index API isn't implemented yet.");
      },
    }
  }

  let _write_op = writer.flush();

  Ok(())
}
