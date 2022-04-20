mod coordinator_state;
mod errors;

use crate::coordinator_state::CoordinatorState;
use ledger::CustomSerde;
use std::collections::HashMap;
use tonic::{transport::Server, Request, Response, Status};

pub mod coordinator_proto {
  tonic::include_proto!("coordinator_proto");
}

use clap::{App, Arg};
use coordinator_proto::{
  call_server::{Call, CallServer},
  AppendReq, AppendResp, NewLedgerReq, NewLedgerResp, ReadByIndexReq, ReadByIndexResp,
  ReadLatestReq, ReadLatestResp, ReadViewByIndexReq, ReadViewByIndexResp,
};

pub struct CoordinatorServiceState {
  state: CoordinatorState,
}

impl CoordinatorServiceState {
  pub fn new(coordinator: CoordinatorState) -> Self {
    CoordinatorServiceState { state: coordinator }
  }

  #[cfg(test)]
  pub fn get_state(&self) -> &CoordinatorState {
    &self.state
  }
}

#[tonic::async_trait]
impl Call for CoordinatorServiceState {
  async fn new_ledger(
    &self,
    req: Request<NewLedgerReq>,
  ) -> Result<Response<NewLedgerResp>, Status> {
    let NewLedgerReq {
      handle: handle_bytes,
      block: block_bytes,
    } = req.into_inner();

    let res = self
      .state
      .create_ledger(None, &handle_bytes, &block_bytes)
      .await;
    if res.is_err() {
      return Err(Status::aborted("Failed to create a new ledger"));
    }

    let receipt = res.unwrap();
    let reply = NewLedgerResp {
      receipt: receipt.to_bytes(),
    };
    Ok(Response::new(reply))
  }

  async fn append(&self, request: Request<AppendReq>) -> Result<Response<AppendResp>, Status> {
    let AppendReq {
      handle: handle_bytes,
      block: block_bytes,
      expected_height,
    } = request.into_inner();

    let res = self
      .state
      .append_ledger(None, &handle_bytes, &block_bytes, expected_height as usize)
      .await;
    if res.is_err() {
      return Err(Status::aborted("Failed to append to a ledger"));
    }

    let receipt = res.unwrap();
    let reply = AppendResp {
      receipt: receipt.to_bytes(),
    };

    Ok(Response::new(reply))
  }

  async fn read_latest(
    &self,
    request: Request<ReadLatestReq>,
  ) -> Result<Response<ReadLatestResp>, Status> {
    let ReadLatestReq {
      handle: handle_bytes,
      nonce: nonce_bytes,
    } = request.into_inner();

    let res = self
      .state
      .read_ledger_tail(&handle_bytes, &nonce_bytes)
      .await;
    if res.is_err() {
      return Err(Status::aborted("Failed to read a ledger tail"));
    }

    let (block, receipt) = res.unwrap();
    let reply = ReadLatestResp {
      block: block.to_bytes(),
      receipt: receipt.to_bytes(),
    };

    Ok(Response::new(reply))
  }

  async fn read_by_index(
    &self,
    request: Request<ReadByIndexReq>,
  ) -> Result<Response<ReadByIndexResp>, Status> {
    let ReadByIndexReq {
      handle: handle_bytes,
      index,
    } = request.into_inner();

    let res = self
      .state
      .read_ledger_by_index(&handle_bytes, index as usize)
      .await;
    if res.is_err() {
      return Err(Status::aborted("Failed to read a ledger"));
    }

    let ledger_entry = res.unwrap();
    let reply = ReadByIndexResp {
      block: ledger_entry.get_block().to_bytes(),
      receipt: ledger_entry.get_receipt().to_bytes(),
    };

    Ok(Response::new(reply))
  }

  async fn read_view_by_index(
    &self,
    request: Request<ReadViewByIndexReq>,
  ) -> Result<Response<ReadViewByIndexResp>, Status> {
    let ReadViewByIndexReq { index } = request.into_inner();

    let res = self.state.read_view_by_index(index as usize).await;
    if res.is_err() {
      return Err(Status::aborted("Failed to read the view ledger"));
    }

    let ledger_entry = res.unwrap();
    let reply = ReadViewByIndexResp {
      block: ledger_entry.get_block().to_bytes(),
      receipt: ledger_entry.get_receipt().to_bytes(),
    };

    Ok(Response::new(reply))
  }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let config = App::new("coordinator")
    .arg(
      Arg::with_name("nimbledb")
        .short("n")
        .long("nimbledb")
        .help("The database name")
        .default_value("nimble_cosmosdb"),
    )
    .arg(
      Arg::with_name("cosmosurl")
        .short("c")
        .long("cosmosurl")
        .takes_value(true)
        .help("The COSMOS URL"),
    )
    .arg(
      Arg::with_name("store")
        .short("s")
        .long("store")
        .help("The type of store used by the service.")
        .default_value("memory"),
    )
    .arg(
      Arg::with_name("host")
        .short("t")
        .long("host")
        .help("The hostname to run the service on.")
        .default_value("[::1]"),
    )
    .arg(
      Arg::with_name("port")
        .short("p")
        .long("port")
        .help("The port number to run the coordinator service on.")
        .default_value("8080"),
    )
    .arg(
      Arg::with_name("endorser")
        .short("e")
        .long("endorser")
        .help("List of URLs to Endorser Services")
        .use_delimiter(true)
        .default_value("http://[::1]:9090"),
    );

  let cli_matches = config.get_matches();
  let hostname = cli_matches.value_of("host").unwrap();
  let port_number = cli_matches.value_of("port").unwrap();
  let store = cli_matches.value_of("store").unwrap();
  let addr = format!("{}:{}", hostname, port_number).parse()?;
  let str_vec: Vec<&str> = cli_matches.values_of("endorser").unwrap().collect();
  let endorser_hostnames = (0..str_vec.len())
    .map(|i| str_vec[i].to_string())
    .collect::<Vec<String>>();
  println!("Endorser_hostnames: {:?}", endorser_hostnames);

  let mut ledger_store_args = HashMap::<String, String>::new();
  if let Some(x) = cli_matches.value_of("cosmosurl") {
    ledger_store_args.insert(String::from("COSMOS_URL"), x.to_string());
  }
  if let Some(x) = cli_matches.value_of("nimbledb") {
    ledger_store_args.insert(String::from("NIMBLE_DB"), x.to_string());
  }
  let res = CoordinatorState::new(store, &ledger_store_args).await;
  assert!(res.is_ok());
  let coordinator = res.unwrap();
  let res = coordinator.add_endorsers(&endorser_hostnames).await;
  assert!(res.is_ok());
  let server = CoordinatorServiceState::new(coordinator);
  println!("Running gRPC Coordinator Service at {:?}", addr);

  Server::builder()
    .add_service(CallServer::new(server))
    .serve(addr)
    .await?;

  Ok(())
}

#[cfg(test)]
mod tests {
  use crate::{
    coordinator_proto::{
      call_server::Call, AppendReq, AppendResp, NewLedgerReq, NewLedgerResp, ReadByIndexReq,
      ReadByIndexResp, ReadLatestReq, ReadLatestResp, ReadViewByIndexReq, ReadViewByIndexResp,
    },
    CoordinatorServiceState, CoordinatorState,
  };
  use rand::Rng;
  use std::{
    collections::HashMap,
    io::{BufRead, BufReader},
    process::{Child, Command, Stdio},
  };
  use verifier::{
    verify_append, verify_new_ledger, verify_read_by_index, verify_read_latest, VerifierState,
  };

  struct BoxChild {
    pub child: Child,
  }

  impl Drop for BoxChild {
    fn drop(&mut self) {
      self.child.kill().expect("failed to kill a child process");
    }
  }

  #[tokio::test]
  #[ignore]
  async fn test_coordinator() {
    if std::env::var_os("ENDORSER_CMD").is_none() {
      panic!("The ENDORSER_CMD environment variable is not specified");
    }
    let endorser_cmd = {
      match std::env::var_os("ENDORSER_CMD") {
        None => panic!("The ENDORSER_CMD environment variable is not specified"),
        Some(x) => x,
      }
    };

    let endorser_args = {
      match std::env::var_os("ENDORSER_ARGS") {
        None => panic!("The ENDORSER_ARGS environment variable is not specified"),
        Some(x) => x.into_string().unwrap(),
      }
    };

    let store = {
      match std::env::var_os("LEDGER_STORE") {
        None => String::from("memory"),
        Some(x) => x.into_string().unwrap(),
      }
    };

    let mut ledger_store_args = HashMap::<String, String>::new();
    if std::env::var_os("COSMOS_URL").is_some() {
      ledger_store_args.insert(
        String::from("COSMOS_URL"),
        std::env::var_os("COSMOS_URL")
          .unwrap()
          .into_string()
          .unwrap(),
      );
    }
    if std::env::var_os("NIMBLE_DB").is_some() {
      ledger_store_args.insert(
        String::from("NIMBLE_DB"),
        std::env::var_os("NIMBLE_DB")
          .unwrap()
          .into_string()
          .unwrap(),
      );
    }

    // Launch the endorser
    let mut endorser = BoxChild {
      child: Command::new(endorser_cmd.clone())
        .args(endorser_args.clone().split_whitespace())
        .stdout(Stdio::piped())
        .spawn()
        .expect("endorser failed to start"),
    };

    // Wait for the endorser to be ready
    let mut buf_reader = BufReader::new(endorser.child.stdout.take().unwrap());
    let mut endorser_output = String::new();
    while let Ok(buflen) = buf_reader.read_line(&mut endorser_output) {
      if buflen == 0 {
        break;
      }
      if endorser_output.contains("listening on") {
        break;
      }
    }

    // Create the coordinator
    let coordinator = CoordinatorState::new(&store, &ledger_store_args)
      .await
      .unwrap();

    let res = coordinator
      .add_endorsers(&["http://[::1]:9090".to_string()])
      .await;
    assert!(res.is_ok());

    let server = CoordinatorServiceState::new(coordinator);

    // Initialization: Fetch view ledger to build VerifierState
    let mut vs = VerifierState::new();

    let mut view_height: usize = 0;
    loop {
      let req = tonic::Request::new(ReadViewByIndexReq {
        index: (view_height + 1) as u64,
      });

      let res = server.read_view_by_index(req).await;
      if res.is_err() {
        break;
      }

      let ReadViewByIndexResp { block, receipt } = res.unwrap().into_inner();
      let res = vs.apply_view_change(&block, &receipt);
      println!("Applying ReadViewByIndexResp Response: {:?}", res);
      assert!(res.is_ok());

      view_height += 1;
    }

    // Step 0: Create some app data
    let block_bytes: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

    // Step 1: NewLedger Request (With Application Data Embedded)
    let handle_bytes = rand::thread_rng().gen::<[u8; 16]>();
    let request = tonic::Request::new(NewLedgerReq {
      handle: handle_bytes.to_vec(),
      block: block_bytes.to_vec(),
    });
    let NewLedgerResp { receipt } = server.new_ledger(request).await.unwrap().into_inner();
    let res = verify_new_ledger(&vs, &handle_bytes, block_bytes.as_ref(), &receipt);
    println!("NewLedger (WithAppData) : {:?}", res);
    assert!(res.is_ok());

    let handle = handle_bytes.to_vec();

    // Step 2: Read At Index
    let req = tonic::Request::new(ReadByIndexReq {
      handle: handle.clone(),
      index: 0,
    });

    let ReadByIndexResp { block, receipt } = server.read_by_index(req).await.unwrap().into_inner();

    let res = verify_read_by_index(&vs, &handle, &block, 0, &receipt);
    println!("ReadByIndex: {:?}", res.is_ok());
    assert!(res.is_ok());

    // Step 3: Read Latest with the Nonce generated
    let nonce = rand::thread_rng().gen::<[u8; 16]>();
    let req = tonic::Request::new(ReadLatestReq {
      handle: handle.clone(),
      nonce: nonce.to_vec(),
    });

    let ReadLatestResp { block, receipt } = server.read_latest(req).await.unwrap().into_inner();

    let res = verify_read_latest(&vs, &handle, &block, nonce.as_ref(), &receipt);
    println!("Read Latest : {:?}", res.is_ok());
    assert!(res.is_ok());

    // Step 4: Append
    let b1: Vec<u8> = "data_block_example_1".as_bytes().to_vec();
    let b2: Vec<u8> = "data_block_example_2".as_bytes().to_vec();
    let b3: Vec<u8> = "data_block_example_3".as_bytes().to_vec();
    let blocks = vec![&b1, &b2, &b3].to_vec();

    let mut expected_height = 0;
    for block_to_append in blocks {
      expected_height += 1;
      let req = tonic::Request::new(AppendReq {
        handle: handle.clone(),
        block: block_to_append.to_vec(),
        expected_height: expected_height as u64,
      });

      let AppendResp { receipt } = server.append(req).await.unwrap().into_inner();

      let res = verify_append(
        &vs,
        &handle,
        block_to_append.as_ref(),
        expected_height,
        &receipt,
      );
      println!("Append verification: {:?} {:?}", block_to_append, res);
      assert!(res.is_ok());
    }

    // Step 4: Read Latest with the Nonce generated and check for new data
    let nonce = rand::thread_rng().gen::<[u8; 16]>();
    let latest_state_query = tonic::Request::new(ReadLatestReq {
      handle: handle.clone(),
      nonce: nonce.to_vec(),
    });

    let ReadLatestResp { block, receipt } = server
      .read_latest(latest_state_query)
      .await
      .unwrap()
      .into_inner();
    assert_eq!(block, b3.clone());

    let is_latest_valid = verify_read_latest(&vs, &handle, &block, nonce.as_ref(), &receipt);
    println!(
      "Verifying ReadLatest Response : {:?}",
      is_latest_valid.is_ok()
    );
    assert!(is_latest_valid.is_ok());

    // Step 5: Read At Index
    let req = tonic::Request::new(ReadByIndexReq {
      handle: handle.clone(),
      index: 1,
    });

    let ReadByIndexResp { block, receipt } = server.read_by_index(req).await.unwrap().into_inner();
    assert_eq!(block, b1.clone());

    let res = verify_read_by_index(&vs, &handle, &block, 1, &receipt);
    println!("Verifying ReadByIndex Response: {:?}", res.is_ok());
    assert!(res.is_ok());

    // Step 6: change the view by adding a new endorser
    let endorser_args2 = endorser_args.clone() + " 9091";
    let mut endorser2 = BoxChild {
      child: Command::new(endorser_cmd.clone())
        .args(endorser_args2.split_whitespace())
        .stdout(Stdio::piped())
        .spawn()
        .expect("endorser failed to start"),
    };

    let mut buf_reader2 = BufReader::new(endorser2.child.stdout.take().unwrap());
    let mut endorser2_output = String::new();
    while let Ok(buflen) = buf_reader2.read_line(&mut endorser2_output) {
      if buflen == 0 {
        break;
      }
      if endorser2_output.contains("listening on") {
        break;
      }
    }

    let res = server
      .get_state()
      .add_endorsers(&["http://[::1]:9091".to_string()])
      .await;
    println!("Added a new endorser: {:?}", res);
    assert!(res.is_ok());

    view_height += 1;
    let req = tonic::Request::new(ReadViewByIndexReq {
      index: view_height as u64, // the first entry on the view ledger starts at 1
    });

    let ReadViewByIndexResp { block, receipt } =
      server.read_view_by_index(req).await.unwrap().into_inner();

    let res = vs.apply_view_change(&block, &receipt);
    println!("Applying ReadViewByIndexResp Response: {:?}", res);
    assert!(res.is_ok());

    // Step 7: Append without a condition
    let message = "no_condition_data_block_append".as_bytes();
    let req = tonic::Request::new(AppendReq {
      handle: handle.clone(),
      block: message.to_vec(),
      expected_height: 0_u64,
    });

    let AppendResp { receipt } = server.append(req).await.unwrap().into_inner();

    let res = verify_append(&vs, &handle, message, 0, &receipt);
    println!("Append verification no condition: {:?}", res.is_ok());
    assert!(res.is_ok());

    // Step 8: Read Latest with the Nonce generated and check for new data appended without condition
    let nonce = rand::thread_rng().gen::<[u8; 16]>();
    let latest_state_query = tonic::Request::new(ReadLatestReq {
      handle: handle.clone(),
      nonce: nonce.to_vec(),
    });

    let ReadLatestResp { block, receipt } = server
      .read_latest(latest_state_query)
      .await
      .unwrap()
      .into_inner();
    assert_eq!(block, message);

    let is_latest_valid = verify_read_latest(&vs, &handle, &block, nonce.as_ref(), &receipt);
    println!(
      "Verifying ReadLatest Response : {:?}",
      is_latest_valid.is_ok()
    );
    assert!(is_latest_valid.is_ok());

    // Step 9: create a ledger and append to it only on the first endorser
    let mut endorsers = server.get_state().get_endorser_pks();
    endorsers.remove(1);

    let handle_bytes = rand::thread_rng().gen::<[u8; 16]>();
    let res = server
      .get_state()
      .create_ledger(Some(endorsers.clone()), handle_bytes.as_ref(), &[])
      .await;
    println!("create_ledger with first endorser: {:?}", res);
    assert!(res.is_ok());

    let new_handle = handle_bytes.to_vec();

    let message = "no_condition_data_block_append 2".as_bytes();
    let res = server
      .get_state()
      .append_ledger(
        Some(endorsers.clone()),
        &new_handle.clone(),
        message,
        0usize,
      )
      .await;
    println!("append_ledger with first endorser: {:?}", res);
    assert!(res.is_ok());

    let handle2_bytes = rand::thread_rng().gen::<[u8; 16]>();
    let res = server
      .get_state()
      .create_ledger(None, handle2_bytes.as_ref(), &[])
      .await;
    println!("create_ledger with first endorser: {:?}", res);
    assert!(res.is_ok());

    let new_handle2 = handle2_bytes.to_vec();

    let message2 = "no_condition_data_block_append 3".as_bytes();
    let res = server
      .get_state()
      .append_ledger(
        Some(endorsers.clone()),
        &new_handle2.clone(),
        message2,
        0usize,
      )
      .await;
    println!("append_ledger with first endorser: {:?}", res);
    assert!(res.is_ok());

    // Step 10: add the third endorser
    let endorser_args3 = endorser_args.clone() + " 9092";
    let mut endorser3 = BoxChild {
      child: Command::new(endorser_cmd.clone())
        .args(endorser_args3.split_whitespace())
        .stdout(Stdio::piped())
        .spawn()
        .expect("endorser failed to start"),
    };

    let mut buf_reader3 = BufReader::new(endorser3.child.stdout.take().unwrap());
    let mut endorser3_output = String::new();
    while let Ok(buflen) = buf_reader3.read_line(&mut endorser3_output) {
      if buflen == 0 {
        break;
      }
      if endorser2_output.contains("listening on") {
        break;
      }
    }

    let res = server
      .get_state()
      .add_endorsers(&["http://[::1]:9092".to_string()])
      .await;
    println!("Added a new endorser: {:?}", res);
    assert!(res.is_ok());

    view_height += 1;
    let req = tonic::Request::new(ReadViewByIndexReq {
      index: view_height as u64, // the first entry on the view ledger starts at 1
    });

    let ReadViewByIndexResp { block, receipt } =
      server.read_view_by_index(req).await.unwrap().into_inner();

    let res = vs.apply_view_change(&block, &receipt);
    println!("Applying ReadViewByIndexResp Response: {:?}", res);
    assert!(res.is_ok());

    // Step 11: read the latest of the new ledger
    let nonce = rand::thread_rng().gen::<[u8; 16]>();
    let latest_state_query = tonic::Request::new(ReadLatestReq {
      handle: new_handle.clone(),
      nonce: nonce.to_vec(),
    });

    let ReadLatestResp { block, receipt } = server
      .read_latest(latest_state_query)
      .await
      .unwrap()
      .into_inner();
    assert_eq!(block, message);

    let is_latest_valid = verify_read_latest(&vs, &new_handle, &block, nonce.as_ref(), &receipt);
    println!("Verifying ReadLatest Response : {:?}", is_latest_valid,);
    assert!(is_latest_valid.is_ok());

    // Step 12: Append without a condition
    let message = "no_condition_data_block_append 3".as_bytes();
    let req = tonic::Request::new(AppendReq {
      handle: new_handle.clone(),
      block: message.to_vec(),
      expected_height: 0_u64,
    });

    let AppendResp { receipt } = server.append(req).await.unwrap().into_inner();

    let res = verify_append(&vs, &new_handle, message, 0, &receipt);
    println!("Append verification no condition: {:?}", res.is_ok());
    assert!(res.is_ok());

    if store != "memory" {
      // set up the endorsers to be at different heights
      let mut endorsers = server.get_state().get_endorser_pks();
      endorsers.remove(1);

      let handle_bytes = rand::thread_rng().gen::<[u8; 16]>();
      let res = server
        .get_state()
        .create_ledger(Some(endorsers.clone()), handle_bytes.as_ref(), &[])
        .await;
      println!("create_ledger with the first two endorser: {:?}", res);
      assert!(res.is_ok());

      let new_handle = handle_bytes.to_vec();

      let message = "no_condition_data_block_append 2".as_bytes();
      let res = server
        .get_state()
        .append_ledger(
          Some(endorsers.clone()),
          &new_handle.clone(),
          message,
          0usize,
        )
        .await;
      println!("append_ledger with the first two endorser: {:?}", res);
      assert!(res.is_ok());

      let handle2_bytes = rand::thread_rng().gen::<[u8; 16]>();
      let res = server
        .get_state()
        .create_ledger(None, handle2_bytes.as_ref(), &[])
        .await;
      println!("create_ledger with all three endorser: {:?}", res);
      assert!(res.is_ok());

      let new_handle2 = handle2_bytes.to_vec();

      let message2 = "no_condition_data_block_append 3".as_bytes();
      let res = server
        .get_state()
        .append_ledger(
          Some(endorsers.clone()),
          &new_handle2.clone(),
          message2,
          0usize,
        )
        .await;
      println!("append_ledger with the first two endorser: {:?}", res);
      assert!(res.is_ok());

      // Step 13: start a new coordinator
      let coordinator2 = CoordinatorState::new(&store, &ledger_store_args)
        .await
        .unwrap();

      let server2 = CoordinatorServiceState::new(coordinator2);
      println!("Started a new coordinator");

      // Step 14: Append without a condition via the new coordinator
      let message = "no_condition_data_block_append 4".as_bytes();
      let req = tonic::Request::new(AppendReq {
        handle: new_handle.clone(),
        block: message.to_vec(),
        expected_height: 0_u64,
      });

      let AppendResp { receipt } = server2.append(req).await.unwrap().into_inner();
      let res = verify_append(&vs, &new_handle, message, 0, &receipt);
      println!("Append verification no condition: {:?}", res.is_ok());
      assert!(res.is_ok());

      // Step 14: Append without a condition via the new coordinator
      let message = "no_condition_data_block_append 4".as_bytes();
      let req = tonic::Request::new(AppendReq {
        handle: new_handle2.clone(),
        block: message.to_vec(),
        expected_height: 0_u64,
      });

      let AppendResp { receipt } = server2.append(req).await.unwrap().into_inner();
      let res = verify_append(&vs, &new_handle2, message, 0, &receipt);
      println!("Append verification no condition: {:?}", res.is_ok());
      assert!(res.is_ok());
    }

    // Step 15: query the state of endorsers
    let _pk_ledger_views = server.get_state().query_endorsers().await.unwrap();

    // We access endorser and endorser2 below
    // to stop them from being dropped earlier
    println!("endorser1 process ID is {}", endorser.child.id());
    println!("endorser2 process ID is {}", endorser2.child.id());
    println!("endorser3 process ID is {}", endorser3.child.id());
    server.get_state().reset_ledger_store().await;
  }
}
