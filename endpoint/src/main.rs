mod errors;

use tonic::{
  transport::{Channel, Endpoint, Server},
  Request, Response, Status,
};

pub mod endpoint_proto {
  tonic::include_proto!("endpoint_proto");
}

pub mod coordinator_proto {
  tonic::include_proto!("coordinator_proto");
}

use crate::{
  endpoint_proto::{
    call_server::{Call, CallServer},
    GetIdentityReq, GetIdentityResp, IncrementCounterReq, IncrementCounterResp, NewCounterReq,
    NewCounterResp, ReadCounterReq, ReadCounterResp,
  },
  errors::EndpointError,
};
use clap::{App, Arg};
use coordinator_proto::{
  call_client::CallClient, AppendReq, AppendResp, NewLedgerReq, NewLedgerResp, ReadLatestReq,
  ReadLatestResp, ReadViewByIndexReq, ReadViewByIndexResp,
};
use ledger::{
  signature::{PrivateKey, PrivateKeyTrait, PublicKeyTrait, SignatureTrait},
  Block, CustomSerde, NimbleDigest, NimbleHashTrait,
};
use std::convert::TryFrom;
use verifier::{verify_append, verify_new_ledger, verify_read_latest, VerifierState};

#[derive(Debug, Clone)]
pub struct Connection {
  client: CallClient<Channel>,
}

impl Connection {
  pub async fn new(coordinator_endpoint_address: String) -> Result<Self, errors::EndpointError> {
    let connection_attempt = Endpoint::from_shared(coordinator_endpoint_address);
    let connection = match connection_attempt {
      Ok(connection) => connection,
      Err(_err) => return Err(EndpointError::CoordinatorHostNameNotFound),
    };
    let channel = connection.connect_lazy();
    let client = CallClient::new(channel);
    Ok(Self { client })
  }

  pub async fn new_ledger(&self, handle: &[u8], block: &[u8]) -> Result<Vec<u8>, EndpointError> {
    let req = Request::new(NewLedgerReq {
      handle: handle.to_vec(),
      block: block.to_vec(),
    });
    let NewLedgerResp { receipt } = self
      .client
      .clone()
      .new_ledger(req)
      .await
      .map_err(|_err| EndpointError::UnableToConnectToCoordinator)?
      .into_inner();
    Ok(receipt)
  }

  pub async fn append(
    &self,
    handle: &[u8],
    block: &[u8],
    expected_height: u64,
  ) -> Result<Vec<u8>, EndpointError> {
    let req = Request::new(AppendReq {
      handle: handle.to_vec(),
      block: block.to_vec(),
      expected_height,
    });
    let AppendResp { receipt } = self
      .client
      .clone()
      .append(req)
      .await
      .map_err(|_err| EndpointError::UnableToConnectToCoordinator)?
      .into_inner();
    Ok(receipt)
  }

  pub async fn read_latest(
    &self,
    handle: &[u8],
    nonce: &[u8],
  ) -> Result<(Vec<u8>, Vec<u8>), EndpointError> {
    let ReadLatestResp { block, receipt } = self
      .client
      .clone()
      .read_latest(ReadLatestReq {
        handle: handle.to_vec(),
        nonce: nonce.to_vec(),
      })
      .await
      .map_err(|_err| EndpointError::UnableToConnectToCoordinator)?
      .into_inner();
    Ok((block, receipt))
  }
}

pub struct EndpointState {
  conn: Connection,
  id: NimbleDigest,
  vs: VerifierState,
  sk: PrivateKey,
}

impl EndpointState {
  pub async fn new(hostname: String) -> Result<Self, EndpointError> {
    // make a connection to the coordinator
    let mut conn = {
      let res = Connection::new(hostname).await;

      match res {
        Ok(conn) => conn,
        Err(e) => {
          panic!("Endpoint Error: {:?}", e);
        },
      }
    };

    // initialize id and vs
    let (id, vs) = {
      let mut vs = VerifierState::default();
      let req = tonic::Request::new(ReadViewByIndexReq {
        index: 1, // the first entry on the view ledger starts at 1
      });

      let ReadViewByIndexResp { block, receipt } = conn
        .client
        .read_view_by_index(req)
        .await
        .unwrap()
        .into_inner();

      let res = vs.apply_view_change(&block, &receipt);
      println!("Applying ReadViewByIndexResp Response: {:?}", res.is_ok());
      assert!(res.is_ok());

      // the hash of the genesis block of the view ledger uniquely identifies a particular instance of NimbleLedger
      let id = Block::from_bytes(&block).unwrap().hash();

      (id, vs)
    };

    // produce a private key pair to sign responses
    let sk = PrivateKey::new();

    Ok(EndpointState { conn, id, vs, sk })
  }
}

#[tonic::async_trait]
impl Call for EndpointState {
  async fn get_identity(
    &self,
    _req: Request<GetIdentityReq>,
  ) -> Result<Response<GetIdentityResp>, Status> {
    let resp = GetIdentityResp {
      id: self.id.to_bytes(),
      pk: self.sk.get_public_key().unwrap().to_bytes(),
    };

    Ok(Response::new(resp))
  }

  async fn new_counter(
    &self,
    req: Request<NewCounterReq>,
  ) -> Result<Response<NewCounterResp>, Status> {
    // receive a request from the light client
    let NewCounterReq { handle, tag } = req.into_inner();

    // issue a request to the coordinator and receive a response
    let receipt = {
      let res = self.conn.new_ledger(&handle, &tag).await;
      if res.is_err() {
        return Err(Status::aborted("Failed to create a new counter"));
      }
      res.unwrap()
    };

    // verify the response received from the coordinator; TODO: handle the case where vs does not have the returned view hash
    let res = verify_new_ledger(&self.vs, handle.as_ref(), tag.as_ref(), &receipt);
    if res.is_err() {
      return Err(Status::aborted("Failed to verify the new counter"));
    }

    // sign a message that unequivocally identifies the counter and tag
    let msg = {
      let s = format!(
        "NewCounter id: {:?}, handle = {:?}, tag = {:?}, counter = {:?}",
        self.id.to_bytes(),
        handle,
        tag,
        1_usize
      );
      NimbleDigest::digest(s.as_bytes())
    };
    let signature = self.sk.sign(&msg.to_bytes()).unwrap().to_bytes();

    // respond to the light client
    Ok(Response::new(NewCounterResp { signature }))
  }

  async fn increment_counter(
    &self,
    req: Request<IncrementCounterReq>,
  ) -> Result<Response<IncrementCounterResp>, Status> {
    // receive a request from the light client
    let IncrementCounterReq {
      handle,
      tag,
      expected_counter,
    } = req.into_inner();

    // convert u64 to usize, returning error
    let expected_height = {
      let res = usize::try_from(expected_counter);
      if res.is_err() {
        return Err(Status::aborted(
          "Failed to convert expected counter to usize",
        ));
      }
      res.unwrap()
    };

    // issue a request to the coordinator and receive a response
    let receipt = {
      let res = self.conn.append(&handle, &tag, expected_counter).await;

      if res.is_err() {
        return Err(Status::aborted("Failed to increment counter"));
      }
      res.unwrap()
    };

    // verify the response received from the coordinator; TODO: handle the case where vs does not have the returned view hash
    let res = verify_append(&self.vs, tag.as_ref(), expected_height, &receipt);
    if res.is_err() {
      return Err(Status::aborted("Failed to verify the increment counter"));
    }

    // sign a message that unequivocally identifies the counter and tag
    let msg = {
      let s = format!(
        "IncrementCounter id: {:?}, handle = {:?}, tag = {:?}, counter = {:?}",
        self.id.to_bytes(),
        handle,
        tag,
        expected_height
      );
      NimbleDigest::digest(s.as_bytes())
    };
    let signature = self.sk.sign(&msg.to_bytes()).unwrap().to_bytes();

    // respond to the light client
    Ok(Response::new(IncrementCounterResp { signature }))
  }

  async fn read_counter(
    &self,
    req: Request<ReadCounterReq>,
  ) -> Result<Response<ReadCounterResp>, Status> {
    // receive a request from the light client
    let ReadCounterReq { handle, nonce } = req.into_inner();

    // issue a request to the coordinator and receive a response
    let (block, receipt) = {
      let res = self.conn.read_latest(&handle, &nonce).await;

      if res.is_err() {
        return Err(Status::aborted("Failed to read counter"));
      }
      res.unwrap()
    };

    // verify the response received from the coordinator; TODO: handle the case where vs does not have the returned view hash
    let res = verify_read_latest(&self.vs, block.as_ref(), &nonce, &receipt);
    if res.is_err() {
      return Err(Status::aborted("Failed to verify read counter"));
    }

    let (tag, counter) = res.unwrap();

    // sign a message that unequivocally identifies the counter and tag
    let msg = {
      let s = format!(
        "ReadCounter id: {:?}, handle = {:?}, tag = {:?}, counter = {:?}, nonce = {:?}",
        self.id.to_bytes(),
        handle,
        tag,
        counter,
        nonce
      );
      NimbleDigest::digest(s.as_bytes())
    };
    let signature = self.sk.sign(&msg.to_bytes()).unwrap().to_bytes();

    // respond to the light client
    Ok(Response::new(ReadCounterResp {
      tag,
      counter: counter as u64,
      signature,
    }))
  }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let (addr, coordinator_hostname) = {
    let config = App::new("endpoint")
      .arg(
        Arg::with_name("coordinator")
          .short("c")
          .long("coordinator")
          .help("The hostname of the coordinator")
          .default_value("http://[::1]:8080"),
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
          .default_value("8081"),
      );
    let cli_matches = config.get_matches();
    let hostname = cli_matches.value_of("host").unwrap();
    let port_number = cli_matches.value_of("port").unwrap();
    let addr = format!("{}:{}", hostname, port_number).parse()?;
    let coordinator_hostname = cli_matches.value_of("coordinator").unwrap().to_string();

    (addr, coordinator_hostname)
  };

  let endpoint_state = {
    let res = EndpointState::new(coordinator_hostname.to_string()).await;
    match res {
      Ok(endpoint_state) => endpoint_state,
      Err(e) => {
        panic!("Endpoint Error: {:?}", e);
      },
    }
  };

  Server::builder()
    .add_service(CallServer::new(endpoint_state))
    .serve(addr)
    .await?;

  Ok(())
}
