use tonic::{transport::Server, Request, Response, Status};

pub mod endpoint_proto {
  tonic::include_proto!("endpoint_proto");
}

use crate::endpoint_proto::{
  call_server::{Call, CallServer},
  GetIdentityReq, GetIdentityResp, IncrementCounterReq, IncrementCounterResp, NewCounterReq,
  NewCounterResp, ReadCounterReq, ReadCounterResp,
};
use clap::{App, Arg};
use endpoint::EndpointState;

pub struct EndpointGrpcState {
  state: EndpointState,
}

impl EndpointGrpcState {
  async fn new(coordinator_endpoint_address: String, pem: Option<String>) -> Self {
    EndpointGrpcState {
      state: EndpointState::new(coordinator_endpoint_address, pem)
        .await
        .unwrap(),
    }
  }
}

#[tonic::async_trait]
impl Call for EndpointGrpcState {
  async fn get_identity(
    &self,
    _req: Request<GetIdentityReq>,
  ) -> Result<Response<GetIdentityResp>, Status> {
    let res = self.state.get_identity();
    if res.is_err() {
      return Err(Status::aborted("Failed to get the identity"));
    }

    let (id, pk) = res.unwrap();
    let resp = GetIdentityResp { id, pk };

    Ok(Response::new(resp))
  }

  async fn new_counter(
    &self,
    req: Request<NewCounterReq>,
  ) -> Result<Response<NewCounterResp>, Status> {
    // receive a request from the light client
    let NewCounterReq { handle, tag } = req.into_inner();

    let res = self.state.new_counter(&handle, &tag).await;
    if res.is_err() {
      return Err(Status::aborted("Failed to create a new counter"));
    }

    let signature = res.unwrap();

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

    let res = self
      .state
      .increment_counter(&handle, &tag, expected_counter)
      .await;
    if res.is_err() {
      return Err(Status::aborted("Failed to increment the counter"));
    }

    let signature = res.unwrap();

    // respond to the light client
    Ok(Response::new(IncrementCounterResp { signature }))
  }

  async fn read_counter(
    &self,
    req: Request<ReadCounterReq>,
  ) -> Result<Response<ReadCounterResp>, Status> {
    // receive a request from the light client
    let ReadCounterReq { handle, nonce } = req.into_inner();

    let res = self.state.read_counter(&handle, &nonce).await;
    if res.is_err() {
      return Err(Status::aborted("Failed to read the counter"));
    }

    let (tag, counter, signature) = res.unwrap();

    // respond to the light client
    Ok(Response::new(ReadCounterResp {
      tag,
      counter,
      signature,
    }))
  }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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
    )
    .arg(
      Arg::with_name("pem")
        .short("m")
        .long("pem")
        .takes_value(true)
        .help("The ECDSA prime256v1 private key pem file"),
    );
  let cli_matches = config.get_matches();
  let hostname = cli_matches.value_of("host").unwrap();
  let port_number = cli_matches.value_of("port").unwrap();
  let addr = format!("{}:{}", hostname, port_number).parse()?;
  let coordinator_hostname = cli_matches.value_of("coordinator").unwrap().to_string();
  let pem = cli_matches
    .value_of("pem")
    .map(|p| std::fs::read_to_string(p).expect("Failed to read the private key pem file"));

  let endpoint_grpc_state = EndpointGrpcState::new(coordinator_hostname.to_string(), pem).await;

  println!("Running endpoint at {}", addr);
  Server::builder()
    .add_service(CallServer::new(endpoint_grpc_state))
    .serve(addr)
    .await?;

  Ok(())
}
