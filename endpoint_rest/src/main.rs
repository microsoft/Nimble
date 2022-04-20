use endpoint::EndpointState;

use axum::{
  extract::{Extension, Path, Query},
  http::StatusCode,
  response::IntoResponse,
  routing::get,
  Json, Router,
};
use serde_json::json;
use std::{
  collections::HashMap,
  net::{IpAddr, SocketAddr},
  str::FromStr,
  sync::Arc,
};
use tower::ServiceBuilder;

use clap::{App, Arg};

use serde::{Deserialize, Serialize};

#[tokio::main]
async fn main() {
  let (ip_addr, port, coordinator_hostname) = {
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
          .default_value("::1"),
      )
      .arg(
        Arg::with_name("port")
          .short("p")
          .long("port")
          .help("The port number to run the coordinator service on.")
          .default_value("8082"),
      );
    let cli_matches = config.get_matches();
    let addr = IpAddr::from_str(cli_matches.value_of("host").unwrap()).unwrap();
    let port_number: u16 = cli_matches.value_of("port").unwrap().parse().unwrap();
    let coordinator_hostname = cli_matches.value_of("coordinator").unwrap().to_string();

    (addr, port_number, coordinator_hostname)
  };

  let endpoint_state = Arc::new(EndpointState::new(coordinator_hostname).await.unwrap());

  // Build our application by composing routes
  let app = Router::new()
      .route("/serviceid", get(get_identity))
      .route("/counters/:handle", get(read_counter).put(new_counter).post(increment_counter))
      // Add middleware to all routes
      .layer(
          ServiceBuilder::new()
              // Handle errors from middleware
              .layer(Extension(endpoint_state))
              .into_inner(),
      );

  // Run our app with hyper
  let addr = SocketAddr::from((ip_addr, port));
  println!("Running endpoint at {}", addr);
  axum::Server::bind(&addr)
    .serve(app.into_make_service())
    .await
    .unwrap();
}

#[derive(Debug, Serialize, Deserialize)]
struct GetIdentityResponse {
  #[serde(rename = "Identity")]
  pub id: String,
  #[serde(rename = "PublicKey")]
  pub pk: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct NewCounterRequest {
  #[serde(rename = "Tag")]
  pub tag: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct NewCounterResponse {
  #[serde(rename = "Signature")]
  pub signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct IncrementCounterRequest {
  #[serde(rename = "Tag")]
  pub tag: String,
  #[serde(rename = "ExpectedCounter")]
  pub expected_counter: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct IncrementCounterResponse {
  #[serde(rename = "Signature")]
  pub signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ReadCounterResponse {
  #[serde(rename = "Tag")]
  pub tag: String,
  #[serde(rename = "Counter")]
  pub counter: u64,
  #[serde(rename = "Signature")]
  pub signature: String,
}

async fn get_identity(Extension(state): Extension<Arc<EndpointState>>) -> impl IntoResponse {
  let (id, pk) = state.get_identity().unwrap();
  let resp = GetIdentityResponse {
    id: base64_url::encode(&id),
    pk: base64_url::encode(&pk),
  };
  (StatusCode::OK, Json(json!(resp)))
}

async fn new_counter(
  Path(handle): Path<String>,
  Json(req): Json<NewCounterRequest>,
  Extension(state): Extension<Arc<EndpointState>>,
) -> impl IntoResponse {
  let res = base64_url::decode(&handle);
  if res.is_err() {
    return (StatusCode::BAD_REQUEST, Json(json!({})));
  }
  let handle = res.unwrap();

  let res = base64_url::decode(&req.tag);
  if res.is_err() {
    return (StatusCode::BAD_REQUEST, Json(json!({})));
  }
  let tag = res.unwrap();

  let res = state.new_counter(&handle, &tag).await;
  if res.is_err() {
    return (StatusCode::CONFLICT, Json(json!({})));
  }
  let signature = res.unwrap();

  let resp = NewCounterResponse {
    signature: base64_url::encode(&signature),
  };

  (StatusCode::OK, Json(json!(resp)))
}

async fn read_counter(
  Path(handle): Path<String>,
  Query(params): Query<HashMap<String, String>>,
  Extension(state): Extension<Arc<EndpointState>>,
) -> impl IntoResponse {
  let res = base64_url::decode(&handle);
  if res.is_err() {
    return (StatusCode::BAD_REQUEST, Json(json!({})));
  }
  let handle = res.unwrap();

  if !params.contains_key("nonce") {
    return (StatusCode::BAD_REQUEST, Json(json!({})));
  }
  let res = base64_url::decode(&params["nonce"]);
  if res.is_err() {
    return (StatusCode::BAD_REQUEST, Json(json!({})));
  }
  let nonce = res.unwrap();

  let res = state.read_counter(&handle, &nonce).await;
  if res.is_err() {
    return (StatusCode::CONFLICT, Json(json!({})));
  }
  let (tag, counter, signature) = res.unwrap();

  let resp = ReadCounterResponse {
    tag: base64_url::encode(&tag),
    counter,
    signature: base64_url::encode(&signature),
  };

  (StatusCode::OK, Json(json!(resp)))
}

async fn increment_counter(
  Path(handle): Path<String>,
  Json(req): Json<IncrementCounterRequest>,
  Extension(state): Extension<Arc<EndpointState>>,
) -> impl IntoResponse {
  let res = base64_url::decode(&handle);
  if res.is_err() {
    return (StatusCode::BAD_REQUEST, Json(json!({})));
  }
  let handle = res.unwrap();

  let res = base64_url::decode(&req.tag);
  if res.is_err() {
    return (StatusCode::BAD_REQUEST, Json(json!({})));
  }
  let tag = res.unwrap();

  let res = state
    .increment_counter(&handle, &tag, req.expected_counter)
    .await;
  if res.is_err() {
    return (StatusCode::CONFLICT, Json(json!({})));
  }
  let signature = res.unwrap();

  let resp = IncrementCounterResponse {
    signature: base64_url::encode(&signature),
  };

  (StatusCode::OK, Json(json!(resp)))
}
