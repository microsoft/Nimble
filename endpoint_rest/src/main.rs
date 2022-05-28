use endpoint::EndpointState;

use axum::{
  extract::{Extension, Path, Query},
  http::StatusCode,
  response::IntoResponse,
  routing::get,
  Json, Router,
};
use axum_server::tls_rustls::RustlsConfig;
use serde_json::json;
use std::{collections::HashMap, sync::Arc};
use tower::ServiceBuilder;

use clap::{App, Arg};

use serde::{Deserialize, Serialize};

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
        .default_value("8082"),
    )
    .arg(
      Arg::with_name("cert")
        .short("e")
        .long("cert")
        .takes_value(true)
        .help("The certificate to run tls"),
    )
    .arg(
      Arg::with_name("key")
        .short("k")
        .long("key")
        .takes_value(true)
        .help("The key to run tls"),
    );
  let cli_matches = config.get_matches();
  let hostname = cli_matches.value_of("host").unwrap();
  let port_num = cli_matches.value_of("port").unwrap();
  let addr = format!("{}:{}", hostname, port_num).parse()?;
  let coordinator_hostname = cli_matches.value_of("coordinator").unwrap().to_string();
  let cert = cli_matches.value_of("cert");
  let key = cli_matches.value_of("key");

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
  println!("Running endpoint at {}", addr);
  if let Some(c) = cert {
    if let Some(k) = key {
      let config = RustlsConfig::from_pem_file(c, k).await.unwrap();

      axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await
        .unwrap();
    } else {
      panic!("cert and key must be provided together!");
    }
  } else {
    axum::Server::bind(&addr)
      .serve(app.into_make_service())
      .await
      .unwrap();
  }
  Ok(())
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
    eprintln!("received a bad handle {:?}", res);
    return (StatusCode::BAD_REQUEST, Json(json!({})));
  }
  let handle = res.unwrap();

  let res = base64_url::decode(&req.tag);
  if res.is_err() {
    eprintln!("received a bad tag {:?}", res);
    return (StatusCode::BAD_REQUEST, Json(json!({})));
  }
  let tag = res.unwrap();

  let res = state.new_counter(&handle, &tag).await;
  if res.is_err() {
    eprintln!("failed to create a new counter {:?}", res);
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
    eprintln!("received a bad handle {:?}", res);
    return (StatusCode::BAD_REQUEST, Json(json!({})));
  }
  let handle = res.unwrap();

  if !params.contains_key("nonce") {
    eprintln!("missing a nonce");
    return (StatusCode::BAD_REQUEST, Json(json!({})));
  }
  let res = base64_url::decode(&params["nonce"]);
  if res.is_err() {
    eprintln!("received a bad nonce {:?}", res);
    return (StatusCode::BAD_REQUEST, Json(json!({})));
  }
  let nonce = res.unwrap();

  let res = state.read_counter(&handle, &nonce).await;
  if res.is_err() {
    eprintln!("failed to read a counter {:?}", res);
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
    eprintln!("received a bad handle {:?}", res);
    return (StatusCode::BAD_REQUEST, Json(json!({})));
  }
  let handle = res.unwrap();

  let res = base64_url::decode(&req.tag);
  if res.is_err() {
    eprintln!("received a bad tag {:?}", res);
    return (StatusCode::BAD_REQUEST, Json(json!({})));
  }
  let tag = res.unwrap();

  let res = state
    .increment_counter(&handle, &tag, req.expected_counter)
    .await;
  if res.is_err() {
    eprintln!("failed to increment a counter {:?}", res);
    return (StatusCode::CONFLICT, Json(json!({})));
  }
  let signature = res.unwrap();

  let resp = IncrementCounterResponse {
    signature: base64_url::encode(&signature),
  };

  (StatusCode::OK, Json(json!(resp)))
}
