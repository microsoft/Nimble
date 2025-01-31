use endpoint::{EndpointState, PublicKeyFormat, SignatureFormat};

use axum::{
  extract::{Extension, Path, Query},
  http::StatusCode,
  response::IntoResponse,
  routing::{get, put},
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
    )
    .arg(
      Arg::with_name("pem")
        .short("m")
        .long("pem")
        .takes_value(true)
        .help("The ECDSA prime256v1 private key pem file"),
    )
    .arg(
      Arg::with_name("channels")
        .short("l")
        .long("channels")
        .takes_value(true)
        .help("The number of grpc channels"),
    );
  let cli_matches = config.get_matches();
  let hostname = cli_matches.value_of("host").unwrap();
  let port_num = cli_matches.value_of("port").unwrap();
  let addr = format!("{}:{}", hostname, port_num).parse()?;
  let coordinator_hostname = cli_matches.value_of("coordinator").unwrap().to_string();
  let cert = cli_matches.value_of("cert");
  let key = cli_matches.value_of("key");
  let pem = cli_matches
    .value_of("pem")
    .map(|p| std::fs::read_to_string(p).expect("Failed to read the private key pem file"));

  let num_grpc_channels: Option<usize> = if let Some(x) = cli_matches.value_of("channels") {
    match x.to_string().parse() {
      Ok(v) => Some(v),
      Err(_) => panic!("Failed to parse the number of grpc channels"),
    }
  } else {
    None
  };

  let endpoint_state = Arc::new(
    EndpointState::new(coordinator_hostname, pem, num_grpc_channels)
      .await
      .unwrap(),
  );

  // Build our application by composing routes
  let app = Router::new()
      .route("/serviceid", get(get_identity))
      .route("/timeoutmap", get(get_timeout_map))
      .route("/pingallendorsers", get(ping_all_endorsers))
      .route("/addendorsers/:uri", put(add_endorsers))
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
  let job = if let Some(c) = cert {
    if let Some(k) = key {
      let config = RustlsConfig::from_pem_file(c, k).await.unwrap();

      tokio::spawn(async move {
        let _ = axum_server::bind_rustls(addr, config)
          .serve(app.into_make_service())
          .await;
      })
    } else {
      panic!("cert and key must be provided together!");
    }
  } else {
    tokio::spawn(async move {
      let _ = axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await;
    })
  };

  job.await?;

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

#[derive(Debug, Serialize, Deserialize)]
struct GetTimeoutMapResp {
  #[serde(rename = "signature")]
  pub signature: String,
  #[serde(rename = "timeout_map")]
  pub timeout_map: HashMap<String, u64>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PingAllResp {
  #[serde(rename = "signature")]
  pub signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AddEndorsersResp {
  #[serde(rename = "signature")]
  pub signature: String,
}

async fn get_identity(
  Query(params): Query<HashMap<String, String>>,
  Extension(state): Extension<Arc<EndpointState>>,
) -> impl IntoResponse {
  let pkformat = if !params.contains_key("pkformat") {
    PublicKeyFormat::UNCOMPRESSED
  } else {
    match params["pkformat"].as_ref() {
      "compressed" => PublicKeyFormat::COMPRESSED,
      "der" => PublicKeyFormat::DER,
      "uncompressed" => PublicKeyFormat::UNCOMPRESSED,
      _ => {
        eprintln!("unsupported format");
        return (StatusCode::BAD_REQUEST, Json(json!({})));
      },
    }
  };

  let (id, pk) = state.get_identity(pkformat).unwrap();
  let resp = GetIdentityResponse {
    id: base64_url::encode(&id),
    pk: base64_url::encode(&pk),
  };
  (StatusCode::OK, Json(json!(resp)))
}

async fn new_counter(
  Path(handle): Path<String>,
  Json(req): Json<NewCounterRequest>,
  Query(params): Query<HashMap<String, String>>,
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

  let sigformat = if params.contains_key("sigformat") {
    match params["sigformat"].as_ref() {
      "der" => SignatureFormat::DER,
      _ => SignatureFormat::RAW,
    }
  } else {
    SignatureFormat::RAW
  };

  let res = state.new_counter(&handle, &tag, sigformat).await;
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

  let sigformat = if params.contains_key("sigformat") {
    match params["sigformat"].as_ref() {
      "der" => SignatureFormat::DER,
      _ => SignatureFormat::RAW,
    }
  } else {
    SignatureFormat::RAW
  };

  let res = state.read_counter(&handle, &nonce, sigformat).await;
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
  Query(params): Query<HashMap<String, String>>,
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

  let sigformat = if params.contains_key("sigformat") {
    match params["sigformat"].as_ref() {
      "der" => SignatureFormat::DER,
      _ => SignatureFormat::RAW,
    }
  } else {
    SignatureFormat::RAW
  };

  let res = state
    .increment_counter(&handle, &tag, req.expected_counter, sigformat)
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

async fn get_timeout_map(
  Query(params): Query<HashMap<String, String>>,
  Extension(state): Extension<Arc<EndpointState>>,
) -> impl IntoResponse {

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

  let sigformat = if params.contains_key("sigformat") {
    match params["sigformat"].as_ref() {
      "der" => SignatureFormat::DER,
      _ => SignatureFormat::RAW,
    }
  } else {
    SignatureFormat::RAW
  };

  let res = state.get_timeout_map(&nonce, sigformat).await;
  if res.is_err() {
    eprintln!("failed to get the timeout map");
    return (StatusCode::CONFLICT, Json(json!({})));
  }
  let (signature, timeout_map) = res.unwrap();

  let resp = GetTimeoutMapResp {
    signature: base64_url::encode(&signature),
    timeout_map: timeout_map,
  };

  (StatusCode::OK, Json(json!(resp)))
}

async fn ping_all_endorsers(
  Query(params): Query<HashMap<String, String>>,
  Extension(state): Extension<Arc<EndpointState>>,
) -> impl IntoResponse {

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

  let sigformat = if params.contains_key("sigformat") {
    match params["sigformat"].as_ref() {
      "der" => SignatureFormat::DER,
      _ => SignatureFormat::RAW,
    }
  } else {
    SignatureFormat::RAW
  };

  let res = state.ping_all_endorsers(&nonce).await;
  if res.is_err() {
    eprintln!("failed to ping all endorsers");
    return (StatusCode::CONFLICT, Json(json!({})));
  }
  let (signature) = res.unwrap();

  let resp = PingAllResp {
    signature: base64_url::encode(&signature),
  };

  (StatusCode::OK, Json(json!(resp)))
}

async fn add_endorsers(
  Query(params): Query<HashMap<String, String>>,
  Extension(state): Extension<Arc<EndpointState>>,
) -> impl IntoResponse {

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

  if !params.contains_key("endorsers") {
    eprintln!("missing a uri endorsers");
    return (StatusCode::BAD_REQUEST, Json(json!({})));
  }

  let res = base64_url::decode(&params["endorsers"]);
  if res.is_err() {
    eprintln!("received no endorsers uri {:?}", res);
    return (StatusCode::BAD_REQUEST, Json(json!({})));
  }
  let endorsers = res.unwrap();
  let endorsers = endorsers.as_slice();
  let endorsers = std::str::from_utf8(endorsers);
  if endorsers.is_err() {
    eprintln!("received a bad endorsers uri {:?}", endorsers);
    return (StatusCode::BAD_REQUEST, Json(json!({})));
  }
  let endorsers = endorsers.unwrap();
  

  let sigformat = if params.contains_key("sigformat") {
    match params["sigformat"].as_ref() {
      "der" => SignatureFormat::DER,
      _ => SignatureFormat::RAW,
    }
  } else {
    SignatureFormat::RAW
  };

  let res = state.add_endorsers(&nonce, endorsers.to_string()).await;
  if res.is_err() {
    eprintln!("failed to add endorsers");
    return (StatusCode::CONFLICT, Json(json!({})));
  }
  let (signature) = res.unwrap();

  let resp = AddEndorsersResp {
    signature: base64_url::encode(&signature),
  };

  (StatusCode::OK, Json(json!(resp)))
}