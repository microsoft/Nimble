use endpoint::EndpointState;

use axum::{
  body::Bytes,
  extract::Extension,
  http::StatusCode,
  response::IntoResponse,
  routing::{get, put},
  Router,
};
use std::{net::SocketAddr, sync::Arc};
use tower::ServiceBuilder;

use clap::{App, Arg};

use serde_derive::{Deserialize, Serialize};

#[tokio::main]
async fn main() {
  let (port, coordinator_hostname) = {
    let config = App::new("endpoint")
      .arg(
        Arg::with_name("coordinator")
          .short("c")
          .long("coordinator")
          .help("The hostname of the coordinator")
          .default_value("http://[::1]:8080"),
      )
      .arg(
        Arg::with_name("port")
          .short("p")
          .long("port")
          .help("The port number to run the coordinator service on.")
          .default_value("8082"),
      );
    let cli_matches = config.get_matches();
    let port_number: u16 = cli_matches.value_of("port").unwrap().parse().unwrap();
    let coordinator_hostname = cli_matches.value_of("coordinator").unwrap().to_string();

    (port_number, coordinator_hostname)
  };

  let endpoint_state = Arc::new(EndpointState::new(coordinator_hostname).await.unwrap());

  // Build our application by composing routes
  let app = Router::new()
      .route("/getidentity", get(get_identity))
      .route("/newcounter", put(new_counter))
      .route("/incrementcounter", put(increment_counter))
      .route("/readcounter", get(read_counter))
      // Add middleware to all routes
      .layer(
          ServiceBuilder::new()
              // Handle errors from middleware
              .layer(Extension(endpoint_state))
              .into_inner(),
      );

  // Run our app with hyper
  let addr = SocketAddr::from(([127, 0, 0, 1], port));
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
  #[serde(rename = "Handle")]
  pub handle: String,
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
  #[serde(rename = "Handle")]
  pub handle: String,
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
struct ReadCounterRequest {
  #[serde(rename = "Handle")]
  pub handle: String,
  #[serde(rename = "Nonce")]
  pub nonce: String,
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

static XML_DECLARATION: &str = "<?xml version=\"1.0\" encoding=\"utf-8\"?>";

async fn get_identity(Extension(state): Extension<Arc<EndpointState>>) -> impl IntoResponse {
  let (id, pk) = state.get_identity().unwrap();
  let resp = GetIdentityResponse {
    id: base64::encode(id),
    pk: base64::encode(pk),
  };
  let xml_output = format!(
    "{}{}",
    XML_DECLARATION,
    serde_xml_rs::ser::to_string(&resp).unwrap()
  );
  axum::http::Response::builder()
    .status(StatusCode::OK)
    .header(axum::http::header::CONTENT_TYPE, "application/xml")
    .body(axum::body::Body::from(xml_output))
    .unwrap();
}

async fn new_counter(
  body: Bytes,
  Extension(state): Extension<Arc<EndpointState>>,
) -> impl IntoResponse {
  let body_str = String::from_utf8(body.to_vec()).unwrap();
  let res = serde_xml_rs::de::from_str(&body_str);
  if res.is_err() {
    let err_msg = "Failed to parse the xml input".to_string();
    return axum::http::Response::builder()
      .status(StatusCode::BAD_REQUEST)
      .body(axum::body::Body::from(err_msg))
      .unwrap();
  }
  let new_counter_req: NewCounterRequest = res.unwrap();

  let res = base64::decode(&new_counter_req.handle);
  if res.is_err() {
    let err_msg = "Failed to decode the handle".to_string();
    return axum::http::Response::builder()
      .status(StatusCode::BAD_REQUEST)
      .body(axum::body::Body::from(err_msg))
      .unwrap();
  }
  let handle = res.unwrap();

  let res = base64::decode(&new_counter_req.tag);
  if res.is_err() {
    let err_msg = "Failed to decode the tag".to_string();
    return axum::http::Response::builder()
      .status(StatusCode::BAD_REQUEST)
      .body(axum::body::Body::from(err_msg))
      .unwrap();
  }
  let tag = res.unwrap();

  let res = state.new_counter(&handle, &tag).await;
  if res.is_err() {
    let err_msg = "Failed to create the new counter".to_string();
    return axum::http::Response::builder()
      .status(StatusCode::CONFLICT)
      .body(axum::body::Body::from(err_msg))
      .unwrap();
  }
  let signature = res.unwrap();

  let resp = NewCounterResponse {
    signature: base64::encode(signature),
  };
  let xml_output = format!(
    "{}{}",
    XML_DECLARATION,
    serde_xml_rs::ser::to_string(&resp).unwrap()
  );
  axum::http::Response::builder()
    .status(StatusCode::OK)
    .body(axum::body::Body::from(xml_output))
    .unwrap()
}

async fn read_counter(
  body: Bytes,
  Extension(state): Extension<Arc<EndpointState>>,
) -> impl IntoResponse {
  let body_str = String::from_utf8(body.to_vec()).unwrap();
  let res = serde_xml_rs::de::from_str(&body_str);
  if res.is_err() {
    let err_msg = "Failed to parse the xml input".to_string();
    return axum::http::Response::builder()
      .status(StatusCode::BAD_REQUEST)
      .body(axum::body::Body::from(err_msg))
      .unwrap();
  }
  let read_counter_req: ReadCounterRequest = res.unwrap();

  let res = base64::decode(&read_counter_req.handle);
  if res.is_err() {
    let err_msg = "Failed to decode the handle".to_string();
    return axum::http::Response::builder()
      .status(StatusCode::BAD_REQUEST)
      .body(axum::body::Body::from(err_msg))
      .unwrap();
  }
  let handle = res.unwrap();

  let res = base64::decode(&read_counter_req.nonce);
  if res.is_err() {
    let err_msg = "Failed to decode the nonce".to_string();
    return axum::http::Response::builder()
      .status(StatusCode::BAD_REQUEST)
      .body(axum::body::Body::from(err_msg))
      .unwrap();
  }
  let nonce = res.unwrap();

  let res = state.read_counter(&handle, &nonce).await;
  if res.is_err() {
    let err_msg = "Failed to read the counter".to_string();
    return axum::http::Response::builder()
      .status(StatusCode::CONFLICT)
      .body(axum::body::Body::from(err_msg))
      .unwrap();
  }
  let (tag, counter, signature) = res.unwrap();

  let resp = ReadCounterResponse {
    tag: base64::encode(tag),
    counter,
    signature: base64::encode(signature),
  };
  let xml_output = format!(
    "{}{}",
    XML_DECLARATION,
    serde_xml_rs::ser::to_string(&resp).unwrap()
  );
  axum::http::Response::builder()
    .status(StatusCode::OK)
    .body(axum::body::Body::from(xml_output))
    .unwrap()
}

async fn increment_counter(
  body: Bytes,
  Extension(state): Extension<Arc<EndpointState>>,
) -> impl IntoResponse {
  let body_str = String::from_utf8(body.to_vec()).unwrap();
  let res = serde_xml_rs::de::from_str(&body_str);
  if res.is_err() {
    let err_msg = "Failed to parse the xml input".to_string();
    return axum::http::Response::builder()
      .status(StatusCode::BAD_REQUEST)
      .body(axum::body::Body::from(err_msg))
      .unwrap();
  }
  let increment_counter_req: IncrementCounterRequest = res.unwrap();

  let res = base64::decode(&increment_counter_req.handle);
  if res.is_err() {
    let err_msg = "Failed to decode the handle".to_string();
    return axum::http::Response::builder()
      .status(StatusCode::BAD_REQUEST)
      .body(axum::body::Body::from(err_msg))
      .unwrap();
  }
  let handle = res.unwrap();

  let res = base64::decode(&increment_counter_req.tag);
  if res.is_err() {
    let err_msg = "Failed to decode the tag".to_string();
    return axum::http::Response::builder()
      .status(StatusCode::BAD_REQUEST)
      .body(axum::body::Body::from(err_msg))
      .unwrap();
  }
  let tag = res.unwrap();

  let res = state
    .increment_counter(&handle, &tag, increment_counter_req.expected_counter)
    .await;
  if res.is_err() {
    let err_msg = "Failed to increment the counter".to_string();
    return axum::http::Response::builder()
      .status(StatusCode::CONFLICT)
      .body(axum::body::Body::from(err_msg))
      .unwrap();
  }
  let signature = res.unwrap();

  let resp = IncrementCounterResponse {
    signature: base64::encode(signature),
  };
  let xml_output = format!(
    "{}{}",
    XML_DECLARATION,
    serde_xml_rs::ser::to_string(&resp).unwrap()
  );
  axum::http::Response::builder()
    .status(StatusCode::OK)
    .body(axum::body::Body::from(xml_output))
    .unwrap()
}
