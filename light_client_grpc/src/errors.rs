#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClientError {
  /// returned if the client uses as InvalidUri as endpoint hostname
  EndpointHostNameNotFound,
}
