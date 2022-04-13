#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EndpointError {
  /// returned if the endpoint uses as InvalidUri as Coordinator hostname
  CoordinatorHostNameNotFound,
  /// returned if the endpoint fails to connect to the Coordinator while creating a channel
  UnableToConnectToCoordinator,
}
