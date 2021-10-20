#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EndorserError {
  /// returned if the supplied ledger name is invalid
  InvalidLedgerName,
  /// returned if one attempts to create a ledger that already exists
  LedgerExists,
  /// returned if the creation of the endorser state fails
  StateCreationError,
  /// returned if the increment results in overflow of ledger height
  LedgerHeightOverflow,
}
