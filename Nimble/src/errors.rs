use core::fmt::Debug;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EndorserError {
  /// returned if the supplied ledger name is invalid
  InvalidLedgerName,
  /// returned if one attempts to create a ledger that already exists
  LedgerExists,
  /// returned if one attempts to perform a conditional append and the condition check fails
  TailDoesNotMatch,
}
