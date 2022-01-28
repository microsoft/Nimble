use super::{Block, Handle, MetaBlock, NimbleDigest, NimbleHashTrait, Receipt};
use crate::errors::StorageError;

pub mod in_memory;

#[derive(Debug, Default, Clone)]
pub struct LedgerEntry {
  pub block: Block,
  pub aux: MetaBlock,
  pub receipt: Receipt,
}

pub trait LedgerStore {
  fn new() -> Result<Self, StorageError>
  where
    Self: Sized;
  fn create_ledger(&self, block: &Block)
    -> Result<(Handle, MetaBlock, NimbleDigest), StorageError>;
  fn append_ledger(
    // TODO: should self be mutable?
    &self,
    handle: &Handle,
    block: &Block,
    cond: &NimbleDigest,
  ) -> Result<(MetaBlock, NimbleDigest), StorageError>;
  fn attach_ledger_receipt(
    &self,
    handle: &Handle,
    aux: &MetaBlock,
    receipt: &Receipt,
  ) -> Result<(), StorageError>;
  fn read_ledger_tail(&self, handle: &Handle) -> Result<LedgerEntry, StorageError>;
  fn read_leger_by_index(&self, handle: &Handle, idx: usize) -> Result<LedgerEntry, StorageError>;
  fn append_view_ledger(&self, block: &Block) -> Result<(MetaBlock, NimbleDigest), StorageError>;
  fn attach_view_leger_receipt(
    &self,
    aux: &MetaBlock,
    receipt: &Receipt,
  ) -> Result<(), StorageError>;
  fn read_view_ledger_tail(&self) -> Result<LedgerEntry, StorageError>;
  fn read_view_ledger_by_index(&self, idx: usize) -> Result<LedgerEntry, StorageError>;
}
