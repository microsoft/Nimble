use crate::{
  errors::{LedgerStoreError, StorageError},
  LedgerEntry, LedgerStore,
};
use async_trait::async_trait;
use bincode;
use fs2::FileExt;
use hex;
use ledger::{Block, CustomSerde, Handle, NimbleDigest, Receipt};
use serde::{Deserialize, Serialize};
use std::{
  collections::HashMap,
  convert::TryFrom,
  fmt::Debug,
  fs,
  fs::{File, OpenOptions},
  io::{prelude::*, SeekFrom},
  path::{Path, PathBuf},
  sync::{Arc, RwLock},
};

const ENTRY_SIZE: usize = 1024; // total bytes in a ledger entry

macro_rules! checked_conversion {
  ($x:expr, $type:tt) => {
    match $type::try_from($x) {
      Err(_) => {
        return Err(LedgerStoreError::LedgerError(StorageError::IntegerOverflow));
      },
      Ok(v) => v,
    }
  };
}

type FileLock = Arc<RwLock<File>>;
type FileMap = Arc<RwLock<HashMap<Handle, FileLock>>>;

#[derive(Clone, Serialize, Deserialize, Debug)]
struct StoreEntry {
  pub block: Vec<u8>,
  pub receipt: Vec<u8>,
}

#[derive(Debug)]
pub struct FileStore {
  dir_path: PathBuf,
  open_files: FileMap,
  view_handle: Handle,
}

impl FileStore {
  pub async fn new(args: &HashMap<String, String>) -> Result<Self, LedgerStoreError> {
    if !args.contains_key("NIMBLE_FSTORE_DIR") {
      return Err(LedgerStoreError::LedgerError(
        StorageError::MissingArguments,
      ));
    }
    let dir_path = Path::new(&args["NIMBLE_FSTORE_DIR"]).to_path_buf();

    let view_handle = match NimbleDigest::from_bytes(&vec![0u8; NimbleDigest::num_bytes()]) {
      Ok(e) => e,
      Err(_) => {
        return Err(LedgerStoreError::LedgerError(
          StorageError::DeserializationError,
        ));
      },
    };

    // Try to create directory. If it exists that's fine.
    match fs::create_dir_all(&dir_path) {
      Ok(()) => (),
      Err(e) => {
        eprintln!("Unable to create path {:?}, error: {:?}", &dir_path, e);
        return Err(LedgerStoreError::LedgerError(StorageError::InvalidDBName));
      },
    };

    let open_files = Arc::new(RwLock::new(HashMap::new()));

    // Check if the view ledger exists, if not, create a new one
    let ledger_lock = open_and_lock(&view_handle, &dir_path, &open_files, true)?;

    let mut view_ledger = match ledger_lock.write() {
      Ok(v) => v,
      Err(_) => {
        return Err(LedgerStoreError::LedgerError(
          StorageError::ViewLedgerWriteLockFailed,
        ));
      },
    };

    let file_len = match view_ledger.metadata() {
      Ok(m) => m.len(),
      Err(e) => {
        eprintln!("Failed to access file metadata {:?}", e);
        return Err(LedgerStoreError::LedgerError(StorageError::UnhandledError));
      },
    };

    // If file is empty
    if file_len == 0 {
      // Initialized view ledger's entry
      let entry = StoreEntry {
        block: Block::new(&[0; 0]).to_bytes(),
        receipt: Receipt::default().to_bytes(),
      };

      // Guaranteed to be the size of 1 file entry
      let ser_entry = serialize_entry(&entry)?;

      write_at(SeekFrom::Start(0), &mut view_ledger, &ser_entry)?;
    }

    let file_store = FileStore {
      dir_path,
      open_files,
      view_handle,
    };

    Ok(file_store)
  }
}

fn serialize_entry(entry: &StoreEntry) -> Result<Vec<u8>, LedgerStoreError> {
  match bincode::serialize(&entry) {
    Ok(mut e) => {
      if e.len() < ENTRY_SIZE {
        e.resize(ENTRY_SIZE, 0);
        Ok(e)
      } else {
        Err(LedgerStoreError::LedgerError(StorageError::DataTooLarge))
      }
    },

    Err(_) => Err(LedgerStoreError::LedgerError(
      StorageError::SerializationError,
    )),
  }
}

// reads value into buf
fn read_at(index: SeekFrom, ledger: &mut File, buf: &mut [u8]) -> Result<(), LedgerStoreError> {
  match ledger.seek(index) {
    Ok(_) => {},
    Err(e) => {
      eprintln!("Failed to seek {:?}", e);
      return Err(LedgerStoreError::LedgerError(StorageError::UnhandledError));
    },
  }

  match ledger.read(buf) {
    Ok(n) => {
      if n != ENTRY_SIZE {
        eprintln!("Read only {} bytes instead of {}", n, ENTRY_SIZE);
        return Err(LedgerStoreError::LedgerError(StorageError::UnhandledError));
      }
    },
    Err(e) => {
      eprintln!("Failed to read {:?}", e);
      return Err(LedgerStoreError::LedgerError(StorageError::UnhandledError));
    },
  }

  Ok(())
}

fn write_at(index: SeekFrom, ledger: &mut File, buf: &[u8]) -> Result<(), LedgerStoreError> {
  match ledger.seek(index) {
    Ok(_) => {},
    Err(e) => {
      eprintln!("Failed to seek {:?}", e);
      return Err(LedgerStoreError::LedgerError(StorageError::UnhandledError));
    },
  }

  match ledger.write(buf) {
    Ok(n) => {
      if n != ENTRY_SIZE {
        eprintln!("Wrote only {} bytes instead of {}", n, ENTRY_SIZE);
        return Err(LedgerStoreError::LedgerError(StorageError::UnhandledError));
      }
    },
    Err(e) => {
      eprintln!("Failed to write {:?}", e);
      return Err(LedgerStoreError::LedgerError(StorageError::UnhandledError));
    },
  }

  Ok(())
}

fn open_and_lock(
  handle: &Handle,
  dir_path: &Path,
  file_map: &FileMap,
  create_flag: bool,
) -> Result<FileLock, LedgerStoreError> {
  let map = match file_map.read() {
    Ok(m) => m,
    Err(_) => {
      return Err(LedgerStoreError::LedgerError(
        StorageError::LedgerReadLockFailed,
      ));
    },
  };

  if let Some(entry) = map.get(handle) {
    Ok(entry.clone())
  } else {
    drop(map); // drops read lock on map

    // Check if the ledger exists.
    let mut options = OpenOptions::new();
    let file_name = dir_path.join(&hex::encode(&handle.to_bytes()));
    let ledger = match options
      .read(true)
      .write(true)
      .create(create_flag)
      .open(&file_name)
    {
      Ok(f) => f,
      Err(e) => {
        eprintln!("Error opening view file {:?}", e);
        return Err(LedgerStoreError::LedgerError(StorageError::InvalidKey));
      },
    };

    // Acquire exclusive lock on file
    if ledger.try_lock_exclusive().is_err() {
      return Err(LedgerStoreError::LedgerError(
        StorageError::LedgerWriteLockFailed,
      ));
    }

    let mut map = match file_map.write() {
      Ok(v) => v,
      Err(_) => {
        return Err(LedgerStoreError::LedgerError(
          StorageError::LedgerWriteLockFailed,
        ));
      },
    };

    let ledger_arc = Arc::new(RwLock::new(ledger));

    map.insert(*handle, ledger_arc.clone());
    Ok(ledger_arc)
  }
}

async fn read_ledger_op(
  handle: &Handle,
  req_idx: Option<usize>,
  dir_path: &Path,
  file_map: &FileMap,
) -> Result<(LedgerEntry, usize), LedgerStoreError> {
  let ledger_lock = open_and_lock(handle, dir_path, file_map, false)?;

  let mut ledger = match ledger_lock.write() {
    Ok(v) => v,
    Err(_) => {
      return Err(LedgerStoreError::LedgerError(
        StorageError::LedgerWriteLockFailed,
      ));
    },
  };

  // Find where to seek
  let index = match req_idx {
    Some(idx) => idx,
    None => match ledger.metadata() {
      Ok(m) => {
        if checked_conversion!(m.len(), usize) < ENTRY_SIZE {
          eprintln!("Trying to read an empty file");
          return Err(LedgerStoreError::LedgerError(StorageError::UnhandledError));
        }

        (checked_conversion!(m.len(), usize) / ENTRY_SIZE) - 1
      },
      Err(e) => {
        eprintln!("Failed to access file metadata {:?}", e);
        return Err(LedgerStoreError::LedgerError(StorageError::UnhandledError));
      },
    },
  };

  let offset = match index.checked_mul(ENTRY_SIZE) {
    Some(v) => checked_conversion!(v, u64),
    None => {
      return Err(LedgerStoreError::LedgerError(StorageError::InvalidIndex));
    },
  };

  let mut serialized_entry = [0; ENTRY_SIZE];
  read_at(SeekFrom::Start(offset), &mut ledger, &mut serialized_entry)?;

  let entry: StoreEntry = match bincode::deserialize(&serialized_entry) {
    Ok(e) => e,
    Err(_) => {
      return Err(LedgerStoreError::LedgerError(
        StorageError::DeserializationError,
      ));
    },
  };

  // 3. Return ledger entry by deserializing its contents
  Ok((
    LedgerEntry::new(
      Block::from_bytes(&entry.block).unwrap(),
      Receipt::from_bytes(&entry.receipt).unwrap(),
    ),
    index,
  ))
}

#[async_trait]
impl LedgerStore for FileStore {
  async fn create_ledger(
    &self,
    handle: &Handle,
    genesis_block: Block,
  ) -> Result<(), LedgerStoreError> {
    // 1. Create and lock file
    let ledger_lock = open_and_lock(handle, &self.dir_path, &self.open_files, true)?;

    let mut ledger = match ledger_lock.write() {
      Ok(v) => v,
      Err(_) => {
        return Err(LedgerStoreError::LedgerError(
          StorageError::LedgerWriteLockFailed,
        ));
      },
    };

    // 2. Check if non-empty file
    match ledger.metadata() {
      Ok(m) => {
        if m.len() > 0 {
          return Err(LedgerStoreError::LedgerError(StorageError::DuplicateKey));
        }
      },
      Err(e) => {
        eprintln!("Failed to access file metadata {:?}", e);
        return Err(LedgerStoreError::LedgerError(StorageError::UnhandledError));
      },
    };

    // 3. Create the ledger entry that we will add to the brand new ledger
    let init_entry = StoreEntry {
      block: genesis_block.to_bytes(),
      receipt: Receipt::default().to_bytes(),
    };

    // Serialize the entry
    let ser_entry = serialize_entry(&init_entry)?;
    write_at(SeekFrom::Start(0), &mut ledger, &ser_entry)?;

    Ok(())
  }

  async fn append_ledger(
    &self,
    handle: &Handle,
    block: &Block,
    expected_height: Option<usize>,
  ) -> Result<usize, LedgerStoreError> {
    let ledger_lock = open_and_lock(handle, &self.dir_path, &self.open_files, false)?;

    let mut ledger = match ledger_lock.write() {
      Ok(v) => v,
      Err(_) => {
        return Err(LedgerStoreError::LedgerError(
          StorageError::LedgerWriteLockFailed,
        ));
      },
    };

    let next_index = match ledger.metadata() {
      Ok(m) => checked_conversion!(m.len(), usize) / ENTRY_SIZE,
      Err(e) => {
        eprintln!("Failed to access file metadata {:?}", e);
        return Err(LedgerStoreError::LedgerError(StorageError::UnhandledError));
      },
    };

    // 1. If it is a conditional update, check if condition still holds
    if expected_height.is_some() && expected_height.unwrap() != next_index {
      eprintln!(
        "Expected height {};  Height-plus-one: {}",
        expected_height.unwrap(),
        next_index
      );

      return Err(LedgerStoreError::LedgerError(
        StorageError::IncorrectConditionalData,
      ));
    }

    // 2. Construct the new entry we are going to append to the ledger
    let new_entry = StoreEntry {
      block: block.to_bytes(),
      receipt: Receipt::default().to_bytes(),
    };

    let ser_entry = serialize_entry(&new_entry)?;

    write_at(SeekFrom::End(0), &mut ledger, &ser_entry)?;
    Ok(next_index)
  }

  async fn attach_ledger_receipt(
    &self,
    handle: &Handle,
    receipt: &Receipt,
  ) -> Result<(), LedgerStoreError> {
    // 1. Get the desired offset
    let offset = match receipt.get_height().checked_mul(ENTRY_SIZE) {
      Some(v) => checked_conversion!(v, u64),
      None => {
        return Err(LedgerStoreError::LedgerError(StorageError::InvalidIndex));
      },
    };

    let ledger_lock = open_and_lock(handle, &self.dir_path, &self.open_files, false)?;

    let mut ledger = match ledger_lock.write() {
      Ok(v) => v,
      Err(_) => {
        return Err(LedgerStoreError::LedgerError(
          StorageError::LedgerWriteLockFailed,
        ));
      },
    };

    let seek_from = SeekFrom::Start(offset);

    // 2. Find the appropriate entry in the ledger
    let mut serialized_entry = [0; ENTRY_SIZE];
    read_at(seek_from, &mut ledger, &mut serialized_entry)?;

    let mut ledger_entry: StoreEntry = match bincode::deserialize(&serialized_entry) {
      Ok(e) => e,
      Err(_) => {
        return Err(LedgerStoreError::LedgerError(
          StorageError::DeserializationError,
        ));
      },
    };

    // 3. Recover the contents of the ledger entry
    let mut ledger_entry_receipt =
      Receipt::from_bytes(&ledger_entry.receipt).expect("failed to deserialize receipt");

    // 4. Update receipt
    let res = ledger_entry_receipt.append(receipt);

    if res.is_err() {
      return Err(LedgerStoreError::LedgerError(
        StorageError::MismatchedReceipts,
      ));
    }
    ledger_entry.receipt = ledger_entry_receipt.to_bytes();

    // 5. Re-serialize
    let ser_entry = serialize_entry(&ledger_entry)?;

    // 6. Update entry
    write_at(seek_from, &mut ledger, &ser_entry)?;

    Ok(())
  }

  async fn read_ledger_tail(&self, handle: &Handle) -> Result<(Block, usize), LedgerStoreError> {
    let (ledger_entry, height) =
      read_ledger_op(handle, None, &self.dir_path, &self.open_files).await?;
    Ok((ledger_entry.block, height))
  }

  async fn read_ledger_by_index(
    &self,
    handle: &Handle,
    index: usize,
  ) -> Result<LedgerEntry, LedgerStoreError> {
    let (ledger_entry, _height) =
      read_ledger_op(handle, Some(index), &self.dir_path, &self.open_files).await?;
    Ok(ledger_entry)
  }

  async fn read_view_ledger_tail(&self) -> Result<(Block, usize), LedgerStoreError> {
    self.read_ledger_tail(&self.view_handle).await
  }

  async fn read_view_ledger_by_index(&self, idx: usize) -> Result<LedgerEntry, LedgerStoreError> {
    self.read_ledger_by_index(&self.view_handle, idx).await
  }

  async fn attach_view_ledger_receipt(&self, receipt: &Receipt) -> Result<(), LedgerStoreError> {
    self.attach_ledger_receipt(&self.view_handle, receipt).await
  }

  async fn append_view_ledger(
    &self,
    block: &Block,
    expected_height: Option<usize>,
  ) -> Result<usize, LedgerStoreError> {
    self
      .append_ledger(&self.view_handle, block, expected_height)
      .await
  }

  async fn reset_store(&self) -> Result<(), LedgerStoreError> {
    match fs::remove_dir_all(&self.dir_path) {
      Ok(_) => Ok(()),
      Err(e) => {
        eprintln!("Error opening view file {:?}", e);
        return Err(LedgerStoreError::LedgerError(StorageError::UnhandledError));
      },
    }
  }
}
