use crate::errors::CoordinatorError;
use ledger::{
  signature::{PublicKey, PublicKeyTrait},
  Handle, NimbleDigest, Nonce, Receipt,
};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tonic::transport::{Channel, Endpoint};

pub mod endorser_proto {
  tonic::include_proto!("endorser_proto");
}

use endorser_proto::endorser_call_client::EndorserCallClient;
use endorser_proto::{
  AppendReq, AppendResp, AppendViewLedgerReq, AppendViewLedgerResp, GetPublicKeyReq,
  GetPublicKeyResp, InitializeStateReq, InitializeStateResp, LedgerTailMapEntry, NewLedgerReq,
  NewLedgerResp, ReadLatestReq, ReadLatestResp, ReadLatestViewLedgerReq, ReadLatestViewLedgerResp,
};

#[derive(Debug, Default)]
pub struct ConnectionStore {
  store: Arc<RwLock<HashMap<Vec<u8>, EndorserCallClient<Channel>>>>,
}

impl ConnectionStore {
  pub fn new() -> ConnectionStore {
    ConnectionStore {
      store: Arc::new(RwLock::new(HashMap::new())),
    }
  }

  pub fn get_all(&self) -> Vec<Vec<u8>> {
    self
      .store
      .read()
      .expect("Failed to get the read lock")
      .iter()
      .map(|(pk, _ec)| pk.clone())
      .collect::<Vec<Vec<u8>>>()
  }

  pub async fn connect_endorser(&mut self, hostname: String) -> Result<Vec<u8>, CoordinatorError> {
    let res = Endpoint::from_shared(hostname.to_string());
    if res.is_err() {
      return Err(CoordinatorError::CannotResolveHostName);
    }
    let endorser_endpoint = res.unwrap();
    let channel = endorser_endpoint.connect_lazy();
    let mut client = EndorserCallClient::new(channel);

    let req = tonic::Request::new(GetPublicKeyReq {});
    let res = client.get_public_key(req).await;
    if res.is_err() {
      return Err(CoordinatorError::FailedToConnectToEndorser);
    }
    let GetPublicKeyResp { pk } = res.unwrap().into_inner();
    println!("Connected Successfully to {:?}", &hostname);

    let res = PublicKey::from_bytes(&pk);
    if res.is_err() {
      return Err(CoordinatorError::UnableToRetrievePublicKey);
    }

    self
      .store
      .write()
      .expect("Failed to get write lock")
      .insert(pk.clone(), client);

    Ok(pk)
  }

  pub async fn initialize_state(
    &mut self,
    ledger_tail_map: &HashMap<NimbleDigest, (NimbleDigest, usize)>,
    view_ledger_tail_height: &(NimbleDigest, usize),
    block_hash: &NimbleDigest,
    cond_updated_tail_hash: &NimbleDigest,
  ) -> Result<Receipt, CoordinatorError> {
    let ledger_tail_map_proto: Vec<LedgerTailMapEntry> = ledger_tail_map
      .iter()
      .map(|(handle, (tail, height))| LedgerTailMapEntry {
        handle: handle.to_bytes(),
        tail: tail.to_bytes(),
        height: *height as u64,
      })
      .collect();

    let mut jobs = Vec::new();
    for (index, (_pk, ec)) in self
      .store
      .read()
      .expect("Failed to get the read lock")
      .iter()
      .enumerate()
    {
      let mut endorser_client = ec.clone();
      let ledger_tail_map = ledger_tail_map_proto.clone();
      let view_ledger_tail = view_ledger_tail_height.0.to_bytes();
      let view_ledger_height = view_ledger_tail_height.1 as u64;
      let block_hash = block_hash.to_bytes();
      let cond_updated_tail_hash = cond_updated_tail_hash.to_bytes();
      let job = tokio::spawn(async move {
        let response = endorser_client
          .initialize_state(tonic::Request::new(InitializeStateReq {
            ledger_tail_map,
            view_ledger_tail,
            view_ledger_height,
            block_hash,
            cond_updated_tail_hash,
          }))
          .await;
        (index, response)
      });
      jobs.push(job);
    }

    let mut receipt_bytes: Vec<(usize, Vec<u8>)> = Vec::new();
    for job in jobs {
      let res = job.await;
      if let Ok((index, Ok(resp))) = res {
        let InitializeStateResp { signature } = resp.into_inner();
        receipt_bytes.push((index, signature));
      }
    }
    let receipt = ledger::Receipt::from_bytes(&receipt_bytes);
    Ok(receipt)
  }

  pub async fn create_ledger(&self, ledger_handle: &Handle) -> Result<Receipt, CoordinatorError> {
    let mut jobs = Vec::new();
    for (index, (_pk, ec)) in self
      .store
      .read()
      .expect("Failed to get the read lock")
      .iter()
      .enumerate()
    {
      let mut endorser_client = ec.clone();
      let handle = *ledger_handle;
      let job = tokio::spawn(async move {
        let response = endorser_client
          .new_ledger(tonic::Request::new(NewLedgerReq {
            handle: handle.to_bytes(),
          }))
          .await;
        (index, response)
      });
      jobs.push(job);
    }

    let mut receipt_bytes: Vec<(usize, Vec<u8>)> = Vec::new();
    for job in jobs {
      let res = job.await;
      if let Ok((index, Ok(resp))) = res {
        let NewLedgerResp { signature } = resp.into_inner();
        receipt_bytes.push((index, signature));
      }
    }
    let receipt = ledger::Receipt::from_bytes(&receipt_bytes);
    Ok(receipt)
  }

  pub async fn append_ledger(
    &self,
    ledger_handle: &Handle,
    block_hash: &NimbleDigest,
    tail_hash: &NimbleDigest,
  ) -> Result<Receipt, CoordinatorError> {
    let mut jobs = Vec::new();
    for (index, (_pk, ec)) in self
      .store
      .read()
      .expect("Failed to get the read lock")
      .iter()
      .enumerate()
    {
      let mut endorser_client = ec.clone();
      let handle = *ledger_handle;
      let block = *block_hash;
      let tail = *tail_hash;
      let job = tokio::spawn(async move {
        let response = endorser_client
          .append(tonic::Request::new(AppendReq {
            handle: handle.to_bytes(),
            block_hash: block.to_bytes(),
            cond_updated_tail_hash: tail.to_bytes(),
          }))
          .await;
        (index, response)
      });
      jobs.push(job);
    }

    let mut receipt_bytes: Vec<(usize, Vec<u8>)> = Vec::new();
    for job in jobs {
      let res = job.await;
      if let Ok((index, Ok(resp))) = res {
        let AppendResp { signature } = resp.into_inner();
        receipt_bytes.push((index, signature));
      }
    }
    let receipt = ledger::Receipt::from_bytes(&receipt_bytes);
    Ok(receipt)
  }

  pub async fn read_ledger_tail(
    &self,
    ledger_handle: &Handle,
    client_nonce: &Nonce,
  ) -> Result<Receipt, CoordinatorError> {
    let mut jobs = Vec::new();
    for (index, (_pk, ec)) in self
      .store
      .read()
      .expect("Failed to get the read lock")
      .iter()
      .enumerate()
    {
      let mut endorser_client = ec.clone();
      let handle = *ledger_handle;
      let nonce = *client_nonce;
      let job = tokio::spawn(async move {
        let response = endorser_client
          .read_latest(tonic::Request::new(ReadLatestReq {
            handle: handle.to_bytes(),
            nonce: nonce.get(),
          }))
          .await;
        (index, response)
      });
      jobs.push(job);
    }

    let mut receipt_bytes: Vec<(usize, Vec<u8>)> = Vec::new();
    for job in jobs {
      let res = job.await;
      if let Ok((index, Ok(resp))) = res {
        let ReadLatestResp { signature } = resp.into_inner();
        receipt_bytes.push((index, signature));
      }
    }
    let receipt = ledger::Receipt::from_bytes(&receipt_bytes);
    Ok(receipt)
  }

  #[allow(dead_code)]
  pub async fn append_view_ledger(
    &self,
    block_hash: &NimbleDigest,
    tail_hash: &NimbleDigest,
  ) -> Result<Receipt, CoordinatorError> {
    let mut jobs = Vec::new();
    for (index, (_pk, ec)) in self
      .store
      .read()
      .expect("Failed to get the read lock")
      .iter()
      .enumerate()
    {
      let mut endorser_client = ec.clone();
      let block = *block_hash;
      let tail = *tail_hash;
      let job = tokio::spawn(async move {
        let response = endorser_client
          .append_view_ledger(tonic::Request::new(AppendViewLedgerReq {
            block_hash: block.to_bytes(),
            cond_updated_tail_hash: tail.to_bytes(),
          }))
          .await;
        (index, response)
      });
      jobs.push(job);
    }

    let mut receipt_bytes: Vec<(usize, Vec<u8>)> = Vec::new();
    for job in jobs {
      let res = job.await;
      if let Ok((index, Ok(resp))) = res {
        let AppendViewLedgerResp { signature } = resp.into_inner();
        receipt_bytes.push((index, signature));
      }
    }
    let receipt = ledger::Receipt::from_bytes(&receipt_bytes);
    Ok(receipt)
  }

  #[allow(dead_code)]
  pub async fn read_view_ledger_tail(
    &self,
    client_nonce: &Nonce,
  ) -> Result<Receipt, CoordinatorError> {
    let mut jobs = Vec::new();
    for (index, (_pk, ec)) in self
      .store
      .read()
      .expect("Failed to get the read lock")
      .iter()
      .enumerate()
    {
      let mut endorser_client = ec.clone();
      let nonce = *client_nonce;
      let job = tokio::spawn(async move {
        let response = endorser_client
          .read_latest_view_ledger(tonic::Request::new(ReadLatestViewLedgerReq {
            nonce: nonce.get(),
          }))
          .await;
        (index, response)
      });
      jobs.push(job);
    }

    let mut receipt_bytes: Vec<(usize, Vec<u8>)> = Vec::new();
    for job in jobs {
      let res = job.await;
      if let Ok((index, Ok(resp))) = res {
        let ReadLatestViewLedgerResp { signature } = resp.into_inner();
        receipt_bytes.push((index, signature));
      }
    }
    let receipt = ledger::Receipt::from_bytes(&receipt_bytes);
    Ok(receipt)
  }
}
