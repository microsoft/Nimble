use crate::Handle;
use ed25519_dalek::PublicKey;
use ledger::{NimbleDigest, Nonce};
use std::collections::HashMap;
use std::error::Error;
use tonic::transport::{Channel, Endpoint};
use tonic::Status;

pub mod endorser_proto {
  tonic::include_proto!("endorser_proto");
}

use endorser_proto::endorser_call_client::EndorserCallClient;
use endorser_proto::{
  AppendReq, AppendResp, AppendViewLedgerReq, AppendViewLedgerResp, GetPublicKeyReq,
  GetPublicKeyResp, InitializeStateReq, InitializeStateResp, LedgerTailMapEntry, NewLedgerReq,
  NewLedgerResp, ReadLatestReq, ReadLatestResp, ReadLatestViewLedgerReq, ReadLatestViewLedgerResp,
};

#[derive(Clone, Debug)]
pub struct EndorserConnection {
  client: EndorserCallClient<Channel>,
  pk: PublicKey,
}

impl EndorserConnection {
  pub fn get_public_key(&self) -> Result<PublicKey, Box<dyn Error>> {
    Ok(self.pk)
  }

  pub async fn new(uri: String) -> Result<Self, Box<dyn Error>> {
    let endorser_endpoint = Endpoint::from_shared(uri.clone())?;
    let channel = endorser_endpoint.connect_lazy()?;
    let mut client = EndorserCallClient::new(channel);

    let req = tonic::Request::new(GetPublicKeyReq {});
    let GetPublicKeyResp { pk } = client.get_public_key(req).await?.into_inner();

    Ok(EndorserConnection {
      client,
      pk: PublicKey::from_bytes(&pk).unwrap(),
    })
  }

  pub async fn initialize_state(
    &mut self,
    ledger_tail_map: &HashMap<NimbleDigest, (NimbleDigest, usize)>,
    view_ledger_tail: &(NimbleDigest, usize),
  ) -> Result<Vec<u8>, Status> {
    let ledger_tail_map_proto: Vec<LedgerTailMapEntry> = ledger_tail_map
      .iter()
      .map(|(handle, (tail, height))| LedgerTailMapEntry {
        handle: handle.to_bytes(),
        tail: tail.to_bytes(),
        height: *height as u64,
      })
      .collect();

    let req = tonic::Request::new(InitializeStateReq {
      ledger_tail_map: ledger_tail_map_proto,
      view_ledger_tail: view_ledger_tail.0.to_bytes(),
      view_ledger_height: view_ledger_tail.1 as u64,
    });
    let InitializeStateResp { signature } = self.client.initialize_state(req).await?.into_inner();
    Ok(signature)
  }

  pub async fn new_ledger(&mut self, handle: &Handle) -> Result<Vec<u8>, Status> {
    let req = tonic::Request::new(NewLedgerReq {
      handle: handle.to_bytes(),
    });
    let NewLedgerResp { signature } = self.client.new_ledger(req).await?.into_inner();
    Ok(signature)
  }

  pub async fn read_latest(&mut self, handle: Vec<u8>, nonce: &Nonce) -> Result<Vec<u8>, Status> {
    let req = tonic::Request::new(ReadLatestReq {
      handle,
      nonce: nonce.get(),
    });

    let ReadLatestResp { signature } = self.client.read_latest(req).await?.into_inner();

    Ok(signature)
  }

  pub async fn append(&mut self, handle: Vec<u8>, block_hash: Vec<u8>) -> Result<Vec<u8>, Status> {
    let req = tonic::Request::new(AppendReq { handle, block_hash });

    let AppendResp { signature } = self.client.append(req).await?.into_inner();

    Ok(signature)
  }

  pub async fn read_latest_view_ledger(&mut self, nonce: &Nonce) -> Result<Vec<u8>, Status> {
    let req = tonic::Request::new(ReadLatestViewLedgerReq { nonce: nonce.get() });

    let ReadLatestViewLedgerResp { signature } =
      self.client.read_latest_view_ledger(req).await?.into_inner();

    Ok(signature)
  }

  pub async fn append_view_ledger(&mut self, block_hash: Vec<u8>) -> Result<Vec<u8>, Status> {
    let req = tonic::Request::new(AppendViewLedgerReq { block_hash });

    let AppendViewLedgerResp { signature } =
      self.client.append_view_ledger(req).await?.into_inner();

    Ok(signature)
  }
}
