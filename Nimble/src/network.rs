use ed25519_dalek::{PublicKey, Signature};
use std::error::Error;
use tonic::transport::{Channel, Endpoint};

pub mod endorser_proto {
  tonic::include_proto!("endorser_proto");
}

use endorser_proto::endorser_call_client::EndorserCallClient;
use endorser_proto::{
  AppendReq, AppendResp, GetEndorserPublicKeyReq, GetEndorserPublicKeyResp, NewLedgerReq,
  NewLedgerResp, ReadLatestReq, ReadLatestResp,
};

#[derive(Clone, Debug)]
pub struct EndorserKeyInformation {
  publickey: PublicKey,
}

#[derive(Clone, Debug)]
pub struct EndorserConnection {
  client: EndorserCallClient<Channel>,
  keyinfo: EndorserKeyInformation,
}

impl EndorserConnection {
  pub fn get_endorser_keyinformation(&self) -> Result<PublicKey, Box<dyn Error>> {
    Ok(self.keyinfo.publickey)
  }

  pub async fn new(uri: String) -> Result<Self, Box<dyn Error>> {
    let endorser_endpoint = Endpoint::from_shared(uri.clone())?;
    let channel = endorser_endpoint.connect_lazy()?;
    let mut client = EndorserCallClient::new(channel);

    let req = tonic::Request::new(GetEndorserPublicKeyReq {});
    let GetEndorserPublicKeyResp { publickey } =
      client.get_endorser_public_key(req).await?.into_inner();

    let public_key_instance = PublicKey::from_bytes(&publickey).unwrap();
    Ok(EndorserConnection {
      client,
      keyinfo: EndorserKeyInformation {
        publickey: public_key_instance,
      },
    })
  }

  pub async fn call_endorser_new_ledger(
    &mut self,
    handle: Vec<u8>,
  ) -> Result<Signature, Box<dyn Error>> {
    let req = tonic::Request::new(NewLedgerReq { handle });
    let NewLedgerResp { signature } = self.client.new_ledger(req).await?.into_inner();

    let signature_instance =
      ed25519_dalek::ed25519::signature::Signature::from_bytes(signature.as_slice()).unwrap();

    Ok(signature_instance)
  }

  pub async fn call_endorser_read_latest(
    &mut self,
    handle: Vec<u8>,
    nonce: Vec<u8>,
  ) -> Result<Signature, Box<dyn Error>> {
    let req = tonic::Request::new(ReadLatestReq { handle, nonce });

    let ReadLatestResp {
      tail_hash: _,
      height: _,
      signature,
    } = self.client.read_latest(req).await?.into_inner();

    let signature_instance =
      ed25519_dalek::ed25519::signature::Signature::from_bytes(&signature).unwrap();

    Ok(signature_instance)
  }

  pub async fn call_endorser_append(
    &mut self,
    handle: Vec<u8>,
    block_hash: Vec<u8>,
    cond_tail_hash: Vec<u8>,
  ) -> Result<(Vec<u8>, u64, Signature), Box<dyn Error>> {
    let req = tonic::Request::new(AppendReq {
      handle,
      block_hash,
      cond_tail_hash,
    });

    let AppendResp {
      tail_hash,
      height,
      signature,
    } = self.client.append(req).await?.into_inner();

    let signature_instance =
      ed25519_dalek::ed25519::signature::Signature::from_bytes(&signature).unwrap();

    Ok((tail_hash, height, signature_instance))
  }
}
