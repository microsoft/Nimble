use ed25519_dalek::{PublicKey, Signature};
use endorserprotocol::endorser_call_client::EndorserCallClient;
use endorserprotocol::{
  EndorserAppendResponse, EndorserLedgerResponse, EndorserPublicKey, EndorserQueryResponse,
};
use std::error::Error;
use tonic::transport::{Channel, Endpoint};

pub mod protocol {
  tonic::include_proto!("protocol");
}

pub mod endorserprotocol {
  tonic::include_proto!("endorserprotocol");
}

#[derive(Clone, Debug)]
pub struct EndorserKeyInformation {
  publickey: PublicKey,
  signature: Signature,
}

#[derive(Clone, Debug)]
pub struct EndorserConnection {
  client: EndorserCallClient<Channel>,
  keyinfo: EndorserKeyInformation,
}

impl EndorserConnection {
  pub fn get_endorser_keyinformation(&self) -> Result<(PublicKey, Signature), Box<dyn Error>> {
    Ok((self.keyinfo.publickey, self.keyinfo.signature))
  }

  pub async fn new(uri: String) -> Result<Self, Box<dyn Error>> {
    let endorser_endpoint = Endpoint::from_shared(uri.clone())?;
    let channel = endorser_endpoint.connect_lazy()?;
    let mut client = EndorserCallClient::new(channel);

    let empty_request = tonic::Request::new(endorserprotocol::Empty {});
    let EndorserPublicKey {
      publickey,
      signature,
    } = client
      .get_endorser_public_key(empty_request)
      .await?
      .into_inner();

    println!(
      "Received PK, Proof from Endorser {:?} = {:?} {:?}",
      endorser_endpoint, publickey, signature
    );

    let public_key_instance = PublicKey::from_bytes(&publickey).unwrap();
    let signature_instance =
      ed25519_dalek::ed25519::signature::Signature::from_bytes(&signature).unwrap();

    Ok(EndorserConnection {
      client,
      keyinfo: EndorserKeyInformation {
        publickey: public_key_instance,
        signature: signature_instance,
      },
    })
  }

  pub async fn call_endorser_new_ledger(
    &mut self,
    handle: Vec<u8>,
  ) -> Result<Signature, Box<dyn Error>> {
    let request = tonic::Request::new(endorserprotocol::Handle { handle });
    let EndorserLedgerResponse { signature } = self.client.new_ledger(request).await?.into_inner();

    println!("Received Ledger Response: {:?}", signature);

    let signature_instance =
      ed25519_dalek::ed25519::signature::Signature::from_bytes(signature.as_slice()).unwrap();

    Ok(signature_instance)
  }

  pub async fn call_endorser_read_latest(
    &mut self,
    handle: Vec<u8>,
    nonce: Vec<u8>,
  ) -> Result<Signature, Box<dyn Error>> {
    let request = tonic::Request::new(endorserprotocol::EndorserQuery { handle, nonce });

    let EndorserQueryResponse {
      nonce: _,
      tail_hash: _,
      signature,
    } = self.client.read_latest(request).await?.into_inner();

    let signature_instance =
      ed25519_dalek::ed25519::signature::Signature::from_bytes(&signature).unwrap();

    Ok(signature_instance)
  }

  pub async fn call_endorser_append(
    &mut self,
    handle: Vec<u8>,
    block_content_hash: Vec<u8>,
    conditional_tail_hash: Vec<u8>,
  ) -> Result<(Vec<u8>, u64, Signature), Box<dyn Error>> {
    let request = tonic::Request::new(endorserprotocol::EndorserAppendRequest {
      endorser_handle: handle,
      block_hash: block_content_hash,
      conditional_tail_hash,
    });

    let EndorserAppendResponse {
      tail_hash,
      ledger_height,
      signature,
    } = self.client.append_to_ledger(request).await?.into_inner();

    let signature_instance =
      ed25519_dalek::ed25519::signature::Signature::from_bytes(&signature).unwrap();

    Ok((tail_hash, ledger_height, signature_instance))
  }
}
