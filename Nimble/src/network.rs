use ed25519_dalek::PublicKey;
use std::error::Error;
use tonic::transport::{Channel, Endpoint};

pub mod endorser_proto {
  tonic::include_proto!("endorser_proto");
}

use endorser_proto::endorser_call_client::EndorserCallClient;
use endorser_proto::{
  AppendReq, AppendResp, GetPublicKeyReq, GetPublicKeyResp, NewLedgerReq, NewLedgerResp,
  ReadLatestReq, ReadLatestResp,
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

  // pub async fn new(uris: Vec<&'static str>) -> Result<Vec<Self>, Box<dyn Error>> {
  //   let mut responses = Vec::with_capacity(uris.len());
  //   let mut clients = Vec::new();
  //   let mut client_futures = FuturesUnordered::new();
  //   for uri in uris {
  //     let endorser_endpoint = Endpoint::from_shared(uri.clone())?;
  //     let channel = endorser_endpoint.connect_lazy()?;
  //     let mut client = EndorserCallClient::new(channel);
  //     let req = tonic::Request::new(GetPublicKeyReq {});
  //     clients.push(client.clone());
  //     client_futures.push(async move { client.get_public_key(req).await });
  //   }
  //   let mut client_index = 0;
  //   while let Some(res) = client_futures.next().await {
  //     match res {
  //       Ok(resp) => {
  //         let GetPublicKeyResp { pk } = resp.into_inner();
  //         let ec = EndorserConnection {
  //           client: clients.get(client_index).unwrap().clone(),
  //           pk: PublicKey::from_bytes(&pk).unwrap(),
  //         };
  //         println!("Adding Valid Response {:?} to available responses.", client_index);
  //         responses.push(ec);
  //       },
  //       Err(e) => {
  //         eprintln!("Error");
  //       }
  //     }
  //     client_index+=1;
  //   }
  //
  //   Ok(responses)
  // }

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

  pub async fn new_ledger(&mut self, handle: Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
    let req = tonic::Request::new(NewLedgerReq { handle });
    let NewLedgerResp { signature } = self.client.new_ledger(req).await?.into_inner();
    Ok(signature)
  }

  pub async fn read_latest(
    &mut self,
    handle: Vec<u8>,
    nonce: Vec<u8>,
  ) -> Result<Vec<u8>, Box<dyn Error>> {
    let req = tonic::Request::new(ReadLatestReq { handle, nonce });

    let ReadLatestResp {
      tail_hash: _,
      height: _,
      signature,
    } = self.client.read_latest(req).await?.into_inner();

    Ok(signature)
  }

  pub async fn append(
    &mut self,
    handle: Vec<u8>,
    block_hash: Vec<u8>,
    cond_tail_hash: Vec<u8>,
  ) -> Result<(Vec<u8>, u64, Vec<u8>), Box<dyn Error>> {
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

    Ok((tail_hash, height, signature))
  }
}
