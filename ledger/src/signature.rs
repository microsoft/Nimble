use core::fmt::Debug;
use itertools::concat;
use openssl::{
  bn::{BigNum, BigNumContext},
  ec::*,
  ecdsa::EcdsaSig,
  nid::Nid,
  pkey::{Private, Public},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CryptoError {
  /// returned if the supplied byte array cannot be parsed as a valid public key
  InvalidPublicKeyBytes,
  /// returned if the provided signature is invalid when verifying
  InvalidSignature,
  /// returned if there's an error when signing
  SignatureGenerationError,
  /// returned if the private key pem is invalid
  InvalidPrivateKeyPem,
  /// returned if there is an error when deriving a signature from DER
  FailedToGetSigFromDER,
}

pub trait PublicKeyTrait {
  fn num_bytes() -> usize;
  fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError>
  where
    Self: Sized;
  fn to_bytes(&self) -> Vec<u8>;
}

pub trait PrivateKeyTrait {
  fn new() -> Self
  where
    Self: Sized;
  fn get_public_key(&self) -> Result<PublicKey, CryptoError>
  where
    PublicKey: PublicKeyTrait;
  fn sign(&self, msg: &[u8]) -> Result<Signature, CryptoError>
  where
    Signature: SignatureTrait;
}

pub trait SignatureTrait {
  fn num_bytes() -> usize;
  fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError>
  where
    Self: Sized;
  fn verify(&self, pk: &PublicKey, msg: &[u8]) -> Result<(), CryptoError>
  where
    PublicKey: PublicKeyTrait;
  fn to_bytes(&self) -> Vec<u8>;
}

/// Types and concrete implementations of types for ECDSA algorithm with P-256 using OpenSSL
pub struct PublicKey {
  key: EcKey<Public>,
}

pub struct PrivateKey {
  key: EcKey<Private>,
}

pub struct Signature {
  sig: EcdsaSig,
}

impl PublicKeyTrait for PublicKey {
  fn num_bytes() -> usize {
    33
  }

  fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let point = {
      let mut ctx = BigNumContext::new().unwrap();
      let res = EcPoint::from_bytes(&group, bytes, &mut ctx);
      if res.is_err() {
        return Err(CryptoError::InvalidPublicKeyBytes);
      }
      res.unwrap()
    };

    let res = EcKey::from_public_key(&group, &point);
    if let Ok(key) = res {
      Ok(PublicKey { key })
    } else {
      Err(CryptoError::InvalidPublicKeyBytes)
    }
  }

  fn to_bytes(&self) -> Vec<u8> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let mut ctx = BigNumContext::new().unwrap();
    self
      .key
      .public_key()
      .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)
      .unwrap()
  }
}

impl PublicKey {
  pub fn to_der(&self) -> Vec<u8> {
    self.key.public_key_to_der().unwrap()
  }

  pub fn to_uncompressed(&self) -> Vec<u8> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let mut ctx = BigNumContext::new().unwrap();
    self
      .key
      .public_key()
      .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
      .unwrap()
  }
}

impl PrivateKeyTrait for PrivateKey {
  fn new() -> Self {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = EcKey::generate(&group).unwrap();
    PrivateKey { key }
  }

  fn get_public_key(&self) -> Result<PublicKey, CryptoError> {
    let key = {
      let point = self.key.public_key();
      let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
      let res = EcKey::from_public_key(&group, point);
      if res.is_err() {
        return Err(CryptoError::InvalidPublicKeyBytes);
      }
      res.unwrap()
    };
    Ok(PublicKey { key })
  }

  fn sign(&self, msg: &[u8]) -> Result<Signature, CryptoError> {
    let sig = {
      let res = EcdsaSig::sign(msg, &self.key);
      if res.is_err() {
        return Err(CryptoError::SignatureGenerationError);
      }
      res.unwrap()
    };
    Ok(Signature { sig })
  }
}

impl PrivateKey {
  pub fn from_pem(pem: &[u8]) -> Result<PrivateKey, CryptoError> {
    let res = EcKey::private_key_from_pem(pem);
    if res.is_err() {
      return Err(CryptoError::InvalidPrivateKeyPem);
    }
    let key = res.unwrap();
    Ok(PrivateKey { key })
  }
}

impl SignatureTrait for Signature {
  fn num_bytes() -> usize {
    64
  }

  fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
    if bytes.len() != Self::num_bytes() {
      return Err(CryptoError::InvalidSignature);
    }

    let r = {
      let res = BigNum::from_slice(&bytes[0..Self::num_bytes() / 2]);
      if res.is_err() {
        return Err(CryptoError::InvalidSignature);
      }
      res.unwrap()
    };
    let s = {
      let res = BigNum::from_slice(&bytes[Self::num_bytes() / 2..]);
      if res.is_err() {
        return Err(CryptoError::InvalidSignature);
      }
      res.unwrap()
    };

    let sig = {
      let res = EcdsaSig::from_private_components(r, s);
      if res.is_err() {
        return Err(CryptoError::InvalidSignature);
      }
      res.unwrap()
    };

    Ok(Signature { sig })
  }

  fn verify(&self, pk: &PublicKey, msg: &[u8]) -> Result<(), CryptoError> {
    let res = self.sig.verify(msg, &pk.key);
    if let Ok(true) = res {
      Ok(())
    } else {
      Err(CryptoError::InvalidSignature)
    }
  }

  fn to_bytes(&self) -> Vec<u8> {
    let r = self
      .sig
      .r()
      .to_vec_padded((Self::num_bytes() / 2) as i32)
      .unwrap();
    let s = self
      .sig
      .s()
      .to_vec_padded((Self::num_bytes() / 2) as i32)
      .unwrap();
    concat(vec![r, s]).to_vec()
  }
}

impl Signature {
  pub fn to_der(&self) -> Vec<u8> {
    self.sig.to_der().unwrap()
  }

  pub fn from_der(der: &[u8]) -> Result<Self, CryptoError> {
    match EcdsaSig::from_der(der) {
      Ok(sig) => Ok(Signature { sig }),
      Err(_) => Err(CryptoError::FailedToGetSigFromDER),
    }
  }
}

impl Clone for PublicKey {
  fn clone(&self) -> Self {
    PublicKey::from_bytes(&self.to_bytes()).unwrap()
  }
}

impl Debug for PublicKey {
  fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
    write!(f, "PublicKey({:?})", self.to_bytes())
  }
}

impl Clone for Signature {
  fn clone(&self) -> Self {
    Signature::from_bytes(&self.to_bytes()).unwrap()
  }
}

impl Debug for Signature {
  fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
    write!(f, "Signature({:?})", self.to_bytes())
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_sig_gen_verify() {
    let sk = PrivateKey::new();
    let msg = b"hello world";
    let sig = sk.sign(msg.as_slice()).unwrap();

    let pk = sk.get_public_key().unwrap();

    // valid verification
    let res = sig.verify(&pk, msg.as_slice());
    assert!(res.is_ok());

    // invalid verification
    let msg2 = b"hello world2";
    let res = sig.verify(&pk, msg2);
    assert!(res.is_err());
  }

  #[test]
  fn test_compressed_pk_and_raw_signature_encoding() {
    let pk_bytes =
      hex::decode("03A60909370C9CCB5DD3B909654AE158E21C4EE35C7A291C7197F38E22CA95B858").unwrap();
    let r_bytes =
      hex::decode("3341835E0BA33047E0B472F5622B157ED5879085213A1777963571220E48BF0F").unwrap();
    let s_bytes =
      hex::decode("8B630A0251F157CAB579FD3D589969A92CCC75C9B5058E2BF77F7038D352DF10").unwrap();
    let sig_bytes = concat(vec![r_bytes, s_bytes]).to_vec();
    let m =
      hex::decode("0000000000000000000000000000000000000000000000000000000000000000").unwrap();

    let pk = PublicKey::from_bytes(&pk_bytes).unwrap();
    let sig = Signature::from_bytes(&sig_bytes).unwrap();
    let res = sig.verify(&pk, &m);
    assert!(res.is_ok());
  }
}
