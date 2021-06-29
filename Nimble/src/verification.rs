use ed25519_dalek::{Signature, PublicKey, Verifier};
use crate::helper;
use std::error::Error;

// Parsing the Genesis Block returns: PublicKey of Endorser, Attestation and the Nonce UUID used
fn parse_genesis_block_data(block_data: Vec<u8>)
    -> Result<(PublicKey, Signature, Vec<u8>), Box<dyn Error>> {
    // TODO:(@sudheesh) Revisit this when there are multiple endorsers to work with.
    let pk_size = 32usize;
    let sig_size = 64usize;
    let nonce_size = 16usize;
    let block_data_buffer = block_data.as_slice();
    let public_key_bytes = &block_data_buffer[0..pk_size];
    let sig_bytes = &block_data_buffer[pk_size..(pk_size+sig_size)];
    let nonce_bytes = &block_data_buffer[(pk_size+sig_size)..((pk_size+sig_size)+nonce_size)];
    println!("PK Bytes: {:?}", public_key_bytes);
    println!("SIG Bytes: {:?}", sig_bytes);
    println!("Nonce Bytes: {:?}", nonce_bytes);
    let pk_instance = PublicKey::from_bytes(public_key_bytes).unwrap();
    let sig_instance = ed25519_dalek::ed25519::signature::Signature::from_bytes(sig_bytes).unwrap();
    Ok((pk_instance, sig_instance, nonce_bytes.to_vec()))
}

fn verify_endorser_information(pk: &PublicKey, attestation: &Signature) -> bool {
    let message_content = pk.as_bytes();
    let verify = pk.verify(message_content, attestation);
    if verify.is_ok() {
        return true;
    }
    return false;
}

fn reconstruct_genesis_metadata(handle: &Vec<u8>) -> Vec<u8> {
    let zero_entry = [0u8; 32].to_vec();
    let ledger_height = 0u64.to_be_bytes().to_vec();
    let mut message: Vec<u8> = vec![];
    message.extend(zero_entry);
    message.extend(handle);
    message.extend(ledger_height);
    message
}

fn verify_endorser_tail_signature(public_key: &PublicKey, tail_hash: &Vec<u8>, signature: &Signature)
    -> bool {
    let is_valid_endorser_message = public_key.verify(tail_hash, signature);
    if is_valid_endorser_message.is_ok() {
        return true;
    }
    return false;
}

pub fn verify_ledger_response(block_data: Vec<u8>, signature_bytes: Vec<u8>) -> bool {
    let handle = helper::hash(&block_data).to_vec();
    let signature = ed25519_dalek::ed25519::signature::Signature::from_bytes(&signature_bytes).unwrap();
    println!("Handle : {:?}", handle);
    let (pk, sig, nonce) = parse_genesis_block_data(block_data).unwrap();
    // For each endorser: Do the following
    let is_endorser_information_valid = verify_endorser_information(&pk, &sig);
    println!("Endorser Verified: {:?}", is_endorser_information_valid);
    let metadata_message = reconstruct_genesis_metadata(&handle);
    let tail_hash = helper::hash(&metadata_message).to_vec();
    let endorser_information_verification = verify_endorser_tail_signature(&pk, &tail_hash, &signature);
    is_endorser_information_valid && endorser_information_verification
}