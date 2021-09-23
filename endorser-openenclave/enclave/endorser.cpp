#include "endorser.h"

int ecall_dispatcher::setup(endorser_id_t* endorser_id) {
  int ret = 0;
  int res = 0;

  uint8_t private_key[PRIVATE_KEY_SIZE_IN_BYTES];
  res = oe_random(private_key, PRIVATE_KEY_SIZE_IN_BYTES);
  if (res != OE_OK) {
    ret = 1;
    goto exit;
  }
  memcpy(this->private_key, private_key, PRIVATE_KEY_SIZE_IN_BYTES);
  
  uint8_t public_key[PUBLIC_KEY_SIZE_IN_BYTES];
  EverCrypt_Ed25519_secret_to_public(public_key, this->private_key);
  
  memcpy(this->public_key, public_key, PUBLIC_KEY_SIZE_IN_BYTES);
  memcpy(endorser_id->pk, this->public_key, PUBLIC_KEY_SIZE_IN_BYTES);

exit:
  return ret;
}

int ecall_dispatcher::new_ledger(handle_t* handle, signature_t* signature) {
  int ret = 0;
  int res = 0;
  Hacl_Streaming_SHA2_state_sha2_256* st;

  // check if the handle already exists
  if (this->endorser_state.find(*handle) != this->endorser_state.end()) {
    TRACE_ENCLAVE("[Enclave] New Ledger :: Handle already exists %d",(int) this->endorser_state.count(*handle));
    ret = 1;
    goto exit;
  }
  
  // create the genesis metadata block
  meta_block_t m;
  memset(m.prev, 0, HASH_VALUE_SIZE_IN_BYTES);
  memcpy(m.cur, handle->v, HASH_VALUE_SIZE_IN_BYTES);
  m.height = 0;
  
  // hash the metadata block
  digest_t h_m;
  st = Hacl_Streaming_SHA2_create_in_256();
  Hacl_Streaming_SHA2_update_256(st, (unsigned char *) &m, 2*HASH_VALUE_SIZE_IN_BYTES + sizeof(unsigned long long));
  Hacl_Streaming_SHA2_finish_256(st, h_m.v);
  Hacl_Streaming_SHA2_free_256(st);

  // Produce an EdDSA Signature from HACL*
  uint8_t signature_bytes[SIGNATURE_SIZE_IN_BYTES];
  EverCrypt_Ed25519_sign(signature_bytes, this->private_key, HASH_VALUE_SIZE_IN_BYTES, h_m.v);
  
  memcpy(signature->v, signature_bytes, SIGNATURE_SIZE_IN_BYTES);

  // store handle under the same name in the map
  this->endorser_state.emplace(*handle, make_tuple(h_m, 0));

exit:
  return ret;
}
  
int ecall_dispatcher::read_latest(handle_t* handle, nonce_t* nonce, digest_t* tail, height_t* h, signature_t* signature) {
  int ret = 0;
  int res = 0;
  unsigned char* prev;
  unsigned long long height;
  digest_t tail_in_endorser;
  Hacl_Streaming_SHA2_state_sha2_256* st;

  // check if the handle exists, exit if there is no handle found to read
  if (this->endorser_state.find(*handle) == this->endorser_state.end()) {
    ret = 1;
    printf("[Read Latest] Exited at the handle existence check. Requested Handle does not exist\n");
    goto exit;
  }
  
  // obtain the current value associated with handle
  tail_in_endorser = get<0>(this->endorser_state[*handle]);
  height = get<1>(this->endorser_state[*handle]);

  // combine the running hash and the nonce value
  unsigned char tail_with_nonce[HASH_VALUE_SIZE_IN_BYTES + NONCE_SIZE_IN_BYTES];
  memcpy(tail_with_nonce, tail_in_endorser.v, HASH_VALUE_SIZE_IN_BYTES);
  memcpy(tail_with_nonce+HASH_VALUE_SIZE_IN_BYTES, nonce->v, NONCE_SIZE_IN_BYTES);

  // compute a hash = Hash(hash, input), overwriting the running hash
  unsigned char h_nonced_tail[HASH_VALUE_SIZE_IN_BYTES];
  st = Hacl_Streaming_SHA2_create_in_256();
  Hacl_Streaming_SHA2_update_256(st, (unsigned char *) tail_with_nonce, HASH_VALUE_SIZE_IN_BYTES + NONCE_SIZE_IN_BYTES);
  Hacl_Streaming_SHA2_finish_256(st, h_nonced_tail);
  Hacl_Streaming_SHA2_free_256(st);

  // produce an ECDSA signature
  uint8_t signature_bytes[SIGNATURE_SIZE_IN_BYTES];
  EverCrypt_Ed25519_sign(signature_bytes, this->private_key, HASH_VALUE_SIZE_IN_BYTES, h_nonced_tail);

  memcpy(signature->v, signature_bytes, SIGNATURE_SIZE_IN_BYTES);

  // copy the tail as response
  memcpy(tail->v, tail_in_endorser.v, HASH_VALUE_SIZE_IN_BYTES);
  h->h = height;

exit:
  return ret;
}
  
int ecall_dispatcher::append(handle_t *handle, digest_t* block_hash, digest_t* cond_tail_hash, digest_t* prev_tail, height_t* h, signature_t* signature) {
  int ret = 0;
  int res = 0;
  // Set the default conditional tail hash to [0; HASH_VALUE_SIZE_IN_BYTES]
  digest_t default_cond_tail_hash;
  memset(default_cond_tail_hash.v, 0, HASH_VALUE_SIZE_IN_BYTES);

  digest_t prev;
  unsigned int height;
  Hacl_Streaming_SHA2_state_sha2_256* st;
  
  // check if the handle exists
  if (this->endorser_state.find(*handle) == this->endorser_state.end()) {
    TRACE_ENCLAVE("[Append] Exited at the handle existence check. Requested handle does not exist\n");
    ret = 1;
    goto exit;
  }
  
  // obtain the current value of the  
  prev = get<0>(this->endorser_state[*handle]);
  height = get<1>(this->endorser_state[*handle]);

  // check for integer overflow of height
  if (height == UINT_MAX) {
    TRACE_ENCLAVE("The number of blocks has reached UINT_MAX");
    ret = 1;
    goto exit;
  }
  // check if the prev tail retrieved from endorser state matches the conditional tail hash or the default zero conditional hash
  int tail_match_default, tail_match_prev;
  tail_match_default = memcmp(default_cond_tail_hash.v, cond_tail_hash->v, HASH_VALUE_SIZE_IN_BYTES);
  tail_match_prev = memcmp(prev.v, cond_tail_hash->v, HASH_VALUE_SIZE_IN_BYTES);
  if (tail_match_default != 0 && tail_match_prev != 0) {
      TRACE_ENCLAVE("Conditional tail hash did not match prev or default");
      ret = 1;
      goto exit;
  }

  // create the metadata block
  meta_block_t m;
  memcpy(m.prev, prev.v, HASH_VALUE_SIZE_IN_BYTES);
  memcpy(m.cur, block_hash->v, HASH_VALUE_SIZE_IN_BYTES);
  m.height = height + 1;
  
  // hash the metadata block
  digest_t h_m;
  st = Hacl_Streaming_SHA2_create_in_256();
  Hacl_Streaming_SHA2_update_256(st, (unsigned char *) &m, 2*HASH_VALUE_SIZE_IN_BYTES + sizeof(unsigned long long));
  Hacl_Streaming_SHA2_finish_256(st, h_m.v);
  Hacl_Streaming_SHA2_free_256(st);

  // Sign the contents
  uint8_t signature_bytes[SIGNATURE_SIZE_IN_BYTES];
  EverCrypt_Ed25519_sign(signature_bytes, this->private_key, HASH_VALUE_SIZE_IN_BYTES, h_m.v);
  memcpy(signature->v, signature_bytes, SIGNATURE_SIZE_IN_BYTES);

  memcpy(prev_tail->v, prev.v, HASH_VALUE_SIZE_IN_BYTES);
  h->h = m.height;
  // store updated hash 
  this->endorser_state[*handle] = make_tuple(h_m, m.height);

exit:
  return ret;
}
  
int ecall_dispatcher::get_public_key(endorser_id_t* endorser_id) {
  int ret = 0;
  memcpy(endorser_id->pk, this->public_key, PUBLIC_KEY_SIZE_IN_BYTES);

exit:
  return ret;
}
  
void ecall_dispatcher::terminate() {
  free(private_key);
  free(public_key);
}
