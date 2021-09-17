#include "endorser.h"
#include "common.h"
#include <string.h>
#include <openssl/rand.h>
#include "hacl/EverCrypt_Ed25519.h"

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

  // check if the handle already exists
  if (this->endorser_state.count(*handle) >= 1) {
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
  SHA256((unsigned char *) &m, 2*HASH_VALUE_SIZE_IN_BYTES + sizeof(unsigned int), h_m.v);
  
  // Produce an EdDSA Signature from HACL*
  uint8_t signature_bytes[SIGNATURE_SIZE_IN_BYTES];
  EverCrypt_Ed25519_sign(signature_bytes, this->private_key, HASH_VALUE_SIZE_IN_BYTES, h_m.v);
  
  memcpy(signature->v, signature_bytes, SIGNATURE_SIZE_IN_BYTES);

  // store handle under the same name in the map
  this->endorser_state.insert(pair<handle_t, tuple<digest_t, int>>(*handle, make_tuple(h_m, 0)));

exit:
  return ret;
}
  
int ecall_dispatcher::read_latest(handle_t* handle, nonce_t* nonce, digest_t* tail, signature_t* signature) {
  int ret = 0;
  int res = 0;
  unsigned char* prev;
  unsigned int height;
  digest_t tail_in_endorser;

  // check if the handle exists
  if (this->endorser_state.count(*handle) == 0) {
    ret = 1;
    goto exit;
  }
  
  // obtain the current value associated with handle
  tail_in_endorser = get<0>(this->endorser_state[*handle]);
  height = get<1>(this->endorser_state[*handle]);

  // combine the running hash and the nonce value
  unsigned char tail_with_nonce[HASH_VALUE_SIZE_IN_BYTES + NONCE_SIZE_IN_BYTES];
  memcpy(tail_with_nonce, tail_in_endorser.v, HASH_VALUE_SIZE_IN_BYTES);
  memcpy(&tail_with_nonce[HASH_VALUE_SIZE_IN_BYTES], nonce->v, NONCE_SIZE_IN_BYTES);

  // compute a hash = Hash(hash, input), overwriting the running hash
  unsigned char h_nonced_tail[HASH_VALUE_SIZE_IN_BYTES];
  SHA256(tail_with_nonce, HASH_VALUE_SIZE_IN_BYTES + NONCE_SIZE_IN_BYTES, h_nonced_tail);

  // produce an ECDSA signature
  uint8_t signature_bytes[SIGNATURE_SIZE_IN_BYTES];
  EverCrypt_Ed25519_sign(signature_bytes, this->private_key, HASH_VALUE_SIZE_IN_BYTES, h_nonced_tail);
  
  memcpy(signature->v, signature_bytes, SIGNATURE_SIZE_IN_BYTES);

  // copy the tail as response
  memcpy(tail->v, tail_in_endorser.v, HASH_VALUE_SIZE_IN_BYTES);

exit:
  return ret;
}
  
int ecall_dispatcher::append(handle_t *handle, digest_t* block_hash, signature_t* signature) {
  int ret = 0;
  int res = 0;
  digest_t prev;
  unsigned int height;
  
  // check if the handle exists
  if (this->endorser_state.count(*handle) == 0) {
    TRACE_ENCLAVE("Requested handle does not exist");
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

  // create the metadata block
  meta_block_t m;
  memcpy(m.prev, prev.v, HASH_VALUE_SIZE_IN_BYTES);
  memcpy(m.cur, block_hash->v, HASH_VALUE_SIZE_IN_BYTES);
  m.height = height + 1;
  
  // hash the metadata block
  digest_t h_m;
  SHA256((unsigned char *) &m, 2*HASH_VALUE_SIZE_IN_BYTES + sizeof(unsigned int), h_m.v);

  // Sign the contents
  uint8_t signature_bytes[SIGNATURE_SIZE_IN_BYTES];
  EverCrypt_Ed25519_sign(signature_bytes, this->private_key, HASH_VALUE_SIZE_IN_BYTES, h_m.v);
  memcpy(signature->v, signature_bytes, SIGNATURE_SIZE_IN_BYTES);

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

int ecall_dispatcher::verify_append(endorser_id_t* endorser_id, handle_t* handle, digest_t* block_hash, signature_t* signature) {
  return 0;
}
