#include "endorser.h"
#include "common.h"
#include <string.h>

int ecall_dispatcher::setup(endorser_id_t* endorser_id) {
  int ret = 0;
  int res = 0;

  eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (eckey == NULL) {
    ret = 1;
    TRACE_ENCLAVE("EC_KEY_new_by_curve_name returned 1");
    goto exit;
  }

  if (!EC_KEY_generate_key(eckey)) {
    ret = 1;
    TRACE_ENCLAVE("EC_KEY_generate_key returned 1");
    goto exit;
  }

  unsigned char *pk;
  res = EC_KEY_key2buf(eckey, POINT_CONVERSION_COMPRESSED, &pk, NULL);
  if (res == 0) {
    ret = 1;
    TRACE_ENCLAVE("EC_KEY_key2buf returned an error");
    goto exit;
  }

  // copy the public key and free the buffer
  assert(res == PUBLIC_KEY_SIZE_IN_BYTES);
  memcpy(endorser_id->pk, pk, PUBLIC_KEY_SIZE_IN_BYTES);
  free(pk);

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
  
  // produce an ECDSA signature
  res = ECDSA_sign(0, h_m.v, HASH_VALUE_SIZE_IN_BYTES, signature->v, &signature->v_len, eckey);

  if (res == 0) {
    ret = 1;
    TRACE_ENCLAVE("ECDSA_sign returned an error");
    goto exit;
  }

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
  res = ECDSA_sign(0, h_nonced_tail, HASH_VALUE_SIZE_IN_BYTES, signature->v, &signature->v_len, eckey);

  // copy the tail as response
  memcpy(tail->v, tail_in_endorser.v, HASH_VALUE_SIZE_IN_BYTES);

  if (res == 0) {
    ret = 1;
    TRACE_ENCLAVE("ECDSA_sign returned an error");
    goto exit;
  }
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

  // produce an ECDSA signature
  res = ECDSA_sign(0, h_m.v, HASH_VALUE_SIZE_IN_BYTES, signature->v, &signature->v_len, eckey);

  if (res == 0) {
    ret = 1;
    TRACE_ENCLAVE("ECDSA_sign returned an error");
    goto exit;
  }

  // store updated hash 
  this->endorser_state[*handle] = make_tuple(h_m, m.height);

exit:
  return ret;
}
  
int ecall_dispatcher::get_public_key(endorser_id_t* endorser_id) {
  int ret = 0;
  unsigned char *pk;
  int res = EC_KEY_key2buf(eckey, POINT_CONVERSION_COMPRESSED, &pk, NULL);
  if (res == 0) {
    ret = 1;
    TRACE_ENCLAVE("EC_KEY_key2buf returned an error");
    goto exit;
  }

  // copy the public key and free the buffer
  assert(res == PUBLIC_KEY_SIZE_IN_BYTES);
  memcpy(endorser_id->pk, pk, PUBLIC_KEY_SIZE_IN_BYTES);
  free(pk);

exit:
  return ret;
}
  
void ecall_dispatcher::terminate() {
  EC_KEY_free(eckey); 
}

int ecall_dispatcher::verify_append(endorser_id_t* endorser_id, handle_t* handle, digest_t* block_hash, signature_t* signature) {
  return 0;
}
