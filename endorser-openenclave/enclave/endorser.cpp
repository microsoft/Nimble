#include "endorser.h"

void calc_digest(unsigned char *m, unsigned long long len, digest_t *digest) {
  SHA256(m, len, digest->v);
}

int calc_signature(EC_KEY *eckey, digest_t *m, signature_t *signature) {
  ECDSA_SIG *sig = ECDSA_do_sign(m->v, HASH_VALUE_SIZE_IN_BYTES, eckey);
  if (sig == NULL) {
    return 0;
  }

  const BIGNUM *sig_r = ECDSA_SIG_get0_r(sig);
  const BIGNUM *sig_s = ECDSA_SIG_get0_s(sig);
  int len_r = BN_bn2binpad(sig_r, signature->v, SIGNATURE_SIZE_IN_BYTES/2);
  int len_s = BN_bn2binpad(sig_s, &signature->v[SIGNATURE_SIZE_IN_BYTES/2], SIGNATURE_SIZE_IN_BYTES/2);
  
  // free ECDSA_sig
  ECDSA_SIG_free(sig);
  
  if (len_r != SIGNATURE_SIZE_IN_BYTES/2 || len_s != SIGNATURE_SIZE_IN_BYTES/2) {
    return 0;
  } else {
    return 1;
  }
}

int private_to_public_key(EC_KEY *eckey, endorser_id_t *endorser_id) {
  int res = 0;
  unsigned char *pk;

  res = EC_KEY_key2buf(eckey, POINT_CONVERSION_COMPRESSED, &pk, NULL);
  if (res == 0) {
    return res;
  }

  // copy the public key and free the buffer
  assert(res == PUBLIC_KEY_SIZE_IN_BYTES);
  memcpy(endorser_id->pk, pk, PUBLIC_KEY_SIZE_IN_BYTES);
  free(pk);
}

int ecall_dispatcher::setup(endorser_id_t* endorser_id) {
  int ret = 0;
  int res = 0;

  // set is_initialized to false 
  this->is_initialized = false;

  eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (eckey == NULL) {
    ret = 1;
    TRACE_ENCLAVE("EC_KEY_new_by_curve_name returned NULL");
    goto exit;
  }
  
  if (!EC_KEY_generate_key(eckey)) {
    ret = 1;
    TRACE_ENCLAVE("EC_KEY_generate_key returned 1");
    goto exit;
  }

  // convert private key into a public key that we send back 
  res = private_to_public_key(this->eckey, endorser_id);
  if (res == 0) {
    ret = 1;
    TRACE_ENCLAVE("Error converting private key to public key");
    goto exit;
  }

exit:
  return ret;
}

int ecall_dispatcher::initialize_state(init_endorser_data_t *state, signature_t* signature) {
  int ret = 0;
  int i = 0;

  // check if the endorser is already initialized 
  // and return an error if the endorser is already initialized
  if (this->is_initialized) {
    ret = 1;
    goto exit;
  }

  // copy each element from ledger_tail_map to this->ledger_tail_map
  for (i = 0; i < state->ledger_tail_map_size; i++) { 

    // check if the handle already exists
    if (this->ledger_tail_map.find(state->ledger_tail_map[i].handle) != this->ledger_tail_map.end()) {
      TRACE_ENCLAVE("[Enclave] initialize_state:: Handle already exists %d",(int) this->ledger_tail_map.count(state->ledger_tail_map[i].handle));
      ret = 1;
      goto exit;
    }
 
    // since the requested handle isn't already inserted, we insert it into state 
    this->ledger_tail_map.emplace(state->ledger_tail_map[i].handle, make_tuple(state->ledger_tail_map[i].tail, state->ledger_tail_map[i].height));
  }

  // copy the view ledger tail and height
  memcpy(this->view_ledger_tail.v, state->view_ledger_tail.v, HASH_VALUE_SIZE_IN_BYTES);
  this->view_ledger_height = state->view_ledger_height;

  this->is_initialized = true;

  return append_view_ledger(&state->block_hash, &state->cond_updated_tail_hash, signature);

 exit:
  return ret;
}

int ecall_dispatcher::new_ledger(handle_t* handle, signature_t* signature) {
  int ret = 0;
  int res = 0;

  // check if the state is initialized
  if (!is_initialized) {
    ret = 1;
    goto exit;
  }

  // check if the handle already exists
  if (this->ledger_tail_map.find(*handle) != this->ledger_tail_map.end()) {
    TRACE_ENCLAVE("[Enclave] New Ledger :: Handle already exists %d",(int) this->ledger_tail_map.count(*handle));
    ret = 1;
    goto exit;
  }
  
  // create the genesis metadata block
  meta_block_t m;
  memcpy(m.view, this->view_ledger_tail.v, HASH_VALUE_SIZE_IN_BYTES);
  memset(m.prev, 0, HASH_VALUE_SIZE_IN_BYTES);
  memcpy(m.cur, handle->v, HASH_VALUE_SIZE_IN_BYTES);
  m.height = 0;
  
  // hash the metadata block
  digest_t h_m;
  calc_digest((unsigned char *) &m, sizeof(meta_block_t), &h_m); 

  // Produce a signature
  res = calc_signature(this->eckey, &h_m, signature);
  if (res == 0) {
    ret = 1;
	  TRACE_ENCLAVE("Error producing a signature");
    goto exit;
  }
  
  // store handle under the same name in the map
  this->ledger_tail_map.emplace(*handle, make_tuple(h_m, 0));

exit:
  return ret;
}
  
int ecall_dispatcher::read_latest(handle_t* handle, nonce_t* nonce, signature_t* signature) {
  int ret = 0;
  int res = 0;
  unsigned long long height;
  digest_t prev;

  // check if the state is initialized
  if (!is_initialized) {
    ret = 1;
    goto exit;
  }

  // check if the handle exists, exit if there is no handle found to read
  if (this->ledger_tail_map.find(*handle) == this->ledger_tail_map.end()) {
    ret = 1;
    TRACE_ENCLAVE("[Read Latest] Exited at the handle existence check. Requested Handle does not exist\n");
    goto exit;
  }
  
  // obtain the current value associated with handle
  prev = get<0>(this->ledger_tail_map[*handle]);
  height = get<1>(this->ledger_tail_map[*handle]);

  // combine the running hash and the nonce value
  unsigned char tail_with_nonce[HASH_VALUE_SIZE_IN_BYTES + NONCE_SIZE_IN_BYTES];
  memcpy(tail_with_nonce, prev.v, HASH_VALUE_SIZE_IN_BYTES);
  memcpy(tail_with_nonce+HASH_VALUE_SIZE_IN_BYTES, nonce->v, NONCE_SIZE_IN_BYTES);

  // compute a hash = Hash(hash, input), overwriting the running hash
  digest_t h_nonced_tail;
  calc_digest((unsigned char *) tail_with_nonce, HASH_VALUE_SIZE_IN_BYTES + NONCE_SIZE_IN_BYTES, &h_nonced_tail);

  // Produce a signature
  res = calc_signature(this->eckey, &h_nonced_tail, signature);
  if (res == 0) {
    ret = 1;
	  TRACE_ENCLAVE("Error producing a signature");
    goto exit;
  }
   
exit:
  return ret;
}
  
int ecall_dispatcher::append(handle_t *handle, digest_t* block_hash, digest_t* cond_updated_tail_hash, signature_t* signature) {
  int ret = 0;
  int res = 0;

  digest_t prev;
  unsigned long long height;
 
  // check if the state is initialized
  if (!is_initialized) {
    ret = 1;
    goto exit;
  } 
  
  // check if the handle exists
  if (this->ledger_tail_map.find(*handle) == this->ledger_tail_map.end()) {
    TRACE_ENCLAVE("[Append] Exited at the handle existence check. Requested handle does not exist\n");
    ret = 1;
    goto exit;
  }
  
  // obtain the current value of the current tail and height
  prev = get<0>(this->ledger_tail_map[*handle]);
  height = get<1>(this->ledger_tail_map[*handle]);

  // check for integer overflow of height
  if (height == UINT_MAX) {
    TRACE_ENCLAVE("The number of blocks has reached UINT_MAX");
    ret = 1;
    goto exit;
  }

  // create the metadata block
  meta_block_t m;
  memcpy(m.view, this->view_ledger_tail.v, HASH_VALUE_SIZE_IN_BYTES);
  memcpy(m.prev, prev.v, HASH_VALUE_SIZE_IN_BYTES);
  memcpy(m.cur, block_hash->v, HASH_VALUE_SIZE_IN_BYTES);
  m.height = height + 1;
  
  // hash the metadata block
  digest_t h_m;
  calc_digest((unsigned char *) &m, sizeof(meta_block_t), &h_m);

  // perform a check on the post-state of the append
  if (memcmp(h_m.v, cond_updated_tail_hash->v, HASH_VALUE_SIZE_IN_BYTES) != 0) {
    TRACE_ENCLAVE("The provided cond_updated_tail_hash did not match with the local computation of the same hash");
    ret = 1;
    goto exit;
  }

  // Produce a signature
  res = calc_signature(this->eckey, &h_m, signature);
  if (res == 0) {
    ret = 1;
	  TRACE_ENCLAVE("Error producing a signature");
    goto exit;
  }
 
  // store updated hash 
  this->ledger_tail_map[*handle] = make_tuple(h_m, m.height);

exit:
  return ret;
}
  
int ecall_dispatcher::get_public_key(endorser_id_t* endorser_id) {
  int ret = 0;
  int res = 0;
  res = private_to_public_key(this->eckey, endorser_id);
  if (res == 0) {
    ret = 1;
    TRACE_ENCLAVE("Error converting private key to public key");
    goto exit;
  }

exit:
  return ret;
}

int ecall_dispatcher::read_latest_view_ledger(nonce_t* nonce, signature_t* signature) {
  int ret = 0;
  int res = 0;
  unsigned long long height;

  // check if the state is initialized
  if (!is_initialized) {
    ret = 1;
    goto exit;
  }

  // combine the running hash and the nonce value
  unsigned char tail_with_nonce[HASH_VALUE_SIZE_IN_BYTES + NONCE_SIZE_IN_BYTES];
  memcpy(tail_with_nonce, this->view_ledger_tail.v, HASH_VALUE_SIZE_IN_BYTES);
  memcpy(tail_with_nonce+HASH_VALUE_SIZE_IN_BYTES, nonce->v, NONCE_SIZE_IN_BYTES);

  // compute a hash = Hash(hash, input), overwriting the running hash
  digest_t h_nonced_tail;
  calc_digest((unsigned char *) tail_with_nonce, HASH_VALUE_SIZE_IN_BYTES + NONCE_SIZE_IN_BYTES, &h_nonced_tail);

  // Produce a signature
  res = calc_signature(this->eckey, &h_nonced_tail, signature);
  if (res == 0) {
    ret = 1;
	  TRACE_ENCLAVE("Error producing a signature");
    goto exit;
  }
  
exit:
  return ret;
}

int calc_hash_of_state(map<handle_t, tuple<digest_t, unsigned long long>, comparator> *ledger_tail_map, digest_t *hash_of_state) {
  int num_entries = ledger_tail_map->size();
  ledger_tail_map_entry_t entries[num_entries];
  int i = 0;
  map<handle_t, tuple<digest_t, unsigned long long>, comparator>::iterator it;

  // if there are no entries in the map, we return a default digest
  if (num_entries == 0) {
    memset(hash_of_state->v, 0, HASH_VALUE_SIZE_IN_BYTES);
  } else {
    for (it = ledger_tail_map->begin(); it != ledger_tail_map->end(); it++) {
      memcpy(entries[i].handle.v, it->first.v, HASH_VALUE_SIZE_IN_BYTES);
      memcpy(entries[i].tail.v, get<0>(it->second).v, HASH_VALUE_SIZE_IN_BYTES);
      entries[i].height = get<1>(it->second);
      i++;
    }
    calc_digest((unsigned char *) entries, num_entries * sizeof(ledger_tail_map_entry_t), hash_of_state);
  }
}

int ecall_dispatcher::append_view_ledger(digest_t* block_hash, digest_t* cond_updated_tail_hash, signature_t* signature) {
  int ret = 0;
  int res = 0;

  digest_t hash_of_state;
 
  // check if the state is initialized
  if (!is_initialized) {
    ret = 1;
    goto exit;
  } 
  
  // obtain the current value of the view ledger information, and check if the height will overflow after the append
  if (this->view_ledger_height == UINT_MAX) {
    TRACE_ENCLAVE("The number of blocks has reached UINT_MAX in the view ledger");
    ret = 1;
    goto exit;
  }

  // calculate the hash of the current state
  calc_hash_of_state(&this->ledger_tail_map, &hash_of_state);

  // create the metadata block
  meta_block_t m;
  memcpy(m.view, hash_of_state.v, HASH_VALUE_SIZE_IN_BYTES);
  memcpy(m.prev, this->view_ledger_tail.v, HASH_VALUE_SIZE_IN_BYTES);
  memcpy(m.cur, block_hash->v, HASH_VALUE_SIZE_IN_BYTES);
  m.height = this->view_ledger_height + 1;
  
  // hash the metadata block
  digest_t h_m;
  calc_digest((unsigned char *) &m, sizeof(meta_block_t), &h_m);

  // perform a check on the post-state of the append
  if (memcmp(h_m.v, cond_updated_tail_hash->v, HASH_VALUE_SIZE_IN_BYTES) != 0) {
    TRACE_ENCLAVE("The provided cond_updated_tail_hash did not match with the local computation of the same hash");
    ret = 1;
    goto exit;
  }

  // Produce a signature
  res = calc_signature(this->eckey, &h_m, signature);
  if (res == 0) {
    ret = 1;
	  TRACE_ENCLAVE("Error producing a signature");
    goto exit;
  }
  
  // update the internal state
  memcpy(this->view_ledger_tail.v, h_m.v, HASH_VALUE_SIZE_IN_BYTES);
  this->view_ledger_height = this->view_ledger_height + 1;

exit:
  return ret;
}
 
void ecall_dispatcher::terminate() {
  EC_KEY_free(this->eckey); 
}
