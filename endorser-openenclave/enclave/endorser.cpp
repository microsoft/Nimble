#include "endorser.h"

int ecall_dispatcher::setup(endorser_id_t* endorser_id) {
  int ret = 0;
  int res = 0;
 
  // set is_initialized to false 
  this->is_initialized = false;

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
      TRACE_ENCLAVE("[Enclave] initialize_satte:: Handle already exists %d",(int) this->ledger_tail_map.count(state->ledger_tail_map[i].handle));
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

  return append_view_ledger(&state->block_hash, signature);

 exit:
  return ret;
}

int ecall_dispatcher::new_ledger(handle_t* handle, signature_t* signature) {
  int ret = 0;
  int res = 0;
  Hacl_Streaming_SHA2_state_sha2_256* st;

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
  st = Hacl_Streaming_SHA2_create_in_256();
  Hacl_Streaming_SHA2_update_256(st, (unsigned char *) &m, sizeof(meta_block_t));
  Hacl_Streaming_SHA2_finish_256(st, h_m.v);
  Hacl_Streaming_SHA2_free_256(st);

  // Produce an EdDSA Signature from HACL*
  uint8_t signature_bytes[SIGNATURE_SIZE_IN_BYTES];
  EverCrypt_Ed25519_sign(signature_bytes, this->private_key, HASH_VALUE_SIZE_IN_BYTES, h_m.v);
  
  memcpy(signature->v, signature_bytes, SIGNATURE_SIZE_IN_BYTES);

  // store handle under the same name in the map
  this->ledger_tail_map.emplace(*handle, make_tuple(h_m, 0));

exit:
  return ret;
}
  
int ecall_dispatcher::read_latest(handle_t* handle, nonce_t* nonce, signature_t* signature) {
  int ret = 0;
  int res = 0;
  unsigned char* prev;
  unsigned long long height;
  digest_t tail_in_endorser;
  Hacl_Streaming_SHA2_state_sha2_256* st;

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
  tail_in_endorser = get<0>(this->ledger_tail_map[*handle]);
  height = get<1>(this->ledger_tail_map[*handle]);

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

exit:
  return ret;
}
  
int ecall_dispatcher::append(handle_t *handle, digest_t* block_hash, signature_t* signature) {
  int ret = 0;
  int res = 0;

  digest_t prev;
  unsigned int height;
  Hacl_Streaming_SHA2_state_sha2_256* st;
 
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
  st = Hacl_Streaming_SHA2_create_in_256();
  Hacl_Streaming_SHA2_update_256(st, (unsigned char *) &m, sizeof(meta_block_t));
  Hacl_Streaming_SHA2_finish_256(st, h_m.v);
  Hacl_Streaming_SHA2_free_256(st);

  // Sign the contents
  uint8_t signature_bytes[SIGNATURE_SIZE_IN_BYTES];
  EverCrypt_Ed25519_sign(signature_bytes, this->private_key, HASH_VALUE_SIZE_IN_BYTES, h_m.v);
  memcpy(signature->v, signature_bytes, SIGNATURE_SIZE_IN_BYTES);

  // store updated hash 
  this->ledger_tail_map[*handle] = make_tuple(h_m, m.height);

exit:
  return ret;
}
  
int ecall_dispatcher::get_public_key(endorser_id_t* endorser_id) {
  int ret = 0;
  memcpy(endorser_id->pk, this->public_key, PUBLIC_KEY_SIZE_IN_BYTES);

exit:
  return ret;
}

int ecall_dispatcher::read_latest_view_ledger(nonce_t* nonce, signature_t* signature) {
  int ret = 0;
  int res = 0;
  unsigned long long height;
  digest_t tail_in_endorser;
  Hacl_Streaming_SHA2_state_sha2_256* st;

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
  unsigned char h_nonced_tail[HASH_VALUE_SIZE_IN_BYTES];
  st = Hacl_Streaming_SHA2_create_in_256();
  Hacl_Streaming_SHA2_update_256(st, (unsigned char *) tail_with_nonce, HASH_VALUE_SIZE_IN_BYTES + NONCE_SIZE_IN_BYTES);
  Hacl_Streaming_SHA2_finish_256(st, h_nonced_tail);
  Hacl_Streaming_SHA2_free_256(st);

  // produce an ECDSA signature
  uint8_t signature_bytes[SIGNATURE_SIZE_IN_BYTES];
  EverCrypt_Ed25519_sign(signature_bytes, this->private_key, HASH_VALUE_SIZE_IN_BYTES, h_nonced_tail);

  memcpy(signature->v, signature_bytes, SIGNATURE_SIZE_IN_BYTES);

exit:
  return ret;
}

int calc_hash_of_state(map<handle_t, tuple<digest_t, unsigned long long>, comparator> *ledger_tail_map, digest_t *hash_of_state) {
  int num_entries = ledger_tail_map->size();
  ledger_tail_map_entry_t entries[num_entries];
  int i = 0;
  map<handle_t, tuple<digest_t, unsigned long long>, comparator>::iterator it;
  Hacl_Streaming_SHA2_state_sha2_256* st;

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
    st = Hacl_Streaming_SHA2_create_in_256();
    Hacl_Streaming_SHA2_update_256(st, (unsigned char *) entries, num_entries * sizeof(ledger_tail_map_entry_t));
    Hacl_Streaming_SHA2_finish_256(st, hash_of_state->v);
    Hacl_Streaming_SHA2_free_256(st);
  }
}

int ecall_dispatcher::append_view_ledger(digest_t* block_hash, signature_t* signature) {
  int ret = 0;
  int res = 0;

  digest_t hash_of_state;
  digest_t prev;
  unsigned int height;
  Hacl_Streaming_SHA2_state_sha2_256* st;
 
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
  st = Hacl_Streaming_SHA2_create_in_256();
  Hacl_Streaming_SHA2_update_256(st, (unsigned char *) &m, sizeof(meta_block_t));
  Hacl_Streaming_SHA2_finish_256(st, h_m.v);
  Hacl_Streaming_SHA2_free_256(st);

  // Sign the contents
  uint8_t signature_bytes[SIGNATURE_SIZE_IN_BYTES];
  EverCrypt_Ed25519_sign(signature_bytes, this->private_key, HASH_VALUE_SIZE_IN_BYTES, h_m.v);
  memcpy(signature->v, signature_bytes, SIGNATURE_SIZE_IN_BYTES);

  // update the internal state
  memcpy(this->view_ledger_tail.v, h_m.v, HASH_VALUE_SIZE_IN_BYTES);
  this->view_ledger_height = this->view_ledger_height + 1;

exit:
  return ret;
}
 
void ecall_dispatcher::terminate() {
  free(private_key);
  free(public_key);
}
