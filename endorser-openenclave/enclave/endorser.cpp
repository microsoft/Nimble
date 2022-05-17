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

void digest_with_digest(digest_t *digest0, digest_t *digest1) {
  digest_t digests[2];

  memcpy(&digests[0], digest0, sizeof(digest_t));
  memcpy(&digests[1], digest1, sizeof(digest_t));
  calc_digest((unsigned char *)&digests[0], sizeof(digest_t) * 2, digest1);
}

void digest_with_nonce(digest_t *digest, nonce_t* nonce) {
  unsigned char buf[sizeof(digest_t) + sizeof(nonce_t)];

  memcpy(&buf[0], digest, sizeof(digest_t));
  memcpy(&buf[sizeof(digest_t)], nonce, sizeof(nonce_t));
  calc_digest(buf, sizeof(digest_t) + sizeof(nonce_t), digest);
}

int calc_receipt(const handle_t * handle, const metablock_t *metablock, const digest_t *hash, digest_t *view, nonce_t* nonce, EC_KEY* eckey, unsigned char* public_key, receipt_t* receipt) {
  digest_t digest;

  // hash the metadata block and construct the message
  memcpy(&digest, hash, sizeof(digest_t));
  if (nonce != NULL)
    digest_with_nonce(&digest, nonce);
  if (handle != NULL)
    digest_with_digest((digest_t*)handle, &digest);
  digest_with_digest(view, &digest);

  // sign the message
  int ret = calc_signature(eckey, &digest, &receipt->sig);
  if (ret) {
    // construct the receipt
    memcpy(receipt->view.v, view->v, HASH_VALUE_SIZE_IN_BYTES);
    memcpy(&receipt->metablock, metablock, sizeof(metablock_t));
    memcpy(receipt->id.v, public_key, PUBLIC_KEY_SIZE_IN_BYTES);
  }

  return ret;
}

endorser_status_code ecall_dispatcher::setup(endorser_id_t* endorser_id) {
  endorser_status_code ret = endorser_status_code::OK;
  int res = 0;

  // set is_initialized to false 
  this->is_initialized = false;

  eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (eckey == NULL) {
    ret = endorser_status_code::INTERNAL;
    TRACE_ENCLAVE("EC_KEY_new_by_curve_name returned NULL");
    goto exit;
  }
  
  if (!EC_KEY_generate_key(eckey)) {
    ret = endorser_status_code::INTERNAL;
    TRACE_ENCLAVE("EC_KEY_generate_key returned 1");
    goto exit;
  }

  unsigned char *pk;
  res = EC_KEY_key2buf(eckey, POINT_CONVERSION_COMPRESSED, &pk, NULL);
  if (res == 0) {
    ret = endorser_status_code::INTERNAL;
    TRACE_ENCLAVE("Error converting private key to public key");
    goto exit;
  }

  // copy the public key and free the buffer
  assert(res == PUBLIC_KEY_SIZE_IN_BYTES);
  memcpy(endorser_id->pk, pk, PUBLIC_KEY_SIZE_IN_BYTES);
  this->public_key = pk;

exit:
  return ret;
}

endorser_status_code ecall_dispatcher::initialize_state(init_endorser_data_t *state, receipt_t *receipt) {
  endorser_status_code ret = endorser_status_code::OK;
  int i = 0;

  // check if the endorser is already initialized 
  // and return an error if the endorser is already initialized
  if (this->is_initialized) {
    ret = endorser_status_code::ALREADY_EXISTS;
    goto exit;
  }

  // copy each element from ledger_tail_map to this->ledger_tail_map
  for (i = 0; i < state->ledger_tail_map_size; i++) { 
    handle_t *handle = &state->ledger_tail_map[i].handle;
    metablock_t *metablock = &state->ledger_tail_map[i].metablock;
    digest_t metablock_hash;

    // check if the handle already exists
    if (this->ledger_tail_map.find(*handle) != this->ledger_tail_map.end()) {
      TRACE_ENCLAVE("[Enclave] initialize_state:: Handle already exists %d",(int) this->ledger_tail_map.count(*handle));
      ret = endorser_status_code::INVALID_ARGUMENT;
      goto exit;
    }
 
    // since the requested handle isn't already inserted, we insert it into state 
    calc_digest((unsigned char*)metablock, sizeof(metablock_t), &metablock_hash);
    this->ledger_tail_map.emplace(*handle, make_pair(*metablock, metablock_hash));
  }

  // copy the view ledger tail metablock
  memcpy(&this->view_ledger_tail_metablock, &state->view_tail_metablock, sizeof(metablock_t));
  calc_digest((unsigned char *)&this->view_ledger_tail_metablock, sizeof(metablock_t), &this->view_ledger_tail_hash);

  this->is_initialized = true;

  return append_view_ledger(&state->block_hash, state->expected_height, receipt);

 exit:
  return ret;
}

endorser_status_code ecall_dispatcher::new_ledger(handle_t* handle, digest_t *block_hash, receipt_t* receipt) {
  endorser_status_code ret = endorser_status_code::OK;
  int res = 0;

  // check if the state is initialized
  if (!is_initialized) {
    ret = endorser_status_code::UNIMPLEMENTED;
    goto exit;
  }

  // check if the handle already exists
  if (this->ledger_tail_map.find(*handle) != this->ledger_tail_map.end()) {
    TRACE_ENCLAVE("[Enclave] New Ledger :: Handle already exists %d",(int) this->ledger_tail_map.count(*handle));
    ret = endorser_status_code::ALREADY_EXISTS;
    goto exit;
  }

  metablock_t metablock;
  digest_t metablock_hash;
  memset(metablock.prev.v, 0, HASH_VALUE_SIZE_IN_BYTES);
  memcpy(metablock.block_hash.v, block_hash->v, HASH_VALUE_SIZE_IN_BYTES);
  metablock.height = 0;
  calc_digest((unsigned char *)&metablock, sizeof(metablock_t), &metablock_hash);

  // store handle under the same name in the map
  this->ledger_tail_map.emplace(*handle, make_tuple(metablock, metablock_hash));

  res = calc_receipt(handle, &metablock, &metablock_hash, &this->view_ledger_tail_hash, nullptr, this->eckey, this->public_key, receipt);
  if (res == 0) {
    ret = endorser_status_code::INTERNAL;
	  TRACE_ENCLAVE("Error producing a signature");
    goto exit;
  }

exit:
  return ret;
}
  
endorser_status_code ecall_dispatcher::read_latest(handle_t* handle, nonce_t* nonce, uint64_t expected_height, uint64_t* current_height, receipt_t* receipt) {
  endorser_status_code ret = endorser_status_code::OK;
  int res = 0;

  // check if the state is initialized
  if (!is_initialized) {
    ret = endorser_status_code::UNIMPLEMENTED;
  } else {
    // check if the handle exists, exit if there is no handle found to read
    auto it = this->ledger_tail_map.find(*handle);
    if (it == this->ledger_tail_map.end()) {
      ret = endorser_status_code::NOT_FOUND;
      TRACE_ENCLAVE("[Read Latest] Exited at the handle existence check. Requested Handle does not exist\n");
    } else {
      metablock_t *metablock = &it->second.first;
      digest_t *metablock_hash = &it->second.second;
      *current_height = metablock->height;

      if (expected_height < metablock->height) {
        ret = endorser_status_code::INVALID_ARGUMENT;
        TRACE_ENCLAVE("The expected tail height is too small");
      } else if (expected_height > metablock->height) {
        ret = endorser_status_code::FAILED_PRECONDITION;
        TRACE_ENCLAVE("The expected tail height is out of order");
      } else {
        res = calc_receipt(handle, metablock, metablock_hash, &this->view_ledger_tail_hash, nonce, this->eckey, this->public_key, receipt);
        if (res == 0) {
          ret = endorser_status_code::INTERNAL;
          TRACE_ENCLAVE("Error producing a signature");
        }
      }
    }
  }

  return ret;
}
  
endorser_status_code ecall_dispatcher::append(handle_t *handle, digest_t* block_hash, uint64_t expected_height, uint64_t* current_height, receipt_t* receipt) {
  endorser_status_code ret = endorser_status_code::OK;
  int res = 0;

  digest_t prev;
  unsigned long long height;
 
  // check if the state is initialized
  if (!is_initialized) {
    ret = endorser_status_code::UNIMPLEMENTED;
  } else {
    // check if the handle exists
    auto it = this->ledger_tail_map.find(*handle);
    if (it == this->ledger_tail_map.end()) {
      TRACE_ENCLAVE("[Append] Exited at the handle existence check. Requested handle does not exist\n");
      ret = endorser_status_code::NOT_FOUND;
      goto exit;
    }

    // obtain the current value of the current tail and height
    metablock_t *metablock = &it->second.first;
    digest_t *metablock_hash = &it->second.second;
    *current_height = metablock->height;

    // check for integer overflow of height
    if (metablock->height == ULLONG_MAX) {
      TRACE_ENCLAVE("The number of blocks has reached ULLONG_MAX");
      ret = endorser_status_code::OUT_OF_RANGE;
      goto exit;
    }

    if (expected_height <= metablock->height) {
      TRACE_ENCLAVE("The new tail height is too small");
      ret = endorser_status_code::ALREADY_EXISTS;
      goto exit;
    }

    if (expected_height > metablock->height + 1) {
      TRACE_ENCLAVE("The new append entry is out of order");
      ret = endorser_status_code::FAILED_PRECONDITION;
      goto exit;
    }

    memcpy(metablock->prev.v, metablock_hash->v, HASH_VALUE_SIZE_IN_BYTES);
    memcpy(metablock->block_hash.v, block_hash->v, HASH_VALUE_SIZE_IN_BYTES);
    metablock->height += 1;
    calc_digest((unsigned char *)metablock, sizeof(metablock_t), metablock_hash);

    res = calc_receipt(handle, metablock, metablock_hash, &this->view_ledger_tail_hash, nullptr, this->eckey, this->public_key, receipt);
    if (res == 0) {
      ret = endorser_status_code::INTERNAL;
      TRACE_ENCLAVE("Error producing a signature");
      goto exit;
    }
  }

exit:
  return ret;
}
  
endorser_status_code ecall_dispatcher::get_public_key(endorser_id_t* endorser_id) {
  memcpy(endorser_id->pk, this->public_key, PUBLIC_KEY_SIZE_IN_BYTES);
  return endorser_status_code::OK;
}

void calc_hash_of_state(map<handle_t, pair<metablock_t, digest_t>, comparator> *ledger_tail_map, digest_t *hash_of_state) {
  int num_entries = ledger_tail_map->size();
  ledger_tail_entry_t entries[num_entries];
  int i = 0;

  // if there are no entries in the map, we return a default digest
  if (num_entries == 0) {
    memset(hash_of_state->v, 0, HASH_VALUE_SIZE_IN_BYTES);
  } else {
    for (auto it = ledger_tail_map->begin(); it != ledger_tail_map->end(); it++) {
      memcpy(entries[i].handle.v, it->first.v, HASH_VALUE_SIZE_IN_BYTES);
      memcpy(entries[i].tail.v, it->second.second.v, HASH_VALUE_SIZE_IN_BYTES);
      entries[i].height = it->second.first.height;
      i++;
    }
    calc_digest((unsigned char *) entries, num_entries * sizeof(ledger_tail_entry_t), hash_of_state);
  }
}

endorser_status_code ecall_dispatcher::append_view_ledger(digest_t* block_hash, uint64_t expected_height, receipt_t* receipt) {
  endorser_status_code ret = endorser_status_code::OK;
  int res = 0;

  digest_t hash_of_state;
 
  // check if the state is initialized
  if (!is_initialized) {
    ret = endorser_status_code::UNIMPLEMENTED;
    goto exit;
  } 
  
  // obtain the current value of the view ledger information, and check if the height will overflow after the append
  if (this->view_ledger_tail_metablock.height == ULLONG_MAX) {
    TRACE_ENCLAVE("The number of blocks has reached ULLONG_MAX in the view ledger");
    ret = endorser_status_code::OUT_OF_RANGE;
    goto exit;
  }

  if (expected_height <= this->view_ledger_tail_metablock.height) {
    TRACE_ENCLAVE("The new tail height is too small");
    ret = endorser_status_code::ALREADY_EXISTS;
    goto exit;
  }

  if (expected_height > this->view_ledger_tail_metablock.height + 1) {
    TRACE_ENCLAVE("The new append entry is out of order");
    ret = endorser_status_code::FAILED_PRECONDITION;
    goto exit;
  }

  // calculate the hash of the current state
  calc_hash_of_state(&this->ledger_tail_map, &hash_of_state);

  // update the view ledger tail metablock
  memcpy(this->view_ledger_tail_metablock.prev.v, view_ledger_tail_hash.v, HASH_VALUE_SIZE_IN_BYTES);
  memcpy(this->view_ledger_tail_metablock.block_hash.v, block_hash->v, HASH_VALUE_SIZE_IN_BYTES);
  this->view_ledger_tail_metablock.height += 1;
  calc_digest((unsigned char *)&this->view_ledger_tail_metablock, sizeof(metablock_t), &this->view_ledger_tail_hash);

  res = calc_receipt(nullptr, &this->view_ledger_tail_metablock, &this->view_ledger_tail_hash, &hash_of_state, nullptr, this->eckey, this->public_key, receipt);
  if (res == 0) {
    ret = endorser_status_code::INTERNAL;
	  TRACE_ENCLAVE("Error producing a signature");
    goto exit;
  }
  
exit:
  return ret;
}

endorser_status_code ecall_dispatcher::get_ledger_tail_map_size(uint64_t* ledger_tail_map_size) {
  *ledger_tail_map_size = this->ledger_tail_map.size();
  return endorser_status_code::OK;
}

endorser_status_code ecall_dispatcher::read_latest_state(uint64_t ledger_tail_map_size, ledger_tail_map_entry_t* ledger_tail_map, metablock_t* view_tail_metablock) {
  if (ledger_tail_map_size != this->ledger_tail_map.size()) {
    return endorser_status_code::INVALID_ARGUMENT;
  }

  memcpy(view_tail_metablock, &this->view_ledger_tail_metablock, sizeof(metablock_t));
  uint64_t index = 0;
  for (auto it = this->ledger_tail_map.begin(); it != this->ledger_tail_map.end(); it++) {
    memcpy(&ledger_tail_map[index].handle, &it->first, sizeof(handle_t));
    memcpy(&ledger_tail_map[index].metablock, &it->second.first, sizeof(metablock_t));
    index++;
  }

  return endorser_status_code::OK;
}
 
void ecall_dispatcher::terminate() {
  EC_KEY_free(this->eckey); 
}
