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

int calc_receipt(const handle_t * handle, const metablock_t *metablock, const digest_t *hash, digest_t *id, digest_t *view, nonce_t* nonce, EC_KEY* eckey, unsigned char* public_key, receipt_t* receipt) {
  digest_t digest;

  // hash the metadata block and construct the message
  memcpy(&digest, hash, sizeof(digest_t));
  if (nonce != NULL)
    digest_with_nonce(&digest, nonce);
  if (handle != NULL)
    digest_with_digest((digest_t*)handle, &digest);
  digest_with_digest(view, &digest);
  digest_with_digest(id, &digest);

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

  this->endorser_mode = endorser_started;
  memset(this->group_identity.v, 0, HASH_VALUE_SIZE_IN_BYTES);

  if (pthread_rwlock_init(&this->view_ledger_rwlock, nullptr) != 0) {
    ret = endorser_status_code::INTERNAL;
    TRACE_ENCLAVE("Error initializing rwlock");
    goto exit;
  }

  if (pthread_rwlock_init(&this->ledger_map_rwlock, nullptr) != 0) {
    ret = endorser_status_code::INTERNAL;
    TRACE_ENCLAVE("Error initializing rwlock");
    goto exit;
  }

exit:
  return ret;
}

endorser_status_code ecall_dispatcher::initialize_state(init_endorser_data_t *state, receipt_t *receipt) {
  endorser_status_code ret = endorser_status_code::OK;
  int i = 0;

  // check if the endorser is already initialized 
  // and return an error if the endorser is already initialized
  if (this->endorser_mode != endorser_started) {
    return endorser_status_code::UNIMPLEMENTED;
  }

  if (pthread_rwlock_wrlock(&this->view_ledger_rwlock) != 0) {
    return endorser_status_code::INTERNAL;
  }

  // copy each element from ledger_tail_map to this->ledger_tail_map
  for (i = 0; i < state->ledger_tail_map_size; i++) { 
    handle_t *handle = &state->ledger_tail_map[i].handle;
    protected_metablock_t* protected_metablock = new protected_metablock_t;

    // check if the handle already exists
    if (this->ledger_tail_map.find(*handle) != this->ledger_tail_map.end()) {
      TRACE_ENCLAVE("[Enclave] initialize_state:: Handle already exists %d",(int) this->ledger_tail_map.count(*handle));
      ret = endorser_status_code::INVALID_ARGUMENT;
      goto exit;
    }
 
    // since the requested handle isn't already inserted, we insert it into state
    if (pthread_rwlock_init(&protected_metablock->rwlock, nullptr) != 0) {
      ret = endorser_status_code::INTERNAL;
      goto exit;
    }
    memcpy(&protected_metablock->metablock, &state->ledger_tail_map[i].metablock, sizeof(metablock_t));
    calc_digest((unsigned char*)&protected_metablock->metablock, sizeof(metablock_t), &protected_metablock->hash);
    this->ledger_tail_map.insert(make_pair(*handle, protected_metablock));
  }

  // copy the view ledger tail metablock
  memcpy(&this->view_ledger_tail_metablock, &state->view_tail_metablock, sizeof(metablock_t));
  calc_digest((unsigned char *)&this->view_ledger_tail_metablock, sizeof(metablock_t), &this->view_ledger_tail_hash);

  // copy the group identity
  memcpy(this->group_identity.v, state->group_identity.v, HASH_VALUE_SIZE_IN_BYTES);

  this->endorser_mode = endorser_initialized;

  ret = append_view_ledger(&state->block_hash, state->expected_height, receipt);

exit:
  pthread_rwlock_unlock(&this->view_ledger_rwlock);

  return ret;
}

endorser_status_code ecall_dispatcher::new_ledger(handle_t* handle, digest_t *block_hash, receipt_t* receipt) {
  endorser_status_code ret = endorser_status_code::OK;
  int res = 0;
  protected_metablock_t* protected_metablock = nullptr;

  // check if the state is initialized
  if (this->endorser_mode != endorser_active) {
    return endorser_status_code::UNIMPLEMENTED;
  }

  if (pthread_rwlock_rdlock(&this->view_ledger_rwlock) != 0) {
    return endorser_status_code::INTERNAL;
  }

  if (pthread_rwlock_wrlock(&this->ledger_map_rwlock) != 0) {
    ret = endorser_status_code::INTERNAL;
    goto exit_view_lock;
  }

  // check if the handle already exists
  if (this->ledger_tail_map.find(*handle) != this->ledger_tail_map.end()) {
    TRACE_ENCLAVE("[Enclave] New Ledger :: Handle already exists %d",(int) this->ledger_tail_map.count(*handle));
    ret = endorser_status_code::ALREADY_EXISTS;
    goto exit_map_lock;
  }

  protected_metablock = new protected_metablock_t;

  if (pthread_rwlock_init(&protected_metablock->rwlock, nullptr) != 0) {
    ret = endorser_status_code::INTERNAL;
    goto exit_map_lock;
  }

  memset(protected_metablock->metablock.prev.v, 0, HASH_VALUE_SIZE_IN_BYTES);
  memcpy(protected_metablock->metablock.block_hash.v, block_hash->v, HASH_VALUE_SIZE_IN_BYTES);
  protected_metablock->metablock.height = 0;
  calc_digest((unsigned char *)&protected_metablock->metablock, sizeof(metablock_t), &protected_metablock->hash);

  res = calc_receipt(handle, &protected_metablock->metablock, &protected_metablock->hash, &this->group_identity, &this->view_ledger_tail_hash, nullptr, this->eckey, this->public_key, receipt);
  if (res == 0) {
    ret = endorser_status_code::INTERNAL;
	  TRACE_ENCLAVE("Error producing a signature");
    goto exit_map_lock;
  }

  // store handle under the same name in the map
  this->ledger_tail_map.insert(std::make_pair(*handle, protected_metablock));

exit_map_lock:
  pthread_rwlock_unlock(&this->ledger_map_rwlock);

exit_view_lock:
  pthread_rwlock_unlock(&this->view_ledger_rwlock);

  return ret;
}
  
endorser_status_code ecall_dispatcher::read_latest(handle_t* handle, nonce_t* nonce, receipt_t* receipt) {
  endorser_status_code ret = endorser_status_code::OK;
  int res = 0;
  protected_metablock_t* protected_metablock = nullptr;

  // check if the state is initialized
  if (this->endorser_mode != endorser_active) {
    return endorser_status_code::UNIMPLEMENTED;
  }

  if (pthread_rwlock_rdlock(&this->view_ledger_rwlock) != 0) {
    return endorser_status_code::INTERNAL;
  }

  if (pthread_rwlock_rdlock(&this->ledger_map_rwlock) != 0) {
    ret = endorser_status_code::INTERNAL;
  } else {
    // check if the handle exists, exit if there is no handle found to read
    auto it = this->ledger_tail_map.find(*handle);
    if (it == this->ledger_tail_map.end()) {
      ret = endorser_status_code::NOT_FOUND;
      TRACE_ENCLAVE("[Read Latest] Exited at the handle existence check. Requested Handle does not exist\n");
    } else {
      protected_metablock = it->second;
      if (pthread_rwlock_rdlock(&protected_metablock->rwlock) != 0) {
        ret = endorser_status_code::INTERNAL;
      } else {
        res = calc_receipt(handle, &protected_metablock->metablock, &protected_metablock->hash, &this->group_identity, &this->view_ledger_tail_hash, nonce, this->eckey, this->public_key, receipt);
        pthread_rwlock_unlock(&protected_metablock->rwlock);
        if (res == 0) {
          ret = endorser_status_code::INTERNAL;
          TRACE_ENCLAVE("Error producing a signature");
        }
      }
    }
    pthread_rwlock_unlock(&this->ledger_map_rwlock);
  }

  pthread_rwlock_unlock(&this->view_ledger_rwlock);

  return ret;
}
  
endorser_status_code ecall_dispatcher::append(handle_t *handle, digest_t* block_hash, uint64_t expected_height, uint64_t* current_height, receipt_t* receipt) {
  endorser_status_code ret = endorser_status_code::OK;
  int res = 0;

  metablock_t* metablock = nullptr;
  unsigned long long height;
 
  // check if the state is initialized
  if (this->endorser_mode != endorser_active) {
    return endorser_status_code::UNIMPLEMENTED;
  }

  if (pthread_rwlock_rdlock(&this->view_ledger_rwlock) != 0) {
    return endorser_status_code::INTERNAL;
  }

  if (pthread_rwlock_rdlock(&this->ledger_map_rwlock) != 0) {
    return endorser_status_code::INTERNAL;
  } else {
    // check if the handle exists
    auto it = this->ledger_tail_map.find(*handle);
    if (it == this->ledger_tail_map.end()) {
      TRACE_ENCLAVE("[Append] Exited at the handle existence check. Requested handle does not exist\n");
      ret = endorser_status_code::NOT_FOUND;
    } else {
      // obtain the current value of the current tail and height
      protected_metablock_t* protected_metablock = it->second;

      if (pthread_rwlock_wrlock(&protected_metablock->rwlock) != 0) {
        ret = endorser_status_code::INTERNAL;
      } else {
        metablock = &protected_metablock->metablock;
        height = metablock->height;
        *current_height = height;

        // check for integer overflow of height
        if (height == ULLONG_MAX) {
          TRACE_ENCLAVE("The number of blocks has reached ULLONG_MAX");
          ret = endorser_status_code::OUT_OF_RANGE;
        } else if (expected_height <= height) {
          TRACE_ENCLAVE("The new tail height is too small");
          ret = endorser_status_code::ALREADY_EXISTS;
        } else if (expected_height > height + 1) {
          TRACE_ENCLAVE("The new append entry is out of order");
          ret = endorser_status_code::FAILED_PRECONDITION;
        } else {
          memcpy(metablock->prev.v, protected_metablock->hash.v, HASH_VALUE_SIZE_IN_BYTES);
          memcpy(metablock->block_hash.v, block_hash->v, HASH_VALUE_SIZE_IN_BYTES);
          metablock->height += 1;
          calc_digest((unsigned char *)metablock, sizeof(metablock_t), &protected_metablock->hash);

          res = calc_receipt(handle, metablock, &protected_metablock->hash, &this->group_identity, &this->view_ledger_tail_hash, nullptr, this->eckey, this->public_key, receipt);
          if (res == 0) {
            ret = endorser_status_code::INTERNAL;
            TRACE_ENCLAVE("Error producing a signature");
          }
        }
        pthread_rwlock_unlock(&protected_metablock->rwlock);
      }
    }
    pthread_rwlock_unlock(&this->ledger_map_rwlock);
  }

  pthread_rwlock_unlock(&this->view_ledger_rwlock);
  return ret;
}
  
endorser_status_code ecall_dispatcher::get_public_key(endorser_id_t* endorser_id) {
  memcpy(endorser_id->pk, this->public_key, PUBLIC_KEY_SIZE_IN_BYTES);
  return endorser_status_code::OK;
}

void calc_hash_of_state(map<handle_t, protected_metablock_t*, comparator> *ledger_tail_map, digest_t *hash_of_state) {
  int num_entries = ledger_tail_map->size();
  ledger_tail_entry_t entries[num_entries];
  int i = 0;

  // if there are no entries in the map, we return a default digest
  if (num_entries == 0) {
    memset(hash_of_state->v, 0, HASH_VALUE_SIZE_IN_BYTES);
  } else {
    for (auto it = ledger_tail_map->begin(); it != ledger_tail_map->end(); it++) {
      memcpy(entries[i].handle.v, it->first.v, HASH_VALUE_SIZE_IN_BYTES);
      memcpy(entries[i].tail.v, it->second->hash.v, HASH_VALUE_SIZE_IN_BYTES);
      entries[i].height = it->second->metablock.height;
      i++;
    }
    calc_digest((unsigned char *) entries, num_entries * sizeof(ledger_tail_entry_t), hash_of_state);
  }
}

endorser_status_code ecall_dispatcher::sign_view_ledger(receipt_t* receipt) {
  digest_t hash_of_state;

  // calculate the hash of the current state
  calc_hash_of_state(&this->ledger_tail_map, &hash_of_state);
 
  int res = calc_receipt(nullptr, &this->view_ledger_tail_metablock, &this->view_ledger_tail_hash, &this->group_identity, &hash_of_state, nullptr, this->eckey, this->public_key, receipt);
  if (res == 0) {
	  TRACE_ENCLAVE("Error producing a signature");
    return endorser_status_code::INTERNAL;
  } else {
    return endorser_status_code::OK;
  }
}

endorser_status_code ecall_dispatcher::append_view_ledger(digest_t* block_hash, uint64_t expected_height, receipt_t* receipt) {
  // obtain the current value of the view ledger information, and check if the height will overflow after the append
  if (this->view_ledger_tail_metablock.height == ULLONG_MAX) {
    TRACE_ENCLAVE("The number of blocks has reached ULLONG_MAX in the view ledger");
    return endorser_status_code::OUT_OF_RANGE;
  }

  if (expected_height <= this->view_ledger_tail_metablock.height) {
    TRACE_ENCLAVE("The new tail height is too small");
    return endorser_status_code::ALREADY_EXISTS;
  }

  if (expected_height > this->view_ledger_tail_metablock.height + 1) {
    TRACE_ENCLAVE("The new append entry is out of order");
    return endorser_status_code::FAILED_PRECONDITION;
  }

  // update the view ledger tail metablock
  memcpy(this->view_ledger_tail_metablock.prev.v, this->view_ledger_tail_hash.v, HASH_VALUE_SIZE_IN_BYTES);
  memcpy(this->view_ledger_tail_metablock.block_hash.v, block_hash->v, HASH_VALUE_SIZE_IN_BYTES);
  this->view_ledger_tail_metablock.height = expected_height;
  calc_digest((unsigned char *)&this->view_ledger_tail_metablock, sizeof(metablock_t), &this->view_ledger_tail_hash);

  return this->sign_view_ledger(receipt);
}

endorser_status_code ecall_dispatcher::fill_ledger_tail_map(uint64_t ledger_tail_map_size, ledger_tail_map_entry_t* ledger_tail_map) {
  if (ledger_tail_map_size != this->ledger_tail_map.size()) {
    return endorser_status_code::INVALID_ARGUMENT;
  }

  uint64_t index = 0;
  for (auto it = this->ledger_tail_map.begin(); it != this->ledger_tail_map.end(); it++) {
    memcpy(&ledger_tail_map[index].handle, &it->first, sizeof(handle_t));
    memcpy(&ledger_tail_map[index].metablock, &it->second->metablock, sizeof(metablock_t));
    index++;
  }

  return endorser_status_code::OK;
}

endorser_status_code ecall_dispatcher::finalize_state(digest_t* block_hash, uint64_t expected_height, uint64_t ledger_tail_map_size, ledger_tail_map_entry_t* ledger_tail_map, receipt_t* receipt) {
  endorser_status_code ret;

  if (this->endorser_mode == endorser_uninitialized || this->endorser_mode == endorser_initialized) {
    return endorser_status_code::UNIMPLEMENTED;
  }

  if (pthread_rwlock_wrlock(&this->view_ledger_rwlock) != 0) {
    return endorser_status_code::INTERNAL;
  }

  if (endorser_mode == endorser_active) {
    ret = this->append_view_ledger(block_hash, expected_height, receipt);
    if (ret == endorser_status_code::OK) {
      endorser_mode = endorser_finalized;
    }
  } else {
    ret = sign_view_ledger(receipt);
  }

  if (ret == endorser_status_code::OK) {
    ret = this->fill_ledger_tail_map(ledger_tail_map_size, ledger_tail_map);
  }

  pthread_rwlock_unlock(&this->view_ledger_rwlock);

  return ret;
}

endorser_status_code ecall_dispatcher::get_ledger_tail_map_size(uint64_t* ledger_tail_map_size) {
  endorser_status_code ret = endorser_status_code::OK;

  if (pthread_rwlock_rdlock(&this->view_ledger_rwlock) != 0) {
    return endorser_status_code::INTERNAL;
  }

  if (pthread_rwlock_rdlock(&this->ledger_map_rwlock) != 0) {
    ret = endorser_status_code::INTERNAL;
  } else {
    *ledger_tail_map_size = this->ledger_tail_map.size();
    pthread_rwlock_unlock(&this->ledger_map_rwlock);
  }

  pthread_rwlock_unlock(&this->view_ledger_rwlock);

  return ret;
}

endorser_status_code ecall_dispatcher::read_state(uint64_t ledger_tail_map_size, ledger_tail_map_entry_t* ledger_tail_map, endorser_mode_t* endorser_mode, receipt_t* receipt) {
  endorser_status_code ret;

  if (pthread_rwlock_rdlock(&this->view_ledger_rwlock) != 0) {
    return endorser_status_code::INTERNAL;
  }

  if (pthread_rwlock_rdlock(&this->ledger_map_rwlock) != 0) {
    ret = endorser_status_code::INTERNAL;
  } else {
    *endorser_mode = this->endorser_mode;

    ret = this->fill_ledger_tail_map(ledger_tail_map_size, ledger_tail_map);
    if (ret == endorser_status_code::OK) {
      ret = this->sign_view_ledger(receipt);
    }

    pthread_rwlock_unlock(&this->ledger_map_rwlock);
  }

  pthread_rwlock_unlock(&this->view_ledger_rwlock);

  return ret;
}

// TODO: implement the logic to verify view change
endorser_status_code ecall_dispatcher::activate() {
  endorser_status_code ret;

  if (pthread_rwlock_wrlock(&this->view_ledger_rwlock) != 0) {
    return endorser_status_code::INTERNAL;
  }

  if (this->endorser_mode != endorser_initialized) {
    ret = endorser_status_code::UNIMPLEMENTED;
  } else {
    this->endorser_mode = endorser_active;
    ret = endorser_status_code::OK;
  }

  pthread_rwlock_unlock(&this->view_ledger_rwlock);

  return ret;
}

void ecall_dispatcher::terminate() {
  EC_KEY_free(this->eckey); 
}
