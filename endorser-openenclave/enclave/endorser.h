#pragma once

#include "../shared.h"
#include <openenclave/enclave.h>
#include <string>
#include <map>
#include <tuple>
#include "common.h"
#include <string.h>
#include <openssl/sha.h>
#include <openssl/ecdsa.h>
#include <openssl/objects.h>

using namespace std;

#ifndef _OPLT
#define _OPLT
struct comparator {
  bool operator() (const handle_t& l, const handle_t& r) const {
    int n;
    n = memcmp(l.v, r.v, HASH_VALUE_SIZE_IN_BYTES);
    return n < 0;
  }
};
#endif

class ecall_dispatcher {
private:
  // ECDSA key of the endorser
  EC_KEY* eckey;

  // tail hash for each ledger along with their current heights
  map<handle_t, tuple<digest_t, unsigned long long>, comparator> ledger_tail_map;

  // tail hash and height of the view ledger
  digest_t view_ledger_tail;
  unsigned long long view_ledger_height;

  // whether the endorser's state (tails and view ledger) is initialized
  bool is_initialized;

public:
  endorser_status_code setup(endorser_id_t* endorser_id);
  endorser_status_code initialize_state(init_endorser_data_t *state, signature_t* signature);
  endorser_status_code new_ledger(handle_t* handle, signature_t* signature);
  endorser_status_code read_latest(handle_t* handle, nonce_t* nonce, signature_t* signature);
  endorser_status_code append(handle_t *handle, digest_t* block_hash, digest_t *cond_updated_tail_hash, uint64_t* cond_updated_tail_height, signature_t* signature);
  endorser_status_code read_latest_view_ledger(nonce_t* nonce, signature_t* signature);
  endorser_status_code append_view_ledger(digest_t* block_hash, digest_t* cond_updated_tail_hash, signature_t* signature);
  endorser_status_code get_public_key(endorser_id_t* endorser_id);
  void terminate();
};
