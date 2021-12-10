#pragma once

#include "../shared.h"
#include <openenclave/enclave.h>
#include <string>
#include <map>
#include <tuple>
#include "common.h"
#include <string.h>
#include "NimbleEverCrypt/EverCrypt_Ed25519.h"
#include "NimbleEverCrypt/Hacl_Streaming_SHA2.h"

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
  // EdDSA KeyPair of the endorser
  uint8_t private_key[PRIVATE_KEY_SIZE_IN_BYTES];
  uint8_t public_key[PUBLIC_KEY_SIZE_IN_BYTES];

  // tail hash for each ledger along with their current heights
  map<handle_t, tuple<digest_t, unsigned long long>, comparator> ledger_tail_map;

  // tail hash and height of the view ledger
  digest_t view_ledger_tail;
  unsigned long long view_ledger_height;

  // whether the endorser's state (tails and view ledger) is initialized
  bool is_initialized;

public:
  int setup(endorser_id_t* endorser_id);
  int initialize_state(init_endorser_data_t *state, signature_t* signature);
  int new_ledger(handle_t* handle, signature_t* signature);
  int read_latest(handle_t* handle, nonce_t* nonce, signature_t* signature);
  int append(handle_t *handle, digest_t* block_hash, signature_t* signature);
  int read_latest_view_ledger(nonce_t* nonce, signature_t* signature);
  int append_view_ledger(digest_t* block_hash, signature_t* signature);
  int get_public_key(endorser_id_t* endorser_id);
  void terminate();
};
