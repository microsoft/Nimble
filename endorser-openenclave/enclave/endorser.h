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

  // tail hash for each ledger
  map<handle_t, tuple<digest_t, unsigned long long>, comparator> endorser_state;

public:
  int setup(endorser_id_t* endorser_id);
  int new_ledger(handle_t* handle, signature_t* signature);
  int read_latest(handle_t* handle, nonce_t* nonce, digest_t* tail, height_t* h, signature_t* signature);
  int append(handle_t *handle, digest_t* block_hash, digest_t* cond_tail_hash, digest_t* prev_tail, height_t* h, signature_t* signature);
  int get_public_key(endorser_id_t* endorser_id);
  void terminate();

  // for testing purposes; TODO: delete
  int verify_append(endorser_id_t* endorser_id, handle_t* handle, digest_t* block_hash, signature_t* signature);
};
