#pragma once

#include "../shared.h"
#include <openenclave/enclave.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/sha.h>
#include <string>
#include <map>
#include <tuple>

using namespace std;

#ifndef _OPLT
#define _OPLT
inline bool operator<(const handle_t& l, const handle_t& r) {
  bool s = true;
  for (int i=0; i< HASH_VALUE_SIZE_IN_BYTES; i++) { 
    s = s & (l.v[i] < r.v[i]);
  }
}
#endif

class ecall_dispatcher {
private:
  // EdDSA KeyPair of the endorser
  uint8_t private_key[PRIVATE_KEY_SIZE_IN_BYTES];
  uint8_t public_key[PUBLIC_KEY_SIZE_IN_BYTES];

  // tail hash for each ledger
  map<handle_t, tuple<digest_t, unsigned int>> endorser_state;

public:
  int setup(endorser_id_t* endorser_id);
  int new_ledger(handle_t* handle, signature_t* signature);
  int read_latest(handle_t* handle, nonce_t* nonce, digest_t* tail, signature_t* signature);
  int append(handle_t *handle, digest_t* block_hash, signature_t* signature);
  int get_public_key(endorser_id_t* endorser_id);
  void terminate();

  // for testing purposes; TODO: delete
  int verify_append(endorser_id_t* endorser_id, handle_t* handle, digest_t* block_hash, signature_t* signature);
};
