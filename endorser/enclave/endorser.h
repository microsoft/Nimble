#pragma once

#include "../shared.h"
#include <openenclave/enclave.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/sha.h>
#include <string>

using namespace std;

class ecall_dispatcher {
private:
  // ECDSA key
  EC_KEY *eckey;

  // tail hash
  unsigned char hash[HASH_VALUE_SIZE_IN_BYTES];

public:
  int initialize(ledger_identity_t *ledger_identity,
                 endorser_identity_t *endorser_identity);
  int endorse(block_t *block, endorsement_t *endorsement);
  int read(nonce_t *block, endorsement_t *endorsement);
  void close();
  int verify_endorse(ledger_identity_t *ledger_identity,
                     endorser_identity_t *endorser_identity, block_t *block,
                     endorsement_t *endorsement);
};
