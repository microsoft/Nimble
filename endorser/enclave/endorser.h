#pragma once

#include "../shared.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/sha256.h"
#include <mbedtls/ecdsa.h>
#include <mbedtls/entropy.h>
#include <openenclave/enclave.h>
#include <string>

using namespace std;

class ecall_dispatcher {
private:
  // ECDSA context
  mbedtls_ecdsa_context ctx_sign;
  mbedtls_ctr_drbg_context ctr_drbg;

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
