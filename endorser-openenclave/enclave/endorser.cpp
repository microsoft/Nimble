#include "endorser.h"
#include "common.h"
#include <string.h>

#define ECPARAMS MBEDTLS_ECP_DP_SECP256R1

int ecall_dispatcher::initialize(ledger_identity_t *ledger_identity,
                                 endorser_identity_t *endorser_identity) {
  int ret = 0;
  int res = 0;

  eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (eckey == NULL) {
    ret = 1;
    TRACE_ENCLAVE("EC_KEY_new_by_curve_name returned 1");
    goto exit;
  }

  if (!EC_KEY_generate_key(eckey)) {
    ret = 1;
    TRACE_ENCLAVE("EC_KEY_generate_key returned 1");
    goto exit;
  }

  unsigned char *pk;
  res = EC_KEY_key2buf(eckey, POINT_CONVERSION_COMPRESSED, &pk, NULL);
  if (res == 0) {
    ret = 1;
    TRACE_ENCLAVE("EC_KEY_key2buf returned an error");
    goto exit;
  }

  // copy the public key and free the buffer
  assert(res == PUBLIC_KEY_SIZE_IN_BYTES);
  memcpy(endorser_identity->public_key, pk, PUBLIC_KEY_SIZE_IN_BYTES);
  free(pk);

  // set the name of the ledger
  memcpy((void *)this->hash, ledger_identity->name, HASH_VALUE_SIZE_IN_BYTES);

exit:
  return ret;
}

int ecall_dispatcher::endorse(block_t *block, endorsement_t *endorsement) {
  int ret = 0;
  int res = 0;

  // endorse only endorses messages of length equal to a hash value
  if (sizeof(block->block) != HASH_VALUE_SIZE_IN_BYTES) {
    ret = 1;
    goto exit;
  }

  // set the output hash as the current running hash
  memcpy(endorsement->hash, this->hash, HASH_VALUE_SIZE_IN_BYTES);

  // combine the running hash and the input value
  unsigned char hash_with_block[2 * HASH_VALUE_SIZE_IN_BYTES];
  memcpy(hash_with_block, this->hash, HASH_VALUE_SIZE_IN_BYTES);
  memcpy(&hash_with_block[HASH_VALUE_SIZE_IN_BYTES], block->block,
         HASH_VALUE_SIZE_IN_BYTES);

  // compute a hash = Hash(hash, input), overwriting the running hash
  SHA256(hash_with_block, 2 * HASH_VALUE_SIZE_IN_BYTES, hash);

  // produce a signature for the new hash
  res = ECDSA_sign(0, hash, HASH_VALUE_SIZE_IN_BYTES, endorsement->sig,
                   &endorsement->sig_len, eckey);

  if (res == 0) {
    ret = 1;
    TRACE_ENCLAVE("ECDSA_sign returned an error");
    goto exit;
  }

exit:
  return ret;
}

int ecall_dispatcher::read(nonce_t *nonce, endorsement_t *endorsement) {
  int ret = 0;
  int res = 0;

  // set the output hash as the current running hash
  memcpy(endorsement->hash, this->hash, HASH_VALUE_SIZE_IN_BYTES);

  // combine the running hash and the nonce value
  unsigned char hash_with_block[HASH_VALUE_SIZE_IN_BYTES + NONCE_SIZE_IN_BYTES];
  memcpy(hash_with_block, this->hash, HASH_VALUE_SIZE_IN_BYTES);
  memcpy(&hash_with_block[NONCE_SIZE_IN_BYTES], nonce->nonce,
         NONCE_SIZE_IN_BYTES);

  // compute a hash = Hash(hash, input), overwriting the running hash
  unsigned char nonced_hash[HASH_VALUE_SIZE_IN_BYTES];
  SHA256(hash_with_block, HASH_VALUE_SIZE_IN_BYTES + NONCE_SIZE_IN_BYTES,
         nonced_hash);

  // produce a signature for the new hash
  res = ECDSA_sign(0, nonced_hash, HASH_VALUE_SIZE_IN_BYTES, endorsement->sig,
                   &endorsement->sig_len, eckey);

  if (res == 0) {
    ret = 1;
    TRACE_ENCLAVE("ECDSA_sign returned an error");
    goto exit;
  }

exit:
  return ret;
}

void ecall_dispatcher::close() { EC_KEY_free(eckey); }