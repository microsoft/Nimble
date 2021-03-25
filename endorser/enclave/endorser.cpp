#include "endorser.h"
#include "common.h"
#include <string.h>

#define ECPARAMS MBEDTLS_ECP_DP_SECP256R1

int ecall_dispatcher::initialize(ledger_identity_t *ledger_identity,
                                 endorser_identity_t *endorser_identity) {
  TRACE_ENCLAVE("ecall_dispatcher::initialize_endorser");

  int ret = 0;

  TRACE_ENCLAVE("initializing ecdsa context");
  mbedtls_ecdsa_init(&this->ctx_sign);

  // seeding a random number generator
  mbedtls_entropy_context entropy;
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  TRACE_ENCLAVE("initializing seed");
  ret =
      mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
  if (ret != 0) {
    TRACE_ENCLAVE("mbedtls_ctr_drbg_seed failed with %d", ret);
    goto exit;
  }

  TRACE_ENCLAVE("generating an ecdsa key pair");
  ret = mbedtls_ecdsa_genkey(&this->ctx_sign, ECPARAMS, mbedtls_ctr_drbg_random,
                             &this->ctr_drbg);
  if (ret != 0) {
    TRACE_ENCLAVE("mbedtls_ecdsa_genkey failed with %d", ret);
    goto exit;
  }

  size_t len;
  ret = mbedtls_ecp_point_write_binary(
      &ctx_sign.grp, &ctx_sign.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &len,
      endorser_identity->public_key, sizeof endorser_identity->public_key);

  if (ret != 0) {
    TRACE_ENCLAVE("mbedtls_ecp_point_write_binary failed with %d", ret);
    goto exit;
  }

  TRACE_ENCLAVE("length of the public key is %d", (int)len);

  // set the group parameters
  ret = mbedtls_ecp_group_copy(&endorser_identity->grp, &ctx_sign.grp);
  if (ret != 0) {
    TRACE_ENCLAVE("mbedtls_ecp_group_copy failed with %d", ret);
    goto exit;
  }

  // set the name of the ledger
  memcpy((void *)this->hash, ledger_identity->name, HASH_VALUE_SIZE_IN_BYTES);

exit:
  mbedtls_entropy_free(&entropy);
  return ret;
}

int ecall_dispatcher::endorse(block_t *block, endorsement_t *endorsement) {
  TRACE_ENCLAVE("ecall_dispatcher::endorse");

  int ret = 0;

  // endorse only endorses messages of length equal to a hash value
  if (sizeof(block->block) != HASH_VALUE_SIZE_IN_BYTES) {
    ret = 1;
    goto exit;
  }

  // combine the previous hash and the input value
  unsigned char hash_with_input[2 * HASH_VALUE_SIZE_IN_BYTES];
  memcpy(hash_with_input, this->hash, HASH_VALUE_SIZE_IN_BYTES);
  memcpy(&hash_with_input[HASH_VALUE_SIZE_IN_BYTES], block->block,
         HASH_VALUE_SIZE_IN_BYTES);

  // compute a hash = Hash(hash, input)
  ret = mbedtls_sha256_ret(hash_with_input, 2 * HASH_VALUE_SIZE_IN_BYTES, hash,
                           0);
  if (ret != 0) {
    TRACE_ENCLAVE("mbedtls_sha256_ret returned %d\n", ret);
    goto exit;
  }

  // produce a signature for the new hash
  unsigned char sig[MBEDTLS_ECDSA_MAX_LEN];
  size_t sig_len;
  ret = mbedtls_ecdsa_write_signature(&this->ctx_sign, MBEDTLS_MD_SHA256, hash,
                                      HASH_VALUE_SIZE_IN_BYTES,
                                      endorsement->sig, &endorsement->sig_len,
                                      mbedtls_ctr_drbg_random, &this->ctr_drbg);

  if (ret != 0) {
    TRACE_ENCLAVE("mbedtls_ecdsa_write_signature returned %d\n", ret);
    goto exit;
  }

exit:
  return ret;
}

int ecall_dispatcher::read(nonce_t *nonce, endorsement_t *endorsement) {
  TRACE_ENCLAVE("ecall_dispatcher::read");

  int ret = 0;

  // nonce length must equal to a hash value
  if (sizeof(nonce->nonce) != NONCE_SIZE_IN_BYTES) {
    ret = 1;
    goto exit;
  }

  // combine the previous hash and the input value
  unsigned char hash_with_input[HASH_VALUE_SIZE_IN_BYTES + NONCE_SIZE_IN_BYTES];
  memcpy(hash_with_input, this->hash, HASH_VALUE_SIZE_IN_BYTES);
  memcpy(&hash_with_input[HASH_VALUE_SIZE_IN_BYTES], nonce->nonce,
         NONCE_SIZE_IN_BYTES);

  // set output hash
  memcpy(endorsement->hash, this->hash, HASH_VALUE_SIZE_IN_BYTES);

  // compute a hash = Hash(hash, input)
  unsigned char nonced_hash[HASH_VALUE_SIZE_IN_BYTES];
  ret = mbedtls_sha256_ret(hash_with_input,
                           HASH_VALUE_SIZE_IN_BYTES + NONCE_SIZE_IN_BYTES,
                           nonced_hash, 0);
  if (ret != 0) {
    TRACE_ENCLAVE("mbedtls_sha256_ret returned %d\n", ret);
    goto exit;
  }

  // produce a signature for the new hash
  unsigned char sig[MBEDTLS_ECDSA_MAX_LEN];
  size_t sig_len;
  ret = mbedtls_ecdsa_write_signature(
      &ctx_sign, MBEDTLS_MD_SHA256, hash, sizeof(hash), endorsement->sig,
      &endorsement->sig_len, mbedtls_ctr_drbg_random, &ctr_drbg);

  if (ret != 0) {
    TRACE_ENCLAVE("mbedtls_ecdsa_write_signature returned %d\n", ret);
    goto exit;
  }

exit:
  return ret;
}

void ecall_dispatcher::close() {
  TRACE_ENCLAVE("ecall_dispatcher::close");
  mbedtls_ecdsa_free(&this->ctx_sign);
  mbedtls_ctr_drbg_free(&this->ctr_drbg);
}

int ecall_dispatcher::verify_endorse(ledger_identity_t *ledger_identity,
                                     endorser_identity_t *endorser_identity,
                                     block_t *block,
                                     endorsement_t *endorsement) {
  TRACE_ENCLAVE("ecall_dispatcher::verify_endorse");
  int ret = 0;
  // check if the endorsement is valid
  // (1) compute hash \gets Hash(name, block)
  unsigned char message[2 * HASH_VALUE_SIZE_IN_BYTES];
  memcpy(message, ledger_identity->name, HASH_VALUE_SIZE_IN_BYTES);
  memcpy(&message[HASH_VALUE_SIZE_IN_BYTES], block->block,
         HASH_VALUE_SIZE_IN_BYTES);
  unsigned char hash[HASH_VALUE_SIZE_IN_BYTES];
  ret = mbedtls_sha256_ret(message, 2 * HASH_VALUE_SIZE_IN_BYTES, hash, 0);
  if (ret != 0) {
    TRACE_ENCLAVE("mbedtls_sha256_ret returned %d", ret);
    goto exit;
  }
  // (2) check if sig is a valid signature on hash under the public key from
  // the initialization
  mbedtls_ecdsa_context ctx_verify;
  mbedtls_ecdsa_init(&ctx_verify);
  ret = mbedtls_ecp_group_copy(&ctx_verify.grp, &endorser_identity->grp);
  if (ret != 0) {
    TRACE_ENCLAVE("mbedtls_ecp_group_copy returned %d", ret);
    goto exit;
  }
  ret = mbedtls_ecp_point_read_binary(&endorser_identity->grp, &ctx_verify.Q,
                                      endorser_identity->public_key,
                                      PUBLIC_KEY_SIZE_IN_BYTES);
  if (ret != 0) {
    TRACE_ENCLAVE("mbedtls_ecp_point_read_binary returned %d", ret);
    goto exit;
  }

  ret =
      mbedtls_ecdsa_read_signature(&ctx_verify, hash, HASH_VALUE_SIZE_IN_BYTES,
                                   endorsement->sig, endorsement->sig_len);
  if (ret != 0) {
    TRACE_ENCLAVE("mbedtls_ecdsa_read_signature returned %d", ret);
    goto exit;
  }

exit:
  return ret;
}
