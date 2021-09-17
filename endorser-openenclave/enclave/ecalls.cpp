#include "../shared.h"
#include "endorser.h"
#include "endorser_t.h"
#include <openenclave/enclave.h>

static ecall_dispatcher dispatcher;

int setup(endorser_id_t* endorser_id) {
  return dispatcher.setup(endorser_id);
}

int new_ledger(handle_t* handle, signature_t* signature) {
  return dispatcher.new_ledger(handle, signature);
}

int read_latest(handle_t* handle, nonce_t* nonce, digest_t* tail, signature_t* signature) {
  return dispatcher.read_latest(handle, nonce, tail, signature);
}

int append(handle_t* handle, digest_t* block_hash, signature_t* signature) {
  return dispatcher.append(handle, block_hash, signature);
}

int get_public_key(endorser_id_t* endorser_id) {
  return dispatcher.get_public_key(endorser_id);
}

void terminate() { return dispatcher.terminate(); }
