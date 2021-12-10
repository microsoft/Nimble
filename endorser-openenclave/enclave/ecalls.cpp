#include "../shared.h"
#include "endorser.h"
#include "endorser_t.h"
#include <openenclave/enclave.h>

static ecall_dispatcher dispatcher;

int setup(endorser_id_t* endorser_id) {
  return dispatcher.setup(endorser_id);
}

int initialize_state(init_endorser_data_t *state, signature_t* signature) {
  return dispatcher.initialize_state(state, signature);
}

int new_ledger(handle_t* handle, signature_t* signature) {
  return dispatcher.new_ledger(handle, signature);
}

int read_latest(handle_t* handle, nonce_t* nonce, signature_t* signature) {
  return dispatcher.read_latest(handle, nonce, signature);
}

int append(handle_t* handle, digest_t* block_hash, signature_t* signature) {
  return dispatcher.append(handle, block_hash, signature);
}

int read_latest_view_ledger(nonce_t* nonce, signature_t* signature) {
  return dispatcher.read_latest_view_ledger(nonce, signature);
}

int append_view_ledger(digest_t* block_hash, signature_t* signature) {
  return dispatcher.append_view_ledger(block_hash, signature);
}

int get_public_key(endorser_id_t* endorser_id) {
  return dispatcher.get_public_key(endorser_id);
}

void terminate() { return dispatcher.terminate(); }
