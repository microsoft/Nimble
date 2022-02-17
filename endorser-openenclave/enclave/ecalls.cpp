#include "../shared.h"
#include "endorser.h"
#include "endorser_t.h"
#include <openenclave/enclave.h>

static ecall_dispatcher dispatcher;

endorser_status_code setup(endorser_id_t* endorser_id) {
  return dispatcher.setup(endorser_id);
}

endorser_status_code initialize_state(init_endorser_data_t *state, signature_t* signature) {
  return dispatcher.initialize_state(state, signature);
}

endorser_status_code new_ledger(handle_t* handle, signature_t* signature) {
  return dispatcher.new_ledger(handle, signature);
}

endorser_status_code read_latest(handle_t* handle, nonce_t* nonce, signature_t* signature) {
  return dispatcher.read_latest(handle, nonce, signature);
}

endorser_status_code append(handle_t* handle, digest_t* block_hash, digest_t* cond_updated_tail_hash, uint64_t* cond_updated_tail_height, signature_t* signature) {
  return dispatcher.append(handle, block_hash, cond_updated_tail_hash, cond_updated_tail_height, signature);
}

endorser_status_code read_latest_view_ledger(nonce_t* nonce, signature_t* signature) {
  return dispatcher.read_latest_view_ledger(nonce, signature);
}

endorser_status_code append_view_ledger(digest_t* block_hash, digest_t* cond_updated_tail_hash, signature_t* signature) {
  return dispatcher.append_view_ledger(block_hash, cond_updated_tail_hash, signature);
}

endorser_status_code get_public_key(endorser_id_t* endorser_id) {
  return dispatcher.get_public_key(endorser_id);
}

void terminate() { return dispatcher.terminate(); }
