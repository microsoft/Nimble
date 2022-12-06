#include <openenclave/enclave.h>
#include "../shared.h"
#include "endorser.h"
#include "endorser_t.h"

static ecall_dispatcher dispatcher;

endorser_status_code setup(endorser_id_t* endorser_id) {
  return dispatcher.setup(endorser_id);
}

endorser_status_code initialize_state(init_endorser_data_t *state, uint64_t ledger_tail_map_size, ledger_tail_map_entry_t* ledger_tail_map, receipt_t* receipt) {
  return dispatcher.initialize_state(state, ledger_tail_map_size, ledger_tail_map, receipt);
}

endorser_status_code new_ledger(handle_t* handle, digest_t *block_hash, uint64_t block_size, uint8_t* block, receipt_t* receipt) {
  return dispatcher.new_ledger(handle, block_hash, block_size, block, receipt);
}

endorser_status_code read_latest(handle_t* handle, nonce_t* nonce, uint64_t* block_size, uint8_t* block, uint64_t* nonces_size, uint8_t* nonces, receipt_t* receipt) {
  return dispatcher.read_latest(handle, nonce, block_size, block, nonces_size, nonces, receipt);
}

endorser_status_code append(handle_t* handle, digest_t* block_hash, uint64_t expected_height, uint64_t* current_height, uint64_t block_size, uint8_t* block, uint64_t nonces_size, uint8_t* nonces, receipt_t* receipt) {
  return dispatcher.append(handle, block_hash, expected_height, current_height, block_size, block, nonces_size, nonces, receipt);
}

endorser_status_code finalize_state(digest_t* block_hash, uint64_t expected_height, uint64_t ledger_tail_map_size, ledger_tail_map_entry_t* ledger_tail_map, receipt_t* receipt) {
  return dispatcher.finalize_state(block_hash, expected_height, ledger_tail_map_size, ledger_tail_map, receipt);
}

endorser_status_code get_public_key(endorser_id_t* endorser_id) {
  return dispatcher.get_public_key(endorser_id);
}

endorser_status_code get_ledger_tail_map_size(uint64_t* ledger_tail_map_size) {
  return dispatcher.get_ledger_tail_map_size(ledger_tail_map_size);
}

endorser_status_code read_state(uint64_t ledger_tail_map_size, ledger_tail_map_entry_t* ledger_tail_map, endorser_mode_t* endorser_mode, receipt_t* receipt) {
  return dispatcher.read_state(ledger_tail_map_size, ledger_tail_map, endorser_mode, receipt);
}

endorser_status_code activate() {
  return dispatcher.activate();
}

void terminate() { return dispatcher.terminate(); }
