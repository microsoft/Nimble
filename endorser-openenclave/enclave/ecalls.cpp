#include "../shared.h"
#include "endorser.h"
#include "endorser_t.h"
#include <openenclave/enclave.h>

static ecall_dispatcher dispatcher;

endorser_status_code setup(endorser_id_t* endorser_id) {
  return dispatcher.setup(endorser_id);
}

endorser_status_code initialize_state(init_endorser_data_t *state, receipt_t* receipt) {
  return dispatcher.initialize_state(state, receipt);
}

endorser_status_code new_ledger(handle_t* handle, digest_t *block_hash, receipt_t* receipt) {
  return dispatcher.new_ledger(handle, block_hash, receipt);
}

endorser_status_code read_latest(handle_t* handle, nonce_t* nonce, uint64_t expected_height, uint64_t* current_height, receipt_t* receipt) {
  return dispatcher.read_latest(handle, nonce, expected_height, current_height, receipt);
}

endorser_status_code append(handle_t* handle, digest_t* block_hash, uint64_t expected_height, uint64_t* current_height, receipt_t* receipt) {
  return dispatcher.append(handle, block_hash, expected_height, current_height, receipt);
}

endorser_status_code append_view_ledger(digest_t* block_hash, uint64_t expected_height, receipt_t* receipt) {
  return dispatcher.append_view_ledger(block_hash, expected_height, receipt);
}

endorser_status_code get_public_key(endorser_id_t* endorser_id) {
  return dispatcher.get_public_key(endorser_id);
}

endorser_status_code get_ledger_tail_map_size(uint64_t* ledger_tail_map_size) {
  return dispatcher.get_ledger_tail_map_size(ledger_tail_map_size);
}

endorser_status_code read_latest_state(uint64_t ledger_tail_map_size, ledger_tail_map_entry_t* ledger_tail_map, metablock_t* view_tail_metablock) {
  return dispatcher.read_latest_state(ledger_tail_map_size, ledger_tail_map, view_tail_metablock);
}

void terminate() { return dispatcher.terminate(); }
