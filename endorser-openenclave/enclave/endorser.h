#pragma once

#include "../shared.h"
#include <openenclave/enclave.h>
#include <string>
#include <map>
#include <tuple>
#include "common.h"
#include <string.h>
#include <openssl/sha.h>
#include <openssl/ecdsa.h>
#include <openssl/objects.h>

using namespace std;

#ifndef _OPLT
#define _OPLT
struct comparator {
  bool operator() (const handle_t& l, const handle_t& r) const {
    int n;
    n = memcmp(l.v, r.v, HASH_VALUE_SIZE_IN_BYTES);
    return n < 0;
  }
};
#endif

#pragma pack(push, 1)

class ecall_dispatcher {
private:
  // ECDSA key of the endorser
  EC_KEY* eckey;
  unsigned char* public_key;

  // tail hash for each ledger along with their current heights
  map<handle_t, pair<metablock_t, digest_t>, comparator> ledger_tail_map;

  // view ledger
  metablock_t view_ledger_tail_metablock;
  digest_t view_ledger_tail_hash;

  // whether the endorser's state (tails and view ledger) is initialized
  bool is_initialized;

public:
  endorser_status_code setup(endorser_id_t* endorser_id);
  endorser_status_code initialize_state(init_endorser_data_t *state, receipt_t* receipt);
  endorser_status_code new_ledger(handle_t* handle, digest_t *block_hash, receipt_t* receipt);
  endorser_status_code read_latest(handle_t* handle, nonce_t* nonce, receipt_t* receipt);
  endorser_status_code append(handle_t *handle, digest_t* block_hash, uint64_t expected_height, receipt_t* receipt);
  endorser_status_code append_view_ledger(digest_t* block_hash, uint64_t expected_height, receipt_t* receipt);
  endorser_status_code get_public_key(endorser_id_t* endorser_id);
  endorser_status_code get_ledger_tail_map_size(uint64_t* ledger_tail_map_size);
  endorser_status_code read_latest_state(uint64_t ledger_tail_map_size, ledger_tail_map_entry_t* ledger_tail_map, metablock_t* view_tail_metablock);

  void terminate();
};

#pragma pack(pop)
