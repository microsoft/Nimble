#pragma once

#include "../shared.h"
#include <openenclave/enclave.h>
#include <pthread.h>
#include <string>
#include <map>
#include <tuple>
#include <cassert>
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

typedef struct _protected_metablock_t {
  pthread_rwlock_t rwlock;
  metablock_t metablock;
  digest_t hash;
} protected_metablock_t;

class ecall_dispatcher {
private:
  // ECDSA key of the endorser
  EC_KEY* eckey;
  unsigned char* public_key;

  // the identity for the service
  digest_t group_identity;

  // tail hash for each ledger along with their current heights
  map<handle_t, protected_metablock_t*, comparator> ledger_tail_map;

  // view ledger
  metablock_t view_ledger_tail_metablock;
  digest_t view_ledger_tail_hash;

  // whether the endorser's state (tails and view ledger) is initialized
  endorser_mode_t endorser_mode;

  // rwlocks
  pthread_rwlock_t view_ledger_rwlock;
  pthread_rwlock_t ledger_map_rwlock;

  endorser_status_code append_view_ledger(digest_t* block_hash, uint64_t expected_height, receipt_t* receipt);
  endorser_status_code sign_view_ledger(receipt_t* receipt);
  endorser_status_code fill_ledger_tail_map(uint64_t ledger_tail_map_size, ledger_tail_map_entry_t* ledger_tail_map);

public:
  endorser_status_code setup(endorser_id_t* endorser_id);
  endorser_status_code initialize_state(init_endorser_data_t *state, receipt_t* receipt);
  endorser_status_code new_ledger(handle_t* handle, digest_t *block_hash, receipt_t* receipt);
  endorser_status_code read_latest(handle_t* handle, nonce_t* nonce, receipt_t* receipt);
  endorser_status_code append(handle_t *handle, digest_t* block_hash, uint64_t expected_height, uint64_t* current_height, receipt_t* receipt);
  endorser_status_code finalize_state(digest_t* block_hash, uint64_t expected_height, uint64_t ledger_tail_map_size, ledger_tail_map_entry_t* ledger_tail_map, receipt_t* receipt);
  endorser_status_code get_public_key(endorser_id_t* endorser_id);
  endorser_status_code get_ledger_tail_map_size(uint64_t* ledger_tail_map_size);
  endorser_status_code read_state(uint64_t ledger_tail_map_size, ledger_tail_map_entry_t* ledger_tail_map, endorser_mode_t* endorser_mode, receipt_t* receipt);
  endorser_status_code activate();

  void terminate();
};

#pragma pack(pop)
