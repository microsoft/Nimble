#ifndef _SHARED_H
#define _SHARED_H

#define PRIVATE_KEY_SIZE_IN_BYTES 32
#define HASH_VALUE_SIZE_IN_BYTES 32
#define PUBLIC_KEY_SIZE_IN_BYTES 33
#define SIGNATURE_SIZE_IN_BYTES 64
#define NONCE_SIZE_IN_BYTES 16

#define MAX_NUM_CHAINS 1024*1024

#pragma pack(push, 1)

// endorser_id_t contains the name of an endorser
typedef struct _endorser_id {
  unsigned char pk[PUBLIC_KEY_SIZE_IN_BYTES];
} endorser_id_t;

// handle_t contains the name of a ledger
typedef struct _handle {
  unsigned char v[HASH_VALUE_SIZE_IN_BYTES];

#ifdef __cplusplus
  friend bool operator< (const struct _handle &h1, const struct _handle &h2) {
    return memcmp(h1.v, h2.v, HASH_VALUE_SIZE_IN_BYTES) < 0;
  }
#endif
} handle_t;

typedef struct _digest {
  unsigned char v[HASH_VALUE_SIZE_IN_BYTES];
} digest_t;

typedef struct _nonce {
  unsigned char v[NONCE_SIZE_IN_BYTES];
} nonce_t;

typedef struct _signature {
  unsigned char v[SIGNATURE_SIZE_IN_BYTES];
} signature_t;

typedef struct _public_key {
  unsigned char v[PUBLIC_KEY_SIZE_IN_BYTES];
} public_key_t;

typedef struct _metablock {
  digest_t prev;
  digest_t block_hash;
  unsigned long long height;
} metablock_t;

typedef struct _chain {
  handle_t handle;
  metablock_t metablock;
  digest_t hash;

  unsigned long long pos;
  unsigned long long prev;
  unsigned long long next;
} chain_t;

typedef struct _receipt {
  digest_t view;
  metablock_t metablock;
  public_key_t id;
  signature_t sig;
} receipt_t;

typedef struct _init_endorser_data {
  chain_t *chains;
  unsigned long long num_chains;
  metablock_t view_tail_metablock;
  digest_t block_hash;
  unsigned long long expected_height;
  digest_t group_identity;
} init_endorser_data_t;

typedef struct _read_ledger_data {
  digest_t block_hash;
  nonce_t nonce;
} read_ledger_data_t;

typedef struct _append_ledger_data {
  digest_t block_hash;
  unsigned long long expected_height;
  bool ignore_lock;
} append_ledger_data_t;

typedef enum _endorser_call {
  start_endorser_call = 0,
  get_pubkey_call = 1,
  init_endorser_call = 2,
  create_ledger_call = 3,
  read_ledger_call = 4,
  append_ledger_call = 5,
  finalize_endorser_call = 6,
  read_endorser_call = 7,
  activate_endorser_call = 8,
} endorser_call_t;

// The following status code should match with grpc
typedef enum _endorser_status_code {
  OK = 0,
  INVALID_ARGUMENT = 3,
  NOT_FOUND = 5,
  ALREADY_EXISTS = 6,
  FAILED_PRECONDITION = 9,
  ABORTED = 10,
  OUT_OF_RANGE = 11,
  UNIMPLEMENTED = 12,
  INTERNAL = 13,
  UNAVAILABLE = 14,
} endorser_status_code;

typedef enum _endorser_mode {
  endorser_uninitialized = -1,
  endorser_started = 0,
  endorser_initialized = 1,
  endorser_active = 2,
  endorser_finalized = 3,
} endorser_mode_t;

#pragma pack(pop)

#endif /* _SHARED_H */
