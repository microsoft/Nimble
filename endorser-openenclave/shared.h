#ifndef _SHARED_H
#define _SHARED_H

#define HASH_VALUE_SIZE_IN_BYTES 32
#define PUBLIC_KEY_SIZE_IN_BYTES 33
#define SIGNATURE_SIZE_IN_BYTES 64 
#define NONCE_SIZE_IN_BYTES 16
#define MAX_BLOCK_SIZE_IN_BYTES 1024
#define MAX_NONCES_SIZE_IN_BYTES 1024

#pragma pack(push, 1)

// endorser_id_t contains the name of an endorser
typedef struct _endorser_id {
  unsigned char pk[PUBLIC_KEY_SIZE_IN_BYTES];
} endorser_id_t;

typedef struct _height {
  unsigned long long h;
} height_t;

// handle_t contains the name of a ledger
typedef struct _handle {
  unsigned char v[HASH_VALUE_SIZE_IN_BYTES];
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

typedef struct _receipt {
  digest_t view;
  metablock_t metablock;
  public_key_t id;
  signature_t sig;
} receipt_t;

typedef struct _ledger_tail_map_entry {
  handle_t handle;
  metablock_t metablock;
  uint64_t block_size;
  uint64_t nonces_size;
  uint8_t block[MAX_BLOCK_SIZE_IN_BYTES];
  uint8_t nonces[MAX_NONCES_SIZE_IN_BYTES];
} ledger_tail_map_entry_t;

typedef struct _init_endorser_data {
  metablock_t view_tail_metablock;
  digest_t block_hash;
  unsigned long long expected_height;
  digest_t group_identity;
} init_endorser_data_t;

typedef struct _ledger_tail_entry {
  handle_t handle;
  digest_t tail;
  unsigned long long height;
} ledger_tail_entry_t;

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
