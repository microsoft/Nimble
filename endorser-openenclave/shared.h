#ifndef _SHARED_H
#define _SHARED_H

#define HASH_VALUE_SIZE_IN_BYTES 32
#define PUBLIC_KEY_SIZE_IN_BYTES 33
#define SIGNATURE_SIZE_IN_BYTES 64 
#define NONCE_SIZE_IN_BYTES 16

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

typedef struct _meta_block {
  unsigned char view[HASH_VALUE_SIZE_IN_BYTES];
  unsigned char prev[HASH_VALUE_SIZE_IN_BYTES];
  unsigned char cur[HASH_VALUE_SIZE_IN_BYTES];
  unsigned long long height;
} meta_block_t;

typedef struct _nonce {
  unsigned char v[NONCE_SIZE_IN_BYTES];
} nonce_t;

typedef struct _signature {
  unsigned char v[SIGNATURE_SIZE_IN_BYTES];
} signature_t;

typedef struct _ledger_tail_map_entry {
  handle_t handle;
  digest_t tail;
  unsigned long long height;
} ledger_tail_map_entry_t;

typedef struct _init_endorser_data {
  unsigned long long ledger_tail_map_size;
  ledger_tail_map_entry_t *ledger_tail_map;
  
  digest_t view_ledger_tail;
  unsigned long long view_ledger_height;
  digest_t block_hash;
  digest_t cond_updated_tail_hash;
} init_endorser_data_t;

// The following status code should match with grpc
typedef enum _endorser_status_code {
  OK = 0,
  INVALID_ARGUMENT = 3,
  NOT_FOUND = 5,
  ALREADY_EXISTS = 6,
  FAILED_PRECONDITION = 9,
  ABORTED = 10,
  OUT_OF_RANGE = 11,
  INTERNAL = 13,
  UNAVAILABLE = 14,
} endorser_status_code;

#endif /* _SHARED_H */
