#ifndef _SHARED_H
#define _SHARED_H

#define PRIVATE_KEY_SIZE_IN_BYTES 32
#define HASH_VALUE_SIZE_IN_BYTES 32
#define PUBLIC_KEY_SIZE_IN_BYTES 33
#define SIGNATURE_SIZE_IN_BYTES 64
#define NONCE_SIZE_IN_BYTES 16

#define MAX_NUM_CHAINS 4096

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

typedef struct _chain {
  handle_t handle;
  digest_t digest;
  unsigned long long height;

  unsigned long long pos;
  unsigned long long prev;
  unsigned long long next;
} chain_t;

typedef struct _init_endorser_data {
  digest_t view_block;
  digest_t view_tail;
  unsigned long long view_height;
  chain_t *chains;
  unsigned long long num_chains;
  digest_t cond_updated_tail_hash;
} init_endorser_data_t;

typedef struct _append_ledger_data {
  digest_t block_hash;
  digest_t cond_updated_tail_hash;
} append_ledger_data_t;

typedef enum _endorser_call {
  start_endorser_call = 0,
  get_pubkey_call = 1,
  init_endorser_call = 2,
  create_ledger_call = 3,
  read_ledger_call = 4,
  append_ledger_call = 5,
  read_view_ledger_call = 6,
  append_view_ledger_call = 7,
} endorser_call_t;

#endif /* _SHARED_H */
