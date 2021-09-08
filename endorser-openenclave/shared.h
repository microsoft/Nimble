#ifndef _SHARED_H
#define _SHARED_H

#define HASH_VALUE_SIZE_IN_BYTES 32
#define PUBLIC_KEY_SIZE_IN_BYTES 33
#define SIGNATURE_SIZE_IN_BYTES 72
#define NONCE_SIZE_IN_BYTES 16

// endorser_id_t contains the name of an endorser
typedef struct _endorser_id {
  unsigned char pk[PUBLIC_KEY_SIZE_IN_BYTES];
} endorser_id_t;

// handle_t contains the name of a ledger
typedef struct _handle {
  unsigned char v[HASH_VALUE_SIZE_IN_BYTES];
} handle_t;

typedef struct _digest {
  unsigned char v[HASH_VALUE_SIZE_IN_BYTES];
} digest_t;

typedef struct _meta_block {
  unsigned char prev[HASH_VALUE_SIZE_IN_BYTES];
  unsigned char cur[HASH_VALUE_SIZE_IN_BYTES];
  unsigned int height;
} meta_block_t;

typedef struct _nonce {
  unsigned char v[NONCE_SIZE_IN_BYTES];
} nonce_t;

typedef struct _signature {
  unsigned char v[SIGNATURE_SIZE_IN_BYTES];
  unsigned int v_len;
} signature_t;

#endif /* _SHARED_H */
