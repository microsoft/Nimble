#ifndef _SHARED_H
#define _SHARED_H

#define HASH_VALUE_SIZE_IN_BYTES 32
#define PUBLIC_KEY_SIZE_IN_BYTES 33
#define SIGNATURE_SIZE_IN_BYTES 72
#define NONCE_SIZE_IN_BYTES 16

// ledger_identity_t contains the identity of a ledger
typedef struct _ledger_identity {
  unsigned char name[HASH_VALUE_SIZE_IN_BYTES];
} ledger_identity_t;

// endorser_identity_t contains the identity of an endorser
typedef struct _endorser_identity {
  unsigned char public_key[PUBLIC_KEY_SIZE_IN_BYTES];
} endorser_identity_t;

typedef struct _block {
  unsigned char block[HASH_VALUE_SIZE_IN_BYTES];
} block_t;

typedef struct _nonce {
  unsigned char nonce[NONCE_SIZE_IN_BYTES];
} nonce_t;

typedef struct _endorsement {
  unsigned char hash[HASH_VALUE_SIZE_IN_BYTES];
  unsigned char sig[SIGNATURE_SIZE_IN_BYTES];
  unsigned int sig_len;
} endorsement_t;

#endif /* _SHARED_H */
