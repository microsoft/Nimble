#include "../shared.h"
#include "endorser.h"
#include "endorser_t.h"
#include <openenclave/enclave.h>

static ecall_dispatcher dispatcher;

int initialize(ledger_identity_t *ledger_identity,
               endorser_identity_t *endorser_identity) {
  return dispatcher.initialize(ledger_identity, endorser_identity);
}

int endorse(block_t *block, endorsement_t *endorsement) {
  return dispatcher.endorse(block, endorsement);
}

int read(nonce_t *nonce, endorsement_t *endorsement) {
  return dispatcher.read(nonce, endorsement);
}

void close_endorser() { return dispatcher.close(); }

int verify_endorse(ledger_identity_t *ledger_identity,
                   endorser_identity_t *endorser_identity, block_t *block,
                   endorsement_t *endorsement) {
  return dispatcher.verify_endorse(ledger_identity, endorser_identity, block,
                                   endorsement);
}
