#include <stddef.h>
#include <string.h>
#include <immintrin.h>
#include "../crypto/Hacl_Hash.h"
#include "../crypto/Hacl_Streaming_SHA2.h"
#include "../crypto/Hacl_P256.h"
#include "../include/shared.h"
#include "../include/enclave.h"
#include <sgx_report.h>

static unsigned char private_key[PRIVATE_KEY_SIZE_IN_BYTES];
static unsigned char public_key[PUBLIC_KEY_SIZE_IN_BYTES];
static unsigned char public_key_uncompressed[64];

static chain_t chains[MAX_NUM_CHAINS];
static unsigned long long num_chains = 0;

unsigned char endorser_stack[0x4000];
unsigned long long old_rsp;

static digest_t zero_digest;
static metablock_t view_ledger_tail_metablock;
static digest_t view_ledger_tail_hash;

typedef enum _state {
  endorser_none = 0,
  endorser_started = 1,
  endorser_initialized = 2,
} state_t;

static state_t endorser_state = endorser_none;

bool equal_32(const void *__s1, const void *__s2)
{
  unsigned long long *s1 = (unsigned long long *)__s1;
  unsigned long long *s2 = (unsigned long long *)__s2;
  return s1[0] == s2[0] && s1[1] == s2[1] && s1[2] == s2[2] && s1[3] == s2[3];
}

int memcmp_32(const void *__s1, const void *__s2)
{
  unsigned char *s1 = (unsigned char *)__s1;
  unsigned char *s2 = (unsigned char *)__s2;
  int i;

  for (i = 0; i < 32; i++) {
    if (s1[i] < s2[i])
      return -1;
    else if (s1[i] > s2[i])
      return 1;
  }

  return 0;
}

void *memcpy (void *__s1, const void *__s2, size_t __n)
{
  size_t i, j;
  unsigned char *s1 = (unsigned char *)__s1;
  unsigned char *s2 = (unsigned char *)__s2;

  for (i = 0; i + sizeof(unsigned long long) <= __n; i += sizeof(unsigned long long))
    *(unsigned long long *)&s1[i] = *(unsigned long long *)&s2[i];

  for (j = i; j < __n; j++)
    s1[j] = s2[j];

  return __s1;
}

void* memset(void *__s1, int __val, size_t __n)
{
  size_t i, j;
  unsigned char *s1 = (unsigned char *)__s1;
  unsigned long long val = 0x0101010101010101UL * (unsigned char)__val;

  for (i = 0; i + sizeof(unsigned long long) <= __n; i += sizeof(unsigned long long))
    *(unsigned long long *)&s1[i] = val;

  for (j = i; j < __n; j++)
    s1[j] = __val;

  return __s1;
}

void calc_digest(unsigned char *input, unsigned long size, digest_t *digest) {
  Hacl_Streaming_SHA2_state_sha2_256 st;
  unsigned char buf[64];
  unsigned int block_state[8];

  st.buf = &buf[0];
  st.block_state = &block_state[0];
  st.total_len = 0;

  Hacl_Hash_Core_SHA2_init_256(st.block_state);
  Hacl_Streaming_SHA2_update_256(&st, input, size);
  Hacl_Streaming_SHA2_finish_256(&st, (unsigned char *)digest);
}

void digest_with_digest(digest_t *digest0, digest_t *digest1) {
  digest_t digests[2];

  memcpy(&digests[0], digest0, sizeof(digest_t));
  memcpy(&digests[1], digest1, sizeof(digest_t));
  calc_digest((unsigned char *)&digests[0], sizeof(digest_t) * 2, digest1);
}

void digest_with_nonce(digest_t *digest, nonce_t* nonce) {
  unsigned char buf[sizeof(digest_t) + sizeof(nonce_t)];

  memcpy(&buf[0], digest, sizeof(digest_t));
  memcpy(&buf[sizeof(digest_t)], nonce, sizeof(nonce_t));
  calc_digest(buf, sizeof(digest_t) + sizeof(nonce_t), digest);
}

void sign_digest(unsigned char *signature, unsigned char *digest) {
  int i;
  unsigned char nonce[32];

  for (i = 0; i < 32; i += sizeof(unsigned long long))
    __builtin_ia32_rdrand64_step((unsigned long long*)&nonce[i]);

  Hacl_P256_ecdsa_sign_p256_without_hash(signature, HASH_VALUE_SIZE_IN_BYTES, digest, private_key, nonce);
}

void sgx_ereport(
  const sgx_target_info_t* target_info, // 512-byte aligned
  const uint8_t* report_data,           // 128-byte aligned
  sgx_report_t* report                  // 512-byte aligned
);

endorser_status_code start_endorser(sgx_target_info_t *sgx_target_info, sgx_report_t *sgx_report) {
  int i;
  chain_t *first_chain;
  chain_t *last_chain;

  sgx_report_t report __attribute__ ((aligned (512))) = { 0 };
  sgx_target_info_t target_info __attribute__ ((aligned (512))) = { 0 };
  unsigned char report_data[64] __attribute__ ((aligned (128))) = { 0 };

  if (endorser_state != endorser_none)
    return UNAVAILABLE;

  _Static_assert(PRIVATE_KEY_SIZE_IN_BYTES % sizeof(unsigned long long) == 0);
  for (i = 0; i < PRIVATE_KEY_SIZE_IN_BYTES; i += sizeof(unsigned long long))
    __builtin_ia32_rdrand64_step((unsigned long long*)&private_key[i]);

  Hacl_P256_ecp256dh_i(public_key_uncompressed, private_key);
  Hacl_P256_compression_compressed_form(public_key_uncompressed, public_key);

  first_chain = &chains[0];
  first_chain->prev = (unsigned long long)-1;
  chains[0].next = MAX_NUM_CHAINS - 1;
  first_chain->pos = 0;
  _Static_assert(HASH_VALUE_SIZE_IN_BYTES % sizeof(unsigned long long) == 0);
  memset(first_chain->handle.v, 0, HASH_VALUE_SIZE_IN_BYTES);

  last_chain = &chains[MAX_NUM_CHAINS-1];
  last_chain->prev = 0;
  last_chain->next = (unsigned long long)-1;
  last_chain->pos = MAX_NUM_CHAINS - 1;
  for (i = 0; i < HASH_VALUE_SIZE_IN_BYTES; i += sizeof(unsigned long long))
  memset(last_chain->handle.v, -1, HASH_VALUE_SIZE_IN_BYTES);

  // get the SGX report
  calc_digest(public_key, PUBLIC_KEY_SIZE_IN_BYTES, (digest_t *)report_data);
  memcpy(&target_info, sgx_target_info, sizeof(sgx_target_info_t));
  sgx_ereport(&target_info, report_data, &report);
  memcpy(sgx_report, &report, sizeof(sgx_report_t));

  endorser_state = endorser_started;

  return OK;
}

bool check_chain(chain_t* outer_chain) {
  chain_t *inner_chain;

  if (outer_chain->pos == 0 || outer_chain->pos > num_chains)
    return false;

  inner_chain = &chains[outer_chain->pos];
  _Static_assert(HASH_VALUE_SIZE_IN_BYTES == 32);
  return equal_32(&inner_chain->handle, &outer_chain->handle)
    && equal_32(&inner_chain->metablock.prev, &outer_chain->metablock.prev)
    && equal_32(&inner_chain->metablock.block_hash, &outer_chain->metablock.block_hash)
    && inner_chain->metablock.height == outer_chain->metablock.height
    && inner_chain->prev == outer_chain->prev
    && inner_chain->pos == outer_chain->pos
    && inner_chain->next == outer_chain->next;
}

bool insert_chain(chain_t* chain) {
  _Static_assert(HASH_VALUE_SIZE_IN_BYTES == 32);
  if (num_chains == MAX_NUM_CHAINS - 2 ||
      chain->pos != num_chains + 1 ||
      chain->prev >= MAX_NUM_CHAINS ||
      chain->next >= MAX_NUM_CHAINS ||
      chains[chain->prev].next != chain->next ||
      chains[chain->next].prev != chain->prev ||
      memcmp_32(chains[chain->prev].handle.v, chain->handle.v) >= 0 ||
      memcmp_32(chain->handle.v, chains[chain->next].handle.v) >= 0)
    return false;

  memcpy(&chains[chain->pos], chain, sizeof(chain_t));
  chains[chain->prev].next = chain->pos;
  chains[chain->next].prev = chain->pos;
  num_chains++;

  return true;
}

void calc_receipt(handle_t * handle, metablock_t *metablock, digest_t *hash, digest_t *view, nonce_t* nonce, receipt_t* receipt) {
  digest_t digest;

  // hash the metadata block and construct the message
  memcpy(&digest, hash, sizeof(digest_t));
  if (nonce != NULL)
    digest_with_nonce(&digest, nonce);
  if (handle != NULL)
    digest_with_digest((digest_t*)handle, &digest);
  digest_with_digest(view, &digest);

  // sign the message
  sign_digest(receipt->sig.v, digest.v);

  // construct the receipt
  memcpy(receipt->view.v, view->v, HASH_VALUE_SIZE_IN_BYTES);
  memcpy(&receipt->metablock, metablock, sizeof(metablock_t));
  memcpy(receipt->id.v, public_key, PUBLIC_KEY_SIZE_IN_BYTES);
}

endorser_status_code create_ledger(chain_t* outer_chain, append_ledger_data_t* ledger_data, receipt_t* receipt) {
  // create the genesis metadata block
  chain_t local_chain;
  chain_t *chain;
  digest_t digest;

  if (endorser_state != endorser_initialized)
    return UNIMPLEMENTED;

  memcpy(&local_chain, outer_chain, sizeof(chain_t));
  // pos, prev, next should be set up by the caller
  if (!insert_chain(&local_chain))
    return INVALID_ARGUMENT;

  chain = &chains[local_chain.pos];

  memset(chain->metablock.prev.v, 0, HASH_VALUE_SIZE_IN_BYTES);
  memcpy(chain->metablock.block_hash.v, ledger_data->block_hash.v, HASH_VALUE_SIZE_IN_BYTES);
  chain->metablock.height = 0;
  calc_digest((unsigned char *)&chain->metablock, sizeof(metablock_t), &chain->hash);
  memcpy(outer_chain, chain, sizeof(chain_t));

  calc_receipt(&chain->handle, &chain->metablock, &chain->hash, &view_ledger_tail_hash, NULL, receipt);
  return OK;
}

endorser_status_code read_ledger(chain_t* outer_chain, read_ledger_data_t* read_ledger_data, receipt_t *receipt) {
  chain_t local_chain;
  chain_t *chain;

  if (endorser_state != endorser_initialized)
    return UNIMPLEMENTED;

  memcpy(&local_chain, outer_chain, sizeof(chain_t));
  if (!check_chain(&local_chain))
    return INVALID_ARGUMENT;

  chain = &chains[local_chain.pos];

  if (read_ledger_data->expected_height < chain->metablock.height)
    return INVALID_ARGUMENT;

  if (read_ledger_data->expected_height > chain->metablock.height)
    return FAILED_PRECONDITION;

  calc_receipt(&chain->handle, &chain->metablock, &chain->hash, &view_ledger_tail_hash, &read_ledger_data->nonce, receipt);
  return OK;
}
  
endorser_status_code append_ledger(chain_t* outer_chain, append_ledger_data_t* append_ledger_data, receipt_t *receipt) {
  chain_t local_chain;
  chain_t *chain;
  digest_t digest;

  if (endorser_state != endorser_initialized)
    return UNIMPLEMENTED;

  memcpy(&local_chain, outer_chain, sizeof(chain_t));
  if (!check_chain(&local_chain))
    return INVALID_ARGUMENT;

  chain = &chains[local_chain.pos];

  // check for integer overflow of height
  if (chain->metablock.height == ULLONG_MAX)
    return OUT_OF_RANGE;

  if (append_ledger_data->expected_height <= chain->metablock.height)
    return ALREADY_EXISTS;

  if (append_ledger_data->expected_height > chain->metablock.height + 1)
    return FAILED_PRECONDITION;

  memcpy(chain->metablock.prev.v, chain->hash.v, HASH_VALUE_SIZE_IN_BYTES);
  memcpy(chain->metablock.block_hash.v, append_ledger_data->block_hash.v, HASH_VALUE_SIZE_IN_BYTES);
  chain->metablock.height += 1;
  calc_digest((unsigned char *)&chain->metablock, sizeof(metablock_t), &chain->hash);
  memcpy(outer_chain, chain, sizeof(chain_t));

  calc_receipt(&chain->handle, &chain->metablock, &chain->hash, &view_ledger_tail_hash, NULL, receipt);
  return OK;
}

endorser_status_code get_pubkey(endorser_id_t* endorser_id) {
  if (endorser_state == endorser_none)
    return UNIMPLEMENTED;

  memcpy(endorser_id->pk, public_key, PUBLIC_KEY_SIZE_IN_BYTES);
  return OK;
}

bool check_pointer(void *ptr, uint64_t size) {
  if ((uint64_t)ptr >= ENCLAVE_BASE + ENCLAVE_SIZE)
    return true;

  if ((uint64_t)ptr + size <= ENCLAVE_BASE)
    return true;

  return false;
}

void hash_state(digest_t *state_hash) {
  Hacl_Streaming_SHA2_state_sha2_256 st;
  unsigned char buf[64];
  unsigned int block_state[8];
  unsigned long long i;
  chain_t *chain;

  if (num_chains == 0) {
    memcpy(state_hash, zero_digest.v, HASH_VALUE_SIZE_IN_BYTES);
    return;
  }

  st.buf = &buf[0];
  st.block_state = &block_state[0];
  st.total_len = 0;

  Hacl_Hash_Core_SHA2_init_256(st.block_state);

  chain = &chains[0];
  for (i = 0; i < num_chains; i++) {
    chain = &chains[chain->next];
    Hacl_Streaming_SHA2_update_256(&st, chain->handle.v, sizeof(handle_t));
    Hacl_Streaming_SHA2_update_256(&st, chain->hash.v, sizeof(digest_t));
    Hacl_Streaming_SHA2_update_256(&st, (unsigned char*)&chain->metablock.height, sizeof(uint64_t));
  }

  Hacl_Streaming_SHA2_finish_256(&st, (unsigned char *)state_hash);

  return;
}

endorser_status_code append_view_ledger(append_ledger_data_t *ledger_data, receipt_t *receipt) {
  digest_t state;

  if (endorser_state != endorser_initialized)
    return UNIMPLEMENTED;

  hash_state(&state);

  // check for integer overflow of height
  if (view_ledger_tail_metablock.height == ULLONG_MAX)
    return OUT_OF_RANGE;

  if (ledger_data->expected_height <= view_ledger_tail_metablock.height)
    return ALREADY_EXISTS;

  if (ledger_data->expected_height > view_ledger_tail_metablock.height + 1)
    return FAILED_PRECONDITION;

  // update the view ledger tail metablock
  memcpy(view_ledger_tail_metablock.prev.v, view_ledger_tail_hash.v, HASH_VALUE_SIZE_IN_BYTES);
  memcpy(view_ledger_tail_metablock.block_hash.v, ledger_data->block_hash.v, HASH_VALUE_SIZE_IN_BYTES);
  view_ledger_tail_metablock.height += 1;
  calc_digest((unsigned char *)&view_ledger_tail_metablock, sizeof(metablock_t), &view_ledger_tail_hash);

  calc_receipt(NULL, &view_ledger_tail_metablock, &view_ledger_tail_hash, &state, NULL, receipt);
  return OK;
}

endorser_status_code init_endorser(init_endorser_data_t *data, receipt_t *receipt) {
  unsigned long long i;
  chain_t *chain;
  append_ledger_data_t ledger_data;

  if (endorser_state != endorser_started)
    return UNIMPLEMENTED;

  if (!check_pointer(data->chains, sizeof(chain_t) * MAX_NUM_CHAINS))
    return INVALID_ARGUMENT;

  if (data->num_chains > MAX_NUM_CHAINS - 2)
    return INVALID_ARGUMENT;

  memcpy(&view_ledger_tail_metablock, &data->view_tail_metablock, sizeof(metablock_t));
  calc_digest((unsigned char *)&view_ledger_tail_metablock, sizeof(metablock_t), &view_ledger_tail_hash);

  memcpy(chains, data->chains, sizeof(chain_t) * (data->num_chains + 1));
  memcpy(&chains[MAX_NUM_CHAINS-1], &data->chains[MAX_NUM_CHAINS-1], sizeof(chain_t));
  for (i = 0; i < data->num_chains; i++) {
      chain = &chains[i+1];
      if (chain->pos != i + 1 ||
          chain->prev >= MAX_NUM_CHAINS ||
          chain->next >= MAX_NUM_CHAINS ||
          chains[chain->prev].next != chain->pos ||
          chains[chain->next].prev != chain->pos ||
          memcmp_32(chains[chain->prev].handle.v, chain->handle.v) >= 0 ||
          memcmp_32(chain->handle.v, chains[chain->next].handle.v) >= 0)
          return INVALID_ARGUMENT;
      calc_digest((unsigned char *)&chain->metablock, sizeof(metablock_t), &chain->hash);
      memcpy(&data->chains[i+1].hash, &chain->hash, sizeof(digest_t));
  }
  num_chains = data->num_chains;

  endorser_state = endorser_initialized;

  memcpy(ledger_data.block_hash.v, data->block_hash.v, HASH_VALUE_SIZE_IN_BYTES);
  ledger_data.expected_height = data->expected_height;
  return append_view_ledger(&ledger_data, receipt);
}

endorser_status_code read_view_tail(metablock_t *metablock) {
  memcpy(metablock, &view_ledger_tail_metablock, sizeof(metablock_t));
  return OK;
}

endorser_status_code endorser_entry(endorser_call_t endorser_call, void *param1, void *param2, void *param3) {
  endorser_status_code ret = INTERNAL;

  switch (endorser_call) {
  case start_endorser_call:
    if (check_pointer(param1, sizeof(sgx_target_info_t)) && check_pointer(param2, sizeof(sgx_report_t)))
      ret = start_endorser((sgx_target_info_t *)param1, (sgx_report_t *)param2);
    break;
  case get_pubkey_call:
    if (check_pointer(param1, sizeof(endorser_id_t)))
      ret = get_pubkey((endorser_id_t *)param1);
    break;
  case init_endorser_call:
    if (check_pointer(param1, sizeof(init_endorser_data_t)) && check_pointer(param2, sizeof(receipt_t)))
      ret = init_endorser((init_endorser_data_t *)param1, (receipt_t *)param2);
    break;
  case create_ledger_call:
    if (check_pointer(param1, sizeof(chain_t)) && check_pointer(param2, sizeof(append_ledger_data_t)) && check_pointer(param3, sizeof(receipt_t)))
      ret = create_ledger((chain_t *)param1, (append_ledger_data_t *)param2, (receipt_t *)param3);
    break;
  case read_ledger_call:
    if (check_pointer(param1, sizeof(chain_t)) && check_pointer(param2, sizeof(read_ledger_data_t)) && check_pointer(param3, sizeof(receipt_t)))
      ret = read_ledger((chain_t *)param1, (read_ledger_data_t *)param2, (receipt_t *)param3);
    break;
  case append_ledger_call:
    if (check_pointer(param1, sizeof(chain_t)) && check_pointer(param2, sizeof(append_ledger_data_t)) && check_pointer(param3, sizeof(receipt_t)))
      ret = append_ledger((chain_t *)param1, (append_ledger_data_t *)param2, (receipt_t *)param3);
    break;
  case append_view_ledger_call:
    if (check_pointer(param1, sizeof(append_ledger_data_t)) && check_pointer(param2, sizeof(receipt_t)))
      ret = append_view_ledger((append_ledger_data_t *)param1, (receipt_t *)param2);
    break;
  case read_view_tail_call:
    if (check_pointer(param1, sizeof(metablock_t)))
      ret = read_view_tail((metablock_t *)param1);
    break;
  default:
    break;
  }

  return ret;
}
