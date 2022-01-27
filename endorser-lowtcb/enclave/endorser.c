#include <stddef.h>
#include <string.h>
#include <immintrin.h>
#include "Hacl_Hash.h"
#include "Hacl_Streaming_SHA2.h"
#include "Hacl_P256.h"
#include "shared.h"
#include "enclave.h"
#include "sgx_report.h"

static unsigned char private_key[PRIVATE_KEY_SIZE_IN_BYTES];
static unsigned char public_key[PUBLIC_KEY_SIZE_IN_BYTES];
static unsigned char public_key_uncompressed[64];

typedef struct _meta_block {
  union {
    unsigned char view[HASH_VALUE_SIZE_IN_BYTES];
    unsigned char state[HASH_VALUE_SIZE_IN_BYTES];
  };
  unsigned char prev[HASH_VALUE_SIZE_IN_BYTES];
  unsigned char cur[HASH_VALUE_SIZE_IN_BYTES];
  unsigned long long height;
} meta_block_t;

static chain_t chains[MAX_NUM_CHAINS];
static unsigned long long num_chains = 0;

unsigned char endorser_stack[0x4000];
unsigned long long old_rsp;

static digest_t zero_digest;
static digest_t view_ledger_tail_hash;
static unsigned long long view_ledger_height;

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

bool equal_96(const void *__s1, const void *__s2)
{
  unsigned char *s1 = (unsigned char *)__s1;
  unsigned char *s2 = (unsigned char *)__s2;

  return equal_32((const void *)&s1[0], (const void *)&s2[0])
    && equal_32((const void *)&s1[32], (const void *)&s2[32])
    && equal_32((const void *)&s1[64], (const void *)&s2[64]);
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

void calc_digest(unsigned char *input, unsigned long size, unsigned char *digest) {
  Hacl_Streaming_SHA2_state_sha2_256 st;
  unsigned char buf[64];
  unsigned int block_state[8];

  st.buf = &buf[0];
  st.block_state = &block_state[0];
  st.total_len = 0;

  Hacl_Hash_Core_SHA2_init_256(st.block_state);
  Hacl_Streaming_SHA2_update_256(&st, input, size);
  Hacl_Streaming_SHA2_finish_256(&st, digest);
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

bool start_endorser(sgx_target_info_t *sgx_target_info, sgx_report_t *sgx_report) {
  int i;
  chain_t *first_chain;
  chain_t *last_chain;

  sgx_report_t report __attribute__ ((aligned (512))) = { 0 };
  sgx_target_info_t target_info __attribute__ ((aligned (512))) = { 0 };
  unsigned char report_data[64] __attribute__ ((aligned (128))) = { 0 };

  if (endorser_state != endorser_none)
    return false;

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
  calc_digest(public_key, PUBLIC_KEY_SIZE_IN_BYTES, report_data);
  memcpy(&target_info, sgx_target_info, sizeof(sgx_target_info_t));
  sgx_ereport(&target_info, report_data, &report);
  memcpy(sgx_report, &report, sizeof(sgx_report_t));

  endorser_state = endorser_started;

  return true;
}

bool check_chain(chain_t* chain) {
  if (chain->pos == 0 || chain->pos > num_chains)
    return false;

  _Static_assert(sizeof(chain_t) == 96);  
  return equal_96(&chains[chain->pos], chain);
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

bool create_ledger(chain_t* chain, signature_t* signature) {
  // create the genesis metadata block
  meta_block_t m;
  chain_t local_chain;
  int i;

  if (endorser_state != endorser_initialized)
    return false;

  memcpy(&local_chain, chain, sizeof(chain_t));
  memcpy(m.view, view_ledger_tail_hash.v, HASH_VALUE_SIZE_IN_BYTES);
  memset(&m.prev, 0, HASH_VALUE_SIZE_IN_BYTES);
  memcpy(m.cur, local_chain.handle.v, HASH_VALUE_SIZE_IN_BYTES);
  m.height = 0;

  // hash the metadata block
  calc_digest((unsigned char *)&m, sizeof(meta_block_t), local_chain.digest.v);

  // pos, prev, next should be set up by the caller
  local_chain.height = 0;
  if (!insert_chain(&local_chain))
    return false;

  // Produce an EdDSA Signature from HACL*
  sign_digest(signature->v, local_chain.digest.v);
  memcpy(chain->digest.v, local_chain.digest.v, HASH_VALUE_SIZE_IN_BYTES);
  chain->height = local_chain.height;

  return true;
}

bool read_ledger(chain_t* chain, nonce_t* nonce, signature_t* signature) {
  chain_t local_chain;
  unsigned char tail_with_nonce[HASH_VALUE_SIZE_IN_BYTES + NONCE_SIZE_IN_BYTES];
  unsigned char h_nonced_tail[HASH_VALUE_SIZE_IN_BYTES];

  if (endorser_state != endorser_initialized)
    return false;

  memcpy(&local_chain, chain, sizeof(chain_t));
  if (!check_chain(&local_chain))
    return false;

  // combine the running hash and the nonce value
  memcpy(tail_with_nonce, local_chain.digest.v, HASH_VALUE_SIZE_IN_BYTES);
  memcpy(&tail_with_nonce[HASH_VALUE_SIZE_IN_BYTES], nonce->v, NONCE_SIZE_IN_BYTES);

  // compute a hash = Hash(hash, input), overwriting the running hash
  calc_digest(tail_with_nonce, HASH_VALUE_SIZE_IN_BYTES + NONCE_SIZE_IN_BYTES, h_nonced_tail);

  // produce an ECDSA signature
  sign_digest(signature->v, h_nonced_tail);

  return true;
}
  
bool append_ledger(chain_t* chain, append_ledger_data_t* ledger_data, signature_t* signature) {
  chain_t local_chain;
  meta_block_t m;
  digest_t new_tail_hash;

  if (endorser_state != endorser_initialized)
    return false;

  memcpy(&local_chain, chain, sizeof(chain_t));
  if (!check_chain(&local_chain))
    return false;

  // check for integer overflow of height
  if (local_chain.height == (unsigned long long)-1)
    return false;

  // create the metadata block
  memcpy(m.view, view_ledger_tail_hash.v, HASH_VALUE_SIZE_IN_BYTES);
  memcpy(m.prev, local_chain.digest.v, HASH_VALUE_SIZE_IN_BYTES);
  memcpy(m.cur, ledger_data->block_hash.v, HASH_VALUE_SIZE_IN_BYTES);
  local_chain.height += 1;
  m.height = local_chain.height;

  // hash the metadata block
  calc_digest((unsigned char *)&m, sizeof(meta_block_t), new_tail_hash.v);

  if (!equal_32(new_tail_hash.v, ledger_data->cond_updated_tail_hash.v))
    return false;

  // Sign the contents
  sign_digest(signature->v, new_tail_hash.v);

  // store updated hash 
  chain->height = local_chain.height;
  memcpy(chain->digest.v, new_tail_hash.v, HASH_VALUE_SIZE_IN_BYTES);
  memcpy(chains[chain->pos].digest.v, new_tail_hash.v, HASH_VALUE_SIZE_IN_BYTES);
  chains[chain->pos].height = chain->height;

  return true;
}

bool get_pubkey(endorser_id_t* endorser_id) {
  if (endorser_state == endorser_none)
    return false;

  memcpy(endorser_id->pk, public_key, PUBLIC_KEY_SIZE_IN_BYTES);
  return true;
}

bool check_pointer(void *ptr, uint64_t size) {
  if ((uint64_t)ptr < ENCLAVE_BASE)
    return true;

  if ((uint64_t)ptr + size >= ENCLAVE_BASE + ENCLAVE_SIZE)
    return true;

  return false;
}

bool read_view_ledger(nonce_t *nonce, signature_t *signature) {
  unsigned char tail_with_nonce[HASH_VALUE_SIZE_IN_BYTES + NONCE_SIZE_IN_BYTES];
  unsigned char h_nonced_tail[HASH_VALUE_SIZE_IN_BYTES];

  if (endorser_state != endorser_initialized)
    return false;

  // combine the running hash and the nonce value
  memcpy(tail_with_nonce, view_ledger_tail_hash.v, HASH_VALUE_SIZE_IN_BYTES);
  memcpy(&tail_with_nonce[HASH_VALUE_SIZE_IN_BYTES], nonce->v, NONCE_SIZE_IN_BYTES);

  // compute a hash = Hash(hash, input), overwriting the running hash
  calc_digest(tail_with_nonce, HASH_VALUE_SIZE_IN_BYTES + NONCE_SIZE_IN_BYTES, h_nonced_tail);

  // produce an ECDSA signature
  sign_digest(signature->v, h_nonced_tail);

  return true;
}

bool hash_state(unsigned char *state_hash) {
  Hacl_Streaming_SHA2_state_sha2_256 st;
  unsigned char buf[64];
  unsigned int block_state[8];
  unsigned long long i;
  chain_t *chain;

  if (num_chains == 0 && equal_32(view_ledger_tail_hash.v, zero_digest.v)) {
    memcpy(state_hash, zero_digest.v, HASH_VALUE_SIZE_IN_BYTES);
    return true;
  }

  st.buf = &buf[0];
  st.block_state = &block_state[0];
  st.total_len = 0;

  Hacl_Hash_Core_SHA2_init_256(st.block_state);

  Hacl_Streaming_SHA2_update_256(&st, view_ledger_tail_hash.v, HASH_VALUE_SIZE_IN_BYTES);
  Hacl_Streaming_SHA2_update_256(&st, (unsigned char *)&view_ledger_height, sizeof(view_ledger_height));

  chain = &chains[0];
  for (i = 0; i < num_chains; i++) {
    chain = &chains[chain->next];
    Hacl_Streaming_SHA2_update_256(&st, (unsigned char *)chain, offsetof(chain_t, pos));
  }

  Hacl_Streaming_SHA2_finish_256(&st, state_hash);

  return true;
}

bool append_view_ledger(append_ledger_data_t *ledger_data, signature_t *signature) {
  meta_block_t m;
  digest_t new_tail_hash;

  if (endorser_state != endorser_initialized)
    return false;

  if (!hash_state(m.state))
    return false;

  // check for integer overflow of height
  if (view_ledger_height == (unsigned long long)-1)
    return false;

  memcpy(m.prev, view_ledger_tail_hash.v, HASH_VALUE_SIZE_IN_BYTES);
  memcpy(m.cur, ledger_data->block_hash.v, HASH_VALUE_SIZE_IN_BYTES);
  m.height = view_ledger_height + 1;

  // compute a hash = Hash(hash, input), overwriting the running hash
  calc_digest((unsigned char *)&m, sizeof(meta_block_t), new_tail_hash.v);

  if (!equal_32(new_tail_hash.v, ledger_data->cond_updated_tail_hash.v))
    return false;

  view_ledger_height = view_ledger_height + 1;
  memcpy(view_ledger_tail_hash.v, new_tail_hash.v, HASH_VALUE_SIZE_IN_BYTES);

  // produce an ECDSA signature
  sign_digest(signature->v, view_ledger_tail_hash.v);

  return true;
}

bool init_endorser(init_endorser_data_t *data, signature_t *signature) {
  unsigned long long i;
  chain_t *chain;
  append_ledger_data_t ledger_data;

  if (endorser_state != endorser_started)
    return false;

  memcpy(view_ledger_tail_hash.v, data->view_tail.v, HASH_VALUE_SIZE_IN_BYTES);
  view_ledger_height = data->view_height;

  for (i = 0; i < data->num_chains; i++) {
    chain = &data->chains[i];
    if (!check_pointer(chain, sizeof(chain_t)) || !insert_chain(chain)) {
      return false;
    }
  }

  endorser_state = endorser_initialized;

  memcpy(ledger_data.block_hash.v, data->view_block.v, HASH_VALUE_SIZE_IN_BYTES);
  memcpy(ledger_data.cond_updated_tail_hash.v, data->cond_updated_tail_hash.v, HASH_VALUE_SIZE_IN_BYTES);
  if (!append_view_ledger(&ledger_data, signature))
    return false;

  return true;
}

bool endorser_entry(endorser_call_t endorser_call, void *param1, void *param2, void *param3) {
  bool ret = false;

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
    if (check_pointer(param1, sizeof(init_endorser_data_t)) && check_pointer(param2, sizeof(signature_t)))
      ret = init_endorser((init_endorser_data_t *)param1, (signature_t *)param2);
    break;
  case create_ledger_call:
    if (check_pointer(param1, sizeof(chain_t)) && check_pointer(param2, sizeof(signature_t)))
      ret = create_ledger((chain_t *)param1, (signature_t *)param2);
    break;
  case read_ledger_call:
    if (check_pointer(param1, sizeof(chain_t)) && check_pointer(param2, sizeof(nonce_t)) && check_pointer(param3, sizeof(signature_t)))
      ret = read_ledger((chain_t *)param1, (nonce_t *)param2, (signature_t *)param3);
    break;
  case append_ledger_call:
    if (check_pointer(param1, sizeof(chain_t)) && check_pointer(param2, sizeof(append_ledger_data_t)) && check_pointer(param3, sizeof(signature_t)))
      ret = append_ledger((chain_t *)param1, (append_ledger_data_t *)param2, (signature_t *)param3);
    break;
  case read_view_ledger_call:
    if (check_pointer(param1, sizeof(nonce_t)) && check_pointer(param2, sizeof(signature_t)))
      ret = read_view_ledger((nonce_t *)param1, (signature_t *)param2);
    break;
  case append_view_ledger_call:
    if (check_pointer(param1, sizeof(append_ledger_data_t)) && check_pointer(param2, sizeof(signature_t)))
      ret = append_view_ledger((append_ledger_data_t *)param1, (signature_t *)param2);
    break;
  default:
    break;
  }

  return ret;
}
