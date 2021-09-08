#include "../shared.h"
#include <iostream>

#include <openenclave/host.h>
#include "endorser_u.h"

using namespace std;

oe_enclave_t *enclave = NULL;

bool check_simulate_opt(int *argc, const char *argv[]) {
  for (int i = 0; i < *argc; i++) {
    if (strcmp(argv[i], "--simulate") == 0) {
      cout << "Running in simulation mode" << endl;
      memmove(&argv[i], &argv[i + 1], (*argc - i) * sizeof(char *));
      (*argc)--;
      return true;
    }
  }
  return false;
}

void print_hex(unsigned char* d, unsigned int len) {
  printf("0x");
  for (int i = 0; i < len; i++) {
    printf("%c%c", "0123456789ABCDEF"[d[i] / 16],
           "0123456789ABCDEF"[d[i] % 16]);
  }
  cout << endl;
}

int main(int argc, const char *argv[]) {
    oe_result_t result;
  int ret = 0;
  uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;

  if (check_simulate_opt(&argc, argv)) {
    cout << "Setting simulation flag" << endl;
    flags |= OE_ENCLAVE_FLAG_SIMULATE;
  }

  cout << "Host: Entering main" << endl;
  if (argc != 2) {
    cerr << "Usage: " << argv[0] << " enclave_image_path [ --simulate  ]"
         << endl;
    return 1;
  }

  cout << "Host: create enclave for image:" << argv[1] << endl;
  result = oe_create_endorser_enclave(argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL,
                                      0, &enclave);
  if (result != OE_OK) {
    cerr << "oe_create_endorser_enclave() failed with " << argv[0] << " "
         << result << endl;
    ret = 1;
  }

  // set the endorser 
  endorser_id_t endorser_id;
  result = setup(enclave, &ret, &endorser_id);
 
  if (result != OE_OK) {
    ret = 1;
    goto exit;
  }
  if (ret != 0) {
    cerr << "Host: intialize failed with " << ret << endl;
    goto exit;
  }

  cout << "Host: PK of the endorser is: 0x";
  print_hex(endorser_id.pk, PUBLIC_KEY_SIZE_IN_BYTES);
  cout << endl;

  // call new_ledger with a handle
  cout << "Host: Asking the endorser to create a new ledger" << endl;
  handle_t handle;
  memset(handle.v, 0x21, HASH_VALUE_SIZE_IN_BYTES);
  signature_t signature;
  result = new_ledger(enclave, &ret, &handle, &signature);
  if (result != OE_OK) {
    ret = 1;
    goto exit;
  }
  if (ret != 0) {
    cerr << "Host: new_ledger failed with " << ret << endl;
    goto exit;
  }

  cout << "Host: Handle is: ";
  print_hex(handle.v, HASH_VALUE_SIZE_IN_BYTES);

  // call append with an arbitrary message in the block_hash
  digest_t block_hash;
  memset(block_hash.v, 0x42, sizeof(block_hash.v));

  result = append(enclave, &ret, &handle, &block_hash, &signature);

  if (result != OE_OK) {
    ret = 1;
    goto exit;
  }
  if (ret != 0) {
    cerr << "Host: append failed with " << ret << endl;
    goto exit;
  }
  
  // call read_latest with a nonce
  nonce_t nonce;
  memset(nonce.v, 0x84, sizeof(nonce.v));
  digest_t tail;

  result = read_latest(enclave, &ret, &handle, &nonce, &tail, &signature);
  if (result != OE_OK) {
    ret = 1;
    goto exit;
  }
  if (ret != 0) {
    cerr << "Host: read_latest failed with " << ret << endl;
    goto exit;
  }
  cout << "Host: Latest tail hash is: ";
  print_hex(tail.v, HASH_VALUE_SIZE_IN_BYTES);

  return 0;

exit:
  cout << "Host: terminate the enclave" << endl;
  cout << "Host: Endorser completed successfully." << endl;
  oe_terminate_enclave(enclave);
  return ret;
  
}
