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

int main(int argc, const char *argv[]) {
  oe_result_t result;
  int ret = 0;
  uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;

  if (check_simulate_opt(&argc, argv)) {
    cout << "Setting simulation flag" << endl;
    flags |= OE_ENCLAVE_FLAG_SIMULATE;
  }

  cout << "Host: enter main" << endl;
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
    goto exit;
  }

  // set the name of the ledger
  ledger_identity_t ledger_identity;
  memset(ledger_identity.name, 0x25, sizeof(ledger_identity.name));

  endorser_identity_t endorser_identity;
  result = initialize(enclave, &ret, &ledger_identity, &endorser_identity);

  if (result != OE_OK) {
    ret = 1;
    goto exit;
  }
  if (ret != 0) {
    cerr << "Host: intialize failed with " << ret << endl;
    goto exit;
  }

  cout << "Host: Identity of the endorser is: 0x";
  for (int i = 0; i < PUBLIC_KEY_SIZE_IN_BYTES; i++) {
    printf("%c%c", "0123456789ABCDEF"[endorser_identity.public_key[i] / 16],
           "0123456789ABCDEF"[endorser_identity.public_key[i] % 16]);
  }
  cout << endl;

  cout << "Host: Asking the endorser to endorse a block" << endl;

  // set an arbitrary message in the block
  block_t block;
  memset(block.block, 0x42, sizeof(block.block));

  endorsement_t endorsement;
  result = endorse(enclave, &ret, &block, &endorsement);

  if (result != OE_OK) {
    ret = 1;
    goto exit;
  }
  if (ret != 0) {
    cerr << "Host: endorse failed with " << ret << endl;
    goto exit;
  }

exit:
  cout << "Host: terminate the enclave" << endl;
  cout << "Host: Endorser completed successfully." << endl;
  oe_terminate_enclave(enclave);
  return ret;
}
