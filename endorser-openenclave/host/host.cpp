#include "../shared.h"
#include <iostream>

#include <openenclave/host.h>
#include "endorser_u.h"

#include <grpcpp/grpcpp.h>
#include "endorser.grpc.pb.h"

using namespace std;
using grpc::Server;
using grpc::ServerContext;
using grpc::Status;
using grpc::ServerBuilder;

using endorser_proto::EndorserCall;
using endorser_proto::GetPublicKeyReq;
using endorser_proto::GetPublicKeyResp;
using endorser_proto::NewLedgerReq;
using endorser_proto::NewLedgerResp;
using endorser_proto::ReadLatestReq;
using endorser_proto::ReadLatestResp;
using endorser_proto::AppendReq;
using endorser_proto::AppendResp;

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

class EndorserCallServiceImpl final: public EndorserCall::Service {
    Status GetPublicKey(ServerContext* context, const GetPublicKeyReq* request, GetPublicKeyResp* reply) override {
        char pk_bytes[] = "this_is_a_public_key";
        reply->set_pk(pk_bytes);
        return Status::OK;
    }

    Status NewLedger(ServerContext *context, const NewLedgerReq* request, NewLedgerResp* reply) override {
        char sig_bytes[] = "this_is_a_signature_byte_response";
        reply->set_signature(sig_bytes);
        return Status::OK;
    }

    Status ReadLatest(ServerContext *context, const ReadLatestReq* request, ReadLatestResp* reply) override {
        char tail_hash[] = "this_is_a_tail_hash_response";
        uint64_t height = std::numeric_limits<uint64_t>::max();
        char sig_bytes[] = "this_is_a_signature_byte_response";
        reply->set_tail_hash(tail_hash);
        reply->set_height(height);
        reply->set_signature(sig_bytes);
        return Status::OK;
    }

    Status Append(ServerContext *context, const AppendReq* request, AppendResp* reply) override {
        char tail_hash[] = "this_is_a_tail_hash_response";
        uint64_t height = std::numeric_limits<uint64_t>::max();
        char sig_bytes[] = "this_is_a_signature_byte_response";
        reply->set_tail_hash(tail_hash);
        reply->set_height(height);
        reply->set_signature(sig_bytes);
        return Status::OK;
    }
};

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

  // Call get_public_key
  endorser_id_t get_id_info;
  result = get_public_key(enclave, &ret,  &get_id_info);
  if (result != 0) {
      cerr << "Host: Failed to retrieve public key" << result << endl;
      goto exit;
  }
  printf("Host: Get PK: ");
  print_hex(get_id_info.pk, PUBLIC_KEY_SIZE_IN_BYTES);

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
  cout << "Host: Signature is : ";
  print_hex(signature.v, SIGNATURE_SIZE_IN_BYTES);

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
  printf("Host: Append Signature : ");
  print_hex(signature.v, SIGNATURE_SIZE_IN_BYTES);

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
  cout << "Host: Latest tail signature is: ";
  print_hex(signature.v, SIGNATURE_SIZE_IN_BYTES);

  // Spinning up gRPC Services.
  {
      std::cout << "Attempting to run Endorser at Address 0.0.0.0:9096" << std::endl;
      std::string server_address("0.0.0.0:9096");
      EndorserCallServiceImpl service;
      ServerBuilder builder;
      builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
      builder.RegisterService(&service);
      std::unique_ptr<Server> server(builder.BuildAndStart());
      std::cout << "Server listening on " << server_address << std::endl;
      server->Wait();
  }
  return 0;

exit:
  cout << "Host: terminate the enclave" << endl;
  cout << "Host: Endorser completed successfully." << endl;
  oe_terminate_enclave(enclave);
  return ret;

}
