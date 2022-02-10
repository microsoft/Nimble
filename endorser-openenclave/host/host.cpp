#include "../shared.h"
#include <iostream>

#include <openenclave/host.h>
#include "endorser_u.h"

#include <grpcpp/grpcpp.h>
#include "endorser.grpc.pb.h"

using namespace std;
using namespace ::google::protobuf;
using grpc::Server;
using grpc::ServerContext;
using grpc::Status;
using grpc::StatusCode;
using grpc::ServerBuilder;

using endorser_proto::EndorserCall;
using endorser_proto::GetPublicKeyReq;
using endorser_proto::GetPublicKeyResp;
using endorser_proto::InitializeStateReq;
using endorser_proto::InitializeStateResp;
using endorser_proto::NewLedgerReq;
using endorser_proto::NewLedgerResp;
using endorser_proto::ReadLatestReq;
using endorser_proto::ReadLatestResp;
using endorser_proto::AppendReq;
using endorser_proto::AppendResp;
using endorser_proto::ReadLatestViewLedgerReq;
using endorser_proto::ReadLatestViewLedgerResp;
using endorser_proto::AppendViewLedgerReq;
using endorser_proto::AppendViewLedgerResp;
using endorser_proto::LedgerTailMapEntry;

void print_hex(unsigned char* d, unsigned int len) {
  printf("0x");
  for (int i = 0; i < len; i++) {
    printf("%c%c", "0123456789ABCDEF"[d[i] / 16],
           "0123456789ABCDEF"[d[i] % 16]);
  }
  cout << endl;
}


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
        int ret = 0;
        oe_result_t result;
        endorser_id_t eid;
        result = get_public_key(enclave, &ret,  &eid);
        if (result != OE_OK) {
            return Status(StatusCode::FAILED_PRECONDITION, "enclave error");
        }
        if (ret != 0) {
            return Status(StatusCode::FAILED_PRECONDITION, "enclave call return error");
        }
        reply->set_pk(reinterpret_cast<const char*>(eid.pk), PUBLIC_KEY_SIZE_IN_BYTES);
        return Status::OK;
    }

    Status InitializeState(ServerContext *context, const InitializeStateReq* request, InitializeStateResp* reply) override {
        RepeatedPtrField<LedgerTailMapEntry> l_t_m = request->ledger_tail_map();
        string t = request->view_ledger_tail();
        unsigned long long h = request->view_ledger_height();
        string b_h = request->block_hash();
        string cond_h = request->cond_updated_tail_hash();

        if (t.size() != HASH_VALUE_SIZE_IN_BYTES || b_h.size() != HASH_VALUE_SIZE_IN_BYTES || cond_h.size() != HASH_VALUE_SIZE_IN_BYTES) {
          return Status(StatusCode::INVALID_ARGUMENT, "one or both of view ledger tail and block hash are invalid");
        }

        auto num_entries = l_t_m.size();
        ledger_tail_map_entry_t ledger_tail_map[num_entries];
        int i = 0;
        for (auto it = l_t_m.begin(); it != l_t_m.end(); it++) {
          memcpy(ledger_tail_map[i].handle.v, it->handle().c_str(), HASH_VALUE_SIZE_IN_BYTES);
          memcpy(ledger_tail_map[i].tail.v, it->tail().c_str(), HASH_VALUE_SIZE_IN_BYTES);
          ledger_tail_map[i].height = it->height();
          i++;
        }

        init_endorser_data_t state;
        state.ledger_tail_map_size = num_entries;
        state.ledger_tail_map = ledger_tail_map;
        memcpy(state.view_ledger_tail.v, t.c_str(), HASH_VALUE_SIZE_IN_BYTES);
        state.view_ledger_height = h;
        memcpy(state.block_hash.v, b_h.c_str(), HASH_VALUE_SIZE_IN_BYTES);
        memcpy(state.cond_updated_tail_hash.v, cond_h.c_str(), HASH_VALUE_SIZE_IN_BYTES);

        int ret = 0;
        oe_result_t result;
        
        signature_t signature;
        result = initialize_state(enclave, &ret, &state, &signature);
        if (result != OE_OK) {
            return Status(StatusCode::FAILED_PRECONDITION, "enclave error");
        }
        if (ret != 0) {
            return Status(StatusCode::FAILED_PRECONDITION, "enclave call to initialize_state returned error");
        }

        reply->set_signature(reinterpret_cast<const char*>(signature.v), SIGNATURE_SIZE_IN_BYTES);
        return Status::OK;
    }

    Status NewLedger(ServerContext *context, const NewLedgerReq* request, NewLedgerResp* reply) override {
        string h = request->handle();
        if (h.size() != HASH_VALUE_SIZE_IN_BYTES) {
            return Status(StatusCode::INVALID_ARGUMENT, "handle size is invalid");
        }

        int ret = 0;
        oe_result_t result;
        handle_t handle;
        memcpy(handle.v, h.c_str(), HASH_VALUE_SIZE_IN_BYTES);
        
        signature_t signature;
        result = new_ledger(enclave, &ret, &handle, &signature);
        if (result != OE_OK) {
            return Status(StatusCode::FAILED_PRECONDITION, "enclave error");
        }
        if (ret != 0) {
            return Status(StatusCode::FAILED_PRECONDITION, "enclave call to new_ledger returned error");
        }

        reply->set_signature(reinterpret_cast<const char*>(signature.v), SIGNATURE_SIZE_IN_BYTES);
        return Status::OK;
    }

    Status ReadLatest(ServerContext *context, const ReadLatestReq* request, ReadLatestResp* reply) override {
        string h = request->handle();
        string n = request->nonce();
        if (h.size() != HASH_VALUE_SIZE_IN_BYTES) {
            return Status(StatusCode::INVALID_ARGUMENT, "handle size is invalid");
        }
        if (n.size() != NONCE_SIZE_IN_BYTES) {
            return Status(StatusCode::INVALID_ARGUMENT, "nonce size is invalid");
        }
        int ret = 0;
        oe_result_t result;
        // Request data
        handle_t handle;
        nonce_t nonce;
        memcpy(handle.v, h.c_str(), HASH_VALUE_SIZE_IN_BYTES);
        memcpy(nonce.v, n.c_str(), NONCE_SIZE_IN_BYTES);

        // Response data
        signature_t signature;
        result = read_latest(enclave, &ret, &handle, &nonce, &signature);
        if (result != OE_OK) {
            return Status(StatusCode::FAILED_PRECONDITION, "enclave error");
        }
        if (ret != 0) {
            return Status(StatusCode::FAILED_PRECONDITION, "enclave call to read_latest returned error");
        }

        reply->set_signature(reinterpret_cast<const char*>(signature.v), SIGNATURE_SIZE_IN_BYTES);
        return Status::OK;
    }

    Status Append(ServerContext *context, const AppendReq* request, AppendResp* reply) override {
        string h = request->handle();
        string b_h = request->block_hash();
        string cond_h = request->cond_updated_tail_hash();

        if (h.size() != HASH_VALUE_SIZE_IN_BYTES || b_h.size() != HASH_VALUE_SIZE_IN_BYTES || cond_h.size() != HASH_VALUE_SIZE_IN_BYTES) {
            return Status(StatusCode::INVALID_ARGUMENT, "append input sizes are invalid");
        }

        // Request data
        handle_t handle;
        digest_t block_hash;
        digest_t cond_updated_tail_hash;
        memcpy(handle.v, h.c_str(), HASH_VALUE_SIZE_IN_BYTES);
        memcpy(block_hash.v, b_h.c_str(), HASH_VALUE_SIZE_IN_BYTES);
        memcpy(cond_updated_tail_hash.v, cond_h.c_str(), HASH_VALUE_SIZE_IN_BYTES);

        // OE Prepare
        int ret = 0;
        oe_result_t result;

        // Response data
        signature_t signature;
        result = append(enclave, &ret, &handle, &block_hash, &cond_updated_tail_hash, &signature);
        if (result != OE_OK) {
            return Status(StatusCode::FAILED_PRECONDITION, "enclave error");
        }
        if (ret != 0) {
            return Status(StatusCode::FAILED_PRECONDITION, "enclave call to append returned error");
        }

        reply->set_signature(reinterpret_cast<const char*>(signature.v), SIGNATURE_SIZE_IN_BYTES);
        return Status::OK;
    }

    Status ReadLatestViewLedger(ServerContext *context, const ReadLatestViewLedgerReq* request, ReadLatestViewLedgerResp* reply) override {
        string n = request->nonce();
        if (n.size() != NONCE_SIZE_IN_BYTES) {
            return Status(StatusCode::INVALID_ARGUMENT, "nonce size is invalid");
        }
        int ret = 0;
        oe_result_t result;
        // Request data
        nonce_t nonce;
        memcpy(nonce.v, n.c_str(), NONCE_SIZE_IN_BYTES);

        // Response data
        signature_t signature;
        result = read_latest_view_ledger(enclave, &ret, &nonce, &signature);
        if (result != OE_OK) {
            return Status(StatusCode::FAILED_PRECONDITION, "enclave error");
        }
        if (ret != 0) {
            return Status(StatusCode::FAILED_PRECONDITION, "enclave call to read_latest returned error");
        }

        reply->set_signature(reinterpret_cast<const char*>(signature.v), SIGNATURE_SIZE_IN_BYTES);
        return Status::OK;
    }

    Status AppendViewLedger(ServerContext *context, const AppendViewLedgerReq* request, AppendViewLedgerResp* reply) override {
        string b_h = request->block_hash();
        string cond_h = request->cond_updated_tail_hash();

        if (b_h.size() != HASH_VALUE_SIZE_IN_BYTES || cond_h.size() != HASH_VALUE_SIZE_IN_BYTES) {
            return Status(StatusCode::INVALID_ARGUMENT, "append input sizes are invalid");
        }

        // Request data
        digest_t block_hash;
        digest_t cond_updated_tail_hash;
        memcpy(block_hash.v, b_h.c_str(), HASH_VALUE_SIZE_IN_BYTES);
        memcpy(cond_updated_tail_hash.v, cond_h.c_str(), HASH_VALUE_SIZE_IN_BYTES);

        // OE Prepare
        int ret = 0;
        oe_result_t result;

        // Response data
        signature_t signature;
        result = append_view_ledger(enclave, &ret, &block_hash, &cond_updated_tail_hash, &signature);
        if (result != OE_OK) {
            return Status(StatusCode::FAILED_PRECONDITION, "enclave error");
        }
        if (ret != 0) {
            return Status(StatusCode::FAILED_PRECONDITION, "enclave call to append returned error");
        }

        reply->set_signature(reinterpret_cast<const char*>(signature.v), SIGNATURE_SIZE_IN_BYTES);
        return Status::OK;
    }
};

int main(int argc, const char *argv[]) {
  oe_result_t result;
  int ret = 0;
  uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;

  if (check_simulate_opt(&argc, argv)) {
    cout << "Setting simulation flag" << endl;
    flags |= OE_ENCLAVE_FLAG_SIMULATE;
  }

  cout << "Host: Entering main" << endl;
  if (argc < 2) {
    cerr << "Usage: " << argv[0] << " enclave_image_path [port_number] [ --simulate  ]"
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

  // Call get_public_key
  endorser_id_t get_id_info;
  result = get_public_key(enclave, &ret,  &get_id_info);
  if (result != 0) {
      cerr << "Host: Failed to retrieve public key" << result << endl;
      goto exit;
  }
  printf("Host: Get PK: ");
  print_hex(get_id_info.pk, PUBLIC_KEY_SIZE_IN_BYTES);

  // Spinning up gRPC Services.
  {
      std::string server_address("0.0.0.0:");
      if (argc >= 3) {
        server_address.append(argv[2]);
      } else {
        server_address.append("9090");
      }
      std::cout << "Attempting to run Endorser at Address " << server_address << std::endl;
      EndorserCallServiceImpl service;
      ServerBuilder builder;
      builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
      builder.RegisterService(&service);
      std::unique_ptr<Server> server(builder.BuildAndStart());
      std::cout << "Endorser host listening on " << server_address << std::endl;
      server->Wait();
  }
  return 0;

exit:
  cout << "Host: terminate the enclave" << endl;
  cout << "Host: Endorser completed successfully." << endl;
  oe_terminate_enclave(enclave);
  return ret;
}
