#include "../shared.h"
#include <iostream>
#include <memory>
#include <thread>

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
using grpc::ResourceQuota;

using endorser_proto::EndorserCall;
using endorser_proto::GetPublicKeyReq;
using endorser_proto::GetPublicKeyResp;
using endorser_proto::NewLedgerReq;
using endorser_proto::NewLedgerResp;
using endorser_proto::ReadLatestReq;
using endorser_proto::ReadLatestResp;
using endorser_proto::AppendReq;
using endorser_proto::AppendResp;
using endorser_proto::LedgerTailMapEntry;
using endorser_proto::EndorserMode;
using endorser_proto::InitializeStateReq;
using endorser_proto::InitializeStateResp;
using endorser_proto::FinalizeStateReq;
using endorser_proto::FinalizeStateResp;
using endorser_proto::ReadStateReq;
using endorser_proto::ReadStateResp;
using endorser_proto::ActivateReq;
using endorser_proto::ActivateResp;

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
        endorser_status_code ret = endorser_status_code::OK;
        oe_result_t result;
        endorser_id_t eid;
        result = get_public_key(enclave, &ret,  &eid);
        if (result != OE_OK) {
            return Status(StatusCode::INTERNAL, "enclave error");
        }
        if (ret != endorser_status_code::OK) {
            return Status((StatusCode)ret, "enclave call return error");
        }
        reply->set_pk(reinterpret_cast<const char*>(eid.pk), PUBLIC_KEY_SIZE_IN_BYTES);
        return Status::OK;
    }

    Status InitializeState(ServerContext *context, const InitializeStateReq* request, InitializeStateResp* reply) override {
        string id = request->group_identity();
        RepeatedPtrField<LedgerTailMapEntry> l_t_m = request->ledger_tail_map();
        string t = request->view_tail_metablock();
        string b_h = request->block_hash();
        unsigned long long h = request->expected_height();

        if (id.size() != HASH_VALUE_SIZE_IN_BYTES || t.size() != sizeof(metablock_t) || b_h.size() != HASH_VALUE_SIZE_IN_BYTES) {
          return Status(StatusCode::INVALID_ARGUMENT, "invalid arguments in the request for InitializeState");
        }

        auto num_entries = l_t_m.size();
        ledger_tail_map_entry_t ledger_tail_map[num_entries];
        int i = 0;
        for (auto it = l_t_m.begin(); it != l_t_m.end(); it++) {
          if (it->handle().size() != HASH_VALUE_SIZE_IN_BYTES || it->metablock().size() != sizeof(metablock_t)) {
            return Status(StatusCode::INVALID_ARGUMENT, "handle or metablock in the ledger tail has wrong size");
          }
          memcpy(ledger_tail_map[i].handle.v, it->handle().c_str(), HASH_VALUE_SIZE_IN_BYTES);
          memcpy(&ledger_tail_map[i].metablock, it->metablock().c_str(), sizeof(metablock_t));
          i++;
        }

        init_endorser_data_t state;
        state.ledger_tail_map_size = num_entries;
        state.ledger_tail_map = ledger_tail_map;
        memcpy(&state.view_tail_metablock, request->view_tail_metablock().c_str(), sizeof(metablock_t));
        memcpy(state.block_hash.v, b_h.c_str(), HASH_VALUE_SIZE_IN_BYTES);
        state.expected_height = h;
        memcpy(state.group_identity.v, id.c_str(), HASH_VALUE_SIZE_IN_BYTES);

        endorser_status_code ret = endorser_status_code::OK;
        oe_result_t result;
        
        receipt_t receipt;
        result = initialize_state(enclave, &ret, &state, &receipt);
        if (result != OE_OK) {
            return Status(StatusCode::INTERNAL, "enclave error");
        }
        if (ret != endorser_status_code::OK) {
            return Status((StatusCode)ret, "enclave call to initialize_state returned error");
        }

        reply->set_receipt(reinterpret_cast<const char*>(&receipt), sizeof(receipt));
        return Status::OK;
    }

    Status NewLedger(ServerContext *context, const NewLedgerReq* request, NewLedgerResp* reply) override {
        string h = request->handle();
        if (h.size() != HASH_VALUE_SIZE_IN_BYTES) {
            return Status(StatusCode::INVALID_ARGUMENT, "handle size is invalid");
        }
        string b_h = request->block_hash();
        if (b_h.size() != HASH_VALUE_SIZE_IN_BYTES) {
          return Status(StatusCode::INVALID_ARGUMENT, "block hash size is invalid");
        }

        endorser_status_code ret = endorser_status_code::OK;
        oe_result_t result;
        handle_t handle;
        memcpy(handle.v, h.c_str(), HASH_VALUE_SIZE_IN_BYTES);
        digest_t block_hash;
        memcpy(block_hash.v, b_h.c_str(), HASH_VALUE_SIZE_IN_BYTES);
        
        receipt_t receipt;
        result = new_ledger(enclave, &ret, &handle, &block_hash, &receipt);
        if (result != OE_OK) {
            return Status(StatusCode::FAILED_PRECONDITION, "enclave error");
        }
        if (ret != endorser_status_code::OK) {
            return Status((StatusCode)ret, "enclave call to new_ledger returned error");
        }

        reply->set_receipt(reinterpret_cast<const char*>(&receipt), sizeof(receipt));
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
        endorser_status_code ret = endorser_status_code::OK;
        oe_result_t result;
        // Request data
        handle_t handle;
        nonce_t nonce;
        memcpy(handle.v, h.c_str(), HASH_VALUE_SIZE_IN_BYTES);
        memcpy(nonce.v, n.c_str(), NONCE_SIZE_IN_BYTES);

        // Response data
        receipt_t receipt;
        result = read_latest(enclave, &ret, &handle, &nonce, &receipt);
        if (result != OE_OK) {
            return Status(StatusCode::INTERNAL, "enclave error");
        }
        if (ret != endorser_status_code::OK) {
            return Status((StatusCode)ret, "enclave call to read_latest returned error");
        }

        reply->set_receipt(reinterpret_cast<const char*>(&receipt), sizeof(receipt_t));
        return Status::OK;
    }

    Status Append(ServerContext *context, const AppendReq* request, AppendResp* reply) override {
        string h = request->handle();
        string b_h = request->block_hash();
        uint64_t expected_height = request->expected_height();

        if (h.size() != HASH_VALUE_SIZE_IN_BYTES || b_h.size() != HASH_VALUE_SIZE_IN_BYTES) {
            return Status(StatusCode::INVALID_ARGUMENT, "append input sizes are invalid");
        }

        // Request data
        handle_t handle;
        digest_t block_hash;
        memcpy(handle.v, h.c_str(), HASH_VALUE_SIZE_IN_BYTES);
        memcpy(block_hash.v, b_h.c_str(), HASH_VALUE_SIZE_IN_BYTES);

        // OE Prepare
        endorser_status_code ret = endorser_status_code::OK;
        oe_result_t result;

        // Response data
        receipt_t receipt;
        uint64_t current_height;
        result = append(enclave, &ret, &handle, &block_hash, expected_height, &current_height, &receipt);
        if (result != OE_OK) {
            return Status(StatusCode::INTERNAL, "enclave error");
        }
        if (ret != endorser_status_code::OK) {
          if (ret == endorser_status_code::FAILED_PRECONDITION) {
            return Status((StatusCode)ret, "Out of order", std::string((const char *)&current_height, sizeof(uint64_t)));
          } else {
            return Status((StatusCode)ret, "enclave call to append returned error");
          }
        }

        reply->set_receipt(reinterpret_cast<const char*>(&receipt), sizeof(receipt_t));
        return Status::OK;
    }

    Status FinalizeState(ServerContext *context, const FinalizeStateReq* request, FinalizeStateResp* reply) override {
        string b_h = request->block_hash();
        uint64_t expected_height = request->expected_height();

        if (b_h.size() != HASH_VALUE_SIZE_IN_BYTES) {
            return Status(StatusCode::INVALID_ARGUMENT, "block hash size is invalid");
        }

        // Request data
        digest_t block_hash;
        memcpy(block_hash.v, b_h.c_str(), HASH_VALUE_SIZE_IN_BYTES);

        // OE Prepare
        endorser_status_code ret = endorser_status_code::OK;
        oe_result_t result;

        // Response data
        receipt_t receipt;
        uint64_t ledger_tail_map_size;
        std::unique_ptr<ledger_tail_map_entry_t[]> ledger_tail_map = nullptr;

        result = get_ledger_tail_map_size(enclave, &ret, &ledger_tail_map_size);
        if (result != OE_OK) {
            return Status(StatusCode::INTERNAL, "enclave error");
        }
        if (ret != endorser_status_code::OK) {
            return Status((StatusCode)ret, "enclave call to get ledger tail map size returned error");
        }

        if (ledger_tail_map_size > 0) {
            ledger_tail_map = std::unique_ptr<ledger_tail_map_entry_t[]>(new ledger_tail_map_entry_t[ledger_tail_map_size]);
        }

        result = finalize_state(enclave, &ret, &block_hash, expected_height, ledger_tail_map_size, ledger_tail_map.get(), &receipt);

        if (result != OE_OK) {
            return Status(StatusCode::INTERNAL, "enclave error");
        }
        if (ret != endorser_status_code::OK) {
            return Status((StatusCode)ret, "enclave call to append returned error");
        }

        reply->set_receipt(reinterpret_cast<const char*>(&receipt), sizeof(receipt_t));
        for (uint64_t index = 0; index < ledger_tail_map_size; index++) {
            ledger_tail_map_entry_t *input = &ledger_tail_map[index];
            auto entry = reply->add_ledger_tail_map();
            entry->set_handle(reinterpret_cast<const char*>(input->handle.v), HASH_VALUE_SIZE_IN_BYTES);
            entry->set_metablock(reinterpret_cast<const char*>(&input->metablock), sizeof(metablock_t));
        }

        return Status::OK;
    }

    Status ReadState(ServerContext *context, const ReadStateReq *request, ReadStateResp *reply) override {
        endorser_status_code ret = endorser_status_code::OK;
        oe_result_t result;
        receipt_t receipt;
        endorser_mode_t endorser_mode;
        uint64_t ledger_tail_map_size;
        std::unique_ptr<ledger_tail_map_entry_t[]> ledger_tail_map = nullptr;

        result = get_ledger_tail_map_size(enclave, &ret, &ledger_tail_map_size);
        if (result != OE_OK) {
            return Status(StatusCode::INTERNAL, "enclave error");
        }
        if (ret != endorser_status_code::OK) {
            return Status((StatusCode)ret, "enclave call to get ledger tail map size returned error");
        }

        if (ledger_tail_map_size > 0) {
            ledger_tail_map = std::unique_ptr<ledger_tail_map_entry_t[]>(new ledger_tail_map_entry_t[ledger_tail_map_size]);
        }

        result = read_state(enclave, &ret, ledger_tail_map_size, ledger_tail_map.get(), &endorser_mode, &receipt);

        if (result != OE_OK) {
            return Status(StatusCode::INTERNAL, "enclave error");
        }
        if (ret != endorser_status_code::OK) {
            return Status((StatusCode)ret, "enclave call to read state returned error");
        }

        reply->set_receipt(reinterpret_cast<const char*>(&receipt), sizeof(receipt_t));
        reply->set_mode((EndorserMode)endorser_mode);
        for (uint64_t index = 0; index < ledger_tail_map_size; index++) {
            ledger_tail_map_entry_t *input = &ledger_tail_map[index];
            auto entry = reply->add_ledger_tail_map();
            entry->set_handle(reinterpret_cast<const char*>(input->handle.v), HASH_VALUE_SIZE_IN_BYTES);
            entry->set_metablock(reinterpret_cast<const char*>(&input->metablock), sizeof(metablock_t));
        }

        return Status::OK;
    }

    Status Activate(ServerContext *context, const ActivateReq *request, ActivateResp *reply) override {
        endorser_status_code ret = endorser_status_code::OK;
        oe_result_t result;

        result = activate(enclave, &ret);
        if (result != OE_OK) {
            return Status(StatusCode::INTERNAL, "enclave error");
        }
        if (ret != endorser_status_code::OK) {
            return Status((StatusCode)ret, "enclave call to read state returned error");
        }

        return Status::OK;
    }
};

int main(int argc, const char *argv[]) {
  oe_result_t result;
  endorser_status_code ret = endorser_status_code::OK;

  uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;

  if (check_simulate_opt(&argc, argv)) {
    cout << "Setting simulation flag" << endl;
    flags |= OE_ENCLAVE_FLAG_SIMULATE;
  }

  cout << "Host: Entering main" << endl;
  if (argc < 2) {
    cerr << "Usage: " << argv[0] << " enclave_image_path [-p port_number] [--simulate  ]"
         << endl;
    return 1;
  }

  cout << "Host: create enclave for image:" << argv[1] << endl;
  result = oe_create_endorser_enclave(argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL,
                                      0, &enclave);
  if (result != OE_OK) {
    cerr << "oe_create_endorser_enclave() failed with " << argv[0] << " "
         << result << endl;
    ret = endorser_status_code::INTERNAL;
  }

  // set the endorser 
  endorser_id_t endorser_id;
  result = setup(enclave, &ret, &endorser_id);
  if (result != OE_OK) {
    ret = endorser_status_code::INTERNAL;
    goto exit;
  }
  if (ret != endorser_status_code::OK) {
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
        if (strcmp(argv[2], "-p") == 0 && argc >= 4) {
          server_address.append(argv[3]);
        } else {
          cerr << "Usage: " << argv[0] << " enclave_image_path [-p port_number] [--simulate  ]"
               << endl;
          return 1;
        }
      } else {
        server_address.append("9090");
      }
      std::cout << "Attempting to run Endorser at Address " << server_address << std::endl;
      EndorserCallServiceImpl service;
      ResourceQuota resource_quota;
      const auto processor_count = std::thread::hardware_concurrency();
      resource_quota.SetMaxThreads(processor_count > 0 ? processor_count : 16);
      ServerBuilder builder;
      builder.SetResourceQuota(resource_quota);
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
  return (int)ret;
}
