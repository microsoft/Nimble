#include <iostream>
#include <map>
#include <mutex>

#include <string.h>
#include "shared.h"

#include <grpcpp/grpcpp.h>
#include "endorser.pb.h"
#include "endorser.grpc.pb.h"

#include "sgx_dcap_ql_wrapper.h"

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
using endorser_proto::InitializeStateReq;
using endorser_proto::InitializeStateResp;
using endorser_proto::LedgerTailMapEntry;

static map<handle_t, chain_t *> hash_chain_map;
static chain_t chains[MAX_NUM_CHAINS];

static mutex endorser_call_mutex;

void print_hex(unsigned char* d, unsigned int len) {
  printf("0x");
  for (int i = 0; i < len; i++) {
    printf("%c%c", "0123456789ABCDEF"[d[i] / 16],
           "0123456789ABCDEF"[d[i] % 16]);
  }
  cout << endl;
}

bool init_chain(handle_t *handle, const char *digest, unsigned long long height, chain_t *chain) {
    auto it = hash_chain_map.lower_bound(*handle);

    // handle exists
    if (memcmp(it->first.v, handle->v, HASH_VALUE_SIZE_IN_BYTES) == 0)
        return false;

    memcpy(chain->handle.v, handle->v, HASH_VALUE_SIZE_IN_BYTES);
    if (digest)
        memcpy(chain->digest.v, digest, HASH_VALUE_SIZE_IN_BYTES);
    else
        memset(chain->digest.v, 0, HASH_VALUE_SIZE_IN_BYTES);
    chain->height = height;
    chain->pos = hash_chain_map.size() - 1;
    chain->prev = it->second->prev;
    chain->next = it->second->pos;
    return true;
}

void insert_chain(chain_t *chain) {
    assert(hash_chain_map.size() - 1 == chain->pos);
    memcpy(&chains[chain->pos], chain, sizeof(chain_t));
    chains[chain->prev].next = chain->pos;
    chains[chain->next].prev = chain->pos;
    hash_chain_map.insert(make_pair(chain->handle, &chains[chain->pos]));
    return;
}

bool find_chain(handle_t *handle, chain_t *chain) {
    auto it = hash_chain_map.find(*handle);

    if (it == hash_chain_map.end())
        return false;

    memcpy(chain, it->second, sizeof(chain_t));

    return true;
}

void update_chain(chain_t *chain) {
    assert(chains[chain->pos].pos == chain->pos);
    memcpy(&chains[chain->pos], chain, sizeof(chain_t));

    return;
}

extern "C" bool enclu_call(endorser_call_t endorser_call, void *param1, void *param2, void *param3);

static bool call_endorser(
    endorser_call_t endorser_call,
    endorser_id_t *endorser_id,
    handle_t *handle,
    signature_t *signature,
    nonce_t *nonce,
    append_ledger_data_t *ledger_data
) {
    chain_t chain;
    bool ret = false;

    // TODO: we can use a fast read-write lock
    // on the hash_chain_map for better performance
    endorser_call_mutex.lock();

    switch(endorser_call) {
    case get_pubkey_call:
        ret = enclu_call(get_pubkey_call, endorser_id, NULL, NULL);
        if (ret) {
            printf("get_pubkey succeeded\n");
        } else {
            fprintf(stderr, "get_pubkey failed\n");
        }
        break;
    case create_ledger_call:
        if (init_chain(handle, NULL, 0, &chain)) {
            ret = enclu_call(create_ledger_call, &chain, signature, NULL);
            if (ret) {
                insert_chain(&chain);
                printf("create_ledger succeeded\n");
            } else {
                fprintf(stderr, "create_ledger failed\n");
            }
        } else {
            fprintf(stderr, "init_chain failed\n");
        }
        break;
    case read_ledger_call:
        if (find_chain(handle, &chain)) {
            ret = enclu_call(read_ledger_call, &chain, nonce, signature);
            if (ret) {
                update_chain(&chain);
                printf("read_ledger succeeded\n");
            } else {
                fprintf(stderr, "read_ledger_call failed\n");
            }
        } else {
            fprintf(stderr, "find_chain failed\n");
        }
        break;
    case append_ledger_call:
        if (find_chain(handle, &chain)) {
            ret = enclu_call(append_ledger_call, &chain, ledger_data, signature);
            if (ret) {
                update_chain(&chain);
                printf("append_ledger succeeded\n");
            } else {
                fprintf(stderr, "append_ledger failed\n");
            }
        } else {
            fprintf(stderr, "find_chain failed\n");
        }
        break;
    case read_view_ledger_call:
        ret = enclu_call(read_view_ledger_call, nonce, signature, NULL);
        if (ret)
            printf("read_view_ledger succeeded\n");
        else
            fprintf(stderr, "read_view_ledger failed\n");
        break;
    case append_view_ledger_call:
        ret = enclu_call(append_view_ledger_call, ledger_data, signature, NULL);
        if (ret)
            printf("append_view_ledger succeeded\n");
        else
            fprintf(stderr, "append_view_ledger failed\n");
        break;
    default:
        break;
    }

    endorser_call_mutex.unlock();

    return ret;
}

int start_endorser() {
    // get the quoting enclave's target info
    sgx_target_info_t qe_target_info;
    quote3_error_t qe_err = sgx_qe_get_target_info(&qe_target_info);
    if (qe_err != 0) {
        fprintf(stderr, "failed to get the target info of the quoting enclave!\n");
        return qe_err;
    }

    sgx_report_t sgx_report;
    endorser_call_mutex.lock();
    bool ok = enclu_call(start_endorser_call, &qe_target_info, &sgx_report, NULL);
    endorser_call_mutex.unlock();

    if (ok) {
        printf("start_endorser succeeded\n");
    } else {
        fprintf(stderr, "start_endorser failed\n");
        return -1;
    }

    uint32_t quote_size;
    qe_err = sgx_qe_get_quote_size(&quote_size);
    if (qe_err != 0) {
        fprintf(stderr, "failed to get the quote size\n");
        return qe_err;
    }

    uint8_t quote[quote_size];
    qe_err = sgx_qe_get_quote(&sgx_report, quote_size, quote);
    if (qe_err != 0) {
        fprintf(stderr, "failed to get the quote\n");
        return qe_err;
    } else {
        printf("sgx_qe_get_quote succeeded (quote size=%d)\n", quote_size);
    }

    return 0;
}

int init_endorser(const RepeatedPtrField<LedgerTailMapEntry> &ledger_tail_map,
                  const char *view_block,
                  const char *view_tail,
                  unsigned long long view_height,
                  const char *cond_updated_tail_hash,
                  signature_t *signature) {
    static bool initialized = false;
    int ret = 0;
    bool ok;
    init_endorser_data_t init_endorser_data;

    memcpy(init_endorser_data.view_block.v, view_block, HASH_VALUE_SIZE_IN_BYTES);
    memcpy(init_endorser_data.cond_updated_tail_hash.v, cond_updated_tail_hash, HASH_VALUE_SIZE_IN_BYTES);
    memcpy(init_endorser_data.view_tail.v, view_tail, HASH_VALUE_SIZE_IN_BYTES);
    init_endorser_data.view_height = view_height;

    endorser_call_mutex.lock();

    if (initialized) {
        fprintf(stderr, "init_endorser can only be called once\n");
        ret = -1;
        goto exit;
    }
    initialized = true;

    for (auto it = ledger_tail_map.begin(); it != ledger_tail_map.end(); it++) {
        chain_t chain;

        if (!init_chain((handle_t *)it->handle().c_str(), it->tail().c_str(), it->height(), &chain)) {
            fprintf(stderr, "duplicated handles\n");
            ret = -1;
            goto exit;
        }

        insert_chain(&chain);
    }

    init_endorser_data.chains = &chains[0];
    init_endorser_data.num_chains = hash_chain_map.size() - 2;
    ok = enclu_call(init_endorser_call, &init_endorser_data, signature, NULL);
    if (ok) {
        printf("init_endorser succeeded\n");
    } else {
        fprintf(stderr, "init_endorser failed\n");
        ret = -1;
    }

exit:
    endorser_call_mutex.unlock();
    return ret;
}

class EndorserCallServiceImpl final: public EndorserCall::Service {
    Status GetPublicKey(ServerContext* context, const GetPublicKeyReq* request, GetPublicKeyResp* reply) override {
        int ret = 0;
        endorser_id_t eid;
        if (!call_endorser(get_pubkey_call,
                           &eid,
                           NULL,
                           NULL,
                           NULL,
                           NULL)) {
            return Status(StatusCode::FAILED_PRECONDITION, "failed to get the endorser identity");
        }

        reply->set_pk(reinterpret_cast<const char*>(eid.pk), PUBLIC_KEY_SIZE_IN_BYTES);
        return Status::OK;
    }

    Status NewLedger(ServerContext *context, const NewLedgerReq* request, NewLedgerResp* reply) override {
        string h = request->handle();
        if (h.size() != HASH_VALUE_SIZE_IN_BYTES) {
            return Status(StatusCode::INVALID_ARGUMENT, "handle size is invalid");
        }

        handle_t handle;
        memcpy(handle.v, h.c_str(), HASH_VALUE_SIZE_IN_BYTES);

        signature_t signature;
        if (!call_endorser(create_ledger_call,
                           NULL,
                           &handle,
                           &signature,
                           NULL,
                           NULL)) {
            return Status(StatusCode::FAILED_PRECONDITION, "failed to create a ledger");
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

        // Request data
        handle_t handle;
        nonce_t nonce;
        memcpy(handle.v, h.c_str(), HASH_VALUE_SIZE_IN_BYTES);
        memcpy(nonce.v, n.c_str(), NONCE_SIZE_IN_BYTES);

        // Response data
        signature_t signature;
        if (!call_endorser(read_ledger_call,
                           NULL,
                           &handle,
                           &signature,
                           &nonce,
                           NULL)) {
            fprintf(stderr, "failed to read a ledger\n");
            return Status(StatusCode::FAILED_PRECONDITION, "failed to read a ledger");
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
        append_ledger_data_t ledger_data;
        memcpy(handle.v, h.c_str(), HASH_VALUE_SIZE_IN_BYTES);
        memcpy(ledger_data.block_hash.v, b_h.c_str(), HASH_VALUE_SIZE_IN_BYTES);
        memcpy(ledger_data.cond_updated_tail_hash.v, cond_h.c_str(), HASH_VALUE_SIZE_IN_BYTES);

        // Response data
        signature_t signature;
        if (!call_endorser(append_ledger_call,
                           NULL,
                           &handle,
                           &signature,
                           NULL,
                           &ledger_data)) {
            return Status(StatusCode::FAILED_PRECONDITION, "failed to append to a ledger");
        }

        reply->set_signature(reinterpret_cast<const char*>(signature.v), SIGNATURE_SIZE_IN_BYTES);
        return Status::OK;
    }

    Status ReadLatestViewLedger(ServerContext *context, const ReadLatestViewLedgerReq* request, ReadLatestViewLedgerResp* reply) override {
        string n = request->nonce();

        if (n.size() != NONCE_SIZE_IN_BYTES) {
            return Status(StatusCode::INVALID_ARGUMENT, "ReadLatestViewLedger: nonce size is invalid");
        }

        // Request data
        nonce_t nonce;
        memcpy(nonce.v, n.c_str(), NONCE_SIZE_IN_BYTES);

        // Response data
        signature_t signature;
        if (!call_endorser(read_view_ledger_call,
                           NULL,
                           NULL,
                           &signature,
                           &nonce,
                           NULL)) {
            return Status(StatusCode::FAILED_PRECONDITION, "failed to read the view ledger");
        }

        reply->set_signature(reinterpret_cast<const char*>(signature.v), SIGNATURE_SIZE_IN_BYTES);

        return Status::OK;
    }

    Status AppendViewLedger(ServerContext *context, const AppendViewLedgerReq* request, AppendViewLedgerResp* reply) override {
        string b_h = request->block_hash();
        string cond_h = request->cond_updated_tail_hash();

        if (b_h.size() != HASH_VALUE_SIZE_IN_BYTES || cond_h.size() != HASH_VALUE_SIZE_IN_BYTES) {
            return Status(StatusCode::INVALID_ARGUMENT, "InitViewLedger input size is invalid");
        }

        // Request data
        append_ledger_data_t ledger_data;
        memcpy(ledger_data.block_hash.v, b_h.c_str(), HASH_VALUE_SIZE_IN_BYTES);
        memcpy(ledger_data.cond_updated_tail_hash.v, cond_h.c_str(), HASH_VALUE_SIZE_IN_BYTES);

        // Response data
        signature_t signature;
        if (!call_endorser(append_view_ledger_call,
                           NULL,
                           NULL,
                           &signature,
                           NULL,
                           &ledger_data)) {
            return Status(StatusCode::FAILED_PRECONDITION, "failed to append the view ledger");
        }

        reply->set_signature(reinterpret_cast<const char*>(signature.v), SIGNATURE_SIZE_IN_BYTES);

        return Status::OK;
    }

    Status InitializeState(ServerContext *context, const InitializeStateReq *request, InitializeStateResp* reply) override {
        signature_t signature;
        if (init_endorser(request->ledger_tail_map(),
                           request->block_hash().c_str(),
                           request->view_ledger_tail().c_str(),
                           request->view_ledger_height(),
                           request->cond_updated_tail_hash().c_str(),
                           &signature)) {
            return Status(StatusCode::FAILED_PRECONDITION, "failed to initialize the endorser state");
        }

        reply->set_signature(reinterpret_cast<const char*>(signature.v), SIGNATURE_SIZE_IN_BYTES);

        return Status::OK;
    }
};

int launch_endorser(const char *endorser_elf_fname, const char *private_key_file);

int main(int argc, const char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "%s <endorser-elf> <private-key> [<port-number>]\n", argv[0]);
        return -1;
    }

    if (launch_endorser(argv[1], argv[2]) != 0) {
        fprintf(stderr, "failed to launch the endorser\n");
        return -1;
    }

    if (start_endorser()) {
        fprintf(stderr, "failed to initialize the endorser\n");
        return -1;
    }

    // initialize hash_chain_map
    chain_t *first_chain = &chains[0];
    chain_t *last_chain = &chains[MAX_NUM_CHAINS-1];
    memset(first_chain, 0, sizeof(chain_t));
    first_chain->prev = (unsigned long long)-1;
    first_chain->next = MAX_NUM_CHAINS - 1;
    memset(last_chain, 0, sizeof(chain_t));
    memset(last_chain->handle.v, 0xff, HASH_VALUE_SIZE_IN_BYTES);
    last_chain->next = (unsigned long long)-1;
    last_chain->pos = MAX_NUM_CHAINS - 1;
    hash_chain_map.insert(make_pair(first_chain->handle, first_chain));
    hash_chain_map.insert(make_pair(last_chain->handle, last_chain));

    // Spinning up gRPC Services.
    {
        std::string server_address("0.0.0.0:");
        if (argc >= 4) {
            server_address.append(argv[3]);
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
}
