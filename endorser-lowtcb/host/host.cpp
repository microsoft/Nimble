#include <iostream>
#include <map>
#include <mutex>

#include <string.h>
#include "../include/shared.h"

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
using endorser_proto::AppendViewLedgerReq;
using endorser_proto::AppendViewLedgerResp;
using endorser_proto::InitializeStateReq;
using endorser_proto::InitializeStateResp;
using endorser_proto::LedgerTailMapEntry;
using endorser_proto::ReadLatestStateReq;
using endorser_proto::ReadLatestStateResp;
using endorser_proto::UnlockReq;
using endorser_proto::UnlockResp;

static map<handle_t, chain_t *> hash_chain_map;
static chain_t chains[MAX_NUM_CHAINS];

static mutex endorser_call_mutex;

static bool endorser_locked = false;

void print_hex(unsigned char* d, unsigned int len) {
  printf("0x");
  for (int i = 0; i < len; i++) {
    printf("%c%c", "0123456789ABCDEF"[d[i] / 16],
           "0123456789ABCDEF"[d[i] % 16]);
  }
  cout << endl;
}

bool init_chain(handle_t *handle, metablock_t *metablock, chain_t *chain) {
    auto it = hash_chain_map.lower_bound(*handle);

    // handle exists
    if (memcmp(it->first.v, handle->v, HASH_VALUE_SIZE_IN_BYTES) == 0)
        return false;

    memcpy(chain->handle.v, handle->v, HASH_VALUE_SIZE_IN_BYTES);
    if (metablock)
        memcpy(&chain->metablock, metablock, sizeof(metablock_t));
    else
        memset(&chain->metablock, 0, sizeof(metablock_t));
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

extern "C" StatusCode enclu_call(endorser_call_t endorser_call, void *param1, void *param2, void *param3);

static StatusCode call_endorser(
    endorser_call_t endorser_call,
    endorser_id_t *endorser_id,
    handle_t *handle,
    receipt_t *receipt,
    read_ledger_data_t *read_ledger_data,
    append_ledger_data_t *append_ledger_data,
    bool ignore_lock
) {
    chain_t chain;
    StatusCode status;

    // TODO: we can use a fast read-write lock
    // on the hash_chain_map for better performance
    endorser_call_mutex.lock();

    switch(endorser_call) {
    case get_pubkey_call:
        status = enclu_call(get_pubkey_call, endorser_id, NULL, NULL);
        break;
    case create_ledger_call:
        if (endorser_locked && !ignore_lock) {
            status = StatusCode::CANCELLED;
        } else if (init_chain(handle, NULL, &chain)) {
            status = enclu_call(create_ledger_call, &chain, append_ledger_data, receipt);
            if (status == StatusCode::OK)
                insert_chain(&chain);
        } else {
            status = StatusCode::ALREADY_EXISTS;
        }
        break;
    case read_ledger_call:
        if (find_chain(handle, &chain)) {
            status = enclu_call(read_ledger_call, &chain, read_ledger_data, receipt);
            if (status == StatusCode::OK)
                update_chain(&chain);
        } else {
            status = StatusCode::NOT_FOUND;
        }
        break;
    case append_ledger_call:
        if (endorser_locked && !ignore_lock) {
            status = StatusCode::CANCELLED;
        } else if (find_chain(handle, &chain)) {
            status = enclu_call(append_ledger_call, &chain, append_ledger_data, receipt);
            if (status == StatusCode::OK)
                update_chain(&chain);
        } else {
            status = StatusCode::NOT_FOUND;
        }
        break;
    case append_view_ledger_call:
        status = enclu_call(append_view_ledger_call, append_ledger_data, receipt, NULL);
        break;
    default:
        status = StatusCode::INVALID_ARGUMENT;
        break;
    }

    endorser_call_mutex.unlock();

    return status;
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
    StatusCode status = enclu_call(start_endorser_call, &qe_target_info, &sgx_report, NULL);
    endorser_call_mutex.unlock();

    if (status != StatusCode::OK) {
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
    }

    return 0;
}

StatusCode init_endorser(const RepeatedPtrField<LedgerTailMapEntry> &ledger_tail_map,
                  const char *view_tail_metablock,
                  const char *block_hash,
                  unsigned long long expected_height,
                  receipt_t *receipt) {
    static bool initialized = false;
    StatusCode status;
    init_endorser_data_t init_endorser_data;

    memcpy((char *)&init_endorser_data.view_tail_metablock, view_tail_metablock, sizeof(metablock_t));
    memcpy(init_endorser_data.block_hash.v, block_hash, HASH_VALUE_SIZE_IN_BYTES);
    init_endorser_data.expected_height = expected_height;

    endorser_call_mutex.lock();

    if (initialized) {
        status = StatusCode::ALREADY_EXISTS;
        goto exit;
    }
    initialized = true;

    for (auto it = ledger_tail_map.begin(); it != ledger_tail_map.end(); it++) {
        chain_t chain;
        metablock_t *metablock = (metablock_t *)it->metablock().c_str();

        if (!init_chain((handle_t *)it->handle().c_str(), metablock, &chain)) {
            status = StatusCode::INVALID_ARGUMENT;
            goto exit;
        }

        insert_chain(&chain);
    }

    init_endorser_data.chains = &chains[0];
    init_endorser_data.num_chains = hash_chain_map.size() - 2;
    status = enclu_call(init_endorser_call, &init_endorser_data, receipt, NULL);

exit:
    endorser_call_mutex.unlock();
    return status;
}

uint64_t get_height(handle_t* handle) {
    chain_t chain;

    if (find_chain(handle, &chain)) {
        return chain.metablock.height;
    } else {
        // this shouldn't happen!
        assert(0);
        return 0;
    }
}

class EndorserCallServiceImpl final: public EndorserCall::Service {
    Status GetPublicKey(ServerContext* context, const GetPublicKeyReq* request, GetPublicKeyResp* reply) override {
        int ret = 0;
        endorser_id_t eid;
        StatusCode status = call_endorser(get_pubkey_call,
                                          &eid,
                                          NULL,
                                          NULL,
                                          NULL,
                                          NULL,
                                          true);
        if (status != StatusCode::OK)
            return Status(status, "failed to get the endorser identity");

        reply->set_pk(reinterpret_cast<const char*>(eid.pk), PUBLIC_KEY_SIZE_IN_BYTES);
        return Status::OK;
    }

    Status NewLedger(ServerContext *context, const NewLedgerReq* request, NewLedgerResp* reply) override {
        string h = request->handle();
        string b_h = request->block_hash();
        bool ignore_lock = request->ignore_lock();

        if (h.size() != HASH_VALUE_SIZE_IN_BYTES) {
            return Status(StatusCode::INVALID_ARGUMENT, "handle size is invalid");
        }
        if (b_h.size() != HASH_VALUE_SIZE_IN_BYTES) {
            return Status(StatusCode::INVALID_ARGUMENT, "block hash size is invalid");
        }

        handle_t handle;
        append_ledger_data_t ledger_data;
        memcpy(handle.v, h.c_str(), HASH_VALUE_SIZE_IN_BYTES);
        memcpy(ledger_data.block_hash.v, b_h.c_str(), HASH_VALUE_SIZE_IN_BYTES);
        ledger_data.expected_height = 0;
        ledger_data.ignore_lock = ignore_lock;

        receipt_t receipt;
        StatusCode status = call_endorser(create_ledger_call,
                                          NULL,
                                          &handle,
                                          &receipt,
                                          NULL,
                                          &ledger_data,
                                          ignore_lock);
        if (status != StatusCode::OK)
            return Status(status, "failed to create a ledger");

        reply->set_receipt(reinterpret_cast<const char*>(&receipt), sizeof(receipt_t));
        return Status::OK;
    }

    Status ReadLatest(ServerContext *context, const ReadLatestReq* request, ReadLatestResp* reply) override {
        string h = request->handle();
        string n = request->nonce();
        uint64_t expected_height = request->expected_height();
        if (h.size() != HASH_VALUE_SIZE_IN_BYTES) {
            return Status(StatusCode::INVALID_ARGUMENT, "handle size is invalid");
        }
        if (n.size() != NONCE_SIZE_IN_BYTES) {
            return Status(StatusCode::INVALID_ARGUMENT, "nonce size is invalid");
        }

        // Request data
        handle_t handle;
        read_ledger_data_t read_ledger_data;
        memcpy(handle.v, h.c_str(), HASH_VALUE_SIZE_IN_BYTES);
        memcpy(read_ledger_data.block_hash.v, h.c_str(), HASH_VALUE_SIZE_IN_BYTES);
        memcpy(read_ledger_data.nonce.v, n.c_str(), NONCE_SIZE_IN_BYTES);
        read_ledger_data.expected_height = expected_height;

        // Response data
        receipt_t receipt;
        StatusCode status = call_endorser(read_ledger_call,
                                          NULL,
                                          &handle,
                                          &receipt,
                                          &read_ledger_data,
                                          NULL,
                                          true);
        if (status != StatusCode::OK) {
            if (status == StatusCode::FAILED_PRECONDITION) {
                uint64_t height = get_height(&handle);
                return Status(status, "Out of order", std::string((const char *)&height, sizeof(uint64_t)));
            } else {
                return Status(status, "failed to read a ledger");
            }
        }

        reply->set_receipt(reinterpret_cast<const char*>(&receipt), sizeof(receipt_t));
        return Status::OK;
    }

    Status Append(ServerContext *context, const AppendReq* request, AppendResp* reply) override {
        string h = request->handle();
        string b_h = request->block_hash();
        uint64_t expected_height = request->expected_height();
        bool ignore_lock = request->ignore_lock();

        if (h.size() != HASH_VALUE_SIZE_IN_BYTES) {
            return Status(StatusCode::INVALID_ARGUMENT, "handle size is invalid");
        }
        if (b_h.size() != HASH_VALUE_SIZE_IN_BYTES) {
            return Status(StatusCode::INVALID_ARGUMENT, "block hash size is invalid");
        }

        // Request data
        handle_t handle;
        append_ledger_data_t append_ledger_data;
        memcpy(handle.v, h.c_str(), HASH_VALUE_SIZE_IN_BYTES);
        memcpy(append_ledger_data.block_hash.v, b_h.c_str(), HASH_VALUE_SIZE_IN_BYTES);
        append_ledger_data.expected_height = expected_height;
        append_ledger_data.ignore_lock = ignore_lock;

        // Response data
        receipt_t receipt;
        StatusCode status = call_endorser(append_ledger_call,
                                          NULL,
                                          &handle,
                                          &receipt,
                                          NULL,
                                          &append_ledger_data,
                                          ignore_lock);
        if (status != StatusCode::OK) {
            if (status == StatusCode::FAILED_PRECONDITION) {
                uint64_t height = get_height(&handle);
                return Status(status, "Out of order", std::string((const char *)&height, sizeof(uint64_t)));
            } else {
                return Status(status, "failed to append to a ledger");
            }
        }

        reply->set_receipt(reinterpret_cast<const char*>(&receipt), sizeof(receipt_t));
        return Status::OK;
    }

    Status AppendViewLedger(ServerContext *context, const AppendViewLedgerReq* request, AppendViewLedgerResp* reply) override {
        string b_h = request->block_hash();
        uint64_t expected_height = request->expected_height();

        if (b_h.size() != HASH_VALUE_SIZE_IN_BYTES) {
            return Status(StatusCode::INVALID_ARGUMENT, "block hash size is invalid");
        }

        // Request data
        append_ledger_data_t ledger_data;
        memcpy(ledger_data.block_hash.v, b_h.c_str(), HASH_VALUE_SIZE_IN_BYTES);
        ledger_data.expected_height = expected_height;
        ledger_data.ignore_lock = true;

        // Response data
        receipt_t receipt;
        StatusCode status = call_endorser(append_view_ledger_call,
                                          NULL,
                                          NULL,
                                          &receipt,
                                          NULL,
                                          &ledger_data,
                                          true);
        if (status != StatusCode::OK)
            return Status(status, "failed to append the view ledger");

        reply->set_receipt(reinterpret_cast<const char*>(&receipt), sizeof(receipt_t));
        return Status::OK;
    }

    Status InitializeState(ServerContext *context, const InitializeStateReq *request, InitializeStateResp* reply) override {
        receipt_t receipt;
        StatusCode status = init_endorser(request->ledger_tail_map(),
                                          request->view_tail_metablock().c_str(),
                                          request->block_hash().c_str(),
                                          request->expected_height(),
                                          &receipt);
        if (status != StatusCode::OK)
            return Status(status, "failed to initialize the endorser state");

        reply->set_receipt(reinterpret_cast<const char*>(&receipt), sizeof(receipt_t));
        return Status::OK;
    }

    Status ReadLatestState(ServerContext *context, const ReadLatestStateReq *request, ReadLatestStateResp *reply) override {
        bool to_lock = request->to_lock();
        metablock_t metablock;

        endorser_call_mutex.lock();

        if (to_lock)
            endorser_locked = true;

        StatusCode status = enclu_call(read_view_tail_call, &metablock, NULL, NULL);
        if (status != StatusCode::OK) {
            endorser_call_mutex.unlock();
            return Status(status, "failed to read view tail metablock");
        }
        reply->set_view_tail_metablock(reinterpret_cast<const char*>(&metablock), sizeof(metablock_t));

        for (unsigned long long pos = chains[0].next; pos != MAX_NUM_CHAINS-1; pos = chains[pos].next) {
            chain_t *chain = &chains[pos];
            auto entry = reply->add_ledger_tail_map();
            entry->set_handle(reinterpret_cast<const char*>(chain->handle.v), HASH_VALUE_SIZE_IN_BYTES);
            entry->set_metablock(reinterpret_cast<const char*>(&chain->metablock), sizeof(metablock_t));
        }
    
        endorser_call_mutex.unlock();
        return Status::OK;
    }

    Status Unlock(ServerContext *context, const UnlockReq *request, UnlockResp *reply) {
        endorser_call_mutex.lock();
        endorser_locked = false;
        endorser_call_mutex.unlock();
        return Status::OK;
    }
};

int launch_endorser(const char *endorser_elf_fname, const char *private_key_file);

int main(int argc, const char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "%s <endorser-elf> <private-key> [-p <port-number>]\n", argv[0]);
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
            if (strcmp(argv[3], "-p") == 0 && argc >= 5) {
                server_address.append(argv[4]);
            } else {
                fprintf(stderr, "%s <endorser-elf> <private-key> [-p <port-number>]\n", argv[0]);
                return -1;
            }
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
