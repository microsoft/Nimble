/*********************************************************
 *      Copyright (c) Microsoft Corporation.
 *
 *  @File: SgxSignTool.h
 *  @Owner: Baumann
 *
 *  Purpose: Tool for measuring and signing SQLPAL enclaves for SGX -- common header
 *
 *  Notes:
 *
 *  @EndHeader@
 ********************************************************/

#pragma once

#include <cstddef>
#include <openssl/sha.h>
#include "def.h"
#include "sgx_arch.h"
#include "sgx_user.h"


// error code
typedef enum {
    ENCLAVE_HASH_NO_ERROR = 0x0000,
    ENCLAVE_HASH_SIGSTRUCT_FAILURE = 0x0100,
    ENCLAVE_HASH_LEPUBKEYHASH_FAILURE = 0x0101,
} enclave_hash_error_t;

// ------------------------------------------------------
// EnclaveHash.cpp

void
MeasureECreate(
    _In_ uint32_t        ssaFrameSize,
    _In_ uint64_t        enclaveSize,
    _Out_ SHA256_CTX*    shaContext);

void
MeasureEAdd(
    _In_ uint64_t        flags,
    _In_ size_t          pageOffsetInEnclave,
    _In_Out_ SHA256_CTX* shaContext);

void
MeasureEExtend(
    _In_ size_t          offsetInEnclave,
    _In_Opt_ const void* data,
    _In_Out_ SHA256_CTX* shaContext);

void
MeasureEInit(
    _In_Out_ SHA256_CTX* shaContext,
    _Out_ uint8_t*       hash);

void
MeasurePage(
    _In_Out_ SHA256_CTX* shaContext,
    _In_ size_t          enclaveOffset,
    _In_ uint64_t        secInfo,
    _In_Opt_ void*       data);

void
MeasurePages(
    _In_Out_ SHA256_CTX* shaContext,
    _In_ size_t          enclaveOffset,
    _In_ uint64_t        secInfo,
    _In_ size_t          byteLen,
    _In_Opt_ void*       data);

// -------------------------------------------------------
// EnclaveSigStruct.cpp
int
MakeSigStructWithKeyInFile(
    _In_ uint8_t*               enclaveHash,
    _In_ const char*            privateKeyFile,
    _Out_ struct sgx_sigstruct* sigStruct);

int
SetSgxLePubKeyHash(
    _In_ struct sgx_sigstruct*  sigStruct);
