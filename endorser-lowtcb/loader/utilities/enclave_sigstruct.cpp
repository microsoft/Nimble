//*********************************************************************
//      Copyright (c) Microsoft Corporation.
//
// @File: EnclaveSigStruct.cpp
// @Owner: Baumann
//
// Purpose: Generate and sign an SGX SigStruct for a given enclave measurement.
//
// Notes:   Derived from original Haven version by MarcusPe
//
// @EndHeader@
//*********************************************************************

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include "SgxSignTool.h"

static void
ReverseEndian(
    _In_  uint8_t* in,
    _Out_ uint8_t* out,
    _In_   size_t size)
{
    for (size_t i = 0; i < size; i++)
    {
        out[i] = in[size-i-1];
    }
}

/////////////////////////////////////////////////////////////////////////////////////////
//
// Create SigStruct
//
/////////////////////////////////////////////////////////////////////////////////////////

//------------------------------------------------------------------------------
// Function: HashSigStruct
//
// Description:
//   Hash the given SigStruct as specified by SGX.
//
static void
HashSigStruct(
    _In_ const struct sgx_sigstruct* sigStruct,
    _Out_ uint8_t*                   hash)
{
    SHA256_CTX shaContext;

    SHA256_Init(&shaContext);
    SHA256_Update(&shaContext, reinterpret_cast<const uint8_t*>(&sigStruct->header), 128);
    SHA256_Update(&shaContext, reinterpret_cast<const uint8_t*>(&sigStruct->body), 128);

    SHA256_Final(hash, &shaContext);
}

//------------------------------------------------------------------------------
// Function: MakeSigStruct
//
// Description:
//   Construct an SGX signature structure ("SigStruct") for the given enclave
//   measurement and sign it with the given private key. The resulting signature
//   is embedded in the output structure.
//
// Params:
//   sigStruct   - output buffer
//   enclaveHash - pre-computed SHA hash of the enclave measurement
//   privKey     - private key for signing
//
// Returns:
//   true on success, false on failure
//
static bool
MakeSigStruct(
    _In_  uint8_t*              enclaveHash,
    _In_  RSA*                  privKey,
    _Out_ struct sgx_sigstruct* sigStruct)
{
    memset(sigStruct, 0, sizeof(*sigStruct));
    //
    // Write the headers
    //
    memcpy(sigStruct->header.header1, SGX_SIGSTRUCT_HEADER1, SGX_SIGSTRUCT_HEADER1_SIZE);
    memcpy(sigStruct->header.header2, SGX_SIGSTRUCT_HEADER2, SGX_SIGSTRUCT_HEADER2_SIZE);

    time_t systime = time(NULL);
    struct tm *time = localtime(&systime);
    sigStruct->header.vendor = 0;    // non-Intel
    sigStruct->header.date = (time->tm_year + 1900) * 0x10000 + (time->tm_mon + 1) * 0x100 + (time->tm_mday);

    //
    // Write RSA part
    //
    const BIGNUM *e = NULL; // public exponent
    const BIGNUM *n = NULL; // public exponent
    assert (privKey);
#if OPENSSL_VERSION_NUMBER >= 0x10100000 && !defined(LIBRESSL_VERSION_NUMBER)
    RSA_get0_key(privKey, &n, &e, NULL);
#else
    e = privKey->e;
    n = privKey->n;
#endif
    int pub_exp_size = BN_num_bytes(e);
    int modulus_size = BN_num_bytes(n);

    if (pub_exp_size != SGX_EXPONENT_SIZE || modulus_size != SGX_MODULUS_SIZE)
    {
        fprintf(stderr, "ERROR: modulus size: %d(bytes)(%d is expected); public exponent size: %d(bytes)(%d is expected)\n", 
                modulus_size, SGX_MODULUS_SIZE, pub_exp_size, SGX_EXPONENT_SIZE);
        return false;
    }

    // Write exponent
    if (BN_bn2bin(e, (uint8_t*)&sigStruct->exponent) != 1)
    {
        fprintf(stderr, "ERROR: cannot write exponent in sigstruct\n");
        return false;
    }
    assert(sigStruct->exponent == 3);

    // Write modulus
    uint8_t modulus[SGX_MODULUS_SIZE] = {0}; // Big-endian
    if (BN_bn2bin(n, modulus) != SGX_MODULUS_SIZE)
    {
        fprintf(stderr, "ERROR: cannot write modulus in sigstruct\n");
        return false;
    }
    ReverseEndian(modulus, (uint8_t*)sigStruct->modulus, SGX_MODULUS_SIZE);

    //
    // Write SigStruct body
    //
    sigStruct->body.attributes |= SGX_ATTR_MODE64BIT;
    sigStruct->body.xfrm |= SGX_XFRM_LEGACY;
    sigStruct->body.attributemask_flags = ~(SGX_ATTR_DEBUG | SGX_ATTR_KSS);
    sigStruct->body.attributemask_xfrm = UINT64_MAX;
    sigStruct->body.miscselect = 0;
    sigStruct->body.miscmask = UINT32_MAX;

    // fill the enclave hash
    memcpy(sigStruct->body.mrenclave, enclaveHash, SHA256_DIGEST_LENGTH);

    sigStruct->body.isvprodid = 0; // ENCLAVE_UNDONE: make configurable
    sigStruct->body.isvsvn = 0;    // ENCLAVE_UNDONE: make configurable

    //
    // Write SigStruct signature
    //
    uint8_t hash[SHA256_DIGEST_LENGTH];
    HashSigStruct(sigStruct, hash);

    uint8_t signature[SGX_SIGNATURE_SIZE] = {0}; // Big-endian
    size_t siglen = 0;
    bool success = RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature, (unsigned int*)&siglen, const_cast<RSA*>(privKey));
    if (!success)
    {
        fprintf(stderr, "ERROR: Failed to write sigstruct signature\n");
        return false;
    }
    ReverseEndian(signature, (uint8_t*)sigStruct->signature, SGX_SIGNATURE_SIZE);

    //
    // Write Q1, Q2
    //
    BIGNUM *ptmp1 = NULL, *ptmp2 = NULL, *pQ1 = NULL, *pQ2 = NULL, *pM = NULL, *pS = NULL; 
    uint8_t *q1 = NULL, *q2 = NULL;
    BN_CTX *ctx = NULL;
    success = false;

    // do {} while (0) only does once
    do {
        if ((ptmp1 = BN_new()) == NULL)
            break;
        if ((ptmp2 = BN_new()) == NULL)
            break;
        if ((pQ1 = BN_new()) == NULL)
            break;
        if ((pQ2 = BN_new()) == NULL)
            break;
        if ((pM = BN_new()) == NULL)
            break;
        if ((pS = BN_new()) == NULL)
            break;

        if (BN_bin2bn(modulus, SGX_MODULUS_SIZE, pM) == NULL)
            break;
        if (BN_bin2bn(signature, SGX_SIGNATURE_SIZE, pS) == NULL)
            break;
        if ((ctx = BN_CTX_new()) == NULL)
            break;

        // Q1 = floor(signature ^ 2 / modulus)
        // Q2 = floor((signature ^ 3 - Q1 * signature * modulus) / modulus)
        if (BN_mul(ptmp1, pS, pS, ctx) != 1)    // ptmp1 = pS * pS
            break;
        if (BN_div(pQ1, ptmp2, ptmp1, pM, ctx) != 1)  // pQ1 = ptmp1 / pM, ptmp2 = ptmp1 % pM
            break;
        if (BN_mul(ptmp1, pS, ptmp2, ctx) != 1) // ptmp1 = pS * ptmp2
            break;
        if (BN_div(pQ2, ptmp2, ptmp1, pM, ctx) != 1) // pQ2 = ptmp1 / pM, ptmp2 = ptmp1 % pM
            break;

        int q1_len = BN_num_bytes(pQ1);
        int q2_len = BN_num_bytes(pQ2);
        if ((q1 = (uint8_t*)malloc(q1_len)) == NULL)
            break;
        if ((q2 = (uint8_t*)malloc(q2_len)) == NULL)
            break;
        if (q1_len != BN_bn2bin(pQ1, (uint8_t*)q1))
            break;
        if (q2_len != BN_bn2bin(pQ2, (uint8_t*)q2))
            break;
        int size_q1 = (q1_len < SGX_MODULUS_SIZE) ? q1_len : SGX_MODULUS_SIZE;
        int size_q2 = (q2_len < SGX_MODULUS_SIZE) ? q2_len : SGX_MODULUS_SIZE;
        for (int i = 0; i < size_q1; i++)
            sigStruct->q1[i] = q1[size_q1 - i - 1];
        for (int i = 0; i < size_q2; i++)
            sigStruct->q2[i] = q2[size_q2 - i - 1];

        success = true;
    } while (0);


    if (q1) free(q1);
    if (q2) free(q2);
    if (ptmp1) BN_clear_free(ptmp1);
    if (ptmp2) BN_clear_free(ptmp2);
    if (pQ1) BN_clear_free(pQ1);
    if (pQ2) BN_clear_free(pQ2);
    if (pS) BN_clear_free(pS);
    if (pM) BN_clear_free(pM);
    if (ctx) BN_CTX_free(ctx);

    return success;
}

//------------------------------------------------------------------------------
// Function: MakeSigStructWithKeyInFile
//
// Description:
//   Given an enclave measurement, construct an SGX signature using a key in the given file.
//
// Returns:
//   enclave hash error code (=0 for no error, >0 otherwise)
//
int
MakeSigStructWithKeyInFile(
    _In_ uint8_t*               enclaveHash,
    _In_ const char*            privateKeyFile,
    _Out_ struct sgx_sigstruct* sigStruct)
{
    int error_code = ENCLAVE_HASH_NO_ERROR;
    FILE* prvkey_file = fopen(privateKeyFile, "rb");
    RSA *rsa_prv = NULL;

    if (prvkey_file == NULL)
    {
        fprintf(stderr, "ERROR: Unable to open private.pem\n");
        error_code = ENCLAVE_HASH_SIGSTRUCT_FAILURE;
        goto Exit;
    }

    rsa_prv = PEM_read_RSAPrivateKey(prvkey_file, &rsa_prv, NULL, NULL);
    if (!rsa_prv)
    {
        fprintf(stderr, "ERROR: Unable to extract private key\n");
        error_code = ENCLAVE_HASH_SIGSTRUCT_FAILURE;
    }

    if (error_code == ENCLAVE_HASH_NO_ERROR)
    {
        if (!MakeSigStruct(enclaveHash, rsa_prv, sigStruct))
        {
            fprintf(stderr, "ERROR: Unable to make sigstruct\n");
            error_code = ENCLAVE_HASH_SIGSTRUCT_FAILURE;
        }
    }

    RSA_free(rsa_prv);

Exit:
    fclose(prvkey_file);

    return error_code;
}

