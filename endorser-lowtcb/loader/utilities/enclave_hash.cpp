//
// Create measurements for user-level enclave operations
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <openssl/sha.h>

#include "def.h"
#include "sgx_arch.h"
#include "sgx_user.h"

static constexpr size_t SGX_SHA_BLOCKSIZE = 64;

// Magic values defined by SGX ISA for measurements performed by ECREATE/EADD/EEXTEND instructions
static constexpr const uint8_t ECREATE_MAGIC[] = {0x45, 0x43, 0x52, 0x45, 0x41, 0x54, 0x45, 0x00};
static constexpr const uint8_t EADD_MAGIC[] = {0x45, 0x41, 0x44, 0x44, 0x00, 0x00, 0x00, 0x00};
static constexpr const uint8_t EEXTEND_MAGIC[] = {0x45, 0x45, 0x58, 0x54, 0x45, 0x4E, 0x44, 0x00};

#pragma pack(4)

// Data hashed when performing ECREATE
struct ECreateData
{
    uint8_t Magic[8];
    uint32_t SsaFrameSize;
    uint64_t SecsSize;
    uint8_t Zero[44];
};

// Data hashed when performing EADD
struct EAddData
{
    uint8_t Magic[8];
    uint64_t PageOffsetInEnclave;
    uint64_t SecInfoFlags;
    uint8_t Zero[40];
};

// Data hashed when performing EEXTEND
struct EExtendData
{
    uint8_t Magic[8];
    uint64_t EnclaveOffset;
    uint8_t Zero[48];
};

#pragma pack()


//---------------------------------------------------------
// Function: MeasureECreate
//
// Description:
//   Initialize a SHA context, and update equivalently to the ECREATE instruction
//
// Params:
//   ssaFrameSize: SSA frame size for this enclave
//   enclaveSize:  Size of this enclave in bytes
//   shaContext:   SHA context for hashing
void
MeasureECreate(
    _In_ uint32_t        ssaFrameSize,
    _In_ uint64_t        enclaveSize,
    _Out_ SHA256_CTX*    shaContext)
{
    SHA256_Init(shaContext);
    ECreateData updateField = {0};

    assert(sizeof(ECREATE_MAGIC) == sizeof(updateField.Magic));
    memcpy(updateField.Magic, ECREATE_MAGIC, sizeof(ECREATE_MAGIC));
    updateField.SsaFrameSize = ssaFrameSize;
    updateField.SecsSize = enclaveSize;

    assert(sizeof(updateField) == SGX_SHA_BLOCKSIZE);
    SHA256_Update(shaContext, reinterpret_cast<uint8_t*>(&updateField), SGX_SHA_BLOCKSIZE);
}

//---------------------------------------------------------
// Function: MeasureEAdd
//
// Description:
//   Update a SHA context equivalently to the EADD instruction
//   Used by MeasurePage(). Shouldn't be called directly by user
//
// Params:
//   flags:               SecInfo flags of the added page
//   pageOffsetInEnclave: Byte offset of the page within the enclave region
//   shaContext:          SHA context for hashing
void
MeasureEAdd(
    _In_ uint64_t        flags,
    _In_ size_t          pageOffsetInEnclave,
    _In_Out_ SHA256_CTX* shaContext)
{
    EAddData updateField = {0};

    assert(sizeof(EADD_MAGIC) == sizeof(updateField.Magic));
    memcpy(updateField.Magic, EADD_MAGIC, sizeof(EADD_MAGIC));
    updateField.PageOffsetInEnclave = pageOffsetInEnclave;
    updateField.SecInfoFlags = flags;
    //if ((flags & SGX_SECINFO_TCS) != 0)
    //{
        //// Ignore permissions for a TCS
        //updateField.SecInfoFlags &= ~SGX_TCS_DBGOPTIN;
    //}

    assert(sizeof(updateField) == SGX_SHA_BLOCKSIZE);
    SHA256_Update(shaContext, reinterpret_cast<uint8_t*>(&updateField), SGX_SHA_BLOCKSIZE);
}

//--------------------------------------------------------------------
// Function: MeasureEExtend
//
// Description:
//   Update a SHA context equivalently to the EEXTEND instruction
//   Used by MeasurePage(). Shouldn't be called directly by user
//
// Params:
//   offsetInEnclave: Byte offset of the measured region within the enclave region
//   data:            Data to be measured. If NULL, zeros are measured
//   shaContext:      SHA context for hashing
void
MeasureEExtend(
    _In_ size_t          offsetInEnclave,
    _In_Opt_ const void* data,
    _In_Out_ SHA256_CTX* shaContext)
{
    EExtendData updateField = {0};

    assert(sizeof(EEXTEND_MAGIC) == sizeof(updateField.Magic));
    memcpy(updateField.Magic, EEXTEND_MAGIC, sizeof(EEXTEND_MAGIC));
    updateField.EnclaveOffset = offsetInEnclave;

    assert(sizeof(updateField) == SGX_SHA_BLOCKSIZE);
    SHA256_Update(shaContext, reinterpret_cast<uint8_t*>(&updateField), SGX_SHA_BLOCKSIZE);

    static const uint8_t zeros[SGX_SHA_BLOCKSIZE] = {0};
    for(int i = 0; i < 4; i++)
    {
        SHA256_Update(shaContext,
                data? static_cast<const uint8_t*>(data) + i * SGX_SHA_BLOCKSIZE : zeros,
                SGX_SHA_BLOCKSIZE);
    }
}

//--------------------------------------------------------------------
// Function: MeasureEInit
//
// Description:
//   Finialize the SHA context and output the resulting enclave hash
//
// Params:
//   hash:       Output buffer
//   shaContext: SHA context for hashing
void
MeasureEInit(
    _In_Out_ SHA256_CTX* shaContext,
    _Out_ uint8_t*       hash)
{
    SHA256_Final(hash, shaContext);
}

//--------------------------------------------------------------------
// Function: MeasurePage
//
// Description:
//   Measure (hash) a single enclave page
//
// Params:
//   shaContext:    SHA Context for hashing
//   enclaveOffset: Page offset within the enclave
//   secInfo:       SGX security flags
//   data:          Page content to be measured. If NULL, zeros are measured
void
MeasurePage(
    _In_Out_ SHA256_CTX* shaContext,
    _In_ size_t          enclaveOffset,
    _In_ uint64_t        secInfo,
    _In_Opt_ void*       data)
{
    // Track page add
    MeasureEAdd(secInfo, enclaveOffset, shaContext);

    // Measure page contents
    for (size_t offset = 0; offset < SGX_PAGE_SIZE; offset += SGX_EEXTEND_SIZE)
    {
        MeasureEExtend(enclaveOffset + offset,
                data ? (reinterpret_cast<char*>(data) + offset) : NULL,
                shaContext);
    }
}

//--------------------------------------------------------------------
// Function: MeasurePages
//
// Description:
//   Measure (hash) a series of contiguous enclave pages,
//   from low to high addresses
//
// Params:
//   shaContext:    SHA context for hashing
//   enclaveOffset: Page offset within the enclave
//   secInfo:       SGX security flags
//   byteLen:       Page-aligned length of region to be measured
//   data:          Page content to be measured. If NULL, zeros are measured
void
MeasurePages(
    _In_Out_ SHA256_CTX* shaContext,
    _In_ size_t          enclaveOffset,
    _In_ uint64_t        secInfo,
    _In_ size_t          byteLen,
    _In_Opt_ void*       data)
{
    assert(byteLen % SGX_PAGE_SIZE == 0);

    for (size_t offset = 0; offset < byteLen; offset += SGX_PAGE_SIZE)
    {
        MeasurePage(shaContext,
                enclaveOffset + offset,
                secInfo,
                (data == NULL) ? data
                : reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(data) + offset));

    }
}
