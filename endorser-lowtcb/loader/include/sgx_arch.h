/*
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2016-2017 Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * Contact Information:
 * Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>
 * Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
 *
 * BSD LICENSE
 *
 * Copyright(c) 2016-2017 Intel Corporation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Authors:
 *
 * Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>
 */

#include <linux/types.h>
#include <inttypes.h>
#ifndef _ASM_X86_SGX_ARCH_H
#define _ASM_X86_SGX_ARCH_H

#define SGX_PAGE_SIZE     4096
#define SGX_EEXTEND_SIZE  256 // bytes measured in a single EEXTEND call

#define SGX_SSA_GPRS_SIZE		182
#define SGX_SSA_MISC_EXINFO_SIZE	16

enum sgx_misc {
	SGX_MISC_EXINFO		= 0x01,
};

#define SGX_EXIT_TYPE_HARDWARE 3 // Hardware exceptions
#define SGX_EXIT_TYPE_SOFTWARE 6 // Software exceptions

typedef union sgx_exitinfo {
    struct {
        uint32_t vector     :  8; // Exception number of exceptions reported inside enclave
        uint32_t exittype   :  3; // SGX_EXIT_TYPE_HARDWARE or SGX_EXIT_TYPE_SOFTWARE
        uint32_t reserved   : 20; // Reserved as zero
        uint32_t valid      :  1; // 0: Unsupported exceptions; 1: Supported exceptions
    };
    uint32_t Raw;
} sgx_exitinfo;

typedef struct sgx_ssa_gpr {

    // (0) RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI
    //
    uint64_t Rax;
    uint64_t Rcx;
    uint64_t Rdx;
    uint64_t Rbx;
    uint64_t Rsp;
    uint64_t Rbp;
    uint64_t Rsi;
    uint64_t Rdi;

    // (64) R8 - R15
    //
    uint64_t R8;
    uint64_t R9;
    uint64_t R10;
    uint64_t R11;
    uint64_t R12;
    uint64_t R13;
    uint64_t R14;
    uint64_t R15;

    // (128) Flags register
    //
    uint64_t Rflags;

    // (136) Instruction pointer
    //
    uint64_t Rip;

    // (144) Non-enclave (outside) stack pointer. Saved by EENTER, restored on AEX
    //
    uint64_t URsp;

    // (152) Non-enclave (outside) frame pointer. Saved by EENTER, restored on AEX
    //
    uint64_t URbp;

    // (160) Contains information about exceptions that causes AEXs, which might be
    // needed by enclave software
    sgx_exitinfo ExitInfo;

    // (164) Reserved
    //
    uint32_t Reserved;

    // (168) FS Base
    uint64_t FsBase;

    // (176) GS Base
    //
    uint64_t GsBase;
} sgx_ssa_gpr;

typedef struct sgx_ssa_misc_exinfo {
    // (0) Linear address that caused a page fault (#PF only; cleared on #GP)
    //
    uint64_t FaultAddress;

    // (8) Exception error code (either #GP or #PF)
    //
    uint32_t ErrorCode;

    // (12) Reserved;
    //
    uint32_t Reserved;
} sgx_ssa_misc_exinfo;

#define SGX_MISC_RESERVED_MASK 0xFFFFFFFFFFFFFFFEL

enum sgx_attribute {
    SGX_ATTR_INITED         = 0x01, // Initialized
	SGX_ATTR_DEBUG		    = 0x02, // Debug mode
	SGX_ATTR_MODE64BIT	    = 0x04, // 64 bit
	SGX_ATTR_PROVISIONKEY	= 0x10, // Access to the provision key
	SGX_ATTR_EINITTOKENKEY	= 0x20, // Access to the EINITTOKEN key
    SGX_ATTR_KSS            = 0x80, // Key Separation and Sharing extension
};

#define SGX_ATTR_RESERVED_MASK 0xFFFFFFFFFFFFFF49L

#define SGX_SECS_RESERVED1_SIZE 24
#define SGX_SECS_RESERVED2_SIZE 32
#define SGX_SECS_RESERVED3_SIZE 32
#define SGX_SECS_RESERVED4_SIZE 3834

typedef struct sgx_secs {
	uint64_t size;
	uint64_t base;
	uint32_t ssaframesize;
	uint32_t miscselect;
	uint8_t reserved1[SGX_SECS_RESERVED1_SIZE];
	uint64_t attributes;
	uint64_t xfrm;
	uint32_t mrenclave[8];
	uint8_t reserved2[SGX_SECS_RESERVED2_SIZE];
	uint32_t mrsigner[8];
	uint8_t	reserved3[SGX_SECS_RESERVED3_SIZE];
	uint32_t configid[16];
	uint16_t isvvprodid;
	uint16_t isvsvn;
	uint16_t configsvn;
	uint8_t reserved4[SGX_SECS_RESERVED4_SIZE];
} sgx_secs;

enum sgx_tcs_flags {
	SGX_TCS_DBGOPTIN	= 0x01, /* cleared on EADD */
};

#define SGX_TCS_RESERVED_MASK 0xFFFFFFFFFFFFFFFEL

typedef struct sgx_tcs {
	uint64_t state;
	uint64_t flags;
	uint64_t ossa;
	uint32_t cssa;
	uint32_t nssa;
	uint64_t oentry;
	uint64_t aep;
	uint64_t ofsbase;
	uint64_t ogsbase;
	uint32_t fslimit;
	uint32_t gslimit;
	uint64_t reserved[503];
} sgx_tcs;

typedef struct sgx_pageinfo {
	uint64_t linaddr;
	uint64_t srcpge;
	union {
		uint64_t secinfo;
		uint64_t pcmd;
	};
	uint64_t secs;
} __attribute__((aligned(32))) sgx_pageinfo;

#define SGX_SECINFO_PERMISSION_MASK	0x0000000000000007L
#define SGX_SECINFO_PAGE_TYPE_MASK	0x000000000000FF00L
#define SGX_SECINFO_RESERVED_MASK	0xFFFFFFFFFFFF00F8L

enum sgx_page_type {
	SGX_PAGE_TYPE_SECS	= 0x00,
	SGX_PAGE_TYPE_TCS	= 0x01,
	SGX_PAGE_TYPE_REG	= 0x02,
	SGX_PAGE_TYPE_VA	= 0x03,
	SGX_PAGE_TYPE_TRIM	= 0x04,
};

enum sgx_secinfo_flags {
	SGX_SECINFO_R		= 0x01,
	SGX_SECINFO_W		= 0x02,
	SGX_SECINFO_X		= 0x04,
	SGX_SECINFO_PENDING	= 0x08,
	SGX_SECINFO_MODIFIED	= 0x010,
	SGX_SECINFO_TCS		= (SGX_PAGE_TYPE_TCS << 8),
	SGX_SECINFO_REG		= (SGX_PAGE_TYPE_REG << 8),
	SGX_SECINFO_TRIM	= (SGX_PAGE_TYPE_TRIM << 8),
};

enum sgx_xfrm_type {
    SGX_XFRM_LEGACY = 0x03,
    SGX_XFRM_AVX    = 0x06,
    SGX_XFRM_AVX512 = 0xE6,
    SGX_XFRM_MPX    = 0x18,
};

typedef struct sgx_secinfo {
	uint64_t flags;
	uint64_t reserved[7];
} __attribute__((aligned(64))) sgx_secinfo;

typedef struct sgx_rdinfo {
	uint64_t status;
	uint64_t flags;
	uint64_t context;
} sgx_rdinfo;

typedef struct sgx_pcmd {
	struct sgx_secinfo secinfo;
	uint64_t enclave_id;
	uint8_t reserved[40];
	uint8_t mac[16];
} sgx_pcmd;

#define SGX_MODULUS_SIZE    384 // RSA modulus size in bytes
#define SGX_EXPONENT_SIZE   1   // RSA public key exponent (3) size in bytes
#define SGX_SIGNATURE_SIZE  384 

//--------------------------------------------------------------
// sgx_struct: signature structure passed at enclave init time
//

// sgx_sigstruct.header.header1: 06000000E10000000000010000000000H
//
#define SGX_SIGSTRUCT_HEADER1 "\006\000\000\000\341\000\000\000\000\000\001\000\000\000\000\000"
#define SGX_SIGSTRUCT_HEADER1_SIZE (sizeof(SGX_SIGSTRUCT_HEADER1) - 1)

// sgx_sigstruct.header.header2: 01010000600000006000000001000000H
//
#define SGX_SIGSTRUCT_HEADER2 "\001\001\000\000\140\000\000\000\140\000\000\000\001\000\000\000"
#define SGX_SIGSTRUCT_HEADER2_SIZE (sizeof(SGX_SIGSTRUCT_HEADER2) - 1)

typedef struct sgx_sigstruct_header {   // 128 bytes
	uint64_t header1[2];        // (0) must be SGX_SIGSTRUCT_HEADER1
	uint32_t vendor;            // (16) Intel=0x8086, ISV=0x0000
	uint32_t date;              // (20) build date as yyyymmdd
	uint64_t header2[2];        // (24) must be SGX_SIGSTRUCT_HEADER2
	uint32_t swdefined;         // (40) For Launch Encave != 0, Others = 0
	uint8_t reserved1[84];      // (44) must be 0
} sgx_sigstruct_header;

typedef struct sgx_sigstruct_body {         // 128 bytes
	uint32_t miscselect;
	uint32_t miscmask;
	uint8_t reserved2[20];
	uint64_t attributes;
	uint64_t xfrm;
    uint64_t attributemask_flags;
    uint64_t attributemask_xfrm;
	uint8_t mrenclave[32];
	uint8_t reserved3[32];
	uint16_t isvprodid;
	uint16_t isvsvn;
} __attribute__((__packed__)) sgx_sigstruct_body;

typedef struct sgx_sigstruct {
	struct sgx_sigstruct_header header;
	uint8_t modulus[SGX_MODULUS_SIZE];  // (128) Module public key (keylength=3072 bites)
	uint32_t exponent;                  // (512) RSA Exponent = 3
	uint8_t signature[SGX_MODULUS_SIZE];// (516) Signature over Header and Body
	struct sgx_sigstruct_body body;     // (900)
	uint8_t reserved4[12];              // (1028) Must be 0
	uint8_t q1[SGX_MODULUS_SIZE];       // (1040) Q1 value for RSA Signature Verification
	uint8_t q2[SGX_MODULUS_SIZE];       // (1424) Q2 value for RSA Signature Verification
} sgx_sigstruct;

typedef struct sgx_sigstruct_payload {
	struct sgx_sigstruct_header header;
	struct sgx_sigstruct_body body;
} sgx_sigstruct_payload;

typedef struct sgx_einittoken_payload {
	uint32_t valid;
	uint32_t reserved1[11];
	uint64_t attributes;
	uint64_t xfrm;
	uint8_t mrenclave[32];
	uint8_t reserved2[32];
	uint8_t mrsigner[32];
	uint8_t reserved3[32];
} __attribute__((__packed__)) sgx_einittoken_payload;

typedef struct sgx_einittoken {
	struct sgx_einittoken_payload payload;
	uint8_t cpusvnle[16];
	uint16_t isvprodidle;
	uint16_t isvsvnle;
	uint8_t reserved2[24];
	uint32_t maskedmiscselectle;
	uint64_t maskedattributesle;
	uint64_t maskedxfrmle;
	uint8_t keyid[32];
	uint8_t mac[16];
} __attribute__((__packed__)) sgx_einittoken;

typedef struct sgx_report {
	uint8_t cpusvn[16];
	uint32_t miscselect;
	uint8_t reserved1[28];
	uint64_t attributes;
	uint64_t xfrm;
	uint8_t mrenclave[32];
	uint8_t reserved2[32];
	uint8_t mrsigner[32];
	uint8_t reserved3[96];
	uint16_t isvprodid;
	uint16_t isvsvn;
	uint8_t reserved4[60];
	uint8_t reportdata[64];
	uint8_t keyid[32];
	uint8_t mac[16];
} sgx_report;

typedef struct sgx_targetinfo {
	uint8_t mrenclave[32];
	uint64_t attributes;
	uint64_t xfrm;
	uint8_t reserved1[4];
	uint32_t miscselect;
	uint8_t reserved2[456];
} sgx_targetinfo;

typedef struct sgx_keyrequest {
	uint16_t keyname;
	uint16_t keypolicy;
	uint16_t isvsvn;
	uint16_t reserved1;
	uint8_t cpusvn[16];
	uint64_t attributemask;
	uint64_t xfrmmask;
	uint8_t keyid[32];
	uint32_t miscmask;
	uint8_t reserved2[436];
} sgx_keyrequest;


// Pagoda-specific struct
typedef struct sgx_tcs_debug {
    // (0) enclave execution state (0=available, 1=unavailable)
    //
    uint64_t State;

    // (8) thread's execution flags
    //
    uint64_t Flags;

    // (16) offset to the base of the State Save Area (SSA) stack
    //
    uint64_t OSSA;

    // (24) Current slot of an SSA frame
    //
    uint32_t CSSA;

    // (28) Number of available slots for SSA frames
    //
    uint32_t NSSA;

    // (32) entry point where control is transferred upon EENTER
    //
    uint64_t OEntry;

    // (40) Value of asynchronous exit pointer saved at EENTER time
    //
    uint64_t AEP;

    // (48) Added to enclave base address to get the FS segment address
    //
    uint64_t OFsBase;

    // (56) Added to enclave base address to get the GS segment address
    //
    uint64_t OGsBase;

    // (64) Size to become the new FS limit in 32-bit mode
    //
    uint32_t FsLimit;

    // (68) Size to become the new GS limit in 32-bit mode
    //
    uint32_t GsLimit;
} sgx_tcs_debug;
#endif /* _ASM_X86_SGX_ARCH_H */
