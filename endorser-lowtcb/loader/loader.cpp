#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <elf.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <vector>
#include <map>

#include "SgxSignTool.h"
#include "enclave.h"

using namespace std;

uint8_t* read_endorser(const char *endorser_elf_fname,
    map<uint64_t, Elf64_Phdr>& endorser_segments,
    uint64_t &endorser_entry_offset,
    uint64_t &endorser_size
    )
{
    // read the endorser elf file
    if (access(endorser_elf_fname, R_OK | X_OK) != 0) {
        fprintf(stderr, "no RX permission on the endorser binary %s", endorser_elf_fname);
        return NULL;
    }

    ifstream instream(endorser_elf_fname);
    string endorser_elf = string((istreambuf_iterator<char>(instream)), istreambuf_iterator<char>());
    Elf64_Ehdr *elf_header = (Elf64_Ehdr *)endorser_elf.data();
    if (memcmp(elf_header->e_ident, ELFMAG, SELFMAG) != 0 ||
        elf_header->e_ident[EI_CLASS] != ELFCLASS64 ||
        elf_header->e_ident[EI_DATA] != ELFDATA2LSB ||
        elf_header->e_type != ET_DYN ||
        elf_header->e_version != EV_CURRENT ||
        elf_header->e_machine != EM_X86_64) {
        fprintf(stderr, "ERROR: incompatible ELF format for %s\n", endorser_elf_fname);
        return NULL;
    }

    Elf64_Addr min_vaddr = UINTPTR_MAX;
    Elf64_Addr max_vaddr = 0;
    Elf64_Phdr *program_headers = (Elf64_Phdr *)((char *)elf_header + elf_header->e_phoff);
    for (int i = 0; i < elf_header->e_phnum; i++) {
        if (program_headers[i].p_type != PT_LOAD || program_headers[i].p_memsz == 0)
            continue;

        if (program_headers[i].p_vaddr < min_vaddr)
            min_vaddr = program_headers[i].p_vaddr;

        if (program_headers[i].p_vaddr + program_headers[i].p_memsz > max_vaddr)
            max_vaddr = program_headers[i].p_vaddr + program_headers[i].p_memsz;
    }
    if (max_vaddr <= min_vaddr) {
        fprintf(stderr, "failed to find loadable segments in %s\n", endorser_elf_fname);
        return NULL;
    }
    endorser_size = ROUND_UP(max_vaddr, SGX_PAGE_SIZE) - ROUND_DOWN(min_vaddr, SGX_PAGE_SIZE);

    uint8_t *endorser_memory = (uint8_t*)aligned_alloc(SGX_PAGE_SIZE, endorser_size);
    if (endorser_memory == NULL) {
        fprintf(stderr, "failed to allocate memory for endorser\n");
        return NULL;
    }
    memset(endorser_memory, 0, endorser_size);
    for (int i = 0; i < elf_header->e_phnum; i++) {
        if (program_headers[i].p_type != PT_LOAD || program_headers[i].p_memsz == 0)
            continue;
        memcpy(&endorser_memory[program_headers[i].p_vaddr - min_vaddr], (char *)elf_header + program_headers[i].p_offset, program_headers[i].p_filesz);
        endorser_segments[program_headers[i].p_vaddr - min_vaddr] = program_headers[i];
    }

    endorser_entry_offset = elf_header->e_entry - min_vaddr;

    return endorser_memory;
}

static uint64_t next_pow2(uint64_t x)
{
    uint64_t p = 1;
    while (p < x)
        p = p << 1;
    return p;
}

static int enclave_load_data(
    int enclave_device,
    uint64_t target_offset,
    const void* source_address,
    size_t target_size,
    uint32_t data_properties
    )
{
    struct sgx_secinfo sec_info;
    memset(&sec_info, 0, sizeof(struct sgx_secinfo));
    sec_info.flags = data_properties;

    if (!(sec_info.flags & SGX_SECINFO_TCS))
        sec_info.flags |= SGX_SECINFO_REG;
    else
        sec_info.flags &= ~SGX_SECINFO_PERMISSION_MASK;

    if (sec_info.flags & SGX_SECINFO_TRIM)
        sec_info.flags ^= SGX_SECINFO_TRIM;

    struct sgx_enclave_add_pages enclave_add_pages_arg;
    memset(&enclave_add_pages_arg, 0, sizeof(sgx_enclave_add_pages));
    enclave_add_pages_arg.src = POINTER_TO_U64(source_address);
    enclave_add_pages_arg.offset = target_offset;
    enclave_add_pages_arg.length = target_size;
    enclave_add_pages_arg.secinfo = POINTER_TO_U64(&sec_info);
    if (!(data_properties & SGX_SECINFO_TRIM))
        enclave_add_pages_arg.flags = SGX_PAGE_MEASURE;
    enclave_add_pages_arg.count = 0;
    int ret = ioctl(enclave_device, SGX_IOC_ENCLAVE_ADD_PAGES, &enclave_add_pages_arg);
    if (ret != 0) {
        fprintf(stderr, "failed to add pages into the enclave\n");
        return ret;
    }

    int prot = sec_info.flags & SGX_SECINFO_PERMISSION_MASK;
    if (sec_info.flags & SGX_SECINFO_TCS)
        prot = SGX_SECINFO_R | SGX_SECINFO_W;

    void *target = mmap((void *)(ENCLAVE_BASE + target_offset), target_size, prot, MAP_SHARED|MAP_FIXED, enclave_device, 0);
    if (POINTER_TO_U64(target) != ENCLAVE_BASE + target_offset) {
        fprintf(stderr, "failed to map memory to the expected address target=%llx target_offset=%lx target_size=%lx prot=%x (errno=%d)\n",
            POINTER_TO_U64(target), target_offset, target_size, prot, errno);
        return errno;
    }

    return 0;
}

int launch_endorser(const char *endorser_elf_fname, const char *private_key_file)
{
    // open the enclave device
    const char *enclave_device_name = "/dev/sgx/enclave";
    int enclave_device = open(enclave_device_name, O_RDWR);
    if (enclave_device == -1) {
        fprintf(stderr, "failed to open the enclave device %s (errno=%d)\n", enclave_device_name, errno);
        return -1;
    }

    // read the endorser
    map<uint64_t, Elf64_Phdr> endorser_segments;
    uint64_t endorser_entry_offset;
    uint64_t endorser_size;
    uint8_t *endorser_memory = read_endorser(endorser_elf_fname, endorser_segments, endorser_entry_offset, endorser_size);
    if (endorser_memory == NULL) {
        fprintf(stderr, "failed to read the endorser %s\n", endorser_elf_fname);
        return -1;
    }

    if (endorser_size + SGX_PAGE_SIZE * 2 > ENCLAVE_SIZE) {
        fprintf(stderr, "the required enclave memory %lu is more than the supported size %lu\n",
                        endorser_size + SGX_PAGE_SIZE * 2,
                        ENCLAVE_SIZE);
        return -1;
    }

    // initialize SECS
    struct sgx_secs secs = { 0 };
    secs.base = ENCLAVE_BASE;
    secs.size = ENCLAVE_SIZE;
    secs.ssaframesize = 1;
    secs.miscselect = 0;
    secs.attributes = SGX_ATTR_DEBUG | SGX_ATTR_MODE64BIT;
    secs.xfrm = SGX_XFRM_LEGACY;

    // initialize sha256 context
    SHA256_CTX sha256_context;
    MeasureECreate(secs.ssaframesize, secs.size, &sha256_context);

    // create enclave with SECS
    sgx_enclave_create enclave_create_arg;
    enclave_create_arg.src = POINTER_TO_U64(&secs);
    int ret = ioctl(enclave_device, SGX_IOC_ENCLAVE_CREATE, &enclave_create_arg);
    if (ret != 0) {
        fprintf(stderr, "failed to create the enclave\n");
        return -1;
    }

    uint8_t *tmp_page = (uint8_t *)aligned_alloc(SGX_PAGE_SIZE, SGX_PAGE_SIZE);
    if (tmp_page == NULL) {
        fprintf(stderr, "failed to allocate a page\n");
        return -1;
    }

    // initialize TCS
    memset(tmp_page, 0, SGX_PAGE_SIZE);
    struct sgx_tcs *tcs = (struct sgx_tcs *)tmp_page;
    tcs->oentry = SGX_PAGE_SIZE * 2 + endorser_entry_offset;
    tcs->nssa = 1;
    tcs->ossa = SGX_PAGE_SIZE; // SSA page follows the TCS page
    tcs->ofsbase = 0;
    tcs->ogsbase = 0;
    tcs->fslimit = (uint32_t)-1;
    tcs->gslimit = (uint32_t)-1;

    // load TCS
    ret = enclave_load_data(enclave_device,
                            0,
                            tcs,
                            SGX_PAGE_SIZE,
                            SGX_SECINFO_TCS);
    if (ret != 0) {
        fprintf(stderr, "failed to load TCS (error=%d)\n", ret);
        return ret;
    }
    MeasurePage(&sha256_context, 0, SGX_SECINFO_TCS, tcs);

    // load SSA
    memset(tmp_page, 0, SGX_PAGE_SIZE);
    ret = enclave_load_data(enclave_device,
                            SGX_PAGE_SIZE,
                            tmp_page,
                            SGX_PAGE_SIZE,
                            SGX_SECINFO_R | SGX_SECINFO_W | SGX_SECINFO_REG);
    if (ret != 0) {
        fprintf(stderr, "failed to load SSA (error=%d)\n", ret);
        return ret;
    }
    MeasurePage(&sha256_context, SGX_PAGE_SIZE,
                SGX_SECINFO_R | SGX_SECINFO_W | SGX_SECINFO_REG,
                tmp_page);

    // load endorser
    for (auto it = endorser_segments.begin(); it != endorser_segments.end(); it++) {
        uint32_t properties = SGX_SECINFO_REG;
        if (it->second.p_flags & PF_R)
            properties |= SGX_SECINFO_R;
        if (it->second.p_flags & PF_W)
            properties |= SGX_SECINFO_W;
        if (it->second.p_flags & PF_X)
            properties |= SGX_SECINFO_X;

        uint64_t segment_offset = ROUND_DOWN(it->first, SGX_PAGE_SIZE);
        uint64_t segment_size = ROUND_UP(it->first + it->second.p_memsz, SGX_PAGE_SIZE) - segment_offset;
        ret = enclave_load_data(enclave_device,
                                SGX_PAGE_SIZE * 2 + segment_offset,
                                &endorser_memory[segment_offset],
                                segment_size,
                                properties);
        if (ret != 0) {
            fprintf(stderr, "failed to load the endorser into the enclave (error=%d)\n", ret);
            return ret;
        }
        MeasurePages(&sha256_context, SGX_PAGE_SIZE * 2 + segment_offset,
                    properties, segment_size, &endorser_memory[segment_offset]);
    }

    // measure the enclave
    uint8_t sha256_digest[SHA256_DIGEST_LENGTH] = { 0 };
    MeasureEInit(&sha256_context, sha256_digest);

    // generate sgx_sigstruct
    struct sgx_sigstruct sigstruct;
    ret = MakeSigStructWithKeyInFile(sha256_digest, private_key_file, &sigstruct);
    if (ret != 0) {
        fprintf(stderr, "failed to generate SGX sig struct (error=%d)\n", ret);
        return ret;
    }

    // finalize the enclave
    struct sgx_enclave_init enclave_init_arg = { 0 };
    enclave_init_arg.sigstruct = POINTER_TO_U64(&sigstruct);
    ret = ioctl(enclave_device, SGX_IOC_ENCLAVE_INIT, &enclave_init_arg);
    if (ret != 0) {
        fprintf(stderr, "failed to initialize the enclave (error=%d)\n", ret);
        return ret;
    }

    close(enclave_device);
    free(tmp_page);
    return 0;
}
