/*
 * Copyright 2022 Google LLC
 * SPDX-License-Identifier: MIT
 */

#include <assert.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <termios.h>
#include <unistd.h>

enum meminfo_sys_type {
    MEMINFO_SYS_MemTotal,
    MEMINFO_SYS_MemFree,
    MEMINFO_SYS_MemAvailable,
    MEMINFO_SYS_Buffers,
    MEMINFO_SYS_Cached,
    MEMINFO_SYS_SwapCached,
    MEMINFO_SYS_Active,
    MEMINFO_SYS_Inactive,
    MEMINFO_SYS_ActiveAnon,
    MEMINFO_SYS_InactiveAnon,
    MEMINFO_SYS_ActiveFile,
    MEMINFO_SYS_InactiveFile,
    MEMINFO_SYS_Unevictable,
    MEMINFO_SYS_Mlocked,
    MEMINFO_SYS_SwapTotal,
    MEMINFO_SYS_SwapFree,
    MEMINFO_SYS_Zswap,
    MEMINFO_SYS_Zswapped,
    MEMINFO_SYS_Dirty,
    MEMINFO_SYS_Writeback,
    MEMINFO_SYS_AnonPages,
    MEMINFO_SYS_Mapped,
    MEMINFO_SYS_Shmem,
    MEMINFO_SYS_KReclaimable,
    MEMINFO_SYS_Slab,
    MEMINFO_SYS_SReclaimable,
    MEMINFO_SYS_SUnreclaim,
    MEMINFO_SYS_KernelStack,
    MEMINFO_SYS_PageTables,
#if 0
    MEMINFO_SYS_NFS_Unstable,
    MEMINFO_SYS_Bounce,
    MEMINFO_SYS_WritebackTmp,
    MEMINFO_SYS_CommitLimit,
    MEMINFO_SYS_Committed_AS,
    MEMINFO_SYS_VmallocTotal,
    MEMINFO_SYS_VmallocUsed,
    MEMINFO_SYS_VmallocChunk,
    MEMINFO_SYS_Percpu,
    MEMINFO_SYS_HardwareCorrupted,
    MEMINFO_SYS_AnonHugePages,
    MEMINFO_SYS_ShmemHugePages,
    MEMINFO_SYS_ShmemPmdMapped,
    MEMINFO_SYS_FileHugePages,
    MEMINFO_SYS_FilePmdMapped,
    MEMINFO_SYS_Hugepagesize,
    MEMINFO_SYS_Hugetlb,
    MEMINFO_SYS_DirectMap4k,
    MEMINFO_SYS_DirectMap2M,
    MEMINFO_SYS_DirectMap1G,
#endif

    MEMINFO_SYS_COUNT,
};

struct meminfo_bucket {
    size_t entry_size;
    int entry_max;
    int entry_count;
    void **entries;
};

struct meminfo {
    int tty_fd;
    struct termios termios;

    bool quit;

    struct meminfo_bucket gb;
    struct meminfo_bucket mb;
    struct meminfo_bucket anon;
    struct meminfo_bucket shmem;
};

static void
meminfo_parse_sys(int *sys)
{
    memset(sys, 0, sizeof(*sys) * MEMINFO_SYS_COUNT);

    FILE *fp = fopen("/proc/meminfo", "r");
    if (!fp)
        return;

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        size_t val;
#define IF_FIELD(f, e, l, v, s)                                                                  \
    if (sscanf(l, f ": %zu kB", &v) == 1)                                                        \
    sys[MEMINFO_SYS_##e] = v
#define IF_SIMPLE(e, l, v, s) IF_FIELD(#e, e, l, v, s)
        IF_SIMPLE(MemTotal, line, val, sys);
        else IF_SIMPLE(MemFree, line, val, sys);
        else IF_SIMPLE(MemAvailable, line, val, sys);
        else IF_SIMPLE(Buffers, line, val, sys);
        else IF_SIMPLE(Cached, line, val, sys);
        else IF_SIMPLE(SwapCached, line, val, sys);
        else IF_SIMPLE(Active, line, val, sys);
        else IF_SIMPLE(Inactive, line, val, sys);
        else IF_FIELD("Active(anon)", ActiveAnon, line, val, sys);
        else IF_FIELD("Inactive(anon)", InactiveAnon, line, val, sys);
        else IF_FIELD("Active(file)", ActiveFile, line, val, sys);
        else IF_FIELD("Inactive(file)", InactiveFile, line, val, sys);
        else IF_SIMPLE(Unevictable, line, val, sys);
        else IF_SIMPLE(Mlocked, line, val, sys);
        else IF_SIMPLE(SwapTotal, line, val, sys);
        else IF_SIMPLE(SwapFree, line, val, sys);
        else IF_SIMPLE(Zswap, line, val, sys);
        else IF_SIMPLE(Zswapped, line, val, sys);
        else IF_SIMPLE(Dirty, line, val, sys);
        else IF_SIMPLE(Writeback, line, val, sys);
        else IF_SIMPLE(AnonPages, line, val, sys);
        else IF_SIMPLE(Mapped, line, val, sys);
        else IF_SIMPLE(Shmem, line, val, sys);
        else IF_SIMPLE(KReclaimable, line, val, sys);
        else IF_SIMPLE(Slab, line, val, sys);
        else IF_SIMPLE(SReclaimable, line, val, sys);
        else IF_SIMPLE(SUnreclaim, line, val, sys);
        else IF_SIMPLE(KernelStack, line, val, sys);
        else IF_SIMPLE(PageTables, line, val, sys);
#if 0
        else IF_SIMPLE(NFS_Unstable, line, val, sys);
        else IF_SIMPLE(Bounce, line, val, sys);
        else IF_SIMPLE(WritebackTmp, line, val, sys);
        else IF_SIMPLE(CommitLimit, line, val, sys);
        else IF_SIMPLE(Committed_AS, line, val, sys);
        else IF_SIMPLE(VmallocTotal, line, val, sys);
        else IF_SIMPLE(VmallocUsed, line, val, sys);
        else IF_SIMPLE(VmallocChunk, line, val, sys);
        else IF_SIMPLE(Percpu, line, val, sys);
        else IF_SIMPLE(HardwareCorrupted, line, val, sys);
        else IF_SIMPLE(AnonHugePages, line, val, sys);
        else IF_SIMPLE(ShmemHugePages, line, val, sys);
        else IF_SIMPLE(ShmemPmdMapped, line, val, sys);
        else IF_SIMPLE(FileHugePages, line, val, sys);
        else IF_SIMPLE(FilePmdMapped, line, val, sys);
        else IF_SIMPLE(Hugepagesize, line, val, sys);
        else IF_SIMPLE(Hugetlb, line, val, sys);
        else IF_SIMPLE(DirectMap4k, line, val, sys);
        else IF_SIMPLE(DirectMap2M, line, val, sys);
        else IF_SIMPLE(DirectMap1G, line, val, sys);
#endif
#undef IF_FIELD
#undef IF_SIMPLE
    }

    fclose(fp);

    for (int i = 0; i < MEMINFO_SYS_COUNT; i++) {
        int mb = (sys[i] + 512) / 1024;
        if (!mb && sys[i])
            mb = 1;
        sys[i] = mb;
    }
}

static void
meminfo_dump(const struct meminfo *info)
{
    int sys[MEMINFO_SYS_COUNT];
    meminfo_parse_sys(sys);

    const int MemTotal = sys[MEMINFO_SYS_MemTotal];
    const int MemFree = sys[MEMINFO_SYS_MemFree];
    const int Buffers = sys[MEMINFO_SYS_Buffers];
    const int Cached = sys[MEMINFO_SYS_Cached];
    const int SwapCached = sys[MEMINFO_SYS_SwapCached];
    const int ActiveAnon = sys[MEMINFO_SYS_ActiveAnon];
    const int InactiveAnon = sys[MEMINFO_SYS_InactiveAnon];
    const int ActiveFile = sys[MEMINFO_SYS_ActiveFile];
    const int InactiveFile = sys[MEMINFO_SYS_InactiveFile];
    const int Unevictable = sys[MEMINFO_SYS_Unevictable];
    const int SwapTotal = sys[MEMINFO_SYS_SwapTotal];
    const int SwapFree = sys[MEMINFO_SYS_SwapFree];
    const int AnonPages = sys[MEMINFO_SYS_AnonPages];
    const int Shmem = sys[MEMINFO_SYS_Shmem];
    const int SReclaimable = sys[MEMINFO_SYS_SReclaimable];
    const int SUnreclaim = sys[MEMINFO_SYS_SUnreclaim];
    const int KernelStack = sys[MEMINFO_SYS_KernelStack];
    const int PageTables = sys[MEMINFO_SYS_PageTables];

    printf("--\n");

    /* used/total pages in buddy and in swap */
    const int mem_used = MemTotal - MemFree;
    const int swap_used = SwapTotal - SwapFree;
    printf("Buddy %d/%dM Swap %d/%dM\n", mem_used, MemTotal, swap_used, SwapTotal);

    /* all consumers */
    const int other = mem_used - (Cached + Buffers + SwapCached + AnonPages + SReclaimable +
                                  SUnreclaim + PageTables + KernelStack);
    printf("Cached/Buffers/SwapCached %d/%d/%dM AnonPages %dM Slab %d+%dM PageTables %dM "
           "KernelStack %dM Other %dM\n",
           Cached, Buffers, SwapCached, AnonPages, SReclaimable, SUnreclaim, PageTables,
           KernelStack, other);

    printf("LRU File/Anon/Unevictable %d/%d/%d Shmem %dM\n", ActiveFile + InactiveFile,
           ActiveAnon + InactiveAnon, Unevictable, Shmem);

    /* malloc is similar to mmap(MAP_PRIVATE | MAP_ANONYMOUS).  It is not
     * backed by any file.
     *
     * shmem is similar to mmap(MAP_SHARED | MAP_ANONYMOUS).  It is backed by
     * a in-memory file.
     */
    const int gb = (info->gb.entry_size >> 30) * info->gb.entry_count;
    const int mb = (info->mb.entry_size >> 20) * info->mb.entry_count;
    const int anon = (info->anon.entry_size >> 30) * info->anon.entry_count;
    const int shmem = (info->shmem.entry_size >> 30) * info->shmem.entry_count;
    printf("Allocated %dG+%dM, anon %dG, shmem %dG\n", gb, mb, anon, shmem);
}

static void
meminfo_drop_caches(void)
{
    sync();
    FILE *fp = fopen("/proc/sys/vm/drop_caches", "w");
    if (fp) {
        char val = '1';
        fwrite(&val, 1, 1, fp);
        fclose(fp);
    }
}

static void
meminfo_malloc_alloc(struct meminfo *info, bool gb)
{
    struct meminfo_bucket *bucket = gb ? &info->gb : &info->mb;

    if (bucket->entry_count >= bucket->entry_max)
        return;

    void *entry = malloc(bucket->entry_size);
    if (!entry)
        return;

    const int val = bucket->entry_count & 0xff;
    memset(entry, val, bucket->entry_size);

    bucket->entries[bucket->entry_count++] = entry;
}

static void
meminfo_malloc_free(struct meminfo *info, bool gb)
{
    struct meminfo_bucket *bucket = gb ? &info->gb : &info->mb;

    if (!bucket->entry_count)
        return;

    void *entry = bucket->entries[--bucket->entry_count];
    free(entry);
}

static void
meminfo_anon_alloc(struct meminfo *info)
{
    struct meminfo_bucket *bucket = &info->anon;

    if (bucket->entry_count >= bucket->entry_max)
        return;

    void *entry = mmap(NULL, bucket->entry_size, PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (entry == MAP_FAILED)
        return;

    const int val = bucket->entry_count & 0xff;
    memset(entry, val, bucket->entry_size);

    bucket->entries[bucket->entry_count++] = entry;
}

static void
meminfo_anon_free(struct meminfo *info)
{
    struct meminfo_bucket *bucket = &info->anon;

    if (!bucket->entry_count)
        return;

    void *entry = bucket->entries[--bucket->entry_count];
    munmap(entry, bucket->entry_size);
}

static void
meminfo_shmem_alloc(struct meminfo *info)
{
    struct meminfo_bucket *bucket = &info->shmem;

    if (bucket->entry_count >= bucket->entry_max)
        return;

    const int fd = memfd_create("shmem", 0);
    if (fd < 0)
        return;

    if (fallocate(fd, 0, 0, bucket->entry_size)) {
        close(fd);
        return;
    }

    void *entry = mmap(NULL, bucket->entry_size, PROT_WRITE, MAP_SHARED, fd, 0);
    if (entry == MAP_FAILED) {
        close(fd);
        return;
    }

    const int val = bucket->entry_count & 0xff;
    memset(entry, val, bucket->entry_size);

    assert(bucket->entry_size >= sizeof(int));
    *((int *)entry) = fd;

    bucket->entries[bucket->entry_count++] = entry;
}

static void
meminfo_shmem_free(struct meminfo *info)
{
    struct meminfo_bucket *bucket = &info->shmem;

    if (!bucket->entry_count)
        return;

    void *entry = bucket->entries[--bucket->entry_count];
    const int fd = *((const int *)entry);

    munmap(entry, bucket->entry_size);
    close(fd);
}

static void
meminfo_reset(struct meminfo *info)
{
    while (info->gb.entry_count)
        meminfo_malloc_free(info, true);
    while (info->mb.entry_count)
        meminfo_malloc_free(info, false);
    while (info->anon.entry_count)
        meminfo_anon_free(info);
    while (info->shmem.entry_count)
        meminfo_shmem_free(info);
}

static void
meminfo_run(struct meminfo *info)
{
    meminfo_dump(info);

    while (!info->quit) {
        bool dump = true;

        const int c = getchar();
        switch (c) {
        case 'r':
            meminfo_reset(info);
            break;
        case 'd':
            meminfo_drop_caches();
            break;
        case 'g':
            meminfo_malloc_alloc(info, true);
            break;
        case 'G':
            meminfo_malloc_free(info, true);
            break;
        case 'm':
            meminfo_malloc_alloc(info, false);
            break;
        case 'M':
            meminfo_malloc_free(info, false);
            break;
        case 'a':
            meminfo_anon_alloc(info);
            break;
        case 'A':
            meminfo_anon_free(info);
            break;
        case 's':
            meminfo_shmem_alloc(info);
            break;
        case 'S':
            meminfo_shmem_free(info);
            break;
        case ' ':
        case 0x0d:
            break;
        case 'q':
        case 0x03:
            info->quit = true;
            dump = false;
            break;
        default:
            printf("unknown key 0x%x\n", c);
            break;
        }

        if (dump)
            meminfo_dump(info);
    }
}

static void
meminfo_cleanup(struct meminfo *info)
{
    meminfo_reset(info);

    if (tcsetattr(info->tty_fd, TCSAFLUSH, &info->termios))
        fprintf(stderr, "failed to restore tty attrs\n");
}

static void
meminfo_die(const char *msg)
{
    fprintf(stderr, "%s\n", msg);
    abort();
}

static void
meminfo_init_termios(struct meminfo *info)
{
    if (tcgetattr(info->tty_fd, &info->termios))
        meminfo_die("failed to get tty attrs");

    struct termios raw = info->termios;
    cfmakeraw(&raw);
    raw.c_oflag |= OPOST;

    if (tcsetattr(info->tty_fd, TCSAFLUSH, &raw))
        meminfo_die("failed to set tty attrs");
}

static void
meminfo_init_buckets(struct meminfo *info)
{
    info->gb.entries = malloc(sizeof(*info->gb.entries) * info->gb.entry_max);
    info->mb.entries = malloc(sizeof(*info->mb.entries) * info->mb.entry_max);
    info->anon.entries = malloc(sizeof(*info->anon.entries) * info->anon.entry_max);
    info->shmem.entries = malloc(sizeof(*info->shmem.entries) * info->shmem.entry_max);
    if (!info->gb.entries || !info->mb.entries || !info->anon.entries || !info->shmem.entries)
        meminfo_die("failed to init buckets");
}

static int
meminfo_get_tty(void)
{
    struct stat in;
    struct stat out;
    struct stat err;
    if (fstat(STDIN_FILENO, &in) || fstat(STDOUT_FILENO, &out) || fstat(STDERR_FILENO, &err))
        return -1;

    if (in.st_dev != out.st_dev || in.st_ino != out.st_ino || in.st_dev != err.st_dev ||
        in.st_ino != err.st_ino)
        return -1;

    const int fd = STDIN_FILENO;
    return isatty(fd) ? fd : -1;
}

static void
meminfo_init(struct meminfo *info)
{
    info->tty_fd = meminfo_get_tty();
    if (info->tty_fd < 0)
        meminfo_die("no tty");

    meminfo_init_buckets(info);

    meminfo_init_termios(info);
}

int
main(void)
{
    struct meminfo info = {
        .tty_fd = -1,
        .gb.entry_size = 1u << 30,
        .gb.entry_max = 256,
        .mb.entry_size = 32u << 20,
        .mb.entry_max = 32,
        .anon.entry_size = 1u << 30,
        .anon.entry_max = 256,
        .shmem.entry_size = 1u << 30,
        .shmem.entry_max = 256,
    };

    meminfo_init(&info);
    meminfo_run(&info);
    meminfo_cleanup(&info);

    return 0;
}
