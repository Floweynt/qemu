#include "qemu/osdep.h"
#include "cpu-qom.h"
#include "exec/hwaddr.h"
#include "hw/i386/apic.h"
#include "hw/i386/e820_memory_layout.h"
#include "hw/i386/x86.h"
#include "hw/i386/x86-limine.h"
#include "system/hw_accel.h"
#include "target/i386/cpu.h"
#include "qemu/error-report.h"
#include "qemu/guest-random.h"
#include "qemu/timer.h"
#include "hw/core/loader.h"
#include "hw/nvram/fw_cfg.h"
#include "system/address-spaces.h"
#include "system/reset.h"
#include "system/system.h"
#include "elf.h"
#include <stdint.h>

#define DEBUG_LIMINE

#ifdef DEBUG_LIMINE
#define mb_debug(a...) error_report(a)
#else
#define mb_debug(a...)
#endif

#define LIMINE_NO_POINTERS
#define LIMINE_TARGET_ARCH LIMINE_ARCH_X86_64
#include "hw/core/limine.h"

#define LIMINE_HIGHER_HALF      ((uint64_t)0xffffffff80000000)
#define ISA_HOLE_END            ((uint64_t)0x100000)
#define SUPPORTED_BASE_REVISION 6
#define MAX_LIMINE_REQUESTS     128
#define LIMINE_CS64             0x28
#define LIMINE_DS64             0x30
#define LIMINE_GDT_ENTRIES      7

static const uint64_t limine_gdt[LIMINE_GDT_ENTRIES] = {
    [0] = 0,
    [1] = 0x00009a000000ffffULL,
    [2] = 0x000092000000ffffULL,
    [3] = 0x00cf9a000000ffffULL,
    [4] = 0x00cf92000000ffffULL,
    [5] = 0x00af9a000000ffffULL,
    [6] = 0x00cf92000000ffffULL,
};

typedef struct {
    Notifier notifier;
    hwaddr cr3;
    hwaddr gdt;
    uint64_t entry_point;
    hwaddr stack_top;
    bool la57;
} LimineBootState;

typedef struct {
    uint64_t physical_base;
    uint64_t min_paddr;
} LimineTranslateData;

typedef struct {
    bool is_relocatable;
    bool lower_to_higher;
    uint64_t min_vaddr, max_vaddr;
    uint64_t min_paddr, max_paddr;
    uint64_t entry;
    int phdr_count;
    Elf64_Phdr *phdrs;
} LimineParsedElf;

typedef struct {
    hwaddr phys;
    uint64_t id[2];
} LimineRequestEntry;

typedef struct {
    int base_revision;
    uint64_t requested_revision;
    hwaddr base_rev_phys;
    LimineRequestEntry requests[MAX_LIMINE_REQUESTS];
    size_t count;
} LimineScanResult;

typedef struct {
    struct entry {
        uint64_t base;
        uint64_t top;
    } ent[2];

    uint64_t cursor;
    size_t index;
} LimineAllocPool;

typedef struct {
    LimineAllocPool *pool;
    struct stager_seg {
        hwaddr base;
        uint8_t *buf;
        size_t capacity;
        size_t used;
    } *segs;
    size_t seg_count;
    size_t seg_alloc;
} LimineStager;

static bool validate_header(uint8_t *header, int file_size, bool wants_kaslr,
                            LimineParsedElf *parsed)
{
    if (file_size < sizeof(Elf64_Ehdr)) {
        return false;
    }

    if (memcmp(header, ELFMAG, SELFMAG) != 0) {
        return false;
    }

    if (header[EI_CLASS] != ELFCLASS64) {
        return false;
    }

    if (header[EI_DATA] != ELFDATA2LSB) {
        return false;
    }

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)header;
    if (ehdr->e_machine != EM_X86_64) {
        return false;
    }

    if (ehdr->e_type == ET_DYN) {
        parsed->is_relocatable = true;
    } else if (ehdr->e_type == ET_EXEC) {
        parsed->is_relocatable = false;
    } else {
        error_report("limine: unsupported ELF type %d (need ET_EXEC or ET_DYN)",
                     ehdr->e_type);
        exit(1);
    }

    if (!parsed->is_relocatable && wants_kaslr) {
        error_report("limine: KASLR requires a relocatable (ET_DYN) kernel");
        exit(1);
    }

    if (ehdr->e_phentsize < sizeof(Elf64_Phdr)) {
        error_report("limine: e_phentsize too small");
        exit(1);
    }

    parsed->entry = ehdr->e_entry;
    return true;
}

static bool read_and_validate_phdrs(FILE *f, LimineParsedElf *parsed)
{
    Elf64_Ehdr ehdr;
    bool lower_to_higher = false;
    bool higher_half = false;
    uint64_t min_vaddr = UINT64_MAX, max_vaddr = 0;
    uint64_t min_paddr = UINT64_MAX, max_paddr = 0;
    uint64_t prev_top = 0;

    fseek(f, 0, SEEK_SET);
    if (fread(&ehdr, sizeof(ehdr), 1, f) != 1) {
        error_report("limine: failed to read ELF header");
        exit(1);
    }

    size_t phdrs_size = (size_t)ehdr.e_phnum * sizeof(Elf64_Phdr);
    Elf64_Phdr *phdrs = g_malloc(phdrs_size);

    fseek(f, ehdr.e_phoff, SEEK_SET);
    if (fread(phdrs, sizeof(Elf64_Phdr), ehdr.e_phnum, f) != ehdr.e_phnum) {
        error_report("limine: failed to read program headers");
        exit(1);
    }

    bool has_loadable = false;
    for (int i = 0; i < ehdr.e_phnum; i++) {
        Elf64_Phdr *ph = &phdrs[i];
        if (ph->p_type != PT_LOAD || ph->p_memsz == 0) {
            continue;
        }
        has_loadable = true;

        if (ph->p_vaddr < LIMINE_HIGHER_HALF) {
            if (!parsed->is_relocatable) {
                error_report("limine: lower-half segment in "
                             "non-relocatable kernel");
                exit(1);
            }
            if (higher_half) {
                error_report("limine: mixed lower/higher half segments");
                exit(1);
            }
            lower_to_higher = true;
        } else {
            if (lower_to_higher) {
                error_report("limine: mixed lower/higher half segments");
                exit(1);
            }
            higher_half = true;
        }

        uint64_t phdr_end = ph->p_vaddr + ph->p_memsz;
        if (ph->p_vaddr < prev_top) {
            error_report("limine: overlapping or out-of-order PT_LOAD %d", i);
            exit(1);
        }
        prev_top = phdr_end;

        if (ph->p_filesz > ph->p_memsz) {
            error_report("limine: p_filesz > p_memsz in segment %d", i);
            exit(1);
        }

        if (ph->p_vaddr < min_vaddr) {
            min_vaddr = ph->p_vaddr;
        }
        if (phdr_end > max_vaddr) {
            max_vaddr = phdr_end;
        }
        if (ph->p_paddr < min_paddr) {
            min_paddr = ph->p_paddr;
        }
        uint64_t paddr_end = ph->p_paddr + ph->p_memsz;
        if (paddr_end > max_paddr) {
            max_paddr = paddr_end;
        }
    }

    if (!has_loadable) {
        error_report("limine: no loadable segments");
        exit(1);
    }

    parsed->lower_to_higher = lower_to_higher;
    parsed->min_vaddr = min_vaddr;
    parsed->max_vaddr = max_vaddr;
    parsed->min_paddr = min_paddr;
    parsed->max_paddr = max_paddr;
    parsed->phdr_count = ehdr.e_phnum;
    parsed->phdrs = phdrs;
    return true;
}

static int64_t vaddr_to_file_offset(Elf64_Phdr *phdrs, int num, uint64_t vaddr)
{
    for (int i = 0; i < num; i++) {
        Elf64_Phdr *ph = &phdrs[i];
        if (ph->p_type != PT_LOAD) {
            continue;
        }
        if (vaddr >= ph->p_vaddr && vaddr < ph->p_vaddr + ph->p_filesz) {
            return ph->p_offset + (vaddr - ph->p_vaddr);
        }
    }
    return -1;
}

static bool read_rela_table(FILE *f, int64_t offset, size_t count,
                            uint64_t ent_size, Elf64_Rela **out)
{
    Elf64_Rela *relas = g_malloc(count * sizeof(Elf64_Rela));
    fseek(f, offset, SEEK_SET);

    for (size_t i = 0; i < count; i++) {
        if (fread(&relas[i], sizeof(Elf64_Rela), 1, f) != 1) {
            g_free(relas);
            return false;
        }
        if (ent_size > sizeof(Elf64_Rela)) {
            fseek(f, ent_size - sizeof(Elf64_Rela), SEEK_CUR);
        }
    }

    *out = relas;
    return true;
}

static void apply_rela_table(Elf64_Rela *relas, size_t count,
                             LimineParsedElf *parsed, uint64_t physical_base,
                             uint64_t bias)
{
    for (size_t i = 0; i < count; i++) {
        uint32_t type = ELF64_R_TYPE(relas[i].r_info);
        uint64_t target_phys =
            physical_base + (relas[i].r_offset - parsed->min_vaddr);

        switch (type) {
        case R_X86_64_RELATIVE: {
            void *ptr = rom_ptr(target_phys, 8);
            if (!ptr) {
                error_report("limine: relocation target 0x%" PRIx64 " not in "
                             "ROM",
                             target_phys);
                exit(1);
            }
            stq_le_p(ptr, bias + relas[i].r_addend);
            break;
        }
        case R_X86_64_NONE: break;
        default:
            error_report("limine: unsupported relocation type %u", type);
            exit(1);
        }
    }
}

static void apply_relocations(FILE *f, LimineParsedElf *parsed,
                              uint64_t physical_base, uint64_t bias)
{
    Elf64_Phdr *phdrs = parsed->phdrs;
    int phdr_count = parsed->phdr_count;

    uint64_t rela_vaddr = 0, rela_size = 0, rela_ent = 0;
    uint64_t jmprel_vaddr = 0, jmprel_size = 0;
    uint64_t pltrel_type = 0;

    for (int i = 0; i < phdr_count; i++) {
        Elf64_Phdr *ph = &phdrs[i];
        if (ph->p_type != PT_DYNAMIC) {
            continue;
        }

        size_t dyn_count = ph->p_filesz / sizeof(Elf64_Dyn);
        g_autofree Elf64_Dyn *dyns = g_malloc(ph->p_filesz);

        fseek(f, ph->p_offset, SEEK_SET);
        if (fread(dyns, sizeof(Elf64_Dyn), dyn_count, f) != dyn_count) {
            error_report("limine: failed to read PT_DYNAMIC");
            exit(1);
        }

        for (size_t j = 0; j < dyn_count; j++) {
            switch (dyns[j].d_tag) {
            case DT_RELA: rela_vaddr = dyns[j].d_un.d_ptr; break;
            case DT_RELASZ: rela_size = dyns[j].d_un.d_val; break;
            case DT_RELAENT: rela_ent = dyns[j].d_un.d_val; break;
            case DT_JMPREL: jmprel_vaddr = dyns[j].d_un.d_ptr; break;
            case DT_PLTRELSZ: jmprel_size = dyns[j].d_un.d_val; break;
            case DT_PLTREL: pltrel_type = dyns[j].d_un.d_val; break;
            case DT_NEEDED:
                error_report("limine: kernel must not have DT_NEEDED");
                exit(1);
            case DT_NULL: goto done_dyn;
            }
        }
done_dyn:
        break;
    }

    if (rela_ent != 0 && rela_ent < sizeof(Elf64_Rela)) {
        error_report("limine: DT_RELAENT too small");
        exit(1);
    }
    if (rela_ent == 0) {
        rela_ent = sizeof(Elf64_Rela);
    }

    if (rela_vaddr && rela_size) {
        int64_t rela_off = vaddr_to_file_offset(phdrs, phdr_count, rela_vaddr);
        if (rela_off < 0) {
            error_report("limine: DT_RELA vaddr not in any PT_LOAD");
            exit(1);
        }

        size_t count = rela_size / rela_ent;
        g_autofree Elf64_Rela *relas = NULL;
        if (!read_rela_table(f, rela_off, count, rela_ent, &relas)) {
            error_report("limine: failed to read DT_RELA entries");
            exit(1);
        }
        apply_rela_table(relas, count, parsed, physical_base, bias);
    }

    if (jmprel_vaddr && jmprel_size) {
        if (pltrel_type != DT_RELA) {
            error_report("limine: DT_PLTREL is not DT_RELA");
            exit(1);
        }

        int64_t jmprel_off =
            vaddr_to_file_offset(phdrs, phdr_count, jmprel_vaddr);
        if (jmprel_off < 0) {
            error_report("limine: DT_JMPREL vaddr not in any PT_LOAD");
            exit(1);
        }

        size_t count = jmprel_size / rela_ent;
        g_autofree Elf64_Rela *jmprels = NULL;
        if (!read_rela_table(f, jmprel_off, count, rela_ent, &jmprels)) {
            error_report("limine: failed to read DT_JMPREL entries");
            exit(1);
        }
        apply_rela_table(jmprels, count, parsed, physical_base, bias);
    }
}

static void scan_requests(uint64_t physical_base, LimineParsedElf *parsed,
                          LimineScanResult *result)
{
    static const uint64_t start_marker[] = LIMINE_REQUESTS_START_MARKER;
    static const uint64_t end_marker[] = LIMINE_REQUESTS_END_MARKER;
    static const uint64_t base_rev[] = LIMINE_BASE_REVISION(0);
    static const uint64_t common_magic[] = { LIMINE_COMMON_MAGIC };

    *result = (LimineScanResult){ 0 };

    for (int seg = 0; seg < parsed->phdr_count; seg++) {
        Elf64_Phdr *ph = &parsed->phdrs[seg];
        if (ph->p_type != PT_LOAD || ph->p_filesz == 0) {
            continue;
        }

        uint64_t seg_phys = physical_base + (ph->p_paddr - parsed->min_paddr);
        uint8_t *data = rom_ptr(seg_phys, ph->p_filesz);
        if (!data) {
            continue;
        }

        for (uint64_t off = 0; off + 16 <= ph->p_filesz; off += 8) {
            uint64_t w = ldq_le_p(data + off);

            if (w != common_magic[0] && w != start_marker[0] &&
                w != end_marker[0] && w != base_rev[0]) {
                continue;
            }

            if (w == end_marker[0] &&
                ldq_le_p(data + off + 8) == end_marker[1]) {
                return;
            }

            if (w == start_marker[0] && off + 32 <= ph->p_filesz &&
                ldq_le_p(data + off + 8) == start_marker[1] &&
                ldq_le_p(data + off + 16) == start_marker[2] &&
                ldq_le_p(data + off + 24) == start_marker[3]) {
                result->count = 0;
                result->base_revision = 0;
                result->base_rev_phys = 0;
                continue;
            }

            if (w == base_rev[0] && off + 24 <= ph->p_filesz &&
                ldq_le_p(data + off + 8) == base_rev[1]) {
                if (result->base_rev_phys) {
                    error_report("limine: duplicate base revision tag");
                    exit(1);
                }
                result->base_rev_phys = seg_phys + off;
                result->requested_revision = ldq_le_p(data + off + 16);
                result->base_revision =
                    MIN(result->requested_revision, SUPPORTED_BASE_REVISION);
                continue;
            }

            if (w == common_magic[0] && off + 32 <= ph->p_filesz &&
                ldq_le_p(data + off + 8) == common_magic[1]) {
                if (result->count >= MAX_LIMINE_REQUESTS) {
                    error_report("limine: too many requests (max %d)",
                                 MAX_LIMINE_REQUESTS);
                    exit(1);
                }
                uint64_t id0 = ldq_le_p(data + off + 16);
                uint64_t id1 = ldq_le_p(data + off + 24);
                for (size_t j = 0; j < result->count; j++) {
                    if (result->requests[j].id[0] == id0 &&
                        result->requests[j].id[1] == id1) {
                        error_report("limine: duplicate request ID "
                                     "0x%" PRIx64 " 0x%" PRIx64,
                                     id0, id1);
                        exit(1);
                    }
                }
                result->requests[result->count++] = (LimineRequestEntry){
                    .phys = seg_phys + off,
                    .id = { id0, id1 },
                };
            }
        }
    }
}

static void ack_base_revision(LimineScanResult *scan)
{
    if (!scan->base_rev_phys) {
        error_report("limine: base revision tag not found");
        exit(1);
    }
    uint64_t *tag = rom_ptr(scan->base_rev_phys, 24);
    stq_le_p(&tag[1], scan->base_revision);
    if (scan->requested_revision <= SUPPORTED_BASE_REVISION) {
        stq_le_p(&tag[2], 0);
    }
}

static hwaddr find_request(LimineScanResult *scan, const uint64_t id[4])
{
    for (size_t i = 0; i < scan->count; i++) {
        if (scan->requests[i].id[0] == id[2] &&
            scan->requests[i].id[1] == id[3]) {
            return scan->requests[i].phys;
        }
    }
    return 0;
}

static void limine_pool_init(LimineAllocPool *pool, uint64_t kernel_top,
                             X86MachineState *x86ms)
{
    pool->ent[0].base = QEMU_ALIGN_UP(kernel_top, 4096);
    pool->ent[0].top = x86ms->below_4g_mem_size;
    pool->ent[1].base = QEMU_ALIGN_UP(x86ms->above_4g_mem_start, 4096);
    pool->ent[1].top = x86ms->above_4g_mem_start + x86ms->above_4g_mem_size;
    pool->index = 0;
    pool->cursor = pool->ent[0].top;
}

static hwaddr limine_pool_alloc(LimineAllocPool *pool, uint64_t size,
                                uint64_t align)
{
    for (; pool->index < 2; pool->index++) {
        uint64_t addr = QEMU_ALIGN_DOWN(pool->cursor - size, align);
        if (addr >= pool->ent[pool->index].base) {
            pool->cursor = addr;
            return addr;
        }
        if (pool->index + 1 < 2) {
            pool->cursor = pool->ent[pool->index + 1].top;
        }
    }
    error_report("limine: boot allocator exhausted");
    exit(1);
}

static void limine_stager_init(LimineStager *s, LimineAllocPool *pool)
{
    *s = (LimineStager){ .pool = pool };
}

static struct stager_seg *stager_grow(LimineStager *s, size_t min_size)
{
    size_t cap = MAX(QEMU_ALIGN_UP(min_size, 4096), 4096);

    if (s->seg_count == s->seg_alloc) {
        s->seg_alloc = MAX(s->seg_alloc * 2, 4);
        s->segs = g_realloc(s->segs, s->seg_alloc * sizeof(struct stager_seg));
    }

    struct stager_seg *seg = &s->segs[s->seg_count++];
    seg->base = limine_pool_alloc(s->pool, cap, 4096);
    seg->buf = g_malloc0(cap);
    seg->capacity = cap;
    seg->used = 0;
    return seg;
}

static hwaddr limine_stager_alloc(LimineStager *s, size_t size, size_t align)
{
    struct stager_seg *seg = s->seg_count ? &s->segs[s->seg_count - 1] : NULL;

    if (seg) {
        size_t off = QEMU_ALIGN_UP(seg->used, align);
        if (off + size <= seg->capacity) {
            seg->used = off + size;
            return seg->base + off;
        }
    }

    seg = stager_grow(s, size);
    size_t off = QEMU_ALIGN_UP(seg->used, align);
    seg->used = off + size;
    return seg->base + off;
}

static void *limine_stager_ptr(LimineStager *s, hwaddr addr)
{
    for (size_t i = 0; i < s->seg_count; i++) {
        struct stager_seg *seg = &s->segs[i];
        if (addr >= seg->base && addr < seg->base + seg->capacity) {
            return seg->buf + (addr - seg->base);
        }
    }

    g_assert_not_reached();
}

static hwaddr limine_stager_copy(LimineStager *s, const void *data, size_t size,
                                 size_t align)
{
    hwaddr addr = limine_stager_alloc(s, size, align);
    memcpy(limine_stager_ptr(s, addr), data, size);
    return addr;
}

static void limine_stager_commit(LimineStager *s)
{
    for (size_t i = 0; i < s->seg_count; i++) {
        struct stager_seg *seg = &s->segs[i];
        g_autofree char *name = g_strdup_printf("limine-data.%zu", i);
        rom_add_blob_fixed(name, seg->buf, seg->used, seg->base);
        g_free(seg->buf);
    }
    g_free(s->segs);
    *s = (LimineStager){ 0 };
}


static uint64_t limine_translate(void *opaque, uint64_t paddr)
{
    LimineTranslateData *d = opaque;
    return d->physical_base + (paddr - d->min_paddr);
}

typedef struct {
    LimineScanResult *scan;
    LimineStager *stager;
    uint64_t hhdm_off;
} LimineResponder;

static hwaddr lr_find(LimineResponder *lr, const uint64_t id[4])
{
    return find_request(lr->scan, id);
}

static hwaddr lr_alloc(LimineResponder *lr, size_t size, size_t align)
{
    return limine_stager_alloc(lr->stager, size, align);
}

static void *lr_ptr(LimineResponder *lr, hwaddr addr)
{
    return limine_stager_ptr(lr->stager, addr);
}

static hwaddr lr_copy(LimineResponder *lr, const void *data, size_t size,
                      size_t align)
{
    return limine_stager_copy(lr->stager, data, size, align);
}

static uint64_t lr_virt(LimineResponder *lr, hwaddr phys)
{
    return cpu_to_le64(lr->hhdm_off + phys);
}

static uint64_t lr_read(hwaddr request, size_t field_off)
{
    return ldq_le_p(rom_ptr(request + field_off, sizeof(uint64_t)));
}

#define LR_READ(request, req_type, field)                                      \
    lr_read((request), offsetof(struct req_type, field))

static void lr_set_response(LimineResponder *lr, hwaddr request,
                            size_t resp_field_off, const void *resp,
                            size_t resp_size)
{
    hwaddr resp_addr = lr_copy(lr, resp, resp_size, 8);
    void *field = rom_ptr(request + resp_field_off, sizeof(uint64_t));
    stq_le_p(field, lr->hhdm_off + resp_addr);
}

#define LR_RESPOND(lr, request, req_type, resp_ptr)                            \
    lr_set_response((lr), (request), offsetof(struct req_type, response),      \
                    (resp_ptr), sizeof(*(resp_ptr)))

static void handle_bootloader_info(LimineResponder *lr)
{
    static const uint64_t id[] = LIMINE_BOOTLOADER_INFO_REQUEST_ID;
    static const char loader_name[] = "QEMU";
    static const char loader_version[] = QEMU_VERSION;

    hwaddr request = lr_find(lr, id);
    if (!request) {
        return;
    }

    hwaddr name_addr = lr_copy(lr, loader_name, sizeof(loader_name), 1);
    hwaddr ver_addr = lr_copy(lr, loader_version, sizeof(loader_version), 1);

    struct limine_bootloader_info_response resp = {
        .revision = cpu_to_le64(0),
        .name = lr_virt(lr, name_addr),
        .version = lr_virt(lr, ver_addr),
    };
    LR_RESPOND(lr, request, limine_bootloader_info_request, &resp);
}

static void handle_cmdline(LimineResponder *lr, const char *cmdline)
{
    static const uint64_t id[] = LIMINE_EXECUTABLE_CMDLINE_REQUEST_ID;

    hwaddr request = lr_find(lr, id);
    if (!request) {
        return;
    }

    if (!cmdline) {
        cmdline = "";
    }
    hwaddr cmdline_addr = lr_copy(lr, cmdline, strlen(cmdline) + 1, 1);

    struct limine_executable_cmdline_response resp = {
        .revision = cpu_to_le64(0),
        .cmdline = lr_virt(lr, cmdline_addr),
    };
    LR_RESPOND(lr, request, limine_executable_cmdline_request, &resp);
}

static void handle_firmware_type(LimineResponder *lr)
{
    static const uint64_t id[] = LIMINE_FIRMWARE_TYPE_REQUEST_ID;

    hwaddr request = lr_find(lr, id);
    if (!request) {
        return;
    }

    struct limine_firmware_type_response resp = {
        .revision = cpu_to_le64(0),
        .firmware_type = cpu_to_le64(LIMINE_FIRMWARE_TYPE_X86BIOS),
    };
    LR_RESPOND(lr, request, limine_firmware_type_request, &resp);
}

static uint64_t handle_stack_size(LimineResponder *lr)
{
    static const uint64_t id[] = LIMINE_STACK_SIZE_REQUEST_ID;

    hwaddr request = lr_find(lr, id);
    if (!request) {
        return 64 * 1024;
    }

    struct limine_stack_size_response resp = {
        .revision = cpu_to_le64(0),
    };
    LR_RESPOND(lr, request, limine_stack_size_request, &resp);
    return LR_READ(request, limine_stack_size_request, stack_size);
}

static void handle_hhdm(LimineResponder *lr)
{
    static const uint64_t id[] = LIMINE_HHDM_REQUEST_ID;

    hwaddr request = lr_find(lr, id);
    if (!request) {
        return;
    }

    struct limine_hhdm_response resp = {
        .revision = cpu_to_le64(0),
        .offset = cpu_to_le64(lr->hhdm_off),
    };
    LR_RESPOND(lr, request, limine_hhdm_request, &resp);
}

static void handle_framebuffer(LimineResponder *lr)
{
    static const uint64_t id[] = LIMINE_FRAMEBUFFER_REQUEST_ID;
    if (lr_find(lr, id)) {
        warn_report("limine: framebuffer not yet supported in direct boot "
                    "mode");
    }
}

static uint64_t resolve_paging_mode(LimineScanResult *scan)
{
    static const uint64_t id[] = LIMINE_PAGING_MODE_REQUEST_ID;

    X86CPU *cpu = X86_CPU(first_cpu);
    bool has_la57 = cpu->env.features[FEAT_7_0_ECX] & CPUID_7_0_ECX_LA57;
    uint64_t hw_max = has_la57 ? LIMINE_PAGING_MODE_X86_64_5LVL :
                                 LIMINE_PAGING_MODE_X86_64_4LVL;

    hwaddr request = find_request(scan, id);
    if (!request) {
        return LIMINE_PAGING_MODE_X86_64_4LVL;
    }

    uint64_t max_mode = LR_READ(request, limine_paging_mode_request, max_mode);
    uint64_t min_mode = LR_READ(request, limine_paging_mode_request, min_mode);
    uint64_t req_mode = LR_READ(request, limine_paging_mode_request, mode);

    if (min_mode > hw_max) {
        error_report("limine: kernel requires paging mode %" PRIu64 " but "
                     "hardware "
                     "supports "
                     "at most "
                     "%" PRIu64,
                     min_mode, hw_max);
        exit(1);
    }

    uint64_t mode = CLAMP(req_mode, min_mode, max_mode);
    return MIN(mode, hw_max);
}

static void handle_paging_mode(LimineResponder *lr, uint64_t mode)
{
    static const uint64_t id[] = LIMINE_PAGING_MODE_REQUEST_ID;

    hwaddr request = lr_find(lr, id);
    if (!request) {
        return;
    }

    struct limine_paging_mode_response resp = {
        .revision = cpu_to_le64(0),
        .mode = cpu_to_le64(mode),
    };
    LR_RESPOND(lr, request, limine_paging_mode_request, &resp);
}

static hwaddr handle_mp(LimineResponder *lr, X86MachineState *x86ms)
{
    static const uint64_t id[] = LIMINE_MP_REQUEST_ID;

    hwaddr request = lr_find(lr, id);
    if (!request) {
        return 0;
    }

    MachineState *ms = MACHINE(x86ms);
    unsigned int cpu_count = ms->smp.cpus;

    hwaddr infos_addr =
        lr_alloc(lr, cpu_count * sizeof(struct limine_mp_info), 8);
    hwaddr ptrs_addr = lr_alloc(lr, cpu_count * sizeof(uint64_t), 8);
    uint64_t *ptrs = lr_ptr(lr, ptrs_addr);

    uint32_t bsp_lapic_id = x86_cpu_apic_id_from_index(x86ms, 0);

    for (unsigned int i = 0; i < cpu_count; i++) {
        hwaddr info_addr = infos_addr + i * sizeof(struct limine_mp_info);
        uint32_t lapic_id = x86_cpu_apic_id_from_index(x86ms, i);

        struct limine_mp_info info = {
            .processor_id = cpu_to_le32(i),
            .lapic_id = cpu_to_le32(lapic_id),
        };
        memcpy(lr_ptr(lr, info_addr), &info, sizeof(info));
        ptrs[i] = lr_virt(lr, info_addr);
    }

    uint64_t flags = LR_READ(request, limine_mp_request, flags);
    X86CPU *bsp = X86_CPU(first_cpu);
    bool has_x2apic = bsp->env.features[FEAT_1_ECX] & CPUID_EXT_X2APIC;

    uint32_t resp_flags = 0;
    if ((flags & cpu_to_le64(LIMINE_MP_REQUEST_X86_64_X2APIC)) && has_x2apic) {
        resp_flags = LIMINE_MP_RESPONSE_X86_64_X2APIC;

        for (unsigned int i = 0; i < cpu_count; i++) {
            CPUState *cs = qemu_get_cpu(i);
            X86CPU *xcpu = X86_CPU(cs);
            uint64_t base = cpu_get_apic_base(xcpu->apic_state);
            cpu_set_apic_base(xcpu->apic_state, base | MSR_IA32_APICBASE_EXTD);
        }
    }

    struct limine_mp_response resp = {
        .revision = cpu_to_le64(0),
        .flags = cpu_to_le32(resp_flags),
        .bsp_lapic_id = cpu_to_le32(bsp_lapic_id),
        .cpu_count = cpu_to_le64(cpu_count),
        .cpus = lr_virt(lr, ptrs_addr),
    };
    LR_RESPOND(lr, request, limine_mp_request, &resp);
    return infos_addr;
}

static uint64_t e820_to_limine_type(uint32_t e820_type)
{
    switch (e820_type) {
    case E820_RAM: return LIMINE_MEMMAP_USABLE;
    case E820_RESERVED: return LIMINE_MEMMAP_RESERVED;
    case E820_ACPI: return LIMINE_MEMMAP_ACPI_RECLAIMABLE;
    case E820_NVS: return LIMINE_MEMMAP_ACPI_NVS;
    case E820_UNUSABLE: return LIMINE_MEMMAP_BAD_MEMORY;
    default: return LIMINE_MEMMAP_RESERVED;
    }
}

typedef struct {
    hwaddr base;
    uint64_t size;
} LimineModuleRegion;

#define MAX_MEMMAP_ENTRIES 256

static int memmap_overlay(struct limine_memmap_entry *map, int count,
                          uint64_t ov_base, uint64_t ov_len, uint64_t ov_type)
{
    uint64_t ov_end = ov_base + ov_len;

    for (int i = 0; i < count && count + 2 < MAX_MEMMAP_ENTRIES; i++) {
        uint64_t base = map[i].base;
        uint64_t end = base + map[i].length;

        if (ov_base >= end || ov_end <= base) {
            continue;
        }
        if (map[i].type != LIMINE_MEMMAP_USABLE) {
            continue;
        }

        if (ov_base <= base && ov_end >= end) {
            map[i].type = ov_type;
            continue;
        }

        if (ov_base > base && ov_end < end) {
            memmove(&map[i + 3], &map[i + 1], (count - i - 1) * sizeof(map[0]));
            map[i] = (struct limine_memmap_entry){ base, ov_base - base,
                                                   LIMINE_MEMMAP_USABLE };
            map[i + 1] =
                (struct limine_memmap_entry){ ov_base, ov_len, ov_type };
            map[i + 2] = (struct limine_memmap_entry){ ov_end, end - ov_end,
                                                       LIMINE_MEMMAP_USABLE };
            count += 2;
            i += 2;
            continue;
        }

        if (ov_base > base) {
            memmove(&map[i + 2], &map[i + 1], (count - i - 1) * sizeof(map[0]));
            map[i] = (struct limine_memmap_entry){ base, ov_base - base,
                                                   LIMINE_MEMMAP_USABLE };
            map[i + 1] =
                (struct limine_memmap_entry){ ov_base, end - ov_base, ov_type };
            count += 1;
            i += 1;
        } else {
            memmove(&map[i + 2], &map[i + 1], (count - i - 1) * sizeof(map[0]));
            map[i] =
                (struct limine_memmap_entry){ base, ov_end - base, ov_type };
            map[i + 1] = (struct limine_memmap_entry){ ov_end, end - ov_end,
                                                       LIMINE_MEMMAP_USABLE };
            count += 1;
            i += 1;
        }
    }
    return count;
}

static int memmap_cmp(const void *a, const void *b)
{
    const struct limine_memmap_entry *ea = a, *eb = b;
    return (ea->base > eb->base) - (ea->base < eb->base);
}

static void handle_memmap(LimineResponder *lr, uint64_t physical_base,
                          uint64_t kernel_size, LimineAllocPool *pool,
                          LimineModuleRegion *modules, int module_count)
{
    static const uint64_t id[] = LIMINE_MEMMAP_REQUEST_ID;

    hwaddr request = lr_find(lr, id);
    if (!request) {
        return;
    }

    hwaddr entries_addr = lr_alloc(
        lr, MAX_MEMMAP_ENTRIES * sizeof(struct limine_memmap_entry), 8);
    hwaddr ptrs_addr = lr_alloc(lr, MAX_MEMMAP_ENTRIES * sizeof(uint64_t), 8);

    struct e820_entry *e820;
    int e820_count = e820_get_table(&e820);

    struct limine_memmap_entry map[MAX_MEMMAP_ENTRIES];
    int count = 0;

    for (int i = 0; i < e820_count && count < MAX_MEMMAP_ENTRIES; i++) {
        map[count++] = (struct limine_memmap_entry){
            .base = e820[i].address,
            .length = e820[i].length,
            .type = e820_to_limine_type(e820[i].type),
        };
    }

    count = memmap_overlay(map, count, physical_base,
                           QEMU_ALIGN_UP(kernel_size, 4096),
                           LIMINE_MEMMAP_EXECUTABLE_AND_MODULES);

    for (int m = 0; m < module_count; m++) {
        count = memmap_overlay(map, count, modules[m].base, modules[m].size,
                               LIMINE_MEMMAP_EXECUTABLE_AND_MODULES);
    }

    for (size_t i = 0; i <= pool->index && i < 2; i++) {
        uint64_t used_base, used_top;
        if (i < pool->index) {
            used_base = pool->ent[i].base;
            used_top = pool->ent[i].top;
        } else {
            used_base = pool->cursor;
            used_top = pool->ent[i].top;
        }
        if (used_top > used_base) {
            count = memmap_overlay(map, count, used_base, used_top - used_base,
                                   LIMINE_MEMMAP_BOOTLOADER_RECLAIMABLE);
        }
    }

    qsort(map, count, sizeof(map[0]), memmap_cmp);

    struct limine_memmap_entry *entries = lr_ptr(lr, entries_addr);
    uint64_t *ptrs = lr_ptr(lr, ptrs_addr);

    for (int i = 0; i < count; i++) {
        entries[i] = (struct limine_memmap_entry){
            .base = cpu_to_le64(map[i].base),
            .length = cpu_to_le64(map[i].length),
            .type = cpu_to_le64(map[i].type),
        };
        ptrs[i] =
            lr_virt(lr, entries_addr + i * sizeof(struct limine_memmap_entry));
    }

    struct limine_memmap_response resp = {
        .revision = cpu_to_le64(0),
        .entry_count = cpu_to_le64(count),
        .entries = lr_virt(lr, ptrs_addr),
    };
    LR_RESPOND(lr, request, limine_memmap_request, &resp);
}

static uint64_t handle_entry_point(LimineResponder *lr, uint64_t default_entry)
{
    static const uint64_t id[] = LIMINE_ENTRY_POINT_REQUEST_ID;

    hwaddr request = lr_find(lr, id);
    if (!request) {
        return default_entry;
    }

    struct limine_entry_point_response resp = {
        .revision = cpu_to_le64(0),
    };
    LR_RESPOND(lr, request, limine_entry_point_request, &resp);
    return LR_READ(request, limine_entry_point_request, entry);
}

static hwaddr stage_limine_file(LimineResponder *lr, FILE *f, size_t file_size,
                                const char *path, const char *string)
{
    hwaddr content = lr_alloc(lr, file_size, 4096);
    fseek(f, 0, SEEK_SET);
    if (fread(lr_ptr(lr, content), 1, file_size, f) != file_size) {
        error_report("limine: failed to read file '%s'", path);
        exit(1);
    }

    hwaddr path_addr = lr_copy(lr, path, strlen(path) + 1, 1);
    hwaddr str_addr = lr_copy(lr, string, strlen(string) + 1, 1);

    struct limine_file lf = {
        .revision = 0,
        .address = lr_virt(lr, content),
        .size = cpu_to_le64(file_size),
        .path = lr_virt(lr, path_addr),
        .string = lr_virt(lr, str_addr),
    };
    return lr_copy(lr, &lf, sizeof(lf), 8);
}

static void handle_executable_file(LimineResponder *lr, FILE *f,
                                   size_t file_size, const char *filename,
                                   const char *cmdline)
{
    static const uint64_t id[] = LIMINE_EXECUTABLE_FILE_REQUEST_ID;

    hwaddr request = lr_find(lr, id);
    if (!request) {
        return;
    }

    hwaddr file_addr = stage_limine_file(lr, f, file_size, filename, cmdline);

    struct limine_executable_file_response resp = {
        .revision = cpu_to_le64(0),
        .executable_file = lr_virt(lr, file_addr),
    };
    LR_RESPOND(lr, request, limine_executable_file_request, &resp);
}

static void handle_modules(LimineResponder *lr, const char *initrd_filename,
                           LimineModuleRegion *regions, int *region_count)
{
    static const uint64_t id[] = LIMINE_MODULE_REQUEST_ID;
    *region_count = 0;

    hwaddr request = lr_find(lr, id);
    if (!request && initrd_filename) {
        warn_report("limine: -initrd given but kernel has no module request");
        return;
    }

    if (!request) {
        return;
    }

    if (!initrd_filename) {
        struct limine_module_response resp = {
            .revision = cpu_to_le64(0),
            .module_count = 0,
            .modules = 0,
        };
        LR_RESPOND(lr, request, limine_module_request, &resp);
        return;
    }

    FILE *mf = fopen(initrd_filename, "rb");
    if (!mf) {
        error_report("limine: cannot open initrd '%s': %s", initrd_filename,
                     strerror(errno));
        exit(1);
    }

    fseek(mf, 0, SEEK_END);
    size_t mod_size = ftell(mf);

    hwaddr file_addr = stage_limine_file(lr, mf, mod_size, initrd_filename, "");
    fclose(mf);

    struct limine_file *lf = lr_ptr(lr, file_addr);
    hwaddr content_phys = le64_to_cpu(lf->address) - lr->hhdm_off;
    regions[0] =
        (LimineModuleRegion){ content_phys, QEMU_ALIGN_UP(mod_size, 4096) };
    *region_count = 1;

    hwaddr ptr_addr =
        lr_copy(lr, &(uint64_t){ lr_virt(lr, file_addr) }, sizeof(uint64_t), 8);

    struct limine_module_response resp = {
        .revision = cpu_to_le64(0),
        .module_count = cpu_to_le64(1),
        .modules = lr_virt(lr, ptr_addr),
    };
    LR_RESPOND(lr, request, limine_module_request, &resp);
}

static void handle_rsdp(LimineResponder *lr)
{
    static const uint64_t id[] = LIMINE_RSDP_REQUEST_ID;
    if (lr_find(lr, id)) {
        warn_report("limine: RSDP unavailable in direct boot mode");
    }
}

static void handle_smbios(LimineResponder *lr)
{
    static const uint64_t id[] = LIMINE_SMBIOS_REQUEST_ID;
    if (lr_find(lr, id)) {
        warn_report("limine: SMBIOS unavailable in direct boot mode");
    }
}

static void handle_efi_system_table(LimineResponder *lr)
{
    static const uint64_t id[] = LIMINE_EFI_SYSTEM_TABLE_REQUEST_ID;
    if (lr_find(lr, id)) {
        warn_report("limine: EFI system table unavailable in BIOS boot mode");
    }
}

static void handle_tpm_event_log(LimineResponder *lr)
{
    static const uint64_t id[] = LIMINE_TPM_EVENT_LOG_REQUEST_ID;
    if (lr_find(lr, id)) {
        warn_report("limine: TPM event log not supported");
    }
}

static void handle_efi_memmap(LimineResponder *lr)
{
    static const uint64_t id[] = LIMINE_EFI_MEMMAP_REQUEST_ID;
    if (lr_find(lr, id)) {
        warn_report("limine: EFI memory map unavailable in BIOS boot mode");
    }
}

static void handle_date_at_boot(LimineResponder *lr)
{
    static const uint64_t id[] = LIMINE_DATE_AT_BOOT_REQUEST_ID;

    hwaddr request = lr_find(lr, id);
    if (!request) {
        return;
    }

    int64_t ns = qemu_clock_get_ns(QEMU_CLOCK_HOST);

    struct limine_date_at_boot_response resp = {
        .revision = cpu_to_le64(0),
        .timestamp = cpu_to_le64(ns / 1000000000LL),
    };
    LR_RESPOND(lr, request, limine_date_at_boot_request, &resp);
}

static void handle_executable_address(LimineResponder *lr,
                                      uint64_t physical_base,
                                      uint64_t virtual_base)
{
    static const uint64_t id[] = LIMINE_EXECUTABLE_ADDRESS_REQUEST_ID;

    hwaddr request = lr_find(lr, id);
    if (!request) {
        return;
    }

    struct limine_executable_address_response resp = {
        .revision = cpu_to_le64(0),
        .physical_base = cpu_to_le64(physical_base),
        .virtual_base = cpu_to_le64(virtual_base),
    };
    LR_RESPOND(lr, request, limine_executable_address_request, &resp);
}

static void handle_dtb(LimineResponder *lr)
{
    static const uint64_t id[] = LIMINE_DTB_REQUEST_ID;
    if (lr_find(lr, id)) {
        warn_report("limine: DTB not available on x86");
    }
}

static void handle_bootloader_performance(LimineResponder *lr)
{
    static const uint64_t id[] = LIMINE_BOOTLOADER_PERFORMANCE_REQUEST_ID;

    hwaddr request = lr_find(lr, id);
    if (!request) {
        return;
    }

    struct limine_bootloader_performance_response resp = {
        .revision = cpu_to_le64(0),
    };
    LR_RESPOND(lr, request, limine_bootloader_performance_request, &resp);
}

static void handle_keep_iommu(LimineResponder *lr)
{
    static const uint64_t id[] = LIMINE_X86_64_KEEP_IOMMU_REQUEST_ID;

    hwaddr request = lr_find(lr, id);
    if (!request) {
        return;
    }

    struct limine_x86_64_keep_iommu_response resp = {
        .revision = cpu_to_le64(0),
    };
    LR_RESPOND(lr, request, limine_x86_64_keep_iommu_request, &resp);
}

static void handle_entropy(LimineResponder *lr)
{
    static const uint64_t id[] = LIMINE_ENTROPY_REQUEST_ID;

    hwaddr request = lr_find(lr, id);
    if (!request) {
        return;
    }

    uint64_t count = LR_READ(request, limine_entropy_request, value_count);
    if (count == 0 || count > 256) {
        count = 2;
    }

    size_t array_size = count * sizeof(uint64_t);
    hwaddr values_addr = lr_alloc(lr, array_size, 8);
    uint64_t *values = lr_ptr(lr, values_addr);
    qemu_guest_getrandom_nofail(values, array_size);

    struct limine_entropy_response resp = {
        .revision = cpu_to_le64(0),
        .value_count = cpu_to_le64(count),
        .values = lr_virt(lr, values_addr),
    };
    LR_RESPOND(lr, request, limine_entropy_request, &resp);
}

static void handle_tsc_frequency(LimineResponder *lr)
{
    static const uint64_t id[] = LIMINE_TSC_FREQUENCY_REQUEST_ID;

    hwaddr request = lr_find(lr, id);
    if (!request) {
        return;
    }

    X86CPU *cpu = X86_CPU(first_cpu);
    uint64_t freq_hz = (uint64_t)cpu->env.tsc_khz * 1000;

    struct limine_tsc_frequency_response resp = {
        .revision = cpu_to_le64(0),
        .frequency = cpu_to_le64(freq_hz),
    };
    LR_RESPOND(lr, request, limine_tsc_frequency_request, &resp);
}

static void handle_flanterm(LimineResponder *lr)
{
    static const uint64_t id[] = LIMINE_FLANTERM_FB_INIT_PARAMS_REQUEST_ID;
    if (lr_find(lr, id)) {
        warn_report("limine: flanterm init params not supported in direct "
                    "boot mode");
    }
}

#define LIMINE_HHDM_4LVL 0xffff800000000000ULL
#define LIMINE_HHDM_5LVL 0xff00000000000000ULL

#define PAGE_4K      (4ULL * 1024)
#define PAGE_2M      (2ULL * 1024 * 1024)
#define PAGE_1G      (1ULL * 1024 * 1024 * 1024)
#define MAX_PT_PAGES 1024

typedef struct {
    LimineAllocPool *pool;
    uint64_t *pages[MAX_PT_PAGES];
    hwaddr addrs[MAX_PT_PAGES];
    size_t count;
    int levels;
} LiminePageTables;

static size_t pt_alloc(LiminePageTables *pt)
{
    g_assert(pt->count < MAX_PT_PAGES);
    size_t idx = pt->count++;
    pt->addrs[idx] = limine_pool_alloc(pt->pool, 4096, 4096);
    pt->pages[idx] = g_malloc0(4096);
    return idx;
}

static size_t pt_ensure(LiminePageTables *pt, size_t tbl, unsigned slot)
{
    uint64_t ent = pt->pages[tbl][slot];
    if (ent & PG_PRESENT_MASK) {
        hwaddr child_phys = ent & ~0xFFFULL;
        for (size_t i = 0; i < pt->count; i++) {
            if (pt->addrs[i] == child_phys) {
                return i;
            }
        }
        g_assert_not_reached();
    }
    size_t child = pt_alloc(pt);
    pt->pages[tbl][slot] = pt->addrs[child] | PG_PRESENT_MASK | PG_RW_MASK;
    return child;
}

static size_t pt_walk(LiminePageTables *pt, size_t root, uint64_t va,
                      int stop_level)
{
    size_t tbl = root;
    int top = pt->levels == 5 ? 4 : 3;
    for (int lvl = top; lvl >= stop_level; lvl--) {
        unsigned idx = (va >> (12 + 9 * lvl)) & 0x1FF;
        tbl = pt_ensure(pt, tbl, idx);
    }
    return tbl;
}

static void pt_map_page(LiminePageTables *pt, size_t root, uint64_t va,
                        uint64_t pa, uint64_t page_size, uint64_t flags)
{
    int stop_level;
    int shift;

    switch (page_size) {
    case PAGE_1G:
        stop_level = 3;
        shift = 30;
        break;
    case PAGE_2M:
        stop_level = 2;
        shift = 21;
        break;
    default:
        stop_level = 1;
        shift = 12;
        break;
    }

    if (page_size > PAGE_4K) {
        flags |= PG_PSE_MASK;
    }

    size_t tbl = pt_walk(pt, root, va, stop_level);
    unsigned slot = (va >> shift) & 0x1FF;
    pt->pages[tbl][slot] = pa | flags;
}

static void pt_map(LiminePageTables *pt, size_t root, uint64_t virt,
                   uint64_t phys, uint64_t size, uint64_t page_size,
                   uint64_t flags)
{
    for (uint64_t off = 0; off < size; off += page_size) {
        pt_map_page(pt, root, virt + off, phys + off, page_size, flags);
    }
}

static void pt_map_mixed(LiminePageTables *pt, size_t root, uint64_t virt,
                         uint64_t phys, uint64_t size, bool use_1g,
                         uint64_t flags)
{
    uint64_t end = phys + size;
    uint64_t off = 0;

    while (phys + off < end) {
        uint64_t va = virt + off;
        uint64_t pa = phys + off;
        uint64_t remaining = end - pa;
        uint64_t page_size;

        if (use_1g && remaining >= PAGE_1G && (pa & (PAGE_1G - 1)) == 0 &&
            (va & (PAGE_1G - 1)) == 0) {
            page_size = PAGE_1G;
        } else if (remaining >= PAGE_2M && (pa & (PAGE_2M - 1)) == 0 &&
                   (va & (PAGE_2M - 1)) == 0) {
            page_size = PAGE_2M;
        } else {
            page_size = PAGE_4K;
        }

        pt_map_page(pt, root, va, pa, page_size, flags);
        off += page_size;
    }
}

static hwaddr pt_commit(LiminePageTables *pt, size_t root)
{
    for (size_t i = 0; i < pt->count; i++) {
        g_autofree char *name = g_strdup_printf("limine-pt.%zu", i);
        rom_add_blob_fixed(name, pt->pages[i], 4096, pt->addrs[i]);
        g_free(pt->pages[i]);
    }
    return pt->addrs[root];
}

static void setup_cpu_state(X86CPU *cpu, bool la57, hwaddr cr3, hwaddr gdt,
                            hwaddr stack, uint64_t entry)
{
    CPUX86State *env = &cpu->env;

    uint32_t cr4 = CR4_PAE_MASK | CR4_PGE_MASK;
    if (la57) {
        cr4 |= CR4_LA57_MASK;
    }

    env->efer = MSR_EFER_LME | MSR_EFER_LMA | MSR_EFER_NXE | MSR_EFER_SCE;
    cpu_x86_update_cr4(env, cr4);
    cpu_x86_update_cr3(env, cr3);
    cpu_x86_update_cr0(env, CR0_PE_MASK | CR0_WP_MASK | CR0_PG_MASK |
                                CR0_NE_MASK | CR0_ET_MASK);

    env->gdt.base = gdt;
    env->gdt.limit = sizeof(limine_gdt) - 1;

    uint32_t code64_flags = DESC_G_MASK | DESC_L_MASK | DESC_P_MASK |
                            DESC_S_MASK | DESC_CS_MASK | DESC_R_MASK |
                            DESC_A_MASK;
    uint32_t data64_flags =
        DESC_G_MASK | DESC_P_MASK | DESC_S_MASK | DESC_W_MASK | DESC_A_MASK;

    cpu_x86_load_seg_cache(env, R_CS, LIMINE_CS64, 0, 0xFFFFFFFF, code64_flags);
    cpu_x86_load_seg_cache(env, R_DS, LIMINE_DS64, 0, 0xFFFFFFFF, data64_flags);
    cpu_x86_load_seg_cache(env, R_ES, LIMINE_DS64, 0, 0xFFFFFFFF, data64_flags);
    cpu_x86_load_seg_cache(env, R_SS, LIMINE_DS64, 0, 0xFFFFFFFF, data64_flags);
    cpu_x86_load_seg_cache(env, R_FS, LIMINE_DS64, 0, 0xFFFFFFFF, data64_flags);
    cpu_x86_load_seg_cache(env, R_GS, LIMINE_DS64, 0, 0xFFFFFFFF, data64_flags);

    env->regs[R_ESP] = stack;
    env->eip = entry;
    env->eflags = 0x2;

    env->regs[R_EAX] = 0;
    env->regs[R_ECX] = 0;
    env->regs[R_EDX] = 0;
    env->regs[R_EBX] = 0;
    env->regs[R_EBP] = 0;
    env->regs[R_ESI] = 0;
    env->regs[R_EDI] = 0;
}

static void limine_reset(void *opaque)
{
    LimineBootState *bs = opaque;
    setup_cpu_state(X86_CPU(first_cpu), bs->la57, bs->cr3, bs->gdt,
                    bs->stack_top, bs->entry_point);

    CPUState *cs;
    CPU_FOREACH(cs)
    {
        if (cs != first_cpu) {
            cs->halted = 1;
        }
    }
}

static void limine_machine_done(Notifier *notifier, void *data)
{
    LimineBootState *bs = container_of(notifier, LimineBootState, notifier);
    qemu_register_reset(limine_reset, bs);
}

typedef struct {
    MemoryRegion mr;
    uint8_t *shadow;
    size_t shadow_size;
    unsigned int cpu_count;
    hwaddr cr3;
    hwaddr gdt;
    bool la57;
    hwaddr *stack_tops;
    hwaddr infos_addr;
} LimineMPWakeup;

static uint64_t mp_wakeup_read(void *opaque, hwaddr addr, unsigned size)
{
    LimineMPWakeup *w = opaque;
    if (addr + size > w->shadow_size) {
        return 0;
    }
    return ldn_le_p(w->shadow + addr, size);
}

static void mp_wakeup_write(void *opaque, hwaddr addr, uint64_t val,
                            unsigned size)
{
    LimineMPWakeup *w = opaque;
    if (addr + size > w->shadow_size) {
        return;
    }

    stn_le_p(w->shadow + addr, size, val);

    unsigned int idx = addr / sizeof(struct limine_mp_info);
    unsigned int field = addr % sizeof(struct limine_mp_info);

    if (field == offsetof(struct limine_mp_info, goto_address) && size == 8 &&
        idx < w->cpu_count && w->stack_tops[idx]) {

        CPUState *cs = qemu_get_cpu(idx);
        if (!cs) {
            return;
        }
        X86CPU *cpu = X86_CPU(cs);

        setup_cpu_state(cpu, w->la57, w->cr3, w->gdt, w->stack_tops[idx], val);
        cpu->env.regs[R_EDI] =
            w->infos_addr + idx * sizeof(struct limine_mp_info);
        w->stack_tops[idx] = 0;

        cs->halted = 0;
        cpu->env.mp_state = KVM_MP_STATE_RUNNABLE;
        cpu_synchronize_post_init(cs);
        qemu_cpu_kick(cs);
    }
}

static const MemoryRegionOps mp_wakeup_ops = {
    .read = mp_wakeup_read,
    .write = mp_wakeup_write,
    .valid.min_access_size = 1,
    .valid.max_access_size = 8,
    .impl.min_access_size = 1,
    .impl.max_access_size = 8,
    .endianness = DEVICE_LITTLE_ENDIAN,
};

static void mp_wakeup_init(LimineMPWakeup *w, hwaddr infos_addr,
                           unsigned int cpu_count, hwaddr cr3, hwaddr gdt,
                           bool la57, hwaddr *stack_tops,
                           const void *initial_data, size_t data_size,
                           uint64_t hhdm_off)
{
    stack_tops[0] = 0;

    *w = (LimineMPWakeup){
        .shadow = g_memdup2(initial_data, data_size),
        .shadow_size = data_size,
        .cpu_count = cpu_count,
        .cr3 = cr3,
        .gdt = gdt,
        .la57 = la57,
        .stack_tops = stack_tops,
        .infos_addr = infos_addr + hhdm_off,
    };

    memory_region_init_io(&w->mr, NULL, &mp_wakeup_ops, w, "limine-mp-wakeup",
                          data_size);
    memory_region_add_subregion_overlap(get_system_memory(), infos_addr, &w->mr,
                                        1);
}

bool x86_load_limine(const char *kernel_filename, FILE *f, int kernel_file_size,
                     uint8_t *header, FWCfgState *fw_cfg,
                     X86MachineState *x86ms)
{
    MachineState *machine = MACHINE(x86ms);
    LimineParsedElf parsed = {};
    bool wants_kaslr = machine->kernel_kaslr;

    if (!validate_header(header, kernel_file_size, wants_kaslr, &parsed)) {
        return false;
    }

    if (!read_and_validate_phdrs(f, &parsed)) {
        return false;
    }

    uint64_t image_size = parsed.max_paddr - parsed.min_paddr;
    uint64_t physical_base = ISA_HOLE_END;
    uint64_t kernel_top = physical_base + image_size;

    mb_debug("limine: loaded kernel of 0x%" PRIx64 " bytes @ phys mem "
             "0x%" PRIx64 " - 0x%" PRIx64,
             image_size, physical_base, kernel_top);

    if (kernel_top > x86ms->below_4g_mem_size) {
        error_report("limine: kernel image (0x%" PRIx64 " bytes) does not fit "
                     "in RAM below 4G (0x%" PRIx64 " available from 1 MiB)",
                     image_size, x86ms->below_4g_mem_size - ISA_HOLE_END);
        exit(1);
    }

    uint64_t slide = 0;
    if (parsed.is_relocatable && wants_kaslr) {
        uint64_t max_align = 0x200000;
        uint32_t rand_val;
        qemu_guest_getrandom_nofail(&rand_val, sizeof(rand_val));
        slide = (uint64_t)(rand_val & ~(max_align - 1));
    }

    uint64_t virtual_base;

    if (parsed.lower_to_higher) {
        virtual_base = LIMINE_HIGHER_HALF + slide;
    } else {
        virtual_base = parsed.min_vaddr + slide;
    }
    uint64_t load_bias = virtual_base - parsed.min_vaddr;

    LimineTranslateData translate_data = {
        .physical_base = physical_base,
        .min_paddr = parsed.min_paddr,
    };

    mb_debug("limine: virtual base: 0x%" PRIx64, virtual_base);

    uint64_t elf_entry, elf_low, elf_high;
    int kernel_size = load_elf(kernel_filename, NULL, limine_translate,
                               &translate_data, &elf_entry, &elf_low, &elf_high,
                               NULL, ELFDATA2LSB, EM_X86_64, 0, 0);
    if (kernel_size < 0) {
        error_report("limine: failed to load ELF: %s",
                     load_elf_strerror(kernel_size));
        exit(1);
    }

    if (parsed.is_relocatable) {
        apply_relocations(f, &parsed, physical_base, load_bias);
    }

    LimineScanResult scan;
    scan_requests(physical_base, &parsed, &scan);

    ack_base_revision(&scan);

    LimineAllocPool pool;
    limine_pool_init(&pool, kernel_top, x86ms);

    LimineStager stager;
    limine_stager_init(&stager, &pool);

    uint64_t paging_mode = resolve_paging_mode(&scan);
    uint64_t hhdm_base = (paging_mode == LIMINE_PAGING_MODE_X86_64_5LVL) ?
                             LIMINE_HHDM_5LVL :
                             LIMINE_HHDM_4LVL;

    uint64_t max_phys =
        x86ms->above_4g_mem_size ?
            x86ms->above_4g_mem_start + x86ms->above_4g_mem_size :
            x86ms->below_4g_mem_size;
    uint64_t hhdm_off = hhdm_base;

    if (machine->kernel_randomise_hhdm_base) {
        uint64_t hhdm_max = virtual_base - max_phys;
        uint64_t hhdm_range =
            QEMU_ALIGN_DOWN(hhdm_max - hhdm_base, 0x40000000ULL);
        if (hhdm_range >= 0x40000000ULL) {
            uint64_t rand_val;
            qemu_guest_getrandom_nofail(&rand_val, sizeof(rand_val));
            hhdm_off = hhdm_base +
                       QEMU_ALIGN_DOWN(rand_val % hhdm_range, 0x40000000ULL);
        }
    }

    LimineResponder lr = {
        .scan = &scan,
        .stager = &stager,
        .hhdm_off = hhdm_off,
    };

    const char *cmdline = machine->kernel_cmdline;

    handle_bootloader_info(&lr);
    handle_cmdline(&lr, cmdline);
    handle_firmware_type(&lr);
    uint64_t stack_sz = handle_stack_size(&lr);
    handle_hhdm(&lr);
    handle_framebuffer(&lr);
    handle_paging_mode(&lr, paging_mode);
    hwaddr infos_addr = handle_mp(&lr, x86ms);

    unsigned int cpu_count = machine->smp.cpus;
    hwaddr *stack_tops = g_new(hwaddr, cpu_count);
    for (unsigned int i = 0; i < cpu_count; i++) {
        hwaddr base = limine_pool_alloc(&pool, stack_sz, 16);
        stack_tops[i] = hhdm_off + base + stack_sz;
    }

    X86CPU *cpu = X86_CPU(first_cpu);
    bool use_1g = cpu->env.features[FEAT_8000_0001_EDX] & CPUID_EXT2_PDPE1GB;
    int levels = (paging_mode == LIMINE_PAGING_MODE_X86_64_5LVL) ? 5 : 4;

    LiminePageTables pt = { .pool = &pool, .levels = levels };
    size_t root = pt_alloc(&pt);

    uint64_t hhdm_map_size = QEMU_ALIGN_UP(max_phys, PAGE_4K);
    pt_map_mixed(&pt, root, hhdm_off, 0, hhdm_map_size, use_1g,
                 PG_PRESENT_MASK | PG_RW_MASK);

    for (int i = 0; i < parsed.phdr_count; i++) {
        Elf64_Phdr *ph = &parsed.phdrs[i];
        if (ph->p_type != PT_LOAD || ph->p_memsz == 0) {
            continue;
        }
        uint64_t seg_virt = virtual_base + (ph->p_vaddr - parsed.min_vaddr);
        uint64_t seg_phys = physical_base + (ph->p_paddr - parsed.min_paddr);
        uint64_t seg_size = QEMU_ALIGN_UP(ph->p_memsz, PAGE_4K);

        uint64_t flags = PG_PRESENT_MASK;
        if (ph->p_flags & PF_W) {
            flags |= PG_RW_MASK;
        }
        if (!(ph->p_flags & PF_X)) {
            flags |= PG_NX_MASK;
        }

        mb_debug("limine: mapping region: 0x%" PRIx64 " -> 0x%" PRIx64
                 " len=0x%" PRIx64 " f=%" PRIx64,
                 seg_virt, seg_phys, seg_size, flags);
        pt_map(&pt, root, seg_virt, seg_phys, seg_size, PAGE_4K, flags);
    }

    hwaddr cr3 = pt_commit(&pt, root);
    mb_debug("limine: elf_entry = 0x%" PRIx64 " slide = 0x%" PRIx64, elf_entry,
             slide);

    uint64_t entry_point = handle_entry_point(&lr, elf_entry + load_bias);
    mb_debug("limine: entrypoint: 0x%" PRIx64, entry_point);

    handle_executable_file(&lr, f, kernel_file_size, kernel_filename,
                           cmdline ? cmdline : "");
    LimineModuleRegion mod_regions[16];
    int mod_region_count = 0;
    handle_modules(&lr, machine->initrd_filename, mod_regions,
                   &mod_region_count);

    handle_rsdp(&lr);
    handle_smbios(&lr);
    handle_efi_system_table(&lr);
    handle_tpm_event_log(&lr);
    handle_efi_memmap(&lr);

    handle_date_at_boot(&lr);
    handle_executable_address(&lr, physical_base, virtual_base);
    handle_dtb(&lr);
    handle_bootloader_performance(&lr);
    handle_keep_iommu(&lr);
    handle_tsc_frequency(&lr);
    handle_entropy(&lr);
    handle_flanterm(&lr);

    hwaddr gdt_phys = limine_pool_alloc(&pool, sizeof(limine_gdt), 16);
    rom_add_blob_fixed("limine-gdt", limine_gdt, sizeof(limine_gdt), gdt_phys);
    uint64_t gdt_virt = hhdm_off + gdt_phys;

    handle_memmap(&lr, physical_base, image_size, &pool, mod_regions,
                  mod_region_count);

    hwaddr bsp_stack = stack_tops[0];

    LimineMPWakeup *mp_wakeup = NULL;
    if (infos_addr && cpu_count > 1) {
        size_t infos_size = cpu_count * sizeof(struct limine_mp_info);
        void *infos_data = limine_stager_ptr(&stager, infos_addr);
        mp_wakeup = g_new(LimineMPWakeup, 1);
        mp_wakeup_init(mp_wakeup, infos_addr, cpu_count, cr3, gdt_virt,
                       levels == 5, stack_tops, infos_data, infos_size,
                       hhdm_base);
    } else {
        g_free(stack_tops);
    }

    limine_stager_commit(&stager);

    LimineBootState *bs = g_new(LimineBootState, 1);
    *bs = (LimineBootState){
        .notifier = { .notify = limine_machine_done },
        .cr3 = cr3,
        .gdt = gdt_virt,
        .entry_point = entry_point,
        .stack_top = bsp_stack,
        .la57 = levels == 5,
    };
    qemu_add_machine_init_done_notifier(&bs->notifier);

    g_free(parsed.phdrs);

    return true;
}
