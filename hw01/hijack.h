#pragma once
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <link.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

static const void **GOT_entries[7] = {0};

static void hijack(const void **GOT_entry, const void *func_ptr)
{
    if (!GOT_entry)
        return;
    uint64_t pagesize = getpagesize();
    void *GOT_entry_page = (void *) ((__uint64_t) GOT_entry & ~(pagesize - 1));
    if (mprotect(GOT_entry_page, pagesize,
                 PROT_READ | PROT_WRITE | PROT_EXEC) == -1)
        perror("mprotect()");

    *GOT_entry = func_ptr;
}

static void *get_main_ptr(const char *filename)
{
    FILE *file = fopen("/proc/self/maps", "r");
    uint64_t mainptr = UINT64_MAX;
    char *line = NULL;
    size_t len = 0;
    while (getline(&line, &len, file) != -1) {
        if (strstr(line, filename)) {
            uint64_t min, max;
            sscanf(line, "%lx-%lx", &min, &max);
            mainptr = (min < mainptr ? min : mainptr);
        }
    }
    if (line)
        free(line);
    fclose(file);
    return (void *) mainptr;
}

static Elf64_Shdr get_section_hdr64(FILE *elf_fp,
                                    Elf64_Ehdr elf_hdr,
                                    Elf64_Off i)
{
    Elf64_Shdr section_hdr;
    fseeko(elf_fp, elf_hdr.e_shoff + i * elf_hdr.e_shentsize, SEEK_SET);
    fread(&section_hdr, sizeof(section_hdr), 1, elf_fp);
    return section_hdr;
}

static void *const get_section(FILE *elf_fp, Elf64_Shdr section_hdr)
{
    void *const entries = malloc(section_hdr.sh_size);
    fseeko(elf_fp, section_hdr.sh_offset, SEEK_SET);
    fread(entries, section_hdr.sh_size, 1, elf_fp);
    return entries;
}

static void load_GOT()
{
    const char *elfpath = realpath("/proc/self/exe", NULL);
    void *mainptr = get_main_ptr(elfpath);
    FILE *elf_fp = fopen(elfpath, "rb");
    Elf64_Ehdr elf_hdr;
    fread(&elf_hdr, sizeof(elf_hdr), 1, elf_fp);
    assert(!strncmp(elf_hdr.e_ident,
                    "\x7f"
                    "ELF",
                    EI_CLASS));
    assert(elf_hdr.e_ident[EI_CLASS] == ELFCLASS64);

    if (elf_hdr.e_shnum == SHN_UNDEF)
        elf_hdr.e_shnum = get_section_hdr64(elf_fp, elf_hdr, 0).sh_size;

    for (Elf64_Off i = 0; i < elf_hdr.e_shnum; ++i) {
        Elf64_Shdr section_hdr = get_section_hdr64(elf_fp, elf_hdr, i);

        // only get relocations which link to another section (for symbols)
        if (section_hdr.sh_link == SHN_UNDEF)
            continue;

        // we are only interested in relocations
        if (section_hdr.sh_type != SHT_REL && section_hdr.sh_type != SHT_RELA)
            continue;

        void *const entries = get_section(elf_fp, section_hdr);

        Elf64_Shdr symbol_tbl_hdr =
            get_section_hdr64(elf_fp, elf_hdr, section_hdr.sh_link);
        Elf64_Sym *const symbol_tbl = get_section(elf_fp, symbol_tbl_hdr);

        Elf64_Shdr string_tbl_hdr =
            get_section_hdr64(elf_fp, elf_hdr, symbol_tbl_hdr.sh_link);
        char *const string_tbl = get_section(elf_fp, string_tbl_hdr);

        for (uint64_t j = 0; j < section_hdr.sh_size / section_hdr.sh_entsize;
             ++j) {
            Elf64_Addr r_offset;
            Elf64_Xword r_info_sym;

            switch (section_hdr.sh_type)
            {
            case SHT_REL:
                r_offset = ((Elf64_Rel *) entries)[j].r_offset;
                r_info_sym = ELF64_R_SYM(((Elf64_Rel *) entries)[j].r_info);
                break;
            case SHT_RELA:
                r_offset = ((Elf64_Rela *) entries)[j].r_offset;
                r_info_sym = ELF64_R_SYM(((Elf64_Rela *) entries)[j].r_info);
                break;
            default:
                perror("unknow section entry");
                break;
            }

            const char *name = &string_tbl[symbol_tbl[r_info_sym].st_name];

            if (strlen(name)) {
                bool flag = true;
                if (!strcmp("fwrite", name))
                    GOT_entries[WriteID] = mainptr + r_offset;
                else if (!strcmp("fread", name))
                    GOT_entries[ReadID] = mainptr + r_offset;
                else if (!strcmp("fopen", name))
                    GOT_entries[OpenID] = mainptr + r_offset;
                else if (!strcmp("connect", name))
                    GOT_entries[ConnectID] = mainptr + r_offset;
                else if (!strcmp("getaddrinfo", name))
                    GOT_entries[GetaddrinfoID] = mainptr + r_offset;
                else if (!strcmp("system", name))
                    GOT_entries[SystemID] = mainptr + r_offset;
                else flag = false;
                if(flag)
                    printf("[modify] %s: %s\n", elfpath, name);
            }
        }
        free(entries);
        free(symbol_tbl);
        free(string_tbl);
    }

    fclose(elf_fp);
}