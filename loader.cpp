#include <bfd.h>
#include "loader.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>

/* Forward declarations of internal helpers */
static bfd *open_bfd(std::string &fname);
static int load_binary_bfd(std::string &fname, Binary *bin, Binary::BinaryType type);
static int load_symbols_bfd(bfd *bfd_h, Binary *bin);
static int load_dynsym_bfd(bfd *bfd_h, Binary *bin);
static int load_sections_bfd(bfd *bfd_h, Binary *bin);

int load_binary(std::string &fname, Binary *bin, Binary::BinaryType type)
{
    return load_binary_bfd(fname, bin, type);
}

void unload_binary(Binary *bin)
{
    for (size_t i = 0; i < bin->sections.size(); ++i)
    {
        Section *sec = &bin->sections[i];
        if (sec->bytes)
        {
            free(sec->bytes);
            sec->bytes = nullptr;
        }
    }
    bin->sections.clear();
    bin->symbols.clear();
}

/* --- open_bfd: initialize bfd and open file --- */
static bfd *open_bfd(std::string &fname)
{
    static int bfd_inited = 0;
    if (!bfd_inited)
    {
        bfd_init();
        bfd_inited = 1;
    }

    bfd *bfd_h = bfd_openr(fname.c_str(), NULL);
    if (!bfd_h)
    {
        fprintf(stderr, "failed to open binary '%s' (%s)\n", fname.c_str(),
                bfd_errmsg(bfd_get_error()));
        return nullptr;
    }

    if (!bfd_check_format(bfd_h, bfd_object))
    {
        fprintf(stderr, "file '%s' does not look like an executable (%s)\n",
                fname.c_str(), bfd_errmsg(bfd_get_error()));
        bfd_close(bfd_h);
        return nullptr;
    }

    /* Workaround for some libbfd versions */
    bfd_set_error(bfd_error_no_error);

    if (bfd_get_flavour(bfd_h) == bfd_target_unknown_flavour)
    {
        fprintf(stderr, "unrecognized format for binary '%s' (%s)\n",
                fname.c_str(), bfd_errmsg(bfd_get_error()));
        bfd_close(bfd_h);
        return nullptr;
    }

    return bfd_h;
}

/* --- load_binary_bfd: parse header, arch, symbols, sections --- */
static int load_binary_bfd(std::string &fname, Binary *bin, Binary::BinaryType type)
{
    int ret = -1;
    bfd *bfd_h = nullptr;
    const bfd_arch_info_type *bfd_info = nullptr;

    bfd_h = open_bfd(fname);
    if (!bfd_h)
    {
        goto cleanup;
    }

    bin->filename = fname;
    bin->entry = bfd_get_start_address(bfd_h);
    if (bfd_h->xvec && bfd_h->xvec->name)
        bin->type_str = std::string(bfd_h->xvec->name);
    else
        bin->type_str = "unknown";

    switch (bfd_h->xvec->flavour)
    {
    case bfd_target_elf_flavour:
        bin->type = Binary::BIN_TYPE_ELF;
        break;
    case bfd_target_coff_flavour:
        bin->type = Binary::BIN_TYPE_PE;
        break;
    default:
        fprintf(stderr, "unsupported binary type (%s)\n", bfd_h->xvec->name);
        goto cleanup;
    }

    bfd_info = bfd_get_arch_info(bfd_h);
    if (!bfd_info)
    {
        fprintf(stderr, "failed to get arch info (%s)\n", bfd_errmsg(bfd_get_error()));
        goto cleanup;
    }

    bin->arch_str = std::string(bfd_info->printable_name ? bfd_info->printable_name : "unknown");

    switch (bfd_info->mach)
    {
    case bfd_mach_i386_i386:
        bin->arch = Binary::ARCH_X86;
        bin->bits = 32;
        break;
    case bfd_mach_x86_64:
        bin->arch = Binary::ARCH_X86;
        bin->bits = 64;
        break;
    default:
        fprintf(stderr, "unsupported architecture (%s)\n", bfd_info->printable_name);
        goto cleanup;
    }

    /* Best-effort symbol loading */
    load_symbols_bfd(bfd_h, bin);
    load_dynsym_bfd(bfd_h, bin);

    if (load_sections_bfd(bfd_h, bin) < 0)
    {
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (bfd_h)
        bfd_close(bfd_h);
    return ret;
}

/* --- load static symbol table --- */
static int load_symbols_bfd(bfd *bfd_h, Binary *bin)
{
    long n = bfd_get_symtab_upper_bound(bfd_h);
    if (n <= 0)
        return 0; /* no static symbol table or error */

    asymbol **bfd_symtab = (asymbol **)malloc(n);
    if (!bfd_symtab)
    {
        fprintf(stderr, "out of memory\n");
        return -1;
    }

    long nsyms = bfd_canonicalize_symtab(bfd_h, bfd_symtab);
    if (nsyms < 0)
    {
        fprintf(stderr, "failed to read symtab (%s)\n", bfd_errmsg(bfd_get_error()));
        free(bfd_symtab);
        return -1;
    }

    for (long i = 0; i < nsyms; ++i)
    {
        if (bfd_symtab[i] && (bfd_symtab[i]->flags & BSF_FUNCTION))
        {
            bin->symbols.push_back(Symbol());
            Symbol *sym = &bin->symbols.back();
            sym->type = Symbol::SYM_TYPE_FUNC;
            sym->name = bfd_symtab[i]->name ? std::string(bfd_symtab[i]->name) : std::string();
            sym->addr = bfd_asymbol_value(bfd_symtab[i]);
        }
    }

    free(bfd_symtab);
    return 0;
}

/* --- load dynamic symbol table --- */
static int load_dynsym_bfd(bfd *bfd_h, Binary *bin)
{
    long n = bfd_get_dynamic_symtab_upper_bound(bfd_h);
    if (n <= 0)
        return 0; /* no dynamic symbol table */

    asymbol **bfd_dynsym = (asymbol **)malloc(n);
    if (!bfd_dynsym)
    {
        fprintf(stderr, "out of memory\n");
        return -1;
    }

    long nsyms = bfd_canonicalize_dynamic_symtab(bfd_h, bfd_dynsym);
    if (nsyms < 0)
    {
        fprintf(stderr, "failed to read dynamic symtab (%s)\n", bfd_errmsg(bfd_get_error()));
        free(bfd_dynsym);
        return -1;
    }

    for (long i = 0; i < nsyms; ++i)
    {
        if (bfd_dynsym[i] && (bfd_dynsym[i]->flags & BSF_FUNCTION))
        {
            bin->symbols.push_back(Symbol());
            Symbol *sym = &bin->symbols.back();
            sym->type = Symbol::SYM_TYPE_FUNC;
            sym->name = bfd_dynsym[i]->name ? std::string(bfd_dynsym[i]->name) : std::string();
            sym->addr = bfd_asymbol_value(bfd_dynsym[i]);
        }
    }

    free(bfd_dynsym);
    return 0;
}

/* --- load sections (code and data) --- */
static int load_sections_bfd(bfd *bfd_h, Binary *bin)
{
    for (asection *bfd_sec = bfd_h->sections; bfd_sec; bfd_sec = bfd_sec->next)
    {
        int flags = bfd_section_flags(bfd_sec);
        Section::SectionType sectype = Section::SEC_TYPE_NONE;

        if (flags & SEC_CODE)
            sectype = Section::SEC_TYPE_CODE;
        else if (flags & SEC_DATA)
            sectype = Section::SEC_TYPE_DATA;
        else
            continue;

        uint64_t vma = bfd_section_vma(bfd_sec);
        bfd_size_type size = bfd_section_size(bfd_sec);
        const char *secname = bfd_section_name(bfd_sec);
        if (!secname)
            secname = "<unnamed>";

        Section sec;
        sec.binary = bin;
        sec.name = std::string(secname);
        sec.type = sectype;
        sec.vma = (uint64_t)vma;
        sec.size = (uint64_t)size;

        if (size == 0)
        {
            sec.bytes = nullptr;
            bin->sections.push_back(sec);
            continue;
        }

        sec.bytes = (uint8_t *)malloc((size_t)size);
        if (!sec.bytes)
        {
            fprintf(stderr, "out of memory while allocating section '%s'\n", sec.name.c_str());
            return -1;
        }

        if (!bfd_get_section_contents(bfd_h, bfd_sec, sec.bytes, 0, size))
        {
            fprintf(stderr, "failed to read section '%s' (%s)\n", sec.name.c_str(), bfd_errmsg(bfd_get_error()));
            free(sec.bytes);
            return -1;
        }

        bin->sections.push_back(sec);
    }

    return 0;
}
