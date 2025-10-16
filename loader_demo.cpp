#include <cstdio>
#include <cstdint>
#include <string>
#include "loader.hpp"

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        printf("Usage: %s <binary>\n", argv[0]);
        return 1;
    }

    std::string fname = argv[1];
    Binary bin;

    if (load_binary(fname, &bin, Binary::BIN_TYPE_AUTO) < 0)
    {
        fprintf(stderr, "failed to load binary '%s'\n", fname.c_str());
        return 1;
    }

    printf("loaded binary '%s' %s/%s (%u bits) entry@0x%016jx\n",
           bin.filename.c_str(),
           bin.type_str.c_str(), bin.arch_str.c_str(),
           bin.bits, bin.entry);

    for (auto &sec : bin.sections)
    {
        printf(" 0x%016jx %-8ju %-20s %s\n",
               sec.vma, sec.size, sec.name.c_str(),
               sec.type == Section::SEC_TYPE_CODE ? "CODE" : "DATA");
    }

    if (!bin.symbols.empty())
    {
        printf("scanned symbol tables\n");
        for (auto &sym : bin.symbols)
        {
            printf(" %-40s 0x%016jx %s\n",
                   sym.name.c_str(), sym.addr,
                   (sym.type & Symbol::SYM_TYPE_FUNC) ? "FUNC" : "");
        }
    }

    unload_binary(&bin);
    return 0;
}
