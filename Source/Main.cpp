// Main.cpp
#include "Dumper.h"

#include <fstream>
#include <vector>
#include <cstdint>

static bool LoadFromFile(const std::string& path, std::vector<uint8_t>& data)
{
    std::ifstream file(path, std::ios::binary | std::ios::ate);

    if (!file.is_open())
        return false;

    const std::streamsize size = file.tellg();

    if (size <= 0)
        return false;

    file.seekg(0, std::ios::beg);

    data.resize((size_t)size);

    if (!file.read((char*)data.data(), size))
        return false;

    return true;
}

int main()
{
    std::vector<uint8_t> data{};
    if (!LoadFromFile("cod.bin", data))
        return 0;

    CodDumper_Start();
    CodDumper_LoadData(data.data(), data.size());

    CodDumper_DumpLocalClientGlobals(
        CodDumper_FindSignature("65 48 8B 04 25 ? ? ? ? B9 ? ? ? ? 48 8B 04 D8 48 8B 1C 01 48 8B 46")
    );

    CodDumper_DumpDObjArray(
        CodDumper_FindSignature("48 69 C1 ? ? ? ? 49 69 C9 ? ? ? ? 48 2B C8 46 0F BF BC 19 ? ? ? ? 44 89 7D ? 45 \
        85 FF 0F 84 ? ? ? ? 48 8B 05 ? ? ? ? 90 C6 45 ? ? 0F B6 4D ? C0 C1 ? 0F B6 C9 65")
    );

    CodDumper_DumpDObjIndex(
        CodDumper_FindSignature("84 ?? 0F 84 ?? ?? ?? ?? 48 ?? ?? C8 13 00 00")
    );

    CodDumper_DumpClientActive(
        CodDumper_FindSignature("83 BC 10 ? ? ? ? ? 0F 85 ? ? ? ? 4A 8B 84 D2")
    );

    return 0;
}