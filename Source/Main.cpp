// Main.cpp

// see Config.h to change settings
#include "Config.h"

#include "Debugger.h"
#include "Disassembler.h"

int main()
{
    if (!Debugger::Start(DUMP_PATH))
        return 0;

    Disassembler::DumpClientInfo(Dump::FindSignature("65 48 8B 04 25 ? ? ? ? B9 ? ? ? ? 48 8B 04 D8 48 8B 1C 01 48 8B 46"));
    Disassembler::DumpClientBase(Dump::FindSignature("4C 8B 83 ? ? ? ? 90 C6 44 24 ? ? 0F B6 44 24"));
    Disassembler::DumpBoneBase(Dump::FindSignature("42 0F BF 84 11 ? ? ? ? 89 44 24 ? 85 C0 0F 84 ? ? ? ? 48 8B 15"));
    Disassembler::DumpBoneIndex(Dump::FindSignature("84 ?? 0F 84 ?? ?? ?? ?? 48 ?? ?? C8 13 00 00"));
    Disassembler::DumpClientActive(Dump::FindSignature("83 BC 10 ? ? ? ? ? 0F 85 ? ? ? ? 4A 8B 84 D2"));

    getchar();
    return 0;
}