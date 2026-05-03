// Disassembler.h
#pragma once
#include <Common.h>

namespace Disassembler
{
	void DumpClientInfo(uint64_t address);
	void DumpClientBase(uint64_t address);
	void DumpBoneBase(uint64_t address);
	void DumpClientActive(uint64_t address);
	void DumpBoneIndex(uint64_t address);
}

