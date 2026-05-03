// Dump.h
#pragma once
#include <Common.h>

namespace Dump
{
	bool LoadDump(const char* path);

	bool Read(uintptr_t address, void* out, size_t size);
	bool Write(uintptr_t address, const void* in, size_t size);
	uint64_t FindSignature(const char* pattern);

	uint64_t GetImageBase();
	uint64_t GetImageSize();
	uint8_t* GetImageData();
};