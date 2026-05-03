// Dump.cpp
#include "Dump.h"
#include <fstream>

std::vector<uint8_t> gRawData = {};
std::vector<uint8_t> gImageData = {};
uint64_t            gImageBase = {};
size_t               gImageSize = {};

bool Dump::LoadDump(const char* path)
{
	gRawData.clear();
	gImageData.clear();
	gImageBase = 0;
	gImageSize = 0;

	std::ifstream file(path, std::ios::binary | std::ios::ate);
	if (!file.is_open()) {
		return false;
	}

	const auto rawSize = static_cast<size_t>(file.tellg());
	file.seekg(0, std::ios::beg);
	gRawData.resize(rawSize);
	if (!file.read(reinterpret_cast<char*>(gRawData.data()), static_cast<std::streamsize>(rawSize))) {
		gRawData.clear();
		return false;
	}

	if (gRawData.size() < sizeof(IMAGE_DOS_HEADER)) {
		return false;
	}

	const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(gRawData.data());
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
		return false;
	}

	if (static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > gRawData.size()) {
		return false;
	}

	const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(gRawData.data() + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE) {
		return false;
	}

	gImageBase = static_cast<uint64_t>(nt->OptionalHeader.ImageBase);
	gImageSize = static_cast<size_t>(nt->OptionalHeader.SizeOfImage);
	gImageData.assign(gImageSize, 0);

	const size_t headerSize = min(static_cast<size_t>(nt->OptionalHeader.SizeOfHeaders), gRawData.size());
	memcpy(gImageData.data(), gRawData.data(), headerSize);

	auto* sections = IMAGE_FIRST_SECTION(const_cast<PIMAGE_NT_HEADERS64>(nt));
	for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
		const auto& section = sections[i];
		if (section.PointerToRawData == 0 || section.SizeOfRawData == 0) {
			continue;
		}

		const size_t srcOffset = static_cast<size_t>(section.PointerToRawData);
		const size_t srcSize = static_cast<size_t>(section.SizeOfRawData);
		const size_t dstOffset = static_cast<size_t>(section.VirtualAddress);
		if (srcOffset >= gRawData.size() || dstOffset >= gImageData.size()) {
			continue;
		}

		const size_t safeSrc = min(srcSize, gRawData.size() - srcOffset);
		const size_t safeDst = min(safeSrc, gImageData.size() - dstOffset);
		memcpy(gImageData.data() + dstOffset, gRawData.data() + srcOffset, safeDst);
	}

	return true;
}

uint64_t Dump::FindSignature(const char* pattern)
{
	auto pattern_to_bytes = [](const char* pat)
		{
			std::vector<int> bytes;
			bytes.reserve(256);

			const char* cur = pat;
			while (*cur)
			{
				if (*cur == ' ') { ++cur; continue; }

				if (*cur == '?')
				{
					++cur;
					if (*cur == '?') ++cur;
					bytes.push_back(-1);
				}
				else
				{
					bytes.push_back(strtoul(cur, const_cast<char**>(&cur), 16));
				}
			}
			return bytes;
		};

	const auto sig = pattern_to_bytes(pattern);
	const size_t sigSize = sig.size();
	if (!sigSize)
		return 0;

	uint8_t* data = gImageData.data();
	size_t size = gImageData.size();

	int first = sig[0];
	bool firstWildcard = (first == -1);

	size_t max = size - sigSize;

	for (size_t i = 0; i <= max; ++i)
	{
		if (!firstWildcard && data[i] != (uint8_t)first)
			continue;

		size_t j = 1;
		for (; j < sigSize; ++j)
		{
			if (sig[j] != -1 && data[i + j] != (uint8_t)sig[j])
				break;
		}

		if (j == sigSize)
			return gImageBase + i;
	}

	return 0;
}

bool Dump::Read(uint64_t address, void* out, size_t size)
{
	if (!out || size == 0 || address < gImageBase) {
		return false;
	}

	const auto offset = static_cast<size_t>(address - gImageBase);
	if (offset > gImageData.size() || size > (gImageData.size() - offset)) {
		return false;
	}

	memcpy(out, gImageData.data() + offset, size);
	return true;
}

bool Dump::Write(uint64_t address, const void* in, size_t size)
{
	if (!in || size == 0 || address < gImageBase) {
		return false;
	}

	const auto offset = static_cast<size_t>(address - gImageBase);
	if (offset > gImageData.size() || size > (gImageData.size() - offset)) {
		return false;
	}

	memcpy(gImageData.data() + offset, in, size);
	return true;
}

uint64_t Dump::GetImageBase()
{
	return gImageBase;
}

uint64_t Dump::GetImageSize()
{
	return gImageSize;
}

uint8_t* Dump::GetImageData()
{
	return gImageData.empty() ? nullptr : gImageData.data();
}
