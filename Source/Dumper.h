// Dumper.h
#pragma once
#include <stdint.h>

void CodDumper_Start();
void CodDumper_Destroy();

void CodDumper_LoadData(uint8_t* data, uint64_t size);
uint64_t CodDumper_FindSignature(const char* pattern);

void CodDumper_DumpLocalClientGlobals(uint64_t address);
void CodDumper_DumpDObjArray(uint64_t address);
void CodDumper_DumpDObjIndex(uint64_t address);
void CodDumper_DumpClientActive(uint64_t address);
