// Debugger.h
#pragma once
#include <Common.h>
#include <Dump.h>

#include <Zydis/Zydis.h>
#include <unicorn/unicorn.h>

namespace Debugger
{
	bool Start(const char* dump_path);
	void Destroy();

	CONTEXT GetContext();
	bool SetContext(CONTEXT* context);

	bool SetRIP(uintptr_t address);
	void SetRegisterValue(ZydisRegister reg, uintptr_t val);
	uintptr_t SingleStep();

	bool DidExceptionHit();
	void ClearException();

	bool Read(uintptr_t address, void* buffer, size_t size);
	void Write(uintptr_t address, const void* buffer, size_t size);

	template<typename T>
	T Read(uintptr_t address) 
	{
		T buffer{};
		Read(address, &buffer, sizeof(T));
		return buffer;
	}

	template<typename T>
	void Write(uintptr_t address, T value) 
	{
		Write(address, &value, sizeof(T));
	}
}