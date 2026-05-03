// Debugger.cpp
#include "Debugger.h"

namespace Debugger
{
	namespace 
	{
		uc_engine* gEngine = nullptr;
		bool gExceptionHit = false;
		const uint64_t kStackBase = 0x0000000080000000ULL;
		const size_t kStackSize = 0x200000;

		int ToUnicornReg(ZydisRegister reg)
		{
			if (ZydisRegisterGetWidth(ZYDIS_MACHINE_MODE_LONG_64, reg) == 32) {
				const ZyanI16 regId = ZydisRegisterGetId(reg);
				reg = ZydisRegisterEncode(ZYDIS_REGCLASS_GPR64, regId);
			}

			switch (reg)
			{
			case ZYDIS_REGISTER_RAX: return UC_X86_REG_RAX;
			case ZYDIS_REGISTER_RBX: return UC_X86_REG_RBX;
			case ZYDIS_REGISTER_RCX: return UC_X86_REG_RCX;
			case ZYDIS_REGISTER_RDX: return UC_X86_REG_RDX;
			case ZYDIS_REGISTER_RSI: return UC_X86_REG_RSI;
			case ZYDIS_REGISTER_RDI: return UC_X86_REG_RDI;
			case ZYDIS_REGISTER_RBP: return UC_X86_REG_RBP;
			case ZYDIS_REGISTER_RSP: return UC_X86_REG_RSP;
			case ZYDIS_REGISTER_R8: return UC_X86_REG_R8;
			case ZYDIS_REGISTER_R9: return UC_X86_REG_R9;
			case ZYDIS_REGISTER_R10: return UC_X86_REG_R10;
			case ZYDIS_REGISTER_R11: return UC_X86_REG_R11;
			case ZYDIS_REGISTER_R12: return UC_X86_REG_R12;
			case ZYDIS_REGISTER_R13: return UC_X86_REG_R13;
			case ZYDIS_REGISTER_R14: return UC_X86_REG_R14;
			case ZYDIS_REGISTER_R15: return UC_X86_REG_R15;
			default: return -1;
			}
		}

		void SeedRegisters()
		{
			uint64_t base = Dump::GetImageBase();
			uint64_t rsp = kStackBase + kStackSize - 0x1000;
			uint64_t rbp = rsp;
			uint64_t rflags = 0x202;

			uc_reg_write(gEngine, UC_X86_REG_RAX, &base);
			uc_reg_write(gEngine, UC_X86_REG_RBX, &base);
			uc_reg_write(gEngine, UC_X86_REG_RCX, &base);
			uc_reg_write(gEngine, UC_X86_REG_RDX, &base);
			uc_reg_write(gEngine, UC_X86_REG_RSI, &base);
			uc_reg_write(gEngine, UC_X86_REG_RDI, &base);
			uc_reg_write(gEngine, UC_X86_REG_R8, &base);
			uc_reg_write(gEngine, UC_X86_REG_R9, &base);
			uc_reg_write(gEngine, UC_X86_REG_R10, &base);
			uc_reg_write(gEngine, UC_X86_REG_R11, &base);
			uc_reg_write(gEngine, UC_X86_REG_R12, &base);
			uc_reg_write(gEngine, UC_X86_REG_R13, &base);
			uc_reg_write(gEngine, UC_X86_REG_R14, &base);
			uc_reg_write(gEngine, UC_X86_REG_R15, &base);
			uc_reg_write(gEngine, UC_X86_REG_RSP, &rsp);
			uc_reg_write(gEngine, UC_X86_REG_RBP, &rbp);
			uc_reg_write(gEngine, UC_X86_REG_EFLAGS, &rflags);
		}
	}

	bool Start(const char* dump_path)
	{
		if (!Dump::LoadDump(dump_path)) 
		{
			DEBUG("Failed to load dump file: %s\n", dump_path);
			return false;
		}

		const size_t mappedSize = (Dump::GetImageSize() + 0xFFF) & ~static_cast<size_t>(0xFFF);
		if (uc_open(UC_ARCH_X86, UC_MODE_64, &gEngine) != UC_ERR_OK) 
		{
			DEBUG("Failed to initialize Unicorn.\n");
			return false;
		}

		if (uc_mem_map(gEngine, Dump::GetImageBase(), mappedSize, UC_PROT_ALL) != UC_ERR_OK) 
		{
			DEBUG("Failed to map image into Unicorn.\n");
			Destroy();
			return false;
		}
		uc_mem_write(gEngine, Dump::GetImageBase(), Dump::GetImageData(), Dump::GetImageSize());

		if (uc_mem_map(gEngine, kStackBase, kStackSize, UC_PROT_ALL) != UC_ERR_OK)
		{
			DEBUG("Failed to map emulated stack.\n");
			Destroy();
			return false;
		}

		SeedRegisters();
		gExceptionHit = false;
		return true;
	}

	void Destroy()
	{
		if (gEngine) 
		{
			uc_close(gEngine);
			gEngine = nullptr;
		}
	}

	CONTEXT GetContext()
	{
		CONTEXT context{};
		context.ContextFlags = CONTEXT_ALL;
		if (!gEngine) 
			return context;

		uc_reg_read(gEngine, UC_X86_REG_RAX, &context.Rax);
		uc_reg_read(gEngine, UC_X86_REG_RBX, &context.Rbx);
		uc_reg_read(gEngine, UC_X86_REG_RCX, &context.Rcx);
		uc_reg_read(gEngine, UC_X86_REG_RDX, &context.Rdx);
		uc_reg_read(gEngine, UC_X86_REG_RSI, &context.Rsi);
		uc_reg_read(gEngine, UC_X86_REG_RDI, &context.Rdi);
		uc_reg_read(gEngine, UC_X86_REG_RBP, &context.Rbp);
		uc_reg_read(gEngine, UC_X86_REG_RSP, &context.Rsp);
		uc_reg_read(gEngine, UC_X86_REG_R8, &context.R8);
		uc_reg_read(gEngine, UC_X86_REG_R9, &context.R9);
		uc_reg_read(gEngine, UC_X86_REG_R10, &context.R10);
		uc_reg_read(gEngine, UC_X86_REG_R11, &context.R11);
		uc_reg_read(gEngine, UC_X86_REG_R12, &context.R12);
		uc_reg_read(gEngine, UC_X86_REG_R13, &context.R13);
		uc_reg_read(gEngine, UC_X86_REG_R14, &context.R14);
		uc_reg_read(gEngine, UC_X86_REG_R15, &context.R15);
		uc_reg_read(gEngine, UC_X86_REG_RIP, &context.Rip);
		uc_reg_read(gEngine, UC_X86_REG_EFLAGS, &context.EFlags);
		return context;
	}

	bool SetContext(CONTEXT* context)
	{
		if (!gEngine || !context)
			return false;

		uc_reg_write(gEngine, UC_X86_REG_RAX, &context->Rax);
		uc_reg_write(gEngine, UC_X86_REG_RBX, &context->Rbx);
		uc_reg_write(gEngine, UC_X86_REG_RCX, &context->Rcx);
		uc_reg_write(gEngine, UC_X86_REG_RDX, &context->Rdx);
		uc_reg_write(gEngine, UC_X86_REG_RSI, &context->Rsi);
		uc_reg_write(gEngine, UC_X86_REG_RDI, &context->Rdi);
		uc_reg_write(gEngine, UC_X86_REG_RBP, &context->Rbp);
		uc_reg_write(gEngine, UC_X86_REG_RSP, &context->Rsp);
		uc_reg_write(gEngine, UC_X86_REG_R8, &context->R8);
		uc_reg_write(gEngine, UC_X86_REG_R9, &context->R9);
		uc_reg_write(gEngine, UC_X86_REG_R10, &context->R10);
		uc_reg_write(gEngine, UC_X86_REG_R11, &context->R11);
		uc_reg_write(gEngine, UC_X86_REG_R12, &context->R12);
		uc_reg_write(gEngine, UC_X86_REG_R13, &context->R13);
		uc_reg_write(gEngine, UC_X86_REG_R14, &context->R14);
		uc_reg_write(gEngine, UC_X86_REG_R15, &context->R15);
		uc_reg_write(gEngine, UC_X86_REG_RIP, &context->Rip);
		uint64_t eflags = static_cast<uint64_t>(context->EFlags);
		uc_reg_write(gEngine, UC_X86_REG_EFLAGS, &eflags);
		return true;
	}

	bool SetRIP(uint64_t address)
	{
		CONTEXT c = GetContext();
		c.Rip = address;
		return SetContext(&c);
	}

	void SetRegisterValue(ZydisRegister reg, uint64_t val)
	{
		const int ucReg = ToUnicornReg(reg);
		if (ucReg != -1)
			uc_reg_write(gEngine, ucReg, &val);
	}

	uint64_t SingleStep()
	{
		gExceptionHit = false;
		CONTEXT c = GetContext();
		uc_err err = uc_emu_start(gEngine, c.Rip, 0, 0, 1);
		if (err != UC_ERR_OK) 
		{
			gExceptionHit = true;
			return c.Rip;
		}
		return GetContext().Rip;
	}

	bool DidExceptionHit()
	{
		return gExceptionHit;
	}

	void ClearException()
	{
		gExceptionHit = false;
	}

	bool Read(uint64_t address, void* buffer, size_t size)
	{
		return Dump::Read(address, buffer, size);
	}

	void Write(uint64_t address, const void* buffer, size_t size)
	{
		Dump::Write(address, buffer, size);
		uc_mem_write(gEngine, address, buffer, size);
	}
}