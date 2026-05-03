// Disassembler.cpp
#include "Disassembler.h"
#include "Debugger.h"
#include <Config.h>

#include <map>
#include <sstream>
#include <regex>

struct InstructionTrace
{
	ZydisDecodedInstruction instruction;
	std::map<ZydisRegister, uint32_t> last_modified;
	std::map<int, uint32_t> rsp_stack_map;
	std::map<int, uint32_t> rbp_stack_map;
	uint64_t rip;
	CONTEXT context;
	bool used;
};

namespace Disassembler
{
	namespace
	{
		std::vector<ZydisRegister> ignore_trace;
		ZydisDecoder decoder;
		ZydisFormatter formatter;
		bool decoder_initialized = false;

		void EnsureDecoderInitialized()
		{
			if (decoder_initialized)
				return;
			ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
			ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
			decoder_initialized = true;
		}

		ZydisDecodedInstruction Decode(uint64_t rip)
		{
			EnsureDecoderInitialized();
			ZydisDecodedInstruction instruction;
			BYTE bRead[20];
			Debugger::Read(rip, bRead, 20);

			if (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(
				&decoder, bRead, 20,
				&instruction)))
			{
				return instruction;
			}
			memset(&instruction, 0, sizeof(ZydisDecodedInstruction));
			return instruction;
		}

		void SkipOverUntilInstruction(uint64_t& rip, ZydisMnemonic mnemonic)
		{
			ZydisDecodedInstruction instruction = Decode(rip);
			while (instruction.mnemonic != mnemonic)
			{
				rip += instruction.length;
				instruction = Decode(rip);
			}
			rip += instruction.length;
			Debugger::SetRIP(rip);
		}

		void SkipUntilInstruction(uint64_t& rip, ZydisMnemonic mnemonic)
		{
			ZydisDecodedInstruction instruction = Decode(rip);
			while (instruction.mnemonic != mnemonic)
			{
				rip += instruction.length;
				instruction = Decode(rip);
			}
			Debugger::SetRIP(rip);
		}

		void RunUntilInstruction(uint64_t& rip, ZydisMnemonic mnemonic)
		{
			ZydisDecodedInstruction instruction = Decode(rip);
			while (instruction.mnemonic != mnemonic)
			{
				uint64_t nextRip = Debugger::SingleStep();
				if (Debugger::DidExceptionHit())
				{
					rip += instruction.length;
					Debugger::SetRIP(rip);
					Debugger::ClearException();
				}
				rip = nextRip;
				instruction = Decode(rip);
			}
		}

		ZydisRegister To64BitRegister(ZydisRegister reg)
		{
			if (ZydisRegisterGetWidth(ZYDIS_MACHINE_MODE_LONG_64, reg) == 32)
			{
				ZyanI16 regID = ZydisRegisterGetId(reg);
				reg = ZydisRegisterEncode(ZYDIS_REGCLASS_GPR64, regID);
			}
			return reg;
		}

		std::string Get64BitRegisterString(ZydisRegister reg)
		{
			return ZydisRegisterGetString(To64BitRegister(reg));
		}

		void GetModifiedRegisters(ZydisDecodedInstruction instruction, ZydisRegister reg[8])
		{
			for (uint32_t i = 0; i < instruction.operand_count; i++)
			{
				if (instruction.operands[i].visibility == ZydisOperandVisibility::ZYDIS_OPERAND_VISIBILITY_EXPLICIT
					|| To64BitRegister(instruction.operands[i].reg.value) == ZydisRegister::ZYDIS_REGISTER_RAX
					|| instruction.mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_AND
					|| instruction.mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_MUL)
				{
					if (instruction.operands[i].type == ZydisOperandType::ZYDIS_OPERAND_TYPE_REGISTER)
					{
						if (instruction.operands[i].actions & ZydisOperandAction::ZYDIS_OPERAND_ACTION_WRITE)
						{
							reg[i] = To64BitRegister(instruction.operands[i].reg.value);
						}
					}
					else if (instruction.operands[i].type == ZydisOperandType::ZYDIS_OPERAND_TYPE_MEMORY)
					{
						if (instruction.operands[i].actions & ZydisOperandAction::ZYDIS_OPERAND_ACTION_WRITE)
						{
							reg[i] = To64BitRegister(instruction.operands[i].mem.base);
						}
					}
				}
			}
		}

		void GetAccessedRegisters(ZydisDecodedInstruction instruction, ZydisRegister reg[8])
		{
			for (uint32_t i = 0; i < instruction.operand_count; i++)
			{
				if (instruction.operands[i].visibility == ZydisOperandVisibility::ZYDIS_OPERAND_VISIBILITY_EXPLICIT
					|| To64BitRegister(instruction.operands[i].reg.value) == ZydisRegister::ZYDIS_REGISTER_RAX
					|| instruction.mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_AND
					|| instruction.mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_MUL)
				{
					if (instruction.operands[i].type == ZydisOperandType::ZYDIS_OPERAND_TYPE_REGISTER)
					{
						if (instruction.operands[i].actions & ZydisOperandAction::ZYDIS_OPERAND_ACTION_READ)
						{
							reg[i] = To64BitRegister(instruction.operands[i].reg.value);
						}
					}
					else if (instruction.operands[i].type == ZydisOperandType::ZYDIS_OPERAND_TYPE_MEMORY)
					{
						if (instruction.operands[i].actions & ZydisOperandAction::ZYDIS_OPERAND_ACTION_READ || (instruction.mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_LEA && i > 0))
						{
							if (instruction.operands[i].mem.base != ZydisRegister::ZYDIS_REGISTER_RIP && instruction.operands[i].mem.base != ZydisRegister::ZYDIS_REGISTER_RBP && instruction.operands[i].mem.base != ZydisRegister::ZYDIS_REGISTER_RSP)
							{
								reg[i] = To64BitRegister(instruction.operands[i].mem.base);
							}
							if (instruction.operands[i].mem.index)
							{
								reg[i + 4] = To64BitRegister(instruction.operands[i].mem.index);
							}
						}
					}
				}
			}
		}

		std::string GetInstructionText(ZydisDecodedInstruction& instruction)
		{
			EnsureDecoderInitialized();
			char DisassembledString[256];
			ZydisFormatterFormatInstruction(&formatter, &instruction, DisassembledString, sizeof(DisassembledString), 0);
			return std::string(DisassembledString);
		}

		std::string AsmToCPP(ZydisDecodedInstruction instruction, uint64_t rip, const char* stack_trace_name = nullptr)
		{
			std::stringstream ss;
			ZydisRegister r1 = instruction.operands[0].reg.value;
			ZydisRegister r2 = instruction.operands[1].reg.value;
			ZydisRegister r3 = instruction.operands[2].reg.value;
			ZydisRegister r4 = instruction.operands[3].reg.value;
			switch (instruction.mnemonic)
			{
			case ZYDIS_MNEMONIC_LEA:
				if (instruction.operands[1].mem.base == ZYDIS_REGISTER_RIP)
				{
					ss << Get64BitRegisterString(r1) << " = " << "BaseAddress";
					if ((rip + instruction.operands[1].mem.disp.value + instruction.length) - Dump::GetImageBase() != 0)
						ss << " + 0x" << std::hex << std::uppercase << (rip + instruction.operands[1].mem.disp.value + instruction.length) - Dump::GetImageBase();
				}
				else if (instruction.operands[1].mem.index != 0 && instruction.operands[1].mem.scale != 0)
				{
					if (instruction.operands[1].mem.base != ZydisRegister::ZYDIS_REGISTER_NONE)
						ss << Get64BitRegisterString(r1) << " = " << Get64BitRegisterString(instruction.operands[1].mem.base) << " + " << Get64BitRegisterString(instruction.operands[1].mem.index) << " * " << (int)instruction.operands[1].mem.scale;
					else
						ss << Get64BitRegisterString(r1) << " = " << Get64BitRegisterString(instruction.operands[1].mem.index) << " * " << (int)instruction.operands[1].mem.scale << " + 0x" << instruction.operands[1].mem.disp.value;
				}
				else
				{
					ss << Get64BitRegisterString(r1) << " = " << Get64BitRegisterString(instruction.operands[1].mem.base) << " + 0x" << std::hex << instruction.operands[1].mem.disp.value;
				}
				break;
			case ZYDIS_MNEMONIC_MOV:
				if (instruction.operands[0].type == ZydisOperandType::ZYDIS_OPERAND_TYPE_REGISTER)
				{
					switch (instruction.operands[1].type)
					{
					case ZydisOperandType::ZYDIS_OPERAND_TYPE_REGISTER:
						ss << Get64BitRegisterString(r1) << " = " << Get64BitRegisterString(r2);
						break;
					case ZydisOperandType::ZYDIS_OPERAND_TYPE_MEMORY:
						if (instruction.operands[1].mem.segment == ZYDIS_REGISTER_GS)
						{
							ss << Get64BitRegisterString(r1) << " = " << "PebAddress";
						}
						else if (instruction.operands[1].mem.base == ZYDIS_REGISTER_RIP && instruction.operands[1].mem.disp.has_displacement)
						{
							ss << Get64BitRegisterString(r1) << " = " << "mem.Read<uint64_t>(BaseAddress + 0x" << std::hex << std::uppercase << (rip + instruction.operands[1].mem.disp.value + instruction.length) - Dump::GetImageBase() << ")";
						}
						else if (stack_trace_name) {
							ss << Get64BitRegisterString(r1) << " = " << stack_trace_name;
						}
						else if (instruction.operands[1].mem.disp.has_displacement)
						{
							ss << Get64BitRegisterString(r1) << " = mem.Read<uint64_t>(" << Get64BitRegisterString(instruction.operands[1].mem.base) << " + 0x" << std::hex << instruction.operands[1].mem.disp.value << ")";
						}
						else
						{
							ss << Get64BitRegisterString(r1) << " = mem.Read<uint64_t>(" << Get64BitRegisterString(instruction.operands[1].mem.base) << ")";
						}
						break;
					case ZydisOperandType::ZYDIS_OPERAND_TYPE_IMMEDIATE:
						if (instruction.operands[1].imm.is_signed)
							ss << Get64BitRegisterString(r1) << " = " << "0x" << std::hex << std::uppercase << instruction.operands[1].imm.value.s;
						else
							ss << Get64BitRegisterString(r1) << " = " << "0x" << std::hex << std::uppercase << instruction.operands[1].imm.value.u;
						break;
					default:
						break;
					}
				}

				break;

			case ZYDIS_MNEMONIC_MOVZX:
			case ZYDIS_MNEMONIC_MOVSX:
				if (instruction.operand_count == 2 && instruction.operands[1].mem.base != 0 && instruction.operands[1].mem.index != 0 && instruction.operands[1].mem.disp.value != 0)
				{
					ss << Get64BitRegisterString(r1) << " = mem.Read<uint16_t>(" << std::uppercase << Get64BitRegisterString(instruction.operands[1].mem.base) << " + " << Get64BitRegisterString(instruction.operands[1].mem.index) << " * "
						<< (int)instruction.operands[1].mem.scale << " + 0x" << std::hex << instruction.operands[1].mem.disp.value << ")";
				}
				else if (stack_trace_name) {
					ss << Get64BitRegisterString(r1) << " = " << stack_trace_name;
				}
				else
					ss << GetInstructionText(instruction);

				break;
			case ZYDIS_MNEMONIC_ROR:
				ss << Get64BitRegisterString(r1) << " = _rotr64(" << Get64BitRegisterString(r1) << ", 0x" << std::hex << std::uppercase << instruction.operands[1].imm.value.u << ")";
				break;
			case ZYDIS_MNEMONIC_ROL:
				ss << Get64BitRegisterString(r1) << " = _rotl64(" << Get64BitRegisterString(r1) << ", 0x" << std::hex << std::uppercase << instruction.operands[1].imm.value.u << ")";
				break;
			case ZYDIS_MNEMONIC_SHR:
				ss << Get64BitRegisterString(r1) << " >>= 0x" << std::hex << std::uppercase << instruction.operands[1].imm.value.s;
				break;
			case ZYDIS_MNEMONIC_SHL:
				ss << Get64BitRegisterString(r1) << " <<= 0x" << std::hex << std::uppercase << instruction.operands[1].imm.value.s;
				break;
			case ZYDIS_MNEMONIC_SUB:
				if (instruction.operand_count == 3 && r2 != 0)
				{
					ss << Get64BitRegisterString(r1) << " -= " << Get64BitRegisterString(r2);
				}
				else if (instruction.operand_count >= 2 && instruction.operands[1].imm.value.s != 0)
				{
					if (instruction.operands[1].imm.is_signed)
						ss << Get64BitRegisterString(r1) << " -= 0x" << std::hex << std::uppercase << instruction.operands[1].imm.value.s;
					else
						ss << Get64BitRegisterString(r1) << " -= 0x" << std::hex << std::uppercase << instruction.operands[1].imm.value.u;
				}
				else if (stack_trace_name) {
					ss << Get64BitRegisterString(r1) << " -= " << stack_trace_name;
				}
				else
					ss << GetInstructionText(instruction);
				break;
			case ZYDIS_MNEMONIC_ADD:
				if (instruction.operand_count == 3 && r2 != 0)
				{
					ss << Get64BitRegisterString(r1) << " += " << std::uppercase << Get64BitRegisterString(r2);
				}
				else if (instruction.operand_count >= 2 && instruction.operands[1].imm.value.s != 0)
				{
					if (instruction.operands[1].imm.is_signed)
						ss << Get64BitRegisterString(r1) << " += 0x" << std::hex << std::uppercase << instruction.operands[1].imm.value.s;
					else
						ss << Get64BitRegisterString(r1) << " += 0x" << std::hex << std::uppercase << instruction.operands[1].imm.value.u;
				}
				else if (stack_trace_name) {
					ss << Get64BitRegisterString(r1) << " += " << stack_trace_name;
				}
				else
					ss << GetInstructionText(instruction);
				break;
			case ZYDIS_MNEMONIC_AND:
				if (instruction.operands[1].imm.value.s != 0 && instruction.operands[0].reg.value != 0)
				{
					if (instruction.operands[1].imm.value.s != 0xffffffffc0000000) {
						if (instruction.operands[1].imm.is_signed) {
							ss << Get64BitRegisterString(r1) << " " << " &= 0x" << std::hex << instruction.operands[1].imm.value.s;
						}
						else {
							ss << Get64BitRegisterString(r1) << " " << " &= 0x" << std::hex << instruction.operands[1].imm.value.u;
						}
					}
					else
						ss << Get64BitRegisterString(r1) << " = 0";
				}
				else if (instruction.operands[0].reg.value != 0 && r2 != 0)
				{
					ss << Get64BitRegisterString(r1) << " &= " << Get64BitRegisterString(r2);
				}
				else
				{
					ss << GetInstructionText(instruction);
				}

				break;
			case ZYDIS_MNEMONIC_XOR:
				if (stack_trace_name) {
					ss << Get64BitRegisterString(r1) << " ^= " << stack_trace_name;
				}
				else if (instruction.operands[1].mem.disp.value != 0)
				{
					ss << Get64BitRegisterString(r1) << " ^= " << "mem.Read<uint64_t>(BaseAddress + 0x" << std::hex << std::uppercase << (rip + instruction.operands[1].mem.disp.value + instruction.length) - Dump::GetImageBase() << ")";
				}
				else
				{
					ss << Get64BitRegisterString(r1) << " ^= " << Get64BitRegisterString(r2);
				}

				break;
			case ZYDIS_MNEMONIC_BSWAP:
				ss << Get64BitRegisterString(r1) << " = _byteswap_uint64(" << Get64BitRegisterString(r1) << ")";
				break;
			case ZYDIS_MNEMONIC_NOT:
				ss << Get64BitRegisterString(r1) << " = ~" << Get64BitRegisterString(r1);
				break;
			case ZYDIS_MNEMONIC_MUL:
				if (instruction.operand_count == 4)
				{
					ss << Get64BitRegisterString(r2) << std::uppercase << " = _umul128(" << Get64BitRegisterString(r2) << ", " << Get64BitRegisterString(r1) << ", (uint64_t*)&" << Get64BitRegisterString(r3) << ")";
				}
				else
					ss << GetInstructionText(instruction);
				break;
			case ZYDIS_MNEMONIC_IMUL:
				if ((instruction.operand_count == 2 || instruction.operand_count == 3) && r2 != 0)
				{
					ss << Get64BitRegisterString(r1) << " *= " << Get64BitRegisterString(r2);
				}
				else if (instruction.operand_count == 2 && instruction.operands[1].imm.value.s != 0)
				{
					if (instruction.operands[1].imm.is_signed)
						ss << Get64BitRegisterString(r1) << " *= 0x" << std::hex << std::uppercase << instruction.operands[1].imm.value.s;
					else
						ss << Get64BitRegisterString(r1) << " *= 0x" << std::hex << std::uppercase << instruction.operands[1].imm.value.u;
				}
				else if (instruction.operands[1].mem.base != 0 && instruction.operands[1].mem.disp.has_displacement)
				{
					if (instruction.operands[1].mem.base != ZYDIS_REGISTER_RSP && instruction.operands[1].mem.base != ZYDIS_REGISTER_RBP)
						ss << Get64BitRegisterString(r1) << " *= " << "mem.Read<uint64_t>(" << Get64BitRegisterString(instruction.operands[1].mem.base) << " + 0x" << std::hex << instruction.operands[1].mem.disp.value << ")";
				}
				else if (instruction.operand_count == 4 && instruction.operands[0].reg.value != 0 && r2 != 0 && instruction.operands[2].imm.value.s != 0)
				{
					ss << Get64BitRegisterString(r1) << " = " << Get64BitRegisterString(r2) << " * 0x" << std::hex << std::uppercase << instruction.operands[2].imm.value.s;
				}
				else if (stack_trace_name) {
					ss << Get64BitRegisterString(r1) << " *= " << stack_trace_name;
				}
				else
				{
					ss << GetInstructionText(instruction);
				}
				break;
			case ZYDIS_MNEMONIC_CALL:
			case ZYDIS_MNEMONIC_JNZ:
			case ZYDIS_MNEMONIC_JMP:
			case ZYDIS_MNEMONIC_NOP:
			case ZYDIS_MNEMONIC_JNBE:
			case ZYDIS_MNEMONIC_CMP:
			case ZYDIS_MNEMONIC_TEST:
			case ZYDIS_MNEMONIC_JZ:
				break;
			default:
				break;
			}
			return ss.str();
		}

		bool Print_PEB(uint64_t& rip)
		{
			ZydisDecodedInstruction instruction;
			for (int i = 0; i < 15; ++i)
			{
				instruction = Decode(rip);
				rip += instruction.length;
				if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV && instruction.operands[1].mem.segment == ZYDIS_REGISTER_GS)
				{
					char DisassembledString[256];
					ZydisFormatterFormatInstruction(&formatter, &instruction, DisassembledString, sizeof(DisassembledString), 0);

					ZydisDecodedInstruction next_instruction = Decode(rip);
					if (next_instruction.mnemonic == ZYDIS_MNEMONIC_NOT)
					{
						OUTPUT("\t%s; \t\t//%s\n", ((std::string)ZydisRegisterGetString(instruction.operands[0].reg.value) + "= ~PebAddress").c_str(), DisassembledString);
					}
					else
					{
						OUTPUT("\t%s; \t\t//%s\n", ((std::string)ZydisRegisterGetString(instruction.operands[0].reg.value) + " = PebAddress").c_str(), DisassembledString);
					}
					ignore_trace.push_back(instruction.operands[0].reg.value);
					return true;
				}
			}
			return false;
		}

		void AddRequiredInstruction(std::vector<InstructionTrace>& instruction_trace, std::vector<InstructionTrace>::iterator trace)
		{
			ZydisRegister accessed[8] = { ZydisRegister::ZYDIS_REGISTER_NONE };
			GetAccessedRegisters(trace->instruction, accessed);
			for (size_t j = 0; j < 8; j++)
			{
				if (accessed[j] != ZydisRegister::ZYDIS_REGISTER_NONE && trace->instruction.operands[1].imm.value.s != 0xffffffffc0000000)
				{
					try
					{
						uint32_t trace_index = trace->last_modified.at(accessed[j]);
						if (!instruction_trace[trace_index].used)
						{
							instruction_trace[trace_index].used = true;
							AddRequiredInstruction(instruction_trace, (instruction_trace.begin() + trace_index));
						}
					}
					catch (const std::exception&)
					{
						if (std::find(ignore_trace.begin(), ignore_trace.end(), accessed[j]) == ignore_trace.end())
						{
							uint64_t offset = (To64BitRegister(accessed[j]) - ZydisRegister::ZYDIS_REGISTER_RAX);
							if (*(&trace->context.Rax + offset) == Dump::GetImageBase())
							{
								OUTPUT("\t%s = BaseAddress;\n", Get64BitRegisterString(accessed[j]).c_str());
							}
						}
					}
				}
			}
		}

		void Print_Decryption(std::vector<InstructionTrace>& instruction_trace, ZydisRegister enc_reg, const char* print_indexing)
		{
			for (size_t j = 0; j < instruction_trace.size(); j++)
			{
				if (enc_reg == ZydisRegister::ZYDIS_REGISTER_MAX_VALUE || instruction_trace[j].used)
				{
					if (instruction_trace[j].instruction.operands[1].mem.base == ZydisRegister::ZYDIS_REGISTER_RSP && instruction_trace[j].instruction.mnemonic != ZydisMnemonic::ZYDIS_MNEMONIC_PUSHFQ) {
						try {
							auto stack_trace = instruction_trace[instruction_trace[j].rsp_stack_map.at(instruction_trace[j].instruction.operands[1].mem.disp.value)];
							auto stack_instruction = stack_trace.instruction;

							char tmp_var[100];
							sprintf_s(tmp_var, 100, "RSP_0x%llX", instruction_trace[j].instruction.operands[1].mem.disp.value);
							OUTPUT("%suint64_t %s;\n", print_indexing, tmp_var);

							std::string trace_code = AsmToCPP(stack_instruction, stack_trace.rip);
							trace_code = std::regex_replace(trace_code, std::regex(Get64BitRegisterString(stack_instruction.operands[0].reg.value)), tmp_var);
							if (trace_code.size() > 1)
								OUTPUT("\t\t%s;\n", trace_code.c_str());
							instruction_trace[j].instruction.operands[1] = stack_instruction.operands[0];

							std::string cpp_code = AsmToCPP(instruction_trace[j].instruction, instruction_trace[j].rip).c_str();
							cpp_code = cpp_code.replace(cpp_code.find("=") + 2, cpp_code.size(), tmp_var);
							if (cpp_code.size() > 1)
								OUTPUT("%s%s;\n", print_indexing, cpp_code.c_str());
						}
						catch (const std::exception&)
						{
							std::string cpp_code = AsmToCPP(instruction_trace[j].instruction, instruction_trace[j].rip, "BaseAddress");
							if (cpp_code.size() > 1)
								OUTPUT("%s%s;\n", print_indexing, cpp_code.c_str());
							continue;
						}
					}
					else if (instruction_trace[j].instruction.operands[1].mem.base == ZydisRegister::ZYDIS_REGISTER_RBP && instruction_trace[j].instruction.mnemonic != ZydisMnemonic::ZYDIS_MNEMONIC_PUSHFQ) {
						try {
							auto stack_trace = instruction_trace[instruction_trace[j].rbp_stack_map.at(instruction_trace[j].instruction.operands[1].mem.disp.value)];
							auto stack_instruction = stack_trace.instruction;

							char tmp_var[100];
							sprintf_s(tmp_var, 100, "RBP_0x%llX", instruction_trace[j].instruction.operands[1].mem.disp.value);
							OUTPUT("%suint64_t %s;\n", print_indexing, tmp_var);

							std::string trace_code = AsmToCPP(stack_instruction, stack_trace.rip);
							trace_code = std::regex_replace(trace_code, std::regex(Get64BitRegisterString(stack_instruction.operands[0].reg.value)), tmp_var);
							if (trace_code.size() > 1)
								OUTPUT("\t\t%s;\n", trace_code.c_str());
							instruction_trace[j].instruction.operands[1] = stack_instruction.operands[0];

							std::string cpp_code = AsmToCPP(instruction_trace[j].instruction, instruction_trace[j].rip).c_str();
							cpp_code = cpp_code.replace(cpp_code.find("=") + 2, cpp_code.size(), tmp_var);
							if (cpp_code.size() > 1)
								OUTPUT("%s%s;\n", print_indexing, cpp_code.c_str());
						}
						catch (const std::exception&)
						{
							std::string cpp_code = AsmToCPP(instruction_trace[j].instruction, instruction_trace[j].rip, "BaseAddress");
							if (cpp_code.size() > 1)
								OUTPUT("%s%s;\n", print_indexing, cpp_code.c_str());
							continue;
						}
					}
					else {
						std::string cpp_code = AsmToCPP(instruction_trace[j].instruction, instruction_trace[j].rip).c_str();
						if (cpp_code.size() > 1)
							OUTPUT("%s%s;\n", print_indexing, cpp_code.c_str());
					}
				}
			}
		}

		void Trace_Decryption(std::vector<InstructionTrace>& instruction_trace, ZydisRegister enc_reg)
		{
			for (int32_t j = instruction_trace.size() - 1; j >= 0; j--)
			{
				if (instruction_trace[j].instruction.operands[0].reg.value == enc_reg)
				{
					instruction_trace[j].used = true;
					AddRequiredInstruction(instruction_trace, (instruction_trace.begin() + j));
					break;
				}
			}
		}

		void Load_DecryptionTrace(uint64_t& rip, std::vector<InstructionTrace>& instruction_trace, uint64_t decryption_end, ZydisMnemonic end_mnemonic)
		{
			std::map<ZydisRegister, uint32_t> last_modified;
			std::map<int, uint32_t> rsp_stack_map;
			std::map<int, uint32_t> rbp_stack_map;
			instruction_trace.reserve(200);

			ZydisDecodedInstruction instruction = Decode(rip);
			while (rip != decryption_end && (end_mnemonic == ZydisMnemonic::ZYDIS_MNEMONIC_INVALID || instruction.mnemonic != end_mnemonic))
			{
				const uint64_t nextRip = Debugger::SingleStep();

				instruction_trace.push_back({ instruction, last_modified, rsp_stack_map, rbp_stack_map, rip, Debugger::GetContext(), false });

				ZydisRegister modified[8] = { ZydisRegister::ZYDIS_REGISTER_NONE };
				ZydisRegister accessed[8] = { ZydisRegister::ZYDIS_REGISTER_NONE };
				GetModifiedRegisters(instruction, modified);
				GetAccessedRegisters(instruction, accessed);
				for (size_t j = 0; j < 8; j++)
				{
					if (modified[j] != ZydisRegister::ZYDIS_REGISTER_NONE)
						last_modified[modified[j]] = instruction_trace.size() - 1;
				}
				if (instruction.operands[0].mem.base == ZydisRegister::ZYDIS_REGISTER_RSP) {
					for (size_t j = 0; j < 8; j++)
					{
						if (accessed[j] != ZydisRegister::ZYDIS_REGISTER_NONE) {
							try
							{
								rsp_stack_map[instruction.operands[0].mem.disp.value] = last_modified.at(accessed[j]);
							}
							catch (const std::exception&)
							{

							}
						}
					}
				}
				if (instruction.operands[0].mem.base == ZydisRegister::ZYDIS_REGISTER_RBP) {
					for (size_t j = 0; j < 8; j++)
					{
						if (accessed[j] != ZydisRegister::ZYDIS_REGISTER_NONE) {
							try
							{
								rbp_stack_map[instruction.operands[0].mem.disp.value] = last_modified.at(accessed[j]);
							}
							catch (const std::exception&)
							{

							}
						}
					}
				}

				rip = nextRip;
				if (Debugger::DidExceptionHit()) {
					rip += instruction.length;
					Debugger::SetRIP(rip);
					Debugger::ClearException();
				}

				instruction = Decode(rip);
			}
		}

		void Dump_Decryption(uint64_t& rip, uint64_t decryption_end, ZydisRegister enc_reg, const char* print_indexing, ZydisMnemonic end_mnemonic)
		{
			std::vector<InstructionTrace> instruction_trace;
			Load_DecryptionTrace(rip, instruction_trace, decryption_end, end_mnemonic);
			Trace_Decryption(instruction_trace, enc_reg);
			Print_Decryption(instruction_trace, enc_reg, print_indexing);
		}

		uint64_t Dump_Switch(uint64_t& rip)
		{
			ZydisDecodedInstruction encrypted_read_instruction = Decode(rip);

			Print_PEB(rip);

			SkipUntilInstruction(rip, ZydisMnemonic::ZYDIS_MNEMONIC_JZ);
			ZydisDecodedInstruction jmp_to_end = Decode(rip);
			uint64_t decryption_end = jmp_to_end.operands[0].imm.value.u + rip + jmp_to_end.length;
			SkipOverUntilInstruction(rip, ZydisMnemonic::ZYDIS_MNEMONIC_JZ);

			Dump_Decryption(rip, 0, ZydisRegister::ZYDIS_REGISTER_MAX_VALUE, "\t", ZydisMnemonic::ZYDIS_MNEMONIC_AND);

			SkipUntilInstruction(rip, ZydisMnemonic::ZYDIS_MNEMONIC_CMP);
			ZydisRegister switch_register = To64BitRegister(Decode(rip).operands[0].reg.value);
			uint64_t switch_address = rip;
			SkipUntilInstruction(rip, ZydisMnemonic::ZYDIS_MNEMONIC_ADD);
			ZydisRegister base_register = To64BitRegister(Decode(rip).operands[1].reg.value);

			OUTPUT("\t%s &= 0xF;\n\tswitch(%s) {\n", Get64BitRegisterString(switch_register).c_str(), Get64BitRegisterString(switch_register).c_str(), Get64BitRegisterString(switch_register).c_str());
			for (uint32_t i = 0; i < 16; i++)
			{
				OUTPUT("\tcase %d:\n\t{\n", i);

				rip = switch_address;
				Debugger::SetRIP(rip);
				Debugger::SetRegisterValue(switch_register, i);
				Debugger::SetRegisterValue(base_register, Dump::GetImageBase());

				Dump_Decryption(rip, decryption_end, encrypted_read_instruction.operands[0].reg.value, "\t\t", ZydisMnemonic::ZYDIS_MNEMONIC_INVALID);

				OUTPUT("\t\treturn %s;\n\t}\n", Get64BitRegisterString(encrypted_read_instruction.operands[0].reg.value).c_str());
			}
			OUTPUT("\t}\n}\n");
			return decryption_end;
		}

		void PrintRegisters()
		{
			OUTPUT("\tconst uint64_t BaseAddress = mem.mProcessBase;\n");
			OUTPUT("\tconst uint64_t PebAddress = mem.mProcessPeb;\n");

			OUTPUT("\tconst uint64_t mb = BaseAddress;\n");
			OUTPUT("\tuint64_t rax = mb, rbx = mb, rcx = mb, rdx = mb, rdi = mb, rsi = mb, r8 = mb, r9 = mb, r10 = mb, r11 = mb, r12 = mb, r13 = mb, r14 = mb, r15 = mb;\n");
		}
	}

	void DumpClientInfo(uint64_t address)
	{
		if (!address)
		{
			DEBUG("ClientInfo pattern scan failed.\n");
			return;
		}

		uint64_t rip = address;
		Debugger::SetRIP(rip);
		OUTPUT("uint64_t get_client_info()\n{\n");
		PrintRegisters();

		SkipOverUntilInstruction(rip, ZydisMnemonic::ZYDIS_MNEMONIC_JZ);
		SkipOverUntilInstruction(rip, ZydisMnemonic::ZYDIS_MNEMONIC_JZ);
		SkipOverUntilInstruction(rip, ZydisMnemonic::ZYDIS_MNEMONIC_JZ);

		ZydisDecodedInstruction encrypted_read_instruction = Decode(rip);
		ignore_trace.push_back(encrypted_read_instruction.operands[0].reg.value);
		OUTPUT("\t%s;\n", AsmToCPP(encrypted_read_instruction, rip).c_str());
		OUTPUT("\tif(!%s)\n\t\treturn %s;\n", Get64BitRegisterString(encrypted_read_instruction.operands[0].reg.value).c_str(), Get64BitRegisterString(encrypted_read_instruction.operands[0].reg.value).c_str());

		RunUntilInstruction(rip, ZydisMnemonic::ZYDIS_MNEMONIC_JZ);
		ZydisDecodedInstruction jmp_to_end = Decode(rip);
		uint64_t decryption_end = jmp_to_end.operands[0].imm.value.u + rip + jmp_to_end.length;
		SkipOverUntilInstruction(rip, ZydisMnemonic::ZYDIS_MNEMONIC_JZ);

		Dump_Decryption(rip, decryption_end, encrypted_read_instruction.operands[0].reg.value, "\t", ZydisMnemonic::ZYDIS_MNEMONIC_INVALID);
		OUTPUT("\treturn %s;\n}\n\n", Get64BitRegisterString(encrypted_read_instruction.operands[0].reg.value).c_str());
		ignore_trace.clear();
	}

	void DumpClientBase(uint64_t address)
	{
		if (!address)
		{
			DEBUG("ClientBase pattern scan failed.\n");
			return;
		}

		uint64_t rip = address;
		Debugger::SetRIP(rip);

		OUTPUT("inline uint64_t decrypt_client_base(uint64_t client_info)\n{\n");
		PrintRegisters();

		ZydisDecodedInstruction encrypted_read_instruction = Decode(rip);
		ignore_trace.push_back(encrypted_read_instruction.operands[0].reg.value);
		std::string enc_client_info = AsmToCPP(encrypted_read_instruction, rip);
		OUTPUT("\t%s;\n", std::regex_replace(enc_client_info, std::regex(Get64BitRegisterString(encrypted_read_instruction.operands[1].mem.base)), "client_info").c_str());
		OUTPUT("\tif(!%s)\n\t\treturn %s;\n", Get64BitRegisterString(encrypted_read_instruction.operands[0].reg.value).c_str(), Get64BitRegisterString(encrypted_read_instruction.operands[0].reg.value).c_str());

		Dump_Switch(rip);
		ignore_trace.clear();
	}

	void DumpClientActive(uint64_t address)
	{
		if (!address)
		{
			DEBUG("ClientActive pattern scan failed.\n");
			return;
		}

		uint64_t rip = address;
		Debugger::SetRIP(rip);
		SkipOverUntilInstruction(rip, ZydisMnemonic::ZYDIS_MNEMONIC_JNZ);

		OUTPUT("inline uint64_t decrypt_client_active()\n{\n");
		PrintRegisters();

		ZydisDecodedInstruction encrypted_read_instruction = Decode(rip);
		ignore_trace.push_back(encrypted_read_instruction.operands[0].reg.value);
		OUTPUT("\t%s;\n", AsmToCPP(encrypted_read_instruction, rip).c_str());
		OUTPUT("\tif(!%s)\n\t\treturn %s;\n", Get64BitRegisterString(encrypted_read_instruction.operands[0].reg.value).c_str(), Get64BitRegisterString(encrypted_read_instruction.operands[0].reg.value).c_str());

		Dump_Switch(rip);
		ignore_trace.clear();
	}

	void DumpBoneBase(uint64_t address)
	{
		if (!address)
		{
			DEBUG("BoneBase pattern scan failed.\n");
			return;
		}

		uint64_t rip = address;
		Debugger::SetRIP(rip);
		SkipOverUntilInstruction(rip, ZydisMnemonic::ZYDIS_MNEMONIC_JZ);

		OUTPUT("inline uint64_t decrypt_bone_base()\n{\n");
		PrintRegisters();

		ZydisDecodedInstruction encrypted_read_instruction = Decode(rip);
		ignore_trace.push_back(encrypted_read_instruction.operands[0].reg.value);
		OUTPUT("\t%s;\n", AsmToCPP(encrypted_read_instruction, rip).c_str());
		OUTPUT("\tif(!%s)\n\t\treturn %s;\n", Get64BitRegisterString(encrypted_read_instruction.operands[0].reg.value).c_str(), Get64BitRegisterString(encrypted_read_instruction.operands[0].reg.value).c_str());

		Dump_Switch(rip);
		ignore_trace.clear();
	}

	void DumpBoneIndex(uint64_t address)
	{
		if (!address)
		{
			DEBUG("BoneIndex pattern scan failed.\n");
			return;
		}

		uint64_t rip = address;
		Debugger::SetRIP(rip);
		OUTPUT("inline uint16_t get_bone_index(uint32_t bone_index)\n{\n");
		PrintRegisters();

		SkipOverUntilInstruction(rip, ZydisMnemonic::ZYDIS_MNEMONIC_JZ);
		SkipUntilInstruction(rip, ZydisMnemonic::ZYDIS_MNEMONIC_TEST);
		ZydisRegister return_register = Decode(rip).operands[0].reg.value;
		rip = address;
		Debugger::SetRIP(rip);

		SkipOverUntilInstruction(rip, ZydisMnemonic::ZYDIS_MNEMONIC_JZ);

		ZydisDecodedInstruction instruction = Decode(rip);
		OUTPUT("\t%s = bone_index;\n", Get64BitRegisterString(instruction.operands[1].reg.value).c_str());
		OUTPUT("\t%s;\n", AsmToCPP(instruction, rip).c_str());
		ignore_trace.push_back(instruction.operands[0].reg.value);

		rip = Debugger::SingleStep();
		if (Debugger::DidExceptionHit())
		{
			rip += instruction.length;
			Debugger::SetRIP(rip);
			Debugger::ClearException();
		}

		Dump_Decryption(rip, 0, return_register, "\t", ZydisMnemonic::ZYDIS_MNEMONIC_TEST);
		OUTPUT("\treturn %s;\n}\n", Get64BitRegisterString(return_register).c_str());
		ignore_trace.clear();
	}

}
