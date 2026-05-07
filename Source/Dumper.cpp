#include "Dumper.h"

#include <cstring>
#include <sstream>
#include <string>
#include <vector>
#include <set>
#include <map>
#include <algorithm>
#include <regex>
#include <Windows.h>

#include <Zydis/Zydis.h>
#include <unicorn/unicorn.h>

static uint64_t sDcUntilRip = 0;
static ZydisMnemonic sDcStopMnemonic = ZYDIS_MNEMONIC_INVALID;
static const char* sDcIndent = "";
static ZydisRegister sDcSinkReg = ZYDIS_REGISTER_MAX_VALUE;
static std::vector<uint64_t> sDcRip;
static std::vector<ZydisDecodedInstruction> sDcIns;
static std::vector<CONTEXT> sDcPost;
static std::vector<std::map<ZydisRegister, uint32_t>> sDcPrevWriter;
static std::vector<std::map<int, uint32_t>> sDcRspSlot, sDcRbpSlot;
static std::vector<uint8_t> sDcEmitMask;

static ZydisDecoder   sDecoder{};
static ZydisFormatter sFormatter{};
static uc_engine* sEngine = nullptr;
static uint8_t* sImage = nullptr;
static uint64_t       sImageBase = 0;
static uint64_t       sImageSize = 0;
static uint64_t       sRip = 0;
static bool           sFaulted = false;

static std::vector<ZydisRegister> sIgnoreTrace;

static constexpr uint64_t kStackBase = 0x80000000ULL;
static constexpr size_t   kStackSize = 0x200000;
static constexpr int64_t kIsolateHighBitsAndImm = (int64_t)(uint64_t)0xFFFFFFFFC0000000ULL;

static bool MemRead(uint64_t address, void* out, size_t size)
{
    if (!sImage || address < sImageBase)
    {
        return false;
    }
    size_t offset = (size_t)(address - sImageBase);
    if (offset + size > sImageSize)
    {
        return false;
    }
    memcpy(out, sImage + offset, size);
    return true;
}

template<typename T>
static T MemRead(uint64_t address)
{
    T val{};
    MemRead(address, &val, sizeof(T));
    return val;
}

static int RegToUnicorn(ZydisRegister reg)
{
    if (ZydisRegisterGetWidth(ZYDIS_MACHINE_MODE_LONG_64, reg) == 32)
    {
        reg = ZydisRegisterEncode(ZYDIS_REGCLASS_GPR64, ZydisRegisterGetId(reg));
    }
    switch (reg)
    {
    case ZYDIS_REGISTER_RAX:
        return UC_X86_REG_RAX;
    case ZYDIS_REGISTER_RBX:
        return UC_X86_REG_RBX;
    case ZYDIS_REGISTER_RCX:
        return UC_X86_REG_RCX;
    case ZYDIS_REGISTER_RDX:
        return UC_X86_REG_RDX;
    case ZYDIS_REGISTER_RSI:
        return UC_X86_REG_RSI;
    case ZYDIS_REGISTER_RDI:
        return UC_X86_REG_RDI;
    case ZYDIS_REGISTER_RBP:
        return UC_X86_REG_RBP;
    case ZYDIS_REGISTER_RSP:
        return UC_X86_REG_RSP;
    case ZYDIS_REGISTER_R8:
        return UC_X86_REG_R8;
    case ZYDIS_REGISTER_R9:
        return UC_X86_REG_R9;
    case ZYDIS_REGISTER_R10:
        return UC_X86_REG_R10;
    case ZYDIS_REGISTER_R11:
        return UC_X86_REG_R11;
    case ZYDIS_REGISTER_R12:
        return UC_X86_REG_R12;
    case ZYDIS_REGISTER_R13:
        return UC_X86_REG_R13;
    case ZYDIS_REGISTER_R14:
        return UC_X86_REG_R14;
    case ZYDIS_REGISTER_R15:
        return UC_X86_REG_R15;
    default:
        return -1;
    }
}

static void RegWrite(ZydisRegister reg, uint64_t val)
{
    int id = RegToUnicorn(reg);
    if (id != -1)
    {
        uc_reg_write(sEngine, id, &val);
    }
}

static uint64_t RipRead()
{
    uint64_t rip = 0;
    uc_reg_read(sEngine, UC_X86_REG_RIP, &rip);
    return rip;
}

static void RipWrite(uint64_t rip)
{
    uc_reg_write(sEngine, UC_X86_REG_RIP, &rip);
}

static void SeedRegisters()
{
    uint64_t rsp = kStackBase + kStackSize - 0x1000;
    uint64_t rflags = 0x202;
    for (auto reg : {
        ZYDIS_REGISTER_RAX, ZYDIS_REGISTER_RBX, ZYDIS_REGISTER_RCX, ZYDIS_REGISTER_RDX,
        ZYDIS_REGISTER_RSI, ZYDIS_REGISTER_RDI, ZYDIS_REGISTER_R8,  ZYDIS_REGISTER_R9,
        ZYDIS_REGISTER_R10, ZYDIS_REGISTER_R11, ZYDIS_REGISTER_R12, ZYDIS_REGISTER_R13,
        ZYDIS_REGISTER_R14, ZYDIS_REGISTER_R15 })
    {
        RegWrite(reg, sImageBase);
    }
    uc_reg_write(sEngine, UC_X86_REG_RSP, &rsp);
    uc_reg_write(sEngine, UC_X86_REG_RBP, &rsp);
    uc_reg_write(sEngine, UC_X86_REG_EFLAGS, &rflags);
}

static CONTEXT GetContext()
{
    CONTEXT c{};
    uc_reg_read(sEngine, UC_X86_REG_RAX, &c.Rax);
    uc_reg_read(sEngine, UC_X86_REG_RBX, &c.Rbx);
    uc_reg_read(sEngine, UC_X86_REG_RCX, &c.Rcx);
    uc_reg_read(sEngine, UC_X86_REG_RDX, &c.Rdx);
    uc_reg_read(sEngine, UC_X86_REG_RSI, &c.Rsi);
    uc_reg_read(sEngine, UC_X86_REG_RDI, &c.Rdi);
    uc_reg_read(sEngine, UC_X86_REG_RBP, &c.Rbp);
    uc_reg_read(sEngine, UC_X86_REG_RSP, &c.Rsp);
    uc_reg_read(sEngine, UC_X86_REG_R8, &c.R8);
    uc_reg_read(sEngine, UC_X86_REG_R9, &c.R9);
    uc_reg_read(sEngine, UC_X86_REG_R10, &c.R10);
    uc_reg_read(sEngine, UC_X86_REG_R11, &c.R11);
    uc_reg_read(sEngine, UC_X86_REG_R12, &c.R12);
    uc_reg_read(sEngine, UC_X86_REG_R13, &c.R13);
    uc_reg_read(sEngine, UC_X86_REG_R14, &c.R14);
    uc_reg_read(sEngine, UC_X86_REG_R15, &c.R15);
    uc_reg_read(sEngine, UC_X86_REG_RIP, &c.Rip);
    return c;
}

static uint64_t SingleStep()
{
    sFaulted = false;
    uint64_t cur = RipRead();
    uc_err err = uc_emu_start(sEngine, cur, 0, 0, 1);
    if (err != UC_ERR_OK)
    {
        sFaulted = true;
        return cur;
    }
    return RipRead();
}

static ZydisDecodedInstruction Decode(uint64_t address)
{
    ZydisDecodedInstruction instr{};
    uint8_t bytes[ZYDIS_MAX_INSTRUCTION_LENGTH]{};
    MemRead(address, bytes, sizeof(bytes));
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&sDecoder, bytes, sizeof(bytes), &instr)))
    {
        memset(&instr, 0, sizeof(instr));
    }
    return instr;
}

static std::string Disasm(uint64_t address)
{
    ZydisDecodedInstruction instr = Decode(address);
    if (instr.length == 0)
    {
        return "<invalid>";
    }
    char buf[256]{};
    ZydisFormatterFormatInstruction(&sFormatter, &instr, buf, sizeof(buf), address);
    return buf;
}

static void SkipUntil(ZydisMnemonic mnemonic)
{
    ZydisDecodedInstruction instr = Decode(sRip);
    while (instr.mnemonic != mnemonic)
    {
        if (instr.length)
        {
            sRip += instr.length;
        }
        else
        {
            sRip += 1;
        }
        RipWrite(sRip);
        instr = Decode(sRip);
    }
}

static void SkipOver(ZydisMnemonic mnemonic)
{
    SkipUntil(mnemonic);
    ZydisDecodedInstruction instr = Decode(sRip);
    sRip += instr.length;
    RipWrite(sRip);
}

static ZydisRegister To64Reg(ZydisRegister reg)
{
    if (reg == ZYDIS_REGISTER_NONE)
    {
        return ZYDIS_REGISTER_NONE;
    }
    ZydisRegisterClass cls = ZydisRegisterGetClass(reg);
    if (cls == ZYDIS_REGCLASS_GPR8 || cls == ZYDIS_REGCLASS_GPR16 || cls == ZYDIS_REGCLASS_GPR32)
    {
        reg = ZydisRegisterEncode(ZYDIS_REGCLASS_GPR64, ZydisRegisterGetId(reg));
    }
    return reg;
}

static const char* Reg64(ZydisRegister reg)
{
    return ZydisRegisterGetString(To64Reg(reg));
}

static void CollectRegisters(const ZydisDecodedInstruction& instr, ZydisRegister regs[8], ZydisOperandAction action)
{
    for (uint32_t i = 0; i < instr.operand_count; i++)
    {
        const auto& op = instr.operands[i];
        bool relevant = op.visibility == ZYDIS_OPERAND_VISIBILITY_EXPLICIT
            || To64Reg(op.reg.value) == ZYDIS_REGISTER_RAX
            || instr.mnemonic == ZYDIS_MNEMONIC_AND
            || instr.mnemonic == ZYDIS_MNEMONIC_MUL;
        if (!relevant)
        {
            continue;
        }

        if (op.type == ZYDIS_OPERAND_TYPE_REGISTER && (op.actions & action))
        {
            regs[i] = To64Reg(op.reg.value);
        }
        else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY && (op.actions & action))
        {
            if (action == ZYDIS_OPERAND_ACTION_READ
                && op.mem.base != ZYDIS_REGISTER_RIP
                && op.mem.base != ZYDIS_REGISTER_RBP
                && op.mem.base != ZYDIS_REGISTER_RSP)
            {
                regs[i] = To64Reg(op.mem.base);
                if (op.mem.index)
                {
                    regs[i + 4] = To64Reg(op.mem.index);
                }
            }
            else if (action == ZYDIS_OPERAND_ACTION_WRITE)
            {
                regs[i] = To64Reg(op.mem.base);
            }
        }
        else if (action == ZYDIS_OPERAND_ACTION_READ
            && instr.mnemonic == ZYDIS_MNEMONIC_LEA
            && i > 0
            && op.type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            if (op.mem.base != ZYDIS_REGISTER_RIP
                && op.mem.base != ZYDIS_REGISTER_RBP
                && op.mem.base != ZYDIS_REGISTER_RSP)
            {
                regs[i] = To64Reg(op.mem.base);
            }
            if (op.mem.index)
            {
                regs[i + 4] = To64Reg(op.mem.index);
            }
        }
    }
}

static std::string DispStr(int64_t disp)
{
    std::ostringstream s;
    if (disp < 0)
    {
        s << " - 0x" << std::hex << std::uppercase << -disp;
    }
    else
    {
        s << " + 0x" << std::hex << std::uppercase << disp;
    }
    return s.str();
}

static std::string ImmStr(uint64_t v)
{
    std::ostringstream s;
    s << "0x" << std::hex << std::uppercase << v;
    return s.str();
}

static std::string MemReadExpr(uint64_t address, const ZydisDecodedInstruction& instr, const ZydisDecodedOperand& op)
{
    std::ostringstream s;
    if (op.mem.base == ZYDIS_REGISTER_RIP)
    {
        uint64_t target = address + instr.length + op.mem.disp.value;
        s << "mem.Read<uintptr_t>(pb + 0x" << std::hex << std::uppercase << (target - sImageBase) << ")";
    }
    else if (op.mem.index != ZYDIS_REGISTER_NONE)
    {
        s << "mem.Read<uintptr_t>(" << Reg64(op.mem.base)
            << " + " << Reg64(op.mem.index)
            << " * " << (int)op.mem.scale;
        if (op.mem.disp.has_displacement)
        {
            s << DispStr(op.mem.disp.value);
        }
        s << ")";
    }
    else if (op.mem.disp.has_displacement)
    {
        s << "mem.Read<uintptr_t>(" << Reg64(op.mem.base) << DispStr(op.mem.disp.value) << ")";
    }
    else
    {
        s << "mem.Read<uintptr_t>(" << Reg64(op.mem.base) << ")";
    }
    return s.str();
}

static std::string Lift(const ZydisDecodedInstruction& instr, uint64_t address, const char* stackTraceName = nullptr)
{
    const auto* ops = instr.operands;
    std::ostringstream ss;

    ZydisRegister r0 = ops[0].reg.value;
    ZydisRegister r1 = ops[1].reg.value;
    ZydisRegister r2 = ops[2].reg.value;

    switch (instr.mnemonic)
    {
    case ZYDIS_MNEMONIC_LEA:
        if (ops[1].mem.base == ZYDIS_REGISTER_RIP)
        {
            uint64_t offset = (address + ops[1].mem.disp.value + instr.length) - sImageBase;
            ss << Reg64(r0) << " = pb";
            if (offset)
            {
                ss << " + 0x" << std::hex << std::uppercase << offset;
            }
        }
        else if (ops[1].mem.index != ZYDIS_REGISTER_NONE && ops[1].mem.scale)
        {
            if (ops[1].mem.base != ZYDIS_REGISTER_NONE)
            {
                ss << Reg64(r0) << " = " << Reg64(ops[1].mem.base)
                << " + " << Reg64(ops[1].mem.index)
                << " * " << (int)ops[1].mem.scale;
            }
            else
            {
                ss << Reg64(r0) << " = " << Reg64(ops[1].mem.index)
                << " * " << (int)ops[1].mem.scale;
            }
            if (ops[1].mem.disp.has_displacement)
            {
                ss << DispStr(ops[1].mem.disp.value);
            }
        }
        else
        {
            ss << Reg64(r0) << " = " << Reg64(ops[1].mem.base);
            if (ops[1].mem.disp.has_displacement)
            {
                ss << DispStr(ops[1].mem.disp.value);
            }
        }
        break;

    case ZYDIS_MNEMONIC_MOV:
        if (ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            if (ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                ss << Reg64(r0) << " = " << Reg64(r1);
            }
            else if (ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                ss << Reg64(r0) << " = " << ImmStr(ops[1].imm.is_signed ? (uint64_t)ops[1].imm.value.s : ops[1].imm.value.u);
            }
            else if (ops[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                if (ops[1].mem.segment == ZYDIS_REGISTER_GS)
                {
                    ss << Reg64(r0) << " = pp";
                }
                else if (stackTraceName)
                {
                    ss << Reg64(r0) << " = " << stackTraceName;
                }
                else
                {
                    ss << Reg64(r0) << " = " << MemReadExpr(address, instr, ops[1]);
                }
            }
        }
        break;

    case ZYDIS_MNEMONIC_MOVZX:
    case ZYDIS_MNEMONIC_MOVSX:
        if (ops[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            if (stackTraceName)
            {
                ss << Reg64(r0) << " = " << stackTraceName;
            }
            else
            {
                ss << Reg64(r0) << " = " << MemReadExpr(address, instr, ops[1]);
            }
        }
        else if (ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            ss << Reg64(r0) << " = " << Reg64(r1);
        }
        break;

    case ZYDIS_MNEMONIC_ROR:
        ss << Reg64(r0) << " = _rotr64(" << Reg64(r0) << ", " << ImmStr(ops[1].imm.value.u) << ")";
        break;
    case ZYDIS_MNEMONIC_ROL:
        ss << Reg64(r0) << " = _rotl64(" << Reg64(r0) << ", " << ImmStr(ops[1].imm.value.u) << ")";
        break;
    case ZYDIS_MNEMONIC_SHR:
        ss << Reg64(r0) << " >>= " << ImmStr(ops[1].imm.value.u);
        break;
    case ZYDIS_MNEMONIC_SHL:
        ss << Reg64(r0) << " <<= " << ImmStr(ops[1].imm.value.u);
        break;
    case ZYDIS_MNEMONIC_NOT:
        ss << Reg64(r0) << " = ~" << Reg64(r0);
        break;
    case ZYDIS_MNEMONIC_NEG:
        ss << Reg64(r0) << " = -" << Reg64(r0);
        break;
    case ZYDIS_MNEMONIC_BSWAP:
        ss << Reg64(r0) << " = _byteswap_uint64(" << Reg64(r0) << ")";
        break;
    case ZYDIS_MNEMONIC_INC:
        ss << "++" << Reg64(r0);
        break;
    case ZYDIS_MNEMONIC_DEC:
        ss << "--" << Reg64(r0);
        break;

    case ZYDIS_MNEMONIC_ADD:
        if (ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            ss << Reg64(r0) << " += " << Reg64(r1);
        }
        else if (ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
        {
            int64_t v = ops[1].imm.value.s;
            if (ops[1].imm.is_signed && v < 0)
            {
                ss << Reg64(r0) << " -= " << ImmStr((uint64_t)-v);
            }
            else
            {
                ss << Reg64(r0) << " += " << ImmStr(ops[1].imm.value.u);
            }
        }
        else if (ops[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            if (stackTraceName)
            {
                ss << Reg64(r0) << " += " << stackTraceName;
            }
            else
            {
                ss << Reg64(r0) << " += " << MemReadExpr(address, instr, ops[1]);
            }
        }
        break;

    case ZYDIS_MNEMONIC_SUB:
        if (ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            ss << Reg64(r0) << " -= " << Reg64(r1);
        }
        else if (ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
        {
            int64_t v = ops[1].imm.value.s;
            if (ops[1].imm.is_signed && v < 0)
            {
                ss << Reg64(r0) << " += " << ImmStr((uint64_t)-v);
            }
            else
            {
                ss << Reg64(r0) << " -= " << ImmStr(ops[1].imm.value.u);
            }
        }
        else if (stackTraceName)
        {
            ss << Reg64(r0) << " -= " << stackTraceName;
        }
        break;

    case ZYDIS_MNEMONIC_XOR:
        if (r0 == r1)
        {
            ss << Reg64(r0) << " = 0";
        }
        else if (ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
        {
            ss << Reg64(r0) << " ^= " << ImmStr(ops[1].imm.value.u);
        }
        else if (ops[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
        {
            if (stackTraceName)
            {
                ss << Reg64(r0) << " ^= " << stackTraceName;
            }
            else
            {
                ss << Reg64(r0) << " ^= " << MemReadExpr(address, instr, ops[1]);
            }
        }
        else
        {
            ss << Reg64(r0) << " ^= " << Reg64(r1);
        }
        break;

    case ZYDIS_MNEMONIC_AND:
        if (ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
        {
            if (ops[1].imm.value.s == kIsolateHighBitsAndImm)
            {
                ss << Reg64(r0) << " = 0";
            }
            else
            {
                ss << Reg64(r0) << " &= " << ImmStr(ops[1].imm.value.u);
            }
        }
        else
        {
            ss << Reg64(r0) << " &= " << Reg64(r1);
        }
        break;

    case ZYDIS_MNEMONIC_OR:
        if (ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
        {
            ss << Reg64(r0) << " |= " << ImmStr(ops[1].imm.value.u);
        }
        else
        {
            ss << Reg64(r0) << " |= " << Reg64(r1);
        }
        break;

    case ZYDIS_MNEMONIC_MUL:
        if (instr.operand_count == 4)
            ss << Reg64(r1) << " = _umul128(" << Reg64(r1) << ", " << Reg64(r0)
            << ", (uint64_t*)&" << Reg64(r2) << ")";
        break;

    case ZYDIS_MNEMONIC_IMUL:
        if (ops[1].type == ZYDIS_OPERAND_TYPE_MEMORY
            && ops[1].mem.base != ZYDIS_REGISTER_RSP
            && ops[1].mem.base != ZYDIS_REGISTER_RBP)
        {
            if (stackTraceName)
            {
                ss << Reg64(r0) << " *= " << stackTraceName;
            }
            else
            {
                ss << Reg64(r0) << " *= " << MemReadExpr(address, instr, ops[1]);
            }
        }
        else if ((instr.operand_count == 2 || instr.operand_count == 3) && r1 != ZYDIS_REGISTER_NONE)
        {
            ss << Reg64(r0) << " *= " << Reg64(r1);
        }
        else if (instr.operand_count == 2 && ops[1].imm.value.s)
        {
            ss << Reg64(r0) << " *= " << ImmStr(ops[1].imm.is_signed ? (uint64_t)ops[1].imm.value.s : ops[1].imm.value.u);
        }
        else if (instr.operand_count == 4 && r0 != ZYDIS_REGISTER_NONE && r1 != ZYDIS_REGISTER_NONE && ops[2].imm.value.s)
        {
            ss << Reg64(r0) << " = " << Reg64(r1) << " * " << ImmStr((uint64_t)ops[2].imm.value.s);
        }
        else if (stackTraceName)
        {
            ss << Reg64(r0) << " *= " << stackTraceName;
        }
        break;

    default:
        break;
    }

    return ss.str();
}

static void PrintPEB()
{
    uint64_t cur = sRip;
    for (int i = 0; i < 15; i++)
    {
        ZydisDecodedInstruction instr = Decode(cur);
        if (instr.length == 0)
        {
            break;
        }

        if (instr.mnemonic == ZYDIS_MNEMONIC_MOV
            && instr.operands[1].mem.segment == ZYDIS_REGISTER_GS)
        {
            char buf[256]{};
            ZydisFormatterFormatInstruction(&sFormatter, &instr, buf, sizeof(buf), cur);

            ZydisDecodedInstruction next = Decode(cur + instr.length);
            if (next.mnemonic == ZYDIS_MNEMONIC_NOT)
            {
                printf("\t%s = ~pp;\t\t//%s\n", Reg64(instr.operands[0].reg.value), buf);
            }
            else
            {
                printf("\t%s = pp;\t\t//%s\n", Reg64(instr.operands[0].reg.value), buf);
            }

            sIgnoreTrace.push_back(instr.operands[0].reg.value);
            cur += instr.length;
            sRip = cur;
            RipWrite(sRip);
            return;
        }

        cur += instr.length;
    }
}

static uint64_t GprFromContext(const CONTEXT& ctx, ZydisRegister r)
{
    switch (To64Reg(r))
    {
    case ZYDIS_REGISTER_RAX:
        return ctx.Rax;
    case ZYDIS_REGISTER_RBX:
        return ctx.Rbx;
    case ZYDIS_REGISTER_RCX:
        return ctx.Rcx;
    case ZYDIS_REGISTER_RDX:
        return ctx.Rdx;
    case ZYDIS_REGISTER_RSI:
        return ctx.Rsi;
    case ZYDIS_REGISTER_RDI:
        return ctx.Rdi;
    case ZYDIS_REGISTER_RBP:
        return ctx.Rbp;
    case ZYDIS_REGISTER_RSP:
        return ctx.Rsp;
    case ZYDIS_REGISTER_R8:
        return ctx.R8;
    case ZYDIS_REGISTER_R9:
        return ctx.R9;
    case ZYDIS_REGISTER_R10:
        return ctx.R10;
    case ZYDIS_REGISTER_R11:
        return ctx.R11;
    case ZYDIS_REGISTER_R12:
        return ctx.R12;
    case ZYDIS_REGISTER_R13:
        return ctx.R13;
    case ZYDIS_REGISTER_R14:
        return ctx.R14;
    case ZYDIS_REGISTER_R15:
        return ctx.R15;
    default:
        return 0;
    }
}

static bool RegOnPbIgnoreList(ZydisRegister r)
{
    const ZydisRegister rr = To64Reg(r);
    return std::find(sIgnoreTrace.begin(), sIgnoreTrace.end(), rr) != sIgnoreTrace.end();
}

static bool Operand1MagicImmBlocksProducerWalk(const ZydisDecodedInstruction& insn)
{
    return insn.operand_count >= 2
        && insn.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE
        && insn.operands[1].imm.value.s == kIsolateHighBitsAndImm;
}

static size_t PriorWriterIdx(ZydisRegister needle, size_t priorStep)
{
    if (needle == ZYDIS_REGISTER_NONE || priorStep >= sDcPrevWriter.size())
    {
        return static_cast<size_t>(-1);
    }
    auto it = sDcPrevWriter[priorStep].find(To64Reg(needle));
    if (it == sDcPrevWriter[priorStep].end())
    {
        return static_cast<size_t>(-1);
    }
    return static_cast<size_t>(it->second);
}

static void RecordDecryptionTrace()
{
    std::map<ZydisRegister, uint32_t> lastWriter;
    std::map<int, uint32_t> rspSlotToWriter, rbpSlotToWriter;

    constexpr size_t kReserve = 256;
    sDcRip.reserve(kReserve);
    sDcIns.reserve(kReserve);
    sDcPost.reserve(kReserve);
    sDcPrevWriter.reserve(kReserve);
    sDcRspSlot.reserve(kReserve);
    sDcRbpSlot.reserve(kReserve);

    for (ZydisDecodedInstruction instr = Decode(sRip);
        sRip != sDcUntilRip
        && (sDcStopMnemonic == ZYDIS_MNEMONIC_INVALID || instr.mnemonic != sDcStopMnemonic);
        instr = Decode(sRip))
    {
        if (instr.length == 0)
        {
            sRip++;
            RipWrite(sRip);
            continue;
        }

        const uint64_t instrRip = sRip;

        sDcRip.push_back(instrRip);
        sDcIns.push_back(instr);
        sDcPrevWriter.push_back(lastWriter);
        sDcRspSlot.push_back(rspSlotToWriter);
        sDcRbpSlot.push_back(rbpSlotToWriter);

        (void)SingleStep();
        if (sFaulted)
        {
            sRip = instrRip + instr.length;
            RipWrite(sRip);
        }
        else
        {
            sRip = RipRead();
        }

        sDcPost.push_back(GetContext());

        const uint32_t thisIdx = (uint32_t)(sDcIns.size() - 1);

        ZydisRegister writers[8] = {}, readers[8] = {};
        CollectRegisters(instr, writers, ZYDIS_OPERAND_ACTION_WRITE);
        CollectRegisters(instr, readers, ZYDIS_OPERAND_ACTION_READ);

        for (unsigned j = 0; j < 8; j++)
        {
            if (writers[j] != ZYDIS_REGISTER_NONE)
            {
                lastWriter[writers[j]] = thisIdx;
            }
        }

        auto linkDisp = [&](int disp, std::map<int, uint32_t>& slotMap)
        {
            for (unsigned j = 0; j < 8; j++)
            {
                if (readers[j] == ZYDIS_REGISTER_NONE)
                {
                    continue;
                }
                auto it = lastWriter.find(readers[j]);
                if (it != lastWriter.end())
                {
                    slotMap[disp] = it->second;
                }
            }
        };

        if (instr.operands[0].mem.base == ZYDIS_REGISTER_RSP)
        {
            linkDisp((int)instr.operands[0].mem.disp.value, rspSlotToWriter);
        }
        if (instr.operands[0].mem.base == ZYDIS_REGISTER_RBP)
        {
            linkDisp((int)instr.operands[0].mem.disp.value, rbpSlotToWriter);
        }
    }
}

static void BuildEmitMask()
{
    const size_t n = sDcIns.size();
    sDcEmitMask.assign(n, 0);
    if (n == 0 || sDcPrevWriter.size() < n || sDcPost.size() < n)
    {
        return;
    }
    if (sDcSinkReg == ZYDIS_REGISTER_MAX_VALUE)
    {
        sDcEmitMask.assign(n, 1);
        return;
    }

    size_t anchor = static_cast<size_t>(-1);
    for (size_t i = n; i-- > 0;)
    {
        if (sDcIns[i].operands[0].reg.value == sDcSinkReg)
        {
            anchor = i;
            break;
        }
    }
    if (anchor == static_cast<size_t>(-1))
    {
        return;
    }

    std::vector<size_t> pending;
    auto enqueue = [&](size_t step)
    {
        if (step >= n || sDcEmitMask[step])
        {
            return;
        }
        sDcEmitMask[step] = 1;
        pending.push_back(step);
    };
    enqueue(anchor);

    while (!pending.empty())
    {
        const size_t at = pending.back();
        pending.pop_back();

        if (Operand1MagicImmBlocksProducerWalk(sDcIns[at]))
        {
            continue;
        }

        ZydisRegister reads[8] = {};
        CollectRegisters(sDcIns[at], reads, ZYDIS_OPERAND_ACTION_READ);

        for (unsigned k = 0; k < 8; k++)
        {
            const ZydisRegister r = reads[k];
            if (r == ZYDIS_REGISTER_NONE)
            {
                continue;
            }

            const size_t w = PriorWriterIdx(r, at);
            if (w != static_cast<size_t>(-1))
            {
                if (w < n)
                {
                    enqueue(w);
                }
            }
            else if (!RegOnPbIgnoreList(r) && GprFromContext(sDcPost[at], r) == sImageBase)
            {
                printf("\t%s = pb;\n", Reg64(r));
            }
        }
    }
}

static void EmitStackSlotLoad(size_t consumerStep, bool rspSlotNotRbp)
{
    const size_t n = sDcIns.size();
    if (consumerStep >= n)
    {
        return;
    }
    const auto& slotSnap = rspSlotNotRbp ? sDcRspSlot[consumerStep] : sDcRbpSlot[consumerStep];
    const ZydisDecodedOperand& srcOp = sDcIns[consumerStep].operands[1];
    if (srcOp.type != ZYDIS_OPERAND_TYPE_MEMORY)
    {
        return;
    }

    ZydisDecodedInstruction& consumer = sDcIns[consumerStep];
    const uint64_t ripHere = sDcRip[consumerStep];

    const auto slot = slotSnap.find((int)srcOp.mem.disp.value);
    const auto fbLine = [&]()
    {
        const std::string fb = Lift(consumer, ripHere, "pb");
        if (fb.size() > 1)
        {
            printf("%s%s;\n", sDcIndent, fb.c_str());
        }
    };

    if (slot == slotSnap.end())
    {
        fbLine();
        return;
    }

    const size_t producer = static_cast<size_t>(slot->second);
    if (producer >= n || sDcIns[producer].operand_count < 1)
    {
        fbLine();
        return;
    }

    char tmp[100]{};
    sprintf_s(tmp, sizeof tmp, "%s_0x%llX",
        rspSlotNotRbp ? "RSP" : "RBP",
        (unsigned long long)(int64_t)srcOp.mem.disp.value);
    printf("%suint64_t %s;\n", sDcIndent, tmp);

    std::string traceCode = Lift(sDcIns[producer], sDcRip[producer]);
    traceCode = std::regex_replace(traceCode,
        std::regex(Reg64(sDcIns[producer].operands[0].reg.value)), tmp);
    if (traceCode.size() > 1)
    {
        printf("\t\t%s;\n", traceCode.c_str());
    }

    consumer.operands[1] = sDcIns[producer].operands[0];

    std::string cppCode = Lift(consumer, ripHere);
    const size_t eq = cppCode.find('=');
    if (eq != std::string::npos && eq + 2 < cppCode.size())
    {
        cppCode.replace(eq + 2, std::string::npos, tmp);
    }

    if (cppCode.size() > 1)
    {
        printf("%s%s;\n", sDcIndent, cppCode.c_str());
    }
    else
    {
        fbLine();
    }
}

static void EmitDecryptionListing()
{
    const size_t n = sDcIns.size();
    const bool filtered = sDcSinkReg != ZYDIS_REGISTER_MAX_VALUE;

    for (size_t i = 0; i < n; i++)
    {
        if (filtered && (i >= sDcEmitMask.size() || !sDcEmitMask[i]))
        {
            continue;
        }

        ZydisDecodedInstruction& insn = sDcIns[i];
        const uint64_t rva = sDcRip[i];

        const bool stackSrc = insn.operand_count >= 2
            && insn.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY
            && insn.mnemonic != ZYDIS_MNEMONIC_PUSHFQ;

        if (stackSrc && insn.operands[1].mem.base == ZYDIS_REGISTER_RSP)
        {
            EmitStackSlotLoad(i, true);
        }
        else if (stackSrc && insn.operands[1].mem.base == ZYDIS_REGISTER_RBP)
        {
            EmitStackSlotLoad(i, false);
        }
        else
        {
            const std::string cppCode = Lift(insn, rva);
            if (cppCode.size() > 1)
            {
                printf("%s%s;\t\t//%s\n", sDcIndent, cppCode.c_str(), Disasm(rva).c_str());
            }
            else
            {
                printf("%s//failed to translate: %s\n", sDcIndent, Disasm(rva).c_str());
            }
        }
    }
}

static void Dump_Decryption(uint64_t decryptionEnd, ZydisRegister encReg, const char* indent, ZydisMnemonic stopMnemonic)
{
    sDcUntilRip = decryptionEnd;
    sDcStopMnemonic = stopMnemonic;
    sDcIndent = indent ? indent : "";
    sDcSinkReg = encReg;

    sDcRip.clear();
    sDcIns.clear();
    sDcPost.clear();
    sDcPrevWriter.clear();
    sDcRspSlot.clear();
    sDcRbpSlot.clear();
    sDcEmitMask.clear();

    RecordDecryptionTrace();
    BuildEmitMask();
    EmitDecryptionListing();
}

static void DumpSwitch(ZydisRegister encReg)
{
    PrintPEB();

    SkipUntil(ZYDIS_MNEMONIC_JZ);
    ZydisDecodedInstruction jzInstr = Decode(sRip);
    uint64_t decryptionEnd = jzInstr.operands[0].imm.value.u + sRip + jzInstr.length;
    SkipOver(ZYDIS_MNEMONIC_JZ);

    Dump_Decryption(0, ZYDIS_REGISTER_MAX_VALUE, "\t", ZYDIS_MNEMONIC_AND);

    SkipUntil(ZYDIS_MNEMONIC_CMP);
    ZydisRegister switchReg = To64Reg(Decode(sRip).operands[0].reg.value);
    uint64_t switchAddr = sRip;
    SkipUntil(ZYDIS_MNEMONIC_ADD);
    ZydisRegister baseReg = To64Reg(Decode(sRip).operands[1].reg.value);

    printf("\t%s &= 0xF;\n\tswitch (%s) {\n", Reg64(switchReg), Reg64(switchReg));

    for (uint32_t i = 0; i < 16; i++)
    {
        printf("\tcase %u:\n\t{\n", i);
        sRip = switchAddr;
        RipWrite(sRip);
        RegWrite(switchReg, i);
        RegWrite(baseReg, sImageBase);
        Dump_Decryption(decryptionEnd, encReg, "\t\t", ZYDIS_MNEMONIC_INVALID);
        printf("\t\treturn %s;\n\t}\n", Reg64(encReg));
    }

    printf("\t}\n}\n");
}

static void PrintFuncHeader(const char* name, const char* params = "")
{
    printf("inline uint64_t %s(%s)\n{\n", name, params);
    printf("\tconst uint64_t pb = mem.mProcessBase;\n");
    printf("\tconst uint64_t pp = mem.mProcessPeb;\n");
    printf("\tuint64_t rax = pb, rbx = pb, rcx = pb, rdx = pb, rdi = pb, rsi = pb;\n");
    printf("\tuint64_t r8 = pb, r9 = pb, r10 = pb, r11 = pb, r12 = pb, r13 = pb, r14 = pb, r15 = pb;\n");
}

void CodDumper_Start()
{
    ZydisDecoderInit(&sDecoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
    ZydisFormatterInit(&sFormatter, ZYDIS_FORMATTER_STYLE_INTEL);
    if (uc_open(UC_ARCH_X86, UC_MODE_64, &sEngine) != UC_ERR_OK)
    {
        printf("Failed to initialize Unicorn.\n");
        return;
    }
}

void CodDumper_Destroy()
{
    if (sEngine)
    {
        uc_close(sEngine);
        sEngine = nullptr;
    }
    if (sImage)
    {
        delete[] sImage;
        sImage = nullptr;
    }
}

void CodDumper_LoadData(uint8_t* data, uint64_t size)
{
    if (sImage)
    {
        delete[] sImage;
    }

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(data);
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(data + dos->e_lfanew);

    sImage = new uint8_t[size];
    sImageSize = (size_t)size;
    sImageBase = nt->OptionalHeader.ImageBase;
    memcpy(sImage, data, size);

    size_t mappedSize = (sImageSize + 0xFFF) & ~(size_t)0xFFF;
    uc_mem_map(sEngine, sImageBase, mappedSize, UC_PROT_ALL);
    uc_mem_write(sEngine, sImageBase, sImage, sImageSize);
    uc_mem_map(sEngine, kStackBase, kStackSize, UC_PROT_ALL);
    SeedRegisters();
}

uint64_t CodDumper_FindSignature(const char* pattern)
{
    auto pattern_to_bytes = [](const char* pat)
    {
        std::vector<int> bytes;
        bytes.reserve(256);
        const char* cur = pat;
        while (*cur)
        {
            if (*cur == ' ')
            {
                ++cur;
                continue;
            }
            if (*cur == '?')
            {
                ++cur;
                if (*cur == '?')
                {
                    ++cur;
                }
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
    const size_t sigSz = sig.size();
    if (!sigSz)
    {
        return 0;
    }

    size_t max = sImageSize - sigSz;
    for (size_t i = 0; i <= max; ++i)
    {
        if (sig[0] != -1 && sImage[i] != (uint8_t)sig[0])
        {
            continue;
        }
        size_t j = 1;
        for (; j < sigSz; ++j)
        {
            if (sig[j] != -1 && sImage[i + j] != (uint8_t)sig[j])
            {
                break;
            }
        }
        if (j == sigSz)
        {
            return sImageBase + i;
        }
    }
    return 0;
}

void CodDumper_DumpLocalClientGlobals(uint64_t address)
{
    if (!address)
    {
        printf("//DumpLocalClientGlobals: pattern not found\n");
        return;
    }

    sRip = address;
    RipWrite(sRip);
    SeedRegisters();
    sIgnoreTrace.clear();

    SkipOver(ZYDIS_MNEMONIC_JZ);
    SkipOver(ZYDIS_MNEMONIC_JZ);
    SkipOver(ZYDIS_MNEMONIC_JZ);

    ZydisDecodedInstruction enc = Decode(sRip);
    ZydisRegister encReg = enc.operands[0].reg.value;
    sIgnoreTrace.push_back(encReg);

    PrintFuncHeader("DecryptLocalClientGlobals");
    printf("\t%s;\n", Lift(enc, sRip).c_str());
    printf("\tif (!%s)\n\t\treturn %s;\n", Reg64(encReg), Reg64(encReg));

    {
        ZydisDecodedInstruction di = Decode(sRip);
        while (di.mnemonic != ZYDIS_MNEMONIC_JZ)
        {
            if (di.length)
            {
                sRip += di.length;
            }
            else
            {
                sRip += 1;
            }
            RipWrite(sRip);
            di = Decode(sRip);
        }
    }

    ZydisDecodedInstruction jzInstr = Decode(sRip);
    uint64_t decryptionEnd = jzInstr.operands[0].imm.value.u + sRip + jzInstr.length;
    SkipOver(ZYDIS_MNEMONIC_JZ);

    Dump_Decryption(decryptionEnd, encReg, "\t", ZYDIS_MNEMONIC_INVALID);
    printf("\treturn %s;\n}\n\n", Reg64(encReg));
    sIgnoreTrace.clear();
}

void CodDumper_DumpDObjArray(uint64_t address)
{
    if (!address)
    {
        printf("//DumpDObjArray: pattern not found\n");
        return;
    }

    sRip = address;
    RipWrite(sRip);
    SeedRegisters();
    sIgnoreTrace.clear();

    SkipOver(ZYDIS_MNEMONIC_JZ);

    ZydisDecodedInstruction enc = Decode(sRip);
    ZydisRegister encReg = enc.operands[0].reg.value;
    sIgnoreTrace.push_back(encReg);

    PrintFuncHeader("DecryptDObjArray");
    printf("\t%s;\n", Lift(enc, sRip).c_str());
    printf("\tif (!%s)\n\t\treturn %s;\n", Reg64(encReg), Reg64(encReg));

    DumpSwitch(encReg);
    sIgnoreTrace.clear();
}

void CodDumper_DumpDObjIndex(uint64_t address)
{
    if (!address)
    {
        printf("//DumpDObjIndex: pattern not found\n");
        return;
    }

    sRip = address;
    RipWrite(sRip);
    SeedRegisters();
    sIgnoreTrace.clear();

    SkipOver(ZYDIS_MNEMONIC_JZ);
    SkipUntil(ZYDIS_MNEMONIC_TEST);
    ZydisRegister returnReg = To64Reg(Decode(sRip).operands[0].reg.value);

    sRip = address;
    RipWrite(sRip);
    SeedRegisters();

    SkipOver(ZYDIS_MNEMONIC_JZ);

    ZydisDecodedInstruction enc = Decode(sRip);
    sIgnoreTrace.push_back(enc.operands[0].reg.value);

    PrintFuncHeader("DecryptDObjIndex", "uint32_t client_num");
    printf("\t%s = client_num;\n", Reg64(enc.operands[1].reg.value));
    printf("\t%s;\n", Lift(enc, sRip).c_str());
    printf("\tif (!%s)\n\t\treturn %s;\n", Reg64(enc.operands[0].reg.value), Reg64(enc.operands[0].reg.value));

    uint64_t next = SingleStep();
    if (sFaulted)
    {
        sRip += enc.length;
        RipWrite(sRip);
    }
    else
    {
        sRip = next;
    }

    Dump_Decryption(0, returnReg, "\t", ZYDIS_MNEMONIC_TEST);
    printf("\treturn %s;\n}\n", Reg64(returnReg));
    sIgnoreTrace.clear();
}

void CodDumper_DumpClientActive(uint64_t address)
{
    if (!address)
    {
        printf("//DumpClientActive: pattern not found\n");
        return;
    }

    sRip = address;
    RipWrite(sRip);
    SeedRegisters();
    sIgnoreTrace.clear();

    SkipOver(ZYDIS_MNEMONIC_JNZ);

    ZydisDecodedInstruction enc = Decode(sRip);
    ZydisRegister encReg = enc.operands[0].reg.value;
    sIgnoreTrace.push_back(encReg);

    PrintFuncHeader("DecryptClientActive");
    printf("\t%s;\n", Lift(enc, sRip).c_str());
    printf("\tif (!%s)\n\t\treturn %s;\n", Reg64(encReg), Reg64(encReg));

    DumpSwitch(encReg);
    sIgnoreTrace.clear();
}