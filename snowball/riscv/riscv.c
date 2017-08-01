#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// TODO Uncomment if target instructions are big endian
#undef BIG_ENDIAN
// #define BIG_ENDIAN

#include "riscv.h"
#include "helpers.h"

// Array of mnemonics
const char *mnemonics[] = {
    "invalid",
#define INS(ins, opcode) #ins,
#include "opcodes.h"
};

// TODO Array of register names
const char *registers[] = {
   "zero",  "x1",  "x2",  "x3",  "x4",  "x5",  "x6",  "x7",
     "x8",  "x9", "x10", "x11", "x12", "x13", "x14", "x15",
    "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
    "x24", "x25", "x26", "x27", "x28", "x29", "x30", "x31"
};
const unsigned int num_registers = sizeof(registers) / sizeof(registers[0]);

// TODO Read instruction from a buffer.
static void read_insn(inst_t *inst)
{
    inst->insn = read_32(inst);
}

// TODO Decoding for specific instruction formats
static void decode_R(inst_t *inst)
{
    read_insn(inst);
    FIELD(opcode, 0, 7);
    FIELD(rd, 7, 5);
    FIELD(funct3, 12, 3);
    FIELD(rs1, 15, 5);
    FIELD(rs2, 20, 5);
    FIELD(funct7, 25, 7);
}
static void decode_Rshift(inst_t *inst)
{
    read_insn(inst);
    FIELD(opcode, 0, 7);
    FIELD(rd, 7, 5);
    FIELD(funct3, 12, 3);
    FIELD(rs1, 15, 5);
    FIELD(imm, 20, 5);
    FIELD(funct7, 25, 7);
}
static void decode_I(inst_t *inst)
{
    read_insn(inst);
    FIELD(opcode, 0, 7);
    FIELD(rd, 7, 5);
    FIELD(funct3, 12, 3);
    FIELD(rs1, 15, 5);
    FIELD(imm, 20, 12);
    SIGN_EXTEND(imm, 12);
}
static void decode_Ijr(inst_t *inst)
{
    decode_I(inst);
    inst->used_rd = 0;
}
static void decode_E(inst_t *inst)
{
    decode_I(inst);
    inst->used_rd = 0;
    inst->used_rs1 = 0;
    inst->used_imm = 0;
}
static void decode_Ishift(inst_t *inst)
{
    read_insn(inst);
    FIELD(opcode, 0, 7);
    FIELD(rd, 7, 5);
    FIELD(funct3, 12, 3);
    FIELD(rs1, 15, 5);
    FIELD(imm, 20, 5);
    FIELD(funct7, 25, 7);
}
static void decode_S(inst_t *inst)
{
    read_insn(inst);
    FIELD(opcode, 0, 7);
    FIELD(funct3, 12, 3);
    FIELD(rs1, 15, 5);
    FIELD(rs2, 20, 5);
    FIELD(imm, 25, 7);
    CONCAT(imm, 7, 5);
    SIGN_EXTEND(imm, 12);
}
static void decode_B(inst_t *inst)
{
    read_insn(inst);
    FIELD(opcode, 0, 7);
    FIELD(funct3, 12, 3);
    FIELD(rs1, 15, 5);
    FIELD(rs2, 20, 5);
    FIELD(imm, 31, 1);
    CONCAT(imm, 7, 1);
    CONCAT(imm, 25, 6);
    CONCAT(imm, 8, 4);
    SIGN_EXTEND(imm, 12);
    inst->imm <<= 1;
    inst->imm += inst->pc; // PC-relative
}
static void decode_U(inst_t *inst)
{
    read_insn(inst);
    FIELD(opcode, 0, 7);
    FIELD(rd, 7, 5);
    FIELD(imm, 12, 20);
}
static void decode_J(inst_t *inst)
{
    read_insn(inst);
    FIELD(opcode, 0, 7);
    FIELD(rd, 7, 5);
    FIELD(imm, 31, 1);
    CONCAT(imm, 12, 8);
    CONCAT(imm, 20, 1);
    CONCAT(imm, 21, 10);
    SIGN_EXTEND(imm, 20);
    inst->imm <<= 1;
    inst->imm += inst->pc; // PC-relative
}
static void decode_Jj(inst_t *inst)
{
    decode_J(inst);
    inst->used_rd = 0;
}

// Decode instruction
static void decode(inst_t *inst)
{
#define FORMAT(fmt) do { clear_used(inst); inst->size = 0; decode_##fmt(inst); } while (0);
#define INS(x,opc) do { if (inst->opcode == opc) { inst->id = I##x; return; } } while (0);
#define INS_1(x,opc,f1,v1) do { if (inst->opcode == opc && inst->f1 == v1) { inst->id = I##x; return; } } while (0);
#define INS_2(x,opc,f1,v1,f2,v2) do { if (inst->opcode == opc && inst->f1 == v1 && inst->f2 == v2) { inst->id = I##x; return; } } while (0);
#define INS_3(x,opc,f1,v1,f2,v2,f3,v3) do { if (inst->opcode == opc && inst->f1 == v1 && inst->f2 == v2 && inst->f3 == v3) { inst->id = I##x; return; } } while (0);
#define INS_4(x,opc,f1,v1,f2,v2,f3,v3,f4,v4) do { if (inst->opcode == opc && inst->f1 == v1 && inst->f2 == v2 && inst->f3 == v3 && inst->f4 == v4) { inst->id = I##x; return; } } while (0);
#include "opcodes.h"
    // default to invalid
    clear_used(inst);
    inst->size = 0;
    inst->id = Iinvalid;
}

// Print instruction
static void tostring(inst_t *inst)
{
    int first = 1;
    inst->mnemonic = mnemonics[inst->id];
    strcpy(inst->str, inst->mnemonic);

    // TODO Print operands
    PRINT_REGISTER(rd);
    PRINT_REGISTER(rs1);
    PRINT_REGISTER(rs2);
    PRINT_IMMEDIATE(imm);
}

// Disassemble one instruction from buf.
EXPORT void disassemble(inst_t *inst, uint32_t pc, const uint8_t *buf)
{
    inst->_st_size = sizeof(inst_t);
    inst->pc = pc;
    inst->bytes = buf;
    decode(inst);
    tostring(inst);
}
