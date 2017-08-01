#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "clemency.h"
#include "helpers.h"

// Array of mnemonics
const char *mnemonics[] = {
    "invalid",
#define INS(ins, opcode) #ins,
#include "opcodes.h"
};

// TODO Array of register names
const char *registers[] = {
    "R0", "R1", "R2", "R3",
    "R4", "R5", "R6", "R7",
    "R8", "R9", "R10", "R11",
    "R12", "R13", "R14", "R15",
    "R16", "R17", "R18", "R19",
    "R20", "R21", "R22", "R23",
    "R24", "R25", "R26", "R27",
    "R28", "ST", "RA", "PC"
};
const unsigned int num_registers = sizeof(registers) / sizeof(registers[0]);

// TODO Decoding for specific instruction formats
static void decode_R(inst_t *inst)
{
    int bit_size = 27;
    inst->insn = read_27(inst);
    FIELD(opcode, 0, 7);
    FIELD(rA, 7, 5);
    FIELD(rB, 12, 5);
    FIELD(rC, 17, 5);
    FIELD(funct, 22, 2);
    FIELD(arith_signed, 24, 1);
    FIELD(is_imm, 25, 1);
    FIELD(uf, 26, 1);
}

static void decode_R_IMM(inst_t *inst)
{
    int bit_size = 27;
    inst->insn = read_27(inst);
    FIELD(opcode, 0, 7);
    FIELD(rA, 7, 5);
    FIELD(rB, 12, 5);
    FIELD(imm, 17, 7);
    FIELD(arith_signed, 24, 1);
    FIELD(is_imm, 25, 1);
    FIELD(uf, 26, 1);
}

static void decode_U(inst_t *inst)
{
    int bit_size = 27;
    inst->insn = read_27(inst);
    FIELD(opcode, 0, 9);
    FIELD(rA, 9, 5);
    FIELD(rB, 14, 5);
    FIELD(funct, 19, 7);
    FIELD(uf, 26, 1);
}

static void decode_BIN_R(inst_t *inst)
{
    int bit_size = 18;
    inst->insn = read_18(inst);
    FIELD(opcode, 0, 8);
    FIELD(rA, 8, 5);
    FIELD(rB, 13, 5);
}

static void decode_BIN_R_IMM(inst_t *inst)
{
    int bit_size = 27;
    inst->insn = read_27(inst);
    FIELD(opcode, 0, 8);
    FIELD(rA, 8, 5);
    FIELD(imm, 13, 14);
}

static void decode_MOV_LOW_HI(inst_t *inst)
{
    int bit_size = 27;
    inst->insn = read_27(inst);
    FIELD(opcode, 0, 5);
    FIELD(rA, 5, 5);
    FIELD(imm, 10, 17);
}

static void decode_MOV_LOW_SIGNED(inst_t *inst)
{
    int bit_size = 27;
    inst->insn = read_27(inst);
    FIELD(opcode, 0, 5);
    FIELD(rA, 5, 5);
    FIELD(imm, 10, 17);
    SIGN_EXTEND(imm, 17);
}

static void decode_B_CC_OFF(inst_t *inst)
{
    int bit_size = 27;
    inst->insn = read_27(inst);
    FIELD(opcode, 0, 6);
    FIELD(cc, 6, 4);
    FIELD(imm, 10, 17);
    SIGN_EXTEND(imm, 17);
}

static void decode_B_CC_LOC(inst_t *inst)
{
    int bit_size = 27;
    inst->insn = read_27(inst);
    FIELD(opcode, 0, 6);
    FIELD(cc, 6, 4);
    FIELD(imm, 10, 17);
}

static void decode_B_CC_R(inst_t *inst)
{
    int bit_size = 18;
    inst->insn = read_18(inst);
    FIELD(opcode, 0, 6);
    FIELD(cc, 6, 4);
    FIELD(rA, 10, 5);
    FIELD(funct, 15, 3);
}

static void decode_B_OFF(inst_t *inst)
{
    int bit_size = 36;
    inst->insn = read_36(inst);
    FIELD(opcode, 0, 9);
    FIELD(imm, 9, 27);
    SIGN_EXTEND(imm, 27);
}

static void decode_B_LOC(inst_t *inst)
{
    int bit_size = 36;
    inst->insn = read_36(inst);
    FIELD(opcode, 0, 9);
    FIELD(imm, 9, 27);
}

static void decode_N(inst_t *inst)
{
    int bit_size = 18;
    inst->insn = read_18(inst);
    FIELD(opcode, 0, 18);
}

static void decode_FLAGS_INTS(inst_t *inst)
{
    int bit_size = 18;
    inst->insn = read_18(inst);
    FIELD(opcode, 0, 12);
    FIELD(rA, 12, 5);
    FIELD(funct, 17, 1);
}

static void decode_U_EXTEND(inst_t *inst)
{
    int bit_size = 27;
    inst->insn = read_27(inst);
    FIELD(opcode, 0, 12);
    FIELD(rA, 12, 5);
    FIELD(rB, 17, 5);
    FIELD(funct, 22, 5);
}

static void decode_RANDOM(inst_t *inst)
{
    int bit_size = 27;
    inst->insn = read_27(inst);
    FIELD(opcode, 0, 9);
    FIELD(rA, 9, 5);
    FIELD(funct, 14, 12);
    FIELD(uf, 26, 1);
}

static void decode_M(inst_t *inst)
{
    int bit_size = 54;
    inst->insn = read_54(inst);
    FIELD(opcode, 0, 7);
    FIELD(rA, 7, 5);
    FIELD(rB, 12, 5);
    FIELD(reg_count, 17, 5);
    FIELD(adj_rb, 22, 2);
    FIELD(imm, 24, 27);
    SIGN_EXTEND(imm, 27);
    FIELD(funct, 51, 3);

    inst->reg_count++;
}

static void decode_MP(inst_t *inst)
{
    int bit_size = 27;
    inst->insn = read_27(inst);
    FIELD(opcode, 0, 7);
    FIELD(rA, 7, 5);
    FIELD(rB, 12, 5);
    FIELD(rw, 17, 1);
    FIELD(mem_flags, 18, 2);
    FIELD(funct, 20, 7);
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

    if (inst->used_uf && inst->uf)
        strcat(inst->str, ".");
    if (inst->used_adj_rb)
    {
        if (inst->adj_rb == 1)
            strcat(inst->str, "i");
        if (inst->adj_rb == 2)
            strcat(inst->str, "d");
    }

    // TODO Print operands
    PRINT_REGISTER(rA);
    PRINT_REGISTER(rB);
    PRINT_REGISTER(rC);
    PRINT_IMMEDIATE(imm);
    PRINT_IMMEDIATE(reg_count);
}

// Disassemble one instruction from buf.
EXPORT void disassemble(inst_t *inst, uint32_t pc, const uint16_t *buf)
{
    inst->_st_size = sizeof(inst_t);
    inst->pc = pc;
    inst->bytes = buf;
    decode(inst);
    tostring(inst);
}
