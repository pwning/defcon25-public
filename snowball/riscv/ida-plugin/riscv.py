import sys
import pyriscv
import idaapi
from idaapi import *

# Registers from the C disassembler.
GREGS = list(map(str, pyriscv.registers))

# Instructions from the C disassembler.
INS = list(map(lambda x: {'name': x, 'feature': 0}, pyriscv.mnemonics))

# Pseudo-instructions for simplification
INS += [
    {'name': 'mov', 'feature': 0},
    {'name': 'movi', 'feature': 0},
]

# Add all instructions to our module's scope for convenience.
for i in xrange(len(INS)):
    globals()['I%s' % INS[i]['name']] = i

# XXX These are mostly optional. Don't worry about them until things are working.
# If the graph view ends the basic block after a call, then you are missing the STOP/CALL/JUMP flags.
FEATURES = {
    # Control flow instructions
    Ijr: CF_STOP | CF_JUMP | CF_USE1,
    Ijalr: CF_CALL | CF_JUMP | CF_USE1 | CF_USE2,
    Ij: CF_STOP | CF_USE1,
    Ijal: CF_CALL | CF_USE1 | CF_USE2,
    # Conditional jumps should not have CF_STOP
    Ibeq: CF_USE1 | CF_USE2 | CF_USE3,
    Ibne: CF_USE1 | CF_USE2 | CF_USE3,
    Ibge: CF_USE1 | CF_USE2 | CF_USE3,
    Iblt: CF_USE1 | CF_USE2 | CF_USE3,
    Ibgeu: CF_USE1 | CF_USE2 | CF_USE3,
    Ibltu: CF_USE1 | CF_USE2 | CF_USE3,
    # Shift instructions
    Isll: CF_CHG1 | CF_USE2 | CF_USE3 | CF_SHFT,
    Isrl: CF_CHG1 | CF_USE2 | CF_USE3 | CF_SHFT,
    Isra: CF_CHG1 | CF_USE2 | CF_USE3 | CF_SHFT,
    Islli: CF_CHG1 | CF_USE2 | CF_USE3 | CF_SHFT,
    Isrli: CF_CHG1 | CF_USE2 | CF_USE3 | CF_SHFT,
    Israi: CF_CHG1 | CF_USE2 | CF_USE3 | CF_SHFT,
    # Arithmetic instructions
    Iaddi: CF_CHG1 | CF_USE2 | CF_USE3,
    Islti: CF_CHG1 | CF_USE2 | CF_USE3,
    Isltiu: CF_CHG1 | CF_USE2 | CF_USE3,
    Ixori: CF_CHG1 | CF_USE2 | CF_USE3,
    Iori: CF_CHG1 | CF_USE2 | CF_USE3,
    Iandi: CF_CHG1 | CF_USE2 | CF_USE3,
    Iadd: CF_CHG1 | CF_USE2 | CF_USE3,
    Isub: CF_CHG1 | CF_USE2 | CF_USE3,
    Islt: CF_CHG1 | CF_USE2 | CF_USE3,
    Isltu: CF_CHG1 | CF_USE2 | CF_USE3,
    Ixor: CF_CHG1 | CF_USE2 | CF_USE3,
    Ior: CF_CHG1 | CF_USE2 | CF_USE3,
    Iand: CF_CHG1 | CF_USE2 | CF_USE3,
    Imul: CF_CHG1 | CF_USE2 | CF_USE3,
    Imulh: CF_CHG1 | CF_USE2 | CF_USE3,
    Imulhsu: CF_CHG1 | CF_USE2 | CF_USE3,
    Imulhu: CF_CHG1 | CF_USE2 | CF_USE3,
    Idiv: CF_CHG1 | CF_USE2 | CF_USE3,
    Idivu: CF_CHG1 | CF_USE2 | CF_USE3,
    Irem: CF_CHG1 | CF_USE2 | CF_USE3,
    Iremu: CF_CHG1 | CF_USE2 | CF_USE3,
    # Load instructions
    Ilb: CF_CHG1 | CF_USE2 | CF_USE3,
    Ilh: CF_CHG1 | CF_USE2 | CF_USE3,
    Ilw: CF_CHG1 | CF_USE2 | CF_USE3,
    Ilbu: CF_CHG1 | CF_USE2 | CF_USE3,
    Ilhu: CF_CHG1 | CF_USE2 | CF_USE3,
    # Store instructions
    Isb: CF_USE1 | CF_USE2 | CF_USE3,
    Ish: CF_USE1 | CF_USE2 | CF_USE3,
    Isw: CF_USE1 | CF_USE2 | CF_USE3,
    # Load constant instructions
    Ilui: CF_CHG1 | CF_USE2,
    Iauipc: CF_CHG1 | CF_USE2,
    # Pseudo-instructions
    Imovi: CF_CHG1 | CF_USE2,
    Imov: CF_CHG1 | CF_USE2,
}
for insn, features in FEATURES.items():
    INS[insn]['feature'] = features

class riscv_processor_t(idaapi.processor_t):
    # IDP id ( Numbers above 0x8000 are reserved for the third-party modules)
    id = 0x8000 + 1

    # Processor features
    flag = PR_ASSEMBLE | PR_SEGS | PR_DEFSEG32 | PR_USE32 | PRN_HEX | PR_RNAMESOK | PR_NO_SEGMOVE

    # Number of bits in a byte for code segments (usually 8)
    # IDA supports values up to 32 bits
    cnbits = 8

    # Number of bits in a byte for non-code segments (usually 8)
    # IDA supports values up to 32 bits
    dnbits = 8

    # short processor names
    # Each name should be shorter than 9 characters
    psnames = ['riscv32']

    # long processor names
    # No restriction on name lengthes.
    plnames = ['RISC-V 32-bit']

    # register names
    regNames = GREGS + [
        # Fake segment registers
        "CS",
        "DS"
    ]

    # number of registers (optional: deduced from the len(regNames))
    regsNum = len(regNames)

    # Segment register information (use virtual CS and DS registers if your
    # processor doesn't have segment registers):
    regFirstSreg = 16 # index of CS
    regLastSreg  = 17 # index of DS

    # size of a segment register in bytes
    segreg_size = 0

    # You should define 2 virtual segment registers for CS and DS.

    # number of CS/DS registers
    regCodeSreg = 16
    regDataSreg = 17

    # Array of typical code start sequences (optional)
    # codestart = ['\x55\x8B', '\x50\x51']

    # Array of 'return' instruction opcodes (optional)
    # retcodes = ['\xC3', '\xC2']

    # Array of instructions
    instruc = INS

    # icode of the first instruction
    instruc_start = 0

    # icode of the last instruction + 1
    instruc_end = len(instruc) + 1

    #
    # Number of digits in floating numbers after the decimal point.
    # If an element of this array equals 0, then the corresponding
    # floating point data is not used for the processor.
    # This array is used to align numbers in the output.
    #      real_width[0] - number of digits for short floats (only PDP-11 has them)
    #      real_width[1] - number of digits for "float"
    #      real_width[2] - number of digits for "double"
    #      real_width[3] - number of digits for "long double"
    # Example: IBM PC module has { 0,7,15,19 }
    #
    # (optional)
    real_width = (0, 7, 15, 0)

    # icode (or instruction number) of return instruction. It is ok to give any of possible return
    # instructions
    icode_return = Ijr

    # only one assembler is supported
    assembler = {
        'flag' : ASH_HEXF3 | AS_UNEQU | AS_COLON | ASB_BINF4 | AS_N2CHR,
        'name': "My processor module bytecode assembler",
        'origin': "org",
        'end': "end",
        'cmnt': ";",
        'ascsep': "\"",
        'accsep': "'",
        'esccodes': "\"'",
        'a_ascii': "db",
        'a_byte': "db",
        'a_word': "dw",
        'a_dword': "dd",
        'a_qword': "dq",
        'a_oword': "xmmword",
        'a_yword': "ymmword",
        'a_float': "dd",
        'a_double': "dq",
        'a_tbyte': "dt",
        'a_packreal': "",
        'a_dups': "#d dup(#v)",
        'a_bss': "%s dup ?",
        'a_equ': ".equ",
        'a_seg': "seg",
        'a_curip': "$",
        'a_public': "public",
        'a_weak': "weak",
        'a_extrn': "extrn",
        'a_comdef': "",
        'a_align': "align",
        'lbrace': "(",
        'rbrace': ")",
        'a_mod': "%",
        'a_band': "&",
        'a_bor': "|",
        'a_xor': "^",
        'a_bnot': "~",
        'a_shl': "<<",
        'a_shr': ">>",
        'a_sizeof_fmt': "size %s",
        'flag2': 0,
        'cmnt2': "",
        'low8': "",
        'high8': "",
        'low16': "",
        'high16': "",
        'a_include_fmt': "include %s",
        'a_vstruc_fmt': "",
        'a_3byte': "",
        'a_rva': "rva"
    } # Assembler

    def notify_is_sane_insn(self, no_crefs):
        """
        is the instruction sane for the current file type?
        args: no_crefs
        1: the instruction has no code refs to it.
           ida just tries to convert unexplored bytes
           to an instruction (but there is no other
           reason to convert them into an instruction)
        0: the instruction is created because
           of some coderef, user request or another
           weighty reason.
        The instruction is in 'cmd'
        returns: 1-ok, <=0-no, the instruction isn't
        likely to appear in the program
        """
        if get_32bit(self.cmd.ea) == 0:
            # All zeros is an invalid instruction.
            return 0
        return 1

    # Instructions that jump and then come back.
    def is_call(self):
        return self.cmd.itype in [
            Ijal,
            Ijalr,
        ]

    # Instructions that jump somewhere and don't come back.
    def is_jump(self):
        return self.cmd.itype in [
            Ij,
            Ijr,
            Ibeq,
            Ibne,
            Iblt,
            Ibge,
            Ibltu,
            Ibgeu,
        ]

    # Add cross-references for an operand.
    def emu_operand(self, op):
        itype = self.cmd.itype
        optype = op.type

        if optype == o_imm:
            if self.is_call():
                ua_add_cref(0, op.value, fl_CN)
            elif self.is_jump():
                ua_add_cref(0, op.value, fl_JN)

    def emu(self):
        """
        Emulate instruction, create cross-references, plan to analyze
        subsequent instructions, modify flags etc. Upon entrance to this function
        all information about the instruction is in 'cmd' structure.
        If zero is returned, the kernel will delete the instruction.
        """
        Feature = self.cmd.get_canon_feature()

        if self.cmd.Op1.type != o_void:
            self.emu_operand(self.cmd.Op1)
        if self.cmd.Op2.type != o_void:
            self.emu_operand(self.cmd.Op2)
        if self.cmd.Op3.type != o_void:
            self.emu_operand(self.cmd.Op3)

        uncond_jmp = self.cmd.itype in [Ij, Ijr]

        flow = (Feature & CF_STOP == 0) and not uncond_jmp
        if flow:
            ua_add_cref(0, self.cmd.ea + self.cmd.size, fl_F)

        return 1

    def outop(self, op):
        """
        Generate text representation of an instructon operand.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by u_emu() function.
        The output text is placed in the output buffer initialized with init_output_buffer()
        This function uses out_...() functions from ua.hpp to generate the operand text
        Returns: 1-ok, 0-operand is hidden.
        """
        optype = op.type

        # We only have two types of operands: registers and immediates.
        if optype == o_reg:
            out_register(self.regNames[op.reg])
        elif optype == o_imm:
            out_symbol('#')
            OutValue(op, OOFW_IMM | OOF_SIGNED)
        else:
            return False
        return True

    def out(self):
        """
        Generate text representation of an instruction in 'cmd' structure.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by u_emu() function.
        Returns: nothing
        """
        # Init output buffer
        buf = idaapi.init_output_buffer(1024)
        OutMnem()

        # output first operand
        # kernel will call outop()
        if self.cmd.Op1.type != o_void:
            out_one_operand(0)

        # output the rest of operands separated by commas
        for i in xrange(1, 3):
            if self.cmd[i].type == o_void:
                break
            out_symbol(',')
            OutChar(' ')
            out_one_operand(i)

        term_output_buffer()
        cvar.gl_comm = 1 # generate comment at the next call to MakeLine()
        MakeLine(buf)

    def fill_op_reg(self, op, r):
        op.type = o_reg
        op.dtyp = dt_dword
        op.reg = r

    def fill_op_imm(self, op, imm):
        op.type = o_imm
        op.dtyp = dt_dword
        op.value = imm

    # Simplify some instructions for brevity.
    def simplify(self, inst):
        itype = inst.id

        if itype == Iaddi:
            # addi rd, rs1, #0 -> mov rd, rs1
            if inst.imm == 0:
                inst.id = Imov
                inst.used_imm = 0
            # addi rd, zero, #0 -> movi rd, #0
            elif inst.rs1 == 0:
                inst.id = Imovi
                inst.used_rs1 = 0

    def ana(self):
        """
        Decodes an instruction into self.cmd.
        Returns: self.cmd.size (=the size of the decoded instruction) or zero
        """
        if (self.cmd.ea & 3) != 0:
            # Unaligned addresses cannot have instructions
            return 0

        inst = pyriscv.disassemble(self.cmd.ea, str(get_many_bytes(self.cmd.ea, 4)))
        if inst.insn == Iinvalid:
            # Ignore invalid instructions
            return 0

        self.simplify(inst)

        self.cmd.size = inst.size
        self.cmd.itype = inst.id

        op = 0
        ops = (self.cmd.Op1, self.cmd.Op2, self.cmd.Op3)
        if inst.used_rd:
            self.fill_op_reg(ops[op], inst.rd)
            op += 1
        if inst.used_rs1:
            self.fill_op_reg(ops[op], inst.rs1)
            op += 1
        if inst.used_rs2:
            self.fill_op_reg(ops[op], inst.rs2)
            op += 1
        if inst.used_imm:
            self.fill_op_imm(ops[op], inst.imm)
            op += 1

        # Return decoded instruction size or zero
        return self.cmd.size

def PROCESSOR_ENTRY():
    return riscv_processor_t()
