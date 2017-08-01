import idaapi
import pyclemency
import string
import sys
from idaapi import *

# Registers from the C disassembler.
GREGS = list(map(str, pyclemency.registers))

REG_FP = 28
REG_ST = 29
REG_RA = 30
REG_PC = 31

# Instructions from the C disassembler.
INS = list(map(lambda x: {'name': x, 'feature': 0}, pyclemency.mnemonics))
for instr in INS:
    name = instr['name']
    if name in pyclemency.comments:
        instr['cmt'] = pyclemency.comments[name]

# Pseudo-instructions for simplification
PSEUDO_MOV = len(INS)
INS.append({'name': 'MOV', 'feature': 0, 'cmt': 'Move register (or dest, src, src)'})

PSEUDO_MOVI = len(INS)
INS.append({'name': 'MOVI', 'feature': 0, 'cmt': 'Move imm to register (mh + ml)'})

ADJ_RB_NO_ADJUST = 0
ADJ_RB_INCREMENT = 1
ADJ_RB_DECREMENT = 2

# sttd {R28,ST,RA}, [ST+#0]
CODESTARTS = ['3a016b015000000000000000'.decode('hex')]

push_args_start = '3a006801'.decode('hex')
push_args_end = '\x00' * 7 + CODESTARTS[0]
for i in xrange(6):
    nargs_d = chr(i * 0x20 + 0x10)
    nargs_i = chr(i * 0x20 + 0x8)
    CODESTARTS.insert(0, push_args_start + nargs_d + push_args_end)
    CODESTARTS.insert(0, push_args_start + nargs_i + push_args_end)

def to_uint16(s):
    arr = (ctypes.c_uint16 * (len(s)/2))()
    for x in xrange(len(s) / 2):
        arr[x] = struct.unpack('<H', s[x*2:(x+1)*2])[0]
    return arr

# instruction flags (stored in self.cmd.insnpref)
# bit 0: UF
UF = 1 << 0
# bits 1-2: adj_rb
ADJ_RB_SHIFT = 1
def get_adj_rb(flags):
    return (flags >> ADJ_RB_SHIFT) & 0b11

CC_SHIFT = 3
def get_cc(flags):
    return (flags >> CC_SHIFT) & 0b1111

CC_NAMES = {
    0b0000: 'n',
    0b0001: 'e',
    0b0010: 'l',
    0b0011: 'le',
    0b0100: 'g',
    0b0101: 'ge',
    0b0110: 'no',
    0b0111: 'o',
    0b1000: 'ns',
    0b1001: 's',
    0b1010: 'sl',
    0b1011: 'sle',
    0b1100: 'sg',
    0b1101: 'sge',
    0b1111: '',
}

# Add all instructions to our module's scope for convenience.
for i in xrange(len(INS)):
    globals()['I%s' % INS[i]['name']] = i

# XXX These are mostly optional. Don't worry about them until things are working.
# If the graph view ends the basic block after a call, then you are missing the STOP/CALL/JUMP flags.
FEATURES = {
    Ibr: CF_JUMP,
    Icr: CF_JUMP | CF_CALL,
    Iht: CF_STOP,
    Ire: CF_STOP,
    Ic: CF_CALL,
    Icar: CF_CALL,
}
for insn, features in FEATURES.items():
    INS[insn]['feature'] = features

# is sp delta fixed by the user?
def is_fixed_spd(ea):
    return (get_aflags(ea) & AFL_FIXEDSPD) != 0

def to_signed(offset):
    return struct.unpack('i', struct.pack('I', offset))[0]

def lookahead_instruction(addr, size=12):
    end = min(addr + size, SegEnd(addr))
    return to_uint16(get_many_bytes(addr, end - addr))

class clemency_hooks_t(idaapi.IDP_Hooks):
    def out_3byte(self, dataea, value, analyze_only):
        if not analyze_only:
            out_long((get_full_byte(dataea+1)<<18) | (get_full_byte(dataea+0)<<9) | get_full_byte(dataea+2), 16)
            return 2
        return 1

class clemency_processor_t(idaapi.processor_t):
    # IDP id ( Numbers above 0x8000 are reserved for the third-party modules)
    id = 0x8000 + 2

    # Processor features
    flag = PR_ASSEMBLE | PR_SEGS | PR_DEFSEG32 | PR_USE32 | PRN_HEX | PR_RNAMESOK | PR_NO_SEGMOVE

    # Number of bits in a byte for code segments (usually 8)
    # IDA supports values up to 32 bits
    cnbits = 16

    # Number of bits in a byte for non-code segments (usually 8)
    # IDA supports values up to 32 bits
    dnbits = 16

    # short processor names
    # Each name should be shorter than 9 characters
    psnames = ['clemency']

    # long processor names
    # No restriction on name lengthes.
    plnames = ['Clemency']

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
    codestart = CODESTARTS

    # Array of 'return' instruction opcodes (optional)
    retcodes = ['00004001'.decode('hex')]

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
    icode_return = Ire

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
        'a_tbyte': "",
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
        'a_3byte': "dt",
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

    def notify_get_autocmt(self):
        """
        Get instruction comment. 'cmd' describes the instruction in question
        @return: None or the comment string
        """
        if 'cmt' in self.instruc[self.cmd.itype]:
            return self.instruc[self.cmd.itype]['cmt']

    # Instructions that jump and then come back.
    def is_call(self):
        return self.cmd.itype in [ Ic, Icaa, Icar, Icr ]

    # Instructions that jump somewhere and don't come back.
    def is_jump(self):
        return self.cmd.itype in [ Ib, Ibr, Ibra, Ibrr ]

    def is_load_store(self):
        return self.cmd.itype in [Ilds, Ildt, Ildw, Ists, Istt, Istw]

    def is_conditional_branch(self):
        return self.cmd.itype in [Ib, Ibr, Ic, Icr]

    visited_addrs = set()
    # Attempt to detect whether addr is a string.
    def emu_offset(self, addr):
        if addr in self.visited_addrs:
            return
        self.visited_addrs.add(addr)

        start = addr
        end = None
        while end is None:
            try:
                size = min((SegEnd(addr) - addr) * 2, 32)
                data = GetManyBytes(addr, size)
            except:
                return
            if data is None:
                return
            for i in xrange(0, len(data), 2):
                if data[i+1] != '\0':
                    return
                c = data[i]
                if c == '\0':
                    end = addr + i / 2 + 1
                    break
                if c not in string.printable:
                    return
            addr += len(data) / 2
        # heuristic: assume 2 printable chars followed by a null byte is
        # a string
        if end - start > 2:
            make_ascii_string(start, end - start, ASCSTR_UNICODE)

    # Add cross-references for an operand.
    def emu_operand(self, op):
        itype = self.cmd.itype
        optype = op.type

        def is_addr(addr):
            if addr < 0x1000:
                return False
            return SegStart(addr) != BADADDR

        if optype == o_imm:
            if self.is_call():
                ua_add_cref(0, op.value, fl_CN)
                op_offset(self.cmd.ea, op.n, REF_OFF32, op.value)
            elif self.is_jump():
                ua_add_cref(0, op.value, fl_JN)
                op_offset(self.cmd.ea, op.n, REF_OFF32, op.value)
            elif is_addr(op.value):
                # heuristic: treat values > 0x1000 as offsets.
                self.emu_offset(op.value)
                op_offset(self.cmd.ea, op.n, REF_OFF32, op.value)
                ua_dodata2(self.cmd.ea, op.value, op.dtyp)
                ua_add_dref(self.cmd.ea, op.value, dr_O)


    def add_stkpnt(self, pfn, v):
        if pfn:
            end = self.cmd.ea + self.cmd.size
            if not is_fixed_spd(end):
                add_auto_stkpnt2(pfn, end, v)

    def trace_sp(self):
        pfn = get_func(self.cmd.ea)
        if not pfn:
            return

        spd = get_spd(pfn, self.cmd.ea)

        if self.cmd.itype == Ior and self.cmd.Op1.reg == REG_FP and self.cmd.Op2.reg == self.cmd.Op3.reg == REG_ST:
            add_frame(pfn, abs(spd), 0, 0)
            return

        offset = 0

        addis = [Iadci, Iadi]
        subis = [Isbci, Isbi]
        if self.cmd.itype in (addis + subis) and self.cmd.Op1.reg == REG_ST:
            offset = to_signed(self.cmd.Op3.value)
            if self.cmd.itype in subis:
                offset = -offset
        elif self.is_load_store():
            adj_rb = get_adj_rb(self.cmd.insnpref)

            scale = 1
            if self.cmd.itype in [Ildw, Istw]:
                scale = 2
            elif self.cmd.itype in [Ildt, Istt]:
                scale = 3

            regcount = self.cmd.Op3.value

            if self.cmd.Op2.reg == REG_ST:
                # push or pop
                if adj_rb == ADJ_RB_NO_ADJUST:
                    return
                offset = regcount * scale
                if adj_rb == ADJ_RB_DECREMENT:
                    offset = -offset
            elif self.cmd.Op1.reg == REG_FP and regcount > (REG_ST - REG_FP):
                # mov sp, [bp]
                offset = -(spd - pfn.frregs)

        if offset != 0:
            self.add_stkpnt(pfn, offset)

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
        if self.cmd.Op4.type != o_void:
            self.emu_operand(self.cmd.Op4)
        if self.cmd.Op5.type != o_void:
            self.emu_operand(self.cmd.Op5)

        itype = self.cmd.itype
        uncond_jmp = itype in [Ibra, Ibrr] or (itype in [Ib, Ibr] and get_cc(self.cmd.insnpref) == 0xf)

        flow = (Feature & CF_STOP == 0) and not uncond_jmp
        if flow:
            ua_add_cref(0, self.cmd.ea + self.cmd.size, fl_F)

        if may_trace_sp():
            if flow:
                self.trace_sp() # trace modification of SP register
            else:
                recalc_spd(self.cmd.ea) # recalculate SP register for the next insn

        ''' # stack doesn't work :-(
        if may_create_stkvars() and self.is_load_store() and self.cmd.Op2.reg == REG_FP:
            pfn = get_func(self.cmd.ea)
            op = self.cmd.Op4
            if pfn and ua_stkvar2(op, op.value, STKVAR_VALID_SIZE):
                op_stkvar(self.cmd.ea, op.n)
        '''

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
        suffix = ''

        adj_rb = get_adj_rb(self.cmd.insnpref)
        if adj_rb > 0:
            suffix += ['', 'i', 'd'][adj_rb]

        if self.is_conditional_branch():
            suffix += CC_NAMES[get_cc(self.cmd.insnpref)]

        if self.cmd.insnpref & UF != 0:
            suffix += '.'

        OutMnem(8, suffix)

        # pretty-print [rA + Offset, RegCount]
        if self.is_load_store():
            regcount = self.cmd.Op3.value
            offset = self.cmd.Op4.value

            if regcount > 1:
                start_reg = self.cmd.Op1.reg
                regs = [(start_reg + i) % len(GREGS) for i in xrange(regcount)]
                out_symbol('{')
                for i, reg in enumerate(regs):
                    out_register(GREGS[reg])
                    if i != len(regs) - 1:
                        out_symbol(',')
                out_symbol('}')
            else:
                out_one_operand(0)

            out_symbol(',')
            OutChar(' ')
            out_symbol('[')
            out_one_operand(1) # register
            if offset != 0:
                out_symbol('+')
                out_one_operand(3) # offset
            out_symbol(']')

        elif self.cmd.itype == Ismp:
            out_one_operand(0)
            out_symbol(',')
            OutChar(' ')
            out_one_operand(1)
            out_symbol(',')
            OutChar(' ')
            s = ['MEM_NO_ACCESS', 'MEM_RO', 'MEM_RW', 'MEM_RE']
            for c in s[self.cmd.Op3.value]:
                OutChar(c)

        else:
            # output first operand
            # kernel will call outop()
            if self.cmd.Op1.type != o_void:
                out_one_operand(0)

            # output the rest of operands separated by commas
            for i in xrange(1, 5):
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

    def fill_op_imm(self, op, imm, inst=None):
        op.type = o_imm
        op.dtyp = dt_qword

        if imm > 0:
            imm = to_signed(imm)

        if self.is_imm_relative(inst):
            op.value = imm + inst.pc
        else:
            op.value = imm

    # Simplify some instructions for brevity. Returns True if the
    # instruction was rewritten (in which case this function is
    # responsible for filling populating the necessary itype, operands,
    # and instruction size).
    def simplify(self, inst):
        itype = inst.id

        if itype == Ior and inst.rB == inst.rC:
            self.cmd.itype = PSEUDO_MOV
            self.fill_op_reg(self.cmd.Op1, inst.rA)
            self.fill_op_reg(self.cmd.Op2, inst.rB)
            self.cmd.size = inst.size
            return True

        elif itype == Iml:
            next_addr = self.cmd.ea + inst.size
	    next_inst = pyclemency.disassemble(next_addr, lookahead_instruction(next_addr))
	    if next_inst.insn == Iinvalid or next_inst.id != Imh or inst.rA != next_inst.rA:
		return False
            lo = inst.imm
            hi = next_inst.imm
            value = (hi << 10) | lo
            self.cmd.itype = PSEUDO_MOVI
            self.fill_op_reg(self.cmd.Op1, inst.rA)
            self.fill_op_imm(self.cmd.Op2, value)
            self.cmd.size = inst.size + next_inst.size
            return True

        return False

    def is_imm_relative(self, inst):
        if inst is None:
            return False
        return inst.id in [Ib, Ic, Ibrr, Icar]

    def ana(self):
        """
        Decodes an instruction into self.cmd.
        Returns: self.cmd.size (=the size of the decoded instruction) or zero
        """
        inst = pyclemency.disassemble(self.cmd.ea, lookahead_instruction(self.cmd.ea))
        if inst.insn == Iinvalid:
            # Ignore invalid instructions
            return 0

        self.cmd.size = inst.size
        self.cmd.itype = inst.id
        self.cmd.insnpref = 0

        if inst.used_uf and inst.uf:
            self.cmd.insnpref |= UF
        if inst.used_adj_rb and inst.adj_rb:
            self.cmd.insnpref |= inst.adj_rb << ADJ_RB_SHIFT
        if inst.used_cc:
            self.cmd.insnpref |= inst.cc << CC_SHIFT

        if self.simplify(inst):
            return self.cmd.size

        op = 0
        ops = (self.cmd.Op1, self.cmd.Op2, self.cmd.Op3, self.cmd.Op4, self.cmd.Op5)
        if inst.used_rA:
            self.fill_op_reg(ops[op], inst.rA)
            op += 1
        if inst.used_rB:
            self.fill_op_reg(ops[op], inst.rB)
            op += 1
        if inst.used_rC:
            self.fill_op_reg(ops[op], inst.rC)
            op += 1
        if inst.used_reg_count:
            self.fill_op_imm(ops[op], inst.reg_count)
            op += 1
        if inst.used_imm:
            self.fill_op_imm(ops[op], inst.imm, inst)
            op += 1
        if inst.used_mem_flags:
            self.fill_op_imm(ops[op], inst.mem_flags)
            op += 1

        # Return decoded instruction size or zero
        return self.cmd.size

hooks_idp = None
def PROCESSOR_ENTRY():
    global hooks_idp
    hooks_idp = clemency_hooks_t()
    hooks_idp.hook()
    return clemency_processor_t()
