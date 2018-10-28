import struct
import pyparsing
import re

special_regs = {"ST": 29, "RA": 30, "PC": 31}

conditions   = "n e l le g ge no o ns s sl sle sg sge".split()
orderedconds = "sge sg sle sl ns no ge le n e l g o s".split()
specials     = [".", "I", "D"] + orderedconds

def u(x, ip=None):
  if isinstance(x, pyparsing.ParseResults):
    return x.asList()[0]
  if isinstance(x, Symbolic):
    return x.value(ip)
  return x

class BitString(object):
  CHECK = False
  def __init__(self, v, size, ip=0, signed=False):
    v = u(v, ip)
    if self.CHECK:
      if signed:
        if v < -(1 << (size-1)) or v >= (1 << (size-1)):
          raise ValueError("Value %d out of range for signed bitfield of size %d" % (v, size))
      else:
        if v < 0 or v >= (1 << size):
          raise ValueError("Value %d out of range for unsigned bitfield of size %d" % (v, size))
    self.v = v & ((1 << size) - 1)
    self.size = size

  def __add__(self, other):
    if not isinstance(other, BitString):
      other = BitString(int(other.encode("hex"),16), len(other)*8)
    return BitString( (self.v << other.size) | other.v, self.size+other.size)

  def __str__(self):
    assert (self.size%8 == 0), "Cannot stringify bitstring of partial bytes"
    return ((hex(self.v)[2:].replace("L","")).rjust((2*len(self)+7)/8, "0")).decode("hex")

  def __len__(self):
    return self.size

  def __repr__(self):
    return "{ %s }"%( bin(self.v)[2:].rjust(self.size, "0") )

  def force_str(self):
    """kinda like str, but will 0 pad at the end"""
    extra = 8-(self.size%8)
    return str(self + BitString(0, extra))

  def __getitem__(self, item):
    if isinstance(item, slice):
      assert not item.step, "No step size supported for slicing"
      if item.start > self.size:
        return BitString(0,0)

      newsize = min(item.stop, self.size) - item.start
      newval  = self.v >> (self.size - newsize - item.start)
      newval &= (1<<newsize)-1
      return BitString(newval, newsize)

class Arg(object):
  def __init__(self, v):
    self.v = u(v)
  def __len__(self):
    """Returns the length in bits"""
    return 8*len(self.raw())
  def __str__(self):
    return "{%s:%s}"%(str(self.__class__.__name__.split("_")[-1]), str(self.v))
  def __repr__(self):
    return self.__str__()
  def arg_size(self):
    return None

class Reg(Arg):
  def raw(self, ip=None):
    if self.v in special_regs:
      return BitString(special_regs[self.v], 5)
    else:
      return BitString(int(self.v[1:]), 5)
  def arg_size(self):
    return 27

class Imm(Arg):
  def raw(self, ip=None):
    return BitString(self.v, 27)
  def arg_size(self):
    return 27

class Const(object):
  def __init__(self, psm, num):
    sizes = {'.ds':1, '.dw':2, '.dt':3, '.dm':6}
    bits = sizes[psm]*9
    self.val = BitString(num, bits)
  def raw(self, ip=None):
    return self.val

class Symbolic(object):
  pass

class Expr(Symbolic):
  def __init__(self, vstr, labelstore, offset=0):
    self.vstr = vstr
    self.labelstore = labelstore
    self.offset = offset
  def __add__(self, value):
    return Expr(self.vstr, self.labelstore, offset=value)
  def __sub__(self, value):
    return Expr(self.vstr, self.labelstore, offset=-value)
  def value(self, ip):
    #shitty eval to eval b2xiao's math
    fixed = self.vstr.replace("$ip", "(ip)")
    fixed = re.sub("\$([a-zA-Z][a-zA-Z0-9]+)","labels.get('\\1',0)",fixed)
    return eval(fixed, {'labels':self.labelstore, 'ip':ip})+self.offset

class Label(Symbolic):
  def __init__(self, name, labelstore, offset=0):
    self.name = name
    self.labelstore = labelstore
    self.offset = offset
  def update(self, value):
    self.labelstore[self.name] = value
  def __add__(self, value):
    return Label(self.name, self.labelstore, offset=value)
  def __sub__(self, value):
    return Label(self.name, self.labelstore, offset=-value)
  def value(self, ip):
    return self.labelstore.get(self.name, 0)+self.offset

class Ins_conditional_offset(object):
  def __init__(self, args, condition=0):
    offset = args[0]
    condition_code = 0
    if not condition:
      condition_code = 15 #unconditional
    elif condition in conditions:
      condition_code = conditions.index(condition)
    else:
      raise Exception("Unknown condition code for instruction: %s"%(condition))
    self.condition_code = condition_code
    self.offset = offset
  def raw(self, ip):
    op = BitString(self.opcodestr, 6) + BitString(self.condition_code, 4)
    return op + BitString(self.offset - ip, 17, ip, signed=True)

class Ins_conditional_reg(object):
  def __init__(self, args, condition=0):
    reg, = args
    condition_code = 0
    if not condition:
      condition_code = 15 #unconditional
    elif condition in conditions:
      condition_code = conditions.index(condition)
    else:
      raise Exception("Unknown condition code for instruction: %s"%(condition))
    self.condition_code = condition_code
    self.reg = reg
  def raw(self, ip):
    op = BitString(self.opcodestr, 6) + BitString(self.condition_code, 4)
    return op + self.reg.raw() + BitString(0, 3)

class Ins_offset(object):
  relative = False
  def __init__(self, args):
    self.offset = args[0]
  def raw(self, ip):
    op = BitString(self.opcodestr, 9)
    if self.relative:
      return op + BitString(self.offset - ip, 27, ip, signed=True)
    else:
      return op + BitString(self.offset, 27, ip, signed=False)

class Ins_three_ref_uf(object):
  special = 0
  def __init__(self, args, uf=False):
    assert len(args) == 3, "Need 3 args for that op"
    self.a = args[0]
    self.b = args[1]
    self.c = args[2]
    self.uf = uf
  def raw(self, ip):
    op = BitString(self.opcodestr, 7)

    partial = op + self.a.raw() + self.b.raw() + self.c.raw()
    partial += BitString(self.special, 4)
    partial += BitString(0b1,1) if self.uf else BitString(0b0,1)
    return partial

class Ins_three(object):
  def __init__(self, args, uf=False):
    assert len(args) == 3, "Need 3 args for that op"
    self.a = args[0]
    self.b = args[1]
    self.c = args[2]
  def raw(self, ip):
    op = BitString(self.opcodestr, 7)

    partial = op + self.a.raw() + self.b.raw() + self.c.raw()
    partial += BitString(0, 5)
    return partial

class Ins_two_imm_uf(object):
  special = 0
  def __init__(self, args, uf=False):
    assert len(args) == 3, "Need 3 args for that op"
    self.a = args[0]
    self.b = args[1]
    self.imm = args[2]
    self.uf = uf
  def raw(self, ip):
    op = BitString(self.opcodestr, 7)
    partial = op + self.a.raw() + self.b.raw() + BitString(self.imm, 7, ip)
    partial += BitString(self.special, 2)
    partial += BitString(0b1,1) if self.uf else BitString(0b0,1)
    return partial

class Imm_three(object):
  def __init__(self, args):
    assert len(args) == 3, "Need 3 args for that op"
    self.a = args[0]
    self.b = args[1]
    self.c = args[2]
  def raw(self, ip):
    op = BitString(self.opcodestr, 7)

    partial = op + self.a.raw() + self.b.raw() + self.c.raw()
    partial += BitString(0b00000, 5)
    return partial


class Ins_two_uf(object):
  special = 0
  def __init__(self, args, uf=False):
    assert len(args) == 2, "Need 2 args for that op"
    self.a = args[0]
    self.b = args[1]
    self.uf = uf
  def raw(self, ip):
    op = BitString(self.opcodestr, 9)
    partial = op + self.a.raw() + self.b.raw()
    partial += BitString(self.special, 7)
    partial += BitString(0b1,1) if self.uf else BitString(0b0,1)
    return partial

class Ins_two(object):
  def __init__(self, args):
    assert len(args) == 2, "Need 2 args for that op"
    self.a = args[0]
    self.b = args[1]
  def raw(self, ip):
    op = BitString(self.opcodestr, 8)
    return op + self.a.raw() + self.b.raw()

class Ins_cmp_imm(object):
  signed = False
  def __init__(self, args):
    assert len(args) == 2, "Need 2 args for that op"
    self.a = args[0]
    self.imm = args[1]
  def raw(self, ip):
    op = BitString(self.opcodestr, 8)
    return op + self.a.raw() + BitString(self.imm, 14, ip, signed=self.signed)

class Ins_one_imm(object):
  signed = False
  def __init__(self, args):
    assert len(args) == 2, "Need 2 args for that op"
    self.a = args[0]
    self.imm = args[1]
  def raw(self, ip):
    op = BitString(self.opcodestr, 5)
    return op + self.a.raw() + BitString(self.imm, 17, ip, signed=self.signed)

class Ins_one_uf(object):
  special = 0
  def __init__(self, args, uf=False):
    assert len(args) == 1, "Need 1 args for that op"
    self.a = args[0]
    self.uf = uf
  def raw(self, ip):
    op = BitString(self.opcodestr, 9, ip)
    partial = op + self.a.raw() + BitString(self.special, 12)
    return partial + (BitString(0b1,1) if self.uf else BitString(0b0,1))

class Ins_one(object):
  def __init__(self, args):
    assert len(args) == 1, "Need 1 args for that op"
    self.a = args[0]
  def raw(self, ip):
    op = BitString(self.opcodestr, 12, ip)
    return op + self.a.raw() + BitString(0b0, 1)

class Ins_mem_prot(object):
  def __init__(self, args):
    assert len(args) == 3, "Need 3 args for that op"
    self.a = args[0]
    self.b = args[1]
    self.flags = 0
    if "W" in args[2]:
      self.flags = 2
    elif "E" in args[2]:
      self.flags = 3
    elif "R" in args[2]:
      self.flags = 1
    elif 'N' in args[2]:
      self.flags = 0
  def raw(self, ip):
    op = BitString(self.opcodestr, 7)
    partial = op + self.a.raw() + self.b.raw() + BitString(1, 1)
    partial += BitString(self.flags, 2)
    partial += BitString(0, 7)
    return partial

class Ins_mem(object):
  def __init__(self, args, adjust=None):
    assert len(args) == 4, "Need 4 args for that op"
    self.a = args[0]
    self.b = args[1]
    assert args[3] >= 0 and args[3] < 31, "Register count outside of normal range"
    self.count = args[3]-1
    if not adjust:
      self.adjust = 0
    elif adjust == "I":
      self.adjust = 1
    elif adjust == "D":
      self.adjust = 2
    else:
      raise Exception("Invalid mem mode: %s"%(adjust))
    self.offset = args[2]
  def raw(self, ip):
    op = BitString(self.opcodestr, 7)
    partial = op + self.a.raw() + self.b.raw() + BitString(self.count, 5)
    partial += BitString(self.adjust, 2) + BitString(self.offset, 27, ip)
    return partial + BitString(0b000, 3)

class Ins_zero(object):
  def __init__(self, bleh=None):
    pass
  def raw(self, ip):
    return BitString(self.opcodestr, 18)
  

class Ins_Ad(Ins_three_ref_uf):
  opcodestr = 0b0000000
class Ins_Adc(Ins_three_ref_uf):
  opcodestr = 0b0100000
class Ins_Adci(Ins_two_imm_uf):
  opcodestr = 0b0100000
  special = 0b01
class Ins_Adcim(Ins_two_imm_uf):
  opcodestr = 0b0100010
  special = 0b01
class Ins_Adcm(Ins_three_ref_uf):
  opcodestr = 0b0100010
class Ins_Adf(Ins_three_ref_uf):
  opcodestr = 0b0000001
class Ins_Adfm(Ins_three_ref_uf):
  opcodestr = 0b0000011
class Ins_Adi(Ins_two_imm_uf):
  opcodestr = 0b0000000
  special = 0b01
class Ins_Adim(Ins_two_imm_uf):
  opcodestr = 0b0000010
  special = 0b01
class Ins_Adm(Ins_three_ref_uf):
  opcodestr = 0b0000010
class Ins_An(Ins_three_ref_uf):
  opcodestr = 0b0010100
class Ins_Ani(Ins_two_imm_uf):
  opcodestr = 0b0010100
  special = 0b01
class Ins_Anm(Ins_three_ref_uf):
  opcodestr = 0b0010110
class Ins_B(Ins_conditional_offset):
  opcodestr = 0b110000
class Ins_Bf(Ins_two_uf):
  opcodestr = 0b101001100
  special = 0b1000000
class Ins_Bfm(Ins_two_uf):
  opcodestr = 0b101001110
  special = 0b1000000
class Ins_Br(Ins_conditional_reg):
  opcodestr = 0b110010
class Ins_Bra(Ins_offset):
  opcodestr = 0b111000100
class Ins_Brr(Ins_offset):
  relative = True
  opcodestr = 0b111000000
class Ins_C(Ins_conditional_offset):
  opcodestr = 0b110101
class Ins_Caa(Ins_offset):
  opcodestr = 0b111001100
class Ins_Car(Ins_offset):
  relative = True
  opcodestr = 0b111001000
class Ins_Cm(Ins_two):
  opcodestr = 0b10111000
class Ins_Cmf(Ins_two):
  opcodestr = 0b10111010
class Ins_Cmfm(Ins_two):
  opcodestr = 0b10111110
class Ins_Cmi(Ins_cmp_imm):
  signed = True
  opcodestr = 0b10111001
class Ins_Cmim(Ins_cmp_imm):
  signed = True
  opcodestr = 0b10111101
class Ins_Cmm(Ins_two):
  opcodestr = 0b10111100
class Ins_Cr(Ins_conditional_reg):
  opcodestr = 0b110111
class Ins_Dbrk(Ins_zero):
  opcodestr = 0b111111111111111111
class Ins_Di(Ins_one):
  opcodestr = 0b101000000101
class Ins_Dmt(Ins_three):
  opcodestr = 0b0110100
class Ins_Dv(Ins_three_ref_uf):
  opcodestr = 0b0001100
class Ins_Dvf(Ins_three_ref_uf):
  opcodestr = 0b0001101
class Ins_Dvfm(Ins_three_ref_uf):
  opcodestr = 0b0001111
class Ins_Dvi(Ins_two_imm_uf):
  opcodestr = 0b0001100
  special = 0b01
class Ins_Dvim(Ins_two_imm_uf):
  opcodestr = 0b0001110
  special = 0b01
class Ins_Dvis(Ins_two_imm_uf):
  opcodestr = 0b0001100
  special = 0b11
class Ins_Dvism(Ins_two_imm_uf):
  opcodestr = 0b0001110
  special = 0b11
class Ins_Dvm(Ins_three_ref_uf):
  opcodestr = 0b0001110
class Ins_Dvs(Ins_three_ref_uf):
  opcodestr = 0b0001100
  special   = 0b10
class Ins_Dvsm(Ins_three_ref_uf):
  opcodestr = 0b0001110
  special   = 0b10
class Ins_Ei(Ins_one):
  opcodestr = 0b101000000100
class Ins_Fti(Ins_two):
  opcodestr = 0b101000101
class Ins_Ftim(Ins_two):
  opcodestr = 0b101000111
class Ins_Ht(Ins_zero):
  opcodestr = 0b101000000011000000
class Ins_Ir(Ins_zero):
  opcodestr = 0b101000000001000000
class Ins_Itf(Ins_two):
  opcodestr = 0b101000100
class Ins_Itfm(Ins_two):
  opcodestr = 0b101000110
class Ins_Lds(Ins_mem):
  opcodestr = 0b1010100
class Ins_Ldt(Ins_mem):
  opcodestr = 0b1010110
class Ins_Ldw(Ins_mem):
  opcodestr = 0b1010101
class Ins_Md(Ins_three_ref_uf):
  opcodestr = 0b0010000
class Ins_Mdf(Ins_three_ref_uf):
  opcodestr = 0b0010001
class Ins_Mdfm(Ins_three_ref_uf):
  opcodestr = 0b0010011
class Ins_Mdi(Ins_two_imm_uf):
  opcodestr = 0b0010000
  special = 0b01
class Ins_Mdim(Ins_two_imm_uf):
  opcodestr = 0b0010010
  special = 0b01
class Ins_Mdis(Ins_two_imm_uf):
  opcodestr = 0b0010000
  special = 0b11
class Ins_Mdism(Ins_two_imm_uf):
  opcodestr = 0b0010010
  special = 0b11
class Ins_Mdm(Ins_three_ref_uf):
  opcodestr = 0b0010010
class Ins_Mds(Ins_three_ref_uf):
  opcodestr = 0b0010000
  special = 0b10
class Ins_Mdsm(Ins_three_ref_uf):
  opcodestr = 0b0010010
  special = 0b10
class Ins_Mh(Ins_one_imm):
  opcodestr = 0b10001
class Ins_Ml(Ins_one_imm):
  opcodestr = 0b10010
class Ins_Ms(Ins_one_imm):
  signed = True
  opcodestr = 0b10011
class Ins_Mu(Ins_three_ref_uf):
  opcodestr = 0b0001000
class Ins_Muf(Ins_three_ref_uf):
  opcodestr = 0b0001001
class Ins_Mufm(Ins_three_ref_uf):
  opcodestr = 0b0001011
class Ins_Mui(Ins_two_imm_uf):
  opcodestr = 0b0001000
  special = 0b01
class Ins_Muim(Ins_two_imm_uf):
  opcodestr = 0b0001010
  special = 0b01
class Ins_Muis(Ins_two_imm_uf):
  opcodestr = 0b0001000
  special = 0b11
class Ins_Muism(Ins_two_imm_uf):
  opcodestr = 0b0001010
  special = 0b11
class Ins_Mum(Ins_three_ref_uf):
  opcodestr = 0b0001010
class Ins_Mus(Ins_three_ref_uf):
  opcodestr = 0b0001000
  special = 0b10
class Ins_Musm(Ins_three_ref_uf):
  opcodestr = 0b0001010
  special = 0b10
class Ins_Ng(Ins_two_uf):
  opcodestr = 0b101001100
class Ins_Ngf(Ins_two_uf):
  opcodestr = 0b101001101
class Ins_Ngfm(Ins_two_uf):
  opcodestr = 0b101001111
class Ins_Ngm(Ins_two_uf):
  opcodestr = 0b101001110
class Ins_Nt(Ins_two_uf):
  opcodestr = 0b101001100
  special = 0b0100000
class Ins_Ntm(Ins_two_uf):
  opcodestr = 0b101001110
  special = 0b0100000
class Ins_Or(Ins_three_ref_uf):
  opcodestr = 0b0011000
class Ins_Ori(Ins_two_imm_uf):
  opcodestr = 0b0011000
  special = 0b01
class Ins_Orm(Ins_three_ref_uf):
  opcodestr = 0b0011010
class Ins_Re(Ins_zero):
  opcodestr = 0b101000000000000000
class Ins_Rf(Ins_one):
  opcodestr = 0b101000001100
class Ins_Rl(Ins_three_ref_uf):
  opcodestr = 0b0110000
class Ins_Rli(Ins_two_imm_uf):
  opcodestr = 0b1000000
  special = 0b00
class Ins_Rlim(Ins_two_imm_uf):
  opcodestr = 0b1000010
  special = 0b00
class Ins_Rlm(Ins_three_ref_uf):
  opcodestr = 0b0110010
class Ins_Rmp(Ins_two):
  opcodestr = 0b1010010
class Ins_Rnd(Ins_one_uf):
  opcodestr = 0b101001100
  special = 0b000001100000
class Ins_Rndm(Ins_one_uf):
  opcodestr = 0b101001110
  special = 0b000001100000
class Ins_Rr(Ins_three_ref_uf):
  opcodestr = 0b0110001
class Ins_Rri(Ins_two_imm_uf):
  opcodestr = 0b1000001
  special = 0b00
class Ins_Rrim(Ins_two_imm_uf):
  opcodestr = 0b1000011
  special = 0b00
class Ins_Rrm(Ins_three_ref_uf):
  opcodestr = 0b0110011
class Ins_Sa(Ins_three_ref_uf):
  opcodestr = 0b0101101
class Ins_Sai(Ins_two_imm_uf):
  opcodestr = 0b0111101
  special = 0b00
class Ins_Saim(Ins_two_imm_uf):
  opcodestr = 0b0111111
  special = 0b00
class Ins_Sam(Ins_three_ref_uf):
  opcodestr = 0b0101111
class Ins_Sb(Ins_three_ref_uf):
  opcodestr = 0b0000100
class Ins_Sbc(Ins_three_ref_uf):
  opcodestr = 0b0100100
class Ins_Sbci(Ins_two_imm_uf):
  opcodestr = 0b0100100
  special = 0b01
class Ins_Sbcim(Ins_two_imm_uf):
  opcodestr = 0b0100110
  special = 0b01
class Ins_Sbcm(Ins_three_ref_uf):
  opcodestr = 0b0100110
class Ins_Sbf(Ins_three_ref_uf):
  opcodestr = 0b0000101
class Ins_Sbfm(Ins_three_ref_uf):
  opcodestr = 0b0000111
class Ins_Sbi(Ins_two_imm_uf):
  opcodestr = 0b0000100
  special = 0b01
class Ins_Sbim(Ins_two_imm_uf):
  opcodestr = 0b0000110
  special = 0b01
class Ins_Sbm(Ins_three_ref_uf):
  opcodestr = 0b0000110
class Ins_Ses(Ins_two):
  opcodestr = 0b101000000111
class Ins_Sew(Ins_two):
  opcodestr = 0b101000001000
class Ins_Sf(Ins_one):
  opcodestr = 0b101000001011
class Ins_Sl(Ins_three_ref_uf):
  opcodestr = 0b0101000
class Ins_Sli(Ins_two_imm_uf):
  opcodestr = 0b0111000
class Ins_Slim(Ins_two_imm_uf):
  opcodestr = 0b0111010
class Ins_Slm(Ins_three_ref_uf):
  opcodestr = 0b0101010
class Ins_Smp(Ins_mem_prot):
  opcodestr = 0b1010010
class Ins_Sr(Ins_three_ref_uf):
  opcodestr = 0b0101001
class Ins_Sri(Ins_two_imm_uf):
  opcodestr = 0b0111001
class Ins_Srim(Ins_two_imm_uf):
  opcodestr = 0b0111011
class Ins_Srm(Ins_three_ref_uf):
  opcodestr = 0b0101011
class Ins_Sts(Ins_mem):
  opcodestr = 0b1011000
class Ins_Stt(Ins_mem):
  opcodestr = 0b1011010
class Ins_Stw(Ins_mem):
  opcodestr = 0b1011001
class Ins_Wt(Ins_zero):
  opcodestr = 0b101000000010000000
class Ins_Xr(Ins_three_ref_uf):
  opcodestr = 0b0011100
class Ins_Xri(Ins_two_imm_uf):
  opcodestr = 0b0011100
  special = 0b01
class Ins_Xrm(Ins_three_ref_uf):
  opcodestr = 0b0011110
class Ins_Zes(Ins_two):
  opcodestr = 0b101000001001
class Ins_Zew(Ins_two):
  opcodestr = 0b101000001010

class Instr(object):
  def __init__(self, mnem):
    #search through all Ins_* that we know about
    #and see if we know this mnem
    for k,v in globals().iteritems():
      if "ins_"+mnem.lower() == k.lower():
        self.iclass = v
        break
    else: #special mnemonic with a suffix
      for end in specials:
        if mnem.lower().endswith(end.lower()):
          break
      else:
        raise Exception("Unknown mnemonic: %s"%(mnem))
      for k,v in globals().iteritems():
        if "ins_"+mnem.lower()[:-len(end)] == k.lower():
          self.iclass = lambda x,f=v:f(x, end)
          break
      else:
        raise Exception("Unknown mnemonic: %s"%(mnem))

    self.mnem = mnem

