from pyparsing import *
import instrs
import sys

sw = Suppress(Optional(White()))

class obj_LineComment(object):
  def __init__(self, lineno, filename, flags=0):
    self.lineno = lineno
    self.filename = filename

def pretty_error(filename, lineno, err, detail, line):
  print >>sys.stderr, "\x1b[1m%s:%d: \x1b[1;31m%s:\x1b[0;1m %s\x1b[0m" % (filename, lineno, err, detail)
  print >>sys.stderr, line
  print >>sys.stderr

def make_parser(labelstore=None):
  #define the relevant things for parsing through an asm string
  Mnem  = Word( alphas, alphanums+"." ).setParseAction(lambda x:instrs.Instr(x[0])).setName("opcode")
  Label = Word( alphas+"_", alphanums+"_" ).setParseAction(lambda x:instrs.Label(x[0], labelstore)).setName("label")
  Num    = (Optional('-') + Or( ["0x"+Word(hexnums), Word(nums)] )).setParseAction(lambda x:int(''.join(x),0)).setName("number")

  Expr = (Suppress("{") + Word( alphanums+"()+-*$&^%~<> \t" ) + Suppress("}")).setParseAction(lambda x:instrs.Expr(x[0], labelstore))

  Reg    = Or( [Word("rR", "0123456789"), oneOf(list(instrs.special_regs))] ).setParseAction(instrs.Reg)
  Mem    = Or( [Num, Suppress("$")+Label] )
  Imm    = Or( [Num] ).setName("immediate")
  Flags  = Word("RWEN").setName("memory flags")
  Const  = (oneOf(".ds .dw .dt .dm") + Num).setParseAction(lambda x:instrs.Const(x[0], x[1])).setName("constant")

  DispA  = (Suppress("[") + Reg + sw + Suppress("+") + sw + Imm + Suppress(",") + sw + Imm + Suppress("]"))
  DispB  = (Suppress("[") + Reg + sw + Suppress(",") + sw + Imm + Suppress("]")).setParseAction(lambda x:[x[0],0,x[1]])
  DispC  = (Suppress("[") + Reg + sw + Suppress("+") + sw + Imm + Suppress("]")).setParseAction(lambda x:[x[0],x[1],1])
  DispD  = (Suppress("[") + Reg + sw + Suppress("]")).setParseAction(lambda x:[x[0],0,1])
  Disp = Or( [DispA, DispB, DispC, DispD] ).setName("index expression")

  Arg       = Or( [Reg, Mem, Imm, Disp, Flags, Suppress("$")+Label, Expr] )
  TwoArgs   = Arg + Suppress(",") + sw + Arg
  ThreeArgs = Arg + Suppress(",") + sw + Arg + Suppress(",") + sw + Arg
  Instr = Mnem + Optional( Or( [Arg, TwoArgs, ThreeArgs] ) ) + sw
  #Instr.setParseAction(lambda x:x[0])

  LineComment = (Suppress("# ") + Num + sw + QuotedString('"', escQuote='\\"') + Suppress(ZeroOrMore(sw + Num))).setParseAction(lambda x: obj_LineComment(*x))
  Line = (Or( [Instr, Const, Label+Suppress(":"), LineComment] ) + LineEnd()).setName("instruction, directive or label")
  return Line


def parse_asm(s, labelstore=None):
  asms = []
  myline = make_parser(labelstore)
  filename = '<input>'
  lineno = 0
  for real_line in s.split("\n"):
    real_line = real_line.strip()
    lineno += 1
    for line in real_line.split(";"):
      line = line.strip()
      try:
        if not line:
          continue
        info = myline.parseString(line)
        if isinstance(info[0], instrs.Const):
          asms.append((filename, lineno, line, info[0]))
        elif isinstance(info[0], instrs.Instr):
          ins = info[0].iclass(info[1:])
          asms.append((filename, lineno, line, ins))
        elif isinstance(info[0], instrs.Label):
          asms.append((filename, lineno, line, info[0]))
        elif isinstance(info[0], obj_LineComment):
          filename = info[0].filename
          lineno = info[0].lineno - 1
        else:
          raise Exception("Unknown line type")
      
      except Exception as e:
        pretty_error(filename, lineno, "parse error", e, real_line)
        raise

  return asms

def swap_endian(bs):
  out = instrs.BitString(0,0)
  for i in xrange(0, len(bs), 27):
    out += bs[i+9:i+18] + bs[i+0:i+9] + bs[i+18:i+27]
  return out

class Assembler(object):
  def __init__(self):
    self.labels = {}

  def assemble(self, asm_str):
    asms = parse_asm(asm_str, self.labels)
    #first pass, resolve labels
    ip = 0
    for filename, lineno, line, asm in asms:
      try:
        if hasattr(asm, 'raw'):
          ip += asm.raw(ip).size/9 #how many bytes is the thingy
        else:
          asm.update(ip)
      except Exception as e:
        pretty_error(filename, lineno, "error (pass 1)", e, line)
        raise

    #second pass, write real things
    instrs.BitString.CHECK = True
    ip = 0
    out = instrs.BitString(0,0)
    for filename, lineno, line, asm in asms:
      try:
        if hasattr(asm, 'raw'):
          out += swap_endian(asm.raw(ip))
          ip += asm.raw(ip).size/9
      except Exception as e:
        pretty_error(filename, lineno, "error (pass 2)", e, line)
        raise

    return out
