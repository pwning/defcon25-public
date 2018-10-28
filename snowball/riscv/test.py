#!/usr/bin/env python
from __future__ import print_function
import pyriscv

code = open('test.bin', 'rb').read()
for pc in xrange(0, len(code), 4):
    inst = pyriscv.disassemble(pc, code[pc:pc+4])
    print('%08X\t%s' % (pc, inst.str))
