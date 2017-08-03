#!/usr/bin/env python
from __future__ import print_function
import pyriscv

with open('test.bin', 'rb') as in_file:
    code = in_file.read()
for pc in range(0, len(code), 4):
    inst = pyriscv.disassemble(pc, code[pc:pc+4])
    print('%08X\t%s' % (pc, inst.str))
