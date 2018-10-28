#!/usr/bin/env python
from __future__ import print_function
import ctypes
import pyclemency
import struct

buf = open('hello.u16', 'rb').read()
pc = 0x90d
while True:
    size = 6
    if pc + size > len(buf) / 2:
        size = len(buf) / 2 - pc
    if size == 0:
        break
    code = (ctypes.c_uint16 * size)()
    for x in xrange(size):
        code[x] = struct.unpack('<H', buf[(pc+x)*2:(pc+x+1)*2])[0]
    inst = pyclemency.disassemble(pc, code)
    print('%08X\t%s' % (pc, inst.str))
    if inst.id == 0:
        break
    pc += inst.size
