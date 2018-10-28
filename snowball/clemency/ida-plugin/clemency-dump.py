"""
Dumps to original_binary.bin.patched.
"""
from __future__ import print_function

import struct
import os
from idaapi import *

class ClemencyFile(object):
    def __init__(self, f):
        self.file = f
        self.rpn = 0
        self.rp = 0
        self.wpn = 0
        self.wp = 0
        self.towrite = []

    def _writenyte(self, n):
        self.wp = (self.wp << 9) | n
        self.wpn += 9
        while self.wpn >= 8:
            self.towrite.append((self.wp >> (self.wpn - 8)) & 0xff)
            self.wpn -= 8
        self.wp = self.wp & ((1 << self.wpn) - 1)

    def _writeflush(self):
        self.wp <<= (8 - self.wpn)
        self.towrite.append(self.wp)
        self.file.write(''.join(map(chr, self.towrite)))
        self.towrite = []
        self.wpn = 0
        self.wp = 0

    def write(self, nytearr):
        for n in nytearr:
            self._writenyte(n)
        self._writeflush()

    def close(self):
        self.file.close()


def get_first_segment():
    """
    Gets first segment as a list of integers (for each 9-bit byte).
    """
    bs = get_many_bytes(SegStart(0), SegEnd(0))
    return struct.unpack('H' * (len(bs) / 2), bs)

def write_patch():
    input_file_path = idaapi.get_input_file_path()

    if not os.path.exists(input_file_path):
        print("ClemDump: warning: {} does not exist.".format(input_file_path))

    output_path = input_file_path + '.patched'

    print("ClemDump: patched binary to", output_path)
    with open(output_path, 'wb') as output_fd:
        ClemencyFile(output_fd).write(get_first_segment())

write_patch()
