"""
IDA Clemency Loader

pyclemency processor support must be installed for this to work
"""

import struct
import sys
import idaapi
from idc import *


class BitReader(object):
    """
    Takes 9-bit BE file descriptor and provides 16-bit LE output.
    """

    def __init__(self, f):
        self.f = f
        self.bits = 0
        self.val = 0

    def get_bit(self):
        if not self.bits:
            b = self.f.read(1)
            if len(b) == 0:
                return None
            self.val = ord(b)
            self.bits = 8
        x = self.val & (1 << (self.bits - 1))
        self.bits -= 1
        return 1 if x else 0

    def get_byte(self):
        x = 0
        for _ in xrange(9):
            bit = self.get_bit()
            if bit is None:
                return None
            x = (x << 1) | bit
        return x

    def get_all_bytes(self):
        while True:
            byte = self.get_byte()
            if byte is None:
                return
            yield byte

    def read_as_u16(self):
        return b''.join(struct.pack('<H', byte)
                        for byte in self.get_all_bytes())


def test_bit_reader():
    with open('hello.u16', 'rb') as o:
        orig_data = o.read()

    with open('hello.u9', 'rb') as f:
        new_data = BitReader(f).read_as_u16()

    assert new_data == orig_data


def accept_file(li, n):
    """
    Is this a clemency file?
    """
    if n > 0:
        return 0

    # There is no binary format, everything is raw bytes mapped to 0.
    # Therefore we always accept. (We could try heuristics.)
    return "Clemency (raw binary)"


def add_segment(start, end, name, type_):
    segment = idaapi.segment_t()
    segment.startEA = start
    segment.endEA = end
    segment.bitness = 1 # 32-bit

    idaapi.add_segm_ex(segment, name, type_, idaapi.ADDSEG_SPARSE | idaapi.ADDSEG_OR_DIE)

def load_file(li, _, __):
    idaapi.set_processor_type("clemency", idaapi.SETPROC_ALL
                              | idaapi.SETPROC_FATAL)

    # Get bytes as u16.
    li.seek(0)
    data_u16 = BitReader(li).read_as_u16()
    program_size = len(data_u16) / 2

    # Load the firmware image.
    add_segment(0, program_size, "MAIN_PROGRAM", "CODE")
    idaapi.put_many_bytes(0, data_u16)
    MakeName(0, '_start')
    AutoMark(0, AU_CODE)
    MakeFunction(0)

    # Fake .BSS in case it's accessed.
    add_segment(program_size, program_size + 0x1000, "BSS", "BSS")

    def make_array(addr, name, size=3):
        MakeName(addr, name)
        MakeArray(addr, size)
        return size

    '''
    0x4000000 3 Timer 1 Delay
    0x4000003 3 Number of milliseconds left for Timer 1
    0x4000006 3 Timer 2 Delay
    0x4000009 3 Number of milliseconds left for Timer 2
    0x400000C 3 Timer 3 Delay
    0x400000F 3 Number of milliseconds left for Timer 3
    0x4000012 3 Timer 4 Delay
    0x4000015 3 Number of milliseconds left for Timer 4
    0x4000018 6 Number of seconds since Aug. 02, 2013 09:00 PST
    0x400001E 3 Number of processing ticks since processor start
    '''
    add_segment(0x4000000, 0x4000021, "CLOCK_IO", "DATA")
    addr = 0x4000000
    for i in xrange(4):
        timer = 'timer%d' % (i+1)
        addr += make_array(addr, 'g_%s_delay' % timer)
        addr += make_array(addr, 'g_%s_ms_left' % timer)
    addr += make_array(addr, 'g_secs_since_epoch', 6)
    addr += make_array(addr, 'g_ticks_since_start')

    add_segment(0x4010000, 0x4011000, "FLAG_IO", "DATA")
    make_array(0x4010000, 'g_flag', 0x1000)

    add_segment(0x5000000, 0x5002003, "DATA_RECEIVED", "DATA")
    make_array(0x5000000, 'g_data_received', 0x2000)
    make_array(0x5002000, 'g_data_received_size')

    add_segment(0x5010000, 0x5012003, "DATA_SENT", "DATA")
    make_array(0x5010000, 'g_data_sent', 0x2000)
    make_array(0x5012000, 'g_data_sent_size')

    add_segment(0x6000000, 0x6800000, "SHARED_MEMORY", "DATA")
    make_array(0x6000000, 'g_shm', 0x800000)

    add_segment(0x6800000, 0x7000000, "NVRAM_MEMORY", "DATA")
    make_array(0x6800000, 'g_nvram', 0x800000)

    '''
    0x7FFFF00 Timer 1
    0x7FFFF03 Timer 2
    0x7FFFF06 Timer 3
    0x7FFFF09 Timer 4
    0x7FFFF0C Invalid Instruction
    0x7FFFF0F Divide by 0
    0x7FFFF12 Memory Exception
    0x7FFFF15 Data Received
    0x7FFFF18 Data Sent
    '''
    add_segment(0x7FFFF00, 0x7FFFF1B, "INTERRUPT_POINTERS", "DATA")
    addr = 0x7FFFF00
    for i in xrange(4):
        timer = 'timer%d' % (i+1)
        addr += make_array(addr, 'g_%s_interrupt_handler' % timer)
    addr += make_array(addr, 'g_invalid_instruction_handler')
    addr += make_array(addr, 'g_div_by_zero_handler')
    addr += make_array(addr, 'g_memory_exn_handler')
    addr += make_array(addr, 'g_data_received_handler')
    addr += make_array(addr, 'g_data_sent_handler')

    '''
    0x7FFFF80 20 Processor name
    0x7FFFFA0 3 Processor version
    0x7FFFFA3 3 Processor functionality flags
    0x7FFFFA6 4A For future use
    0x7FFFFF0 1 Interrupt stack direction flag
    0x7FFFFF1 F For future use
    '''
    add_segment(0x7FFFF80, 0x8000000, "PROC_ID_FEATURES", "DATA")
    addr = 0x7FFFF80
    addr += make_array(addr, 'g_processor_name', 0x20)
    addr += make_array(addr, 'g_processor_version')
    addr += make_array(addr, 'g_processor_flags')
    addr += make_array(addr, 'g_processor_reserved_1', 0x4a)
    addr += make_array(addr, 'g_interrupt_stack_direction', 1)
    addr += make_array(addr, 'g_processor_reserved_2', 0xf)

    return 1
