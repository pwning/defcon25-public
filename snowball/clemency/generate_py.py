#!/usr/bin/env python
# Generate python wrapper from headers.
import re
import sys


def extract_insn(header):
    insns = ['invalid']
    infp = open(header, 'r')
    for line in infp:
        comment = line.find('//')
        if comment >= 0:
            # ignore comments
            line = line[:comment]
        line = line.strip()
        if len(line) == 0 or line.startswith('#'):
            # ignore empty lines and preprocessor defines
            continue
        elif line.startswith('FORMAT'):
            # ignore
            continue
        else:
            _, insn, _ = re.match('^INS(_\d)?\s*\(\s*([\w\d]+)\s*(,.*)?\s*\)$', line).groups()
            insns += [insn]
    insns += ['__count']
    return ''.join('I%s = %d\n' % (insn, i) for i, insn in enumerate(insns))


def extract_struct(header):
    def c_to_ctype(typ, const=None, unsigned=None, signed=None, ptr=None, arr=None):
        if typ == 'char':
            result = 'c_ubyte' if unsigned else 'c_char'
        elif typ == 'short':
            result = 'c_ushort' if unsigned else 'c_short'
        elif typ == 'int':
            result = 'c_uint' if unsigned else 'c_int'
        elif typ.endswith('_t'):
            # uint8_t -> c_uint8
            result = 'c_' + typ[:-2]
        else:
            raise Exception('Unhandled type %s' % typ)

        if result == 'c_char' and ptr:
            result = 'c_char_p'
        elif ptr:
            result = 'POINTER(%s)' % result

        if arr:
            size = int(arr[1:-1].strip(), 0)
            result = '%s*%d' % (result, size)

        return result

    fields = []
    in_struct = False

    infp = open(header, 'r')
    for line in infp:
        comment = line.find('//')
        if comment >= 0:
            # ignore comments
            line = line[:comment]
        line = line.strip()
        if len(line) == 0 or line.startswith('#'):
            # ignore empty lines and preprocessor defines
            pass
        elif line.startswith('EXPORT'):
            # ignore exported functions
            pass
        elif line.startswith('typedef struct'):
            in_struct = True
        elif line.startswith('} inst_t'):
            in_struct = False
        elif in_struct:
            try:
                if line.startswith('DEFINE_FIELD'):
                    typ, name = re.match(r'^DEFINE_FIELD\s*\(\s*([^,\s]*)\s*,\s*([^,\s]*)\s*\)$', line).groups()
                    fields += [
                        (name, c_to_ctype(typ)),
                        ('used_%s' % name, 'c_uint8')
                    ]
                elif line.startswith('BEGIN_FIELDS') or line.startswith('END_FIELDS'):
                    # ignore
                    pass
                else:
                    const, unsigned, signed, typ, ptr, name, arr = re.match(r'^(const)?\s*(unsigned)?(signed)?\s*([\d\w]+)\s*(\*)?\s*([\d\w]+)\s*(\[\s*\d+\s*\])?\s*;$', line).groups()
                    fields += [(name, c_to_ctype(typ, const=const, unsigned=unsigned, ptr=ptr, arr=arr))]
            except AttributeError:
                raise Exception('Bad line: %s' % line)

    infp.close()
    s = ''
    s += 'class Inst(Structure):\n'
    s += '    _fields_ = [\n'
    for f in fields:
        s += '        ("%s", %s),\n' % f
    s += '    ]\n'
    return s


TEMPLATE = '''# Autogenerated
from ctypes import *
import platform

if platform.system() == 'Windows':
    if platform.architecture()[0] == '32bit':
        dll = cdll.@@NAME@@_32
    else:
        dll = cdll.@@NAME@@_64
elif platform.system() == 'Darwin':
    dll = cdll.LoadLibrary('lib@@NAME@@.dylib')
else:
    dll = cdll.LoadLibrary('lib@@NAME@@.so')

@@STRUCT@@

@@INSN@@

dll.disassemble.argtypes = [POINTER(Inst), c_uint32, POINTER(c_uint16)]

def disassemble(pc, input):
    inst = Inst()
    dll.disassemble(byref(inst), pc, input)
    assert inst._st_size == sizeof(inst)
    return inst

mnemonics = (c_char_p * I__count).in_dll(dll, 'mnemonics')
num_registers = c_uint.in_dll(dll, 'num_registers').value
registers = (c_char_p * num_registers).in_dll(dll, 'registers')

comments = {
    'ad': 'Add',
    'adc': 'Add With Carry',
    'adci': 'Add Immediate With Carry',
    'adcm': 'Add Multi Reg With Carry',
    'adf': 'Add Floating Point',
    'adfm': 'Add Floating Point Multi Reg',
    'adi': 'Add Immediate',
    'adim': 'Add Immediate Multi Reg',
    'adm': 'Add Multi Reg',
    'an': 'And',
    'ani': 'And Immediate',
    'anm': 'And Multi Reg',
    'b': 'Branch Conditional',
    'bf': 'Bit Flip',
    'bfm': 'Bit Flip Multi Reg',
    'br': 'Branch Register Conditional',
    'bra': 'Branch Absolute',
    'brr': 'Branch Relative',
    'c': 'Call Conditional',
    'caa': 'Call Absolute',
    'car': 'Call Relative',
    'cm': 'Compare',
    'cmf': 'Compare Floating Point',
    'cmfm': 'Compare Floating Point Multi Reg',
    'cmi': 'Compare Immediate',
    'cmim': 'Compare Immediate Multi Reg',
    'cmm': 'Compare Multi Reg',
    'cr': 'Call Register Conditional',
    'dbrk': 'Debug Break',
    'di': 'Disable Interrupts',
    'dmt': 'Direct Memory Transfer',
    'dv': 'Divide',
    'dvf': 'Divide Floating Point',
    'dvfm': 'Divide Floating Point Multi Reg',
    'dvi': 'Divide Immediate',
    'dvim': 'Divide Immediate Multi Reg',
    'dvis': 'Divide Immediate Signed',
    'dvm': 'Divide Multi Reg',
    'dvs': 'Divide Signed',
    'dvsm': 'Divide Signed Multi Reg',
    'ei': 'Enable Interrupts',
    'fti': 'Float to Integer',
    'ftim': 'Float to Integer Multi Reg',
    'ht': 'Halt',
    'ir': 'Interrupt Return',
    'itf': 'Integer to Float',
    'itfm': 'Integer to Float Multi Reg',
    'lds': 'Load Single',
    'ldt': 'Load Tri',
    'ldw': 'Load Word',
    'md': 'Modulus',
    'mdf': 'Modulus Floating Point',
    'mdfm': 'Modulus Floating Point Multi Reg',
    'mdi': 'Modulus Immediate',
    'mdim': 'Modulus Immediate Multi Reg',
    'mdis': 'Modulus Immediate Signed',
    'mdm': 'Modulus Multi Reg',
    'mds': 'Modulus Signed',
    'mdsm': 'Modulus Signed Multi Reg',
    'mh': 'Move High',
    'ml': 'Move Low',
    'ms': 'Move Low Signed',
    'mu': 'Multiply',
    'muf': 'Multiply Floating Point',
    'mufm': 'Multiply Floating Point Multi Reg',
    'mui': 'Multiply Immediate',
    'muim': 'Multiply Immediate Multi Reg',
    'muis': 'Multiply Immediate Signed',
    'mum': 'Multiply Multi Reg',
    'mus': 'Multiply Signed',
    'musm': 'Multiply Signed Multi Reg',
    'ng': 'Negate',
    'ngf': 'Negate Floating Point',
    'ngfm': 'Negate Floating Point Multi Reg',
    'ngm': 'Negate Multi Reg',
    'nt': 'Not',
    'ntm': 'Not Multi Reg',
    'or': 'Or',
    'ori': 'Or Immediate',
    'orm': 'Or Multi Reg',
    're': 'Return',
    'rf': 'Read Flags',
    'rl': 'Rotate Left',
    'rli': 'Rotate Left Immediate',
    'rlim': 'Rotate Left Immediate Multi Reg',
    'rlm': 'Rotate Left Multi Reg',
    'rmp': 'Read Memory Protection',
    'rnd': 'Random',
    'rndm': 'Random Multi Reg',
    'rr': 'Rotate Right',
    'rri': 'Rotate Right Immediate',
    'rrim': 'Rotate Right Immediate Multi Reg',
    'rrm': 'Rotate Right Multi Reg',
    'sa': 'Shift Arithemetic Right',
    'sai': 'Shift Arithemetic Right Immediate',
    'sam': 'Shift Arithemetic Right Multi Reg',
    'sb': 'Subtract',
    'sbc': 'Subtract With Carry',
    'sbci': 'Subtract Immediate With Carry',
    'sbcm': 'Subtract Multi Reg With Carry',
    'sbf': 'Subtract Floating Point',
    'sbfm': 'Subtract Floating Point Multi Reg',
    'sbi': 'Subtract Immediate',
    'sbim': 'Subtract Immediate Multi Reg',
    'sbm': 'Subtract Multi Reg',
    'ses': 'Sign Extend Single',
    'sew': 'Sign Extend Word',
    'sf': 'Set Flags',
    'sl': 'Shift Left',
    'sli': 'Shift Left Immediate',
    'slim': 'Shift Left Immediate Multi Reg',
    'slm': 'Shift Left Multi Reg',
    'smp': 'Set Memory Protection',
    'sr': 'Shift Right',
    'sri': 'Shift Right Immediate',
    'srim': 'Shift Right Immediate Multi Reg',
    'srm': 'Shift Right Multi Reg',
    'sts': 'Store Single',
    'stt': 'Store Tri',
    'stw': 'Store Word',
    'wt': 'Wait',
    'xr': 'Xor',
    'xri': 'Xor Immediate',
    'xrm': 'Xor Multi Reg',
    'zes': 'Zero Extend Single',
    'zew': 'Zero Extend Word',
}
'''

name = sys.argv[1]
output = TEMPLATE
output = output.replace('@@NAME@@', name)
output = output.replace('@@INSN@@', extract_insn('opcodes.h'))
output = output.replace('@@STRUCT@@', extract_struct('%s.h' % name))
with open('py%s.py' % name, 'w') as outfp:
    outfp.write(output)
