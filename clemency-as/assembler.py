import subprocess
import parser
import instrs
import os

import tempfile

def parse_args(argv):
    import argparse
    parser = argparse.ArgumentParser(description="Assemble a thing")
    parser.add_argument('infile', help='Input file')
    parser.add_argument('outfile', nargs='?', help='Output file')
    return parser.parse_args(argv)

def main(argv):
    args = parse_args(argv)

    if args.outfile is None:
        args.outfile = os.path.splitext(args.infile)[0] + '.bin'

    print "Assembling %s to %s..." % (args.infile, args.outfile)

    asm = subprocess.check_output(['cpp', '-xc++', args.infile])

    out = parser.Assembler().assemble(asm)
    print "Output: %d nytes" % (len(out)/9)
    with open(args.outfile, 'wb') as outf:
        outf.write(out.force_str())

def assemble_string(s):
    t = tempfile.NamedTemporaryFile(delete=False)
    t.write(s)
    t.close()
    asm = subprocess.check_output(['cpp', '-xc++', t.name])
    os.unlink(t.name)
    out = parser.Assembler().assemble(asm)
    return out

if __name__ == '__main__':
    import sys
    exit(main(sys.argv[1:]))
