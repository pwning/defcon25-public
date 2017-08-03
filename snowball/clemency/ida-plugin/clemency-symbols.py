"""
Saves all function names in idb to symbol map for org's Clemency debugger.
"""

from __future__ import print_function
import os
import idaapi
from idaapi import *


def get_symbol_map():
    """
    Return symbols in current .idb as .map format.
    """
    functions = {}
    for ea in Segments():
        for funcea in Functions(SegStart(ea), SegEnd(ea)):
            size = FindFuncEnd(funcea) - funcea
            functions[funcea] = (GetFunctionName(funcea), size)
    # It may not be necessary to sort by ea, but be safe...
    output_lines = []
    for i, (ea, (name, size)) in enumerate(sorted(functions.items())):
        if len(name) > 255:
            print("ClemSym: truncating name", name)
        name = name[:255]
        line = "%d: %s @ %07x %d" % (i, name, ea, size)
        output_lines.append(line)
    return '\n'.join(output_lines)


def save_symbols():
    """
    Gather symbols and write to .map using expected naming convention.
    """
    input_file_path = idaapi.get_input_file_path()

    if not os.path.exists(input_file_path):
        print("ClemSym: warning: {} does not exist.".format(input_file_path))

    output_path = input_file_path + '.map'

    new_data = get_symbol_map()

    if os.path.exists(output_path):
        with open(output_path, 'rb') as orig_fd:
            orig_data = orig_fd.read()
        if orig_data == new_data:
            print("ClemSym: symbol map on disk is already up to date")
            return

        # Always backup as we *really* don't want to kill someone's
        # hand-made symbol map!
        bak_ctr = 0
        while os.path.exists(output_path + '.bak' + str(bak_ctr)):
            bak_ctr += 1
        os.rename(output_path, output_path + '.bak' + str(bak_ctr))

    print("ClemSym: writing symbols to", output_path)
    with open(output_path, 'wb') as output_fd:
        output_fd.write(new_data)


save_symbols()
