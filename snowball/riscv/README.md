## Usage

Run `make` to build the dynamic library, Windows DLLs, and wrapper for Python. The _Makefile_ uses MinGW to cross compile the Windows DLLs, so you will get errors if you don't have it installed. If you are on macOS, it is sufficient to `brew install mingw-w64`.

You can do a basic test of the disassembler by running _test.py_. It will attempt to disassemble every 4 byte sequency in _test.bin_.

If you want use the IDA plugin, you will need to copy the files to the appropriate directories. Assuming that *IDA_PATH* is your IDA directory, copy the following files:

  - riscv_32.dll, riscv_64.dll -> *IDA_PATH/*
  - pyriscv.py -> *IDA_PATH/python/*
  - ida-plugin/riscv.py -> *IDA_PATH/procs/*

The C library exposes a simple interface:

```
EXPORT void disassemble(inst_t *inst, uint32_t pc, const uint8_t *buf);
EXPORT const char *mnemonics[];
EXPORT const char *registers[];
EXPORT const unsigned int num_registers;
```

The Python wrapper exposes a similar interface:

```
disassemble(pc, buf) # returns inst_t structure
registers            # array of register names
mnemonics            # array of instruction mnemonics
```

The *inst_t* structure contains the results of the disassembly. The fields should be customized for the target architecture and are filled in by the _decode_ functions in _riscv.c_. Every field also defines *used\_field\_name* which is set in _decode_ if that field is initialized.

Every architecture has the following members in *inst_t*:

```
    uint32_t pc;
    const uint8_t *bytes;
    unsigned int size;
    unsigned int id;
    const char *mnemonic;
    char str[64];
```

The riscv32 architecture defines these additional members (e.g. fields):

```
    uint8_t opcode;
    uint8_t funct3;
    uint8_t funct7;
    uint8_t rd;
    uint8_t rs1;
    uint8_t rs2;
    int32_t imm;

    uint8_t used_opcode;
    uint8_t used_funct3;
    uint8_t used_funct7;
    uint8_t used_rd;
    uint8_t used_rs1;
    uint8_t used_rs2;
    uint8_t used_imm;
```

The header exposes all of the instructions as _Imnemonic_, with _Iinvalid_ (0) as a special instruction that indicates disassembly failure. Specifically, `mnemonics[Iadd] = "add"`.

## Opcodes

The _opcodes.h_ file defines all of the instructions for the architecture. It is included in several places to setup the decoding and enumerations. It uses two macros: _FORMAT_ and _INS_. _FORMAT_ defines the decode function that will be used for the subsequent instructions. _INS_ defines the actual instruction. Every instruction should belong to a format.

An instruction is defined by its mnemonic and opcode, which is tested against _inst->opcode_. Additional qualifiers can be added by using the *INS_1*, *INS_2*, ... macros. These macros take an additional field name and value to test for equality.

For example:

```
FORMAT( R )
INS_2( xor, 0b0110011, funct3, 0b100, funct7, 0b0000000 )
INS_2( srl, 0b0110011, funct3, 0b101, funct7, 0b0000000 )
```

This example defines two instructions which are both decoded by `decode_R`. If `inst->opcode == 0b0110011` and `inst->funct3 == 0b100` and `inst->funct7 == 0b0000000`, then it will be disassembled as _xor_.

## Helpers

The library defines and uses several macros and helper functions to reduce code repetition.

The *read_8*, *read_16*, *read_24*, and *read_32* helpers read an integer of that many bits and increments `inst->size` by the corresponding number of bytes. The *read_insn* helper reads the 32-bit instruction into `inst->insn` for convenience.

`EXTRACT(src, offset, count)` extracts a *count*-bit integer from *src* starting at bit *offset*.

`FIELD(name, offset, count)` extracts an integer from `inst->insn` and puts it in `inst->name`. It also sets the flag `inst->used_name`. *CONCAT* extracts an intger from `inst->insn` and appends the bits to the end of `inst->name`. *SIGN_EXTEND* sign extends a *count*-bit integer in `inst->name` to 32 bits.
