To use, you probably just want to run `python assembler.py your_file.s`

See the example in the `example` folder for an example assembly file.

A few features include: full? support for clemency instruction set, labels (declared as `label:` and used as `$label`), label arithmetic for instructions supporting offsets (use `{$label - $pc + 10}`, etc), data store pseudo-ops (`.ds .dw .dt .dm`), also supports using macros with the C pre-processor.

