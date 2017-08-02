simple example

```
sttd   R0, [ST+0, 2]
sttd   R28, [ST+0, 3]
or.    R28, ST, ST
sbi.   ST, ST, 0xf
sttd   R8, [ST+0, 4]
ldt    R8, [R28 + 0x9, 1]
ldt    R9, [R28 + 0xc, 1]
ml     R2, 0x21
ml     R1, 0x0
ml     R0, 0x4c
mh     R0, 0x1b
car    0x532e
ml     R2, 0xf
ml     R1, 0x0
or.    R0, R8, R8
car    0x5321
stt    R9, [R8 + 0, 1]
ml     R10, 0x6a
mh     R10, 0x1b
stt    R8, [R10 + 0, 1]
```

then do `pretty_asm(THAT_STRING)`
(more useful features coming soon)
