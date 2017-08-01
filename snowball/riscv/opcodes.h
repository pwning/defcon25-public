// XXX This file is processed by generate_py.py.

// Default macros. You can safely ignore these.
#ifndef FORMAT
#define FORMAT(x)
#endif
#ifndef INS
#define INS(x,y)
#endif
#ifndef INS_1
#define INS_1(w,x,y,z) INS(w,x)
#endif
#ifndef INS_2
#define INS_2(w,x,y1,z1,y2,z2) INS_1(w,x,y1,z1)
#endif
#ifndef INS_3
#define INS_3(w,x,y1,z1,y2,z2,y3,z3) INS_2(w,x,y1,z1,y2,z2)
#endif
#ifndef INS_4
#define INS_4(w,x,y1,z1,y2,z2,y3,z3,y4,z4) INS_3(w,x,y1,z1,y2,z2,y3,z3)
#endif

// TODO Instruction definitions
FORMAT( U )
INS( lui, 0b0110111 )
INS( auipc, 0b0010111 )

FORMAT( Jj )
INS_1( j, 0b1101111, rd, 0 )

FORMAT( J )
INS( jal, 0b1101111 )

FORMAT( Ijr )
INS_2( jr, 0b1100111, funct3, 0b000, rd, 0 )

FORMAT( I )
INS_1( jalr, 0b1100111, funct3, 0b000 )
INS_1( lb, 0b0000011, funct3, 0b000 )
INS_1( lh, 0b0000011, funct3, 0b001 )
INS_1( lw, 0b0000011, funct3, 0b010 )
INS_1( lbu, 0b0000011, funct3, 0b100 )
INS_1( lhu, 0b0000011, funct3, 0b101 )
INS_1( addi, 0b0010011, funct3, 0b000 )
INS_1( slti, 0b0010011, funct3, 0b010 )
INS_1( sltiu, 0b0010011, funct3, 0b011 )
INS_1( xori, 0b0010011, funct3, 0b100 )
INS_1( ori, 0b0010011, funct3, 0b110 )
INS_1( andi, 0b0010011, funct3, 0b111 )

FORMAT( E )
INS_4( ecall, 0b1110011, funct3, 0b000, rd, 0, rs1, 0, imm, 0 )
INS_4( ebreak, 0b1110011, funct3, 0b000, rd, 0, rs1, 0, imm, 1 )

FORMAT( S )
INS_1( sb, 0b0100011, funct3, 0b000 )
INS_1( sh, 0b0100011, funct3, 0b001 )
INS_1( sw, 0b0100011, funct3, 0b010 )

FORMAT( Rshift )
INS_2( slli, 0b0010011, funct3, 0b001, funct7, 0b0000000 )
INS_2( srli, 0b0010011, funct3, 0b101, funct7, 0b0000000 )
INS_2( srai, 0b0010011, funct3, 0b101, funct7, 0b0100000 )

FORMAT( R )
INS_2( add, 0b0110011, funct3, 0b000, funct7, 0b0000000 )
INS_2( sub, 0b0110011, funct3, 0b000, funct7, 0b0100000 )
INS_2( sll, 0b0110011, funct3, 0b001, funct7, 0b0000000 )
INS_2( slt, 0b0110011, funct3, 0b010, funct7, 0b0000000 )
INS_2( sltu, 0b0110011, funct3, 0b011, funct7, 0b0000000 )
INS_2( xor, 0b0110011, funct3, 0b100, funct7, 0b0000000 )
INS_2( srl, 0b0110011, funct3, 0b101, funct7, 0b0000000 )
INS_2( sra, 0b0110011, funct3, 0b101, funct7, 0b0100000 )
INS_2( or, 0b0110011, funct3, 0b110, funct7, 0b0000000 )
INS_2( and, 0b0110011, funct3, 0b111, funct7, 0b0000000 )
INS_2( mul, 0b0110011, funct3, 0b000, funct7, 0b0000001 )
INS_2( mulh, 0b0110011, funct3, 0b001, funct7, 0b0000001 )
INS_2( mulhsu, 0b0110011, funct3, 0b010, funct7, 0b0000001 )
INS_2( mulhu, 0b0110011, funct3, 0b011, funct7, 0b0000001 )
INS_2( div, 0b0110011, funct3, 0b100, funct7, 0b0000001 )
INS_2( divu, 0b0110011, funct3, 0b101, funct7, 0b0000001 )
INS_2( rem, 0b0110011, funct3, 0b110, funct7, 0b0000001 )
INS_2( remu, 0b0110011, funct3, 0b111, funct7, 0b0000001 )

FORMAT( B )
INS_1( beq, 0b1100011, funct3, 0b000 )
INS_1( bne, 0b1100011, funct3, 0b001 )
INS_1( blt, 0b1100011, funct3, 0b100 )
INS_1( bge, 0b1100011, funct3, 0b101 )
INS_1( bltu, 0b1100011, funct3, 0b110 )
INS_1( bgeu, 0b1100011, funct3, 0b111 )

// Unset the macros. You can safely ignore these.
#undef FORMAT
#undef INS
#undef INS_1
#undef INS_2
#undef INS_3
#undef INS_4
