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
FORMAT( R )
INS_3( ad, 0b0000000, funct, 0, arith_signed, 0, is_imm, 0 )
INS_3( adc, 0b0100000, funct, 0, arith_signed, 0, is_imm, 0 )
INS_3( adcm, 0b0100010, funct, 0, arith_signed, 0, is_imm, 0 )
INS_3( adf, 0b0000001, funct, 0, arith_signed, 0, is_imm, 0 )
INS_3( adfm, 0b0000011, funct, 0, arith_signed, 0, is_imm, 0 )
INS_3( adm, 0b0000010, funct, 0, arith_signed, 0, is_imm, 0 )
INS_3( an, 0b0010100, funct, 0, arith_signed, 0, is_imm, 0 )
INS_3( anm, 0b0010110, funct, 0, arith_signed, 0, is_imm, 0 )
INS_4( dmt, 0b0110100, funct, 0, arith_signed, 0, is_imm, 0, uf, 0 )
INS_3( dv, 0b0001100, funct, 0, arith_signed, 0, is_imm, 0 )
INS_3( dvs, 0b0001100, funct, 0, arith_signed, 1, is_imm, 0 )
INS_3( dvf, 0b0001100, funct, 0, arith_signed, 0, is_imm, 0 )
INS_3( dvfm, 0b0001111, funct, 0, arith_signed, 0, is_imm, 0 )
INS_3( dvm, 0b0001110, funct, 0, arith_signed, 0, is_imm, 0 )
INS_3( dvsm, 0b0001110, funct, 0, arith_signed, 1, is_imm, 0 )
INS_3( md, 0b0010000, funct, 0, arith_signed, 0, is_imm, 0 )
INS_3( mds, 0b0010000, funct, 0, arith_signed, 1, is_imm, 0 )
INS_3( mdf, 0b0010001, funct, 0, arith_signed, 0, is_imm, 0 )
INS_3( mdfm, 0b0010011, funct, 0, arith_signed, 0, is_imm, 0 )
INS_3( mdm, 0b0010010, funct, 0, arith_signed, 0, is_imm, 0 )
INS_3( mdsm, 0b0010010, funct, 0, arith_signed, 1, is_imm, 0 )

FORMAT( R_IMM )
INS_2( adci, 0b0100000, arith_signed, 0, is_imm, 1 )
INS_2( adcim, 0b0100010, arith_signed, 0, is_imm, 1 )
INS_2( adi, 0b0000000, arith_signed, 0, is_imm, 1 )
INS_2( adim, 0b0000010, arith_signed, 0, is_imm, 1 )
INS_2( ani, 0b0010100, arith_signed, 0, is_imm, 1 )
INS_2( dvi, 0b0001100, arith_signed, 0, is_imm, 1 )
INS_2( dvis, 0b0001100, arith_signed, 1, is_imm, 1 )
INS_2( dvim, 0b0001110, arith_signed, 0, is_imm, 1 )
INS_2( dvism, 0b0001110, arith_signed, 1, is_imm, 1 )
INS_3( mdi, 0b0010000, funct, 0, arith_signed, 0, is_imm, 1 )
INS_3( mdis, 0b0010000, funct, 0, arith_signed, 1, is_imm, 1 )
INS_3( mdim, 0b0010010, funct, 0, arith_signed, 0, is_imm, 1 )
INS_3( mdism, 0b0010010, funct, 0, arith_signed, 1, is_imm, 1 )

FORMAT( B_CC_OFF )
INS( b, 0b110000 )
INS( c, 0b110101 )

FORMAT( B_CC_R )
INS_1( br, 0b110010, funct, 0 )
INS_1( cr, 0b110111, funct, 0 )

FORMAT( B_OFF )
INS( brr, 0b111000000 )
INS( car, 0b111001000 )

FORMAT( B_LOC )
INS( bra, 0b111000100 )
INS( caa, 0b111001100 )

FORMAT( BIN_R )
INS( cm, 0b10111000 )
INS( cmf, 0b10111010 )
INS( cmfm, 0b10111110 )
INS( cmm, 0b10111100 )

FORMAT( BIN_R_IMM )
INS( cmi, 0b10111001 )
INS( cmim, 0b10111101 )

FORMAT( MOV_LOW_HI )
INS( mh, 0b10001 )
INS( ml, 0b10010 )

FORMAT( MOV_LOW_SIGNED )
INS( ms, 0b10011 )

FORMAT( U )
INS_2( fti, 0b101000101, funct, 0, uf, 0)
INS_2( ftim, 0b101000111, funct, 0, uf, 0)
INS_2( itf, 0b101000100, funct, 0, uf, 0)
INS_2( itfm, 0b101000110, funct, 0, uf, 0)

FORMAT( R )
INS_3( mu, 0b0001000, funct, 0, arith_signed, 0, is_imm, 0 )
INS_3( muf, 0b0001001, funct, 0, arith_signed, 0, is_imm, 0 )
INS_3( mufm, 0b0001011, funct, 0, arith_signed, 0, is_imm, 0 )
INS_3( mum, 0b0001010, funct, 0, arith_signed, 0, is_imm, 0 )
INS_3( mus, 0b0001000, funct, 0, arith_signed, 1, is_imm, 0 )
INS_3( musm, 0b0001010, funct, 0, arith_signed, 1, is_imm, 0 )
INS_3( or, 0b0011000, funct, 0, arith_signed, 0, is_imm, 0 )
INS_3( orm, 0b0011010, funct, 0, arith_signed, 0, is_imm, 0 )
INS_3( rl, 0b0110000, funct, 0, arith_signed, 0, is_imm, 0 )
INS_3( rlm, 0b0110010, funct, 0, arith_signed, 0, is_imm, 0 )
INS_3( rr, 0b0110001, funct, 0, arith_signed, 0, is_imm, 0 )
INS_3( rrm, 0b0110011, funct, 0, arith_signed, 0, is_imm, 0 )
INS_3( sa, 0b0101101, funct, 0, arith_signed, 0, is_imm, 0 )
INS_3( sam, 0b0101111, funct, 0, arith_signed, 0, is_imm, 0 )
INS_3( sb, 0b0000100, funct, 0, arith_signed, 0, is_imm, 0 )
INS_3( sbc, 0b0100100, funct, 0, arith_signed, 0, is_imm, 0 )
INS_3( sbcm, 0b0100110, funct, 0, arith_signed, 0, is_imm, 0 )
INS_3( sbf, 0b0000101, funct, 0, arith_signed, 0, is_imm, 0 )
INS_3( sbfm, 0b0000111, funct, 0, arith_signed, 0, is_imm, 0 )
INS_3( sbm, 0b0000110, funct, 0, arith_signed, 0, is_imm, 0 )
INS_3( sl, 0b0101000, funct, 0, arith_signed, 0, is_imm, 0 )
INS_3( slm, 0b0101010, funct, 0, arith_signed, 0, is_imm, 0 )
INS_3( sr, 0b0101001, funct, 0, arith_signed, 0, is_imm, 0 )
INS_3( srm, 0b0101011, funct, 0, arith_signed, 0, is_imm, 0 )
INS_3( xr, 0b0011100, funct, 0, arith_signed, 0, is_imm, 0 )
INS_3( xrm, 0b0011110, funct, 0, arith_signed, 0, is_imm, 0 )

FORMAT( R_IMM )
INS_2( mui, 0b0001000, arith_signed, 0, is_imm, 1 )
INS_2( muim, 0b0001010, arith_signed, 0, is_imm, 1 )
INS_2( muis, 0b0001000, arith_signed, 1, is_imm, 1 )
INS_2( muism, 0b0001010, arith_signed, 1, is_imm, 1 )
INS_2( ori, 0b0011000, arith_signed, 0, is_imm, 1 )
INS_2( rli, 0b1000000, arith_signed, 0, is_imm, 0 )
INS_2( rlim, 0b1000010, arith_signed, 0, is_imm, 0 )
INS_2( rri, 0b1000001, arith_signed, 0, is_imm, 0 )
INS_2( rrim, 0b1000011, arith_signed, 0, is_imm, 0 )
INS_2( sai, 0b0111101, arith_signed, 0, is_imm, 0 )
INS_2( saim, 0b0111111, arith_signed, 0, is_imm, 0 )
INS_2( sbi, 0b0000100, arith_signed, 0, is_imm, 1 )
INS_2( sbci, 0b0100100, arith_signed, 0, is_imm, 1 )
INS_2( sbcim, 0b0100110, arith_signed, 0, is_imm, 1 )
INS_2( sbim, 0b0000110, arith_signed, 0, is_imm, 1 )
INS_2( sli, 0b0111000, arith_signed, 0, is_imm, 0 )
INS_2( slim, 0b0111010, arith_signed, 0, is_imm, 0 )
INS_2( sri, 0b0111001, arith_signed, 0, is_imm, 0 )
INS_2( srim, 0b0111011, arith_signed, 0, is_imm, 0 )
INS_2( xri, 0b0011100, arith_signed, 0, is_imm, 1 )

FORMAT( U )
INS_1( bf, 0b101001100, funct, 0b1000000 )
INS_1( bfm, 0b101001110, funct, 0b1000000 )
INS_1( ng, 0b101001100, funct, 0b0000000 )
INS_1( ngf, 0b101001101, funct, 0b0000000 )
INS_1( ngfm, 0b101001111, funct, 0b0000000 )
INS_1( ngm, 0b101001110, funct, 0b0000000 )
INS_1( nt, 0b101001100, funct, 0b0100000 )
INS_1( ntm, 0b101001110, funct, 0b0100000 )

FORMAT( U_EXTEND )
INS_1( ses, 0b101000000111, funct, 0 )
INS_1( sew, 0b101000001000, funct, 0 )
INS_1( zes, 0b101000001001, funct, 0 )
INS_1( zew, 0b101000001010, funct, 0 )

FORMAT( N )
INS( re, 0b101000000000000000 )
INS( dbrk, 0b111111111111111111 )
INS( ht, 0b101000000011000000 )
INS( ir, 0b101000000001000000 )
INS( wt, 0b101000000010000000 )

FORMAT( FLAGS_INTS )
INS_1( rf, 0b101000001100, funct, 0 )
INS_1( sf, 0b101000001011, funct, 0 )
INS_1( ei, 0b101000000100, funct, 0 )
INS_1( di, 0b101000000101, funct, 0 )

FORMAT( M )
INS_1( ldt, 0b1010110, funct, 0)
INS_1( lds, 0b1010100, funct, 0)
INS_1( ldw, 0b1010101, funct, 0)
INS_1( stt, 0b1011010, funct, 0)
INS_1( sts, 0b1011000, funct, 0)
INS_1( stw, 0b1011001, funct, 0)

FORMAT( RANDOM )
INS_1( rnd, 0b101001100, funct, 0b000001100000 )
INS_1( rndm, 0b101001110, funct, 0b000001100000 )

FORMAT( MP )
INS_3( rmp, 0b1010010, rw, 0, mem_flags, 0, funct, 0)
INS_2( smp, 0b1010010, rw, 1, funct, 0)

// Unset the macros. You can safely ignore these.
#undef FORMAT
#undef INS
#undef INS_1
#undef INS_2
#undef INS_3
#undef INS_4
