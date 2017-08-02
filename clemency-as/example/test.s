ldt    R01, [R00 + 0x57, 3]
smp    R00, R01, E
ad     R00, R00, R01
ml     R04, 0x400
mu     R05, R00, R04
smp    R05, R02, RW
ad     R00, R00, R02
mu     R05, R00, R04
smp    R05, R03, RW
ad     R00, R00, R03
adi    R00, R00, 0x1
ml     R02, 0xffde
sb     R02, R02, R00
mu     R05, R00, R04
smp    R05, R02, RW
ml     R00, 0x0
mh     R00, 0xffdf
ml     R01, 0x20
smp    R00, R01, RW
mu     R01, R01, R04
ad     ST, R00, R01
ml     R00, 0x1ff
ei     R00
or     R00, R05, R05
mu     R01, R02, R04
car    $sub_901
ht

sub_901:
  sttd   R00, [ST, 2]
  sttd   R28, [ST, 3]
  or.    R28, ST, ST
  sbi.   ST, ST, 0xf
  sttd   R08, [ST, 4]
  ldt    R08, [R28 + 0x9]
  ldt    R09, [R28 + 0xc]
  ml     R02, 0x21
  ml     R01, 0x0
  ml     R00, 0x4c
  mh     R00, 0x1b
  car    $sub_5c5f
  ml     R02, 0xf
  ml     R01, 0x0
  or.    R00, R08, R08
  car    $sub_5c5f
  stt    R09, [R08]
  ml     R10, 0x6a
  mh     R10, 0x1b
  stt    R08, [R10]
  ml     R00, 0x0
  ldti   R08, [ST, 4]
  ldt    R28, [R28, 3]
  adi.   ST, ST, 0x6
  re

sub_5c5f:
  or     R03, R00, R00
  rli    R04, R01, 0x09
  or     R01, R04, R01
  rli    R04, R01, 0x09
  or     R01, R04, R01
lbl_5c6e:
  cmi    R02, 0x3
  bsl    $lbl_5c80
  stti   R01, [R03]
  sbi    R02, R02, 0x3
  b      $lbl_5c6e
lbl_5c80:
  cmi    R02, 0x1
  bl     $lbl_5c98
  bg     $lbl_5c92
  sts    R01, [R03]
  b      $lbl_5c98
lbl_5c92:
  stw    R01, [R03]
lbl_5c98:
  re

data:
  .ds 31
  .ds 100
  .ds 511
  .dw 131072
  .dw 262141
  .dt 123456789
  .dm 12987912378913823791
