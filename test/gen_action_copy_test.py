preamble = r"""
#include "fbt_translate.h"
#include "fbt_libc.h"
#include "fbt_mem_mgmt.h"
#include "fbt_x86_opcode.h"
#include "fbt_llio.h"

#include <unistd.h>
#include <stdio.h>
#include <asm-generic/mman.h>

// Here we include the code that we would like to test
//#include "sdbg_insert_lea.h"
enum translation_state action_copy(struct translate *ts);


int check_action_copy(unsigned char* orig, unsigned char* xpect, int len, char* humanreadable){
  int error = 0;

  struct translate ts;
  struct thread_local_data tld;
  ts.tld = &tld;
  unsigned char trans[16];

  ts.cur_instr = (uint32_t)(uint64_t)&orig[0];
  ts.next_instr = ts.cur_instr;
  ts.tld->transl_instr = &trans[0];

  fbt_disasm_instr(&ts);

  int ret = action_copy(&ts);

  if (ts.tld->transl_instr-&trans[0] != len){
      error = 1;
  }
  int i;
  for (i=0; i<len; i++){
     if (xpect[i] != trans[i]){
         error = 1;
         //assert(0);
     }
  }
  if (error){
    printf("ERROR %s\n", humanreadable);
    printf("expected: ");
    for (i=0; i<len; i++){
      printf("%02x ", (unsigned)xpect[i]);
    }
    printf("\n");
    printf("got:      ");
    for (i=0; i<len; i++){
      printf("%02x ", (unsigned)trans[i]);
    }
    printf("\n");
  } else {
    for (i=0; i<len; i++){
      printf("%02x ", (unsigned)xpect[i]);
    }
    printf(":  ");
    printf("test successful \t\t%s\n", humanreadable);
  }
  return error;
}

uchar* buf1;
uchar* buf2;
"""


def arithmeticInstructionsTemplate(mnem):
    """
    Generates tests for arithmetic operations trying
    to cover all the possible encodings. The methodology
    is to to through the list of all opcodes for
    the "ADD" instruction and then to just substitute
    'add' with mnemonics of other arithmetic instruction.
    This should guarantee good coverage.
    """
    arin = [
# 00: add r8, r/m8
    mnem + " %bl, %cl",
    mnem + " %cl, 0xdeadbee",
    mnem + " %dl, 24(%eax,%ebx,2)",

# 01: add r16/32, r/m16/32
    mnem + " %bx, %cx",
    mnem + " %cx, 0xdeadbee",
    mnem + " %dx, 24(%eax,%ebx,2)",
    mnem + " %ebx, %ecx",
    mnem + " %ecx, 0xdeadbee",
    mnem + " %edx, 24(%eax,%ebx,2)",

# 02: add r/m8, r8
    mnem + " %cl, %bl",
    mnem + " 0xdeadbee, %cl",
    mnem + " 24(%eax,%ebx,2), %dl",

# 03: add r1/m6/32, r16/32
    mnem + " %cx, %bx",
    mnem + " 0xdeadbee, %cx",
    mnem + " 24(%eax,%ebx,2), %dx",
    mnem + " %ecx, %ebx", 
    mnem + " 0xdeadbee, %ecx",
    mnem + " 24(%eax,%ebx,2), %edx",

# 04: add imm8, al
    mnem + " $37, %al",

#05: add imm16/32, eAX
    mnem + " $0x3753, %ax",
    mnem + " $0x3753341, %eax",

#80: add imm8, r/m8
    mnem + " $0xbe, %cl",
    mnem + "b $0xbe, 0x34234",  # byte suffix
    mnem + "b $0xbe, 0x34234(%ecx, %edx, 8)",  # byte suffix

#80: add imm8, r/m8
    mnem + " $0xdead, %cx",
    mnem + "w $0xdead, 0x34234",  # word suffix
    mnem + "w $0xdead, 0x34234(%ecx, %edx, 8)",  # word suffix
    mnem + " $0xdeadbeef, %ecx",
    mnem + "l $0xdeadbeef, 0x34234",  # long suffix
    mnem + "l $0xdeadbeef, 0x34234(%ecx, %edx, 8)",  # long suffix

# test special addressing schemes (table 1-13 amd man vol 3)

    mnem + " 24(,%ebx,2), %dl",
    mnem + " 24(,%eax,2), %dl",
    mnem + " 24(%ebp,%ebx,2), %dl",
    mnem + " 24(%ebp,%eax,2), %dl",

# some random tests
    mnem + " %al, %al",
    mnem + " %dl, %dl",

# negative offsets
    mnem + " %edx, -8(%eax)",
    mnem + " -8(%eax), %edx",    
    ]

    return arin;

divMulInstructions = ["div %cl",
                      "idiv %cl",
                      "div %cx",
                      "idiv %cx",
                      "div %ecx",
                      "idiv %ecx",
                      "divb 0xdeadfee",
                      "divb 0xdeadfee(%eax, %ebp, 4)",
                      "divw 0xdeadfee",
                      "divw 0xdeadfee(%eax, %ebp, 4)",
                      "divl 0xdeadfee",
                      "divl 0xdeadfee(%eax, %ebp, 4)",
                      "mul %cl",
                      "imul %cl",
                      "mul %cx",
                      "imul %cx",
                      "mul %ecx",
                      "imul %ecx",
                      "mulb 0xdeadfee",
                      "mulb 0xdeadfee(%eax, %ebp, 4)",
                      "mulw 0xdeadfee",
                      "mulw 0xdeadfee(%eax, %ebp, 4)",
                      "mull 0xdeadfee",
                      "mull 0xdeadfee(%eax, %ebp, 4)"

                      ]

specialOneByteInstructions = [
 "nop",
 "pause",
 "cbw",
 "cwde",
 "cwd",
 "cdq",
 "wait",
 "sahf",
 "lahf",
 "xlatb",
]

xchgInstructions = [
 "xchg %al, %cl",
 "xchg %al, 0xdeadfee",
 "xchg 0xdeadfee, %al",
 "xchg %bl, %cl",
 "xchg %bl, 0xdeadfee",
 "xchg 0xdeadfee, %bl",
 "xchg %ax, %cx",
 "xchg %ax, 0xdeadfee",
 "xchg 0xdeadfee, %ax",
 "xchg %eax, %ecx",
 "xchg %eax, 0xdeadfee",
 "xchg 0xdeadfee, %eax",
 "xchg %eax, 0xdeadfee(%esp, %ebp, 4)",
 "xchg 0xdeadfee(%esp, %ebp, 4), %eax",
 ]

leaInstructions = [
    "lea 0xdeadbee, %ecx",
    "lea 24(%eax,%ebx,2), %edx",
    "lea 24(%eax,%ebx,2), %edx",
]

shiftInstructions = [
"rol $3, %al",
"rolb $3, 0xdeadfee",
"rolb $3, 0xdeadfee(%eax, %edx, 2)",
"sal $3, %al",
"salb $3, 0xdeadfee",
"salb $3, 0xdeadfee(%eax, %edx, 2)",
]

stringInstructions = [
"movsb",
"movsw",
"movsl",
"cmpsb",
"cmpsw",
"cmpsl",
"stosb",
"stosw",
"stosl",
"lodsb",
"lodsw",
"lodsl",
]

floatInstructions = [
"fadd 0xdeadbee",
"fadd 0xdeadbee(%eax, %ebx, 4)",
"faddp",
"fmul 0xdeadbee",
"fmul 0xdeadbee(%eax, %ebx, 4)",
"fmulp",
"fcomp",
"fsubp",
"fsubp",
"fdivp",
"fld 0xdeadbee",
]


realWorldCodeSnippet1 = [
"fstps  -0xc(%ebp)",
"flds   -0xc(%ebp)",
"fstpl  0x8(%esp)",
"flds   (%edx)",
"flds   (%ebx)",
"fsubs  (%ecx)",
"flds   0x4(%ebx)",
"fsubs  0x4(%ecx)",
"flds   0x8(%ebx)",
"fsubs  0x8(%ecx)",
"flds   (%edi)",
"mov    -0x44(%ebp),%edi",
"fld1   ",
"fld    %st(0)",
"fdivs  (%edi,%eax,4)",
"fxch   %st(5)",
"fmul   %st(0),%st",
"fldz   ",
"fadd   %st,%st(1)",
"fxch   %st(5)",
"fmul   %st(0),%st",
"faddp  %st,%st(1)",
"fld    %st(5)",
"fmul   %st(6),%st",
"fxch   %st(4)",
"fmul   %st(0),%st",
"faddp  %st,%st(1)",
"fnstcw -0x6(%ebp)",
"lock cmpxchg %ecx,(%esi)",
]

movInstructions = [
"movl $0x16136,0x4(%esp)",
"mov 0xfa, %al",
"mov %al, 0xfa",
"mov 0xfa, %ax",
"mov %ax, 0xfa",
"mov 0xfa, %eax",
"mov %eax, 0xfa",
"movzwl 0x8(%ebp),%ecx",
"movzwl 0x8(%ebp),%ecx",
"movzx %bx, %eax",
"movzx %bl, %ax",
"movzx %bl, %eax",
"movzxb (%ebx), %eax",
"movzxw (%ebx), %eax",
"movzxb (%ebx), %ax",
"mov %edx,-0x20(%ebp)",
]

xmmsInstructions = [
"pcmpeqb (%esi),%xmm0",
"pxor   %xmm0,%xmm0",
"pmovmskb %xmm0,%edx",
"pcmpeqb (%esi),%xmm0",
"movdqa %xmm2,(%eax)",
"pmovmskb %xmm0,%edx",
 "pand   0x8119960,%xmm6",
 "psubusb %xmm6,%xmm4",
 "movdqa %xmm3,%xmm6",
 "psubusb %xmm5,%xmm6",
 "paddusb %xmm3,%xmm5",
 "pmaxub %xmm6,%xmm4",
 "pminub %xmm5,%xmm4",
 "movdqa %xmm4,(%eax,%ecx,1)",
 "movdqa %xmm1,%xmm5",
 "pxor   %xmm2,%xmm5",
 "pand   0x8119960,%xmm5",
 "pcmpeqb %xmm4,%xmm4",
 "pxor   %xmm4,%xmm3",
 "pavgb  %xmm0,%xmm3",
 "pavgb  0x8119970,%xmm3",
 "pxor   %xmm1,%xmm4",
 "pavgb  %xmm2,%xmm4",
 "pavgb  %xmm5,%xmm3",
 "paddusb %xmm4,%xmm3",
 "movdqa 0x8119980,%xmm6",
 "psubusb %xmm3,%xmm6",
 "psubusb 0x8119980,%xmm3",
 "pminub %xmm7,%xmm6",
 "pminub %xmm7,%xmm3",
 "psubusb %xmm6,%xmm1",
 "psubusb %xmm3,%xmm2",
 "paddusb %xmm3,%xmm1",
 "paddusb %xmm6,%xmm2",
 "movdqa %xmm1,(%esi,%ecx,2)",
 "movdqa %xmm2,(%eax)",
 "movdqa %xmm3,%xmm7",
 "movdqa %xmm1,%xmm6",
 "psubusb %xmm1,%xmm7",
 "psubusb %xmm3,%xmm6",
 "psubusb %xmm5,%xmm7",
 "psubusb %xmm5,%xmm6",
 "pcmpeqb %xmm7,%xmm6",
 "pand   %xmm4,%xmm6",
 "pand   0x10(%esp),%xmm4",
 "movdqa %xmm4,%xmm7",
 "psubb  %xmm6,%xmm7",
 "pand   %xmm4,%xmm6",
 "movdqa %xmm1,%xmm4",
 "pavgb  %xmm2,%xmm4",
 "pavgb  %xmm4,%xmm3",
 "pxor   (%esi),%xmm4",
 "pand   0x8119960,%xmm4",
 "psubusb %xmm4,%xmm3",
 "movdqa %xmm0,%xmm4",
 "psubusb %xmm6,%xmm4",
 "paddusb %xmm0,%xmm6",
 "pmaxub %xmm4,%xmm3",
 "pminub %xmm6,%xmm3",
 "movdqa %xmm3,(%esi,%ecx,1)",
 "movdqa (%eax,%ecx,2),%xmm4",
 "movdqa %xmm4,%xmm3",
 "movdqa %xmm2,%xmm6",
 "psubusb %xmm2,%xmm3",
 "psubusb %xmm4,%xmm6",
 "psubusb %xmm5,%xmm3",
 "psubusb %xmm5,%xmm6",
 "pcmpeqb %xmm3,%xmm6",
 "pand   %xmm5,%xmm6",
#mark
 "movdqa 0x10(%esp),%xmm5",
 "pand   %xmm6,%xmm5",
 "psubb  %xmm6,%xmm7",
 "movdqa (%eax,%ecx,1),%xmm3",
 "movdqa %xmm1,%xmm6",
 "pavgb  %xmm2,%xmm6",
 "pavgb  %xmm6,%xmm4",
 "pxor   (%eax,%ecx,2),%xmm6",
 "movdqa (%esi,%ecx,1),%xmm0",
 "movdqa (%esi,%ecx,2),%xmm1",
 "movdqa (%eax),%xmm2",
 "movdqa (%eax,%ecx,1),%xmm3",
 "movd   %edx,%xmm4",
 "movd   %ebx,%xmm5",
 "pshuflw $0x0,%xmm4,%xmm4",
 "punpcklqdq %xmm4,%xmm4",
 "pshuflw $0x0,%xmm5,%xmm5",
 "punpcklqdq %xmm5,%xmm5",
 "packuswb %xmm4,%xmm4",
 "packuswb %xmm5,%xmm5",
 "movdqa %xmm2,%xmm6",
 "movdqa %xmm1,%xmm7",
 "psubusb %xmm1,%xmm6",
 "psubusb %xmm2,%xmm7",
 "por    %xmm6,%xmm7",
 "psubusb %xmm4,%xmm7",
 "movdqa %xmm1,%xmm6",
 "movdqa %xmm0,%xmm4",
 "psubusb %xmm0,%xmm6",
 "psubusb %xmm1,%xmm4",
 "por    %xmm6,%xmm4",
 "psubusb %xmm5,%xmm4",
 "por    %xmm4,%xmm7",
 "movdqa %xmm2,%xmm6",
 "movdqa %xmm3,%xmm4",
 "psubusb %xmm3,%xmm6",
 "psubusb %xmm2,%xmm4",
 "por    %xmm6,%xmm4",
 "psubusb %xmm5,%xmm4",
 "por    %xmm4,%xmm7",
 "pxor   %xmm6,%xmm6",
 "pcmpeqb %xmm6,%xmm7",
 "movd   (%ebx),%xmm4",
 "punpcklbw %xmm4,%xmm4",
 "punpcklbw %xmm4,%xmm4",
 "pcmpeqb %xmm3,%xmm3",
 "pcmpgtb %xmm3,%xmm4",
 "pand   %xmm7,%xmm4",
"movdqa (%esi),%xmm3",
"movd   %mm0,(%eax,%ebx,1)",
"movd   %mm1,(%eax,%ebx,2)",
 "punpckhdq %mm1,%mm1",
"movd   %mm1,(%ecx)",
 "punpckhdq %mm3,%mm3",
 "punpcklbw %mm5,%mm4",
 "punpcklbw %mm3,%mm6",
 "movq   %mm4,%mm5",
 "punpcklwd %mm6,%mm4",
 "punpckhwd %mm6,%mm5",
 "movd   %mm4,(%ecx,%ebx,1)",
 "punpckhdq %mm4,%mm4",
 "movd   %mm4,(%ecx,%ebx,2)",
 "movd   %mm5,(%ecx,%esi,1)",
 "punpckhdq %mm5,%mm5",
 "movd   %mm5,(%ecx,%ebx,4)",
 "movdqa (%esi,%ecx,1),%xmm0"
]

# We comment out the ones already tested to speed up testing
instructions = []
instructions += arithmeticInstructionsTemplate("add")
instructions += arithmeticInstructionsTemplate("or")
instructions += arithmeticInstructionsTemplate("adc")
instructions += arithmeticInstructionsTemplate("sbb")
instructions += arithmeticInstructionsTemplate("and")
instructions += arithmeticInstructionsTemplate("sub")
instructions += arithmeticInstructionsTemplate("xor")
instructions += arithmeticInstructionsTemplate("cmp")
instructions += arithmeticInstructionsTemplate("test")
instructions += arithmeticInstructionsTemplate("mov")
instructions += divMulInstructions
instructions += specialOneByteInstructions
instructions += leaInstructions
instructions += shiftInstructions
instructions += stringInstructions
instructions += floatInstructions
instructions += realWorldCodeSnippet1
instructions += movInstructions
instructions += xmmsInstructions
instructions += ["psubusb 0x8119980,%xmm3",
                 "psubusb (%eax),%xmm3",
                 "psubusb (,%eax,4),%xmm3",
                 "punpcklbw 0x8119980,%mm4",
                 "psubusb %xmm6,%xmm4"];

# segment... atomic... etc.
instructionPairs = [
("mov %gs:(%edx),%eax",
 "mov %gs:(%rdx),%eax"),

("mov %gs:(%eax),%eax",
 "mov %gs:(%rax),%eax"),

("mov %gs:-56,%eax",
 "mov %gs:-56,%eax"),

("mov %gs:0x80,%eax",
 "mov %gs:0x80,%eax"),

("xor %gs:0x80,%eax",
 "xor %gs:0x80,%eax"),

("cmp $0x9, %gs:(%eax)",
 "cmp $0x9, %gs:(%rax)"),
]


# Problematic instructions: still to support

#instructions = ["vmovdqu -0x40(%ebp),%xmm0",
	        #"vpshufb %xmm6,%xmm0,%xmm0",
	        #"vzeroall",
	        #"vpaddd %xmm7,%xmm2,%xmm6",
	        #"vpalignr $0x8,%xmm0,%xmm1,%xmm4",
	        #"vpaddd %xmm3,%xmm7,%xmm7"];
#instructions = ["lfence",
	        #"mfence",
                #"pblendw $129, %xmm2, %xmm1",
                 #"vmovaps %ymm1, %ymm0"];
#instructionPairs = [];

# Code is printed here

print preamble

for i in range(0, len(instructions)):
  print "int test"+str(i)+"(){ /* 0 on fail, 1 on success */"
  print "  uchar* pa = buf1;" 
  print "  uchar* pb = buf2;"
  print "  BEGIN_32ASM(pa)"
  print "    " + instructions[i]
  print "  END_ASM"
  print "  BEGIN_ASM(pb)"
  print "    " + instructions[i]
  print "  END_ASM"
  print "  int er = check_action_copy(buf1, buf2, (int)(pb-buf2), \""+instructions[i]+"\");"
  print r"""if (er) { 
              printf("orig:     ");
              uchar* i;
              for (i = buf1; i!=pa; i++){ 
                printf("%02x ", (unsigned)*i); 
              } 
              printf("\n");
              return 0;
           } else {
              return 1;
           }"""
  print "}"

for i in range(0, len(instructionPairs)):
  print "int testPair"+str(i)+"(){ /* 0 on fail, 1 on success */"
  print "  uchar* pa = buf1;" 
  print "  uchar* pb = buf2;"
  print "  BEGIN_32ASM(pa)"
  print "    " + instructionPairs[i][0]
  print "  END_ASM"
  print "  BEGIN_ASM(pb)"
  print "    " + instructionPairs[i][1]
  print "  END_ASM"
  print "  int er = check_action_copy(buf1, buf2, (int)(pb-buf2), \""+instructionPairs[i][0]+"\");"
  print r"""if (er) { 
              printf("orig:     ");
              uchar* i;
              for (i = buf1; i!=pa; i++){ 
                printf("%02x ", (unsigned)*i); 
              } 
              printf("\n");
              return 0;
           } else {
              return 1;
           }"""
  print "}"

print r"""
int main(){
  // Generates buffers for 32 bit instructions. 
  // We use mmap since they need to be addressable with 32 bit pointers

  buf1 = fbt_mmap((void*)0x90000, 5 * PAGESIZE, PROT_READ|PROT_WRITE,
					 MAP_PRIVATE|MAP_ANONYMOUS, -1, 0,
					 "fail!!\nn");
  buf2 = fbt_mmap((void*)0x180000, 5 * PAGESIZE, PROT_READ|PROT_WRITE,
					 MAP_PRIVATE|MAP_ANONYMOUS, -1, 0,
					 "fail!!!\n");
  int nsuccess = 0;
  int ntests = 0;
"""
for i in range(0, len(instructions)):
    print "nsuccess += test"+str(i)+"();\n"
    print "ntests++;"
for i in range(0, len(instructionPairs)):
    print "nsuccess += testPair"+str(i)+"();\n"
    print "ntests++;"
print r"""
  printf("\n\n%d of %d tests successful\n\n", nsuccess, ntests);
  if (nsuccess == ntests){
    return 0;
  } else {
    return -1;
  }
}
"""





