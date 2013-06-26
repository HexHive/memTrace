import subprocess
import objdump

def getMachineCode(string, bits):
    fil = open("asm.as", "w")
    fil.write(string)
    fil.close()

    if bits == 32:
        s = 'as --32 "asm.as" -o "asm.o"'
    else:
        s = 'as --64 "asm.as" -o "asm.o"'

    p = subprocess.Popen(s, shell=True)
    p.wait()
    if p.returncode != 0:
        raise Exception('Assembly generation failed.')

    # Read generated object code
    obj = objdump.objdump("asm.o", {})
    return obj.bytes


biarg = ["add", "sub", "or", "mov",
         "and", "xor", "cmp", "sbb", 
         "adc", "test", "xchg"]

combos = [
          ("r8", "r8", "b"),
          ("r8", "m", "b"),
          ("r8", "mm", "b"),
          ("m", "r8", "b"),
          ("mm", "r8", "b"),
          ("i8", "r8", "b"),
          ("i8", "m", "b"),
          ("i8", "mm", "b"),

          ("r16", "r16", "w"),
          ("r16", "m", "w"),
          ("r16", "mm", "w"),
          ("m", "r16", "w"),
          ("mm", "r16", "w"),
          ("i16", "r16", "w"),
          ("i16", "m", "w"),
          ("i16", "mm", "w"),

          ("r32", "r32", "l"),
          ("r32", "m", "l"),
          ("r32", "mm", "l"),
          ("m", "r32", "l"),
          ("mm", "r32", "l"),
          ("i32", "r32", "l"),
          ("i32", "m", "l"),
          ("i32", "mm", "l"),
          ]

regs8 = ["%al", "%cl", "%dl", "%bl"]
regs16 = ["%ax", "%cx", "%dx", "%bx", "%si", "%di", "%sp", "%bp"]
regs32 = ["%eax", "%ecx", "%edx", "%ebx", "%esi", "%edi", "%esp", "%ebp"]

# an example...
ex = {"r8":"%bl",
      "r16":"%bx",
      "r32":"%ebx",
      "m":"0xdeadbee",
      "mm":"0xdeadbee(%ecx, %eax, 8)",
      "i8":"$0xde",
      "i16":"$0xdead",
      "i32":"$0xdeadbeef"
     }

def main():
    for inst in []: #biarg:
        for (src, dst, suffix) in combos:
            s = inst + suffix + " " + ex[src] + ", " + ex[dst] + "\n"
            print s
            m32 = getMachineCode(s, 32)
            m64 = getMachineCode(s, 64)
            if  m32 == m64:
                print "SAME"
            else:
                print "DIFFER"
            print m32
            print m64

    s = "add %eax, 0xdeadbee(%ebx, %ecx, 8)\n"
    print s
    print getMachineCode(s, 32)
    print getMachineCode(s, 64)

    s = "add %ebp, 0xdeadbee(%ebx)\n"
    print s
    print getMachineCode(s, 32)
    print getMachineCode(s, 64)

    s = "add %ebp, 0xdeadbee(, %ecx, 8)\n"
    print s
    print getMachineCode(s, 32)
    print getMachineCode(s, 64)

    s = "add %bx, 0xdeadbee(, %ecx, 8)\n"
    print s
    print getMachineCode(s, 32)
    print getMachineCode(s, 64)

    s = "add %bx, 0xdeadbee(, %ecx, 8)\n"
    print s
    print getMachineCode(s, 32)
    print getMachineCode(s, 64)

    s = "add %ebp, 0xdeadbee\n"
    print s
    print getMachineCode(s, 32)
    print getMachineCode(s, 64)

    s = "add %eax, 0xdeadbee\n"
    print s
    print getMachineCode(s, 32)
    print getMachineCode(s, 64)

    s = "add %edi, 0xdeadbee\n"
    print s
    print getMachineCode(s, 32)
    print getMachineCode(s, 64)

    s = "leal 0xdeadbee(, %ecx, 8), %eax\n"
    print s
    print getMachineCode(s, 32)
    print getMachineCode(s, 64)

    s = "leal 0xdeadbee, %eax\n"
    print s
    print getMachineCode(s, 32)
    print getMachineCode(s, 64)

    s = "add %edx, (%ebx)\n"
    print s
    print getMachineCode(s, 32)
    print getMachineCode(s, 64)

    s = "add %eax, 0xdeadbee\n"
    print s
    print getMachineCode(s, 32)
    print getMachineCode(s, 64)

    s = "mov %eax, 0xdeadbee\n"
    print s
    print getMachineCode(s, 32)
    print getMachineCode(s, 64)

    s = "mov %eax, 0xdeadbee\n"
    print s
    print getMachineCode(s, 32)
    print getMachineCode(s, 64)
main()

