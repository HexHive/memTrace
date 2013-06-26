from writers.CWriter import CWriter

class MovAbsR10Macro(object):
    def __init__(self, args, label):
        self.args = args
        assert len(self.args) == 1
        
        call_target = self.args[0]
        call_target = call_target.strip()
        assert call_target.startswith('{')
        assert call_target.endswith('}')
        self.call_target = call_target[1:-1]

        self.label = label
        
    def expand(self):
        """Expands the macro into what should be passed to the GNU assembler"""
        return '\n'.join(['nop'] * 10)

    def generate(self, writer, target, obj):
        """Returns the assembly generation code, i.e. the C code that generates the assembly at run time"""
        if type(writer) != CWriter and type(getattr(writer, 'inner', None)) != CWriter:
            raise Exception('CallAbsMacro currently only supports C as target language')
    
#  4004b8:  49 b8 ee ff c0 ee df    movabs $0xdeadfeec0ffee,%r8
#  4004bf:   ea 0d 00 

        writer.write_raw("""
        *((%(target)s)++)=0x49; \n
        *((%(target)s)++)=0xba; \n
        *((uint64_t*)(%(target)s)) = (uint64_t)(%(call_target)s);\n
        (%(target)s)+=8;\n
        """ % {'target': target, 'call_target': self.call_target})
        return 10
