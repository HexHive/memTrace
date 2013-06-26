from writers.CWriter import CWriter

class JneAbsMacro(object):
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
        return '\n'.join(['nop'] * 6)

    def generate(self, writer, target, obj):
        """Returns the assembly generation code, i.e. the C code that generates the assembly at run time"""
        if type(writer) != CWriter and type(getattr(writer, 'inner', None)) != CWriter:
            raise Exception('CallAbsMacro currently only supports C as target language')

        # TODO: This is as ugly as it is because the DSL is applied *after*
        # C macros are expanded, which means that we cannot use them in DSL 
        # macros.

        writer.write_raw("""
        *((%(target)s)++)=0x0f;\n
        *((%(target)s)++)=0x85;\n
        if ((((uint64_t)(%(call_target)s) - (uint64_t)(%(target)s) - 4) & (uint32_t)0x0) != 0) {\n\n
          fllwrite(1, "Relative jump target is too far away!\\n");\n
          __asm__ volatile("hlt" : : : "memory");\n
        }\n\n
        *((uint32_t*)(%(target)s)) = (uint32_t)((uint64_t)(%(call_target)s) - (uint64_t)(%(target)s) - 4);\n\n
        (%(target)s)+=4;\n\n
        """ % {'target': target, 'call_target': self.call_target})
        return 5

