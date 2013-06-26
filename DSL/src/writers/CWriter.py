#!/usr/bin/env python

"""
Contains a writer that generates ANSI C code that produces assembly code at run time
"""

class CWriter(object):
    def __init__(self, target):
        self.target = target
        self.source = '{\n'        
    
    def set_line_number(self, file_name, line_number):
        self.file_name = file_name
        self.line_number = line_number    

    def write_line_number(self):
        self.source += '# %d "%s"\n' % (self.line_number, self.file_name)

    def write_comment(self, text):
        self.write_line_number()
        self.source += '// %s\n' % text
        
    def write_byte(self, byte):
        self.write_line_number()
        self.source += '*((%s)++) = 0x%s;\n' % (self.target, byte)
        
    def write_int32(self, value):
        self.write_line_number()
        self.source += '*((long*)(%s)) = 0x%s;\n' % (self.target, value)
        self.source += '(%s) += 4;\n' % self.target        
        
    def write_expression(self, expression):
        self.write_line_number()
        self.source += '*((uint32_t*)(%s)) = (uint32_t)(%s);\n' % (self.target, expression)
        self.source += '(%s) += 4;\n' % self.target
        
    def write_expression64(self, expression):
        self.write_line_number()
        self.source += '*((uint64_t*)(%s)) = (uint64_t)(%s);\n' % (self.target, expression)
        self.source += '(%s) += 4;\n' % self.target

    def write_raw(self, source):
        self.write_line_number()
        self.source += source    

    def end_line(self):
        self.source += '\n'    
        
    def flush(self):
        pass        
    
    def end(self):
        self.flush()
        self.source += '}\n'
