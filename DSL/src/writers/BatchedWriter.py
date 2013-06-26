#!/usr/bin/env python

"""
A writer that buffers output and tries to 'batch' multiple chars into a single integer write to reduce instructions.
"""

class BatchedWriter(object):
    def __init__(self, inner):
        self.inner = inner
        self.batch = []
        
    def write_comment(self, text):    
        self.inner.write_comment(text)
        
    def write_byte(self, byte):
        self.batch += [byte]
        if len(self.batch) >= 4:
            self.flush()
        
    def write_expression(self, expression):
        self.flush()
        self.inner.write_expression(expression)

    def write_raw(self, source):
        self.flush()    
        self.inner.write_raw(source)      
        
    def flush(self):
        assert len(self.batch) <= 4
        
        if len(self.batch) < 4:    
            for byte in self.batch:
                self.inner.write_byte(byte)
        else:
            compact = ''
            for byte in self.batch:
                compact = byte + compact
            self.inner.write_int32(compact)
        
        self.batch = []
        self.end_line()        

    def end_line(self):
        self.inner.end_line()

    def write_int32(self, value):
        self.inner.write_int32(self, value)        
        
    def _get_source(self):
        return self.inner.source
    
    def set_line_number(self, file_name, line_number):
        return self.inner.set_line_number(file_name, line_number)

    def end(self):
        self.flush()
        self.inner.end()
        
    source = property(_get_source)        
