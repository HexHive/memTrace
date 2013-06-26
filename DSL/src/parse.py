#!/usr/bin/env python

"""
Preprocessor step for C / C++ code that allows easy generation of x86 in your
program.
"""

import re
import os
import sys
import subprocess
import tempfile

from args import ArgParser
from writers.CWriter import CWriter
from writers.BatchedWriter import BatchedWriter

from macros.CallAbsMacro import CallAbsMacro
from macros.MovAbsMacro import MovAbsMacro
from macros.MovAbsR8Macro import MovAbsR8Macro
from macros.MovAbsR10Macro import MovAbsR10Macro
from macros.MovAbsR14Macro import MovAbsR14Macro
from macros.JmpAbsMacro import JmpAbsMacro
from macros.JneAbsMacro import JneAbsMacro
from macros.StoreLabelMacro import StoreLabelMacro
from objdump import objdump

class AssemblyRewriter(object):
    def __init__(self):
        self.magic_number = int('13370000', 16)
        self.macros = {
            'movabs_to_rax': MovAbsMacro,
            'movabs_to_r8': MovAbsR8Macro,
            'movabs_to_r10': MovAbsR10Macro,
            'movabs_to_r14': MovAbsR14Macro,
            'call_abs': CallAbsMacro,
            'jmp_abs': JmpAbsMacro,
            'jne_abs': JneAbsMacro,
            'store_label': StoreLabelMacro
        }
        self.marker = ['BEGIN_ASM', 'END_ASM']
        self.macro_instances = None

    def rewrite_asm(self, asm, bits):
        """This step turns the code of a DSL block into valid AT&T assembler
        syntax and compiles it with the GNU Assembler.
        
        Arguments:
            asm: The source code in our assembler DSL
            
        Returns:
            An objdump for the generated assembly (see objdump.py) 
        """

        variables = {}
        
        raw = ''
        
        # First, let's remove all multiline comments
        # TODO: currently does not work with line numbers
        found = True
        while found:
            start = asm.find('/*')
            end = asm.find('*/', start+2)
            if start == -1 or end == -1:
                found = False
            else:
                print 'Removed comment {%s}' % asm[start:end+2]
                linebreaks = ''.join(lb for lb in asm[start:end+2] if lb in ('\n', '\r'))
                print 'linebreaks = ', len(linebreaks)
                asm = asm[:start] + linebreaks + asm[end+2:]
        
        
        # Rewrite assembly code
        self.macro_instances = []

        #statements = reduce(lambda x,y: x+y, map(lambda x: x.split(";"), asm.split("\n")));
        statements = asm.split("\n");
 	#print statements
        for line_pos, line in enumerate(statements):
            line, _, _ = line.partition('//')

            if len(line.strip()) == 0:
                continue    
        
            # Parse this line
            line = line.strip()
            command, _, args = line.partition(' ')
            command = command.strip()
            args = [a.strip() for a in args.split(',')]

            #print command
            if command in self.macros:
                # We add a label so we can find this instruction later
                # in the machine code
                label = 'macro%d' % len(self.macro_instances)
                macro = self.macros[command](args, label)
                new_line = '\n%s:\n%s\n' % (label, macro.expand())

                line = new_line
                
                self.macro_instances += [macro]

            # Does this line contain a variable?
            pattern = r'\{(.*?)\}'        
            match = re.search(pattern, line)
            while match:
                var_name = match.groups()[0]
                if var_name not in variables:
                    variables[var_name] = self.magic_number
                    self.magic_number += 1
                
                magic = variables[var_name]

                line = line[:match.span()[0]] + ('%s' % magic) + line[match.span()[1]:]
                match = re.search(pattern, line)            
            
            raw += '_I%d:\n' % line_pos
            raw += line + '\n'

        # Compile assembly
        f = tempfile.NamedTemporaryFile('w', suffix='.as', delete=False)
        f.write(raw)
        f.close()
        
        obj_path = os.path.splitext(f.name)[0] + '.out'
        if bits == 32:
            s = 'as --32 "%s" -o "%s"' % (f.name, obj_path)
        else:
            s = 'as --64 "%s" -o "%s"' % (f.name, obj_path),
        p = subprocess.Popen(s, shell=True)
        p.wait()
        
        if p.returncode != 0:
            raise Exception('Assembly generation failed.')

        # Read generated object code
        obj = objdump(obj_path, variables)
        return obj

    def create_target_code(self, obj, original_target, line_mapping):
        # Keep track of all macro offsets
        macro_offsets = {}
        for macro in self.macro_instances:
            offset = obj.labels[macro.label]
            macro_offsets[offset] = macro

        # We stored a _In macro for each instruction, let's translate those back
        instruction_mapping = {}
        for label, offset in obj.labels.iteritems():
            if not label.startswith('_I'):
                continue
            
            instruction_no = int(label[2:])

            instruction_mapping[offset] = instruction_no

        # Collect all backpatching offsets
        offsets = {}
        for variable, var_offsets in obj.variable_occurrences.iteritems():
            for offset in var_offsets:
                offsets[offset] = variable

        # Generate source code
        writer = BatchedWriter(CWriter(original_target))
        offset = 0
        
        while offset < len(obj.bytes):
            # Emit line number
            instruction_no = instruction_mapping.get(offset, None)
            if instruction_no is not None:
                file_name, line_no = line_mapping[instruction_no]
                writer.set_line_number(file_name, line_no)

            # Generate code
            byte = obj.bytes[offset]
            if offset in obj.code:
                writer.write_comment(str(obj.code.get(offset)))
            
            macro_written = 0
            if offset in macro_offsets:
                macro = macro_offsets[offset]
                # TODO: clean up data passed into macro generation step
                macro_written = macro.generate(writer, original_target, obj)
                offset += macro_written
                writer.end_line()               

            if macro_written == 0: 
              if offset in offsets:
                  writer.write_expression(offsets[offset])
                  offset += 4
                  
              else:
                  writer.write_byte(byte)
                  offset += 1      

              writer.end_line()  
                
        writer.flush()    
        writer.end()              
        return writer.source

    def process_file(self, in_path, out_path):
        """Process a whole source file, stored at <in_path> and writes the 
        result, a (hopefully) valid source file in the target language to 
        <out_path>
        
        Arguments:
            in_path: The path to the source file containing DSL fragments
            out_path: Where to store the resulting source file

        Returns:
            None
        """
        
        # The generated C source code
        out = ''
        
        # Are we currently parsing assembler code?
        is_asm = False
        
        # The assembler code in the current assembly block
        asm = ''    
        
        # The name of the target C variable which will contain the address at which we'll write the machine code
        asm_target = None

        # Pattern to match for line number annotations
        line_number_pattern = r'\#\s([0-9]+)\s\"(.*)\"'

        # Keep track of what file the current source line is part of
        current_line, current_file = 1, None
        block_line, block_file = None, None
        
        print 'Rewriting <%s> to <%s>' % (in_path, out_path)

        # Parse the source file and rewrite each assembler block
        for line in open(in_path, 'r'):
            begin_match = re.match(r'%s\(([a-zA-Z_]+)\)' % re.escape(self.marker[0]), line.strip())
            begin_match32 = re.match(r'%s\(([a-zA-Z_]+)\)' % re.escape("BEGIN_32ASM"), line.strip())
            
            line_number_match = re.match(line_number_pattern, line.strip())
            
            if line.strip().startswith('#'):
                if line_number_match:
                    current_line, current_file = line_number_match.groups()
                    current_line = int(current_line)
                out += line
            else:
                if begin_match:
                    #print "64 bit match"
                    # Write out current line number, so line numbers still match
                    # up
                    out += '# %d "%s"\n' % (current_line, current_file)
                    
                    # Start capturing input string
                    line_mapping = []
                    asm_target = begin_match.groups()[0]
                    is_asm = True
                    asm = ''
                    bits = 64
                elif begin_match32:
                    #print " bit match"
                    # Write out current line number, so line numbers still match
                    # up
                    out += '# %d "%s"\n' % (current_line, current_file)
                    
                    # Start capturing input string
                    line_mapping = []
                    asm_target = begin_match32.groups()[0]
                    is_asm = True
                    asm = ''
                    bits = 32
                elif line.strip().startswith(self.marker[1]):
                    assert is_asm, "%s without %s." % (self.marker[1], self.marker[0])            
                    is_asm = False
                    #print "Processing"
                    #print asm
                    obj = self.rewrite_asm(asm, bits)
                    out += self.create_target_code(obj, asm_target, line_mapping)
                    asm = ''            
                    
                    # Make sure line numbers are consistent after the assembly
                    # block
                    out += '# %d "%s"\n' % (current_line + 1, current_file)
                elif is_asm:
                    # expand the line
                    stmts = line.split(";")
                    for s in stmts:
                      #print "adding " + s
                      asm += s.strip() + "\n"
                      line_mapping += [(current_file, current_line)]
                else:
                    out += line
                current_line += 1                    

        # We have some left-over assembly code: missing an end marker
        if len(asm) > 0:
            raise Exception("Leftover assembler code. Did you miss a %s?" % self.marker[1])

        # Write result
        f = open(out_path, 'w')
        f.write(out)
        f.close()        

    def main(self):   
        p = ArgParser()
        (options, in_path, out_path) = p.parse_args()
        self.options = options
        obj = self.process_file(in_path, out_path)
    

if __name__ == '__main__':
    asm_rewriter = AssemblyRewriter()
    asm_rewriter.main()
    sys.exit(0)

