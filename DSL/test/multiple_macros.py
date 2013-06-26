#!/usr/bin/env python

import unittest
import os
import subprocess

DSL_PATH = '../src/parse.py'

def execute(command):
    p = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
    
    p.wait()
    stdout, stderr = p.communicate()    
    return (p.returncode, stdout, stderr)

class TestMultipleMacros(unittest.TestCase):
    """Tests that we can use multiple instances of the same macro while they still
    generate different code"""       
        
    def test_compilation(self):
        os.environ['DSL_PATH'] = DSL_PATH
       
        dsl_result = os.system('$DSL_PATH "%s" "%s"' % ('multiple_macros.dsl', 'multiple_macros.c'))
        self.assertEqual(dsl_result, 0)
        
        compilation_result = os.system('gcc -m32 multiple_macros.c -o multiple_macros')
        self.assertEqual(compilation_result, 0)
        
        execution_result, stdout, stderr = execute(['./multiple_macros'])

        self.assertEqual(execution_result, 0)        
        self.assertEqual(stdout.splitlines(), ['a()', 'b()'])
        
if __name__ == '__main__':
    unittest.main()    
