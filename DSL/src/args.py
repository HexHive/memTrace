#!/usr/bin/env python

"""Contains code for parsing the command line arguments passed to the program"""

from optparse import OptionParser

class ArgParser(OptionParser):
    def __init__(self):
        OptionParser.__init__(self, usage="usage: %prog [options] in_file out_file")
        self.add_option('-c', '--config', dest='config',
                     help='Loads a custom configuration from a JSON file.')

    def parse_args(self, *args, **kwargs):                     
        (options, args) = OptionParser.parse_args(self, *args, **kwargs)

        if len(args) != 2:
            self.error('Incorrect number of positional arguments.')
            
        return (options, args[0], args[1])
