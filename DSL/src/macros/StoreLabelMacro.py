from writers.CWriter import CWriter

class StoreLabelMacro(object):
    """This macro is used to store the run-time address of a label into a 
    variable in the generation language"""
    
    def __init__(self, args, label):
        self.args = args
        print self.args
        assert len(self.args) == 1
        
        self.var_name, _, self.label_name = self.args[0].partition('=')
        print self.var_name, self.label_name
        self.label = label

    def expand(self):
        return '\n # StoreLabelMacro'

    def generate(self, writer, target, obj):
        if type(writer) != CWriter and type(getattr(writer, 'inner', None)) != CWriter:
            raise Exception('CallAbsMacro currently only supports C as target language')

        print obj.labels[self.label_name]

        writer.write_raw("""%s = _dsl_original_target + %d;\n""" % (self.var_name, obj.labels[self.label_name]))
        raw_input
        return 0
