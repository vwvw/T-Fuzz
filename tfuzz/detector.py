import os
import struct
import shutil
from .utils import replace_input_placeholder
from .qemu_runner import QEMURunner

class Detection(object):

    def __init__(self, binary, target_opts, working_dir, valid_input_file, input_placeholder='@@'):
        self.binary = os.path.abspath(binary)
        self.target_opts = target_opts
        self.input_placeholder = input_placeholder
        self.working_dir = os.path.abspath(working_dir)
        if os.path.isdir(self.working_dir):
            #raise Exception("working_dir already exists.")
            shutil.rmtree(self.working_dir)
        os.makedirs(self.working_dir)
        
        if not os.path.isfile(valid_input_file):
            raise Exception("valid_input_file is not correct")
        self.valid_input_file = valid_input_file

        self.malformed_input_dir = os.path.join(self.working_dir, "malformed_inputs")
        print self.malformed_input_dir
        os.makedirs(self.malformed_input_dir)
        
        self.mutate_input(self.valid_input_file)
        self.run()


    def mutate_input(self, input_file):
        for offset in range(0, os.stat(input_file).st_size):
            malformed_input = os.path.join(self.malformed_input_dir, "malformed_input_" + str(offset) + ".png")
            shutil.copyfile(input_file, malformed_input)
            with open(malformed_input, "r+b") as f:
                f.seek(offset, 0)
                b = f.read(1)
                f.seek(-1, 1) # moving the pointer back because of the read
                f.write(struct.pack('B', ord(b)^0xFF))

    def run(self):
        malformed_traces = []
        for i, malformed_input in enumerate(sorted(os.listdir(self.malformed_input_dir))):
            #import ipdb; ipdb.set_trace()
            opts = replace_input_placeholder(self.target_opts,
                                             os.path.join(self.malformed_input_dir, malformed_input),
                                             self.input_placeholder)
            t = QEMURunner(self.binary, input='', argv=[self.binary] + opts, record_stdout=True)
            if t.crash_mode:
                print "Crashed"
            if t.tmout:
                print "tmout"
            malformed_traces.append(t.trace)

        opts = replace_input_placeholder(self.target_opts,
                                         self.valid_input_file,
                                         self.input_placeholder)
        t = QEMURunner(self.binary, input='', argv=[self.binary] + opts)
        
        print t.trace
        print malformed_traces[0]


