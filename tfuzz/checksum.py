import os
from .utils import replace_input_placeholder
from .qemu_runner import QEMURunner
from .r2 import Radare2
import ipdb


class ChecksumDetector(object):
    def __init__(self, binary, valid_input_dir, malformed_input_dir, target_opts=None, input_placeholder='@@'):
        self.binary = os.path.abspath(binary)
        self.valid_input_dir = os.path.abspath(valid_input_dir)
        self.malformed_input_dir = os.path.abspath(malformed_input_dir)
        self.target_opts = target_opts
        self.input_placeholder = input_placeholder
        self._detect_checksum()

    def _detect_checksum(self):
        radare2 = Radare2(self.binary, flags=['-w'])
        initial_run = True
        possible_checksum = set()
        for input_file in os.listdir(self.valid_input_dir)[:10]: 
            opts = replace_input_placeholder(self.target_opts,
                                             os.path.abspath(os.path.join("png", input_file)),
                                             self.input_placeholder)
            t = QEMURunner(self.binary, input='', argv=[self.binary] + opts)
            if initial_run:
                possible_checksum.update(t.trace)
                initial_run = False
                print t.trace
            else:
                possible_checksum.intersection_update(t.trace)
            c_addr = radare2.get_cjump_addr(t.trace[0])

        print possible_checksum
        for input_file in os.listdir(self.malformed_input_dir):
            opts = replace_input_placeholder(self.target_opts,
                                             os.path.abspath(os.path.join("png", input_file)),
                                             self.input_placeholder)
            t = QEMURunner(self.binary, input='', argv=[self.binary] + opts)
            print t.trace
            possible_checksum.difference_update(t.trace)


        print possible_checksum






