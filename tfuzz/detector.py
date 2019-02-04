from collections import defaultdict
import os
# import r2
import re
import shutil
import struct
import subprocess

from anytree import AnyNode as Node
from .utils import replace_input_placeholder
from .qemu_runner import QEMURunner
from .r2 import Radare2
from pympler.tracker import SummaryTracker


def run_qemu(args):
    binary, opts = args
    return QEMURunner(binary,
                      input='',
                      argv=[binary] + opts,
                      record_stdout=True)


class Detection(object):

    def __init__(self, binary, target_opts, working_dir, valid_input_file,
                 input_placeholder='@@'):
        self.tracker = SummaryTracker()
        self.binary = os.path.abspath(binary)
        self.target_opts = target_opts
        self.input_placeholder = input_placeholder
        self.working_dir = os.path.abspath(working_dir)
        if os.path.isdir(self.working_dir):
            # raise Exception("working_dir already exists.")
            shutil.rmtree(self.working_dir)
        os.makedirs(self.working_dir)

        if not os.path.isfile(valid_input_file):
            raise Exception("valid_input_file is not correct")
        _, self.file_extension = os.path.splitext(valid_input_file)
        self.wellformed_input_dir = os.path.join(self.working_dir,
                                                 "wellformed_inputs")
        os.makedirs(self.wellformed_input_dir)
        self.valid_input_file = \
            os.path.join(self.wellformed_input_dir,
                         "wellformed_input_{:03}{}".format(
                             0, self.file_extension))
        shutil.copy(valid_input_file, self.valid_input_file)

        self.malformed_input_dir = os.path.join(self.working_dir,
                                                "malformed_inputs")
        os.makedirs(self.malformed_input_dir)

        self.mutate_input(self.valid_input_file)
        self.root_node = Node(trace=[])
        self.traces = []
        self.run()

    def mutate_input(self, input_file):
        for offset in range(0, os.stat(input_file).st_size):
            malformed_input_name = \
                "malformed_input_{:05}{}".format(offset,
                                                  self.file_extension)
            malformed_input = os.path.join(self.malformed_input_dir,
                                           malformed_input_name)
            shutil.copyfile(input_file, malformed_input)
            with open(malformed_input, "r+b") as f:
                f.seek(offset, 0)
                b = f.read(1)
                f.seek(-1, 1)  # moving the pointer back because of the read
                f.write(struct.pack('B', ord(b) ^ 0xFF))

    def modify_node(self, modified_node, child_node):
        for i, trace in enumerate(self.traces):
            for j, n in enumerate(trace):
                if n == modified_node:
                    self.traces[i] = trace[:j+1] + [child_node] + \
                            (trace[j+1:] if j+1 < len(trace) else [])

    def add_trace_to_tree(self, trace, last_node):
        if len(trace) > 0:
            next_node_list = [c for c in last_node.children
                              if c.trace[0] == trace[0]]
            if len(next_node_list) == 0:
                return [last_node, Node(parent=last_node, trace=trace)]
            else:
                # there is already a trace with this node
                assert len(next_node_list) == 1
                next_node = next_node_list[0]
                idx = 0
                min_len = min(len(trace), len(next_node.trace))
                while idx < min_len and next_node.trace[idx] == trace[idx]:
                    idx += 1
                assert idx != 0
                if idx < min_len:
                    # traces diverge at some point
                    old_trace = Node(trace=next_node.trace[idx:])
                    new_trace = Node(parent=next_node, trace=trace[idx:])
                    next_node.trace = next_node.trace[:idx]
                    for c in next_node.children:
                        c.parent = old_trace
                    old_trace.parent = next_node

                    self.modify_node(next_node, old_trace)
                    return [last_node, next_node, new_trace]
                elif min_len < len(next_node.trace):
                    # new trace is a subset of old trace
                    old_trace = Node(parent=next_node,
                                     trace=next_node.trace[idx:])
                    next_node.trace = next_node.trace[:idx]

                    self.modify_node(next_node, old_trace)
                    return [last_node, next_node]
                elif min_len < len(trace):
                    # new trace is longer than previous one,
                    # need to look at childrens.
                    # / ! \ recusrsion
                    r = self.add_trace_to_tree(trace[idx:], next_node)
                    return [last_node] + r
                else:
                    # traces are identical and stop at the same place
                    # could actually be collapsed in the elif before
                    assert len(trace) == len(next_node.trace)
                    return [last_node, next_node]

    def find_entry_point(self):
        entry = None
        prog = re.compile(r'^start address (?P<entry>0x[\da-f]+)$')
        output = subprocess.check_output(["objdump", "-f", self.binary])
        for line in output.split("\n"):
            m = prog.match(line)
            if m is not None:
                entry = int(m.group('entry'), 16)
        return entry

    def analyze_checksum(self, address):
        self.radare2 = Radare2(self.binary)
        # print self.radare2.get_cjump_addr(address)

    def find_divergent_point(self, trace):
        i = 0
        while i < min(len(self.valid_trace), len(trace)) \
                and self.valid_trace[i] == trace[i]:
                    i += 1
        return i
    
    def diff(self, a,b):
        i = 0
        while i < min(len(a), len(b)) and a[i] == b[i]:
            i += 1
        print "0x{:02x}".format(a[i])
        print "0x{:02x}".format(b[i])
        print "0x{:02x}".format(a[i-1])
        print "0x{:02x}".format(b[i-1])
        print i
        print min(len(a), len(b))
        print a[i-5: i+ 15]
        print b[i-5: i + 15]

    def run(self):
        offset = 20
        consecutive_identic_traces_lim = 8
        diff = 1
        # entry = self.find_entry_point()
        opts = replace_input_placeholder(self.target_opts,
                                         self.valid_input_file,
                                         self.input_placeholder)
        t = QEMURunner(self.binary, input='', argv=[self.binary] + opts,
                       record_stdout=True)
        self.valid_trace = t.trace
        # print "Length valid trace: " + str(len(valid_trace))

        opts_list = []

        checksum_bytes = []
        headers_bytes = []
        unused_bytes = []

        last_traces = []
        malformed_inputs = sorted(os.listdir(self.malformed_input_dir))[59:]
        for input_byte_idx, malformed_input in enumerate(malformed_inputs):
            if input_byte_idx < 45:
                pass
                #continue
            print "Input byte: {}, input: {}".format(input_byte_idx, malformed_input)
            opts = replace_input_placeholder(self.target_opts,
                                             os.path.join(
                                                 self.malformed_input_dir,
                                                 malformed_input),
                                             self.input_placeholder)
            opts_list.append((self.binary, opts))

            t = run_qemu((self.binary, opts))
            assert len(t.trace) > 0
            identic = True
            unused = False
            if self.find_divergent_point(t.trace) == \
                    min(len(t.trace), len(self.valid_trace)):
                print(len(t.trace))
                print t.trace
                print t.crash_mode
                print t.returncode
                print t.stdout

                print(len(self.valid_trace))
                identic = False
                unused = True

            idx = 0
            # while identic and idx < len(last_traces):
            #     old_trace = last_traces[idx]
            #     i = 0
            #     while i + offset <= min(len(t.trace), len(old_trace)):
            #         s = set(t.trace[i:i+offset])
            #         ot = old_trace[i:i+offset]
            #         if len(s.intersection(ot)) < min(len(s), len(ot)) - diff:
            #             identic = False
            #         i += offset
            #     idx += 1
            for old_trace in last_traces:
                identic = identic and old_trace == t.trace

            if len(last_traces) == 0:
                identic = False
            if identic:
                last_traces.append(t.trace)
                print "found identical byte as before"
            else:
                if len(last_traces) > consecutive_identic_traces_lim:
                    print "last checksum found"
                    checksum_bytes += range(input_byte_idx - len(last_traces),
                                            input_byte_idx)
                elif input_byte_idx -1 not in unused_bytes:
                    headers_bytes += range(input_byte_idx - len(last_traces),
                                           input_byte_idx)
                if unused:
                    print "Found unused byte"
                    unused_bytes.append(input_byte_idx)
                last_traces = [t.trace]
            
            # if input_byte_idx == 4:
            #     aaaa = t.trace

            # import sys
            # if input_byte_idx == 8:
            #     tr = 0
            #     off = 0
            #     for j in range(0, len(t.trace), 10)[:-1]:
            #         if j + 10 < len(aaaa) and \
            #                 len(set(t.trace[j:j+10]).intersection(
            #                     aaaa[j:j+10])) >= len(set(
            #                         t.trace[j:j+10]))-1:
            #             sys.stdout.write(u"\u2009 ")
            #         else:
            #             sys.stdout.write(u"\u2588")
            #     sys.stdout.flush()

            if not unused:
                print 'Failing at address: 0x{:02x}'.format(t.trace[
                    self.find_divergent_point(t.trace)])

            if input_byte_idx + 1 == len(malformed_inputs):
                # last one
                input_byte_idx += 1
                if len(last_traces) > consecutive_identic_traces_lim:
                    print "last checksum found"
                    checksum_bytes += range(input_byte_idx - len(last_traces),
                                            input_byte_idx)
                elif input_byte_idx - 1 not in unused_bytes:
                    headers_bytes += range(input_byte_idx - len(last_traces),
                                           input_byte_idx)
                

        # result analysis

    #    pool = multiprocessing.Pool(1)
    #    out = zip(*pool.map(run_qemu, opts_list))
    #    for t in out:
    #       self.traces.append(self.add_trace_to_tree(t.trace, self.root_node))
    #        # Verify trace
    #        tt = self.traces[-1]
    #        ttt = []
    #        for n in tt[1:]:
    #            ttt = ttt + n.trace
    #        assert ttt == t.trace

        print "Location of checksums"
        print checksum_bytes

        print "Bytes considered as headers: " + str(len(headers_bytes))
        print headers_bytes

        print "Bytes considered as unknown: " + str(len(unused_bytes))
        print unused_bytes
