import re
from collections import Counter
import subprocess
import tempfile

tt_out = tempfile.mkstemp()
input_file = "/home/nicolasbadoux/T-Fuzz/png/all_gray.png"
chksm_start = 41
chksm_end = 64
chksm_len = chksm_end - chksm_start
program = "convert"
options = [input_file, "hello.jpg"]


def taint_analysis():
    args = ["/home/nicolasbadoux/valgrind-3.14.0/build/bin/valgrind",
            "--tool=taintgrind",
            "--file-filter=" + input_file,
            "--taint-start=" + str(hex(chksm_start)),
            "--taint-len=" + str(hex(chksm_len)),
            program] + options
    print args
    proc = subprocess.Popen(args, stderr=subprocess.PIPE)
    print "Done with taintgrind"
    function_executed = []

    r = re.compile(r"^(?P<addr>0x[0-9a-fA-F]+): (?P<func_name>.+?)( (| "
                   "(?P<inst>[^A-Z]*?) )?(| (?P<operation>.+) )?| "
                   "(?P<value>0x[0-9a-fA-F]+))? | (((?P<dest>.+?) <-( "
                   "(?P<src>.+?))?)|(?P<taint>.+?)?)\n$")
    for i, l in enumerate(proc.stderr.readlines()):
        res = r.match(l)
        if res:
            func_name = res.group("func_name").split(" ")[0]
            function_executed.append(func_name)

    coll = Counter(function_executed)
    for i in coll:
        print i + " " + str(coll[i])
