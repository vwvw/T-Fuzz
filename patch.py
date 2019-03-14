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
mod_lib_name = "modified_intercept_lib"


#def taint_analysis():
#    args = ["/home/nicolasbadoux/valgrind-3.14.0/build/bin/valgrind",
#            "--tool=taintgrind",
#            "--file-filter=" + input_file,
#            "--taint-start=" + str(hex(chksm_start)),
#            "--taint-len=" + str(hex(chksm_len)),
#            program] + options
#    print args
#    proc = subprocess.Popen(args, stderr=subprocess.PIPE)
#    print "Done with taintgrind"
#    function_executed = []
#
#    r = re.compile(r"^(?P<addr>0x[0-9a-fA-F]+): (?P<func_name>.+?)( (| "
#                   "(?P<inst>[^A-Z]*?) )?(| (?P<operation>.+) )?| "
#                   "(?P<value>0x[0-9a-fA-F]+))? | (((?P<dest>.+?) <-( "
#                   "(?P<src>.+?))?)|(?P<taint>.+?)?)\n$")
#    for i, l in enumerate(proc.stderr.readlines()):
#        res = r.match(l)
#        if res:
#            func_name = res.group("func_name").split(" ")[0]
#            function_executed.append(func_name)
#
#    coll = Counter(function_executed)
#    for i in coll:
#        print i + " " + str(coll[i])
#    # TODO need to do some processing on an execution trace to get the function name
#
#    check_func = coll.most_common(0)[0]
#    return check_func
#

def patch_program(check_addr, func_name, lib_name):
    with open('intercept_lib.c', 'r') as file:
        filedata = file.read()
        filedata = filedata.replace('__REPLACE__FUNC_NAME__', func_name).replace(
                '__REPLACE__ORIGINAL__LIBRARY__', lib_name).replace(
                        '__INPUT_ARG_NUMBER__', "3").replace(
                        '__COMPRESSED_DATA_OFFSET__', "1000")
        filedata = filedata.replace('__REPLACE_NUMBER_CHECK_ADDR__', str(len(check_addr)))
        c_addr_str = ""
        for i, a in enumerate(check_addr):
            c_addr_str += "check_addr_str[" + str(i) + '] = "' + a + '";\n'
        filedata = filedata.replace('__REPLACE_CHECK_ADDR__', c_addr_str)
    with open(mod_lib_name + '.c', 'w') as file:
        file.write(filedata)

    # compile library
    subprocess.call(['gcc', '-g', '-fPIC', '-c', mod_lib_name + '.c'])
    subprocess.call(['gcc', '-g', '-shared', '-o',
        mod_lib_name + '.so', mod_lib_name + '.o', '-ldl'])

def run(pr):
    subprocess.call(pr, env={'LD_PRELOAD': './' + mod_lib_name + '.so'})

patch_program(['2aaaa06af2fd'], 'inflate', '/lib/x86_64-linux-gnu/libz.so.1')
