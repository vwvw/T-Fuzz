import subprocess
import os

mod_lib_name = "modified_intercept_lib_seed"



def patch_program(func_name, lib_name):
    with open('intercept_lib_seed.c', 'r') as file:
        filedata = file.read()
        filedata = filedata.replace('__REPLACE__FUNC_NAME__', func_name).replace(
                '__REPLACE__ORIGINAL__LIBRARY__', lib_name)
    with open(mod_lib_name + '.c', 'w') as file:
        file.write(filedata)

    # compile library
    subprocess.call(['gcc', '-w', '-g', '-fPIC', '-c', mod_lib_name + '.c'])
    subprocess.call(['gcc', '-w', '-g', '-shared', '-o',
        mod_lib_name + '.so', mod_lib_name + '.o', '-ldl'])

patch_program('inflate', '/home/nicolasbadoux/aa/lib/libz.so')
my_env = os.environ.copy()
my_env["LD_PRELOAD"] = "/home/nicolasbadoux/T-Fuzz/modified_intercept_lib_seed.so"
program = "/home/nicolasbadoux/T-Fuzz/evaluation/convert/bin2/png_only_magick"
seed_file = "/home/nicolasbadoux/T-Fuzz/seed.png"
args = [program, "convert", seed_file, "out.jpg"]
output = subprocess.check_output(args, env=my_env)

byte_s = [int(char, 16) for char in output.split(' ') if len(char) > 0]

i = os.path.getsize(seed_file)
print i
offset = 1
while i > 1:
    offset *= 10;
    i /= 10.0

if os.path.getsize(seed_file) + 500 > offset:
    offset = 1000

print offset
f = open(seed_file, 'ab')
seed_size = os.path.getsize(seed_file)
while seed_size < offset:
    f.write(b'\x00')
    seed_size+=1


def to_bytes(n, length, endianess='big'):
    h = '%x' % n
    s = ('0'*(len(h) % 2) + h).zfill(length*2).decode('hex')
    return s if endianess == 'big' else s[::-1]
for b in byte_s:
    f.write(to_bytes(b, 1))
f.close()
