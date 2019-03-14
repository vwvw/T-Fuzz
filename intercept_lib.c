#include <string.h> 
#include <signal.h>
#include <stdbool.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <stdlib.h> 
#include <stdio.h>
#include <execinfo.h>
#include <unistd.h>
#include "zconf.h"

typedef voidpf (*alloc_func) OF((voidpf opaque, uInt items, uInt size));
typedef void   (*free_func)  OF((voidpf opaque, voidpf address));

typedef struct z_stream_s {
    z_const Bytef *next_in;     /* next input byte */
    uInt     avail_in;  /* number of bytes available at next_in */
    uLong    total_in;  /* total number of input bytes read so far */

    Bytef    *next_out; /* next output byte will go here */
    uInt     avail_out; /* remaining free space at next_out */
    uLong    total_out; /* total number of bytes output so far */

    z_const char *msg;  /* last error message, NULL if no error */
    struct internal_state FAR *state; /* not visible by applications */

    alloc_func zalloc;  /* used to allocate the internal state */
    free_func  zfree;   /* used to free the internal state */
    voidpf     opaque;  /* private data object passed to zalloc and zfree */

    int     data_type;  /* best guess about the data type: binary or text
                           for deflate, or the decoding state for inflate */
    uLong   adler;      /* Adler-32 or CRC-32 value of the uncompressed data */
    uLong   reserved;   /* reserved for future use */
} z_stream;


typedef int plugin_func();
unsigned long __REPLACE__FUNC_NAME__(z_stream* strm, int flush) {
    //recover program name
    FILE *fptr;
    char c;
    fptr = fopen("/proc/self/cmdline", "r");
    if (fptr == NULL)
    {
        printf("Cannot open file \n");
        exit(0);
    }

    // Read contents from file
    static char original_arguments [10][1280];
    int args_len [10];
    int ii = 0;
    int jj = 0;
    c = fgetc(fptr);
    while (c != EOF) {
        if (c == 0) {
            args_len[ii] = jj;
            ii++;
            jj = 0;
        } else {
            original_arguments[ii][jj] = c;
            jj++;
        }
        c = fgetc(fptr);
    }
    fclose(fptr);
    // find at which address binary is loaded.
    char buf[512];
    FILE *file;
    sprintf(buf, "/proc/%d/maps", getpid());
    file = fopen(buf, "rt");
    unsigned long load_address = 0;
    while (fgets(buf, 512, file)) {
        unsigned int pgoff, major, minor;
        unsigned long from, to, ino;
        char flags[4];
        char prog[500];
       int ret = sscanf(buf, "%lx-%lx %c%c%c%c %x %x:%x %lu %s", &from, &to, &flags[0],&flags[1],&flags[2],&flags[3], &pgoff, &major, &minor,&ino, prog);
        if (flags[2] == 'x' && strstr(prog, original_arguments[0]) != NULL){
           if (load_address != 0) {exit(2);}
           load_address = from;
        }
    }
    fclose(file);

    void* return_address = __builtin_return_address(0);
    unsigned long rel_ret_addr = (unsigned long)return_address - (unsigned long)load_address;
    const char *check_addr_str[__REPLACE_NUMBER_CHECK_ADDR__];
    __REPLACE_CHECK_ADDR__
    unsigned long check_addr[__REPLACE_NUMBER_CHECK_ADDR__];

    bool in_add = false;
    for(int k = 0; k < __REPLACE_NUMBER_CHECK_ADDR__; k++) {
        in_add = in_add || rel_ret_addr == strtoul(check_addr_str[k], NULL, 16);    
    }

    int ret = 0;
    if(in_add) {
        // return fuzzing data
        FILE *fout = fopen(original_arguments[__INPUT_ARG_NUMBER__ - 1], "rb");
        int cOut;

        int j = 0;
        int initial_offset = __COMPRESSED_DATA_OFFSET__;
        if (fout == NULL)
        {
            fprintf(stderr, "Error opening file!\n");
            exit(EXIT_FAILURE);
        }

        // push iterator to the point where we have data not yet sent
        cOut = fgetc(fout);
        while(cOut != EOF && j < strm->total_out + initial_offset) {
            j++;
            cOut = fgetc(fout);
        }
        int i = 0;
        while(cOut != EOF && i < strm->avail_out)
        {
            strm->next_out[i] = cOut;  //iterate buffer byte by byte
            i++;
            cOut = fgetc(fout);
        }
        if(cOut != EOF ) {
            strm->total_in += 1;
            strm->total_out += strm->avail_out;
            strm->avail_out = 0;
            strm->avail_in -= 1;
            strm->next_in += 1;
        } else {
            strm->total_out += i;
            strm->total_in += strm->avail_in;
            strm->avail_out -= i;
            strm->next_in += strm->avail_in;
            strm->avail_in = 0;
            ret = 1;
        }
        fclose(fout);
    } else {
        fprintf(stdout, "current check call: %p", (void*)rel_ret_addr);
        void* handle = dlopen("__REPLACE__ORIGINAL__LIBRARY__", RTLD_LAZY);
        if (handle == NULL) {
            fprintf(stderr, "Could not open plugin: %s\n", dlerror());
            return 1;
        }

        plugin_func* f = dlsym(handle, "__REPLACE__FUNC_NAME__");
        if (f == NULL) {
            fprintf(stderr, "Could not find plugin_func: %s\n", dlerror());
            return 1;
        }
        ret = f(strm, flush);
        if (dlclose(handle) != 0) {
            fprintf(stderr, "Could not close plugin: %s\n", dlerror());
            return 1;
        }
    }

    return ret;
}
