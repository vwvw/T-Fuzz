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
    int ret = 0;
    Bytef* rta = strm->next_out;
    uInt old = strm->avail_out;
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
    int aay=0;
    while(aay < old) {
        fprintf(stdout, " %x", rta[aay]);
        aay++;
    }
    printf("\n");

    return ret;
}
