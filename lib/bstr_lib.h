/*
 * This source file is a subset from the bstring string library.  This code was
 * written by Paul Hsieh in 2002-2015, and is covered by the BSD open source
 * license and the GPL. Refer to the accompanying documentation for details
 * on usage and license.
 */

/*
 * bstr_lib.h
 *
 * This file is the interface for the core bstring functions.
 */

#ifndef BSTRLIB_INCLUDE
#define BSTRLIB_INCLUDE

// #include <stdarg.h>
// #include <string.h>
#include <limits.h>
// #include <ctype.h>

#define BSTR_ERR (-1)
#define BSTR_OK (0)

typedef struct tagbstring * bstring;
typedef const struct tagbstring * const_bstring;

struct tagbstring {
	int mlen;
	int slen;
	unsigned char * data;
};

extern bstring bstr_from_cstr (const char * str);
extern bstring bstr_cpy (const_bstring b1);
extern int bstr_destroy (bstring b);
extern int bstr_cmp (const_bstring b0, const_bstring b1);
#define bstr_length(b)          (((b) == (void *)0 || (b)->slen < 0) ? 0 : ((b)->slen))
#define bstr_data(b)            (((b) == (void *)0 || (b)->data == (void*)0) ? (char *)0 : ((char *)(b)->data))

#endif