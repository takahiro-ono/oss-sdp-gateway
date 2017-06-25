/*
 * This source file is a subset from the bstring string library.  This code was
 * written by Paul Hsieh in 2002-2015, and is covered by the BSD open source
 * license and the GPL. Refer to the accompanying documentation for details
 * on usage and license.
 */

#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "bstr_lib.h"


/* Compute the snapped size for a given requested size.  By snapping to powers
   of 2 like this, repeated reallocations are avoided. */
static int snapUpSize (int i) {
    if (i < 8) {
        i = 8;
    } else {
        unsigned int j;
        j = (unsigned int) i;

        j |= (j >>  1);
        j |= (j >>  2);
        j |= (j >>  4);
        j |= (j >>  8);     /* Ok, since int >= 16 bits */
#if (UINT_MAX != 0xffff)
        j |= (j >> 16);     /* For 32 bit int systems */
#if (UINT_MAX > 0xffffffffUL)
        j |= (j >> 32);     /* For 64 bit int systems */
#endif
#endif
        /* Least power of two greater than i */
        j++;
        if ((int) j >= i) i = (int) j;
    }
    return i;
}



bstring bstr_cpy (const_bstring b) {
    bstring b0;
    int i,j;

    /* Attempted to copy an invalid string? */
    if (b == NULL || b->slen < 0 || b->data == NULL) return NULL;

    b0 = (bstring) malloc (sizeof (struct tagbstring));
    if (b0 == NULL) {
        /* Unable to allocate memory for string header */
        return NULL;
    }

    i = b->slen;
    j = snapUpSize (i + 1);

    b0->data = (unsigned char *) malloc (j);
    if (b0->data == NULL) {
        j = i + 1;
        b0->data = (unsigned char *) malloc (j);
        if (b0->data == NULL) {
            /* Unable to allocate memory for string data */
            free (b0);
            return NULL;
        }
    }

    b0->mlen = j;
    b0->slen = i;

    if (i) memcpy ((char *) b0->data, (char *) b->data, i);
    b0->data[b0->slen] = (unsigned char) '\0';

    return b0;
}


int bstr_destroy (bstring b) {
    if (b == NULL || b->slen < 0 || b->mlen <= 0 || b->mlen < b->slen ||
        b->data == NULL)
        return BSTR_ERR;

    free (b->data);

    /* In case there is any stale usage, there is one more chance to
       notice this error. */

    b->slen = -1;
    b->mlen = -__LINE__;
    b->data = NULL;

    free (b);
    return BSTR_OK;
}


bstring bstr_from_cstr (const char * str) {
    bstring b;
    int i;
    size_t j;

    if (str == NULL) return NULL;
    j = (strlen) (str);
    i = snapUpSize ((int) (j + (2 - (j != 0))));
    if (i <= (int) j) return NULL;

    b = (bstring) malloc (sizeof (struct tagbstring));
    if (NULL == b) return NULL;
    b->slen = (int) j;
    if (NULL == (b->data = (unsigned char *) malloc (b->mlen = i))) {
        free (b);
        return NULL;
    }

    memcpy (b->data, str, j+1);
    return b;
}

int bstr_cmp (const_bstring b0, const_bstring b1) {
    int i, v, n;

    if (b0 == NULL || b1 == NULL || b0->data == NULL || b1->data == NULL ||
        b0->slen < 0 || b1->slen < 0) return SHRT_MIN;
    n = b0->slen; if (n > b1->slen) n = b1->slen;
    if (b0->slen == b1->slen && (b0->data == b1->data || b0->slen == 0))
        return BSTR_OK;

    for (i = 0; i < n; i ++) {
        v = ((char) b0->data[i]) - ((char) b1->data[i]);
        if (v != 0) return v;
        if (b0->data[i] == (unsigned char) '\0') return BSTR_OK;
    }

    if (b0->slen > n) return 1;
    if (b1->slen > n) return -1;
    return BSTR_OK;
}

