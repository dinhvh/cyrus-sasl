/* Generic SASL plugin utility functions
 * Rob Siemborski
 * $Id: plugin_common.c,v 1.1.2.5 2001/06/18 18:43:36 rjs3 Exp $
 */
/* 
 * Copyright (c) 2000 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <config.h>
#ifdef WIN32
# include <winsock.h>
#else
# include <sys/param.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>
# include <netdb.h>
#endif /* WIN32 */
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#include <sasl.h>
#include <saslutil.h>
#include <saslplug.h>

#include <errno.h>
#include <ctype.h>
#include <sys/uio.h>

#include "plugin_common.h"

/* FIXME: This only parses IPV4 addresses */
int _plug_ipfromstring(const char *addr, struct sockaddr_in *out) 
{
    int i;
    unsigned int val = 0;
    unsigned int port;
    
    if(!addr || !out) return SASL_BADPARAM;

    /* Parse the address */
    for(i=0; i<4 && *addr && *addr != ';'; i++) {
	int inval;
	
	inval = atoi(addr);
	if(inval < 0 || inval > 255) return SASL_BADPARAM;

	val = val << 8;
	val |= inval;
	
        for(;*addr && *addr != '.' && *addr != ';'; addr++)
	    if(!isdigit((int)(*addr))) return SASL_BADPARAM;

	/* skip the separator */
	addr++;
    }
    
    /* We have a bad ip address if we have less than 4 octets, or
     * if we didn't just skip a semicolon */
    if(i!=4 || *(addr-1) != ';') return SASL_BADPARAM;
    
    port = atoi(addr);

    /* Ports can only be 16 bits in IPV4 */
    if((port & 0xFFFF) != port) return SASL_BADPARAM;
        
    for(;*addr;addr++)
	if(!isdigit((int)(*addr))) return SASL_BADPARAM;
    
    memset(out, 0, sizeof(struct sockaddr_in));
    out->sin_addr.s_addr = val;
    out->sin_port = port;

    return SASL_OK;
}

int _plug_iovec_to_buf(const sasl_utils_t *utils, const struct iovec *vec,
		       unsigned numiov, buffer_info_t **output) 
{
    unsigned i;
    int ret;
    buffer_info_t *out;
    char *pos;

    if(!vec || !output) return SASL_BADPARAM;

    if(!(*output)) {
	*output = utils->malloc(sizeof(buffer_info_t));
	if(!*output) return SASL_NOMEM;
	memset(*output,0,sizeof(buffer_info_t));
    }

    out = *output;
    
    out->curlen = 0;
    for(i=0; i<numiov; i++)
	out->curlen += vec[i].iov_len;

    ret = _plug_buf_alloc(utils, &out->data, &out->reallen, out->curlen);

    if(ret != SASL_OK) return SASL_NOMEM;
    
    memset(out->data, 0, out->reallen);
    pos = out->data;
    
    for(i=0; i<numiov; i++) {
	memcpy(pos, vec[i].iov_base, vec[i].iov_len);
	pos += vec[i].iov_len;
    }

    return SASL_OK;
}

/* Basically a conditional call to realloc(), if we need more */
int _plug_buf_alloc(const sasl_utils_t *utils, char **rwbuf,
		    unsigned *curlen, unsigned newlen) 
{
    if(!rwbuf || !curlen) return SASL_BADPARAM;

    if(!(*rwbuf)) {
	*rwbuf = utils->malloc(newlen);
	if (*rwbuf == NULL) {
	    *curlen = 0;
	    return SASL_NOMEM;
	}
	*curlen = newlen;
    } else if(*rwbuf && *curlen < newlen) {
	size_t needed = 2*(*curlen);

	while(needed < newlen)
	    needed *= 2;

	*rwbuf = utils->realloc(*rwbuf, needed);
	if (*rwbuf == NULL) {
	    *curlen = 0;
	    return SASL_NOMEM;
	}
	*curlen = needed;
    } 

    return SASL_OK;
}
