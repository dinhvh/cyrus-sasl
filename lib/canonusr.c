/* canonusr.c - user canonicalization support
 * Rob Siemborski
 */
/* 
 * Copyright (c) 2001 Carnegie Mellon University.  All rights reserved.
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
#include <sasl.h>
#include <string.h>
#include <ctype.h>
#include <prop.h>
#include "saslint.h"

/* default behavior:
 *                   eliminate leading & trailing whitespace,
 *                   null-terminate, and get into the outparams */
/* Also does auxprop lookups once username is canonoicalized */
/* a zero ulen or alen indicates that it is strlen(value) */
int _sasl_canon_user(sasl_conn_t *conn,
                     const char *user, unsigned ulen,
                     const char *authid, unsigned alen,
                     unsigned flags,
                     sasl_out_params_t *oparams)
{
    const char *begin_u, *begin_a;
    sasl_server_conn_t *sconn = NULL;
    int u_apprealm = 0, a_apprealm = 0;
    sasl_server_canon_user_t *cuser_cb;
    int result;
    void *cuser_ctx;
    unsigned i;

    if(!conn) return SASL_BADPARAM;    

    if(conn->type == SASL_CONN_SERVER) sconn = (sasl_server_conn_t *)conn;

    /* check to see if we have been overridden by the application */
    result = _sasl_getcallback(conn, SASL_CB_CANON_USER,
			       &cuser_cb, &cuser_ctx);
    if(result == SASL_OK && cuser_cb) {
	const size_t canon_buf_size = 256;
	
	/* Allocate the memory */
	if(!conn->user_buf) conn->user_buf = sasl_ALLOC(canon_buf_size);
	else conn->user_buf = sasl_REALLOC(conn->user_buf, canon_buf_size);
    
	if(!conn->user_buf) return SASL_NOMEM;
	
	if(!conn->authid_buf) conn->authid_buf = sasl_ALLOC(canon_buf_size);
	else conn->authid_buf = sasl_REALLOC(conn->authid_buf, canon_buf_size);

	if(!conn->authid_buf) {
	    sasl_FREE(conn->user_buf);
	    conn->user_buf = NULL;
	    return SASL_NOMEM;
	}
	
	result = cuser_cb(conn, cuser_ctx,
			user, ulen, authid, alen,
			flags, (conn->type == SASL_CONN_SERVER ?
				((sasl_server_conn_t *)conn)->user_realm :
				NULL),
			conn->user_buf, canon_buf_size, &ulen,
			conn->authid_buf, canon_buf_size, &alen);

	if (result != SASL_OK) return result;

	goto done;
    }
    
    if(!user || !authid || !oparams) return SASL_BADPARAM;

    /* FIXME: Plugin Support (also: how does this work with auxpropness?) */
    if(!ulen) ulen = strlen(user);
    if(!alen) alen = strlen(authid);

    /* Strip User ID */
    for(i=0;isspace(user[i]) && i<ulen;i++);
    begin_u = &(user[i]);
    if(i>0) ulen -= i;

    for(;isspace(begin_u[ulen-1]) && ulen > 0; ulen--);
    if(begin_u == &(user[ulen])) return SASL_FAIL;

    /* Strip Auth ID */
    for(i=0;isspace(authid[i]) && i<alen;i++);
    begin_a = &(authid[i]);
    if(i>0) alen -= i;

    for(;isspace(begin_a[alen-1]) && alen > 0; alen--);
    if(begin_a == &(user[alen])) return SASL_FAIL;

    /* Need to append realm if necessary (see sasl.h) */
    if(sconn && sconn->user_realm && !strchr(user, '@')) {
	u_apprealm = strlen(sconn->user_realm) + 1;
    }
    if(sconn && sconn->user_realm && !strchr(authid, '@')) {
	a_apprealm = strlen(sconn->user_realm) + 1;
    }
    
    /* Now allocate the memory */
    if(!conn->user_buf) conn->user_buf = sasl_ALLOC(ulen + u_apprealm + 1);
    else conn->user_buf = sasl_REALLOC(conn->user_buf, ulen + u_apprealm + 1);
    
    if(!conn->user_buf) return SASL_NOMEM;
    
    if(!conn->authid_buf) conn->authid_buf = sasl_ALLOC(alen + a_apprealm + 1);
    else conn->authid_buf = sasl_REALLOC(conn->authid_buf, alen + a_apprealm + 1);

    if(!conn->authid_buf) {
	sasl_FREE(conn->user_buf);
	conn->user_buf = NULL;
	return SASL_NOMEM;
    }

    /* Now copy! */
    memcpy(conn->user_buf, begin_u, ulen);
    if(u_apprealm) {
	conn->user_buf[ulen] = '@';
	memcpy(&(conn->user_buf[ulen+1]), sconn->user_realm, u_apprealm-1);
    }
    conn->user_buf[ulen + u_apprealm] = '\0';
    
    memcpy(conn->authid_buf, begin_a, alen);
    if(a_apprealm) {
	conn->authid_buf[alen] = '@';
	memcpy(&(conn->user_buf[alen+1]), sconn->user_realm, a_apprealm-1);
    }
    conn->authid_buf[alen + a_apprealm] = '\0';

    done:

    /* finally, do auxprop lookups (server only) */
    if(conn->type == SASL_CONN_SERVER) {
	sasl_server_conn_t *sconn = (sasl_server_conn_t *)conn;

	_sasl_auxprop_lookup(sconn->sparams, 0, user, 0);
    }

    oparams->user = conn->user_buf;
    oparams->ulen = ulen;
    oparams->authid = conn->authid_buf;
    oparams->alen = alen;

    return SASL_OK;
}
