/* dlopen.c--Unix dlopen() dynamic loader interface
 * Rob Siemborski
 * Rob Earhart
 * $Id: staticopen.c,v 1.1.2.2 2001/07/06 15:22:56 rjs3 Exp $
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
#include <stdlib.h>
#include <limits.h>
#include <sys/param.h>
#include <sasl.h>
#include "saslint.h"
#include "staticopen.h"

const int _is_sasl_server_static = 1;

/* gets the list of mechanisms */
int _sasl_get_mech_list(const char *entryname,
			const sasl_callback_t *getpath_cb
			  __attribute__((unused)),
			const sasl_callback_t *verifyfile_cb
			  __attribute__((unused)),
			int (*add_plugin)(void *,void *))
{
    int result;

    enum Sasl_conn_type type;

    /* What type of plugin are we looking for? */
    if(!strcmp(entryname, "sasl_server_plug_init")) {
	type = SASL_CONN_SERVER;
    } else if (!strcmp(entryname, "sasl_client_plug_init")) {
	type = SASL_CONN_CLIENT;
    } else if (!strcmp(entryname, "sasl_auxprop_plug_init")) {
	/* NOT IMPLEMENTED */
	return SASL_OK;
    } else if (!strcmp(entryname, "sasl_canonuser_init")) {
	/* NOT IMPLEMENTED */
	return SASL_OK;
    } else {
	/* What are we looking for then? */
	return SASL_FAIL;
    }

#ifdef STATIC_ANONYMOUS
    if(type == SASL_CONN_SERVER) {
	result = (*add_plugin)(SPECIFIC_SERVER_PLUG_INIT( anonymous ), NULL);
    } else {
	result = (*add_plugin)(SPECIFIC_CLIENT_PLUG_INIT( anonymous ), NULL);
    }
    if(result != SASL_OK) return result;
#endif

#ifdef STATIC_CRAMMD5
    if(type == SASL_CONN_SERVER) {
	result = (*add_plugin)(SPECIFIC_SERVER_PLUG_INIT( crammd5 ), NULL);
    } else {
	result = (*add_plugin)(SPECIFIC_CLIENT_PLUG_INIT( crammd5 ), NULL);
    }
    if(result != SASL_OK) return result;
#endif

#ifdef STATIC_DIGESTMD5
    if(type == SASL_CONN_SERVER) {
	result = (*add_plugin)(SPECIFIC_SERVER_PLUG_INIT( digestmd5 ), NULL);
    } else {
	result = (*add_plugin)(SPECIFIC_CLIENT_PLUG_INIT( digestmd5 ), NULL);
    }
    if(result != SASL_OK) return result;
#endif

#ifdef STATIC_GSSAPIV2
    if(type == SASL_CONN_SERVER) {
	result = (*add_plugin)(SPECIFIC_SERVER_PLUG_INIT( gssapiv2 ), NULL);
    } else {
	result = (*add_plugin)(SPECIFIC_CLIENT_PLUG_INIT( gssapiv2 ), NULL);
    }
    if(result != SASL_OK) return result;
#endif

#ifdef STATIC_KERBEROS4
    if(type == SASL_CONN_SERVER) {
	result = (*add_plugin)(SPECIFIC_SERVER_PLUG_INIT( kerberos4 ), NULL);
    } else {
	result = (*add_plugin)(SPECIFIC_CLIENT_PLUG_INIT( kerberos4 ), NULL);
    }
    if(result != SASL_OK) return result;
#endif

#ifdef STATIC_LOGIN
    if(type == SASL_CONN_SERVER) {
	result = (*add_plugin)(SPECIFIC_SERVER_PLUG_INIT( login ), NULL);
    } else {
	result = (*add_plugin)(SPECIFIC_CLIENT_PLUG_INIT( login ), NULL);
    }
    if(result != SASL_OK) return result;
#endif

#ifdef STATIC_PLAIN
    if(type == SASL_CONN_SERVER) {
	result = (*add_plugin)(SPECIFIC_SERVER_PLUG_INIT( plain ), NULL);
    } else {
	result = (*add_plugin)(SPECIFIC_CLIENT_PLUG_INIT( plain ), NULL);
    }
    if(result != SASL_OK) return result;
#endif

#ifdef STATIC_SRP
    if(type == SASL_CONN_SERVER) {
	result = (*add_plugin)(SPECIFIC_SERVER_PLUG_INIT( srp ), NULL);
    } else {
	result = (*add_plugin)(SPECIFIC_CLIENT_PLUG_INIT( srp ), NULL);
    }
    if(result != SASL_OK) return result;
#endif

    return SASL_OK;
}



/* loads a single mechanism (or rather, fails to) */
int _sasl_get_plugin(const char *file __attribute__((unused)),
                     const char *entryname __attribute__((unused)),
                     const sasl_callback_t *verifyfile_cb
		       __attribute__((unused)),
                     void **entrypointptr __attribute__((unused)),
                     void **libraryptr __attribute__((unused))) 
{
    return SASL_FAIL;
}

int
_sasl_done_with_plugin(void *plugin __attribute__((unused))) 
{
    return SASL_OK;
}
