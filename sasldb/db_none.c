/* db_none.c--provides linkage for systems which lack a backend db lib
 * Rob Siemborski
 * Rob Earhart
 * $Id: db_none.c,v 1.1.2.2 2001/07/26 22:12:14 rjs3 Exp $
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
#include "sasldb.h"

/* This just exists to provide these symbols on systems where configure
 * couldn't find a database library. */

static int getsecret(const sasl_utils_t *utils __attribute__((unused)),
		     sasl_conn_t *context __attribute__((unused)),
		     const char *auth_identity __attribute__((unused)),
		     const char *realm __attribute__((unused)),
		     sasl_secret_t ** secret __attribute__((unused))) 
{
    return SASL_FAIL;
}

static int putsecret(const sasl_utils_t *utils __attribute__((unused)),
		     sasl_conn_t *context __attribute__((unused)),
		     const char *auth_identity __attribute__((unused)),
		     const char *realm __attribute__((unused)),
		     const sasl_secret_t *secret __attribute__((unused))) 
{
    return SASL_FAIL;
}

sasl_server_getsecret_t *_sasl_db_getsecret = &getsecret;
sasl_server_putsecret_t *_sasl_db_putsecret = &putsecret;

int _sasl_check_db(const sasl_utils_t *utils __attribute__((unused)),
		   sasl_conn_t *conn __attribute__((unused)))
{
    return SASL_FAIL;
}

sasldb_handle _sasldb_getkeyhandle(const sasl_utils_t *utils __attribute__((unused)),
                                   sasl_conn_t *conn __attribute__((unused))) 
{
    return NULL;
}

int _sasldb_getnextkey(const sasl_utils_t *utils __attribute__((unused)),
                       sasldb_handle handle __attribute__((unused)),
		       char *out __attribute__((unused)),
                       const size_t max_out __attribute__((unused)),
		       size_t *out_len __attribute__((unused))) 
{
    return SASL_FAIL;
}

int _sasldb_releasekeyhandle(const sasl_utils_t *utils __attribute__((unused)),
                             sasldb_handle handle __attribute__((unused)))  
{
    return SASL_FAIL;
}
