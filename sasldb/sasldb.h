/* saslint.h - internal SASL library definitions
 * Rob Siemborski
 * Tim Martin
 * $Id: sasldb.h,v 1.1.2.2 2001/07/24 19:16:44 rjs3 Exp $
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

#ifndef SASLDB_H
#define SASLDB_H

#include "sasl.h"
#include "saslplug.h"

/* Get a secret from sasldb for the given authid/realm */
typedef int sasl_server_getsecret_t(const sasl_utils_t *utils,
				    sasl_conn_t *context,
				    const char *auth_identity,
				    const char *realm,
				    sasl_secret_t ** secret);

/* Put a secret into sasldb for the given authid/realm */
/* A NULL secret here means to delete the key */
typedef int sasl_server_putsecret_t(const sasl_utils_t *utils,
				    sasl_conn_t *context,
				    const char *auth_identity,
				    const char *realm,
				    const sasl_secret_t * secret);

extern sasl_server_getsecret_t *_sasl_db_getsecret;
extern sasl_server_putsecret_t *_sasl_db_putsecret;

int _sasl_check_db(const sasl_utils_t *utils);

#endif /* SASLDB_H */
