/* db_berkeley.c--SASL berkeley db interface
 * Rob Siemborski
 * Tim Martin
 * $Id: allockey.c,v 1.1.2.1 2001/07/25 17:37:42 rjs3 Exp $
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

#include <sys/stat.h>
#include <stdlib.h>
#include <assert.h>
#include "sasldb.h"

/*
 * Construct a key
 *
 */
int _sasldb_alloc_key(const sasl_utils_t *utils,
		      const char *auth_identity,
		      const char *realm,
		      const char *propName,
		      char **key,
		      size_t *key_len)
{
  size_t auth_id_len, realm_len, prop_len;
  
  assert(utils && auth_identity && realm && propName && key && key_len);

  auth_id_len = strlen(auth_identity);
  realm_len = strlen(realm);
  prop_len = strlen(propName);

  *key_len = auth_id_len + realm_len + prop_len + 2;
  *key = utils->malloc(*key_len);
  if (! *key)
    return SASL_NOMEM;
  memcpy(*key, auth_identity, auth_id_len);
  (*key)[auth_id_len] = '\0';
  memcpy(*key + auth_id_len + 1, realm, realm_len);
  (*key)[auth_id_len + realm_len + 1] = '\0';
  memcpy(*key + auth_id_len + realm_len + 2, propName, prop_len);

  return SASL_OK;
}
