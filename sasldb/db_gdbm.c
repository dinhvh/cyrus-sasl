/* db_gdbm.c--SASL gdbm interface
 * Rob Siemborski
 * Rob Earhart
 * $Id: db_gdbm.c,v 1.1.2.1 2001/07/17 21:48:48 rjs3 Exp $
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
#include <gdbm.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <assert.h>
#include "sasldb.h"

static int db_ok = 0;

/* This provides a version of _sasl_db_getsecret and
 * _sasl_db_putsecret which work with gdbm. */

static int alloc_key(const sasl_utils_t *utils,
		     const char *auth_identity,
		     const char *realm,
		     char **key,
		     size_t *key_len)
{
  size_t auth_id_len, realm_len;

  assert(auth_identity && realm && key && key_len);

  auth_id_len = strlen(auth_identity);
  realm_len = strlen(realm);
  *key_len = auth_id_len + realm_len + 1;
  *key = utils->malloc(*key_len);
  if (! *key)
    return SASL_NOMEM;
  memcpy(*key, auth_identity, auth_id_len);
  (*key)[auth_id_len] = '\0';
  memcpy(*key + auth_id_len + 1, realm, realm_len);

  return SASL_OK;
}

static int
getsecret(const sasl_utils_t *utils,
	  sasl_conn_t *conn,
	  const char *auth_identity,
	  const char *realm,
	  sasl_secret_t ** secret)
{
  int result = SASL_OK;
  char *key;
  size_t key_len;
  GDBM_FILE db;
  datum gkey, gvalue;  
  void *cntxt;
  sasl_getopt_t *getopt;
  const char *path = SASL_DB_PATH;

  if (!auth_identity || !secret || !realm || !db_ok)
    return SASL_FAIL;

  result = alloc_key(utils, auth_identity, realm, &key, &key_len);
  if (result != SASL_OK)
    return result;

  if (utils->getcallback(conn, SASL_CB_GETOPT,
                        &getopt, &cntxt) == SASL_OK) {
      const char *p;
      if (getopt(cntxt, NULL, "sasldb_path", &p, NULL) == SASL_OK 
	  && p != NULL && *p != 0) {
          path = p;
      }
  }
  db = gdbm_open((char *)path, 0, GDBM_READER, S_IRUSR | S_IWUSR, NULL);
  if (! db) {
    result = SASL_FAIL;
    goto cleanup;
  }
  gkey.dptr = key;
  gkey.dsize = key_len;
  gvalue = gdbm_fetch(db, gkey);
  gdbm_close(db);
  if (! gvalue.dptr) {
    result = SASL_NOUSER;
    goto cleanup;
  }
  *secret = utils->malloc(sizeof(sasl_secret_t)
			  + gvalue.dsize
			  + 1);
  if (! *secret) {
    result = SASL_NOMEM;
    free(gvalue.dptr);
    goto cleanup;
  }
  (*secret)->len = gvalue.dsize;
  memcpy(&(*secret)->data, gvalue.dptr, gvalue.dsize);
  (*secret)->data[(*secret)->len] = '\0'; /* sanity */
  /* Note: not sasl_FREE!  This is memory allocated by gdbm,
   * which is using libc malloc/free. */
  free(gvalue.dptr);

 cleanup:
  utils->free(key);

  return result;
}

static int
putsecret(const sasl_utils_t *utils,
	  sasl_conn_t *conn,
	  const char *auth_identity,
	  const char *realm,
	  const sasl_secret_t * secret)
{
  int result = SASL_OK;
  char *key;
  size_t key_len;
  GDBM_FILE db;
  datum gkey;
  void *cntxt;
  sasl_getopt_t *getopt;
  const char *path = SASL_DB_PATH;

  if (!auth_identity || !realm)
      return SASL_FAIL;

  result = alloc_key(utils, auth_identity, realm, &key, &key_len);
  if (result != SASL_OK)
    return result;

  if (utils->getcallback(conn, SASL_CB_GETOPT,
			 &getopt, &cntxt) == SASL_OK) {
      const char *p;
      if (getopt(cntxt, NULL, "sasldb_path", &p, NULL) == SASL_OK 
	  && p != NULL && *p != 0) {
          path = p;
      }
  }
  db = gdbm_open((char *)path, 0, GDBM_WRCREAT, S_IRUSR | S_IWUSR, NULL);
  if (! db) {
      utils->log(NULL, SASL_LOG_ERR,
		"SASL error opening password file. Do you have write permissions?\n");
    result = SASL_FAIL;
    goto cleanup;
  }
  gkey.dptr = key;
  gkey.dsize = key_len;
  if (secret) {
    datum gvalue;
    gvalue.dptr = (char *)&secret->data;
    gvalue.dsize = secret->len;
    if (gdbm_store(db, gkey, gvalue, GDBM_REPLACE))
      result = SASL_FAIL;
  } else {
    if (gdbm_delete(db, gkey))
      result = SASL_NOUSER;
  }
  gdbm_close(db);

 cleanup:
  utils->free(key);

  return result;
}

sasl_server_getsecret_t *_sasl_db_getsecret = &getsecret;
sasl_server_putsecret_t *_sasl_db_putsecret = &putsecret;

int _sasl_check_db(const sasl_utils_t *utils)
{
    const char *path = SASL_DB_PATH;
    int ret;
    void *cntxt;
    sasl_getopt_t *getopt;
    sasl_verifyfile_t *vf;

    if (utils->getcallback(NULL, SASL_CB_GETOPT,
			   &getopt, &cntxt) == SASL_OK) {
	const char *p;
	if (getopt(cntxt, NULL, "sasldb_path", &p, NULL) == SASL_OK 
	    && p != NULL && *p != 0) {
	    path = p;
	}
    }

    ret = utils->getcallback(NULL, SASL_CB_VERIFYFILE,
			     &vf, &cntxt);
    if(ret != SASL_OK) return ret;

    ret = vf(cntxt, path, SASL_VRFY_PASSWD);
						       path, SASL_VRFY_PASSWD);
    if (ret == SASL_OK) {
	db_ok = 1;
    }

    if (ret == SASL_OK || ret == SASL_CONTINUE) {
	return SASL_OK;
    } else {
	return ret;
    }
}
