/* saslint.h - internal SASL library definitions
 * Tim Martin
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

#ifndef SASLINT_H
#define SASLINT_H

#include <config.h>
#include "sasl.h"
#include "saslplug.h"

extern int _sasl_common_init(void);

/* dlopen.c */
extern int _sasl_get_mech_list(const char *entryname,
			       const sasl_callback_t *getpath_callback,
			       const sasl_callback_t *verifyfile_callback,
			       int (*add_plugin)(void *,void *));
extern int _sasl_get_plugin(const char *file,
			    const char *entryname,
			    const sasl_callback_t *verifyfile_callback,
			    void **entrypoint,
			    void **library);

extern const sasl_callback_t *
_sasl_find_getpath_callback(const sasl_callback_t *callbacks);

extern const sasl_callback_t *
_sasl_find_verifyfile_callback(const sasl_callback_t *callbacks);

extern int _sasl_done_with_plugin(void *plugin);

extern void (*_sasl_client_cleanup_hook)(void);
extern void (*_sasl_server_cleanup_hook)(void);

extern int (*_sasl_client_idle_hook)(sasl_conn_t *conn);
extern int (*_sasl_server_idle_hook)(sasl_conn_t *conn);

extern int _sasl_strdup(const char *in, char **out, int *outlen);

typedef struct {
  const sasl_callback_t *callbacks;
  const char *appname;
} sasl_global_callbacks_t;

typedef struct _sasl_external_properties 
{
    sasl_ssf_t ssf;
    char *auth_id;
} _sasl_external_properties_t;

typedef struct buffer_info
{ 
    char *data;
    unsigned curlen;
    unsigned reallen;
} buffer_info_t;

struct sasl_conn {
  void (*destroy_conn)(sasl_conn_t *); /* destroy function */

  char *service;

  int secflags;  /* security layer flags passed to sasl_*_new */

    /* IP information.  A buffer of size 52 is adequate for this in its
       longest format (see sasl.h) */
    /* We keep this in 2 formats, because in verifying the format
       of what is passed ot us, we might as well just convert it all the
       way to a sockaddr_in. */
  int got_ip_local, got_ip_remote;
  char iplocalport[52], ipremoteport[52];
  struct sockaddr_in ip_local, ip_remote;    

  void *context;
  sasl_out_params_t oparams;

  sasl_security_properties_t props;
  _sasl_external_properties_t external;

  sasl_secret_t *secret;

  int (*idle_hook)(sasl_conn_t *conn);
  const sasl_callback_t *callbacks;
  const sasl_global_callbacks_t *global_callbacks; /* global callbacks
						    * for this
						    * connection */
  char *serverFQDN;

  /* Pointers to memory that we are responsible for */
  buffer_info_t *encode_buf;

  char *decode_buf;
  unsigned decode_buf_len;

  char *user_buf, *authid_buf;
};

extern int _sasl_conn_init(sasl_conn_t *conn,
			   const char *service,
			   int secflags,
			   int (*idle_hook)(sasl_conn_t *conn),
			   const char *serverFQDN,
			   const char *iplocalport,
			   const char *ipremoteport,
			   const sasl_callback_t *callbacks,
			   const sasl_global_callbacks_t * global_callbacks);

extern void _sasl_conn_dispose(sasl_conn_t *conn);

typedef struct sasl_allocation_utils {
  sasl_malloc_t *malloc;
  sasl_calloc_t *calloc;
  sasl_realloc_t *realloc;
  sasl_free_t *free;
} sasl_allocation_utils_t;

typedef struct sasl_log_utils_s {
  sasl_log_t *log;
} sasl_log_utils_t;

extern sasl_allocation_utils_t _sasl_allocation_utils;

#define sasl_ALLOC(__size__) (_sasl_allocation_utils.malloc((__size__)))
#define sasl_CALLOC(__nelem__, __size__) \
	(_sasl_allocation_utils.calloc((__nelem__), (__size__)))
#define sasl_REALLOC(__ptr__, __size__) \
	(_sasl_allocation_utils.realloc((__ptr__), (__size__)))
#define sasl_FREE(__ptr__) (_sasl_allocation_utils.free((__ptr__)))

typedef struct sasl_mutex_utils {
  sasl_mutex_alloc_t *alloc;
  sasl_mutex_lock_t *lock;
  sasl_mutex_unlock_t *unlock;
  sasl_mutex_free_t *free;
} sasl_mutex_utils_t;

extern sasl_mutex_utils_t _sasl_mutex_utils;

#define sasl_MUTEX_ALLOC() (_sasl_mutex_utils.alloc())
#define sasl_MUTEX_LOCK(__mutex__) (_sasl_mutex_utils.lock((__mutex__)))
#define sasl_MUTEX_UNLOCK(__mutex__) (_sasl_mutex_utils.unlock((__mutex__)))
#define sasl_MUTEX_FREE(__mutex__) \
	(_sasl_mutex_utils.free((__mutex__)))

extern sasl_utils_t *
_sasl_alloc_utils(sasl_conn_t *conn,
		  sasl_global_callbacks_t *global_callbacks);

extern int
_sasl_free_utils(sasl_utils_t ** utils);

extern int
_sasl_server_check_db(const sasl_callback_t *verifyfile_cb);

extern int
_sasl_getcallback(sasl_conn_t * conn,
		  unsigned long callbackid,
		  int (**pproc)(),
		  void **pcontext);

extern void
_sasl_log(sasl_conn_t *conn,
	  int level,
	  const char *fmt,
	  ...);

/* external plugin (external.c) */
int external_client_init(const sasl_utils_t *utils,
			 int max_version,
			 int *out_version,
			 const sasl_client_plug_t **pluglist,
			 int *plugcount);
extern const sasl_client_plug_t external_client_mech;
int external_server_init(const sasl_utils_t *utils,
			 int max_version,
			 int *out_version,
			 const sasl_server_plug_t **pluglist,
			 int *plugcount);
extern const sasl_server_plug_t external_server_mech;



/* config file declarations (config.c) */
extern int sasl_config_init(const char *filename);
extern const char *sasl_config_getstring(const char *key,const char *def);
extern int sasl_config_getint(const char *key,int def);
extern int sasl_config_getswitch(const char *key,int def);

/* clear password checking declarations (checkpw.c) */
typedef int sasl_plaintext_verifier(sasl_conn_t *conn,
				    const char *userid,
				    const char *passwd,
				    const char *service,
				    const char *user_realm,
				    const char **reply);
struct sasl_verify_password_s {
    char *name;
    sasl_plaintext_verifier *verify;
};

extern struct sasl_verify_password_s _sasl_verify_password[];

extern int _sasl_sasldb_set_pass(sasl_conn_t *conn,
				 const char *user, 
				 const char *pass,
				 unsigned passlen,
				 const char *user_realm,
				 int flags);


/* The following is defined in common.c */
/* Basically a conditional call to realloc(), if we need more */
int _buf_alloc(char **rwbuf, unsigned *curlen, unsigned newlen);

/* convert an iovec to a single buffer */
int _iovec_to_buf(const struct iovec *vec,
		  unsigned numiov, buffer_info_t **output);

/* The following are defined in saslutil.c */
/* FIXME: Should they be in common.c instead? */
int _sasl_iptostring(const struct sockaddr_in *addr,
		     char *out, unsigned outlen);
int _sasl_ipfromstring(const char *addr, struct sockaddr_in *out);

extern int _sasl_canon_user(sasl_conn_t *conn,
			    const char *user, unsigned ulen,
			    const char *authid, unsigned alen,
			    unsigned flags,
			    sasl_out_params_t *oparams);


#endif /* SASLINT_H */
