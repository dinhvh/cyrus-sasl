/* saslint.h - internal SASL library definitions
 * Rob Siemborski
 * Tim Martin
 * $Id: saslint.h,v 1.33.2.26 2001/07/02 22:50:07 rjs3 Exp $
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

#ifndef SASLINT_H
#define SASLINT_H

#include <config.h>
#include "sasl.h"
#include "saslplug.h"

#define DEFAULT_MAXOUTBUF 8192


extern const sasl_utils_t *global_utils;

extern int _sasl_common_init(void);
extern int _is_sasl_server_active(void);

/* dlopen.c and staticopen.c */
extern const int _is_sasl_server_static;
extern int _sasl_get_mech_list(const char *entryname,
			       const sasl_callback_t *getpath_callback,
			       const sasl_callback_t *verifyfile_callback,
			       int (*add_plugin)(void *,void *));
extern int _sasl_done_with_plugin(void *plugin);
extern int _sasl_get_plugin(const char *file,
			    const char *entryname,
			    const sasl_callback_t *verifyfile_callback,
			    void **entrypoint,
			    void **library);

/* common.c */
extern const sasl_callback_t *
_sasl_find_getpath_callback(const sasl_callback_t *callbacks);

extern const sasl_callback_t *
_sasl_find_verifyfile_callback(const sasl_callback_t *callbacks);

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

enum Sasl_conn_type { SASL_CONN_UNKNOWN = 0,
		      SASL_CONN_SERVER = 1,
                      SASL_CONN_CLIENT = 2 };

#define CANON_BUF_SIZE 256

struct sasl_conn {
  enum Sasl_conn_type type;

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
						    * connection */
  char *serverFQDN;

  /* Pointers to memory that we are responsible for */
  buffer_info_t *encode_buf;

  char *error_buf;
  unsigned error_buf_len;
  char *decode_buf;
  unsigned decode_buf_len;

  char user_buf[CANON_BUF_SIZE+1], authid_buf[CANON_BUF_SIZE+1];
};

/* Server Conn Type Information */

typedef struct mechanism
{
    int version;
    int condition; /* set to SASL_NOUSER if no available users;
		      set to SASL_CONTINUE if delayed plugn loading */
    const sasl_server_plug_t *plug;
    struct mechanism *next;
    union {
	void *library; /* this a pointer to shared library returned by dlopen 
			  or some similar function on other platforms */
	char *f;       /* where should i load the mechanism from? */
    } u;
} mechanism_t;

typedef struct mech_list {
  const sasl_utils_t *utils;  /* gotten from plug_init */

  void *mutex;            /* mutex for this data */ 
  mechanism_t *mech_list; /* list of mechanisms */
  int mech_length;       /* number of mechanisms */
} mech_list_t;

typedef struct sasl_server_conn {
    sasl_conn_t base; /* parts common to server + client */

    char *mechlist_buf;
    unsigned mechlist_buf_len;

    char *user_realm; /* domain the user authenticating is in */
    int authenticated;
    mechanism_t *mech; /* mechanism trying to use */
    sasl_server_params_t *sparams;
} sasl_server_conn_t;

/* Client Conn Type Information */

typedef struct cmechanism
{
  int version;
  const sasl_client_plug_t *plug;
  void *library;

  struct cmechanism *next;  
} cmechanism_t;

typedef struct cmech_list {
  const sasl_utils_t *utils; 

  void *mutex;            /* mutex for this data */ 
  cmechanism_t *mech_list; /* list of mechanisms */
  int mech_length;       /* number of mechanisms */

} cmech_list_t;

typedef struct sasl_client_conn {
  sasl_conn_t base; /* parts common to server + client */

  cmechanism_t *mech;
  sasl_client_params_t *cparams;

  char *serverFQDN;

} sasl_client_conn_t;

extern int _sasl_conn_init(sasl_conn_t *conn,
			   const char *service,
			   int secflags,
			   int (*idle_hook)(sasl_conn_t *conn),
			   const char *serverFQDN,
			   const char *iplocalport,
			   const char *ipremoteport,
			   const sasl_callback_t *callbacks,
			   const sasl_global_callbacks_t *global_callbacks);

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

/* FIXME: This const here is kind of ugly */
extern int
_sasl_free_utils(const sasl_utils_t ** utils);


/* Database Stuff */
typedef int sasl_server_getsecret_t(sasl_conn_t *context,
				    const char *auth_identity,
				    const char *realm,
				    sasl_secret_t ** secret);

typedef int sasl_server_putsecret_t(sasl_conn_t *context,
				    const char *auth_identity,
				    const char *realm,
				    const sasl_secret_t * secret);

extern sasl_server_getsecret_t *_sasl_db_getsecret;
extern sasl_server_putsecret_t *_sasl_db_putsecret;

extern int
_sasl_server_check_db(const sasl_callback_t *verifyfile_cb);
/* End Database Stuff */

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
			 sasl_client_plug_t **pluglist,
			 int *plugcount,
			 const char *plugname);
extern sasl_client_plug_t external_client_mech;
int external_server_init(const sasl_utils_t *utils,
			 int max_version,
			 int *out_version,
			 sasl_server_plug_t **pluglist,
			 int *plugcount,
			 const char *plugname);
extern sasl_server_plug_t external_server_mech;



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
				    const char *user_realm);
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

#ifdef DO_SASL_CHECKAPOP
int _sasl_sasldb_verify_apop(sasl_conn_t *conn,
			     const char *userstr,
			     const char *challenge,
			     const char *response,
			     const char *user_realm);
#endif /* DO_SASL_CHECKAPOP */

/* auxprop.c */
void _sasl_auxprop_free();
void _sasl_auxprop_lookup(sasl_server_params_t *sparams,
			  unsigned flags,
			  const char *user, unsigned ulen);

/* checkpw.c */
int sasldb_auxprop_plug_init(const sasl_utils_t *utils,
			     int max_version,
			     int *out_version,
			     sasl_auxprop_plug_t **plug,
			     const char *plugname);

/* canonuser.c */
void _sasl_canonuser_free();
int internal_canonuser_init(const sasl_utils_t *utils,
			    int max_version,
			    int *out_version,
			    sasl_canonuser_plug_t **plug,
			    const char *plugname);

/* The following is defined in common.c */
/* Basically a conditional call to realloc(), if we need more */
int _buf_alloc(char **rwbuf, unsigned *curlen, unsigned newlen);

/* convert an iovec to a single buffer */
int _iovec_to_buf(const struct iovec *vec,
		  unsigned numiov, buffer_info_t **output);

/* Convert between string formats and sockaddr formats */
int _sasl_iptostring(const struct sockaddr_in *addr,
		     char *out, unsigned outlen);
int _sasl_ipfromstring(const char *addr, struct sockaddr_in *out);

extern int _sasl_canon_user(sasl_conn_t *conn,
			    const char *user, unsigned ulen,
			    const char *authid, unsigned alen,
			    unsigned flags,
			    sasl_out_params_t *oparams);

#endif /* SASLINT_H */
