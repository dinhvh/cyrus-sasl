/* SASL server API implementation
 * Rob Siemborski
 * Tim Martin
 * $Id: checkpw.c,v 1.41.2.14 2001/07/03 18:00:56 rjs3 Exp $
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

/* checkpw stuff */

#include "sasl.h"
#include "saslutil.h"
#include "saslplug.h"
#include "saslint.h"

#include <assert.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdlib.h>

#ifndef WIN32
#include <strings.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/param.h>
#include <sys/un.h>
#else
#include <string.h>
#endif

#include <sys/types.h>
#include <ctype.h>

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif /* HAVE_PWD_H */
#ifdef HAVE_SHADOW_H
#include <shadow.h>
#endif /* HAVE_SHADOW_H */

#if defined(HAVE_PWCHECK) || defined(HAVE_SASLAUTHD)
# include <errno.h>
# include <sys/types.h>
# include <sys/uio.h>
# include <sys/socket.h>
# include <sys/un.h>
# ifdef HAVE_UNISTD_H
#  include <unistd.h>
# endif

extern int errno;
#endif

/* erase & dispose of a sasl_secret_t
 */

static void _sasl_free_secret(sasl_secret_t **secret)
{
  if (secret==NULL) return;
  if (*secret==NULL) return;

  /* overwrite the memory */
  sasl_erasebuffer((*secret)->data, (*secret)->len);

  sasl_FREE(*secret);

  *secret=NULL;
}

/* returns the realm we should pretend to be in */
static int parseuser(char **user, char **realm, const char *user_realm, 
		     const char *serverFQDN, const char *input)
{
    int ret;
    char *r;

    assert(user && serverFQDN);

    if (!user_realm) {
	ret = _sasl_strdup(serverFQDN, realm, NULL);
	if (ret == SASL_OK) {
	    ret = _sasl_strdup(input, user, NULL);
	}
    } else if (user_realm[0]) {
	ret = _sasl_strdup(user_realm, realm, NULL);
	if (ret == SASL_OK) {
	    ret = _sasl_strdup(input, user, NULL);
	}
    } else {
	/* otherwise, we gotta get it from the user */
	r = strchr(input, '@');
	if (!r) {
	    /* hmmm, the user didn't specify a realm */
	    /* we'll default to the serverFQDN */
	    ret = _sasl_strdup(serverFQDN, realm, NULL);
	    if (ret == SASL_OK) {
		ret = _sasl_strdup(input, user, NULL);
	    }
	} else {
	    r++;
	    ret = _sasl_strdup(r, realm, NULL);
	    *--r = '\0';
	    *user = sasl_ALLOC(r - input + 1);
	    if (*user) {
		strncpy(*user, input, r - input +1);
	    } else {
		ret = SASL_NOMEM;
	    }
	    *r = '@';
	}
    }

    return ret;
}

static int sasldb_verify_password(sasl_conn_t *conn,
				  const char *userstr,
				  const char *passwd,
				  const char *service __attribute__((unused)),
				  const char *user_realm)
{
    int ret = SASL_FAIL;
    sasl_secret_t *secret = NULL;
    char *userid = NULL;
    char *realm = NULL;

    if (!userstr)
	return SASL_BADPARAM;

    ret = parseuser(&userid, &realm, user_realm, conn->serverFQDN, userstr);
    if (ret != SASL_OK) {
	/* error parsing user */
	goto done;
    }

    ret = _sasl_db_getsecret(conn, userid, realm, &secret);
    if (ret != SASL_OK) {
	/* error getting secret */
	goto done;
    }

    /* It is possible for us to get useful information out of just
     * the lookup, so we won't check that we have a password until now */
    if(!passwd) {
	ret = SASL_BADPARAM;
	goto done;
    }
    
    if (!memcmp(secret->data, passwd, secret->len)) {
	/* password verified! */
	ret = SASL_OK;
    } else {
	/* passwords do not match */
	ret = SASL_BADAUTH;
    }

 done:
    if (userid) sasl_FREE(userid);
    if (realm)  sasl_FREE(realm);

    if (secret) _sasl_free_secret(&secret);
    return ret;
}

#ifdef DO_SASL_CHECKAPOP
int _sasl_sasldb_verify_apop(sasl_conn_t *conn,
			     const char *userstr,
			     const char *challenge,
			     const char *response,
			     const char *user_realm)
{
    int ret = SASL_FAIL;
    sasl_secret_t *secret = NULL;
    char *userid = NULL;
    char *realm = NULL;
    unsigned char digest[16];
    char digeststr[32];
    MD5_CTX ctx;
    int i;

    if (!userstr || !challenge || !response) {
      return SASL_BADPARAM;
    }

    ret = parseuser(&userid, &realm, user_realm, conn->serverFQDN, userstr);
    if (ret != SASL_OK) {
      /* error parsing user */
      goto done;
    }

    ret = _sasl_db_getsecret(conn, userid, realm, &secret);
    if (ret != SASL_OK) {
      /* error getting APOP secret */
      goto done;
    }

    _sasl_MD5Init(&ctx);
    _sasl_MD5Update(&ctx, challenge, strlen(challenge));
    _sasl_MD5Update(&ctx, secret->data, strlen(secret->data));
    _sasl_MD5Final(digest, &ctx);

    /* convert digest from binary to ASCII hex */
    for (i = 0; i < 16; i++)
      sprintf(digeststr + (i*2), "%02x", digest[i]);

    if (!strncasecmp(digeststr, response, 32)) {
      /* password verified! */
      ret = SASL_OK;
    } else {
      /* passwords do not match */
      ret = SASL_BADAUTH;
    }

 done:
    if (userid) sasl_FREE(userid);
    if (realm)  sasl_FREE(realm);

    if (secret) _sasl_free_secret(&secret);
    return ret;
}
#endif /* DO_SASL_CHECKAPOP */

/* this routine sets the sasldb password given a user/pass */
int _sasl_sasldb_set_pass(sasl_conn_t *conn,
			  const char *userstr, 
			  const char *pass,
			  unsigned passlen,
			  const char *user_realm,
			  int flags)
{
    char *userid = NULL;
    char *realm = NULL;
    int ret = SASL_OK;

    ret = parseuser(&userid, &realm, user_realm, conn->serverFQDN, userstr);
    if (ret != SASL_OK) {
	return ret;
    }

    if (pass != NULL && !(flags & SASL_SET_DISABLE)) {
	/* set the password */
	sasl_secret_t *sec = NULL;

	/* if SASL_SET_CREATE is set, we don't want to overwrite an
	   existing account */
	if (flags & SASL_SET_CREATE) {
	    ret = _sasl_db_getsecret(conn, userid, realm, &sec);
	    if (ret == SASL_OK) {
		_sasl_free_secret(&sec);
		ret = SASL_NOCHANGE;
	    } else {
		/* Don't give up yet-- the DB might have failed because
		 * does not exist, but will be created later... */
		ret = SASL_OK;
	    }
	}
	
	/* ret == SASL_OK iff we still want to set this password */
	if (ret == SASL_OK) {
	    /* Create the sasl_secret_t */
	    sec = sasl_ALLOC(sizeof(sasl_secret_t) + passlen);
	    if(!sec) ret = SASL_NOMEM;
	    else {
		memcpy(sec->data, pass, passlen);
		sec->data[passlen] = '\0';
		sec->len = passlen;
	    }
	}
	if (ret == SASL_OK) {
	    ret = _sasl_db_putsecret(conn, userid, realm, sec);
	}
	if (ret != SASL_OK) {
	    _sasl_log(conn, SASL_LOG_ERR, NULL, ret, 0,
		      "failed to set plaintext secret for %s: %z", userid);
	}
	if (sec) {
	    _sasl_free_secret(&sec);
	}
    } else { 
	/* SASL_SET_DISABLE specified */
	ret = _sasl_db_putsecret(conn, userid, realm, NULL);

	if (ret != SASL_OK) {
	    _sasl_log(conn, SASL_LOG_ERR,
		      "failed to disable account for %s: %z", userid);
	}
    }

    if (userid)   sasl_FREE(userid);
    if (realm)    sasl_FREE(realm);
    return ret;
}


static void sasldb_auxprop_lookup(void *glob_context __attribute__((unused)),
				  sasl_server_params_t *sparams,
				  unsigned flags,
				  const char *user,
				  unsigned ulen __attribute__((unused))) 
{
    char *userid = NULL;
    char *realm = NULL;
    sasl_secret_t *secret = NULL;
    sasl_server_conn_t *sconn;
    int ret;
    const char *proplookup[] = { SASL_AUX_PASSWORD, NULL };
    struct propval values[2];

    if(!sparams || !user) return;

    sconn = (sasl_server_conn_t *)(sparams->utils->conn);
    
    ret = parseuser(&userid, &realm, sconn->user_realm,
		    sparams->utils->conn->serverFQDN, user);
    if(ret!= SASL_OK) goto done;

    ret = _sasl_db_getsecret(sparams->utils->conn, userid, realm, &secret);
    if (ret != SASL_OK) {
	/* error getting secret */
	goto done;
    }

    ret = prop_getnames(sparams->propctx, proplookup, values);
    /* did we get the one we were looking for? */
    if(ret == 1 && values[0].values && values[0].valsize) {
	if(flags & SASL_AUXPROP_OVERRIDE) {
	    prop_erase(sparams->propctx, SASL_AUX_PASSWORD);
	} else {
	    /* We aren't going to override it... */
	    goto done;
	}
    }
    
    /* Set the auxprop (the only one we support) */
    prop_set(sparams->propctx, SASL_AUX_PASSWORD, secret->data, secret->len);

 done:
    if (userid) sasl_FREE(userid);
    if (realm)  sasl_FREE(realm);

    if (secret) _sasl_free_secret(&secret);
}

static sasl_auxprop_plug_t sasldb_auxprop_plugin = {
    0,           /* Features */
    0,           /* spare */
    NULL,        /* glob_context */
    NULL,        /* auxprop_free */
    sasldb_auxprop_lookup, /* auxprop_lookup */
    NULL,        /* spares */
    NULL
};

int sasldb_auxprop_plug_init(const sasl_utils_t *utils __attribute__((unused)),
                             int max_version,
                             int *out_version,
                             sasl_auxprop_plug_t **plug,
                             const char *plugname) 
{
    if(!out_version || !plug || !plugname) return SASL_BADPARAM;

    /* We only support the "SASLDB" plugin */
    if(strcmp(plugname, "SASLDB")) return SASL_NOMECH;

    if(max_version < SASL_AUXPROP_PLUG_VERSION) return SASL_BADVERS;
    
    *out_version = SASL_AUXPROP_PLUG_VERSION;

    *plug = &sasldb_auxprop_plugin;

    return SASL_OK;
}

#ifdef HAVE_PWCHECK
/*
 * Keep calling the writev() system call with 'fd', 'iov', and 'iovcnt'
 * until all the data is written out or an error occurs.
 */
static int retry_writev(int fd, struct iovec *iov, int iovcnt)
{
    int n;
    int i;
    int written = 0;
    static int iov_max =
#ifdef MAXIOV
	MAXIOV
#else
#ifdef IOV_MAX
	IOV_MAX
#else
	8192
#endif
#endif
	;
    
    for (;;) {
	while (iovcnt && iov[0].iov_len == 0) {
	    iov++;
	    iovcnt--;
	}

	if (!iovcnt) return written;

	n = writev(fd, iov, iovcnt > iov_max ? iov_max : iovcnt);
	if (n == -1) {
	    if (errno == EINVAL && iov_max > 10) {
		iov_max /= 2;
		continue;
	    }
	    if (errno == EINTR) continue;
	    return -1;
	}

	written += n;

	for (i = 0; i < iovcnt; i++) {
	    if (iov[i].iov_len > n) {
		iov[i].iov_base = (char *)iov[i].iov_base + n;
		iov[i].iov_len -= n;
		break;
	    }
	    n -= iov[i].iov_len;
	    iov[i].iov_len = 0;
	}

	if (i == iovcnt) return written;
    }
}



/* pwcheck daemon-authenticated login */
static int pwcheck_verify_password(sasl_conn_t *conn,
				   const char *userid, 
				   const char *passwd,
				   const char *service __attribute__((unused)),
				   const char *user_realm 
				               __attribute__((unused)))
{
    int s;
    struct sockaddr_un srvaddr;
    int r;
    struct iovec iov[10];
    static char response[1024];
    int start, n;
    char pwpath[1024];
    sasl_getopt_t *getopt;
    void *context;

    if (strlen(PWCHECKDIR)+8+1 > sizeof(pwpath)) return SASL_FAIL;

    strcpy(pwpath, PWCHECKDIR);
    strcat(pwpath, "/pwcheck");

    s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s == -1) return errno;

    memset((char *)&srvaddr, 0, sizeof(srvaddr));
    srvaddr.sun_family = AF_UNIX;
    strncpy(srvaddr.sun_path, pwpath, sizeof(srvaddr.sun_path));
    r = connect(s, (struct sockaddr *)&srvaddr, sizeof(srvaddr));
    if (r == -1) {
	sasl_seterror(conn,0,"cannot connect to pwcheck server");
	return SASL_FAIL;
    }

    iov[0].iov_base = (char *)userid;
    iov[0].iov_len = strlen(userid)+1;
    iov[1].iov_base = (char *)passwd;
    iov[1].iov_len = strlen(passwd)+1;

    retry_writev(s, iov, 2);

    start = 0;
    while (start < sizeof(response) - 1) {
	n = read(s, response+start, sizeof(response) - 1 - start);
	if (n < 1) break;
	start += n;
    }

    close(s);

    if (start > 1 && !strncmp(response, "OK", 2)) {
	return SASL_OK;
    }

    response[start] = '\0';
    sasl_seterror(conn,0,response);
    return SASL_BADAUTH;
}

#endif

#ifdef HAVE_SASLAUTHD
/* saslauthd-authenticated login */
static int saslauthd_verify_password(sasl_conn_t *conn,
				   const char *userid, 
				   const char *passwd,
				   const char *service __attribute__((unused)),
				   const char *user_realm 
				               __attribute__((unused)))
{
    static char response[1024];
    int s;
    struct sockaddr_un srvaddr;
    int r, n;
    unsigned int start;
    sasl_getopt_t *getopt;
    void *context;
    char pwpath[sizeof(srvaddr.sun_path)];
    const char *p = NULL;

    /* check to see if the user configured a rundir */
    if (_sasl_getcallback(conn, SASL_CB_GETOPT, &getopt, &context) == SASL_OK) {
	getopt(context, NULL, "saslauthd_path", &p, NULL);
    }
    if (p) {
	strncpy(pwpath, p, sizeof(pwpath));
    } else {
	if (strlen(PATH_SASLAUTHD_RUNDIR) + 4 + 1 > sizeof(pwpath))
	    return SASL_FAIL;

	strcpy(pwpath, PATH_SASLAUTHD_RUNDIR);
	strcat(pwpath, "/mux");
    }

    s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s == -1)
	return errno;

    memset((char *)&srvaddr, 0, sizeof(srvaddr));
    srvaddr.sun_family = AF_UNIX;
    strncpy(srvaddr.sun_path, pwpath, sizeof(srvaddr.sun_path));

    r = connect(s, (struct sockaddr *) &srvaddr, sizeof(srvaddr));
    if (r == -1) {
	sasl_seterror(conn, 0, "cannot connect to pwcheck server");
	return SASL_FAIL;
    }

    {
	int u_len;
	int p_len;
	char *msg;

	u_len = strlen(userid) + 1;
	p_len = strlen(passwd) + 1;
	msg = sasl_ALLOC(u_len + p_len);
	if (msg == NULL) {
	    close(s);
	    sasl_seterror(conn, 0, "not enough memory");
	    return SASL_NOMEM;
	}
	strcpy(msg, userid);
	strcpy(msg + u_len, passwd);

	while (write(s, msg, u_len + p_len) == -1)
	    switch (errno) {
	    case EINTR:
		continue;
	    default:
		sasl_FREE(msg);
		sasl_seterror(conn,0,"write failed");
		return SASL_FAIL;
	    }

	sasl_FREE(msg);
    }

    start = 0;
    while (start < sizeof(response) - 1) {
	n = read(s, response + start, sizeof(response) - 1 - start);
	if (n < 1)
	    break;
	start += n;
    }

    close(s);

    if (start > 1 && !strncmp(response, "OK", 2))
	return SASL_OK;

    response[start] = '\0';
    sasl_seterror(conn,0,response);
    return SASL_BADAUTH;
}

#endif

struct sasl_verify_password_s _sasl_verify_password[] = {
    { "sasldb", &sasldb_verify_password },
#ifdef HAVE_PWCHECK
    { "pwcheck", &pwcheck_verify_password },
#endif
#ifdef HAVE_SASLAUTHD
    { "saslauthd", &saslauthd_verify_password },
#endif
    { NULL, NULL }
};
