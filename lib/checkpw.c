/* SASL server API implementation
 * Rob Siemborski
 * Tim Martin
 * $Id: checkpw.c,v 1.41.2.18 2001/07/17 21:48:44 rjs3 Exp $
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

#include <stdio.h>
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
static int sasldb_verify_password(sasl_conn_t *conn,
				  const char *userstr,
				  const char *passwd,
				  const char *service __attribute__((unused)),
				  const char *user_realm __attribute__((unused)))
{
    int ret = SASL_FAIL;
    char *userid = NULL;
    char *realm = NULL;
    int result = SASL_OK;
    sasl_server_conn_t *sconn = (sasl_server_conn_t *)conn;
    const char *password_request[] = { SASL_AUX_PASSWORD, NULL };
    struct propval auxprop_values[2];
    
    if (!conn || !userstr)
	return SASL_BADPARAM;

    /* We need to clear any previous results and re-canonify to 
     * ensure correctness */

    prop_clear(sconn->sparams->propctx, 0);
	
    /* ensure its requested */
    result = prop_request(sconn->sparams->propctx, password_request);

    if(result != SASL_OK) return result;

    result = _sasl_canon_user(conn,
			      userstr, 0, userstr, 0,
			      0, &(conn->oparams));
    result = prop_getnames(sconn->sparams->propctx, password_request,
			   auxprop_values);
    if(result < 0)
	return result;

    if(!auxprop_values[0].name
       || !auxprop_values[0].values || !auxprop_values[0].values[0])
	    return SASL_FAIL;
        
    /* It is possible for us to get useful information out of just
     * the lookup, so we won't check that we have a password until now */
    if(!passwd) {
	ret = SASL_BADPARAM;
	goto done;
    }

    /* At the point this has been called, the username has been canonified
     * and we've done the auxprop lookup.  This should be easy. */
    if(!strcmp(auxprop_values[0].values[0], passwd)) {
	return SASL_OK;
    } else {
	/* passwords do not match */
	ret = SASL_BADAUTH;
    }

 done:
    if (userid) sasl_FREE(userid);
    if (realm)  sasl_FREE(realm);

    /* We're not going to erase the property here because other people
     * may want it */
    return ret;
}

#ifdef DO_SASL_CHECKAPOP
int _sasl_sasldb_verify_apop(sasl_conn_t *conn,
			     const char *userstr,
			     const char *challenge,
			     const char *response,
			     const char *user_realm __attribute__((unused)))
{
    int ret = SASL_FAIL;
    char *userid = NULL;
    char *realm = NULL;
    unsigned char digest[16];
    char digeststr[32];
    const char *password_request[] = { SASL_AUX_PASSWORD, NULL };
    struct propval auxprop_values[2];
    sasl_server_conn_t *sconn = (sasl_server_conn_t *)conn;
    MD5_CTX ctx;
    int i;

    if (!conn || !userstr || !challenge || !response) {
      return SASL_BADPARAM;
    }

    /* We've done the auxprop lookup already (in our caller) */
    ret = prop_getnames(sconn->sparams->propctx, password_request,
			auxprop_values);
    if(ret < 0)
	goto done;

    if(!auxprop_values[0].name)
	goto done;
    
    if(!auxprop_values[0].values[0])
	goto done;
    

    _sasl_MD5Init(&ctx);
    _sasl_MD5Update(&ctx, challenge, strlen(challenge));
    _sasl_MD5Update(&ctx, auxprop_values[0].values[0],
		    strlen(auxprop_values[0].values[0]));
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

    return ret;
}
#endif /* DO_SASL_CHECKAPOP */

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
