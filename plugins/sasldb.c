/* SASL server API implementation
 * Rob Siemborski
 * Tim Martin
 * $Id: sasldb.c,v 1.1.2.2 2001/07/20 20:39:16 rjs3 Exp $
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
#include <assert.h>

#include "sasl.h"
#include "saslutil.h"
#include "saslplug.h"
#include "../sasldb/sasldb.h"

#include "plugin_common.h"

/* returns the realm we should pretend to be in */
static int parseuser(const sasl_utils_t *utils,
		     char **user, char **realm, const char *user_realm, 
		     const char *serverFQDN, const char *input)
{
    int ret;
    char *r;

    assert(user && serverFQDN);

    r = strchr(input, '@');
    if (!r) {
	/* hmmm, the user didn't specify a realm */
	if(user_realm && user_realm[0]) {
	    ret = _plug_strdup(utils, user_realm, realm, NULL);
	} else {
	    /* Default to serverFQDN */
	    ret = _plug_strdup(utils, serverFQDN, realm, NULL);
	}
	
	if (ret == SASL_OK) {
	    ret = _plug_strdup(utils, input, user, NULL);
	}
    } else {
	r++;
	ret = _plug_strdup(utils, r, realm, NULL);
	*--r = '\0';
	*user = utils->malloc(r - input + 1);
	if (*user) {
	    strncpy(*user, input, r - input +1);
	} else {
	    MEMERROR( utils );
	    ret = SASL_NOMEM;
	}
	*r = '@';
    }

    return ret;
}

static void sasldb_auxprop_lookup(void *glob_context __attribute__((unused)),
				  sasl_server_params_t *sparams,
				  unsigned flags,
				  const char *user,
				  unsigned ulen) 
{
    char *userid = NULL;
    char *realm = NULL;
    const char *user_realm = NULL;
    sasl_secret_t *secret = NULL;
    int ret;
    const char *proplookup[] = { SASL_AUX_PASSWORD, NULL };
    struct propval values[2];
    char *user_buf;
    
    if(!sparams || !user) return;

    user_buf = sparams->utils->malloc(ulen + 1);
    if(!user_buf)
	goto done;

    memcpy(user_buf, user, ulen);
    user_buf[ulen] = '\0';
    user = user_buf;

    ret = sparams->utils->getprop(sparams->utils->conn, SASL_DEFUSERREALM,
				  (const void **)&user_realm);
    if(ret != SASL_OK) goto done;

    ret = parseuser(sparams->utils, &userid, &realm, user_realm,
		    sparams->serverFQDN, user);
    if(ret != SASL_OK) goto done;

    ret = _sasl_db_getsecret(sparams->utils,
			     sparams->utils->conn, userid, realm, &secret);
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
    if (userid) sparams->utils->free(userid);
    if (realm)  sparams->utils->free(realm);
    if (user_buf) sparams->utils->free(user_buf);

    if (secret) _plug_free_secret(sparams->utils, &secret);
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

int sasldb_auxprop_plug_init(const sasl_utils_t *utils,
                             int max_version,
                             int *out_version,
                             sasl_auxprop_plug_t **plug,
                             const char *plugname) 
{
    if(!out_version || !plug) return SASL_BADPARAM;

    /* We only support the "SASLDB" plugin */
    if(plugname && strcmp(plugname, "SASLDB")) return SASL_NOMECH;

    /* Do we have database support? */
    if(_sasl_check_db(utils) != SASL_OK)
	return SASL_NOMECH;

    if(max_version < SASL_AUXPROP_PLUG_VERSION) return SASL_BADVERS;
    
    *out_version = SASL_AUXPROP_PLUG_VERSION;

    *plug = &sasldb_auxprop_plugin;

    return SASL_OK;
}
