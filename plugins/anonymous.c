/* Anonymous SASL plugin
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

#include <config.h>
#include <sasl.h>
#include <saslplug.h>

#include <stdio.h>
#include <string.h> 
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef macintosh 
#include <sasl_anonymous_plugin_decl.h> 
#endif 

#ifdef WIN32
/* This must be after sasl.h, saslutil.h */
# include "saslANONYMOUS.h"
#endif

#include "plugin_common.h"

static const char rcsid[] = "$Implementation: Carnegie Mellon SASL " VERSION " $";

static const char anonymous_id[] = "anonymous";

#ifdef L_DEFAULT_GUARD
# undef L_DEFAULT_GUARD
# define L_DEFAULT_GUARD (0)
#endif

/* only used by client */
typedef struct context {
  int state;
  char *out_buf;
  unsigned out_buf_len;
} context_t;

static int
server_start(void *glob_context __attribute__((unused)),
      sasl_server_params_t *sparams __attribute__((unused)),
      const char *challenge __attribute__((unused)),
      unsigned challen __attribute__((unused)),
      void **conn_context)
{
  /* holds state are in */
  if (!conn_context)
      return SASL_BADPARAM;
  
  *conn_context = NULL;

  return SASL_OK;
}

static int
server_continue_step (void *conn_context __attribute__((unused)),
	       sasl_server_params_t *sparams,
	       const char *clientin,
	       unsigned clientinlen,
	       const char **serverout,
	       unsigned *serveroutlen,
	       sasl_out_params_t *oparams)
{
  char *clientdata;

  if (!sparams
      || !serverout
      || !serveroutlen
      || !oparams)
    return SASL_BADPARAM;

  if (! clientin) {
    *serverout = NULL;
    *serveroutlen = 0;
    return SASL_CONTINUE;
  }

  /* We force a truncation 255 characters (specified by RFC 2245) */
  if (clientinlen > 255) clientinlen = 255;

  /* NULL-terminate the clientin... */
  clientdata = sparams->utils->malloc(clientinlen + 1);
  if (! clientdata)
    return SASL_NOMEM;
  strncpy(clientdata, clientin, clientinlen);
  clientdata[clientinlen] = '\0';

  sparams->utils->log(sparams->utils->conn,
		      SASL_LOG_NOTE,
		      "login: \"%s\"",
		      clientdata);

  if (clientdata != clientin)
    sparams->utils->free(clientdata);
  
  oparams->mech_ssf=0;
  oparams->maxoutbuf=0;
  oparams->encode=NULL;
  oparams->decode=NULL;

  sparams->canon_user(sparams->utils->conn,
		      anonymous_id, 0, anonymous_id, 0,
		      0, oparams);
  
  oparams->param_version=0;

  /*nothing more to do; authenticated */
  oparams->doneflag=1;
  
  *serverout = NULL;
  *serveroutlen = 0;
  return SASL_OK;
}

static const sasl_server_plug_t plugins[] = 
{
  {
    "ANONYMOUS",		/* mech_name */
    0,				/* max_ssf */
    SASL_SEC_NOPLAINTEXT,	/* security_flags */
    0,                          /* features */
    NULL,			/* glob_context */
    &server_start,		/* mech_new */
    &server_continue_step,	/* mech_step */
    NULL,			/* mech_dispose */
    NULL,			/* mech_free */
    NULL,			/* setpass */
    NULL,			/* user_query */
    NULL,			/* idle */
    NULL,			/* mech_avail */
    NULL                        /* spare */
  }
};

int sasl_server_plug_init(const sasl_utils_t *utils __attribute__((unused)),
			  int maxversion,
			  int *out_version,
			  const sasl_server_plug_t **pluglist,
			  int *plugcount)
{
  if (maxversion<SASL_SERVER_PLUG_VERSION)
    return SASL_BADVERS;

  *pluglist=plugins;

  *plugcount=1;  
  *out_version=SASL_SERVER_PLUG_VERSION;

  return SASL_OK;
}

static void dispose(void *conn_context, const sasl_utils_t *utils)
{
  context_t *text;

  if(!conn_context) return;

  text=(context_t *)conn_context;
  if (!text) return;

  if(text->out_buf) utils->free(text->out_buf);

  utils->free(text);
}

/* FIXME: put in SASL_WRONGMECH check */
static int
client_start(void *glob_context __attribute__((unused)),
	sasl_client_params_t *cparams,
	void **conn_context)
{
  context_t *text;

  if (! conn_context)
    return SASL_BADPARAM;

  /* holds state are in */
  text = cparams->utils->malloc(sizeof(context_t));
  if (text==NULL) return SASL_NOMEM;
  text->state=1;
 
  text->out_buf = NULL;
  text->out_buf_len = 0;

  *conn_context=text;

  return SASL_OK;
}

static int
client_continue_step(void *conn_context,
		sasl_client_params_t *cparams,
		const char *serverin __attribute__((unused)),
		unsigned serverinlen,
		sasl_interact_t **prompt_need,
		const char **clientout,
		unsigned *clientoutlen,
		sasl_out_params_t *oparams)
{
  int result;
  unsigned userlen;
  char hostname[256];
  sasl_getsimple_t *getuser_cb;
  void *getuser_context;
  const char *user = NULL;
  context_t *text;
  text=conn_context;

  if (text->state == 3) {
      *clientout = NULL;
      *clientoutlen = 0;
      VL(("Verify we're done step"));
      text->state++;
      return SASL_OK;      
  }

  if (clientout == NULL && text->state == 1) {
      /* no initial client send */
      *clientout = NULL;
      *clientoutlen = 0;
      text->state = 2;
      return SASL_CONTINUE;
  } else if (text->state == 1) {
      text->state = 2;
  }

  if (text->state != 2) {
      return SASL_FAIL;
  }

  VL(("ANONYMOUS: step 1\n"));

  if (!cparams
      || !clientout
      || !clientoutlen
      || !oparams)
    return SASL_BADPARAM;

  if (serverinlen != 0)
    return SASL_BADPROT;

  /* check if sec layer strong enough */
  if (cparams->props.min_ssf>0)
    return SASL_TOOWEAK;

  /* Watch out if this doesn't start nulled! */
  /* Get the username */
  if (prompt_need && *prompt_need) {
    VL(("Received prompt\n"));
    /* We used an interaction to get it. */
    if (! (*prompt_need)[0].result)
      return SASL_BADPARAM;

    user = (*prompt_need)[0].result;
    userlen = (*prompt_need)[0].len;
    cparams->utils->free(*prompt_need);
  } else {
    /* Try to get the callback... */
    result = cparams->utils->getcallback(cparams->utils->conn,
					SASL_CB_AUTHNAME,
					&getuser_cb,
					&getuser_context);
    switch (result) {
    case SASL_INTERACT:
      /* Set up the interaction... */
      if (prompt_need) {
	*prompt_need = cparams->utils->malloc(sizeof(sasl_interact_t) * 2);
	if (! *prompt_need)
	  return SASL_FAIL;
	memset(*prompt_need, 0, sizeof(sasl_interact_t) * 2);
	(*prompt_need)[0].id = SASL_CB_AUTHNAME;
	(*prompt_need)[0].prompt = "Anonymous identification";
	(*prompt_need)[0].defresult = "";
	(*prompt_need)[1].id = SASL_CB_LIST_END;
      }
      return SASL_INTERACT;
    case SASL_OK:
      if (! getuser_cb
	  || (getuser_cb(getuser_context,
			 SASL_CB_AUTHNAME,
			 &user,
			 &userlen)
	      != SASL_OK)) {
	/* Use default */
      }
      break;
    default:
      /* Use default */
      break;
    }
  }
  
  if (!user) {
      user = "anonymous";
      userlen = strlen(user);
  }
  
  memset(hostname, 0, sizeof(hostname));
  gethostname(hostname, sizeof(hostname));
  hostname[sizeof(hostname)-1] = '\0';
  
  *clientoutlen = userlen + strlen(hostname) + 2;

  result = _plug_buf_alloc(cparams->utils, &text->out_buf,
			   &text->out_buf_len, *clientoutlen);

  if(result != SASL_OK) return result;

  *clientout = text->out_buf;

  strcpy(text->out_buf, user);
  text->out_buf[userlen] = '@';
  strcpy(text->out_buf + userlen + 1, hostname);

  VL(("anonymous: out=%s\n", *clientout));

  oparams->doneflag = 1;
  oparams->mech_ssf=0;
  oparams->maxoutbuf=0;
  oparams->encode=NULL;
  oparams->decode=NULL;

  cparams->canon_user(cparams->utils->conn,
		      anonymous_id, 0, anonymous_id, 0,
		      0, oparams);

  oparams->param_version=0;

  text->state = 3;

  return SASL_CONTINUE;
}

static const long client_required_prompts[] = {
  SASL_CB_AUTHNAME,
  SASL_CB_LIST_END
};

static const sasl_client_plug_t client_plugins[] = 
{
  {
    "ANONYMOUS",		/* mech_name */
    0,				/* max_ssf */
    SASL_SEC_NOPLAINTEXT,	/* security_flags */
    0,                          /* features */
    client_required_prompts,	/* required_prompts */
    NULL,			/* glob_context */
    &client_start,		/* mech_new */
    &client_continue_step,	/* mech_step */
    &dispose,			/* mech_dispose */
    NULL,			/* mech_free */
    NULL,			/* idle */
    NULL,			/* spare */
    NULL                        /* spare */
  }
};

int sasl_client_plug_init(const sasl_utils_t *utils __attribute__((unused)),
			  int maxversion,
			  int *out_version,
			  const sasl_client_plug_t **pluglist,
			  int *plugcount)
{
  if (maxversion < SASL_CLIENT_PLUG_VERSION)
    return SASL_BADVERS;

  *pluglist=client_plugins;

  *plugcount=1;
  *out_version=SASL_CLIENT_PLUG_VERSION;

  return SASL_OK;
}
