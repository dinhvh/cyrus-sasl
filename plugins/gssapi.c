/* GSSAPI SASL plugin
 * Leif Johansson
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

#ifdef HAVE_GSSAPI_H
#include <gssapi.h>
#else
#include <gssapi/gssapi.h>
#endif

#ifdef WIN32
#  include <winsock.h>

#  ifndef R_OK
#    define R_OK 04
#  endif
   /* we also need io.h for access() prototype */
#  include <io.h>
#else
#  include <sys/param.h>
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <netdb.h>
#endif /* WIN32 */
#include <fcntl.h>
#include <stdio.h>
#include <sasl.h>
#include <saslutil.h>
#include <saslplug.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <errno.h>

#ifdef WIN32
/* This must be after sasl.h */
# include "saslgssapi.h"
#endif /* WIN32 */

#ifndef HAVE_GSS_C_NT_HOSTBASED_SERVICE
extern gss_OID gss_nt_service_name;
#define GSS_C_NT_HOSTBASED_SERVICE gss_nt_service_name
#endif

/* GSSAPI SASL Mechanism by Leif Johansson <leifj@matematik.su.se>
 * inspired by the kerberos mechanism and the gssapi_server and
 * gssapi_client from the heimdal distribution by Assar Westerlund
 * <assar@sics.se> and Johan Danielsson <joda@pdc.kth.se>. 
 * See the configure.in file for details on dependencies.
 * Heimdal can be obtained from http://www.pdc.kth.se/heimdal
 *
 * Important contributions from Sam Hartman <hartmans@fundsxpress.com>.
 */

#include "plugin_common.h"

typedef struct context {
    int state;

    gss_ctx_id_t gss_ctx;
    gss_name_t   client_name;
    gss_name_t   server_name;
    gss_cred_id_t server_creds;
    sasl_ssf_t limitssf, requiressf; /* application defined bounds, for the
					server */

    const sasl_utils_t *utils;

    /* layers buffering */
    char *buffer;
    int bufsize;
    char sizebuf[4];
    int cursize;
    int size;
    unsigned needsize;

    char *encode_buf;                /* For encoding/decoding mem management */
    char *decode_buf;
    unsigned encode_buf_len;
    unsigned decode_buf_len;
    buffer_info_t *enc_in_buf;

    char *out_buf;                   /* per-step mem management */
    unsigned out_buf_len;    

    union 
    {	
	char *authid; /* hold the authid between steps - server */
	char *user;   /* hold the userid between steps - client */
    } u;
} context_t;

enum {
    SASL_GSSAPI_STATE_AUTHNEG = 1,
    SASL_GSSAPI_STATE_SSFCAP = 2,
    SASL_GSSAPI_STATE_SSFREQ = 3,
    SASL_GSSAPI_STATE_AUTHENTICATED = 4
};

static int 
sasl_gss_encode(void *context, const struct iovec *invec, unsigned numiov,
		const char **output, unsigned *outputlen, int privacy)
{
  context_t *text = (context_t *)context;
  OM_uint32 maj_stat, min_stat;
  gss_buffer_t input_token, output_token;
  gss_buffer_desc real_input_token, real_output_token;
  int ret;

  if(!output) return SASL_BADPARAM;
  
  ret = _plug_iovec_to_buf(text->utils, invec, numiov, &text->enc_in_buf);
  if(ret != SASL_OK) return ret;

  if (text->state != SASL_GSSAPI_STATE_AUTHENTICATED) return SASL_NOTDONE;
  
  input_token = &real_input_token;
  
  real_input_token.value  = text->enc_in_buf->data;
  real_input_token.length = text->enc_in_buf->curlen;
  
  output_token = &real_output_token;
  
  maj_stat = gss_wrap (&min_stat,
		       text->gss_ctx,
		       privacy,
		       GSS_C_QOP_DEFAULT,
		       input_token,
		       NULL,
		       output_token);
  
  if (GSS_ERROR(maj_stat))
    {
      if (output_token->value)
	  gss_release_buffer(&min_stat, output_token);
      return SASL_FAIL;
    }

  if (output_token->value && output) {
      int len;

      ret = _plug_buf_alloc(text->utils, &(text->encode_buf),
			    &text->encode_buf_len, output_token->length + 4);

      if (ret != SASL_OK) {
	  gss_release_buffer(&min_stat, output_token);
	  return ret;
      }

      len = htonl(output_token->length);
      memcpy(text->encode_buf, &len, 4);
      memcpy(text->encode_buf + 4, output_token->value, output_token->length);
  }

  if (outputlen) {
      *outputlen = output_token->length + 4;
  }

  *output = text->encode_buf;

  if (output_token->value)
      gss_release_buffer(&min_stat, output_token);

  return SASL_OK;
}

static int
sasl_gss_privacy_encode(void *context, const struct iovec *invec,
			unsigned numiov, const char **output,
			unsigned *outputlen)
{
  return sasl_gss_encode(context,invec,numiov,output,outputlen,1);
}


static int
sasl_gss_integrity_encode(void *context, const struct iovec *invec,
			unsigned numiov, const char **output,
			unsigned *outputlen) 
{
  return sasl_gss_encode(context,invec,numiov,output,outputlen,0);
}

#define myMIN(a,b) (((a) < (b)) ? (a) : (b))

static int 
sasl_gss_decode_once(void *context,
		     const char **input, unsigned *inputlen,
		     char **output, unsigned *outputlen)
{
    context_t *text = (context_t *)context;
    OM_uint32 maj_stat, min_stat;
    gss_buffer_t input_token, output_token;
    gss_buffer_desc real_input_token, real_output_token;
    unsigned diff;

    if (text->state != SASL_GSSAPI_STATE_AUTHENTICATED)
	return SASL_NOTDONE;

    /* first we need to extract a packet */
    if (text->needsize > 0) {
	/* how long is it? */
	int tocopy = myMIN(text->needsize, *inputlen);

	memcpy(text->sizebuf + 4 - text->needsize, *input, tocopy);
	text->needsize -= tocopy;
	*input += tocopy;
	*inputlen -= tocopy;

	if (text->needsize == 0) {
	    /* got the entire size */
	    memcpy(&text->size, text->sizebuf, 4);
	    text->size = ntohl(text->size);
	    text->cursize = 0;

	    if (text->size > 0xFFFF || text->size <= 0) return SASL_FAIL;

	    if (text->bufsize < text->size + 5) {
		text->buffer = text->utils->realloc(text->buffer, text->size + 5);
		text->bufsize = text->size + 5;
	    }
	    if (text->buffer == NULL) return SASL_NOMEM;
	}
	if (*inputlen == 0) {
	    /* need more data ! */
	    *outputlen = 0;
	    *output = NULL;

	    return SASL_OK;
	}
    }

    diff = text->size - text->cursize;

    if (*inputlen < diff) {
	/* ok, let's queue it up; not enough data */
	memcpy(text->buffer + text->cursize, *input, *inputlen);
	text->cursize += *inputlen;
	*outputlen = 0;
	*output = NULL;
	return SASL_OK;
    } else {
	memcpy(text->buffer + text->cursize, *input, diff);
	*input += diff;
	*inputlen -= diff;
    }

    input_token = &real_input_token; 
    real_input_token.value = text->buffer;
    real_input_token.length = text->size;
  
    output_token = &real_output_token;
    
    maj_stat = gss_unwrap (&min_stat,
			   text->gss_ctx,
			   input_token,
			   output_token,
			   NULL,
			   NULL);
    
    if (GSS_ERROR(maj_stat))
    {
	if (output_token->value)
	    gss_release_buffer(&min_stat, output_token);
	return SASL_FAIL;
    }

    if (outputlen)
	*outputlen = output_token->length;
    if (output_token->value) {
	if (output)
	    *output = output_token->value;
	else
	    gss_release_buffer(&min_stat, output_token);
    }

    /* reset for the next packet */
    text->size = -1;
    text->needsize = 4;

    return SASL_OK;
}

static int sasl_gss_decode(void *context,
			   const char *input, unsigned inputlen,
			   const char **output, unsigned *outputlen)
{
    char *tmp = NULL;
    unsigned tmplen = 0;
    context_t *text=context;
    int ret;
    
    *outputlen = 0;

    while (inputlen!=0)
    {
      ret = sasl_gss_decode_once(text, &input, &inputlen,
				 &tmp, &tmplen);

      if(ret != SASL_OK) return ret;

      if (tmp!=NULL) /* if received 2 packets merge them together */
      {
	  ret = _plug_buf_alloc(text->utils, &text->decode_buf,
				&text->decode_buf_len, *outputlen + tmplen);
	  if(ret != SASL_OK) return ret;

	  *output = text->decode_buf;
	  memcpy(text->decode_buf + *outputlen, tmp, tmplen);
	  *outputlen+=tmplen;
	  text->utils->free(tmp);
      }
    }

    return SASL_OK;    
}

static context_t *gss_new_context(const sasl_utils_t *utils)
{
    context_t *ret;

    ret = utils->malloc(sizeof(context_t));
    if(!ret) return NULL;

    memset(ret,0,sizeof(context_t));
    ret->utils = utils;

    ret->needsize = 4;

    return ret;
}

static int 
sasl_gss_server_start(void *glob_context __attribute__((unused)), 
		      sasl_server_params_t *params,
		      const char *challenge __attribute__((unused)), 
		      unsigned challen __attribute__((unused)),
		      void **conn)
{
  context_t *text;
  
  text = gss_new_context(params->utils);
  if (text == NULL) 
    return SASL_NOMEM;

  text->gss_ctx = GSS_C_NO_CONTEXT;
  text->client_name = GSS_C_NO_NAME;
  text->server_name = GSS_C_NO_NAME;
  text->server_creds = GSS_C_NO_CREDENTIAL;
  text->state = SASL_GSSAPI_STATE_AUTHNEG;

  *conn = text;

  return SASL_OK;
}

static void 
sasl_gss_free_context_contents(context_t *text)
{
  OM_uint32 maj_stat, min_stat;

  if (text->gss_ctx != GSS_C_NO_CONTEXT) {
    maj_stat = gss_delete_sec_context (&min_stat,&text->gss_ctx,GSS_C_NO_BUFFER);
    text->gss_ctx = GSS_C_NO_CONTEXT;
  }

  if (text->client_name != GSS_C_NO_NAME) {
    maj_stat = gss_release_name(&min_stat,&text->client_name);
    text->client_name = GSS_C_NO_NAME;
  }

  if (text->server_name != GSS_C_NO_NAME) {
    maj_stat = gss_release_name(&min_stat,&text->server_name);
    text->server_name = GSS_C_NO_NAME;
  }
  
  if ( text->server_creds != GSS_C_NO_CREDENTIAL) {
    maj_stat = gss_release_cred(&min_stat, &text->server_creds);
    text->server_creds = GSS_C_NO_CREDENTIAL;
  }

  if (text->encode_buf) {
      text->utils->free(text->encode_buf);
      text->encode_buf = NULL;
  }

  if (text->decode_buf) {
      text->utils->free(text->decode_buf);
      text->decode_buf = NULL;
  }
  
  if (text->enc_in_buf) {
      if(text->enc_in_buf->data) text->utils->free(text->enc_in_buf->data);
      text->utils->free(text->enc_in_buf);
      text->enc_in_buf = NULL;
  }
  
  if (text->buffer) {
      text->utils->free(text->buffer);
      text->buffer = NULL;
  }

  if (text->u.authid) { /* works for both client and server */
      text->utils->free(text->u.authid);
      text->u.authid = NULL;
  }
}

static void 
sasl_gss_dispose(void **conn_context, const sasl_utils_t *utils)
{
  sasl_gss_free_context_contents((context_t *)(*conn_context));
  utils->free(*conn_context);
  *conn_context = NULL;
}

static void 
sasl_gss_free(void *global_context, const sasl_utils_t *utils)
{
  utils->free(global_context);
}

static int 
sasl_gss_server_step (void *conn_context,
		      sasl_server_params_t *params,
		      const char *clientin,
		      unsigned clientinlen,
		      const char **serverout,
		      unsigned *serveroutlen,
		      sasl_out_params_t *oparams)
{
  context_t *text = (context_t *)conn_context;
  gss_buffer_t input_token, output_token;
  gss_buffer_desc real_input_token, real_output_token;
  OM_uint32 maj_stat, min_stat;
  gss_buffer_desc name_token;
  int ret;

  input_token = &real_input_token;
  output_token = &real_output_token;
  output_token->value = NULL; output_token->length = 0;
  input_token->value = NULL; input_token->length = 0;

  if(!serverout) return SASL_BADPARAM;

  switch (text->state)
    {
    case SASL_GSSAPI_STATE_AUTHNEG:
      
      if (clientinlen == 0)
	{
	  /* Just don't free it, but this is faster ;) */
	  *serverout = "";
	  *serveroutlen = 0;
	  
	  return SASL_CONTINUE;
	}

      if (text->server_name == GSS_C_NO_NAME) /* only once */
	{
	  name_token.length = strlen(params->service) + 1 + strlen(params->serverFQDN);
	  name_token.value = (char *)params->utils->malloc((name_token.length + 1) * sizeof(char));
	  if (name_token.value == NULL)
	    {
	      sasl_gss_free_context_contents(text);
	      return SASL_NOMEM;
	    }
	  sprintf(name_token.value,"%s@%s", params->service, params->serverFQDN);

	  maj_stat = gss_import_name (&min_stat,
				      &name_token,
				      GSS_C_NT_HOSTBASED_SERVICE,
				      &text->server_name);
	  
	  params->utils->free(name_token.value);
	  name_token.value = NULL;
	  
	  if (GSS_ERROR(maj_stat)) {
	      sasl_gss_free_context_contents(text);
	      return SASL_FAIL;
	  }

	  if ( text->server_creds != GSS_C_NO_CREDENTIAL) {
	      maj_stat = gss_release_cred(&min_stat, &text->server_creds);	  
	      text->server_creds = GSS_C_NO_CREDENTIAL;
	  }

	  maj_stat = gss_acquire_cred(&min_stat, 
				      text->server_name,
				      GSS_C_INDEFINITE, 
				      GSS_C_NO_OID_SET,
				      GSS_C_ACCEPT,
				      &text->server_creds, 
				      NULL, 
				      NULL);
	  
	  if (GSS_ERROR(maj_stat)) {
	      sasl_gss_free_context_contents(text);
	      return SASL_FAIL;
	  }
	}
      
      if(clientinlen)
	{
	  real_input_token.value = (void *)clientin;
	  real_input_token.length = clientinlen;
	}
      
      VL(("sasl_gss_server_step: AUTHNEG\n"));

      maj_stat =
	gss_accept_sec_context (&min_stat,
				&(text->gss_ctx),
				text->server_creds,
				input_token,
				GSS_C_NO_CHANNEL_BINDINGS,
				&text->client_name,
				NULL,
				output_token,
				NULL,
				NULL,
				NULL);
      
      if (GSS_ERROR(maj_stat)) {
	  if (output_token->value) {
	      gss_release_buffer(&min_stat, output_token);
	  }

	  sasl_gss_free_context_contents(text);
	  return SASL_BADAUTH;
      }
      
      if (serveroutlen)
	  *serveroutlen = output_token->length;
      if (output_token->value) {
	  if (serverout) {
	      ret = _plug_buf_alloc(text->utils, &(text->out_buf),
				    &(text->out_buf_len), *serveroutlen);
	      if(ret != SASL_OK) {
		  gss_release_buffer(&min_stat, output_token);
		  return ret;
	      }
	      memcpy(text->out_buf, output_token->value, *serveroutlen);
	      *serverout = text->out_buf;
	  }
	  
	  gss_release_buffer(&min_stat, output_token);
      }

      
      if (maj_stat == GSS_S_COMPLETE)
	{
	  VL (("GSS_S_COMPLETE\n"));
          /* Switch to ssf negotiation */
	  text->state = SASL_GSSAPI_STATE_SSFCAP;
	}
      
      return SASL_CONTINUE;
      break;
    case SASL_GSSAPI_STATE_SSFCAP:
      {
	unsigned char sasldata[4];
	gss_buffer_desc name_token;
	gss_buffer_desc name_without_realm;
	gss_name_t without = NULL;
	int equal;

	name_token.value = NULL;
	name_without_realm.value = NULL;
	VL(("sasl_gss_server_step: SSFCAP\n"));

	name_token.value = NULL;
	
	/* We ignore whatever the client sent us at this stage */

	maj_stat = gss_display_name (&min_stat,
				     text->client_name,
				     &name_token,
				     NULL);

	if (GSS_ERROR(maj_stat)) {
	    if (name_without_realm.value)
	      params->utils->free(name_without_realm.value);

	    if (name_token.value)
		gss_release_buffer(&min_stat, &name_token);
	    if (without)
		gss_release_name(&min_stat, &without);
	    sasl_gss_free_context_contents(text);
	    return SASL_BADAUTH;
	}

	/* If the id contains a realm get the identifier for the user
	   without the realm and see if it's the same id (i.e. 
	   tmartin == tmartin@ANDREW.CMU.EDU. If this is the case we just want
	   to return the id (i.e. just "tmartin" */
	if (strchr((char *)name_token.value, (int) '@')!=NULL)
	{
	    name_without_realm.value = (char *) params->utils->malloc(strlen(name_token.value)+1);
	    if (name_without_realm.value == NULL) return SASL_NOMEM;

	    strcpy(name_without_realm.value, name_token.value);

	    /* cut off string at '@' */
	    (strchr(name_without_realm.value,'@'))[0] = '\0';

	    name_without_realm.length = strlen( (char *) name_without_realm.value );

	    maj_stat = gss_import_name (&min_stat,
					&name_without_realm,
					GSS_C_NULL_OID,
					&without);
	    if (GSS_ERROR(maj_stat)) {
		params->utils->free(name_without_realm.value);
		if (name_token.value)
		    gss_release_buffer(&min_stat, &name_token);
		if (without)
		    gss_release_name(&min_stat, &without);
		sasl_gss_free_context_contents(text);
		return SASL_BADAUTH;
	    }

	    maj_stat = gss_compare_name(&min_stat,
					text->client_name,
					without,
					&equal);
    
	    if (GSS_ERROR(maj_stat)) {
		params->utils->free(name_without_realm.value);
		if (name_token.value)
		    gss_release_buffer(&min_stat, &name_token);
		if (without)
		    gss_release_name(&min_stat, &without);
		sasl_gss_free_context_contents(text);
		return SASL_BADAUTH;
	    }

	    gss_release_name(&min_stat,&without);

	} else {
	    equal = 0;
	}

	if (equal == 1) /* xxx True doesn't seem to exist in gssapi.h */
	{
	    text->u.authid = (char *) params->utils->malloc(strlen(name_without_realm.value)+1);
	    if (text->u.authid == NULL) return SASL_NOMEM;
	    strcpy(text->u.authid, name_without_realm.value);
	} else {
	    text->u.authid = (char *) params->utils->malloc(strlen(name_token.value)+1);
	    if (text->u.authid == NULL) return SASL_NOMEM;
	    strcpy(text->u.authid, name_token.value);
	}

	if (name_token.value)
	    params->utils->free(name_token.value);
	if (name_without_realm.value)
	    gss_release_buffer(&min_stat, &name_without_realm);
	
	/* we have to decide what sort of encryption/integrity/etc.,
	   we support */
	if (params->props.max_ssf < params->external_ssf) {
	    text->limitssf = 0;
	} else {
	    text->limitssf = params->props.max_ssf - params->external_ssf;
	}
	if (params->props.min_ssf < params->external_ssf) {
	    text->requiressf = 0;
	} else {
	    text->requiressf = params->props.min_ssf - params->external_ssf;
	}

	sasldata[0] = 0;
	if (text->requiressf == 0) {
	    sasldata[0] |= 1; /* authentication */
	}
	if (text->requiressf <= 1 && text->limitssf >= 1) {
	    sasldata[0] |= 2;
	}
	if (text->requiressf <= 56 && text->limitssf >= 56) {
	    sasldata[0] |= 4;
	}

	sasldata[1] = 0x0F; /* XXX use something non-artificial */
	sasldata[2] = 0xFF;
	sasldata[3] = 0xFF;
	
	real_input_token.value = (void *)sasldata;
	real_input_token.length = 4;
	
	maj_stat = gss_wrap (&min_stat,
			     text->gss_ctx,
			     0, /* Just integrity checking here */
			     GSS_C_QOP_DEFAULT,
			     input_token,
			     NULL,
			     output_token);
	
	if (GSS_ERROR(maj_stat)) {
	    if (output_token->value)
		gss_release_buffer(&min_stat, output_token);
	    sasl_gss_free_context_contents(text);
	    return SASL_FAIL;
	}


	if (serveroutlen)
            *serveroutlen = output_token->length;
        if (output_token->value) {
	  if (serverout) {
	      ret = _plug_buf_alloc(text->utils, &(text->out_buf),
				    &(text->out_buf_len), *serveroutlen);
	      if(ret != SASL_OK) {
		  gss_release_buffer(&min_stat, output_token);
		  return ret;
	      }
	      memcpy(text->out_buf, output_token->value, *serveroutlen);
	      *serverout = text->out_buf;
	  }

	  gss_release_buffer(&min_stat, output_token);
        }

	VL(("Sending %d bytes (ssfcap) to client\n",*serveroutlen));
        /* Wait for ssf request and authid */
	text->state = SASL_GSSAPI_STATE_SSFREQ; 
	
	return SASL_CONTINUE;
	
	break;
      }
    case SASL_GSSAPI_STATE_SSFREQ:
      {
	int layerchoice;

	real_input_token.value = (void *)clientin;
	real_input_token.length = clientinlen;
	
	maj_stat = gss_unwrap (&min_stat,
			       text->gss_ctx,
			       input_token,
			       output_token,
			       NULL,
			       NULL);
	
	if (GSS_ERROR(maj_stat)) {
	    sasl_gss_free_context_contents(text);
	    return SASL_FAIL;
	}
	
	layerchoice = (int)(((char *)(output_token->value))[0]);
	if (layerchoice == 1 && text->requiressf == 0) { /* no encryption */
	    oparams->encode = NULL;
	    oparams->decode = NULL;
	    oparams->mech_ssf = 0;
	} else if (layerchoice == 2 && text->requiressf <= 1 &&
		   text->limitssf >= 1) { /* integrity */
	    oparams->encode=&sasl_gss_integrity_encode;
	    oparams->decode=&sasl_gss_decode;
	    oparams->mech_ssf=1;
	} else if (layerchoice == 4 && text->requiressf <= 56 &&
		   text->limitssf >= 56) { /* privacy */
	    oparams->encode = &sasl_gss_privacy_encode;
	    oparams->decode = &sasl_gss_decode;
	    oparams->mech_ssf = 56;
	} else {
	    /* not a supported encryption layer */
	    params->utils->log(params->utils->conn, SASL_LOG_WARN,
		    "protocol violation: client requested invalid layer");
	    if (output_token->value)
		gss_release_buffer(&min_stat, output_token);
	    sasl_gss_free_context_contents(text);
	    return SASL_FAIL;
	}

	VL (("Got %d bytes from client\n",output_token->length));

	if (output_token->length > 4) {
	    int ret;

	    ret = params->canon_user(params->utils->conn,
				     ((char *) output_token->value) + 4,
				     (output_token->length - 3) * sizeof(char),
				     text->u.authid,
				     0, /* strlen(text->u.authid) */
				     0, oparams);

	    if (ret != SASL_OK) {
		sasl_gss_free_context_contents(text);
		return SASL_NOMEM;
	    }

	    VL(("Got user %s\n",oparams->user));

	    memcpy(&oparams->maxoutbuf,((char *) real_output_token.value) + 1,
		   sizeof(unsigned));
	    oparams->maxoutbuf = ntohl(oparams->maxoutbuf);
	}

	gss_release_buffer(&min_stat, output_token);
	
	text->state = SASL_GSSAPI_STATE_AUTHENTICATED;

	*serverout = NULL;
	*serveroutlen = 0;	

	return SASL_OK;
	break;
      }
    case SASL_GSSAPI_STATE_AUTHENTICATED:
	*serverout = NULL;
	*serveroutlen = 0;
      return SASL_OK;
      break;

    default:
      return SASL_FAIL;
      break;
    }

  /* we should never get here ! */
  return SASL_FAIL;
}

static const sasl_server_plug_t plugins[] = 
{
  {
    "GSSAPI",
    56, /* max ssf */
    SASL_SEC_NOPLAINTEXT | SASL_SEC_NOACTIVE | SASL_SEC_NOANONYMOUS,
    0,
    NULL,
    &sasl_gss_server_start,
    &sasl_gss_server_step,
    &sasl_gss_dispose,
    &sasl_gss_free,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
  }
};

int 
sasl_server_plug_init(
#ifndef HAVE_GSSKRB5_REGISTER_ACCEPTOR_IDENTITY
		      sasl_utils_t *utils __attribute__((unused)),
#else
		      sasl_utils_t *utils,
#endif 
		      int maxversion,
		      int *out_version,
		      const sasl_server_plug_t **pluglist,
		      int *plugcount)
{
#ifdef HAVE_GSSKRB5_REGISTER_ACCEPTOR_IDENTITY
    const char *keytab;
    unsigned int rl;
#endif

    if (maxversion < SASL_SERVER_PLUG_VERSION) {
	return SASL_BADVERS;
    }

#ifdef HAVE_GSSKRB5_REGISTER_ACCEPTOR_IDENTITY
    /* unfortunately, we don't check for readability of keytab if it's
       the standard one, since we don't know where it is */

    /* FIXME: This code is broken */

    utils->getopt(utils->getopt_context, "GSSAPI", "keytab", &keytab, &rl);
    if (keytab != NULL) {
	if (access(keytab, R_OK) != 0) {
	    utils->log(NULL, SASL_LOG_ERR,
		       "can't access keytab file %s: %m", keytab, errno);
	    return SASL_FAIL;
	}
	
	gsskrb5_register_acceptor_identity(keytab);
    }
#endif

    *pluglist = plugins;
    *plugcount = 1;  
    *out_version = SASL_SERVER_PLUG_VERSION;

    return SASL_OK;
}

static int 
sasl_gss_client_start(void *glob_context __attribute__((unused)), 
		      sasl_client_params_t *params,
		      void **conn)
{
  context_t *text;

  /* holds state are in */
  text = gss_new_context(params->utils);
  if (text == NULL) 
    return SASL_NOMEM;

  text->state = SASL_GSSAPI_STATE_AUTHNEG;
  text->gss_ctx = GSS_C_NO_CONTEXT;
  text->client_name = GSS_C_NO_NAME;
  text->server_creds = GSS_C_NO_CREDENTIAL;

  *conn = text;
  
  return SASL_OK;
}

static void 
free_prompts(sasl_client_params_t *params,
	     sasl_interact_t **prompts)
{
    if(!params || !prompts || !*prompts) return;

    params->utils->free(*prompts);
    *prompts=NULL;
}

static int
make_prompts(sasl_client_params_t *params,
	     sasl_interact_t **prompts_res,
	     int user_res,
	     int auth_res,
	     int pass_res)
{
   int num=1;
   sasl_interact_t *prompts;
 
   if (user_res==SASL_INTERACT) num++;
   if (auth_res==SASL_INTERACT) num++;
   if (pass_res==SASL_INTERACT) num++;
 
   if (num==1) return SASL_FAIL;
 
   prompts=params->utils->malloc(sizeof(sasl_interact_t)*(num+1));
   if ((prompts) ==NULL) return SASL_NOMEM;
   *prompts_res=prompts;

   if (user_res==SASL_INTERACT)
   {
     /* We weren't able to get the callback; let's try a SASL_INTERACT */
     (prompts)->id=SASL_CB_USER;
     (prompts)->challenge="Authorization Name";
     (prompts)->prompt="Please enter your authorization name";
     (prompts)->defresult=NULL;
 
     prompts++;
   }
 
   if (auth_res==SASL_INTERACT)
   {
     /* We weren't able to get the callback; let's try a SASL_INTERACT */
     (prompts)->id=SASL_CB_AUTHNAME;
     (prompts)->challenge="Authentication Name";
     (prompts)->prompt="Please enter your authentication name";
     (prompts)->defresult=NULL;
 
     prompts++;
   }
 
 
   if (pass_res==SASL_INTERACT)
   {
     /* We weren't able to get the callback; let's try a SASL_INTERACT */
     (prompts)->id=SASL_CB_PASS;
     (prompts)->challenge="Password";
     (prompts)->prompt="Please enter your password";
     (prompts)->defresult=NULL;
 
     prompts++;
   }
 
 
   /* add the ending one */
   (prompts)->id=SASL_CB_LIST_END;
   (prompts)->challenge=NULL;
   (prompts)->prompt   =NULL;
   (prompts)->defresult=NULL;
 
   return SASL_OK;
 }


static sasl_interact_t *
find_prompt(sasl_interact_t **promptlist, unsigned int lookingfor)
{
  sasl_interact_t *prompt;

  if (promptlist && *promptlist)
    for (prompt = *promptlist;
	 prompt->id != SASL_CB_LIST_END;
	 ++prompt)
      if (prompt->id==lookingfor)
	return prompt;

  return NULL;
}

static int 
get_userid(sasl_client_params_t *params,
	   char **userid, sasl_interact_t **prompt_need)
{
  int result;
  sasl_getsimple_t *getuser_cb;
  void *getuser_context;
  sasl_interact_t *prompt;
  const char *id;

  /* see if we were given the userid in the prompt */
  prompt=find_prompt(prompt_need,SASL_CB_USER);
  if (prompt!=NULL)
    {
      /* copy it */
      *userid=params->utils->malloc(prompt->len+1);
      if ((*userid)==NULL) return SASL_NOMEM;

      strncpy(*userid, prompt->result, prompt->len+1);      
      return SASL_OK;
    }

  /* Try to get the callback... */
  result = params->utils->getcallback(params->utils->conn,
				      SASL_CB_USER,
				      &getuser_cb,
				      &getuser_context);
  if (result == SASL_OK && getuser_cb) {
    id = NULL;
    result = getuser_cb(getuser_context,
			SASL_CB_USER,
			&id,
			NULL);
    if (result != SASL_OK)
      return result;
    if (! id) {
	*userid = NULL;
	return SASL_BADPARAM;
    }

    *userid = params->utils->malloc(strlen(id) + 1);
    if (! *userid)
      return SASL_NOMEM;
    strcpy(*userid, id);
  }

  return result;
}

static int 
sasl_gss_client_step (void *conn_context,
		      sasl_client_params_t *params,
		      const char *serverin,
		      unsigned serverinlen,
		      sasl_interact_t **prompt_need,
		      const char **clientout,
		      unsigned *clientoutlen,
		      sasl_out_params_t *oparams)
{
  context_t *text = (context_t *)conn_context;
  gss_buffer_t input_token, output_token;
  gss_buffer_desc real_input_token, real_output_token;
  OM_uint32 maj_stat, min_stat;
  gss_buffer_desc name_token;
  int ret;
  
  input_token = &real_input_token;
  output_token = &real_output_token;
  output_token->value = NULL;
  input_token->value = NULL; 
  input_token->length = 0;

  if (!clientout && text->state == SASL_GSSAPI_STATE_AUTHNEG) {
      /* initial client send not allowed */
      return SASL_CONTINUE;
  }

  *clientout = NULL;
  *clientoutlen = 0;

  switch (text->state)
    {
    case SASL_GSSAPI_STATE_AUTHNEG:
      {
	  VL(("sasl_gss_client_step: AUTHNEG\n"));

	  /* try to get the userid */
	  if (text->u.user ==NULL)
	  {
	    int auth_result = SASL_OK;
	    VL (("Trying to get userid\n"));

	    auth_result=get_userid(params,
				   &text->u.user,
				   prompt_need);

	    if (text->u.user) {
		VL (("Userid: %s\n",text->u.user));
	    }

	    if ((auth_result!=SASL_OK) && (auth_result!=SASL_INTERACT))
	      {
		sasl_gss_free_context_contents(text);
		return auth_result;
	      }

	    /* free prompts we got */
	    if (prompt_need)
	      free_prompts(params,prompt_need);

	    /* if there are prompts not filled in */
	    if (  (auth_result==SASL_INTERACT))
	      {
		/* make the prompt list */
		int result=make_prompts(params,prompt_need,
					auth_result, SASL_OK, SASL_OK);
		if (result!=SASL_OK) return result;
		
		return SASL_INTERACT;
	      }

	    
	    /* FIXME: This *can't* be right, (note: authid!) */
	    ret = params->canon_user(params->utils->conn,
				     text->u.user, 0,
				     text->u.user, 0,
				     0, oparams);

	    if(ret != SASL_OK) return ret;
	  }

	if (text->server_name == GSS_C_NO_NAME) /* only once */
	  {
	    name_token.length = strlen(params->service) + 1 + strlen(params->serverFQDN);
	    name_token.value = (char *)params->utils->malloc((name_token.length + 1) * sizeof(char));
	    if (name_token.value == NULL)
	      {
		sasl_gss_free_context_contents(text);
		return SASL_NOMEM;
	      }
	    if (params->serverFQDN == NULL || strlen(params->serverFQDN) == 0)
	      return SASL_FAIL;
	    sprintf(name_token.value,"%s@%s", params->service, params->serverFQDN);
	    VL(("name: %s\n",(char *)name_token.value)); /* */

	    maj_stat = gss_import_name (&min_stat,
					&name_token,
					GSS_C_NT_HOSTBASED_SERVICE,
					&text->server_name);
	    
	    params->utils->free(name_token.value);
	    name_token.value = NULL;
	    
	    if (GSS_ERROR(maj_stat))
	      {
		sasl_gss_free_context_contents(text);
		return SASL_FAIL;
	      }
	  }

	if (serverinlen)
	  {
	    real_input_token.value = (void *)serverin;
	    real_input_token.length = serverinlen;
	  }
	else if (text->gss_ctx != GSS_C_NO_CONTEXT )
         {
           /* This can't happen under GSSAPI: we have a non-null context
            * and no input from the server.  However, thanks to Imap,
            * which discards our first output, this happens all the time.
            * Throw away the context and try again. */
           maj_stat = gss_delete_sec_context (&min_stat,&text->gss_ctx,GSS_C_NO_BUFFER);
           text->gss_ctx = GSS_C_NO_CONTEXT;
         }

	maj_stat =
	  gss_init_sec_context(&min_stat,
			       GSS_C_NO_CREDENTIAL,
			       &text->gss_ctx,
			       text->server_name,
			       GSS_C_NO_OID,
			       GSS_C_MUTUAL_FLAG | GSS_C_SEQUENCE_FLAG,
			       0,
			       GSS_C_NO_CHANNEL_BINDINGS,
			       input_token,
			       NULL,
			       output_token,
			       NULL,
			       NULL);
	
	if (GSS_ERROR(maj_stat))
	{
	    if (output_token->value)
		gss_release_buffer(&min_stat, output_token);
	    sasl_gss_free_context_contents(text);
	    return SASL_FAIL;
	}

	*clientoutlen = output_token->length;

        if (output_token->value) {
	    if (clientout) {
		ret = _plug_buf_alloc(text->utils, &(text->out_buf),
				      &(text->out_buf_len), *clientoutlen);
		if(ret != SASL_OK) {
		    gss_release_buffer(&min_stat, output_token);
		    return ret;
		}
		memcpy(text->out_buf, output_token->value, *clientoutlen);
		*clientout = text->out_buf;
	    }
	    
	    gss_release_buffer(&min_stat, output_token);
        }

	if (maj_stat == GSS_S_COMPLETE)
	  {
	    VL(("GSS_S_COMPLETE\n"));
	    text->state = SASL_GSSAPI_STATE_SSFCAP; /* Switch to ssf negotiation */
	  }
	
	return SASL_CONTINUE;
	break;
      }
    case SASL_GSSAPI_STATE_SSFCAP:
      {
	sasl_security_properties_t *secprops = &(params->props);
	unsigned int alen, external = params->external_ssf;
	sasl_ssf_t need, allowed;
	char serverhas, mychoice;

	VL(("sasl_gss_client_step: SSFCAP\n"));

	real_input_token.value = (void *) serverin;
	real_input_token.length = serverinlen;

	maj_stat = gss_unwrap (&min_stat,
			       text->gss_ctx,
			       input_token,
			       output_token,
			       NULL,
			       NULL);
	
	if (GSS_ERROR(maj_stat)) {
	    sasl_gss_free_context_contents(text);
	    if (output_token->value)
		gss_release_buffer(&min_stat, output_token);
	    return SASL_FAIL;
	}
	
	/* taken from kerberos.c */
	if (secprops->min_ssf > (56 + external)) {
	    return SASL_TOOWEAK;
	} else if (secprops->min_ssf > secprops->max_ssf) {
	    return SASL_BADPARAM;
	}

	/* need bits of layer -- sasl_ssf_t is unsigned so be careful */
	if (secprops->max_ssf >= external) {
	    allowed = secprops->max_ssf - external;
	} else {
	    allowed = 0;
	}
	if (secprops->min_ssf >= external) {
	    need = secprops->min_ssf - external;
	} else {
	    /* good to go */
	    need = 0;
	}

	/* bit mask of server support */
	serverhas = ((char *)output_token->value)[0];

	/* if client didn't set use strongest layer available */
	if (allowed >= 56 && need <= 56 && (serverhas & 4)) {
	    /* encryption */
	    oparams->encode = &sasl_gss_privacy_encode;
	    oparams->decode = &sasl_gss_decode;
	    oparams->mech_ssf = 56;
	    mychoice = 4;
	    VL (("Using encryption layer\n"));
	} else if (allowed >= 1 && need <= 1 && (serverhas & 2)) {
	    /* integrity */
	    oparams->encode = &sasl_gss_integrity_encode;
	    oparams->decode = &sasl_gss_decode;
	    oparams->mech_ssf = 1;
	    mychoice = 2;
	    VL (("Using integrity layer\n"));
	} else if (need <= 0 && (serverhas & 1)) {
	    /* no layer */
	    oparams->encode = NULL;
	    oparams->decode = NULL;
	    oparams->mech_ssf = 0;
	    mychoice = 1;
	    VL (("Using no layer\n"));
	} else {
	    /* there's no appropriate layering for us! */
	    sasl_gss_free_context_contents(text);
	    return SASL_TOOWEAK;
	}
	
	gss_release_buffer(&min_stat, output_token);

	if (oparams->user)
		alen = strlen(oparams->user);
	else
		alen = 0;

	input_token->length = 4 + alen;
	input_token->value = (char *)params->utils->malloc( (input_token->length + 1)* sizeof(char));
	if (input_token->value == NULL)
	  {
	    sasl_gss_free_context_contents(text);
	    return SASL_NOMEM;
	  }
	VL(("user: %s,buflen=%d\n",oparams->user,input_token->length));
	if (oparams->user)
	    memcpy((char *)input_token->value+4,oparams->user,alen);
	
	((unsigned char *)input_token->value)[0] = mychoice;
	oparams->maxoutbuf = 1024; /* FIXME: do something real here */
	((unsigned char *)input_token->value)[1] = 0x0F;
	((unsigned char *)input_token->value)[2] = 0xFF;
	((unsigned char *)input_token->value)[3] = 0xFF;

	maj_stat = gss_wrap (&min_stat,
			     text->gss_ctx,
			     0, /* Just integrity checking here */
			     GSS_C_QOP_DEFAULT,
			     input_token,
			     NULL,
			     output_token);
	
	params->utils->free(input_token->value);
	input_token->value = NULL;
	
	if (GSS_ERROR(maj_stat))
	  {
	    if (output_token->value)
		gss_release_buffer(&min_stat, output_token);
	    sasl_gss_free_context_contents(text);
	    return SASL_FAIL;
	  }
	
	if (clientoutlen)
            *clientoutlen = output_token->length;
        if (output_token->value) {
	  if (clientout) {
	      ret = _plug_buf_alloc(text->utils, &(text->out_buf),
				    &(text->out_buf_len), *clientoutlen);
	      if(ret != SASL_OK) {
		  gss_release_buffer(&min_stat, output_token);
		  return ret;
	      }
	      memcpy(text->out_buf, output_token->value, *clientoutlen);
	      *clientout = text->out_buf;
	  }

	  gss_release_buffer(&min_stat, output_token);
        }
	
	text->state = SASL_GSSAPI_STATE_AUTHENTICATED;

	return SASL_OK;
      }
    case SASL_GSSAPI_STATE_AUTHENTICATED:
      VL(("sasl_gss_client_step: AUTHENTICATED\n"));
      return SASL_OK;
      break;

    default:
      return SASL_FAIL;
      break;
    }

  /* we should never get here!!! */
  return SASL_FAIL;
}

static const sasl_client_plug_t client_plugins[] = 
{
  {
    "GSSAPI",
    56, /* max ssf */
    SASL_SEC_NOPLAINTEXT | SASL_SEC_NOACTIVE | SASL_SEC_NOANONYMOUS,
    0,
    NULL,
    NULL,
    &sasl_gss_client_start,
    &sasl_gss_client_step,
    &sasl_gss_dispose,
    &sasl_gss_free,
    NULL,
    NULL,
    NULL
  }
};

int 
sasl_client_plug_init(sasl_utils_t *utils __attribute__((unused)), 
		      int maxversion,
		      int *out_version, 
		      const sasl_client_plug_t **pluglist,
		      int *plugcount)
{
  if (maxversion<SASL_CLIENT_PLUG_VERSION)
    return SASL_BADVERS;
  
  *pluglist=client_plugins;

  *plugcount=1;
  *out_version=SASL_CLIENT_PLUG_VERSION;

  return SASL_OK;
}
