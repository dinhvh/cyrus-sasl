/* Kerberos4 SASL plugin
 * Tim Martin 
 * $Id: kerberos4.c,v 1.65.2.1 2001/05/30 19:17:47 rjs3 Exp $
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
#include <krb.h>
#include <des.h>
#ifdef WIN32
# include <winsock.h>
#else
# include <sys/param.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>
# include <netdb.h>
#endif /* WIN32 */
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#include <sasl.h>
#include <saslutil.h>
#include <saslplug.h>

#include <errno.h>
#include <ctype.h>
#include <sys/uio.h>

#ifdef WIN32
/* This must be after sasl.h, saslutil.h */
# include "saslKERBEROSV4.h"

/* KClient doesn't define this */
typedef struct krb_principal {
    char name[ANAME_SZ];
    char instance[INST_SZ];
    char realm[REALM_SZ];
} krb_principal;

/* This isn't defined under WIN32.  For access() */
#ifndef R_OK
#define R_OK 04
#endif
/* we also need io.h for access() prototype */
#include <io.h>
#endif /* WIN32 */

static const char rcsid[] = "$Implementation: Carnegie Mellon SASL " VERSION " $";

#ifdef L_DEFAULT_GUARD
# undef L_DEFAULT_GUARD
# define L_DEFAULT_GUARD (0)
#endif

#ifdef sun
/* gotta define gethostname ourselves on suns */
extern int gethostname(char *, int);
#endif

#define KERBEROS_VERSION (SASL_CLIENT_PLUG_VERSION)

#define KRB_SECFLAG_NONE (1)
#define KRB_SECFLAG_INTEGRITY (2)
#define KRB_SECFLAG_ENCRYPTION (4)
#define KRB_SECFLAGS (7)
#define KRB_SECFLAG_CREDENTIALS (8)

#define KRB_DES_SECURITY_BITS (56)
#define KRB_INTEGRITY_BITS (1)

typedef struct context {
  int state;

  int challenge;         /* this is the challenge (32 bit int) used 
			    for the authentication */

  char *service;                   /* kerberos service */
  char instance[ANAME_SZ];
  char pname[ANAME_SZ];
  char pinst[INST_SZ];
  char prealm[REALM_SZ];
  char *hostname;                  /* hostname */
  char *realm;                     /* kerberos realm */
  char *auth;                      /* */

  CREDENTIALS credentials;

  des_cblock key;                  /* session key */
  des_cblock session;              /* session key */

  des_key_schedule init_keysched;  /* key schedule for initialization */
  des_key_schedule enc_keysched;   /* encryption key schedule */
  des_key_schedule dec_keysched;   /* decryption key schedule */


  struct sockaddr_in ip_local;     /* local ip address and port.
				       needed for layers */
  struct sockaddr_in ip_remote;    /* remote ip address and port.
				       needed for layers */

  sasl_malloc_t *malloc;           /* encode and decode need these */
  sasl_realloc_t *realloc;       
  sasl_free_t *free;

  char *encode_buf;                /* For encoding/decoding mem management */
  char *decode_buf;
  char *out_buf;
  unsigned encode_buf_len;
  unsigned decode_buf_len;
  unsigned out_buf_len;

  char *user;                      /* used by client */

  char *buffer;                    /* used for layers */
  int bufsize;
  char sizebuf[4];
  int cursize;
  int size;
  int needsize;
  int secflags; /* client/server supports layers? */

  long time_sec; /* These are used to make sure we are getting */
  char time_5ms; /* strictly increasing timestamps */

} context_t;


/* FIXME: A *GLOBAL VARIABLE*? Don't we want the POSSIBILITY of this being
 * thread-safe? */
static char *srvtab = NULL;

/* FIXME: These shouldn't really be needed on a per-plugin basis! */
/* FIXME: This only parses IPV4 addresses */
int _sasl_ipfromstring(const char *addr, struct sockaddr_in *out) 
{
    int i;
    unsigned int val = 0;
    unsigned int port;
    
    if(!addr || !out) return SASL_BADPARAM;

    /* Parse the address */
    for(i=0; i<4 && *addr && *addr != ';'; i++) {
	int inval;
	
	inval = atoi(addr);
	if(inval < 0 || inval > 255) return SASL_BADPARAM;

	val = val << 8;
	val |= inval;
	
        for(;*addr && *addr != '.' && *addr != ';'; addr++)
	    if(!isdigit(*addr)) return SASL_BADPARAM;

	/* skip the separator */
	addr++;
    }
    
    /* We have a bad ip address if we have less than 4 octets, or
     * if we didn't just skip a semicolon */
    if(i!=4 || *(addr-1) != ';') return SASL_BADPARAM;
    
    port = atoi(addr);

    /* Ports can only be 16 bits in IPV4 */
    if((port & 0xFFFF) != port) return SASL_BADPARAM;
        
    for(;*addr;addr++)
	if(!isdigit(*addr)) return SASL_BADPARAM;
    
    bzero(out, sizeof(struct sockaddr_in));
    out->sin_addr.s_addr = val;
    out->sin_port = port;

    return SASL_OK;
}

static int
_iovec_to_buf(context_t *text, const struct iovec *vec, unsigned numiov,
	      char **output, unsigned *outputlen) 
{
    unsigned i;
    char *pos;
    
    *outputlen = 0;
    for(i=0; i<numiov; i++)
	*outputlen += vec[i].iov_len;

    *output = text->malloc(*outputlen);
    if(!output) return SASL_NOMEM;
    
    bzero(*output, *outputlen);
    pos = *output;
    
    for(i=0; i<numiov; i++) {
	memcpy(pos, vec[i].iov_base, vec[i].iov_len);
	pos += vec[i].iov_len;
    }

    return SASL_OK;
}

/* Basically a conditional call to realloc(), if we need more */
static int _buf_alloc(context_t *text, char **rwbuf,
		      unsigned *curlen, unsigned newlen) 
{
    if(!(*rwbuf)) {
	*rwbuf = text->malloc(newlen);
	if (*rwbuf == NULL) {
	    *curlen = 0;
	    return SASL_NOMEM;
	}
	*curlen = newlen;
    } else if(*rwbuf && *curlen < newlen) {
	*rwbuf = text->realloc(*rwbuf, newlen);
	if (*rwbuf == NULL) {
	    *curlen = 0;
	    return SASL_NOMEM;
	}
	*curlen = newlen;
    } 

    return SASL_OK;
}


static int privacy_encode(void *context,
			  const struct iovec *invec,
			  unsigned numiov,
			  const char **output,
			  unsigned *outputlen)
{
  unsigned inputlen;
  int len, ret;
  char *input;
  context_t *text;
  text=context;

  ret = _iovec_to_buf(text, invec, numiov, &input, &inputlen);
  if(ret != SASL_OK) return ret;

  ret = _buf_alloc(text, &(text->encode_buf), &text->encode_buf_len,
		   inputlen+40);
  if(ret != SASL_OK) {
      text->free(input);
      return ret;
  }

  len=krb_mk_priv((char *) input, text->encode_buf+4,
		  inputlen,  text->init_keysched, 
		  &text->session, &text->ip_local,
		  &text->ip_remote);

  /* returns -1 on error */
  if (len==-1) return SASL_FAIL;

  text->free(input);

  /* now copy in the len of the buffer in network byte order */
  *outputlen=len+4;
  len=htonl(len);
  memcpy(text->encode_buf, &len, 4);

  /* Setup the const pointer */
  *output = text->encode_buf;
  
  return SASL_OK;
}


static int privacy_decode_once(void *context,
			       const char **input, unsigned *inputlen,
			       char **output, unsigned *outputlen)
{
    int len, tocopy;
    unsigned diff;
    MSG_DAT *data;
    context_t *text=context;

    if (text->needsize>0) { /* 4 bytes for how long message is */
	/* if less than 4 bytes just copy those we have into text->size */
	if (*inputlen<4) 
	    tocopy=*inputlen;
	else
	  tocopy=4;
      
	if (tocopy>text->needsize)
	    tocopy=text->needsize;

	memcpy(text->sizebuf+4-text->needsize, *input, tocopy);
	text->needsize-=tocopy;
	
	*input+=tocopy;
	*inputlen-=tocopy;

	if (text->needsize==0) /* got all of size */
	{
	    memcpy(&(text->size), text->sizebuf, 4);
	    text->cursize=0;
	    text->size=ntohl(text->size);
	    
	    /* too big? */
	    if ((text->size>0xFFFF) || (text->size < 0)) return SASL_FAIL;
	    
	    if (text->bufsize < text->size + 5) {
		text->buffer = text->realloc(text->buffer, text->size + 5);
		text->bufsize = text->size + 5;
	    }
	    if (text->buffer == NULL) return SASL_NOMEM;
	}
	*outputlen=0;
	*output=NULL;
	if (*inputlen==0) /* have to wait until next time for data */
	    return SASL_OK;
	
	if (text->size==0)  /* should never happen */
	    return SASL_FAIL;
    }
    
    diff=text->size - text->cursize; /* bytes need for full message */
    
    if (! text->buffer)
	return SASL_FAIL;
    
    if (*inputlen < diff) { /* not enough for a decode */
	memcpy(text->buffer+text->cursize, *input, *inputlen);
	text->cursize+=*inputlen;
	*outputlen=0;
	*output=NULL;
	return SASL_OK;
    } else {
	memcpy(text->buffer+text->cursize, *input, diff);
	*input+=diff;      
	*inputlen-=diff;
    }
    
    data=text->malloc(sizeof(MSG_DAT));
    if (data==NULL) return SASL_NOMEM;
    memset(data,0,sizeof(MSG_DAT));
    
    len= krb_rd_priv((char *) text->buffer,text->size,  text->init_keysched, 
		     &text->session, &text->ip_remote, &text->ip_local, data);

    /* see if the krb library gave us a failure */
    if (len != 0) {
	return SASL_FAIL;
    }

    /* check to make sure the timestamps are ok */
    if ((data->time_sec < text->time_sec) || /* if an earlier time */
	(((data->time_sec == text->time_sec) && /* or the exact same time */
	 (data->time_5ms < text->time_5ms)))) 
    {
      return SASL_FAIL;
    }
    text->time_sec = data->time_sec;
    text->time_5ms = data->time_5ms;

    *output = text->malloc(data->app_length + 1);
    if ((*output) == NULL) {
	return SASL_NOMEM;
    }
    
    *outputlen = data->app_length;
    memcpy(*output, data->app_data, data->app_length);
    (*output)[*outputlen] = '\0';

    text->free(data);
    text->size = -1;
    text->needsize = 4;

    return SASL_OK;
}

static int privacy_decode(void *context,
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
      ret = privacy_decode_once(text, &input, &inputlen,
				&tmp, &tmplen);

      if(ret != SASL_OK) return ret;

      if (tmp!=NULL) /* if received 2 packets merge them together */
      {
	  ret = _buf_alloc(text, &text->decode_buf, &text->decode_buf_len,
			   *outputlen + tmplen);
	  if(ret != SASL_OK) return ret;

	  *output = text->decode_buf;
	  memcpy(text->decode_buf + *outputlen, tmp, tmplen);
	  *outputlen+=tmplen;
	  text->free(tmp);
      }
    }

    return SASL_OK;
}

static int
integrity_encode(void *context,
		 const struct iovec *invec,
		 unsigned numiov,
		 const char **output,
		 unsigned *outputlen)
{
  unsigned inputlen;
  int len, ret;
  char *input;
  context_t *text;
  text=context;

  ret = _iovec_to_buf(text, invec, numiov, &input, &inputlen);
  if(ret != SASL_OK) return ret;

  ret = _buf_alloc(text, &text->encode_buf, &text->encode_buf_len,
		   inputlen+40);

  if(ret != SASL_OK) {
      text->free(input);
      return ret;
  }
  
  len=krb_mk_safe((char *) input, (text->encode_buf+4), inputlen,
		  &text->session, &text->ip_local, &text->ip_remote);

  /* returns -1 on error */
  if (len==-1) return SASL_FAIL;

  text->free(input);

  /* now copy in the len of the buffer in network byte order */
  *outputlen=len+4;
  len=htonl(len);
  memcpy(text->encode_buf, &len, 4);

  /* Setup the const pointer */
  *output = text->encode_buf;
  
  return SASL_OK;
}

static int integrity_decode_once(void *context,
				 const char **input, unsigned *inputlen,
				 char **output, unsigned *outputlen)
{
    int len, tocopy;
    MSG_DAT *data;
    context_t *text=context;
    unsigned diff;

    if (text->needsize>0) /* 4 bytes for how long message is */
    {
      /* if less than 4 bytes just copy those we have into text->size */
      if (*inputlen<4) 
	tocopy=*inputlen;
      else
	tocopy=4;
      
      if (tocopy>text->needsize)
	tocopy=text->needsize;

      memcpy(text->sizebuf+4-text->needsize, *input, tocopy);
      text->needsize-=tocopy;

      *input+=tocopy;
      *inputlen-=tocopy;

      if (text->needsize==0) /* got all of size */
      {
	memcpy(&(text->size), text->sizebuf, 4);
	text->cursize=0;
	text->size=ntohl(text->size);
	if ((text->size>0xFFFF) || (text->size < 0)) return SASL_FAIL; /* too big probably error */

	if (text->bufsize < text->size) {
	    text->buffer = text->realloc(text->buffer, text->size);
	    text->bufsize = text->size;
	}
	if (text->buffer == NULL) return SASL_NOMEM;
      }

      *outputlen=0;
      *output=NULL;
      if (*inputlen==0) /* have to wait until next time for data */
	return SASL_OK;

      if (text->size==0)  /* should never happen */
	return SASL_FAIL;
    }

    diff=text->size - text->cursize; /* bytes need for full message */

    if (*inputlen < diff) /* not enough for a decode */
    {

      memcpy(text->buffer+text->cursize, *input, *inputlen);
      text->cursize+=*inputlen;
      *inputlen=0;
      *outputlen=0;
      *output=NULL;
      return SASL_OK;
    } else {
      memcpy(text->buffer+text->cursize, *input, diff);
      input+=diff;      
      *inputlen-=diff;
    }
  
    data=text->malloc(sizeof(MSG_DAT));
    if (data==NULL) return SASL_NOMEM;

    len = krb_rd_safe((char *) text->buffer, text->size,
		     &text->session, &text->ip_remote, &text->ip_local, data);

    /* see if the krb library found a problem with what we were given */
    if (len!=0)
    {
      return SASL_FAIL;
    }

    /* check to make sure the timestamps are ok */
    if ((data->time_sec < text->time_sec) || /* if an earlier time */
	(((data->time_sec == text->time_sec) && /* or the exact same time */
	 (data->time_5ms < text->time_5ms)))) 
    {
      return SASL_FAIL;
    }
    text->time_sec = data->time_sec;
    text->time_5ms = data->time_5ms;

    *output=text->malloc(data->app_length+1);
    if ((*output) == NULL) return SASL_NOMEM;
 
    *outputlen=data->app_length;
    memcpy((char *)*output, data->app_data,data->app_length);

    text->free(data);
    text->size=-1;
    text->needsize=4;

    return SASL_OK;
}

static int integrity_decode(void *context,
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
      ret = integrity_decode_once(text, &input, &inputlen,
			   &tmp, &tmplen);

      if(ret != SASL_OK) return ret;

      if (tmp!=NULL) /* if received 2 packets merge them together */
      {
	  ret = _buf_alloc(text, &text->decode_buf, &text->decode_buf_len,
			   *outputlen + tmplen);

	  *output = text->decode_buf;
	  memcpy(text->decode_buf + *outputlen, tmp, tmplen);
	  *outputlen+=tmplen;
	  text->free(tmp);
      }
    }

    return SASL_OK;
}


static int
new_text(const sasl_utils_t *utils, context_t **text)
{
    context_t *ret = (context_t *) utils->malloc(sizeof(context_t));

    if (ret==NULL) return SASL_NOMEM;

    ret->malloc = utils->malloc;
    ret->realloc = utils->realloc;
    ret->free = utils->free;

    ret->encode_buf = NULL;
    ret->decode_buf = NULL;
    ret->out_buf = NULL;
    ret->encode_buf_len = 0;
    ret->decode_buf_len = 0;
    ret->out_buf_len = 0;
    
    ret->user = NULL;

    ret->buffer = NULL;
    ret->bufsize = 0;

    ret->time_sec = 0;
    ret->time_5ms = 0;

    ret->state = 0;  
    *text = ret;

    return SASL_OK;
}

static int
server_start(void *glob_context __attribute__((unused)),
	     sasl_server_params_t *sparams,
	     const char *challenge __attribute__((unused)),
	     unsigned challen __attribute__((unused)),
	     void **conn_context)
{
  return new_text(sparams->utils, (context_t **) conn_context);
}



static void dispose(void **conn_context, const sasl_utils_t *utils)
{
    context_t *text;
    text = (context_t *)(*conn_context);

    if (text->buffer) utils->free(text->buffer);
    if (text->encode_buf) utils->free(text->encode_buf);
    if (text->decode_buf) utils->free(text->decode_buf);
    if (text->out_buf) utils->free(text->out_buf);
    if (text->user) utils->free(text->user);
    
    utils->free(text);
    *conn_context = NULL;
}

static void mech_free(void *glob_context __attribute__((unused)),
		      const sasl_utils_t *utils)
{
    if (srvtab) utils->free(srvtab);
}

static int cando_sec(sasl_security_properties_t *props,
		     int secflag)
{
  switch (secflag) {
  case KRB_SECFLAG_NONE:
    if (props->min_ssf == 0)
      return 1;
    break;
  case KRB_SECFLAG_INTEGRITY:
    if ((props->min_ssf <= KRB_INTEGRITY_BITS)
	&& (KRB_INTEGRITY_BITS <= props->max_ssf))
      return 1;
    break;
  case KRB_SECFLAG_ENCRYPTION:
    if ((props->min_ssf <= KRB_DES_SECURITY_BITS)
	&& (KRB_DES_SECURITY_BITS <= props->max_ssf))
      return 1;
    break;
  case KRB_SECFLAG_CREDENTIALS:
    if (props->security_flags & SASL_SEC_PASS_CREDENTIALS)
      return 1;
    break;
  }
  return 0;
}

static int server_continue_step (void *conn_context,
	      sasl_server_params_t *sparams,
	      const char *clientin,
	      unsigned clientinlen,
	      const char **serverout,
	      unsigned *serveroutlen,
	      sasl_out_params_t *oparams)
{
  int result;
  context_t *text=conn_context;

  if (text->state==0)
  {    
      /* random 32-bit number */
      int randocts, nchal;

      /* shouldn't we check for erroneous client input here?!? */

    VL(("KERBEROS_V4 Step 1\n"));
    
    sparams->utils->rand(sparams->utils->rpool,(char *) &randocts ,
			 sizeof(randocts));    
    text->challenge=randocts; 
    nchal=htonl(text->challenge);

    result = _buf_alloc(text, &text->out_buf, &text->out_buf_len, 5);
    if(result != SASL_OK)
	return result;

    memcpy(text->out_buf,&nchal,4);
    *serverout = text->out_buf;
    *serveroutlen=4;

    text->state=1;
    return SASL_CONTINUE;
  }

  if (text->state == 1) {
    int nchal;
    unsigned char sout[8];  
    AUTH_DAT ad;
    KTEXT_ST ticket;
    unsigned lup;
    struct sockaddr_in addr;

    VL(("KERBEROS_V4 Step 2\n"));

    /* received authenticator */

    /* create ticket */
    if (clientinlen > MAX_KTXT_LEN)
	/* Request larger than maximum ticket size */
	return SASL_FAIL;

    ticket.length=clientinlen;
    for (lup=0;lup<clientinlen;lup++)      
      ticket.dat[lup]=clientin[lup];

    text->realm = krb_realmofhost(sparams->serverFQDN);

    /* get instance */
    strncpy (text->instance, krb_get_phost (sparams->serverFQDN),
	     sizeof (text->instance));
    text->instance[sizeof(text->instance)-1] = 0;

    memset(&addr, 0, sizeof(struct sockaddr_in));
#define KRB4_IGNORE_IP_ADDRESS
#ifndef KRB4_IGNORE_IP_ADDRESS
    /* (we ignore IP addresses in krb4 tickets at CMU to facilitate moving
        from machine to machine) */

    /* get ip number in addr*/
    result = _sasl_ipfromstring(sparams->ipremoteport, &addr);
    if (result != SASL_OK)
	/* couldn't get remote IP address */
	return result;
#endif

    /* check ticket */
    result = krb_rd_req(&ticket, (char *) sparams->service, text->instance, 
			addr.sin_addr.s_addr, &ad, srvtab);

    if (result) { /* if fails mechanism fails */
	VL(("krb_rd_req failed service=%s instance=%s error code=%i\n",
	    sparams->service, text->instance,result));
	return SASL_BADAUTH;
    }

    /* 8 octets of data
     * 1-4 checksum+1
     * 5 security layers
     * 6-8max cipher text buffer size
     * use DES ECB in the session key
     */
    
    nchal=htonl(text->challenge+1);
    memcpy(sout, &nchal, 4);
    sout[4]= 0;
    if (cando_sec(&sparams->props, KRB_SECFLAG_NONE))
      sout[4] |= KRB_SECFLAG_NONE;
    if (cando_sec(&sparams->props, KRB_SECFLAG_INTEGRITY))
      sout[4] |= KRB_SECFLAG_INTEGRITY;
    if (cando_sec(&sparams->props, KRB_SECFLAG_ENCRYPTION))
      sout[4] |= KRB_SECFLAG_ENCRYPTION;
    if (cando_sec(&sparams->props, KRB_SECFLAG_CREDENTIALS))
      sout[4] |= KRB_SECFLAG_CREDENTIALS;
    sout[5]=0x00;  /* max ciphertext buffer size */
    sout[6]=0xFF;  /* let's say we can support up to 64K */
    sout[7]=0xFF;  /* no inherent inability with our layers to support more */

    memcpy(text->session, ad.session, 8);
    memcpy(text->pname, ad.pname, sizeof(text->pname));
    memcpy(text->pinst, ad.pinst, sizeof(text->pinst));
    memcpy(text->prealm, ad.prealm, sizeof(text->prealm));
    des_key_sched(&ad.session, text->init_keysched);

    /* make keyschedule for encryption and decryption */
    des_key_sched(&ad.session, text->enc_keysched);
    des_key_sched(&ad.session, text->dec_keysched);
    
    des_ecb_encrypt((des_cblock *)sout,
		    (des_cblock *)sout,
		    text->init_keysched,
		    DES_ENCRYPT);
   
    result = _buf_alloc(text, &text->out_buf, &text->out_buf_len, 9);
    if(result != SASL_OK)
	return result;

    memcpy(text->out_buf,&sout,8);
    *serverout = text->out_buf;
    *serveroutlen=8;
   
    text->state=2;
    return SASL_CONTINUE;
  }

  if (text->state==2)
  {
    int result;
    int testnum;
    int flag;
    unsigned char *in;

    if ((clientinlen==0) || (clientinlen % 8 != 0))
	/* Response to challenge is not a multiple of 8 octets (a DES block) */
	return SASL_FAIL;	

    /* we need to make a copy because des does in place decrpytion */
    in = sparams->utils->malloc(clientinlen + 1);
    if (in == NULL) return SASL_NOMEM;
    memcpy(in, clientin, clientinlen);
    in[clientinlen]='\0';

    /* decrypt; verify checksum */

    des_pcbc_encrypt((des_cblock *)in,
		     (des_cblock *)in,
		     clientinlen,
		     text->init_keysched,
		     &text->session,
		     DES_DECRYPT);

    testnum=(in[0]*256*256*256)+(in[1]*256*256)+(in[2]*256)+in[3];

    if (testnum != text->challenge)
	/* incorrect response to challenge */
	return SASL_BADAUTH;

    if (! cando_sec(&sparams->props, in[4] & KRB_SECFLAGS)) {
	/* invalid security property specified */
	return SASL_BADPROT;
    }
    
    switch (in[4] & KRB_SECFLAGS) {
    case KRB_SECFLAG_NONE:
	oparams->encode=NULL;
	oparams->decode=NULL;
	oparams->mech_ssf=0;
	break;
    case KRB_SECFLAG_INTEGRITY:
	oparams->encode=&integrity_encode;
	oparams->decode=&integrity_decode;
	oparams->mech_ssf=KRB_INTEGRITY_BITS;
	break;
    case KRB_SECFLAG_ENCRYPTION:
	oparams->encode=&privacy_encode;
	oparams->decode=&privacy_decode;
	oparams->mech_ssf=KRB_DES_SECURITY_BITS;
	break;
    default:
        /* not a supported encryption layer */
	return SASL_BADPROT;
    }

    /* get ip data */
    /* get ip number in addr*/
    result = _sasl_ipfromstring(sparams->iplocalport, &(text->ip_local));
    if (result != SASL_OK) {
	/* couldn't get local IP address */
	return result;
    }

    result = _sasl_ipfromstring(sparams->ipremoteport, &(text->ip_remote));
    if (result != SASL_OK) {
	/* couldn't get remote IP address */
	return result;
    }

    text->malloc=sparams->utils->malloc;        
    text->free=sparams->utils->free;

    /* fill in oparams */
    oparams->maxoutbuf = (in[5] << 16) + (in[6] << 8) + in[7];
    oparams->param_version = 0;
    
    if(sparams->canon_user)
    {
      char *user=NULL, *authid=NULL;
      size_t ulen = 0, alen = strlen(text->pname);
      int ret;

      if (text->pinst[0]) {
	alen += strlen(text->pinst) + 1 /* for the . */;
      }
      flag = 0;
      if (strcmp(text->realm, text->prealm)) {
	alen += strlen(text->prealm) + 1 /* for the @ */;
	flag = 1;
      }

      authid = sparams->utils->malloc(alen + 1);
      if (!authid)
	return SASL_NOMEM;
      strcpy(authid, text->pname);
      if (text->pinst[0]) {
	strcat(authid, ".");
	strcat(authid, text->pinst);
      }
      if (flag) {
	strcat(authid, "@");
	strcat(authid, text->prealm);
      }

      if (in[8]) {
	  user = sparams->utils->malloc(strlen((char *) in + 8) + 1);
	  if (!user) return SASL_NOMEM;
	  strcpy(user, (char *) in + 8);
	  ulen = strlen(user);
      } else {
	  user = authid;
	  ulen = alen;
      }

      ret = sparams->canon_user(sparams->utils->conn, user, ulen,
				authid, alen, 0, oparams);
      
      sparams->utils->free(authid);
      if(user != authid)
	  sparams->utils->free(user);

      if(ret != SASL_OK) 
	  return ret;
    }

    /* output */
    *serverout = NULL;
    *serveroutlen = 0;

    /* nothing more to do; authenticated */
    oparams->doneflag=1;

    text->size=-1;
    text->needsize=4;

    sparams->utils->free(in);
    return SASL_OK;
  }
  
  /* Improper step. Probably application error */
  return SASL_FAIL; /* should never get here */
}

static const sasl_server_plug_t plugins[] = 
{
  {
    "KERBEROS_V4",
    KRB_DES_SECURITY_BITS,
    SASL_SEC_NOPLAINTEXT | SASL_SEC_NOACTIVE | SASL_SEC_NOANONYMOUS,
    0,
    NULL,
    &server_start,
    &server_continue_step,
    &dispose,
    &mech_free,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
  }
};

int sasl_server_plug_init(sasl_utils_t *utils,
			  int maxversion,
			  int *out_version,
			  const sasl_server_plug_t **pluglist,
			  int *plugcount)
{
    const char *ret;
    unsigned int rl;
    
    if (maxversion < KERBEROS_VERSION) {
	return SASL_BADVERS;
    }

    utils->getopt(utils->getopt_context, "KERBEROS_V4", "srvtab", &ret, &rl);

    if (ret == NULL) {
	ret = KEYFILE;
	rl = strlen(ret);
    }
    srvtab = utils->malloc(sizeof(char) * (rl + 1));
    strcpy(srvtab, ret);

    /* fail if we can't open the srvtab file */
    if (access(srvtab, R_OK) != 0) {
	utils->log(NULL, SASL_LOG_ERR,
		   "can't access srvtab file %s: %m", srvtab, errno);
	utils->free(srvtab);
	return SASL_FAIL;
    }

    *pluglist = plugins;

    *plugcount = 1;
    *out_version = KERBEROS_VERSION;
    
    return SASL_OK;
}

static int client_start(void *glob_context __attribute__((unused)), 
		 sasl_client_params_t *params,
		 void **conn)
{
  VL(("KERBEROS_V4 Client start\n"));

  return new_text(params->utils, (context_t **) conn);
}

/* FIXME?: Freeing results is responsibility of caller */
static void free_prompts(sasl_client_params_t *params,
			 sasl_interact_t *prompts)
{
    sasl_interact_t *ptr=prompts;
    if (ptr==NULL) return;
    params->utils->free(prompts);
    prompts = NULL;
}

static int client_continue_step (void *conn_context,
				 sasl_client_params_t *cparams,
				 const char *serverin,
				 unsigned serverinlen,
				 sasl_interact_t **prompt_need,
				 const char **clientout,
				 unsigned *clientoutlen,
				 sasl_out_params_t *oparams)
{
    KTEXT_ST authent;
    context_t *text=conn_context;
    int ret;

    authent.length = MAX_KTXT_LEN;
  
    if (text->state==0)
    {
	VL(("KERBEROS_V4 Step 1\n"));

	if (clientout) {
	    *clientout = NULL;
	    *clientoutlen = 0;
	}

	text->state=1;

	return SASL_CONTINUE;
    }

    else if (text->state==1) {
	/* We should've just recieved a 32-bit number in network byte order.
	 * We want to reply with an authenticator. */
	int result;
	KTEXT_ST ticket;

	VL(("KERBEROS_V4 Step 2\n"));

	memset(&ticket, 0L, sizeof(ticket));
	ticket.length=MAX_KTXT_LEN;   

	if (serverinlen != 4) {
	    cparams->utils->log(NULL, SASL_LOG_ERR,
			       "server challenge not 4 bytes long");
	    return SASL_FAIL; 
	}

	memcpy(&text->challenge, serverin, 4);

	text->challenge=ntohl(text->challenge); 

	if (cparams->serverFQDN == NULL) {
	    cparams->utils->log(NULL, SASL_LOG_ERR,
				"no 'serverFQDN' set");
	    return SASL_BADPARAM;
	}
	if (cparams->service == NULL) {
	    cparams->utils->log(NULL, SASL_LOG_ERR,
				"no 'service' set");
	    return SASL_BADPARAM;
	}

	text->realm=krb_realmofhost(cparams->serverFQDN);
	text->hostname=(char *) cparams->serverFQDN;

	/* the instance of the principal we're authenticating with */
	strncpy (text->instance, krb_get_phost (cparams->serverFQDN), 
		 sizeof (text->instance));
	/* text->instance is NULL terminated unless it was too long */
	text->instance[sizeof(text->instance)-1] = '\0';

	if ((result=krb_mk_req(&ticket, (char *) cparams->service, 
			       text->instance, text->realm, text->challenge)))
	{
	    cparams->utils->log(NULL, SASL_LOG_ERR, 
			       "krb_mk_req() failed: %s (%d)",
			       krb_err_txt[result], result);
	    return SASL_FAIL;
	}

	ret = _buf_alloc(text, &(text->out_buf), &(text->out_buf_len),
			 ticket.length);
	if(ret != SASL_OK) return ret;
	
	memcpy(text->out_buf, ticket.dat, ticket.length);

	*clientout=text->out_buf;
	*clientoutlen=ticket.length;

	text->state=2;
	return SASL_CONTINUE;
    }

    /* challenge #2 */
    else if (text->state==2) {
	int need = 0;
	int musthave = 0;
	int testnum;
	int nchal;    
	unsigned char *sout = NULL;
	unsigned len;
	unsigned char in[8];
	const char *userid;
	int result;
	sasl_getsimple_t *getuser_cb;
	void *getuser_context;
	sasl_interact_t *prompt;
	int prompt_for_userid = 0;
	int servermaxbuf;
	char *buf;

	if (prompt_need && *prompt_need) {
	    /* If we requested prompts, make sure they're
	     * properly filled in. */
	    for (prompt = *prompt_need;
		 prompt->id != SASL_CB_LIST_END;
		 ++prompt)
		if (! prompt->result)
		    return SASL_BADPARAM;

	    /* Get the username */
	    if (! text->user) {
		for (prompt = *prompt_need;
		     prompt->id != SASL_CB_LIST_END;
		     ++prompt)
		    if (prompt->id == SASL_CB_USER) {
			text->user = cparams->utils->malloc(strlen(prompt->result) + 1);
			if(!text->user) return SASL_NOMEM;
			strcpy(text->user, prompt->result);
			
			break;
		    }
	    }
	    
	    free_prompts(cparams, *prompt_need);
	    *prompt_need = NULL;
	}

	/* Now, try to get the userid by normal means... */
	if (! text->user) {
	    /* Try to get the callback... */
	    result = cparams->utils->getcallback(cparams->utils->conn,
						 SASL_CB_USER,
						 &getuser_cb,
						 &getuser_context);
	    switch (result) {
	    case SASL_INTERACT:
		/* We'll set up an interaction later. */
		prompt_for_userid = 1;
		break;
	    case SASL_OK:
		if (! getuser_cb)
		    break;
		result = getuser_cb(getuser_context,
				    SASL_CB_USER,
				    &userid,
				    NULL);
		if (result != SASL_OK)
		    return result;
		if (userid) {		    
		    text->user = cparams->utils->malloc(strlen(userid) + 1);
		    if (!text->user) return SASL_NOMEM;
		    strcpy(text->user, userid);
		}
		break;
	    default:
		return result;
	    }
	}
      
	/* And now, if we *still* don't have userid,
	 * but we think we can prompt, we need to set up a prompt. */
	if (! text->user && prompt_for_userid) {
	    if (! prompt_need)
		return SASL_INTERACT;
	    *prompt_need = cparams->utils->malloc(sizeof(sasl_interact_t) * 2);
	    if (! *prompt_need)
		return SASL_NOMEM;
	    prompt = *prompt_need;
	    prompt->id = SASL_CB_USER;
	    prompt->prompt = "Remote Userid";
	    prompt->defresult = NULL;
	    prompt++;
	    prompt->id = SASL_CB_LIST_END;
	    return SASL_INTERACT;
	}
      
	/* must be 8 octets */
	if (serverinlen!=8) {
	    cparams->utils->log(NULL, SASL_LOG_ERR,
			        "server response not 8 bytes long");
	    return SASL_BADAUTH;
	}

	memcpy(in, serverin, 8);

	/* get credentials */
	if ((result = krb_get_cred((char *)cparams->service,
			  text->instance,
			  text->realm,
			  &text->credentials)) != 0) {
	    cparams->utils->log(NULL, SASL_LOG_ERR,
				"krb_get_cred() failed: %s (%d)",
				krb_err_txt[result], result);
	    return SASL_BADAUTH;
	}

	memcpy(text->session, text->credentials.session, 8);

	/* make key schedule for encryption and decryption */
	des_key_sched(&text->session, text->init_keysched);
	des_key_sched(&text->session, text->enc_keysched);
	des_key_sched(&text->session, text->dec_keysched);

	/* decrypt from server */
	des_ecb_encrypt((des_cblock *)in, (des_cblock *)in,
			text->init_keysched, DES_DECRYPT);

	/* convert to 32bit int */
	testnum = (in[0]*256*256*256)+(in[1]*256*256)+(in[2]*256)+in[3];

	/* verify data 1st 4 octets must be equal to chal+1 */
	if (testnum != text->challenge+1)
	{
	    cparams->utils->log(NULL, SASL_LOG_ERR,
				"server response incorrect");
	    return SASL_BADAUTH;
	}

	/* construct 8 octets
	 * 1-4 - original checksum
	 * 5 - bitmask of sec layer
	 * 6-8 max buffer size
	 */
	if (cparams->props.min_ssf > 
	       KRB_DES_SECURITY_BITS + cparams->external_ssf) {
	    cparams->utils->log(NULL, SASL_LOG_ERR,
			       "minimum ssf too strong for this mechanism");
	    return SASL_TOOWEAK;
	} else if (cparams->props.min_ssf > cparams->props.max_ssf) {
	    cparams->utils->log(NULL, SASL_LOG_ERR,
			       "minimum ssf larger than maximum ssf");
	    return SASL_BADPARAM;
	}

	/* create stuff to send to server */
	sout = (char *) cparams->utils->malloc(9+strlen(text->user)+9);

	nchal=htonl(text->challenge);
	memcpy(sout, &nchal, 4);

	/* need bits of layer */
	need = cparams->props.max_ssf - cparams->external_ssf;
	musthave = cparams->props.min_ssf - cparams->external_ssf;

	if ((in[4] & KRB_SECFLAG_ENCRYPTION)
	    && (need>=56) && (musthave <= 56)) {
	    /* encryption */
	    oparams->encode = &privacy_encode;
	    oparams->decode = &privacy_decode;
	    oparams->mech_ssf = 56;
	    sout[4] = KRB_SECFLAG_ENCRYPTION;
	    /* using encryption layer */
	} else if ((in[4] & KRB_SECFLAG_INTEGRITY)
		   && (need >= 1) && (musthave <= 1)) {
	    /* integrity */
	    oparams->encode=&integrity_encode;
	    oparams->decode=&integrity_decode;
	    oparams->mech_ssf=1;
	    sout[4] = KRB_SECFLAG_INTEGRITY;
	    /* using integrity layer */
	} else if ((in[4] & KRB_SECFLAG_NONE) && (musthave <= 0)) {
	    /* no layer */
	    oparams->encode=NULL;
	    oparams->decode=NULL;
	    oparams->mech_ssf=0;
	    sout[4] = KRB_SECFLAG_NONE;
	} else {
	    cparams->utils->log(NULL, SASL_LOG_ERR,
				"unable to agree on layers with server");
	    return SASL_BADPROT;
	}

	servermaxbuf=in[5]*256*256+in[6]*256+in[7];
	oparams->maxoutbuf=servermaxbuf;

	sout[5] = (oparams->maxoutbuf) >> 16;  /* max ciphertext buffer size */
	sout[6] = (oparams->maxoutbuf) >> 8;
	sout[7] = (oparams->maxoutbuf);

	sout[8] = 0x00; /* just to be safe */

	/* append userid */
	len = 9;			/* 8 + trailing NULL */
	if (text->user) {
	    strcpy((char *)sout + 8, text->user);
	    len += strlen(text->user);
	}

	/* append 0 based octets so is multiple of 8 */
	while(len % 8)
	{
	    sout[len]=0;
	    len++;
	}
	sout[len]=0;
    
	des_pcbc_encrypt((des_cblock *)sout,
			 (des_cblock *)sout,
			 len,
			 text->init_keysched,
			 (des_cblock *)text->session,
			 DES_ENCRYPT);

	_buf_alloc(text, &text->out_buf, &text->out_buf_len, len);

	memcpy(text->out_buf, sout, len);

	*clientout = text->out_buf;
	*clientoutlen=len;

	/* nothing more to do; should be authenticated */
	/* FIXME: Is ignoring IP here really correct behavior? */
	if(cparams->iplocalport) {   
	    result = _sasl_ipfromstring(cparams->iplocalport, &(text->ip_local));
	    if (result != SASL_OK) {
		/* couldn't get local IP address */
		return result;
	    }
	}
	
	if(cparams->ipremoteport) {
	    result = _sasl_ipfromstring(cparams->ipremoteport, &(text->ip_remote));
	    if (result != SASL_OK) {
		/* couldn't get local IP address */
		return result;
	    }
	}
	
	buf = cparams->utils->malloc(strlen(text->credentials.pname)
				   + strlen(text->credentials.pinst)
				   + 2);
	if (!buf)
	    return SASL_NOMEM;
	strcpy(buf, text->credentials.pname);
	if (text->credentials.pinst[0]) {
	    strcat(buf, ".");
	    strcat(buf, text->credentials.pinst);
	}

	if (text->user && !text->user[0]) {
	    cparams->utils->free(text->user);
	    text->user = NULL;
	}
	if (! text->user) {
	    /* 0 in length fields means use strlen() */
	    ret = cparams->canon_user(cparams->utils->conn, buf, 0,
				      buf, 0, 0, oparams);
	} else {
	    ret = cparams->canon_user(cparams->utils->conn, text->user, 0,
				      buf, 0, 0, oparams);
	}

	cparams->utils->free(buf);

	oparams->doneflag=1;
	oparams->param_version=0;

	text->size=-1;
	text->needsize=4;

	text->state++;

	if (sout) cparams->utils->free(sout);

	return SASL_CONTINUE;
    }
    else if (text->state==3) {
	*clientout = NULL;
	*clientoutlen = 0;

	/* we're done! */
	text->state++;
	return SASL_OK;
    }

    return SASL_FAIL; /* should never get here */
}

static const long client_required_prompts[] = {
  SASL_CB_USER,
  SASL_CB_LIST_END
};

static const sasl_client_plug_t client_plugins[] = 
{
  {
    "KERBEROS_V4",
    KRB_DES_SECURITY_BITS,
    SASL_SEC_NOPLAINTEXT | SASL_SEC_NOACTIVE | SASL_SEC_NOANONYMOUS,
    0,
    client_required_prompts,
    NULL,
    &client_start,
    &client_continue_step,
    &dispose,
    &mech_free,
    NULL,
    NULL,
    NULL
  }
};

int sasl_client_plug_init(sasl_utils_t *utils __attribute__((unused)),
			  int maxversion,
			  int *out_version,
			  const sasl_client_plug_t **pluglist,
			  int *plugcount)
{
  if (maxversion<KERBEROS_VERSION)
    return SASL_BADVERS;

  *pluglist=client_plugins;

  *plugcount=1;
  *out_version=KERBEROS_VERSION;

  return SASL_OK;
}

