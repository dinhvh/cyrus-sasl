/* auxprop.c - auxilliary property support
 * Rob Siemborski
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
#include <sasl.h>
#include <prop.h>
#include "saslint.h"

struct proppool 
{
    struct proppool *next;

    void *data;
    size_t size;          /* Size of Block */
    size_t unused;        /* Space Remaining in this Block */
};

struct propctx  {
    struct propval *values;
    unsigned used_values, allocated_values;

    struct proppool *mem_base;
    struct proppool *mem_cur;
};

static struct proppool *alloc_proppool(size_t size) 
{
    struct proppool *ret;
    ret = sasl_ALLOC(sizeof(struct proppool));
    if(!ret) return NULL;

    ret->data = sasl_ALLOC(size);
    if(!ret->data) {
	sasl_FREE(ret);
	return NULL;
    }

    memset(ret->data, 0, size);

    ret->size = ret->unused = size;

    return ret;
}

static void free_proppool(struct proppool *pool) 
{
    if(!pool) return;
    if(pool->data) sasl_FREE(pool->data);
    sasl_FREE(pool);
}

static int prop_init(struct propctx *ctx, unsigned estimate) 
{
    const unsigned VALUES_SIZE = PROP_DEFAULT * sizeof(struct propval);

    ctx->values = sasl_ALLOC(VALUES_SIZE);
    if(!ctx->values) return SASL_NOMEM;

    ctx->allocated_values = PROP_DEFAULT;
    ctx->used_values = 0;

    ctx->mem_base = alloc_proppool(estimate);
    if(!ctx->mem_base) return SASL_NOMEM;

    memset(ctx->values, 0, VALUES_SIZE);
    ctx->mem_cur = ctx->mem_base;
    return SASL_OK;
}

/* create a property context
 *  estimate -- an estimate of the storage needed for requests & responses
 *              0 will use module default
 * returns NULL on error
 */
struct propctx *prop_new(unsigned estimate) 
{
    struct propctx *new_ctx;

    if(!estimate) estimate = PROP_DEFAULT * 50;

    new_ctx = sasl_ALLOC(sizeof(struct propctx));
    if(!new_ctx) return NULL;

    if(prop_init(new_ctx, estimate) != SASL_OK) {
	prop_dispose(&new_ctx);
    }

    return new_ctx;
}

/* create new propctx which duplicates the contents of an existing propctx
 * returns -1 on error
 */
int prop_dup(struct propctx *src_ctx, struct propctx **dst_ctx) 
{
    if(!src_ctx || !dst_ctx) return SASL_BADPARAM;

    /* FIXME: [broken] */
    
    *dst_ctx = sasl_ALLOC(sizeof(struct propctx));
    if(!(*dst_ctx)) return SASL_NOMEM;
    
    return SASL_OK;
}

/* dispose of property context
 *  ctx      -- is disposed and set to NULL; noop if ctx or *ctx is NULL
 */
void prop_dispose(struct propctx **in_ctx)
{
    struct propctx *ctx;
    
    if(!in_ctx || !*in_ctx) return;

    ctx = *in_ctx;

    if(ctx->values) sasl_FREE(ctx->values);
    if(ctx->mem_base) free_proppool(ctx->mem_base);
    
    sasl_FREE(ctx);
    *in_ctx = NULL;

    return;
}

/* Add property names to request
 *  ctx       -- context from prop_new()
 *  names     -- list of property names; must persist until context freed
 *               or requests cleared
 *
 * NOTE: may clear values from context as side-effect
 * returns -1 on error
 */
int prop_request(struct propctx *ctx, const char **names) 
{
    unsigned i, new_values, total_values;

    if(!ctx || !names) return SASL_BADPARAM;

    /* Count how many we need to add */
    for(new_values=0; names[new_values]; new_values++);

    /* Do we need to add ANY? */
    if(!new_values) return SASL_OK;

    total_values = new_values + ctx->used_values;

    if(total_values > ctx->allocated_values) {
	unsigned new_alloc_length;
	
	if(total_values > 2 * ctx->allocated_values) {
	    new_alloc_length = total_values;
	} else {
	    new_alloc_length = 2 * ctx->allocated_values;
	}
	
	/* We need to allocate more! */
	ctx->values = sasl_REALLOC(ctx->values,
				   new_alloc_length * sizeof(struct propval));

	if(!ctx->values) {
	    ctx->allocated_values = ctx->used_values = 0;
	    return SASL_NOMEM;
	}

	/* It worked! Update the structure! */
	ctx->allocated_values = new_alloc_length;
    }

    /* Now do the copy, or referencing rather */
    for(i=0;i<new_values;i++) {
	ctx->values[ctx->used_values++].name = names[i];
    }

    /* FIXME: Clear Values as Side-Effect? */
    
    return SASL_OK;
}

/* return array of struct propval from the context
 *  return value persists until next call to
 *   prop_request, prop_clear or prop_dispose on context
 */
const struct propval *prop_get(struct propctx *ctx) 
{
    return NULL;
}

/* Fill in an array of struct propval based on a list of property names
 *  return value persists until next call to
 *   prop_request, prop_clear or prop_dispose on context
 *  returns -1 on error (no properties ever requested, ctx NULL, etc)
 *  returns number of matching properties which were found (values != NULL)
 *  if a name requested here was never requested by a prop_request, then
 *  the name field of the associated vals entry will be set to NULL
 */
int prop_getnames(struct propctx *ctx, const char **names,
		  struct propval *vals) 
{
    return SASL_FAIL;
}


/* clear values and optionally requests from property context
 *  ctx      -- property context
 *  requests -- 0 = don't clear requests, 1 = clear requests
 */
void prop_clear(struct propctx *ctx, int requests) 
{
    return;
}

/* erase the value of a property
 */
void prop_erase(struct propctx *ctx, const char *name)
{
    return;
}

/****fetcher interfaces****/

/* format the requested property names into a string
 *  ctx    -- context from prop_new()/prop_request()
 *  sep    -- separator between property names (unused if none requested)
 *  seplen -- length of separator, if < 0 then strlen(sep) will be used
 *  outbuf -- output buffer
 *  outmax -- maximum length of output buffer including NUL terminator
 *  outlen -- set to length of output string excluding NUL terminator
 * returns 0 on success and amount of additional space needed on failure
 */
int prop_format(struct propctx *ctx, const char *sep, int seplen,
		char *outbuf, unsigned outmax, unsigned *outlen) 
{
    return SASL_FAIL;
}

/* add a property value to the context
 *  ctx    -- context from prop_new()/prop_request()
 *  name   -- name of property to which value will be added
 *            if NULL, add to the same name as previous prop_set/setvals call
 *  value  -- a value for the property; will be copied into context
 *            if NULL, remove existing values
 *  vallen -- length of value, if < 0 then strlen(value) will be used
 */
int prop_set(struct propctx *ctx, const char *name,
	     const char *value, int vallen)
{
    return SASL_FAIL;
}


/* set the values for a property
 *  ctx    -- context from prop_new()/prop_request()
 *  name   -- name of property to which value will be added
 *            if NULL, add to the same name as previous prop_set/setvals call
 *  values -- array of values, ending in NULL.  Each value is a NUL terminated
 *            string
 */
int prop_setvals(struct propctx *ctx, const char *name,
		 const char **values)
{
    return SASL_FAIL;
}

/* Request a set of auxiliary properties
 *  conn         connection context
 *  propnames    list of auxiliary property names to request ending with
 *               NULL.  
 *
 * Subsequent calls will add items to the request list.  Call with NULL
 * to clear the request list.
 *
 * errors
 *  SASL_OK       -- success
 *  SASL_BADPARAM -- bad count/conn parameter
 *  SASL_NOMEM    -- out of memory
 */
int sasl_auxprop_request(sasl_conn_t *conn, const char **propnames) 
{
    return SASL_FAIL;
}


/* Returns current auxiliary property context.
 * Use functions in prop.h to access content
 *
 *  if authentication hasn't completed, property values may be empty/NULL
 *
 *  properties not recognized by active plug-ins will be left empty/NULL
 *
 *  returns NULL if conn is invalid.
 */
struct propctx *sasl_auxprop_getctx(sasl_conn_t *conn) 
{
    sasl_server_conn_t *sconn;
    
    if(!conn || conn->type != SASL_CONN_SERVER) return NULL;

    sconn = (sasl_server_conn_t *)conn;

    return  sconn->propctx;
}

