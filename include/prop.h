/* prop.h -- property request/response management routines
 *
 * Author: Chris Newman
 *
 * This is intended to be used to create a list of properties to request,
 * and _then_ request values for all properties.  Any change to the request
 * list will discard any existing values.  This assumption allows a very
 * efficient and simple memory model.  This was designed for SASL API auxiliary
 * property support, but would be fine for other contexts where this property
 * model is appropriate.
 *
 * The "struct propctx" is allocated by prop_new and is a fixed size structure.
 * If a prop_init() call were added, it would be reasonable to embed a "struct
 * propctx" in another structure.  prop_new also allocates a pool of memory
 * (in the vbase field) which will be used for an array of "struct propval"
 * to list all the requested properties.  The vbase pool is grown as necessary
 * when more properties are requested so that the array is contiguous.
 *
 * Properties may be multi-valued.  When a property is set, the active memory
 * pool is determined -- initially the pool will be any leftover space in the
 * vbase pool.  Once the vbase pool is gone, then new memory pools (of type
 * "struct proppool" will be created as necessary.
 *
 * An array of pointers to the property values is stored from the bottom of
 * the active pool going up.  The actual text strings of the properties are
 * stored from the top of the active pool going down.
 *
 * With a correct estimate in prop_new(), only two calls to malloc will ever
 * be necessary in the common case (one for "struct propctx", the other for
 * the vbase pool).
 */

#ifndef PROP_H
#define PROP_H 1

/* the resulting structure for property values
 */
struct propval {
    const char *name;	 /* name of property; NULL = end of list */
                         /* same pointer used in request will be used here */
    const char **values; /* list of strings, values == NULL if property not
			  * found, *values == NULL if property found with
			  * no values */
    unsigned nvalues;    /* total number of value strings */
    unsigned valsize;	 /* total size in characters of all value strings */
};

/* internal memory pool structure
 */
struct proppool {
    struct proppool *next;	/* next block */
    unsigned size;		/* size of this block */
    unsigned unused;		/* amount of block that's unused */
    char *data;			/* data area */
};

/* private internal structure
 */
#define PROP_DEFAULT 4		/* default number of propvals to assume */
struct propctx {
    struct propval *vbase;	/* array of property values */
    struct propval *vlast;	/* last property used by prop_set */
    const char *novalue;	/* always set to NULL */
    char *dptr;			/* pointer to base of data area */
    char **slend;		/* pointer to end of string list area */
    struct proppool *pool;	/* start of memory pool list */
    struct proppool *cur;	/* current item in memory pool list */
    unsigned unused;		/* bytes of unused space between slend&dptr */
    unsigned vused;		/* number of propval entries used */
    unsigned vtotal;		/* total additional entries in vbase */
};

/* create a property context
 *  estimate -- an estimate of the storage needed for requests & responses
 *              0 will use module default
 * returns -1 on error
 */
struct propctx *prop_new(unsigned estimate);

/* create new propctx which duplicates the contents of an existing propctx
 * returns -1 on error
 */
int prop_dup(struct propctx *src_ctx, struct propctx **dst_ctx);

/* Add property names to request
 *  ctx       -- context from prop_new()
 *  names     -- list of property names; must persist until context freed
 *               or requests cleared
 *
 * NOTE: may clear values from context as side-effect
 * returns -1 on error
 */
int prop_request(struct propctx *ctx, const char **names);

/* return array of struct propval from the context
 *  return value persists until next call to
 *   prop_request, prop_clear or prop_dispose on context
 */
const struct propval *prop_get(struct propctx *ctx);

/* Fill in an array of struct propval based on a list of property names
 *  return value persists until next call to
 *   prop_request, prop_clear or prop_dispose on context
 *  returns -1 on error (no properties ever requested, ctx NULL, etc)
 *  returns number of matching properties which were found (values != NULL)
 *  if a name requested here was never requested by a prop_request, then
 *  the name field of the associated vals entry will be set to NULL
 */
int prop_getnames(struct propctx *ctx, const char **names,
		  struct propval *vals);

/* clear values and optionally requests from property context
 *  ctx      -- property context
 *  requests -- 0 = don't clear requests, 1 = clear requests
 */
void prop_clear(struct propctx *ctx, int requests);

/* erase the value of a property
 */
void prop_erase(struct propctx *ctx, const char *name);

/* dispose of property context
 *  ctx      -- is disposed and set to NULL; noop if ctx or *ctx is NULL
 */
void prop_dispose(struct propctx **ctx);


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
		char *outbuf, unsigned outmax, unsigned *outlen);

/* add a property value to the context
 *  ctx    -- context from prop_new()/prop_request()
 *  name   -- name of property to which value will be added
 *            if NULL, add to the same name as previous prop_set/setvals call
 *  value  -- a value for the property; will be copied into context
 *            if NULL, remove existing values
 *  vallen -- length of value, if < 0 then strlen(value) will be used
 */
int prop_set(struct propctx *ctx, const char *name,
	     const char *value, int vallen);

/* set the values for a property
 *  ctx    -- context from prop_new()/prop_request()
 *  name   -- name of property to which value will be added
 *            if NULL, add to the same name as previous prop_set/setvals call
 *  values -- array of values, ending in NULL.  Each value is a NUL terminated
 *            string
 */
int prop_setvals(struct propctx *ctx, const char *name,
		 const char **values);


#endif /* PROP_H */
