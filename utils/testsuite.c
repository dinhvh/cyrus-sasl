/* testsuite.c -- Stress the library a little
 * Rob Siemborski
 * Tim Martin
 * $Id: testsuite.c,v 1.13.2.15 2001/06/26 23:05:48 rjs3 Exp $
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

/*
 * To create a krb5 srvtab file given a krb4 srvtab
 *
 * ~/> ktutil
 * ktutil:  rst /etc/srvtab
 * ktutil:  wkt /etc/krb5.keytab
 * ktutil:  q
 */

/*
 * TODO [FIXME]:
 *  put in alloc() routines that fail occasionally.
 *  verify ssf's
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>

#include <sasl/sasl.h>
#include <sasl/saslutil.h>

#include <sasl/md5global.h>
#include <sasl/md5.h>
#include <sasl/hmac-md5.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <time.h>
#include <string.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

char myhostname[1024+1];
#define MAX_STEPS 7 /* maximum steps any mechanism takes */

#define CLIENT_TO_SERVER "Hello. Here is some stuff"

#define REALLY_LONG_LENGTH  32000
#define REALLY_LONG_BACKOFF  2000

const char *username = "rjs3";
const char *nonexistant_username = "ABCDEFGHIJ";
const char *authname = "rjs3";
const char *password = "1234";

static const char *gssapi_service = "host";

/* our types of failures */
typedef enum {
    NOTHING = 0,
    ONEBYTE_RANDOM,		/* replace one byte with something random */
    ONEBYTE_NULL,		/* replace one byte with a null */
    ONEBYTE_QUOTES,		/* replace one byte with a double quote 
				   (try to fuck with digest-md5) */
    ONLY_ONE_BYTE,		/* send only one byte */
    ADDSOME,			/* add some random bytes onto the end */
    SHORTEN,			/* shorten the string some */
    REASONABLE_RANDOM,		/* send same size but random */
    REALLYBIG,			/* send something absurdly large all random */
    NEGATIVE_LENGTH,		/* send negative length */
    CORRUPT_SIZE		/* keep this one last */
} corrupt_type_t;

const char *corrupt_types[] = {
    "NOTHING",
    "ONEBYTE_RANDOM",
    "ONEBYTE_NULL",
    "ONEBYTE_QUOTES",
    "ONLY_ONE_BYTE",
    "ADDSOME",
    "SHORTEN",
    "REASONABLE_RANDOM",
    "REALLYBIG",
    "NEGATIVE_LENGTH",
    "CORRUPT_SIZE"
};


typedef void *foreach_t(char *mech, void *rock);

typedef struct tosend_s {
    corrupt_type_t type; /* type of corruption to make */
    int step; /* step it should send bogus data on */
} tosend_t;

typedef struct mem_info 
{
    void *addr;
    struct mem_info *next;
} mem_info_t;

int DETAILED_MEMORY_DEBUGGING = 0;

mem_info_t *head = NULL;

void *test_malloc(size_t size)
{
    void *out;
    mem_info_t *new_data;
    
    out = malloc(size);

    if(DETAILED_MEMORY_DEBUGGING)
	fprintf(stderr, "  %X = malloc(%d)\n", (unsigned)out, size);
    
    if(out) {
	new_data = malloc(sizeof(mem_info_t));
	if(!new_data) return out;

	new_data->addr = out;
	new_data->next = head;
	head = new_data;
    }

    return out;
}

void *test_realloc(void *ptr, size_t size)
{
    void *out;
    mem_info_t **prev, *cur;
    
    out = realloc(ptr, size);
    
    if(DETAILED_MEMORY_DEBUGGING)
	fprintf(stderr, "  %X = realloc(%X,%d)\n",
		(unsigned)out, (unsigned)ptr, size);

    /* don't need to update the mem info structure */
    if(out == ptr) return out;

    prev = &head; cur = head;
    
    while(cur) {
	if(cur->addr == ptr) {
	    cur->addr = out;
	    return out;
	}
	
	prev = &cur->next;
	cur = cur->next;
    }
    
    if(DETAILED_MEMORY_DEBUGGING && cur == NULL) {
	fprintf(stderr,
		"  MEM WARNING: reallocing something we never allocated!\n");

	cur = malloc(sizeof(mem_info_t));
	if(!cur) return out;

	cur->addr = out;
	cur->next = head;
	head = cur;
    }

    return out;
}

void *test_calloc(size_t nmemb, size_t size)
{
    void *out;
    mem_info_t *new_data;
    
    out = calloc(nmemb, size);

    if(DETAILED_MEMORY_DEBUGGING)    
	fprintf(stderr, "  %X = calloc(%d, %d)\n",
		(unsigned)out, nmemb, size);

    if(out) {
	new_data = malloc(sizeof(mem_info_t));
	if(!new_data) return out;

	new_data->addr = out;
	new_data->next = head;
	head = new_data;
    }
    
    return out;
}


void test_free(void *ptr)
{
    mem_info_t **prev, *cur;

    if(DETAILED_MEMORY_DEBUGGING)
	fprintf(stderr, "  free(%X)\n",
		(unsigned)ptr);

    prev = &head; cur = head;
    
    while(cur) {
	if(cur->addr == ptr) {
	    *prev = cur->next;
	    free(cur);
	    break;
	}
	
	prev = &cur->next;
	cur = cur->next;
    }

    if(DETAILED_MEMORY_DEBUGGING && cur == NULL) {
	fprintf(stderr,
		"  MEM WARNING: Freeing something we never allocated!\n");
    }

    free(ptr);
}

int mem_stat() 
{
    mem_info_t *cur;

    if(!head) {
	fprintf(stderr, "  All memory accounted for!\n");
	return SASL_OK;
    }
    
    fprintf(stderr, "  Currently Still Allocated:\n");
    for(cur = head; cur; cur = cur->next) {
	fprintf(stderr, "    %X\n", (unsigned)cur->addr);
    }
    return SASL_FAIL;
}
/************* End Memory Allocation functions ******/

void fatal(char *str)
{
    printf("Failed with: %s\n",str);
    exit(3);
}

/* my mutex functions */
int g_mutex_cnt = 0;

typedef struct my_mutex_s {

    int num;
    int val;
    
} my_mutex_t;

void *my_mutex_new(void)
{
    my_mutex_t *ret = (my_mutex_t *)malloc(sizeof(my_mutex_t));
    ret->num = g_mutex_cnt;
    g_mutex_cnt++;

    ret->val = 0;

    return ret;
}

int my_mutex_lock(my_mutex_t *m)
{
    if (m->val != 0)
    {
	fatal("Trying to lock a mutex already locked. This is not good in a single threaded app");
    }

    m->val = 1;
    return SASL_OK;
}

int my_mutex_unlock(my_mutex_t *m)
{
    if (m->val != 1)
    {
	fatal("Unlocking mutex that isn't locked");
    }

    m->val = 0;

    return SASL_OK;
}

int my_mutex_dispose(my_mutex_t *m)
{
    if (m==NULL) return SASL_OK;

    free(m);

    return SASL_OK;
}

int good_getopt(void *context __attribute__((unused)), 
		const char *plugin_name __attribute__((unused)), 
		const char *option,
		const char **result,
		unsigned *len)
{
    if (strcmp(option,"pwcheck_method")==0)
    {
	*result = "sasldb";
	if (len)
	    *len = strlen("sasldb");
	return SASL_OK;
    } else if (!strcmp(option, "sasldb_path")) {
	*result = "./sasldb";
	if (len)
	    *len = strlen("./sasldb");
	return SASL_OK;
    }

    return SASL_FAIL;
}

static struct sasl_callback goodsasl_cb[] = {
    { SASL_CB_GETOPT, &good_getopt, NULL },
    { SASL_CB_LIST_END, NULL, NULL }
};

int givebadpath(void * context __attribute__((unused)), 
		char ** path)
{
    int lup;
    *path = malloc(10000);    
    strcpy(*path,"/tmp/is/not/valid/path/");

    for (lup = 0;lup<1000;lup++)
	strcat(*path,"a/");

    return SASL_OK;
}

static struct sasl_callback withbadpathsasl_cb[] = {
    { SASL_CB_GETPATH, &givebadpath, NULL },
    { SASL_CB_LIST_END, NULL, NULL }
};

int giveokpath(void * context __attribute__((unused)), 
		char ** path)
{
    *path = malloc(1000);
    strcpy(*path,"/tmp/");

    return SASL_OK;
}

static struct sasl_callback withokpathsasl_cb[] = {
    { SASL_CB_GETPATH, &giveokpath, NULL },
    { SASL_CB_LIST_END, NULL, NULL }
};

static struct sasl_callback emptysasl_cb[] = {
    { SASL_CB_LIST_END, NULL, NULL }
};

char really_long_string[REALLY_LONG_LENGTH];

/*
 * Setup some things for test
 */
void init(unsigned int seed)
{
    int lup;
    int result;

    srand(seed);    

    for (lup=0;lup<REALLY_LONG_LENGTH;lup++)
	really_long_string[lup] = '0' + (rand() % 10);

    really_long_string[REALLY_LONG_LENGTH - rand() % REALLY_LONG_BACKOFF] = '\0';

    result = gethostname(myhostname, sizeof(myhostname)-1);
    if (result == -1) fatal("gethostname");

    sasl_set_mutex((sasl_mutex_alloc_t *) &my_mutex_new,
		   (sasl_mutex_lock_t *) &my_mutex_lock,
		   (sasl_mutex_unlock_t *) &my_mutex_unlock,
		   (sasl_mutex_free_t *) &my_mutex_dispose);

    sasl_set_alloc((sasl_malloc_t *)test_malloc,
		   (sasl_calloc_t *)test_calloc,
		   (sasl_realloc_t *)test_realloc,
		   (sasl_free_t *)test_free);
}

/*
 * Tests for sasl_server_init
 */

void test_init(void)
{
    int result;

    /* sasl_done() before anything */
    sasl_done();

    /* Try passing appname a really long string (just see if it crashes it)*/

    result = sasl_server_init(NULL,really_long_string);
    sasl_done();

    /* try passing NULL name */
    result = sasl_server_init(emptysasl_cb, NULL);

    if (result == SASL_OK) fatal("Allowed null name to sasl_server_init");

    /* this calls sasl_done when it wasn't inited */
    sasl_done();

    /* try giving it a different path for where the plugins are */
    result = sasl_server_init(withokpathsasl_cb, "Tester");

    if (result!=SASL_OK) fatal("Didn't deal with ok callback path very well");
    sasl_done();

    /* try giving it an invalid path for where the plugins are */
    result = sasl_server_init(withbadpathsasl_cb, NULL);

    if (result==SASL_OK) fatal("Allowed invalid path");
    sasl_done();
}


/* 
 * Tests sasl_listmech command
 */

void test_listmech(void)
{
    sasl_conn_t *saslconn;
    int result;
    const char *str = NULL;
    unsigned int plen;
    unsigned lup, pcount;

    /* test without initializing library */
    result = sasl_listmech(NULL, /* conn */
			   NULL,
			   "[",
			   "-",
			   "]",
			   &str,
			   NULL,
			   NULL);

    /*    printf("List mech without library initialized: %s\n",sasl_errstring(result,NULL,NULL));*/
    if (result == SASL_OK) fatal("Failed sasl_listmech() with NULL saslconn");




    if (sasl_server_init(emptysasl_cb,"TestSuite")!=SASL_OK) fatal("");

    if (sasl_server_new("rcmd", myhostname,
			NULL, NULL, NULL, NULL, 0, 
			&saslconn) != SASL_OK) {
	fatal("");
    }


    /* Test with really long user */

    result = sasl_listmech(saslconn,
			   really_long_string,
			   "[",
			   "-",
			   "]",
			   &str,
			   NULL,
			   NULL);

    if (result != SASL_OK) fatal("Failed sasl_listmech() with long user");

    if (str[0]!='[') fatal("Failed sasl_listmech() with long user (didn't start with '['");

    printf("We have the following mechs:\n %s\n",str);

    /* Test with really long prefix */

    result = sasl_listmech(saslconn,
			   NULL,
			   really_long_string,
			   "-",
			   "]",
			   &str,
			   NULL,
			   NULL);

    if (result != SASL_OK) fatal("failed sasl_listmech() with long prefix");

    if (str[0]!=really_long_string[0]) fatal("failed sasl_listmech() with long prefix (str is suspect)");

    /* Test with really long suffix */

    result = sasl_listmech(saslconn,
			   NULL,
			   "[",
			   "-",
			   really_long_string,
			   &str,
			   NULL,
			   NULL);

    if (result != SASL_OK) fatal("Failed sasl_listmech() with long suffix");

    /* Test with really long seperator */

    result = sasl_listmech(saslconn,
			   NULL,
			   "[",
			   really_long_string,
			   "]",
			   &str,
			   NULL,
			   NULL);

    if (result != SASL_OK) fatal("Failed sasl_listmech() with long seperator");

    /* Test contents of output string is accurate */
    result = sasl_listmech(saslconn,
			   NULL,
			   "",
			   "%",
			   "",
			   &str,
			   &plen,
			   &pcount);

    if (result != SASL_OK) fatal("Failed sasl_listmech()");

    if (strlen(str)!=plen) fatal("Length of string doesn't match what we were told");
    
    for (lup=0;lup<plen;lup++)
	if (str[lup]=='%')
	    pcount--;

    pcount--;
    if (pcount != 0)
    {
	printf("mechanism string = %s\n",str);
	printf("Mechs left = %d\n",pcount);
	fatal("Number of mechs received doesn't match what we were told");
    }

    /* Call sasl done then make sure listmech doesn't work anymore */
    sasl_dispose(&saslconn);
    sasl_done();

    result = sasl_listmech(saslconn,
			   NULL,
			   "[",
			   "-",
			   "]",
			   &str,
			   NULL,
			   NULL);

    if (result == SASL_OK) fatal("Called sasl_done but listmech still works\n");

}

/*
 * Perform tests on the random utilities
 */

void test_random(void)
{
    sasl_rand_t *rpool;
    int lup;
    char buf[4096];

    /* make sure it works consistantly */

    for (lup = 0;lup<10;lup++)
    {
	if (sasl_randcreate(&rpool) != SASL_OK) fatal("sasl_randcreate failed");
	sasl_randfree(&rpool);
    }

    /* try seeding w/o calling rand_create first */
    rpool = NULL;
    sasl_randseed(rpool, "seed", 4);

    /* try seeding with bad values */
    sasl_randcreate(&rpool);
    sasl_randseed(rpool, "seed", 0);
    sasl_randseed(rpool, NULL, 0);
    sasl_randseed(rpool, NULL, 4);    
    sasl_randfree(&rpool);

    /* try churning with bad values */
    sasl_randcreate(&rpool);
    sasl_churn(rpool, "seed", 0);
    sasl_churn(rpool, NULL, 0);
    sasl_churn(rpool, NULL, 4);    
    sasl_randfree(&rpool);

    /* try seeding with a lot of crap */
    sasl_randcreate(&rpool);
    
    for (lup=0;lup<(int) sizeof(buf);lup++)
    {
	buf[lup] = (rand() % 256);	
    }
    sasl_randseed(rpool, buf, sizeof(buf));
    sasl_churn(rpool, buf, sizeof(buf));

    sasl_randfree(&rpool);
}

/*
 * Test SASL base64 conversion routines
 */

void test_64(void)
{
    char orig[4096];
    char enc[8192];
    unsigned encsize;
    int lup;

    /* make random crap and see if enc->dec produces same as original */
    for (lup=0;lup<(int) sizeof(orig);lup++)
	orig[lup] = (char) (rand() % 256);
    
    if (sasl_encode64(orig, sizeof(orig), enc, sizeof(enc), &encsize)!=SASL_OK) 
	fatal("encode64 failed when we didn't expect it to");
    
    if (sasl_decode64(enc, encsize, enc, 8192, &encsize)!=SASL_OK)
	fatal("decode failed when didn't expect");
    
    if (encsize != sizeof(orig)) fatal("Now has different size");
    
    for (lup=0;lup<(int) sizeof(orig);lup++)
	if (enc[lup] != orig[lup])
	    fatal("enc64->dec64 doesn't match");

    /* try to get a SASL_BUFOVER */
    
    if (sasl_encode64(orig, sizeof(orig)-1, enc, 10, &encsize)!=SASL_BUFOVER)
	fatal("Expected SASL_BUFOVER");


    /* pass some bad params */
    if (sasl_encode64(NULL, 10, enc, sizeof(enc), &encsize)==SASL_OK)
	fatal("Said ok to null data");

    if (sasl_encode64(orig, sizeof(orig), enc, sizeof(enc), NULL)!=SASL_OK)
	fatal("Didn't allow null return size");
    
}


/* callbacks we support */
static sasl_callback_t client_callbacks[] = {
  {
#ifdef SASL_CB_GETREALM
    SASL_CB_GETREALM, NULL, NULL
  }, {
#endif
    SASL_CB_USER, NULL, NULL
  }, {
    SASL_CB_AUTHNAME, NULL, NULL
  }, {
    SASL_CB_PASS, NULL, NULL    
  }, {
    SASL_CB_LIST_END, NULL, NULL
  }
};

void interaction (int id, const char *prompt,
		  char **tresult, unsigned int *tlen)
{
    /* FIXME: Look at that memory leak! */
    
    if (id==SASL_CB_PASS) {
	*tresult=(char *) strdup(password);
    } else if (id==SASL_CB_USER) {
	*tresult=(char *) strdup(username);
    } else if (id==SASL_CB_AUTHNAME) {
	*tresult=(char *) strdup(authname);
#ifdef SASL_CB_GETREALM
    } else if ((id==SASL_CB_GETREALM)) {
	*tresult=(char *) strdup(myhostname);
#endif
    } else {
	char result[1024];
	int c;
	
	printf("%s: ",prompt);
	fgets(result, sizeof(result) - 1, stdin);
	c = strlen(result);
	result[c - 1] = '\0';
	*tresult=strdup(result);
    }

    *tlen=strlen(*tresult);
}

void fillin_correctly(sasl_interact_t *tlist)
{
  while (tlist->id!=SASL_CB_LIST_END)
  {
    interaction(tlist->id, tlist->prompt,
		(void *) &(tlist->result), 
		&(tlist->len));
    tlist++;
  }

}

const sasl_security_properties_t security_props = {
    0,
    128,
    8192,
    0,
    NULL,
    NULL	    
};

void set_properties(sasl_conn_t *conn)
{
  if (sasl_setprop(conn, SASL_SEC_PROPS, &security_props)!=SASL_OK)
      fatal("sasl_setprop() failed");
}

/*
 * This corrupts the string for us
 */

void corrupt(corrupt_type_t type, char *in, int inlen, char **out, unsigned *outlen)
{
    unsigned lup;
    

    switch (type)
	{
	case NOTHING:
	    *out = in;
	    *outlen = inlen;
	    break;
	case ONEBYTE_RANDOM: /* corrupt one byte */

	    if (inlen>0)
		in[ (rand() % inlen) ] = (char) (rand() % 256);

	    *out = in;
	    *outlen = inlen;

	    break;
	case ONEBYTE_NULL:
	    if (inlen>0)
		in[ (rand() % inlen) ] = '\0';

	    *out = in;
	    *outlen = inlen;
	    break;
	case ONEBYTE_QUOTES:
	    if (inlen>0)
		in[ (rand() % inlen) ] = '"';

	    *out = in;
	    *outlen = inlen;
	    break;
	case ONLY_ONE_BYTE:
	    *out = (char *) malloc(1);
	    (*out)[0] = (char) (rand() % 256);
	    *outlen = 1;
	    break;

	case ADDSOME:
	    *outlen = inlen+ (rand() % 100);
	    *out = (char *) malloc(*outlen);
	    memcpy( *out, in, inlen);
	    
	    for (lup=inlen;lup<*outlen;lup++)
		(*out)[lup] = (char) (rand() %256);

	    break;

	case SHORTEN:
	    if (inlen > 0)
	    {
		*outlen = (rand() % inlen);
		*out = (char *) malloc(*outlen);
		memcpy(*out, in, *outlen);
	    } else {
		*outlen = inlen;
		*out = in;
	    }
	    break;
	case REASONABLE_RANDOM:
	    *outlen = inlen;
	    *out = (char *) malloc(*outlen);
	    for (lup=0;lup<*outlen;lup++)
		(*out)[lup] = (char) (rand() % 256);
	    break;
	case REALLYBIG:
	    *outlen = rand() % 50000;
	    *out = (char *) malloc( *outlen);
	    
	    for (lup=0;lup<*outlen;lup++)
		(*out)[lup] = (char) (rand() % 256);
	    
	    break;
	case NEGATIVE_LENGTH:

	    *out = in;
	    if (inlen == 0) inlen = 10;
	    *outlen = -1 * (rand() % inlen);
	    
	    break;
	default:
	    fatal("Invalid corruption type");
	    break;
	}
}

void sendbadsecond(char *mech, void *rock)
{
    int result, need_another_client = 0;
    sasl_conn_t *saslconn;
    sasl_conn_t *clientconn;
    const char *out, *dec, *out2;
    char *tmp;
    unsigned outlen, declen, outlen2;
    sasl_interact_t *client_interact=NULL;
    const char *mechusing;
    const char *service = "rcmd";
    int mystep = 0; /* what step in the authentication are we on */
    int mayfail = 0; /* we did some corruption earlier so it's likely to fail now */
    
    tosend_t *send = (tosend_t *)rock;

    struct sockaddr_in addr;
    struct hostent *hp;
    char buf[8192];

    printf("%s --> start\n",mech);
    
    if (strcmp(mech,"GSSAPI")==0) service = gssapi_service;

    if (sasl_client_init(client_callbacks)!=SASL_OK) fatal("Unable to init client");

    if (sasl_server_init(goodsasl_cb,"TestSuite")!=SASL_OK) fatal("unable to init server");

    if ((hp = gethostbyname(myhostname)) == NULL) {
	perror("gethostbyname");
	fatal("");
    }

    addr.sin_family = 0;
    memcpy(&addr.sin_addr, hp->h_addr, hp->h_length);
    addr.sin_port = htons(0);

    sprintf(buf,"%s;%d", inet_ntoa(addr.sin_addr), 23);

    /* client new connection */
    if (sasl_client_new(service,
			myhostname,
			buf, buf, NULL,
			0,
			&clientconn)!= SASL_OK) fatal("sasl_client_new() failure");

    set_properties(clientconn);

    if (sasl_server_new(service, myhostname, NULL,
			buf, buf, NULL, 0, 
			&saslconn) != SASL_OK) {
	fatal("");
    }
    set_properties(saslconn);

    do {
	result = sasl_client_start(clientconn, mech,
				   &client_interact,
				   &out, &outlen,
				   &mechusing);

	if (result == SASL_INTERACT) fillin_correctly(client_interact);
	else if(result == SASL_CONTINUE) need_another_client = 1;
	else if(result == SASL_OK) need_another_client = 0;
    } while (result == SASL_INTERACT);
			       
    if (result < 0)
    {
	printf("%s - \n",sasl_errstring(result,NULL,NULL));
	fatal("sasl_client_start() error");
    }

    if (mystep == send->step)
    {
	memcpy(buf, out, outlen);
	corrupt(send->type, buf, outlen, &tmp, &outlen);
	out = tmp;
	mayfail = 1;
    }

    result = sasl_server_start(saslconn,
			       mech,
			       out,
			       outlen,
			       &out,
			       &outlen);

    if (mayfail)
    {
	if (result >= SASL_OK)
	    printf("WARNING: We did a corruption but it still worked\n");
	else {
	    goto done;
	}
    } else {
	if (result < 0) 
	{
	    printf("%s\n",sasl_errstring(result,NULL,NULL));
	    fatal("sasl_server_start() error");
	}
    }
    mystep++;

    while (result == SASL_CONTINUE) {

	if (mystep == send->step)
	{
	    memcpy(buf,out,outlen);
	    corrupt(send->type, buf, outlen, &tmp, &outlen);
	    out = tmp;
	    mayfail = 1;
	}

	do {
	    result = sasl_client_step(clientconn,
				      out, outlen,
				      &client_interact,
				      &out2, &outlen2);
	    
	    if (result == SASL_INTERACT)
		fillin_correctly(client_interact);
	    else if (result == SASL_CONTINUE)
		need_another_client = 1;
	    else if (result == SASL_OK)
		need_another_client = 0;
	} while (result == SASL_INTERACT);

	if (mayfail == 1)
	{
	    if (result >= 0)
		printf("WARNING: We did a corruption but it still worked\n");
	    else {
		goto done;
	    }
	} else {
	    if (result < 0) 
	    {
		printf("%s\n",sasl_errstring(result,NULL,NULL));
		fatal("sasl_client_step() error");
	    }
	}
	out=out2;
	outlen=outlen2;
	mystep++;

	if (mystep == send->step)
	{
	    memcpy(buf, out, outlen);
	    corrupt(send->type, buf, outlen, &tmp, &outlen);
	    out = tmp;
	    mayfail = 1;
	}

	result = sasl_server_step(saslconn,
				  out,
				  outlen,
				  &out,
				  &outlen);
	
	if (mayfail == 1)
	{
	    if (result >= 0)
		printf("WARNING: We did a corruption but it still worked\n");
	    else {
		goto done;
	    }
	} else {
	    if (result < 0) 
	    {
		printf("%s\n",sasl_errstring(result,NULL,NULL));
		fatal("sasl_server_step() error");
	    }
	}
	mystep++;

    }

    if(need_another_client) {
	result = sasl_client_step(clientconn,
				  out, outlen,
				  &client_interact,
				  &out2, &outlen2);
	if(result != SASL_OK)
	    fatal("client was not ok on last server step");
    }
    

    /* client to server */
    result = sasl_encode(clientconn, CLIENT_TO_SERVER,
			 strlen(CLIENT_TO_SERVER), &out, &outlen);
    if (result != SASL_OK) fatal("Error encoding");

    if (mystep == send->step)
    {
	memcpy(buf, out, outlen);
	corrupt(send->type, buf, outlen, &tmp, &outlen);
	out = tmp;
	mayfail = 1;
    }

    result = sasl_decode(saslconn, out, outlen, &dec, &declen);

    if (mayfail == 1)
    {
	if (result >= 0)
	    printf("WARNING: We did a corruption but it still worked\n");
	else {
	    goto done;
	}
    } else {
	if (result < 0) 
	{
	    printf("%s\n",sasl_errstring(result,NULL,NULL));
	    fatal("sasl_decode() failure");
	}
    }
    mystep++;

    /* no need to do other direction since symetric */

    /* Just verify oparams */
    if(sasl_getprop(saslconn, SASL_USERNAME, (const void **)&out)
       != SASL_OK) {
	fatal("couldn't get server username");
	goto done;
    }
    if(sasl_getprop(clientconn, SASL_USERNAME, (const void **)&out2)
       != SASL_OK) {
	fatal("couldn't get client username");
	goto done;
    }
    if(strcmp(out,out2)) {
	fatal("client username does not match server username");
	goto done;
    }

    printf("%s --> %s (as %s)\n",mech,sasl_errstring(result,NULL,NULL),out);

 done:
    sasl_dispose(&clientconn);
    sasl_dispose(&saslconn);
    sasl_done();
}

/* Authenticate two sasl_conn_t's to eachother, validly.
 * used to test the security layer */
int doauth(char *mech, sasl_conn_t **server_conn, sasl_conn_t **client_conn)
{
    int result, need_another_client = 0;
    sasl_conn_t *saslconn;
    sasl_conn_t *clientconn;
    const char *out, *out2;
    unsigned outlen, outlen2;
    sasl_interact_t *client_interact=NULL;
    const char *mechusing;
    const char *service = "rcmd";

    struct sockaddr_in addr;
    struct hostent *hp;
    char buf[8192];

    if(!server_conn || !client_conn) return SASL_BADPARAM;
    
    if (strcmp(mech,"GSSAPI")==0) service = gssapi_service;

    if (sasl_client_init(client_callbacks)!=SASL_OK) fatal("Unable to init client");

    if (sasl_server_init(goodsasl_cb,"TestSuite")!=SASL_OK) fatal("unable to init server");

    if ((hp = gethostbyname(myhostname)) == NULL) {
	perror("gethostbyname");
	fatal("");
    }

    addr.sin_family = 0;
    memcpy(&addr.sin_addr, hp->h_addr, hp->h_length);
    addr.sin_port = htons(0);

    sprintf(buf,"%s;%d", inet_ntoa(addr.sin_addr), 0);

    /* client new connection */
    if (sasl_client_new(service,
			myhostname,
			buf, buf, NULL,
			0,
			&clientconn)!= SASL_OK) fatal("sasl_client_new() failure");

    /* Set the security properties */
    set_properties(clientconn);

    if (sasl_server_new(service, myhostname, NULL,
			buf, buf, NULL, 0, 
			&saslconn) != SASL_OK) {
	fatal("");
    }
    set_properties(saslconn);

    do {
	result = sasl_client_start(clientconn, mech,
				   &client_interact,
				   &out, &outlen,
				   &mechusing);

	if (result == SASL_INTERACT) fillin_correctly(client_interact);
	else if(result == SASL_CONTINUE) need_another_client = 1;
	else if(result == SASL_OK) need_another_client = 0;
    } while (result == SASL_INTERACT);
			       
    if (result < 0)
    {
	printf("%s - \n",sasl_errstring(result,NULL,NULL));
	fatal("sasl_client_start() error");
    }

    result = sasl_server_start(saslconn,
			       mech,
			       out,
			       outlen,
			       &out,
			       &outlen);

    if (result < 0) 
    {
	printf("%s\n",sasl_errstring(result,NULL,NULL));
	fatal("sasl_server_start() error");
    }

    while (result == SASL_CONTINUE) {
	do {
	    result = sasl_client_step(clientconn,
				      out, outlen,
				      &client_interact,
				      &out2, &outlen2);
	    
	    if (result == SASL_INTERACT)
		fillin_correctly(client_interact);
	    else if (result == SASL_CONTINUE)
		need_another_client = 1;
	    else if (result == SASL_OK)
		need_another_client = 0;
	} while (result == SASL_INTERACT);

	if (result < 0) 
	{
	    printf("%s\n",sasl_errstring(result,NULL,NULL));
	    fatal("sasl_client_step() error");
	}

	out=out2;
	outlen=outlen2;

	result = sasl_server_step(saslconn,
				  out,
				  outlen,
				  &out,
				  &outlen);
	
	if (result < 0) 
	{
	    printf("%s\n",sasl_errstring(result,NULL,NULL));
	    fatal("sasl_server_step() error");
	}

    }

    if(need_another_client) {
	result = sasl_client_step(clientconn,
				  out, outlen,
				  &client_interact,
				  &out2, &outlen2);
	if(result != SASL_OK)
	    fatal("client was not ok on last server step");
    }

    *server_conn = saslconn;
    *client_conn = clientconn;
    
    return SASL_OK;
}

void cleanup_auth(sasl_conn_t **client, sasl_conn_t **server) 
{
    sasl_dispose(client);
    sasl_dispose(server);
    sasl_done();
}

void testseclayer(char *mech, void *rock __attribute__((unused))) 
{
    sasl_conn_t *sconn, *cconn;
    int result;
    char buf[8192], buf2[8192];
    const char *txstring = "THIS IS A TEST";
    const char *out, *out2;
    char *tmp;
    unsigned outlen, outlen2, totlen;
    
    printf("%s --> security layer start\n", mech);
    

    /* Basic crash-tests (none should cause a crash): */
    if(doauth(mech, &sconn, &cconn) != SASL_OK) {
	fatal("doauth failed in testseclayer");
    }

    sasl_encode(NULL, txstring, strlen(txstring), &out, &outlen);
    sasl_encode(cconn, NULL, strlen(txstring), &out, &outlen);
    sasl_encode(cconn, txstring, 0, &out, &outlen);
    sasl_encode(cconn, txstring, (unsigned)-1, &out, &outlen);
    sasl_encode(cconn, txstring, strlen(txstring), NULL, &outlen);
    sasl_encode(cconn, txstring, strlen(txstring), &out, NULL);

    sasl_decode(NULL, txstring, strlen(txstring), &out, &outlen);
    sasl_decode(cconn, NULL, strlen(txstring), &out, &outlen);
    sasl_decode(cconn, txstring, 0, &out, &outlen);
    sasl_decode(cconn, txstring, (unsigned)-1, &out, &outlen);
    sasl_decode(cconn, txstring, strlen(txstring), NULL, &outlen);
    sasl_decode(cconn, txstring, strlen(txstring), &out, NULL);

    cleanup_auth(&sconn, &cconn);

    /* Basic I/O Test */
    if(doauth(mech, &sconn, &cconn) != SASL_OK) {
	fatal("doauth failed in testseclayer");
    }

    result = sasl_encode(cconn, txstring, strlen(txstring), &out, &outlen);
    if(result != SASL_OK) {
	fatal("basic sasl_encode failure");
    }

    result = sasl_decode(sconn, out, outlen, &out, &outlen);
    if(result != SASL_OK) {
	fatal("basic sasl_decode failure");
    }    
    
    cleanup_auth(&sconn, &cconn);

    /* Split one block and reassemble */
    if(doauth(mech, &sconn, &cconn) != SASL_OK) {
	fatal("doauth failed in testseclayer");
    }

    result = sasl_encode(cconn, txstring, strlen(txstring), &out, &outlen);
    if(result != SASL_OK) {
	fatal("basic sasl_encode failure (2)");
    }

    memcpy(buf, out, 5);
    buf[5] = '\0';
    
    out += 5;

    result = sasl_decode(sconn, buf, 5, &out2, &outlen2);
    if(result != SASL_OK) {
	printf("Failed with: %s\n", sasl_errstring(result, NULL, NULL));
	fatal("sasl_decode failure part 1/2");
    }    
    
    memset(buf2, 0, 8192);
    memcpy(buf2, out2, outlen2);

    result = sasl_decode(sconn, out, outlen - 5, &out, &outlen);
    if(result != SASL_OK) {
	fatal("sasl_decode failure part 2/2");
    }

    strcat(buf2, out);
    if(strcmp(buf2, txstring)) {
	fatal("did not get correct string back after 2 sasl_decodes");
    }

    cleanup_auth(&sconn, &cconn);

    /* Combine 2 blocks */
    if(doauth(mech, &sconn, &cconn) != SASL_OK) {
	fatal("doauth failed in testseclayer");
    }

    result = sasl_encode(cconn, txstring, strlen(txstring), &out, &outlen);
    if(result != SASL_OK) {
	fatal("basic sasl_encode failure (3)");
    }

    memcpy(buf, out, outlen);

    tmp = buf + outlen;
    totlen = outlen;
    
    result = sasl_encode(cconn, txstring, strlen(txstring), &out, &outlen);
    if(result != SASL_OK) {
	fatal("basic sasl_encode failure (4)");
    }

    memcpy(tmp, out, outlen);
    totlen += outlen;

    result = sasl_decode(sconn, buf, totlen, &out, &outlen);
    if(result != SASL_OK) {
	printf("Failed with: %s\n", sasl_errstring(result, NULL, NULL));
	fatal("sasl_decode failure (2 blocks)");
    }    

    sprintf(buf2, "%s%s", txstring, txstring);

    if(strcmp(out, buf2)) {
	fatal("did not get correct string back (2 blocks)");
    }

    cleanup_auth(&sconn, &cconn);

    /* Combine 2 blocks with 1 split */
    if(doauth(mech, &sconn, &cconn) != SASL_OK) {
	fatal("doauth failed in testseclayer");
    }

    result = sasl_encode(cconn, txstring, strlen(txstring), &out, &outlen);
    if(result != SASL_OK) {
	fatal("basic sasl_encode failure (3)");
    }

    memcpy(buf, out, outlen);

    tmp = buf + outlen;
    
    result = sasl_encode(cconn, txstring, strlen(txstring), &out2, &outlen2);
    if(result != SASL_OK) {
	fatal("basic sasl_encode failure (4)");
    }

    memcpy(tmp, out2, 5);
    tmp[5] = '\0';
    outlen += 5;

    outlen2 -= 5;
    out2 += 5;

    result = sasl_decode(sconn, buf, outlen, &out, &outlen);
    if(result != SASL_OK) {
	printf("Failed with: %s\n", sasl_errstring(result, NULL, NULL));
	fatal("sasl_decode failure 1/2 (2 blocks, 1 split)");
    }    

    memset(buf2, 0, 8192);
    memcpy(buf2, out, outlen);

    tmp = buf2 + outlen;

    result = sasl_decode(sconn, out2, outlen2, &out, &outlen);
    if(result != SASL_OK) {
	printf("Failed with: %s\n", sasl_errstring(result, NULL, NULL));
	fatal("sasl_decode failure 2/2 (2 blocks, 1 split)");
    }

    memcpy(tmp, out, outlen);

    sprintf(buf, "%s%s", txstring, txstring);
    if(strcmp(buf, buf2)) {
	fatal("did not get correct string back (2 blocks, 1 split)");
    }

    cleanup_auth(&sconn, &cconn);

    printf("%s --> security layer OK\n", mech);
    
}


/*
 * Apply the given function to each machanism 
 */

void foreach_mechanism(foreach_t *func, void *rock)
{
    const char *out;
    char *str, *start;
    sasl_conn_t *saslconn;
    int result;
    struct sockaddr_in addr;
    struct hostent *hp;
    unsigned len;
    char buf[8192];

    /* Get the list of mechanisms */
    sasl_done();

    if (sasl_server_init(emptysasl_cb,"TestSuite")!=SASL_OK)
	fatal("sasl_server_init failed in foreach_mechanism");

    if ((hp = gethostbyname(myhostname)) == NULL) {
        perror("gethostbyname");
        fatal("");
    }

    addr.sin_family = 0;
    memcpy(&addr.sin_addr, hp->h_addr, hp->h_length);
    addr.sin_port = htons(0);

    sprintf(buf,"%s;%d", inet_ntoa(addr.sin_addr), 0);

    if (sasl_server_new("rcmd", myhostname, NULL,
			buf, buf, NULL, 0,
			&saslconn) != SASL_OK) {
	fatal("sasl_server_new in foreach_mechanism");
    }

    result = sasl_listmech(saslconn,
			   NULL,
			   "",
			   "\n",
			   "",
			   &out,
			   &len,
			   NULL);

    if(result != SASL_OK) {
	fatal("sasl_listmech in foreach_mechanism");
    }
    
    memcpy(buf, out, len + 1);

    sasl_dispose(&saslconn);
    sasl_done();

    /* call the function for each mechanism */
    start = str = buf;
    while (*start != '\0')
    {
	while ((*str != '\n') && (*str != '\0'))
	    str++;

	if (*str == '\n')
	{
	    *str = '\0';
	    str++;
	}

	func(start, rock);

	start = str;
    }
}

void test_serverstart()
{
    int result;
    sasl_conn_t *saslconn;
    const char *out;
    unsigned outlen;
    tosend_t tosend;
    struct sockaddr_in addr;
    struct hostent *hp;
    char buf[8192];

    if (sasl_server_init(emptysasl_cb,"TestSuite")!=SASL_OK) fatal("");

    if ((hp = gethostbyname(myhostname)) == NULL) {
        perror("gethostbyname");
        fatal("");
    }

    addr.sin_family = 0;
    memcpy(&addr.sin_addr, hp->h_addr, hp->h_length);
    addr.sin_port = htons(0);

    sprintf(buf,"%s;%d", inet_ntoa(addr.sin_addr), 0);

    if (sasl_server_new("rcmd", myhostname, NULL,
			buf, buf, NULL, 0, 
			&saslconn) != SASL_OK) {
	fatal("");
    }


    /* Test null connection */
    result = sasl_server_start(NULL,
			       "foobar",
			       NULL,
			       0,
			       NULL,
			       NULL);
    
    if (result == SASL_OK) fatal("Said ok to null sasl_conn_t in sasl_server_start()");

    /* send plausible but invalid mechanism */
    result = sasl_server_start(saslconn,
			       "foobar",
			       NULL,
			       0,
			       &out,
			       &outlen);

    if (result == SASL_OK) fatal("Said ok to invalid mechanism");

    /* send really long and invalid mechanism */
    result = sasl_server_start(saslconn,
			       really_long_string,
			       NULL,
			       0,
			       &out,
			       &outlen);

    if (result == SASL_OK) fatal("Said ok to invalid mechanism");

    sasl_dispose(&saslconn);
    sasl_done();

    tosend.type = NOTHING;
    tosend.step = 500;

    printf("trying to do correctly\n");
    foreach_mechanism((foreach_t *) &sendbadsecond,&tosend);
}

void test_rand_corrupt(unsigned steps) 
{
    unsigned lup;
    tosend_t tosend;
    
    for (lup=0;lup<steps;lup++)
    {
	tosend.type = rand() % CORRUPT_SIZE;
	tosend.step = lup % MAX_STEPS;

	printf("RANDOM TEST: (%s in step %d) (%d of %d)\n",corrupt_types[tosend.type],tosend.step,lup+1,steps);
	foreach_mechanism((foreach_t *) &sendbadsecond,&tosend);
    }
}

void test_all_corrupt() 
{
    tosend_t tosend;
    
    /* Start just beyond NOTHING */
    for(tosend.type=1; tosend.type<CORRUPT_SIZE; tosend.type++) {
	for(tosend.step=0; tosend.step<MAX_STEPS; tosend.step++) {
	    printf("TEST: %s in step %d:\n", corrupt_types[tosend.type],
		   tosend.step);
	    foreach_mechanism((foreach_t *) &sendbadsecond, &tosend);
	}
    }
}

void test_seclayer() 
{
    foreach_mechanism((foreach_t *) &testseclayer, NULL);
}

void create_ids(void)
{
    sasl_conn_t *saslconn;
    int i,result;
    struct sockaddr_in addr;
    struct hostent *hp;
    char buf[8192];
    const char challenge[] = "<1896.697170952@cyrus.andrew.cmu.edu>";
    MD5_CTX ctx;
    unsigned char digest[16];
    char digeststr[32];

    if (sasl_server_init(goodsasl_cb,"TestSuite")!=SASL_OK) fatal("");

    if ((hp = gethostbyname(myhostname)) == NULL) {
        perror("gethostbyname");
        fatal("");
    }

    addr.sin_family = 0;
    memcpy(&addr.sin_addr, hp->h_addr, hp->h_length);
    addr.sin_port = htons(0);

    sprintf(buf,"%s;%d", inet_ntoa(addr.sin_addr), 0);

    if (sasl_server_new("rcmd", myhostname, NULL,
			buf, buf, NULL, 0,
			&saslconn) != SASL_OK)
	fatal("");
    
    /* Try to set password then check it */

    result = sasl_setpass(saslconn, username, password, strlen(password),
			  NULL, 0, SASL_SET_CREATE);
    if (result != SASL_OK) {
	printf("error was %s (%d)\n",sasl_errstring(result,NULL,NULL),result);
	fatal("Error setting password. Do we have write access to sasldb?");
    }    
    
    result = sasl_checkpass(saslconn, username, strlen(username),
			    password, strlen(password));
    if (result != SASL_OK)
	fatal("Unable to verify password we just set");

    result = sasl_user_exists(saslconn, "imap", NULL, username);
    if(result != SASL_OK)
	fatal("sasl_user_exists did not find user");

    result = sasl_user_exists(saslconn, "imap", NULL,
			      nonexistant_username);
    if(result == SASL_OK)
	fatal("sasl_user_exists found nonexistant username");

    /* Test sasl_checkapop */
    _sasl_MD5Init(&ctx);
    _sasl_MD5Update(&ctx,challenge,strlen(challenge));
    _sasl_MD5Update(&ctx,password,strlen(password));
    _sasl_MD5Final(digest, &ctx);
                            
    /* convert digest from binary to ASCII hex */
    for (i = 0; i < 16; i++)
      sprintf(digeststr + (i*2), "%02x", digest[i]);

    sprintf(buf, "%s %s", username, digeststr);
    
    result = sasl_checkapop(saslconn,
                            challenge, strlen(challenge),
                            buf, strlen(buf));
    if(result != SASL_OK)
        fatal("Unable to checkapop password we just set");
    /* End checkapop test */

    /* now delete user and make sure can't find him anymore */
    result = sasl_setpass(saslconn, username, password,
			  strlen(password), NULL, 0, SASL_SET_DISABLE);
    if (result != SASL_OK)
	fatal("Error disabling password. Do we have write access to sasldb?");
    
    result = sasl_checkpass(saslconn, username, strlen(username),
			    password, strlen(password));
    if (result == SASL_OK)
	fatal("sasl_checkpass got SASL_OK after disableing");

    /* And checkapop... */
    result = sasl_checkapop(saslconn,
                            challenge, strlen(challenge), 
                            buf, strlen(buf));
    if(result == SASL_OK)
        fatal("Checkapop succeeded but should have failed");
    /* End checkapop */

    /* try bad params */
    if (sasl_setpass(NULL,username, password, strlen(password), NULL, 0, SASL_SET_CREATE)==SASL_OK)
	fatal("Didn't specify saslconn");
    if (sasl_setpass(saslconn,username, password, 0, NULL, 0, SASL_SET_CREATE)==SASL_OK)
	fatal("Allowed password of zero length");
    if (sasl_setpass(saslconn,username, password, strlen(password), NULL, 0, 43)==SASL_OK)
	fatal("Gave weird code");

#ifndef SASL_NDBM
    if (sasl_setpass(saslconn,really_long_string, password, strlen(password), 
		     NULL, 0, SASL_SET_CREATE)!=SASL_OK)
	fatal("Didn't allow really long username");
#else
    printf("WARNING: skipping sasl_setpass() on really_long_string with NDBM\n");
#endif

    if (sasl_setpass(saslconn,"bob",really_long_string,
		     strlen(really_long_string),NULL, 0,
		     SASL_SET_CREATE)!=SASL_OK)
	fatal("Didn't allow really long password");

    result = sasl_setpass(saslconn,"frank" ,password, strlen(password), 
			  NULL, 0, SASL_SET_DISABLE);

    if ((result!=SASL_NOUSER) && (result!=SASL_OK))
	{
	    printf("error = %d\n",result);
	    fatal("Disabling non-existant didn't return SASL_NOUSER");
	}
    
    /* Now set the user again (we use for rest of program) */
    result = sasl_setpass(saslconn, username, password, strlen(password),
			  NULL, 0, SASL_SET_CREATE);
    if (result != SASL_OK)
	fatal("Error setting password. Do we have write access to sasldb?");

    /* cleanup */
    sasl_dispose(&saslconn);
    sasl_done();
}

/*
 * Test the checkpass routine
 */

void test_checkpass(void)
{
    sasl_conn_t *saslconn;

    /* try without initializing anything */
    if(sasl_checkpass(NULL, username, strlen(username),
		      password, strlen(password)) != SASL_NOTINIT) {
	fatal("sasl_checkpass() when library not initialized");
    }    

    if (sasl_server_init(goodsasl_cb,"TestSuite")!=SASL_OK) fatal("");

    if (sasl_server_new("rcmd", myhostname,
			NULL, NULL, NULL, NULL, 0, 
			&saslconn) != SASL_OK)
	fatal("");

    /* make sure works for general case */

    if (sasl_checkpass(saslconn, username, strlen(username),
		       password, strlen(password))!=SASL_OK)
	fatal("sasl_checkpass() failed on simple case");

    /* NULL saslconn */
    if (sasl_checkpass(NULL, username, strlen(username),
		   password, strlen(password)) == SASL_OK)
	fatal("Suceeded with NULL saslconn");

    /* NULL username */
    if (sasl_checkpass(saslconn, NULL, strlen(username),
		   password, strlen(password)) == SASL_OK)
	fatal("Suceeded with NULL username");

    /* NULL password */
    if (sasl_checkpass(saslconn, username, strlen(username),
		   NULL, strlen(password)) == SASL_OK)
	fatal("Suceeded with NULL password");

    sasl_dispose(&saslconn);
    sasl_done();
}



void notes(void)
{
    printf("NOTE:\n");
    printf("-For KERBEROS_V4 must be able to read srvtab file (usually /etc/srvtab)\n");
    printf("-For GSSAPI must be able to read srvtab (/etc/krb5.keytab)\n");
    printf("-For both KERBEROS_V4 and GSSAPI you must have non-expired tickets\n");
    printf("-Must be able to read and write to sasldb.\n");
    printf("\n\n");
}

void usage(void)
{
    printf("Usage:\n" \
           " testsuite [-g name] [-s seed] [-r tests] -a -M\n" \
           "    g -- gssapi service name to use (default: host)\n" \
	   "    r -- # of random tests to do (default: 25)\n" \
	   "    a -- do all corruption tests (and ignores random ones unless -r specified)\n" \
	   "    h -- show this screen\n" \
           "    s -- random seed to use\n" \
	   "    M -- detailed memory debugging ON\n" \
           );
}

int main(int argc, char **argv)
{
    char c;
    int random_tests = -1;
    int do_all = 0;
    unsigned int seed = time(NULL);
    while ((c = getopt(argc, argv, "Ms:g:r:h:a")) != EOF)
	switch (c) {
	case 'M':
	    DETAILED_MEMORY_DEBUGGING = 1;
	    break;
	case 's':
	    seed = atoi(optarg);
	    break;
	case 'g':
	    gssapi_service = optarg;
	    break;
	case 'r':
	    random_tests = atoi(optarg);
	    break;
	case 'a':
	    random_tests = 0;
	    do_all = 1;
	    break;
	case 'h':
	    usage();
	    exit(0);
	    break;
	default:
	    usage();
	    fatal("Invalid parameter\n");
	    break;
    }

    if(random_tests < 0) random_tests = 25;

    notes();

    init(seed);

    create_ids();
    printf("Created id's in sasldb... ok\n");
    if(mem_stat() != SASL_OK) fatal("memory error");

    test_checkpass();
    printf("Checking plaintext passwords... ok\n");
    if(mem_stat() != SASL_OK) fatal("memory error");

    test_random();
    printf("Random number functions... ok\n");
    if(mem_stat() != SASL_OK) fatal("memory error");

    test_64();
    printf("Tested base64 functions... ok\n");
    if(mem_stat() != SASL_OK) fatal("memory error");

    test_init();
    printf("Tests of sasl_server_init()... ok\n");
    if(mem_stat() != SASL_OK) fatal("memory error");

    test_listmech();
    printf("Tests of sasl_listmech()... ok\n");
    if(mem_stat() != SASL_OK) fatal("memory error");

    test_serverstart();
    printf("Tests of serverstart... ok\n");
    if(mem_stat() != SASL_OK) fatal("memory error");

    /* FIXME: do memory tests below here on the things
     * that are MEANT to fail sometime. */
    if(do_all) {	
	test_all_corrupt();
	printf("All corruption tests... ok\n");
    }
    
    if(random_tests) {
	test_rand_corrupt(random_tests);
	printf("Random tests... ok\n");
    }

    test_seclayer();
    printf("Tests of security layer... ok\n");

    printf("All tests seemed to go ok (i.e. we didn't crash)\n");

    exit(0);
}
