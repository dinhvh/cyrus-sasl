/*
 * library to emulate unix kerberos on a macintosh
 */
#include <config.h>
#include <krb.h>
#include <extra_krb.h>
#include <kcglue_krb.h>

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#include <stdio.h>

/*
 * given a hostname return the kerberos realm
 * NOT thread safe....
 */
char *krb_realmofhost(const char *s)
{
	s=strchr(s,'.');
	if(s==0)
		return "ANDREW.CMU.EDU";
	return (char *)(s+1);
}

/*
 * return the default instance to use for a given hostname
 * NOT thread safe... but then neathoer is the real kerberos one
 */
char *krb_get_phost(const char *alias)
{
#define MAX_HOST_LEN (512)
    static char instance[MAX_HOST_LEN];
    char *dst=instance;
    int remaining=MAX_HOST_LEN-10;
    while(remaining-->0) {
    	char ch= *alias++;
    	if(ch==0) break;
    	if(isupper(ch))
    		ch=tolower(ch);
    	if(ch=='.')
    		break;
    	*dst++=ch;
    }
    *dst=0;
    return instance;
}
