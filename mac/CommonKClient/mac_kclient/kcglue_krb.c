#include <stdlib.h>
#include <string.h>
#include <kcglue_krb.h>
#include "macKClientPublic.h"

#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif

#define SOME_KRB_ERR_NUMBER (70)
#define		MAX_KRB_ERRORS	256

const char *krb_err_txt[MAX_KRB_ERRORS]={
 "krb err","krb err","krb err","krb err","krb err","krb err","krb err","krb err",
 "krb err","krb err","krb err","krb err","krb err","krb err","krb err","krb err",
 "krb err","krb err","krb err","krb err","krb err","krb err","krb err","krb err",
 "krb err","krb err","krb err","krb err","krb err","krb err","krb err","krb err",
 "krb err","krb err","krb err","krb err","krb err","krb err","krb err","krb err",
 "krb err","krb err","krb err","krb err","krb err","krb err","krb err","krb err",
 "krb err","krb err","krb err","krb err","krb err","krb err","krb err","krb err",
 "krb err","krb err","krb err","krb err","krb err","krb err","krb err","krb err",
 "krb err","krb err","krb err","krb err","krb err","krb err","krb err","krb err",
 "krb err","krb err","krb err","krb err","krb err","krb err","krb err","krb err",
 "krb err","krb err","krb err","krb err","krb err","krb err","krb err","krb err",
 "krb err","krb err","krb err","krb err","krb err","krb err","krb err","krb err",
 "krb err","krb err","krb err","krb err","krb err","krb err","krb err","krb err",
 "krb err","krb err","krb err","krb err","krb err","krb err","krb err","krb err",
 "krb err","krb err","krb err","krb err","krb err","krb err","krb err","krb err",
 "krb err","krb err","krb err","krb err","krb err","krb err","krb err","krb err",
 "krb err","krb err","krb err","krb err","krb err","krb err","krb err","krb err",
 "krb err","krb err","krb err","krb err","krb err","krb err","krb err","krb err",
 "krb err","krb err","krb err","krb err","krb err","krb err","krb err","krb err",
 "krb err","krb err","krb err","krb err","krb err","krb err","krb err","krb err",
 "krb err","krb err","krb err","krb err","krb err","krb err","krb err","krb err",
 "krb err","krb err","krb err","krb err","krb err","krb err","krb err","krb err",
 "krb err","krb err","krb err","krb err","krb err","krb err","krb err","krb err",
 "krb err","krb err","krb err","krb err","krb err","krb err","krb err","krb err",
 "krb err","krb err","krb err","krb err","krb err","krb err","krb err","krb err",
 "krb err","krb err","krb err","krb err","krb err","krb err","krb err","krb err",
 "krb err","krb err","krb err","krb err","krb err","krb err","krb err","krb err",
 "krb err","krb err","krb err","krb err","krb err","krb err","krb err","krb err",
 "krb err","krb err","krb err","krb err","krb err","krb err","krb err","krb err",
 "krb err","krb err","krb err","krb err","krb err","krb err","krb err","krb err",
 "krb err","krb err","krb err","krb err","krb err","krb err","krb err","krb err",
 "krb err","krb err","krb err","krb err","krb err","krb err","krb err","krb err"
};


/*
 * given a service instance and realm, combine them to foo.bar@REALM
 * return true upon success
 */
static int implode_krb_user_info(char *dst,const char *service,const char *instance,const char *realm)
{
  	if(strlen(service)>=KCGLUE_ITEM_SIZE)
  		return FALSE;
  	if(strlen(instance)>=KCGLUE_ITEM_SIZE)
  		return FALSE;
  	if(strlen(realm)>=KCGLUE_ITEM_SIZE)
  		return FALSE;
  	strcpy(dst,service);
  	dst+=strlen(dst);
  	if(instance[0]!=0) {
  		*dst++='.';
  		strcpy(dst,instance);
  		dst+=strlen(dst);
  	}
  	*dst++='@';
  	strcpy(dst,realm);
  	return TRUE;
}

int kcglue_krb_mk_req(void *dat,int *len, const char *service, char *instance, char *realm, 
	   long checksum,
	   void *des_key,
	   char *pname,
	   char *pinst)
{
	char tkt_buf[KCGLUE_MAX_KTXT_LEN+20];
	char user_id[KCGLUE_MAX_K_STR_LEN+1];
  	KClientSessionInfo ses;
  	int have_session=FALSE;
  	int rc;

	if(!implode_krb_user_info(user_id,service,instance,realm))
		return SOME_KRB_ERR_NUMBER;

  	rc=KClientNewSession(&ses,0,0,0,0);
  	if(rc!=0)
    	return SOME_KRB_ERR_NUMBER;
  	have_session=TRUE;
  	
    *len=sizeof(tkt_buf)-10;
  	rc=KClientGetTicketForServiceFull(&ses,user_id,tkt_buf,len,checksum);
  	if(rc==0) {
		memcpy(dat,tkt_buf+4,*len);	/*kclient puts out a 4 byte length that mit doesnt*/
		rc=KClientGetSessionKey(&ses,des_key);
	}
	if(rc==0)
		rc=KClientGetUserName(pname);
	*pinst=0;
	if(have_session)
    	KClientDisposeSession(&ses);
  
	if(rc!=0)
		return SOME_KRB_ERR_NUMBER;
	return 0;
}
