/*
 * internaly sasl or its test programs use some functions which are not availible
 * on the macintosh.  these have common names like strdrup gethostname etc.  defining
 * them as routines could make conflicts with clients of the library.  in config.h
 * we macro define such names to start with xxx_.  The implementation for them is
 * here.  The xxx_ is in hopes of not conflicting with a name in client program.
 */
 
 #include <string.h>
 #include <stdlib.h>
 #include <ctype.h>
 
 #include <config.h>
// #include <netinet/in.h>

/*
 * return the smaller of two integers
 */
static int xxy_min(int a,int b)
{
	if(a<b)
		return a;
	return b;
}

static int limit_strcpy(char *dest,const char *src,int len)
{
	int slen=strlen(src);
	if(len<1)
		return 0;
	slen=xxy_min(slen,len-1);
	if(slen>0)
		memcpy(dest,src,slen);
	dest[slen]=0;
	return slen;	
}

int strcpy_truncate(char *dest,char *src,int len)
{
	return limit_strcpy(dest,src,len);
}

int gethostname(char *dest,int destlen)
{
	limit_strcpy(dest,"localhost",destlen);
	return 0;
}

char *strdup(const char *str)
{
 	if(str==0)
 		return 0;
 	{
 		const int len=strlen(str);
 		char *result=malloc(len+1);
 		strcpy(result,str);
 		return result;
  	}
 	
}
 
int strncasecmp(const char *s1,const char *s2,int len)
{
	while(len-- >0) {
		char c1= *s1++;
		char c2= *s2++;
		if((c1==0)&&(c2==0))
			return 0;
		if(c1==0)
			return -1;
		if(c2==0)
			return 1;
		/* last ansi spec i read tolower was undefined for non uppercase chars
		 * but it works in most implementations
		 */
		if(isupper(c1))
			c1=tolower(c1);
		if(isupper(c2))
			c2=tolower(c2);
		if(c1<c2)
			return -1;
		if(c1>c2)
			return 1;
	}
	return 1;
}

int strcasecmp(const char *s1,const char *s2)
{
	while(1) {
		char c1= *s1++;
		char c2= *s2++;
		if((c1==0)&&(c2==0))
			return 0;
		if(c1==0)
			return -1;
		if(c2==0)
			return 1;
		/* last ansi spec i read tolower was undefined for non uppercase chars
		 * but it works in most implementations
		 */
		if(isupper(c1))
			c1=tolower(c1);
		if(isupper(c2))
			c2=tolower(c2);
		if(c1<c2)
			return -1;
		if(c1>c2)
			return 1;
	}
}

int inet_aton(const char *cp, struct in_addr *inp)
{
	char *cptr1, *cptr2, *cptr3;
	long u;
	char cptr0[256];
	strcpy(cptr0, cp);

	if (!(cptr1 = strchr(cptr0, '.'))) return 0;
	*cptr1++ = 0;
	if (!(cptr2 = strchr(cptr1, '.'))) return 0;
	*cptr2++ = 0;
	if (!(cptr3 = strchr(cptr2, '.'))) return 0;
	*cptr3++ = 0;
	if (!*cptr3) return 0;

	u = ((atoi(cptr0) << 8 + atoi(cptr1)) << 8 + atoi(cptr2)) << 8 + atoi(cptr3);
	inp->s_addr = htonl(u);
	return 1;
}
