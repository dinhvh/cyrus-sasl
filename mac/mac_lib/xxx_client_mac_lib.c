/*
 * routines used by the sasl test programs and not provided
 * by a mac.  see also xxx_mac_lib.c for routines needed by
 * the sasl library and not supplied by the system runtime
 */

#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>
 
#include <config.h>
#include <netinet/in.h>

char *__progname="mac";

struct hostent *gethostbyname(const char *hnam)
{
	static struct hostent result;
	int bytes[4];
	int i;
	unsigned int ip=0;
	if(sscanf(hnam,"%d.%d.%d.%d",bytes,bytes+1,bytes+2,bytes+3)!=4)
		return 0;
	for(i=0;i<4;i++) {
		ip<<=8;
		ip|=(bytes[i]&0x0ff);
	}
	memcpy(result.h_addr,&ip,4);
	return &result;
}

/*
 * ala perl chomp
 */
static void xxy_chomp(char *s,const char stop_here)
{
	char ch;
	while((ch= (*s++))!=0)
		if(ch==stop_here) {
			s[-1]=0;
			return;
		}
}

char* getpass(const char *prompt)
{
	const int max_buf=200;
	char *buf=malloc(max_buf);
	if(buf==0)
		return 0;
	memset(buf,0,max_buf);  /* not likely to be a performance issue eheh */
	printf("%s",prompt);
	fgets(buf,max_buf-1,stdin);
	xxy_chomp(buf,'\n');
	return buf;
}

#ifdef TARGET_API_MAC_CARBON
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
#endif
