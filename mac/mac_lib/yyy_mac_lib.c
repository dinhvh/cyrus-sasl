#include "sasl_mac_krb_locl.h"
#include <script.h>
#include <ToolUtils.h>

int krbONE=1;
int krb_debug;

int krb_get_config_bool(const char *variable)
{
	/* return the value of the only config variable we know of */
	if(strcmp(variable,"reverse_lsb_test")==0)
		return 0;
	return 0;
}

/*
 * compare two ip addresses
 */
int krb_equiv(
	u_int32_t a,
	u_int32_t b)
{
	if(a==0)
		return 1;
	if(b==0)
		return 1;
#ifdef STRICT_ADDRESS_EQUIV
	return a==b;
#else
	return 1;
#endif
}

int abs(int x)
{
  if(x>=0)
	return x;
  return -x;
}


/*
 * from kerberos.c -- return the offset from gmt
 */
static long getTimeZoneOffset(void )
{
	MachineLocation		macLocation;
	long			gmtDelta;

	macLocation.u.gmtDelta=0L;
	ReadLocation(&macLocation);
	gmtDelta=macLocation.u.gmtDelta & 0x00FFFFFF;
	if (BitTst((void *)&gmtDelta,23L))
		gmtDelta |= 0xFF000000;
	gmtDelta /= 3600L;
	return(gmtDelta);
}

/*
 * from kerberos.c -- convert mac time to unix time
 */
static void mac_time_to_unix_time (unsigned long *time)
{
	*time -= 66L * 365L * 24L * 60L * 60L + 17L * 60L * 60L * 24L + getTimeZoneOffset() * 60L * 60L;
}

/*
 * return the current unix time
 */
static unsigned long get_unix_time(void)
{
	unsigned long result;
	GetDateTime(&result);
	mac_time_to_unix_time(&result);
	return result;
}

/*
 * printf a warning
 */
void krb_warning(const char *fmt,...)
{
}

void krb_kdctimeofday (struct timeval *tv)
{
	gettimeofday(tv,0);
}

int gettimeofday(struct timeval *tp, void *foo)
{
	tp->tv_sec=get_unix_time();
	tp->tv_usec=0;
	return 0;
}

void swab(char *src, char *dst,int len)
{
	while(len>=2) {
		char a;
		char b;
		a= *src++;
		b= *src++;
		len-=2;
		*dst++=b;
		*dst++=a;
	}
}

char *inet_ntoa(unsigned long n)
{
#define BYTE0(xxx) ((int)((xxx)&0x0ff))
	static char buf[32];
	sprintf(buf,"%d.%d.%d.%d",
		BYTE0(n>>24),
		BYTE0(n>>16),
		BYTE0(n>>8),
		BYTE0(n));
	return buf;
}

#ifdef RUBBISH
u_int32_t lsb_time(
	time_t t,
	struct sockaddr_in *src,
	struct sockaddr_in *dst)
{
	return 0;
}
#endif
