#include <stdio.h>

@TOP@

/* Symbols that need defining */
/* do we have gssapi.h or gssapi/gssapi.h? */
#undef HAVE_GSSAPI_H

/* what flavor of GSSAPI are we using? */
#undef HAVE_GSS_C_NT_HOSTBASED_SERVICE

/* Do we have kerberos for plaintext password checking? */
#undef HAVE_KRB

/* do we have SIA for plaintext password checking? */
#undef HAVE_SIA

/* do we have a getuserpw? */
#undef HAVE_GETUSERPW

/* do we have a getspnam? */
#undef HAVE_GETSPNAM

/* Path to saslauthd rundir */
#undef PATH_SASLAUTHD_RUNDIR

/* Things SASLAUTHd doesn't really care about */
#undef HAVE_SASLAUTHD
#undef STATIC_GSSAPIV2
#undef STATIC_KERBEROS4
#undef STATIC_PLAIN

@BOTTOM@

#ifndef NI_WITHSCOPEID
#define NI_WITHSCOPEID  0
#endif

