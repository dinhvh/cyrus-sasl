# Makefile.am for the SASL plugins
# Rob Siemborski
# Rob Earhart
# $Id: Makefile.am,v 1.39.2.19 2001/07/30 18:59:16 rjs3 Exp $
#
################################################################
# Copyright (c) 2000 Carnegie Mellon University.  All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer. 
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# 3. The name "Carnegie Mellon University" must not be used to
#    endorse or promote products derived from this software without
#    prior written permission. For permission or any other legal
#    details, please contact  
#      Office of Technology Transfer
#      Carnegie Mellon University
#      5000 Forbes Avenue
#      Pittsburgh, PA  15213-3890
#      (412) 268-4387, fax: (412) 268-7395
#      tech-transfer@andrew.cmu.edu
#
# 4. Redistributions of any form whatsoever must retain the following
#    acknowledgment:
#    "This product includes software developed by Computing Services
#     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
#
# CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
# THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
# FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
# AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
# OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
################################################################

# Library version info - here at the top, for sanity
# CURRENT:REVISION:AGE
plain_version = 1:1:0
anonymous_version = 1:1:0
kerberos4_version = 1:2:0
crammd5_version = 1:1:0
gssapiv2_version = 1:1:0
digestmd5_version = 1:2:0
login_version = 1:1:0
sasldb_version = 1:0:0
srp_version = 1:1:0

INCLUDES=-I$(top_srcdir)/include -I$(top_srcdir)/lib
LDFLAGS = @LDFLAGS@ -module -export-dynamic -rpath $(plugindir)

EXTRA_DIST = makeinit.sh
noinst_SCRIPTS = makeinit.sh

plugindir = @plugindir@

common_sources = plugin_common.c plugin_common.h

sasldir = $(prefix)/lib/sasl2
sasl_LTLIBRARIES = @SASL_MECHS@
EXTRA_LTLIBRARIES = libplain.la libanonymous.la libkerberos4.la libcrammd5.la \
	libgssapiv2.la libdigestmd5.la liblogin.la libsrp.la libsasldb.la

libplain_la_SOURCES = plain.c plain_init.c $(common_sources)
libplain_la_LDFLAGS = -version-info $(plain_version)
libplain_la_LIBADD = $(PLAIN_LIBS)

libanonymous_la_SOURCES = anonymous.c anonymous_init.c $(common_sources)
libanonymous_la_LDFLAGS = -version-info $(anonymous_version)

libkerberos4_la_SOURCES = kerberos4.c kerberos4_init.c $(common_sources)
libkerberos4_la_LDFLAGS = -version-info $(kerberos4_version)
libkerberos4_la_LIBADD = $(SASL_KRB_LIB) $(LIB_SOCKET)

libgssapiv2_la_SOURCES = gssapi.c gssapiv2_init.c $(common_sources)
libgssapiv2_la_LDFLAGS = -version-info $(gssapiv2_version)
libgssapiv2_la_LIBADD = $(GSSAPIBASE_LIBS) $(GSSAPI_LIBS) $(LIB_SOCKET)

libcrammd5_la_SOURCES = cram.c crammd5_init.c $(common_sources)
libcrammd5_la_LDFLAGS = -version-info $(crammd5_version)

libdigestmd5_la_SOURCES = digestmd5.c digestmd5_init.c $(common_sources)
libdigestmd5_la_LDFLAGS = -version-info $(digestmd5_version)
libdigestmd5_la_LIBADD = $(LIB_DES) $(LIB_SOCKET)

liblogin_la_SOURCES = login.c login_init.c $(common_sources)
liblogin_la_LDFLAGS = -version-info $(login_version)
liblogin_la_LIBADD = $(PLAIN_LIBS)

libsrp_la_SOURCES = srp.c srp_init.c $(common_sources)
libsrp_la_LDFLAGS = -version-info $(srp_version)
libsrp_la_LIBADD = $(SRP_LIBS)

# Auxprop Plugins
libsasldb_la_SOURCES = sasldb.c sasldb_init.c $(common_sources)
libsasldb_la_LDFLAGS = -version-info $(sasldb_version)
libsasldb_la_LIBADD = ../sasldb/libsasldb.la

# Instructions for making the _init files

init_src=anonymous_init.c crammd5_init.c digestmd5_init.c gssapiv2_init.c \
kerberos4_init.c login_init.c plain_init.c srp_init.c sasldb_init.c

CLEANFILES=$(init_src)

${init_src}: $(srcdir)/makeinit.sh
	$(SHELL) $(srcdir)/makeinit.sh
