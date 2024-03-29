##
## src/Makefile.am
##
## This file is part of GNU Anubis.
## Copyright (C) 2001-2024 The Anubis Team.
##
## GNU Anubis is free software; you can redistribute it and/or modify it
## under the terms of the GNU General Public License as published by the
## Free Software Foundation; either version 3 of the License, or (at your
## option) any later version.
##
## GNU Anubis is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License along
## with GNU Anubis.  If not, see <http://www.gnu.org/licenses/>.
##

adm_sbin_programs = anubisadm 
adm_bin_programs =

sbin_PROGRAMS = anubis @ANUBIS_SBIN_ADM@
bin_PROGRAMS = @ANUBIS_BIN_ADM@
EXTRA_PROGRAMS = $(adm_bin_programs) $(adm_sbin_programs)

noinst_LIBRARIES = libanubis.a
anubis_LDADD = \
 ./libanubis.a\
 @LIBINTL@\
 $(GUILE_LIBS)\
 @LIBGNUTLS_LIBS@\
 @GSASL_LIBS@\
 $(LIBGCRYPT_LIBS)

anubis_SOURCES = \
 authmode.c \
 daemon.c \
 env.c \
 errs.c \
 esmtp.c \
 exec.c \
 extern.h \
 headers.h \
 help.c \
 ident.c \
 log.c \
 logport.c\
 main.c \
 map.c \
 mda.c \
 message.c \
 mime.c \
 misc.c \
 net.c \
 proclist.c \
 quit.c \
 rcfile.c \
 rcfile.h \
 rc-gram.y \
 rc-gram.h \
 rc-lex.l \
 regex.c \
 socks.c \
 transmode.c \
 tunnel.c

if GSASL_COND
  anubis_SOURCES += gsasl_srv.c
endif

if GPG_COND
  anubis_SOURCES += gpg.c
endif

if GUILE_COND
  anubis_SOURCES += guile.c
endif

if GCRYPT_COND
  anubis_SOURCES += idecrypt.c
endif

anubisadm_SOURCES = anubisadm.c anubisadm.h adm.c
anubisadm_LDADD = ./libanubis.a @LIBINTL@
anubisusr_SOURCES = anubisusr.c anubisusr.h usr.c
anubisusr_LDADD = ./libanubis.a @LIBINTL@ @LIBGNUTLS_LIBS@ @GSASL_LIBS@ 

libanubis_a_SOURCES = \
 anubisdb.c \
 dbtext.c \
 getpass.c \
 keyword.c \
 keyword.h \
 list.c \
 list.h \
 mem.c \
 mysql.c \
 pgsql.c \
 sql.h \
 sql.c \
 smtprepl.c \
 smtprepl.h \
 stream.c \
 url.c \
 wordsplit/wordsplit.c \
 wordsplit/wordsplit.h

if TLS_COND
  libanubis_a_SOURCES += tls.c md5sum.c xdatabase.c
  adm_bin_programs += anubisusr
else
  libanubis_a_SOURCES += notls.c
endif

if GSASL_COND
  libanubis_a_SOURCES += gsasl.c
endif

if GDBM_COND
  libanubis_a_SOURCES += gdbm.c
endif


AM_YFLAGS = -dtv
AM_LFLAGS = -dvp
EXTRA_DIST = getopt.m4 env.opt gettext.h

BUILT_SOURCES = env.c

localedir = $(datadir)/locale
DEFS = @DEFS@ -DLOCALEDIR=\"$(localedir)\"
AM_CPPFLAGS =\
 @ADD_INCLUDES@\
 @GUILE_INCLUDES@\
 @LIBGNUTLS_INCLUDES@\
 $(LIBGCRYPT_CFLAGS)\
 -I$(top_srcdir)\
 -I$(srcdir)\
 -I$(srcdir)/wordsplit

SUFFIXES=.opt .c

.opt.c:
	m4 -s $(top_srcdir)/src/getopt.m4 $< | sed '1d' > $@

FLOWCHART_FILES=$(anubis_SOURCES) $(libanubis_a_SOURCES)

flowchart: anubis.cflow

anubis.cflow: $(FLOWCHART_FILES)
	CFLOWRC=$(top_srcdir)/build/cflow.rc \
	 cflow -o$@ --brief -i^s $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) \
	            $(CPPFLAGS) `echo $(FLOWCHART_FILES)|sed 's/[^ ]*\.h //g'`

## EOF

