# This file is part of GNU Anubis.
# Copyright (C) 2020-2023 The Anubis Team.
#
# Anubis is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
#
# Anubis is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with anubis.  If not, see <http://www.gnu.org/licenses/>.

EXTRA_DIST = $(TESTSUITE_AT) testsuite package.m4
DISTCLEANFILES       = atconfig $(check_SCRIPTS)
MAINTAINERCLEANFILES = Makefile.in $(TESTSUITE)

## ------------ ##
## package.m4.  ##
## ------------ ##

$(srcdir)/package.m4: $(top_srcdir)/configure.ac
	$(AM_V_GEN){                                      \
	  echo '# Signature of the current package.'; \
	  echo 'm4_define([AT_PACKAGE_NAME],      [@PACKAGE_NAME@])'; \
	  echo 'm4_define([AT_PACKAGE_TARNAME],   [@PACKAGE_TARNAME@])'; \
	  echo 'm4_define([AT_PACKAGE_VERSION],   [@PACKAGE_VERSION@])'; \
	  echo 'm4_define([AT_PACKAGE_STRING],    [@PACKAGE_STRING@])'; \
	  echo 'm4_define([AT_PACKAGE_BUGREPORT], [@PACKAGE_BUGREPORT@])'; \
	} >$(srcdir)/package.m4

#

## ------------ ##
## Test suite.  ##
## ------------ ##

TESTSUITE_AT = \
  anubisusr.at\
  bmod.at\
  cond.at\
  empty.at\
  badd.at\
  fadd.at\
  hadd00.at\
  hadd01.at\
  hadd02.at\
  hdel00.at\
  hdel01.at\
  hdel02.at\
  hdel03.at\
  hmod.at\
  gpgcrypt.at\
  gpgsign.at\
  gpgse.at\
  mime00.at\
  mime01.at\
  mult.at\
  no-backref.at\
  parse.at\
  paolo.at\
  remailer.at\
  rot-13.at\
  testsuite.at\
  tlsoneway.at\
  trigger.at

TESTSUITE = $(srcdir)/testsuite
M4=m4

AUTOTEST = $(AUTOM4TE) --language=autotest
$(TESTSUITE): package.m4 $(TESTSUITE_AT)
	$(AM_V_GEN)$(AUTOTEST) -I $(srcdir) testsuite.at -o $@.tmp
	$(AM_V_at)mv $@.tmp $@

atconfig: $(top_builddir)/config.status 
	cd $(top_builddir) && ./config.status tests/$@

clean-local:
	@test ! -f $(TESTSUITE) || $(SHELL) $(TESTSUITE) --clean

check-local: atconfig atlocal $(TESTSUITE)
	@$(SHELL) $(TESTSUITE)

noinst_PROGRAMS=anustart mta
mta_LDADD = @LIBGNUTLS_LIBS@
AM_CPPFLAGS = @LIBGNUTLS_INCLUDES@

