##
## Makefile.am
##
## This file is part of GNU Anubis.
## Copyright (C) 2001-2023 The Anubis Team.
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

ACLOCAL_AMFLAGS = -I m4 -I am -I gint -I doc/imprimatur
SUBDIRS = build gint src po doc scripts examples guile contrib \
	  elisp tests 

AM_DISTCHECK_CONFIGURE_FLAGS =\
 --with-gsasl\
 --with-mysql\
 --with-postgres\
 --with-pam\
 --with-tcp-wrappers\
 --with-socks-proxy\
 --with-pcre

gen_start_date = 2008-12-16
prev_change_log = ChangeLog-CVS-old

.PHONY: ChangeLog
ChangeLog:
	$(AM_V_GEN)if test -d .git; then                                    \
          (git log --pretty='format:%ad  %cn  <%ae>%n%n%w(72,8,8)%s%n%n%b'  \
                   --date=short                                             \
                   --since=$(gen_start_date);                               \
           echo "";                                                         \
           cat $(prev_change_log);                                          \
           echo "") > ChangeLog.tmp;                                        \
          cmp ChangeLog ChangeLog.tmp > /dev/null 2>&1 ||                   \
            mv ChangeLog.tmp ChangeLog;                                     \
          rm -f ChangeLog.tmp;                                              \
        fi
