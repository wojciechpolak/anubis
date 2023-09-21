##
## doc/Makefile.am
##
## This file is part of GNU Anubis.
## Copyright (C) 2001-2020 The Anubis Team.
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

man_MANS = anubis.1
EXTRA_DIST = $(man_MANS) pixie-dixie.pl.txt gendocs_template 

info_TEXINFOS = anubis.texi
anubis_TEXINFOS = fdl.texi mime.texi pixie-dixie.texi

AM_MAKEINFOFLAGS=@IMPRIMATUR_MAKEINFOFLAGS@
imprimatur_INPUT=$(info_TEXINFOS) $(anubis_TEXINFOS)
include $(srcdir)/imprimatur/imprimatur.mk
CHECK_DOCS=$(top_srcdir)/@IMPRIMATUR_MODULE_DIR@/check-docs.sh
SUBDIRS = imprimatur

clean-local:
	rm -rf manual

GENDOCS=$(srcdir)/gendocs.sh

TEXI2DVI=texi2dvi -E
WEBDOC_MAKEINFOFLAGS=-I $(abs_srcdir)/imprimatur
WEBDOC_RENDITION = PUBLISH

# Make sure you set TEXINPUTS
# Usual value is:
# /usr/share/texmf/pdftex/plain/misc:/usr/share/texmf/pdftex/config
manual:
	TEXINPUTS=$(srcdir):$(top_srcdir)/build:$(TEXINPUTS) \
	 MAKEINFO="$(MAKEINFO) $(WEBDOC_MAKEINFOFLAGS) -D$(WEBDOC_RENDITION) $(MAKEINFOFLAGS)" \
	 TEXI2DVI="$(TEXI2DVI) -t '@set $(WEBDOC_RENDITION)' -t @finalout" \
	 TEXI2HTML="texi2html $(WEBDOC_MAKEINFOFLAGS)" \
	$(GENDOCS) --texi2html $(PACKAGE) '$(PACKAGE_NAME) manual'

manual-rebuild: clean-local manual

