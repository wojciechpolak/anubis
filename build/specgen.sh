#!/bin/sh
#
# This file is part of GNU Anubis.
# Copyright (C) 2001, 2002, 2003 The Anubis Team.
#
# GNU Anubis is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# GNU Anubis is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GNU Anubis; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
# GNU Anubis is released under the GPL with the additional exemption that
# compiling, linking, and/or using OpenSSL is allowed.
#

cat <<EOF
Summary: An outgoing mail processor and the SMTP tunnel.
Name: anubis
Version: $1
Release: 1
URL: http://www.gnu.org/software/anubis/
Source: ftp://ftp.gnu.org/gnu/anubis/%{name}-%{version}.tar.gz
Group: System Environment/Daemons
Copyright: GPL
BuildRoot: %{_tmppath}/%{name}-%{version}
BuildRequires: openssl-devel
Requires: openssl pidentd
Prereq: /sbin/chkconfig /sbin/install-info /usr/sbin/useradd /usr/sbin/userdel

%description
GNU Anubis is an outgoing mail processor. It goes between the MUA (Mail User
Agent) and the MTA (Mail Transport Agent), and can perform on the fly various
sorts of processing and conversion on the outgoing mail in accord with the
sender's specified rules, based on a highly configurable regular expressions
system. It operates as a proxy server, independently from mail user agents.
GNU Anubis can edit outgoing mail headers, encrypt and/or sign mail with the
GNU Privacy Guard, build secure SMTP tunnels (Simple Mail Transport Protocol)
using the TLS/SSL encryption even if your mail user agent doesn't support it,
or tunnel a connection through a SOCKS proxy server.

%define _initdir /etc/init.d
%define _unprivileged anubis.unprivileged

%prep
%setup -q

%build
CFLAGS="\$RPM_OPT_FLAGS" ./configure --prefix=/usr --with-openssl
make

%install
if [ -d \$RPM_BUILD_ROOT ]
then
 rm -fr \$RPM_BUILD_ROOT
fi
make install prefix=\$RPM_BUILD_ROOT/usr mandir=\$RPM_BUILD_ROOT%{_mandir} \
infodir=\$RPM_BUILD_ROOT%{_infodir}
mkdir -p \$RPM_BUILD_ROOT%{_initdir}
install -m 0755 ./scripts/redhat.init \$RPM_BUILD_ROOT%{_initdir}/anubis

%clean
rm -f ./src/anubis*
rm -fr \$RPM_BUILD_ROOT
make distclean

%pre
rm -f %{_infodir}/anubis.info*
rm -f %{_mandir}/man1/anubis.1*
rm -f /usr/man/man1/anubis.1*
/usr/sbin/useradd -s /dev/null %{_unprivileged} >/dev/null 2>&1 || :

%post
/sbin/install-info %{_infodir}/anubis.info.gz %{_infodir}/dir

%preun
%{_initdir}/anubis stop >/dev/null 2>&1
/sbin/chkconfig --del anubis >/dev/null 2>&1
/sbin/install-info --delete %{_infodir}/anubis.info.gz %{_infodir}/dir

%postun
/usr/sbin/userdel -r %{_unprivileged} >/dev/null 2>&1 || :

%files
%defattr(-,root,root)
%doc COPYING AUTHORS THANKS README INSTALL NEWS ChangeLog TODO
%doc examples contrib
%{_mandir}/man1/anubis.1*
%attr(0644,root,root) %{_infodir}/anubis.info*
%attr(0755,root,root) %{_sbindir}/anubis
%attr(0755,root,root) %config %{_initdir}/anubis
%attr(0644,root,root) /usr/share/locale/*/*/anubis.mo

%changelog
* Tue Dec 03 2002  Wojciech Polak <polak@gnu.org>
- removed default system configuration file.

* Fri Nov 01 2002  Wojciech Polak <polak@gnu.org>
- updated to GNU. Now it's GNU Anubis!

# EOF

