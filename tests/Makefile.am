## Process this file with automake to produce Makefile.in
# Copyright (C) 2002-2022 Simon Josefsson
#
# This file is part of GNU SASL.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

dist_noinst_DATA = cram-md5.pwd

AM_CFLAGS = $(WERROR_CFLAGS) $(WARN_CFLAGS) $(WEASY_CFLAGS)
AM_CPPFLAGS = -I$(top_srcdir)/gl -I$(top_builddir)/gl \
	 -I$(top_srcdir)/lib/src -I$(top_builddir)/lib/src
AM_LDFLAGS = -no-install
LDADD = ../lib/src/libgsasl.la libutils.la
LDADD += ../lib/gl/liblgl.la ../gl/libgl.la

EXTRA_DIST = libgsasl.supp gssapi.key gssapi.tkt shishi.conf

noinst_LTLIBRARIES = libutils.la
libutils_la_SOURCES = utils.h utils.c

AM_TESTS_ENVIRONMENT = \
	GSASL="$(LIBTOOL) --mode=execute $(LOG_VALGRIND) ../src/gsasl$(EXEEXT)" \
	SHISHI_KEYS=$(srcdir)/gssapi.key \
	SHISHI_TICKETS=$(srcdir)/gssapi.tkt \
	SHISHI_CONFIG=$(srcdir)/shishi.conf \
	SHISHI_HOME=$(srcdir) \
	SHISHI_USER=ignore-this-warning \
	THREADSAFETY_FILES=`ls $(top_srcdir)/lib/*/*.c | $(GREP) -v -e lib/gl/vasnprintf.c -e lib/gl/getdelim.c -e lib/gltests/` \
	MD5FILE=$(srcdir)/cram-md5.pwd \
	EGREP="$(EGREP)" \
	GNUGSS="$(HAVE_LIBGSS)"; \
	export GSASL SHISHI_KEYS SHISHI_TICKETS SHISHI_CONFIG SHISHI_HOME SHISHI_USER THREADSAFETY_FILES MD5FILE EGREP GNUGSS;

LOG_COMPILER=$(VALGRIND)

ctests = version external cram-md5 digest-md5 md5file name errors	\
	suggest simple crypto scram scramplus symbols readnz gssapi	\
	gs2-krb5 saml20 openid20 scram-sha256 scram-simple		\
	scram-nopasswd startcb scram-incremental scram-exporter

check_PROGRAMS = $(ctests)
dist_check_SCRIPTS = threadsafety.sh gsasl-scram-pbkdf2.sh gsasl-mailutils-cram.sh gsasl-dovecot-gssapi.sh
TEST_EXTENSIONS = .sh
TESTS = $(dist_check_SCRIPTS) $(ctests)
