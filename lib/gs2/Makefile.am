## Process this file with automake to produce Makefile.in
# Copyright (C) 2006-2022 Simon Josefsson.
#
# This file is part of GNU SASL Library.
#
# GNU SASL Library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public License
# as published by the Free Software Foundation; either version 2.1 of
# the License, or (at your option) any later version.
#
# GNU SASL Library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with GNU SASL Library; if not, write to the Free
# Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301, USA.

AM_CFLAGS = $(WERROR_CFLAGS) $(WSTACK_CFLAGS) $(WARN_CFLAGS)
AM_CFLAGS += $(CFLAG_VISIBILITY)
AM_CPPFLAGS = -I$(srcdir)/../src -I../src -I$(srcdir)/../gl -I../gl \
	$(GSS_CFLAGS)

noinst_LTLIBRARIES = libgsasl-gs2.la
libgsasl_gs2_la_SOURCES = gs2.h mechinfo.c \
	gs2helper.h gs2helper.c

if CLIENT
libgsasl_gs2_la_SOURCES += client.c
endif

if SERVER
libgsasl_gs2_la_SOURCES += server.c
endif

libgsasl_gs2_la_LIBADD = $(LTLIBGSS) $(LTLIBGSSGLUE) $(LTLIBGSSAPI32) $(GSS_LIBS)
