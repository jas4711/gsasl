# Copyright (C) 2002-2022 Simon Josefsson
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

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libgsasl.pc

# Visual Studio project files.
EXTRA_DIST = win32/libgsasl.sln win32/libgsasl.vcproj		\
	win32/include/ac-stdint.h win32/include/alloca.h	\
	win32/include/idn-int.h win32/include/stdbool.h		\
	win32/include/stdint.h win32/include/unistd.h		\
	win32/include/config.h

EXTRA_DIST += m4/gnulib-cache.m4

SUBDIRS = gl

# Plugins:
if EXTERNAL
SUBDIRS += external
endif

if ANONYMOUS
SUBDIRS += anonymous
endif

if PLAIN
SUBDIRS += plain
endif

if LOGIN
SUBDIRS += login
endif

if CRAM_MD5
SUBDIRS += cram-md5
endif

if DIGEST_MD5
SUBDIRS += digest-md5
endif

if SCRAM
SUBDIRS += scram
endif

if SAML20
SUBDIRS += saml20
endif

if OPENID20
SUBDIRS += openid20
endif

if NTLM
SUBDIRS += ntlm
endif

if GSSAPI
SUBDIRS += gssapi
endif

if GS2
SUBDIRS += gs2
endif

if SECURID
SUBDIRS += securid
endif

SUBDIRS += src
