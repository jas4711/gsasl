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

DISTCHECK_CONFIGURE_FLAGS = --enable-gtk-doc --with-gssapi-impl=no

ACLOCAL_AMFLAGS = -I m4 -I lib/m4

SUBDIRS = lib po gl src examples tests doc gltests

EXTRA_DIST = cfg.mk maint.mk
EXTRA_DIST += build-aux/git2cl
EXTRA_DIST += m4/gnulib-cache.m4

# git-version-gen
EXTRA_DIST += $(top_srcdir)/.version
BUILT_SOURCES = $(top_srcdir)/.version
$(top_srcdir)/.version:
	echo $(VERSION) > $@-t && mv $@-t $@
dist-hook: gen-ChangeLog
	echo $(VERSION) > $(distdir)/.tarball-version

.PHONY: gen-ChangeLog
gen-ChangeLog:
	$(AM_V_GEN)if test -d .git; then				\
		$(srcdir)/build-aux/git2cl > $(distdir)/cl-t &&		\
		{ tail -6 NEWS >> $(distdir)/cl-t &&			\
		  rm -f $(distdir)/ChangeLog &&				\
		  mv $(distdir)/cl-t $(distdir)/ChangeLog; }		\
	fi
