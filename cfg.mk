# Copyright (C) 2006-2021 Simon Josefsson
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

manual_title = Simple Authentication and Security Layer
gendocs_options_ = -I ../examples

old_NEWS_hash = b7d3e53b0fe7030ba617c7010311aa92

gnulib_dir = $(GNULIB_SRCDIR)

bootstrap-tools = autoconf,automake,libtoolize,gnulib,makeinfo,help2man,gperf,gengetopt,gtkdocize,tar,gzip

INDENT_SOURCES = `find . -name '*.[chly]' | grep -v -e /gl -e build-aux -e /win32/ -e /examples/`

local-checks-to-skip = sc_error_message_uppercase			\
	sc_prohibit_gnu_make_extensions sc_prohibit_have_config_h	\
	sc_prohibit_strcmp sc_require_config_h				\
	sc_require_config_h_first

VC_LIST_ALWAYS_EXCLUDE_REGEX = \
	^((lib/)?GNUmakefile|gtk-doc.make|m4/pkg.m4|doc/gendocs_template|doc/fdl-1.3.texi|doc/specification|doc/doxygen/Doxyfile|(lib/)?po/.*.po.in|(lib/)?maint.mk|((lib/)?(gl|gltests|build-aux))/.*)

# Explicit syntax-check exceptions.
exclude_file_name_regexp--sc_prohibit_empty_lines_at_EOF = ^(lib/)?ABOUT-NLS|doc/.*\.(dia|png)|tests/gssapi.tkt$$
exclude_file_name_regexp--sc_GPL_version = ^doc/lgpl-2.1.texi|lib/.*$$
exclude_file_name_regexp--sc_copyright_check = ^doc/gsasl.texi$$
exclude_file_name_regexp--sc_m4_quote_check = ^m4/.*|lib/m4/.*$$
exclude_file_name_regexp-- = ^m4/.*|lib/m4/.*$$
exclude_file_name_regexp--sc_unmarked_diagnostics = ^examples/.*|src/gsasl.c$$
exclude_file_name_regexp--sc_makefile_TAB_only_indentation = ^(lib/)?po/Makefile.in.in$$
exclude_file_name_regexp--sc_makefile_path_separator_check = ^(lib/)?po/Makefile.in.in$$
exclude_file_name_regexp--sc_bindtextdomain = ^doc/print-errors.c|examples/.*|lib/digest-md5/test-parser.c|lib/tests/test-error.c|tests/.*$$
exclude_file_name_regexp--sc_program_name = $(exclude_file_name_regexp--sc_bindtextdomain)
exclude_file_name_regexp--sc_prohibit_magic_number_exit = ^(lib/)?m4/.*|doc/gsasl.texi|examples/(openid20|saml20)/.*.php|tests.*$$
exclude_file_name_regexp--sc_trailing_blank = ^(lib/)?ABOUT-NLS|doc/.*\.(eps|png)|(lib/)?po/.*$$
exclude_file_name_regexp--sc_space_tab = ^(lib/)?m4/lib-prefix.m4$$
exclude_file_name_regexp--sc_useless_cpp_parens = ^(lib/)?m4/.*$$
exclude_file_name_regexp--sc_prohibit_test_minus_ao = ^lib/m4/libgcrypt.m4$$
exclude_file_name_regexp--sc_prohibit_doubled_word = ^ABOUT-NLS$$
exclude_file_name_regexp--sc_prohibit_always_true_header_tests =^lib/win32/include/config.h$$

update-copyright-env = UPDATE_COPYRIGHT_HOLDER="Simon Josefsson" UPDATE_COPYRIGHT_USE_INTERVALS=2 UPDATE_COPYRIGHT_FORCE=1

review-tag ?= $(shell git describe --abbrev=0)
review-diff:
	git diff $(review-tag).. \
	| grep -v -e '^index' -e '^deleted file mode' -e '^diff --git' \
	| filterdiff -p 1 -x 'gl/*' -x 'm4/*' -x 'gltests/*' -x 'lib/build-aux/*' -x 'lib/gl*' -x 'lib/m4/*' -x 'lib/gltests/*' -x 'po/*' -x 'lib/po/*' -x 'maint.mk' -x 'lib/maint.mk' -x '.gitignore' -x '.x-sc*' -x 'doc/specification/*' -x ChangeLog -x GNUmakefile -x ABOUT-NLS -x lib/ABOUT-NLS \
	| less

# FIXME: gtkdoc doxygen
