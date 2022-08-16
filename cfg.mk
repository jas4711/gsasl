# Copyright (C) 2006-2022 Simon Josefsson
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

old_NEWS_hash = 4d694b6f076185fa2ca47424abd485f7

bootstrap-tools = autoconf,automake,libtoolize,gnulib,makeinfo,help2man,gperf,gengetopt,gtkdocize,tar,gzip

update-copyright-env = \
	UPDATE_COPYRIGHT_HOLDER="Simon Josefsson"	\
	UPDATE_COPYRIGHT_USE_INTERVALS=2		\
	UPDATE_COPYRIGHT_FORCE=1

review-tag ?= $(shell git describe --abbrev=0)
review-diff:
	git diff $(review-tag).. \
	| grep -v -e '^index' -e '^deleted file mode' -e '^new file mode' \
	| filterdiff -p 1 -x 'gl/*' -x 'm4/*' -x 'gltests/*' -x 'lib/gl*' -x 'lib/m4/*' -x 'po/*' -x 'maint.mk' -x '.gitignore' -x '.x-sc*' -x ChangeLog -x GNUmakefile -x ABOUT-NLS -x .prev-version -x .gitlab-ci.yml -x autogen.sh -x autopull.sh -x bootstrap -x bootstrap-funclib.sh \
	| less

# syntax-check
local-checks-to-skip = sc_error_message_uppercase			\
	sc_prohibit_gnu_make_extensions sc_prohibit_have_config_h	\
	sc_prohibit_strcmp sc_require_config_h				\
	sc_require_config_h_first
exclude_file_name_regexp--sc_GPL_version = ^m4/pkg.m4|build-aux/git2cl|lib/.*$$
exclude_file_name_regexp--sc_bindtextdomain = ^doc/print-errors.c|examples/.*|lib/digest-md5/test-parser.c|lib/tests/test-error.c|tests/.*$$
exclude_file_name_regexp--sc_file_system = ^doc/doxygen/Doxyfile.*$$
exclude_file_name_regexp--sc_prohibit_always_true_header_tests = ^lib/win32/include/config.h$$
exclude_file_name_regexp--sc_prohibit_defined_have_decl_tests = ^lib/gl/lib/gss-extra.c$$
exclude_file_name_regexp--sc_prohibit_empty_lines_at_EOF = ^gl/0001-Fix-export-symbols-and-export-symbols-regex-support-.patch|doc/gsasl-[2a-z]*.(dia|png)|tests/gssapi.tkt$$
exclude_file_name_regexp--sc_prohibit_magic_number_exit = ^doc/gsasl.texi|examples/(openid20|saml20)/.*.php$$
exclude_file_name_regexp--sc_trailing_blank = ^gl/0001-Fix-export-symbols-and-export-symbols-regex-support-.patch|build-aux/git2cl|doc/gsasl-[2a-z]*.(eps|png|pdf|dia)|doc/doxygen/Doxyfile.*|gl/doc/gendocs_template.diff|gl/top/README-release.diff$$
exclude_file_name_regexp--sc_space_tab = ^doc/gsasl-controlflow.pdf$$
exclude_file_name_regexp--sc_unmarked_diagnostics = ^examples/.*|src/gsasl.c$$

# maint.mk's public-submodule-commit breaks on shallow gnulib
# https://lists.gnu.org/archive/html/bug-gnulib/2022-08/msg00040.html
# so let's disable it - XXX FIXME let's revisit this later
submodule-checks =
gl_public_submodule_commit =
