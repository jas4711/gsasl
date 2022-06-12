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

SUBDIRS = cyclo
if ENABLE_GTK_DOC
SUBDIRS += reference
endif

EXTRA_DIST = gdoc \
	gsasl-controlflow.dia gsasl-controlflow2.dia gsasl-abstraction.dia \
	doxygen/Doxyfile.in doxygen/gdoc2doxygen

.dia.png:
	$(DIA) --export=$@ $<

.dia.eps:
	$(DIA) --export=$@ $<

.eps.pdf:
	$(EPSTOPDF) $<

info_TEXINFOS = gsasl.texi
gsasl_TEXINFOS = fdl-1.3.texi $(gdoc_TEXINFOS) \
	gsasl-controlflow.eps gsasl-controlflow.png gsasl-controlflow.pdf \
	gsasl-controlflow2.eps gsasl-controlflow2.png gsasl-controlflow2.pdf \
	gsasl-abstraction.eps gsasl-abstraction.png gsasl-abstraction.pdf \
	gsasl-api-error-labels.texi

AM_CPPFLAGS = -I$(top_builddir)/lib/src -I$(top_srcdir)/lib/src
noinst_PROGRAMS = print-errors
print_errors_LDADD = ../lib/src/libgsasl.la

gsasl-api-error-labels.texi: $(top_srcdir)/lib/src/error.c print-errors.c
	make print-errors$(EXEEXT)
	$(builddir)/print-errors$(EXEEXT) > $@.new
	mv $@.new $@

AM_MAKEINFOFLAGS = -I $(top_srcdir)/examples \
	-I $(top_srcdir)/doc -I $(top_builddir)/doc
TEXI2DVI = texi2dvi $(AM_MAKEINFOFLAGS)
AM_MAKEINFOHTMLFLAGS = --no-split $(AM_MAKEINFOFLAGS)

dist_man_MANS = gsasl.1 $(gdoc_MANS)
MAINTAINERCLEANFILES = $(dist_man_MANS)

gsasl.1: $(top_srcdir)/src/gsasl.c $(top_srcdir)/src/gsasl.ggo \
		$(top_srcdir)/.version
	$(AM_V_GEN)$(HELP2MAN) \
		--name="SASL library command line interface" \
		--output=$@ $(top_builddir)/src/gsasl$(EXEEXT)

gdoc_MANS =
gdoc_MANS += man/gsasl_base64_to.3
gdoc_MANS += man/gsasl_base64_from.3
gdoc_MANS += man/gsasl_hex_to.3
gdoc_MANS += man/gsasl_hex_from.3
gdoc_MANS += man/gsasl_callback_set.3
gdoc_MANS += man/gsasl_callback.3
gdoc_MANS += man/gsasl_callback_hook_set.3
gdoc_MANS += man/gsasl_callback_hook_get.3
gdoc_MANS += man/gsasl_session_hook_set.3
gdoc_MANS += man/gsasl_session_hook_get.3
gdoc_MANS += man/gsasl_nonce.3
gdoc_MANS += man/gsasl_random.3
gdoc_MANS += man/gsasl_hash_length.3
gdoc_MANS += man/gsasl_scram_secrets_from_salted_password.3
gdoc_MANS += man/gsasl_scram_secrets_from_password.3
gdoc_MANS += man/gsasl_done.3
gdoc_MANS += man/gsasl_strerror.3
gdoc_MANS += man/gsasl_strerror_name.3
gdoc_MANS += man/gsasl_free.3
gdoc_MANS += man/gsasl_init.3
gdoc_MANS += man/gsasl_client_mechlist.3
gdoc_MANS += man/gsasl_server_mechlist.3
gdoc_MANS += man/gsasl_simple_getpass.3
gdoc_MANS += man/gsasl_mechanism_name.3
gdoc_MANS += man/gsasl_property_free.3
gdoc_MANS += man/gsasl_property_set.3
gdoc_MANS += man/gsasl_property_set_raw.3
gdoc_MANS += man/gsasl_property_fast.3
gdoc_MANS += man/gsasl_property_get.3
gdoc_MANS += man/gsasl_register.3
gdoc_MANS += man/gsasl_saslprep.3
gdoc_MANS += man/gsasl_mechanism_name_p.3
gdoc_MANS += man/gsasl_client_suggest_mechanism.3
gdoc_MANS += man/gsasl_client_support_p.3
gdoc_MANS += man/gsasl_server_support_p.3
gdoc_MANS += man/gsasl_check_version.3
gdoc_MANS += man/gsasl_encode.3
gdoc_MANS += man/gsasl_decode.3
gdoc_MANS += man/gsasl_finish.3
gdoc_MANS += man/gsasl_client_start.3
gdoc_MANS += man/gsasl_server_start.3
gdoc_MANS += man/gsasl_step.3
gdoc_MANS += man/gsasl_step64.3

gdoc_TEXINFOS =
gdoc_TEXINFOS += texi/base64.c.texi
gdoc_TEXINFOS += texi/callback.c.texi
gdoc_TEXINFOS += texi/crypto.c.texi
gdoc_TEXINFOS += texi/done.c.texi
gdoc_TEXINFOS += texi/doxygen.c.texi
gdoc_TEXINFOS += texi/error.c.texi
gdoc_TEXINFOS += texi/free.c.texi
gdoc_TEXINFOS += texi/init.c.texi
gdoc_TEXINFOS += texi/listmech.c.texi
gdoc_TEXINFOS += texi/md5pwd.c.texi
gdoc_TEXINFOS += texi/mechname.c.texi
gdoc_TEXINFOS += texi/mechtools.c.texi
gdoc_TEXINFOS += texi/property.c.texi
gdoc_TEXINFOS += texi/register.c.texi
gdoc_TEXINFOS += texi/saslprep.c.texi
gdoc_TEXINFOS += texi/suggest.c.texi
gdoc_TEXINFOS += texi/supportp.c.texi
gdoc_TEXINFOS += texi/version.c.texi
gdoc_TEXINFOS += texi/xcode.c.texi
gdoc_TEXINFOS += texi/xfinish.c.texi
gdoc_TEXINFOS += texi/xstart.c.texi
gdoc_TEXINFOS += texi/xstep.c.texi
gdoc_TEXINFOS += texi/gsasl_base64_to.texi
gdoc_TEXINFOS += texi/gsasl_base64_from.texi
gdoc_TEXINFOS += texi/gsasl_hex_to.texi
gdoc_TEXINFOS += texi/gsasl_hex_from.texi
gdoc_TEXINFOS += texi/gsasl_callback_set.texi
gdoc_TEXINFOS += texi/gsasl_callback.texi
gdoc_TEXINFOS += texi/gsasl_callback_hook_set.texi
gdoc_TEXINFOS += texi/gsasl_callback_hook_get.texi
gdoc_TEXINFOS += texi/gsasl_session_hook_set.texi
gdoc_TEXINFOS += texi/gsasl_session_hook_get.texi
gdoc_TEXINFOS += texi/gsasl_nonce.texi
gdoc_TEXINFOS += texi/gsasl_random.texi
gdoc_TEXINFOS += texi/gsasl_hash_length.texi
gdoc_TEXINFOS += texi/gsasl_scram_secrets_from_salted_password.texi
gdoc_TEXINFOS += texi/gsasl_scram_secrets_from_password.texi
gdoc_TEXINFOS += texi/gsasl_done.texi
gdoc_TEXINFOS += texi/gsasl_strerror.texi
gdoc_TEXINFOS += texi/gsasl_strerror_name.texi
gdoc_TEXINFOS += texi/gsasl_free.texi
gdoc_TEXINFOS += texi/gsasl_init.texi
gdoc_TEXINFOS += texi/gsasl_client_mechlist.texi
gdoc_TEXINFOS += texi/gsasl_server_mechlist.texi
gdoc_TEXINFOS += texi/gsasl_simple_getpass.texi
gdoc_TEXINFOS += texi/gsasl_mechanism_name.texi
gdoc_TEXINFOS += texi/gsasl_property_free.texi
gdoc_TEXINFOS += texi/gsasl_property_set.texi
gdoc_TEXINFOS += texi/gsasl_property_set_raw.texi
gdoc_TEXINFOS += texi/gsasl_property_fast.texi
gdoc_TEXINFOS += texi/gsasl_property_get.texi
gdoc_TEXINFOS += texi/gsasl_register.texi
gdoc_TEXINFOS += texi/gsasl_saslprep.texi
gdoc_TEXINFOS += texi/gsasl_mechanism_name_p.texi
gdoc_TEXINFOS += texi/gsasl_client_suggest_mechanism.texi
gdoc_TEXINFOS += texi/gsasl_client_support_p.texi
gdoc_TEXINFOS += texi/gsasl_server_support_p.texi
gdoc_TEXINFOS += texi/gsasl_check_version.texi
gdoc_TEXINFOS += texi/gsasl_encode.texi
gdoc_TEXINFOS += texi/gsasl_decode.texi
gdoc_TEXINFOS += texi/gsasl_finish.texi
gdoc_TEXINFOS += texi/gsasl_client_start.texi
gdoc_TEXINFOS += texi/gsasl_server_start.texi
gdoc_TEXINFOS += texi/gsasl_step.texi
gdoc_TEXINFOS += texi/gsasl_step64.texi

$(gdoc_MANS) $(gdoc_TEXINFOS):
	make update-makefile
	make Makefile
	make doit

GDOC_SRC = $(top_srcdir)/lib/src/*.c

update-makefile:
	MANS=""; \
	TEXINFOS=""; \
	for i in $(GDOC_SRC); do \
		BASE=`basename $$i`; \
		TEXINFOS="$$TEXINFOS\ngdoc_TEXINFOS += texi/$$BASE.texi"; \
	done; \
	FUNCS=`$(srcdir)/gdoc -listfunc $(GDOC_SRC)`; \
	for i in $$FUNCS; do \
		MANS="$$MANS\ngdoc_MANS += man/$$i.3"; \
		TEXINFOS="$$TEXINFOS\ngdoc_TEXINFOS += texi/$$i.texi"; \
	done; \
	grep -v -e '^gdoc_MANS += ' -e '^gdoc_TEXINFOS += ' Makefile.am | \
		perl -p -e "s,^gdoc_MANS =,gdoc_MANS =$$MANS," | \
		perl -p -e "s,^gdoc_TEXINFOS =,gdoc_TEXINFOS =$$TEXINFOS,;" \
		> Makefile.am.new && \
	mv Makefile.am.new Makefile.am

doit:
	@$(mkdir_p) man texi; \
	echo -n "Creating function documentation" && \
	for i in `$(srcdir)/gdoc -listfunc $(GDOC_SRC)`; do \
		$(srcdir)/gdoc -man \
			-module $(PACKAGE) \
			-sourceversion $(VERSION) \
			-bugsto $(PACKAGE_BUGREPORT) \
			-pkg-name "$(PACKAGE_NAME)" \
			-includefuncprefix \
			-seeinfo $(PACKAGE) -verbatimcopying \
			-copyright "2002-2021 Simon Josefsson" \
			-function $$i \
			$(GDOC_SRC) > man/$$i.3 && \
		$(srcdir)/gdoc -texinfo -function $$i \
			$(GDOC_SRC) > texi/$$i.texi && \
		echo -n "."; \
	done; \
	echo ""; \
	echo -n "Creating file documentation" && \
	for i in $(GDOC_SRC); do \
		BASE=`basename $$i`; \
		$(srcdir)/gdoc -texinfo $$i > texi/$$BASE.texi && \
		echo -n "."; \
	done; \
	echo ""

.PHONY: update-makefile doit
