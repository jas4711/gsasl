# Copyright (C) 2008-2022 Simon Josefsson
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

CYCLO_SRCS = `echo ${top_srcdir}/lib/*/*.[ch] | grep -v -e /lib/gl/ -e test-parser.c`

cyclo-$(PACKAGE).html: ${top_srcdir}/lib/*/*.[ch]
	$(AM_V_GEN)$(PMCCABE) $(CYCLO_SRCS) \
		| LC_ALL=C sort -nr \
		| LC_ALL=C $(AWK) -f ${top_srcdir}/build-aux/pmccabe2html \
			-v lang=html -v name="$(PACKAGE_NAME)" \
			-v vcurl="https://git.savannah.gnu.org/gitweb/?p=$(PACKAGE).git;a=blob;f=%FILENAME%;hb=HEAD" \
			-v url="https://www.gnu.org/software/$(PACKAGE)/" \
			-v css=${top_srcdir}/build-aux/pmccabe.css \
			-v cut_dir=${top_srcdir}/ \
			> $@-tmp
	mv $@-tmp $@
