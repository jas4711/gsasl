/* suggest.c --- Test the SASL mechanism suggestion function.
 * Copyright (C) 2002-2021 Simon Josefsson
 *
 * This file is part of GNU SASL.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <gsasl.h>

#include "utils.h"

void
doit (void)
{
  Gsasl *ctx = NULL;
  const char *str;
  const char *p;
  int res;

  res = gsasl_init (&ctx);
  if (res != GSASL_OK)
    {
      fail ("gsasl_init() failed (%d):\n%s\n", res, gsasl_strerror (res));
      return;
    }

  if (gsasl_mechanism_name_p (NULL))
    fail ("FAIL: NULL is a valid mechanism name?!\n");

  if (gsasl_mechanism_name_p (""))
    fail ("FAIL: empty string is a valid mechanism name?!\n");

  if (!gsasl_mechanism_name_p ("1"))
    fail ("FAIL: 1 is not a valid mechanism name?!\n");

  if (!gsasl_mechanism_name_p ("12345678901234567890"))
    fail ("FAIL: 20chars is not a valid mechanism name?!\n");

  if (gsasl_mechanism_name_p ("123456789012345678901"))
    fail ("FAIL: 21chars is a valid mechanism name?!\n");

  if (gsasl_mechanism_name_p ("lower"))
    fail ("FAIL: lowercase string is a valid mechanism name?!\n");

  if (!gsasl_mechanism_name_p ("A0-_Z9"))
    fail ("FAIL: weird string is not a valid mechanism name?!\n");

  if (!gsasl_mechanism_name_p ("PLAIN"))
    fail ("FAIL: PLAIN is not a valid mechanism name?!\n");

  str = "FOO BAR FOO";
  p = gsasl_client_suggest_mechanism (ctx, str);
  if (debug)
    printf ("gsasl_client_suggest_mechanism(%s) = %s\n", str,
	    p ? p : "(null)");
  if (p)
    fail ("FAIL: not null?!\n");

  if (gsasl_client_support_p (ctx, "EXTERNAL"))
    {
      str = "FOO BAR EXTERNAL BAR FOO";
      p = gsasl_client_suggest_mechanism (ctx, str);
      if (debug)
	printf ("gsasl_client_suggest_mechanism(%s) = %s\n", str, p);
      if (!p || strcmp (p, "EXTERNAL") != 0)
	fail ("FAIL: not external?!\n");
    }

  if (gsasl_client_support_p (ctx, "CRAM-MD5"))
    {
      str = "FOO BAR CRAM-MD5 BAR FOO";
      p = gsasl_client_suggest_mechanism (ctx, str);
      if (debug)
	printf ("gsasl_client_suggest_mechanism(%s) = %s\n", str, p);
      if (!p || strcmp (p, "CRAM-MD5") != 0)
	fail ("FAIL: not cram-md5?!\n");
    }

  if (gsasl_client_support_p (ctx, "PLAIN")
      && gsasl_client_support_p (ctx, "CRAM-MD5"))
    {
      str = "FOO PLAIN CRAM-MD5 BAR FOO";
      p = gsasl_client_suggest_mechanism (ctx, str);
      if (debug)
	printf ("gsasl_client_suggest_mechanism(%s) = %s\n", str, p);
      if (!p || strcmp (p, "CRAM-MD5") != 0)
	fail ("FAIL: not cram-md5?!\n");
    }

  if (gsasl_client_support_p (ctx, "PLAIN"))
    {
      str = "FOO PLAIN BAR FOO";
      p = gsasl_client_suggest_mechanism (ctx, str);
      if (debug)
	printf ("gsasl_client_suggest_mechanism(%s) = %s\n", str, p);
      if (!p || strcmp (p, "PLAIN") != 0)
	fail ("FAIL: not plain?!\n");
    }

  if (gsasl_client_support_p (ctx, "PLAIN")
      && gsasl_client_support_p (ctx, "CRAM-MD5")
      && gsasl_client_support_p (ctx, "DIGEST-MD5"))
    {
      str = "FOO PLAIN CRAM-MD5 DIGEST-MD5 FOO";
      p = gsasl_client_suggest_mechanism (ctx, str);
      if (debug)
	printf ("gsasl_client_suggest_mechanism(%s) = %s\n", str, p);
      if (!p || strcmp (p, "CRAM-MD5") != 0)
	fail ("FAIL: not cram-md5?!\n");
    }

  gsasl_done (ctx);
}
