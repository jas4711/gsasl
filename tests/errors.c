/* errors.c --- Test the gsasl_strerror and gsasl_strerror_name functions.
 * Copyright (C) 2002-2022 Simon Josefsson
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

#include "utils.h"

#define ERRSTR(err) #err

void
doit (void)
{
  const char *this = NULL, *last = NULL;
  const char *name;
  int i = 0;

  do
    {
      last = this;

      this = gsasl_strerror (i);
      name = gsasl_strerror_name (i);

      printf ("%s (%d)\n\t%s\n", name ? name : "NULL", i, this);

      if (this == NULL)
	fail ("Null error string?!\n");

      i++;
    }
  while (i < GSASL_NO_CB_TLS_EXPORTER || (this != last && this != NULL));

  {
    const char *p = gsasl_strerror_name (GSASL_NO_CB_TLS_EXPORTER + 1);
    if (p)
      fail ("added new error code? %s\n", p);
  }

  {
    const char *p = gsasl_strerror (GSASL_NO_CB_TLS_EXPORTER + 1);
    const char *q = gsasl_strerror (4711);
    if (strcmp (p, q) != 0)
      fail ("added new error code? p %s q %s\n", p, q);
  }

  if (strcmp (gsasl_strerror_name (GSASL_OK), ERRSTR (GSASL_OK)) != 0)
    fail ("names differ GSASL_OK != %s\n", gsasl_strerror_name (GSASL_OK));

  if (strcmp (gsasl_strerror_name (GSASL_NO_HOSTNAME),
	      ERRSTR (GSASL_NO_HOSTNAME)) != 0)
    fail ("names differ GSASL_NO_HOSTNAME != %s\n",
	  gsasl_strerror_name (GSASL_NO_HOSTNAME));
}
