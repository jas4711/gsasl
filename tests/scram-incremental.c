/* scram-incremental.c --- Test SCRAM-SHA-1-PLUS incremental without callback.
 * Copyright (C) 2009-2022 Simon Josefsson
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

/* Based on scram-simple.c.  Test that SCRAM returns proper error
   codes for missing properties, and handle resuming operation
   incrementally after each failure.  This triggered a number of
   memory leaks in earlier versions of the library. */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "utils.h"

#define USERNAME "user"
#define PASSWORD "pencil"

#define CBDATA "Zm5vcmQ="

void
doit (void)
{
  Gsasl *ctx = NULL;
  Gsasl_session *server = NULL, *client = NULL;
  char *s1, *s2;
  size_t s1len, s2len;
  int res;

  res = gsasl_init (&ctx);
  if (res != GSASL_OK)
    {
      fail ("gsasl_init() failed (%d):\n%s\n", res, gsasl_strerror (res));
      return;
    }

  if (!gsasl_client_support_p (ctx, "SCRAM-SHA-1-PLUS")
      || !gsasl_server_support_p (ctx, "SCRAM-SHA-1-PLUS"))
    {
      gsasl_done (ctx);
      fail ("No support for SCRAM-SHA-1-PLUS.\n");
      exit (77);
    }

  res = gsasl_server_start (ctx, "SCRAM-SHA-1-PLUS", &server);
  if (res != GSASL_OK)
    {
      fail ("gsasl_server_start() failed (%d):\n%s\n",
	    res, gsasl_strerror (res));
      return;
    }
  res = gsasl_client_start (ctx, "SCRAM-SHA-1-PLUS", &client);
  if (res != GSASL_OK)
    {
      fail ("gsasl_client_start() failed (%d):\n%s\n",
	    res, gsasl_strerror (res));
      return;
    }

  s1 = NULL;
  s1len = 0;

  /* Client first... */

  res = gsasl_step (client, s1, s1len, &s1, &s1len);
  if (res != GSASL_NO_AUTHID)
    {
      fail ("gsasl_step-cfauthid failed (%d):\n%s\n", res,
	    gsasl_strerror (res));
      return;
    }

  res = gsasl_property_set (client, GSASL_AUTHID, USERNAME);
  if (res != GSASL_OK)
    {
      fail ("gsasl_property_set() failed (%d):\n%s\n",
	    res, gsasl_strerror (res));
      return;
    }

  res = gsasl_step (client, s1, s1len, &s1, &s1len);
  if (res != GSASL_NO_CB_TLS_EXPORTER)
    {
      fail ("gsasl_step-cfcb failed (%d):\n%s\n", res, gsasl_strerror (res));
      return;
    }

  res = gsasl_property_set (client, GSASL_CB_TLS_UNIQUE, CBDATA);
  if (res != GSASL_OK)
    {
      fail ("gsasl_property_set() failed (%d):\n%s\n",
	    res, gsasl_strerror (res));
      return;
    }

  res = gsasl_step (client, s1, s1len, &s1, &s1len);
  if (res != GSASL_NEEDS_MORE)
    {
      fail ("gsasl_step-cf failed (%d):\n%s\n", res, gsasl_strerror (res));
      return;
    }

  if (debug)
    printf ("C: %.*s [%c]\n", (int) s1len, s1, res == GSASL_OK ? 'O' : 'N');

  /* Server first... */

  res = gsasl_step (server, s1, s1len, &s2, &s2len);
  if (res != GSASL_NO_CB_TLS_UNIQUE)
    {
      fail ("gsasl_step-sfcb failed (%d):\n%s\n", res, gsasl_strerror (res));
      return;
    }

  res = gsasl_property_set (server, GSASL_CB_TLS_UNIQUE, "Zm5vcmQ=");
  if (res != GSASL_OK)
    {
      fail ("gsasl_property_set() failed (%d):\n%s\n",
	    res, gsasl_strerror (res));
      return;
    }

  res = gsasl_step (server, s1, s1len, &s2, &s2len);
  gsasl_free (s1);
  if (res != GSASL_NEEDS_MORE)
    {
      fail ("gsasl_step-sf failed (%d):\n%s\n", res, gsasl_strerror (res));
      return;
    }

  if (debug)
    printf ("S: %.*s [%c]\n", (int) s2len, s2, res == GSASL_OK ? 'O' : 'N');

  /* Client last... */

  res = gsasl_step (client, s2, s2len, &s1, &s1len);
  if (res != GSASL_NO_PASSWORD)
    {
      fail ("gsasl_step-clpasswd failed (%d):\n%s\n",
	    res, gsasl_strerror (res));
      return;
    }

  res = gsasl_property_set (client, GSASL_PASSWORD, PASSWORD);
  if (res != GSASL_OK)
    {
      fail ("gsasl_property_set() failed (%d):\n%s\n",
	    res, gsasl_strerror (res));
      return;
    }

  res = gsasl_step (client, s2, s2len, &s1, &s1len);
  gsasl_free (s2);
  if (res != GSASL_NEEDS_MORE)
    {
      fail ("gsasl_step-cl failed (%d):\n%s\n", res, gsasl_strerror (res));
      return;
    }

  if (debug)
    printf ("C: %.*s [%c]\n", (int) s1len, s1, res == GSASL_OK ? 'O' : 'N');

  /* Server last... */

  res = gsasl_step (server, s1, s1len, &s2, &s2len);
  if (res != GSASL_NO_PASSWORD)
    {
      fail ("gsasl_step-slpasswd failed (%d):\n%s\n",
	    res, gsasl_strerror (res));
      return;
    }

  res = gsasl_property_set (server, GSASL_PASSWORD, PASSWORD);
  if (res != GSASL_OK)
    {
      fail ("gsasl_property_set() failed (%d):\n%s\n",
	    res, gsasl_strerror (res));
      return;
    }

  res = gsasl_step (server, s1, s1len, &s2, &s2len);
  gsasl_free (s1);
  if (res != GSASL_OK)
    {
      fail ("gsasl_step-sl failed (%d):\n%s\n", res, gsasl_strerror (res));
      return;
    }

  if (debug)
    printf ("S: %.*s [%c]\n\n", (int) s2len, s2, res == GSASL_OK ? 'O' : 'N');

  /* Let client parse server final... */

  res = gsasl_step (client, s2, s2len, &s1, &s1len);
  gsasl_free (s2);
  if (res != GSASL_OK)
    {
      fail ("gsasl_step-c failed (%d):\n%s\n", res, gsasl_strerror (res));
      return;
    }

  if (s1len != 0)
    fail ("dummy final client step produced output?!\n");

  {
    const char *p = gsasl_property_fast (server, GSASL_AUTHID);
    if (p && strcmp (p, USERNAME) != 0)
      fail ("Bad authid? %s != %s\n", p, USERNAME);
    if (debug)
      printf ("GSASL_AUTHID: %s\n", p);
  }

  {
    const char *ci = gsasl_property_fast (client, GSASL_SCRAM_ITER);
    const char *si = gsasl_property_fast (server, GSASL_SCRAM_ITER);
    if (debug)
      {
	printf ("GSASL_SCRAM_ITER (client): %s\n", ci);
	printf ("GSASL_SCRAM_ITER (server): %s\n", si);
      }
    if (!ci || !si || strcmp (ci, si) != 0)
      fail ("scram iter mismatch\n");
  }

  {
    const char *cs = gsasl_property_fast (client, GSASL_SCRAM_SALT);
    const char *ss = gsasl_property_fast (server, GSASL_SCRAM_SALT);
    if (debug)
      {
	printf ("GSASL_SCRAM_SALT (client): %s\n", cs);
	printf ("GSASL_SCRAM_SALT (server): %s\n", ss);
      }
    if (!cs || !ss || strcmp (cs, ss) != 0)
      fail ("scram salt mismatch\n");
  }

  {
    const char *csp =
      gsasl_property_fast (client, GSASL_SCRAM_SALTED_PASSWORD);
    const char *ssp =
      gsasl_property_fast (server, GSASL_SCRAM_SALTED_PASSWORD);

    if (debug)
      {
	printf ("GSASL_SCRAM_SALTED_PASSWORD (client): %s\n", csp);
	printf ("GSASL_SCRAM_SALTED_PASSWORD (server): %s\n", ssp);
      }
    if (!csp || !ssp || strcmp (csp, ssp) != 0)
      fail ("scram salted password mismatch\n");
  }

  {
    const char *sek = gsasl_property_fast (server, GSASL_SCRAM_SERVERKEY);
    const char *stk = gsasl_property_fast (server, GSASL_SCRAM_STOREDKEY);

    if (debug)
      {
	printf ("GSASL_SCRAM_SERVERKEY: %s\n", sek);
	printf ("GSASL_SCRAM_STOREDKEY: %s\n", stk);
      }

    if (!sek)
      fail ("missing ServerKey\n");
    if (!stk)
      fail ("missing StoredKey\n");
  }

  if (debug)
    printf ("\n");

  gsasl_finish (client);
  gsasl_finish (server);

  gsasl_done (ctx);
}
