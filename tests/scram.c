/* scram.c --- Test the SCRAM mechanism.
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "utils.h"

#define PASSWORD "Open, Sesame"

#define N_AUTHID 4
static const char *AUTHID[N_AUTHID] = {
  "Ali Baba", "BAB,ABA", ",=,=", "="
    /* "Ali " "\xC2\xAD" "Bab" "\xC2\xAA" */
    /* "Al\xC2\xAA""dd\xC2\xAD""in\xC2\xAE" */
};

#define N_AUTHZID 4
static const char *AUTHZID[N_AUTHZID] = {
  "jas", "BAB,ABA", ",=,=", "="
};

int i;

static int
callback (Gsasl * ctx, Gsasl_session * sctx, Gsasl_property prop)
{
  int rc = GSASL_NO_CALLBACK;

  /* Get user info from user. */

  switch (prop)
    {
    case GSASL_PASSWORD:
      rc = gsasl_property_set (sctx, prop, PASSWORD);
      break;

    case GSASL_AUTHID:
      rc = gsasl_property_set (sctx, prop, AUTHID[i % N_AUTHID]);
      break;

    case GSASL_AUTHZID:
      if (i & 0x01)
	rc = gsasl_property_set (sctx, prop, AUTHZID[i % N_AUTHZID]);
      break;

    case GSASL_SCRAM_ITER:
      if (strcmp (gsasl_property_fast (sctx, GSASL_AUTHID),
		  AUTHID[i % N_AUTHID]) != 0)
	fail ("Username mismatch: %s",
	      gsasl_property_fast (sctx, GSASL_AUTHID));
      if (i & 0x02)
	rc = gsasl_property_set (sctx, prop, "1234");
      break;

    case GSASL_SCRAM_SALT:
      if (i & 0x04)
	rc = gsasl_property_set (sctx, prop, "c2FsdA==");
      break;

#define SP1 "06bfd2d70a0fa425c20473722a93700df39f3cbd"
#define SP2 "f1e6c0e5a207367176ac42c7799b67ae3e097d7e"

    case GSASL_SCRAM_SALTED_PASSWORD:
      if (i & 0x04 && i & 0x08)	/* Only works with fixed salt. */
	{
	  const char *str[] = { SP1, SP2 };
	  /* >>1 to mask out authzid. */
	  size_t pos = (i & ~0x04 & ~0x08) >> 1;
	  rc = gsasl_property_set (sctx, prop, str[pos]);
	}
      break;

    case GSASL_SCRAM_SERVERKEY:
    case GSASL_SCRAM_STOREDKEY:
      break;

    case GSASL_CB_TLS_UNIQUE:
    case GSASL_CB_TLS_EXPORTER:
      break;

    default:
      fail ("Unknown callback property %u\n", prop);
      break;
    }

  return rc;
}

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

  if (!gsasl_client_support_p (ctx, "SCRAM-SHA-1")
      || !gsasl_server_support_p (ctx, "SCRAM-SHA-1"))
    {
      gsasl_done (ctx);
      fail ("No support for SCRAM-SHA-1.\n");
      exit (77);
    }

  gsasl_callback_set (ctx, callback);

  for (i = 0; i <= 21; i++)
    {
      bool server_first = (i % 2) == 0;

      if (debug)
	printf ("Iteration %d ...\n", i);

      res = gsasl_server_start (ctx, "SCRAM-SHA-1", &server);
      if (res != GSASL_OK)
	{
	  fail ("gsasl_server_start() failed (%d):\n%s\n",
		res, gsasl_strerror (res));
	  return;
	}
      res = gsasl_client_start (ctx, "SCRAM-SHA-1", &client);
      if (res != GSASL_OK)
	{
	  fail ("gsasl_client_start() failed (%d):\n%s\n",
		res, gsasl_strerror (res));
	  return;
	}

      if (server_first)
	{
	  res = gsasl_step (server, NULL, 0, &s1, &s1len);
	  if (res != GSASL_NEEDS_MORE)
	    {
	      fail ("gsasl_step[%d](0) failed (%d):\n%s\n", i, res,
		    gsasl_strerror (res));
	      return;
	    }

	  if (s1len != 0)
	    fail ("dummy initial server step produced output?!\n");

	  if (debug)
	    printf ("S: %.*s [%c]\n", (int) s1len,
		    s1, res == GSASL_OK ? 'O' : 'N');
	}
      else
	{
	  s1 = NULL;
	  s1len = 0;
	}

      /* Client first... */

      res = gsasl_step (client, s1, s1len, &s1, &s1len);
      if (res != GSASL_NEEDS_MORE)
	{
	  fail ("gsasl_step[%d](1) failed (%d):\n%s\n", i, res,
		gsasl_strerror (res));
	  return;
	}

      if (i == 16 || i == 17)
	s1[0] = 'y';

      if (i == 18)
	{
	  char *s;
	  int l;

	  l = asprintf (&s, "%s,a=b", s1);
	  if (l < 0)
	    {
	      fail ("malloc");
	      return;
	    }
	  gsasl_free (s1);
	  s1 = s;
	  s1len = strlen (s);
	}

      if (i == 20)
	{
	  char *s;
	  int l;

	  l = asprintf (&s, "%s,a=b,b=c,c=d", s1);
	  if (l < 0)
	    {
	      fail ("malloc");
	      return;
	    }
	  gsasl_free (s1);
	  s1 = s;
	  s1len = strlen (s);
	}

      if (debug)
	printf ("C: %.*s [%c]\n", (int) s1len,
		s1, res == GSASL_OK ? 'O' : 'N');

      /* Server first... */

      res = gsasl_step (server, s1, s1len, &s2, &s2len);
      gsasl_free (s1);
      if (res != GSASL_NEEDS_MORE)
	{
	  fail ("gsasl_step[%d](2) failed (%d):\n%s\n", i, res,
		gsasl_strerror (res));
	  return;
	}

      if (debug)
	printf ("S: %.*s [%c]\n", (int) s2len,
		s2, res == GSASL_OK ? 'O' : 'N');

      /* Client final... */

      res = gsasl_step (client, s2, s2len, &s1, &s1len);
      gsasl_free (s2);
      if (res != GSASL_NEEDS_MORE)
	{
	  fail ("gsasl_step[%d](3) failed (%d):\n%s\n", i, res,
		gsasl_strerror (res));
	  return;
	}

      if (i == 17)
	memcpy (s1 + 2, "eS", 2);

      if (i == 19 && s1len > 31)
	{
	  char *s;
	  int l;

	  l = asprintf (&s, "%.*s,a=b,%s", (int) (s1len - 31),
			s1, s1 + s1len - 31 + 1);
	  if (l < 0)
	    {
	      fail ("malloc");
	      return;
	    }
	  gsasl_free (s1);
	  s1 = s;
	  s1len = strlen (s);
	}

      if (i == 21 && s1len > 31)
	{
	  char *s;
	  int l;

	  l = asprintf (&s, "%.*s,a=b,b=c,c=d,%s", (int) (s1len - 31),
			s1, s1 + s1len - 31 + 1);
	  if (l < 0)
	    {
	      fail ("malloc");
	      return;
	    }
	  gsasl_free (s1);
	  s1 = s;
	  s1len = strlen (s);
	}

      if (debug)
	printf ("C: %.*s [%c]\n", (int) s1len,
		s1, res == GSASL_OK ? 'O' : 'N');

      /* Server final... */

      res = gsasl_step (server, s1, s1len, &s2, &s2len);
      gsasl_free (s1);
      if (i >= 16 && i <= 21)
	{
	  if (res == GSASL_AUTHENTICATION_ERROR)
	    {
	      if (debug)
		success ("Authentication failed expectedly\n");
	      goto done;
	    }
	  else
	    res = GSASL_AUTHENTICATION_ERROR;
	}
      if (res != GSASL_OK)
	{
	  fail ("gsasl_step[%d](4) failed (%d):\n%s\n", i, res,
		gsasl_strerror (res));
	  return;
	}

      if (debug)
	printf ("S: %.*s [%c]\n", (int) s2len,
		s2, res == GSASL_OK ? 'O' : 'N');

      /* Let client parse server final... */

      res = gsasl_step (client, s2, s2len, &s1, &s1len);
      gsasl_free (s2);
      if (res != GSASL_OK)
	{
	  fail ("gsasl_step[%d](5) failed (%d):\n%s\n", i, res,
		gsasl_strerror (res));
	  return;
	}

      if (s1len != 0)
	fail ("dummy final client step produced output?!\n");

      {
	const char *p = gsasl_property_fast (server, GSASL_AUTHID);
	if (p && strcmp (p, AUTHID[i % N_AUTHID]) != 0)
	  fail ("Bad authid? %s != %s\n", p, AUTHID[i % N_AUTHID]);
	if (i & 0x01 && !p)
	  fail ("Expected authid? %d/%s\n", i, AUTHID[i % N_AUTHID]);
      }

      {
	const char *p = gsasl_property_fast (server, GSASL_AUTHZID);
	if (p && strcmp (p, AUTHZID[i % N_AUTHZID]) != 0)
	  fail ("Bad authzid? %s != %s\n", p, AUTHZID[i % N_AUTHZID]);
	if (i & 0x01 && !p)
	  fail ("Expected authzid? %d/%s\n", i, AUTHZID[i % N_AUTHZID]);
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
	    printf ("GSASL_SCRAM_ITER (client): %s\n", cs);
	    printf ("GSASL_SCRAM_ITER (server): %s\n", ss);
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
	const char *ssp =
	  gsasl_property_fast (server, GSASL_SCRAM_SALTED_PASSWORD);

	if (debug)
	  {
	    printf ("GSASL_SCRAM_SERVERKEY: %s\n", sek);
	    printf ("GSASL_SCRAM_STOREDKEY: %s\n", stk);
	  }

	if (!sek)
	  fail ("missing ServerKey\n");
	if (!stk)
	  fail ("missing StoredKey\n");
	if ((strcmp (ssp, SP2) == 0)
	    && (strcmp (sek, "m05YwQmkiYtfagsfqHyTaFbylTI=") != 0))
	  fail ("incorrect ServerKey\n");
	if ((strcmp (ssp, SP2) == 0)
	    && (strcmp (stk, "bgzByAo2e3aFvfezFeqJy5OJSUs=") != 0))
	  fail ("incorrect StoredKey\n");
      }

    done:
      if (debug)
	printf ("\n");

      gsasl_finish (client);
      gsasl_finish (server);
    }

  gsasl_done (ctx);
}
