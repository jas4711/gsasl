/* crypto.c --- Test the crypto related SASL functions.
 * Copyright (C) 2009-2021 Simon Josefsson
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
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gsasl.h>

#include "utils.h"

void
doit (void)
{
#define SIZE 10
  char tmp[SIZE];
  char savetmp[SIZE];
  size_t tmplen;
  int rc;
  Gsasl *ctx;

  rc = gsasl_init (&ctx);
  if (rc != GSASL_OK)
    fail ("gsasl_init %d: %s\n", rc, gsasl_strerror (rc));

  memset (tmp, 42, SIZE);
  memcpy (savetmp, tmp, SIZE);
  tmplen = sizeof (tmp);
  rc = gsasl_nonce (tmp, tmplen);
  if (rc != GSASL_OK)
    fail ("gsasl_nonce %d: %s\n", rc, gsasl_strerror (rc));
  if (memcmp (savetmp, tmp, SIZE) == 0)
    fail ("gsasl_nonce memcmp fail\n");
  success ("gsasl_nonce\n");

#if 0
  /* This often times out on build machines. */
  memcpy (savetmp, tmp, SIZE);
  tmplen = sizeof (tmp);
  rc = gsasl_random (tmp, tmplen);
  if (rc != GSASL_OK)
    fail ("gsasl_random %d: %s\n", rc, gsasl_strerror (rc));
  if (memcmp (savetmp, tmp, SIZE) == 0)
    fail ("gsasl_random memcmp fail\n");
  success ("gsasl_random\n");
#endif

  gsasl_done (ctx);
}
