/* version.c --- Version handling self tests.
 * Copyright (C) 2003-2022 Simon Josefsson
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

#include "config.h"

#include <stdio.h>		/* printf */
#include <stdlib.h>		/* EXIT_SUCCESS */
#include <string.h>		/* strcmp */

/* Get GSASL prototypes. */
#include <gsasl.h>

int
main (int argc, char *argv[])
{
  int exit_code = EXIT_SUCCESS;
  char *out = NULL;
  int j;
  unsigned gvn = GSASL_VERSION_NUMBER;
  unsigned gvmmp = (GSASL_VERSION_MAJOR << 16)
    + (GSASL_VERSION_MINOR << 8) + GSASL_VERSION_PATCH;

  printf ("GSASL_VERSION: %s\n", GSASL_VERSION);
  printf ("GSASL_VERSION_MAJOR: %d\n", GSASL_VERSION_MAJOR);
  printf ("GSASL_VERSION_MINOR: %d\n", GSASL_VERSION_MINOR);
  printf ("GSASL_VERSION_PATCH: %d\n", GSASL_VERSION_PATCH);
  printf ("GSASL_VERSION_NUMBER: %x\n", gvn);
  printf ("(GSASL_VERSION_MAJOR << 16) + (GSASL_VERSION_MINOR << 8)"
	  " + GSASL_VERSION_PATCH: %x\n", gvmmp);

  j = asprintf (&out, "%d.%d.%d", GSASL_VERSION_MAJOR,
		GSASL_VERSION_MINOR, GSASL_VERSION_PATCH);
  if (j < 0)
    {
      printf ("asprintf failure: %d", j);
      exit_code = EXIT_FAILURE;
      out = NULL;
    }

  if (out)
    printf
      ("GSASL_VERSION_MAJOR.GSASL_VERSION_MINOR.GSASL_VERSION_PATCH: %s\n",
       out);

  printf ("gsasl_check_version (NULL): %s\n", gsasl_check_version (NULL));

  if (!gsasl_check_version (GSASL_VERSION))
    {
      printf ("FAIL: gsasl_check_version (GSASL_VERSION)\n");
      exit_code = EXIT_FAILURE;
    }

  if (!gsasl_check_version ("1.0.1"))
    {
      printf ("FAIL: gsasl_check_version (1.0.1)\n");
      exit_code = EXIT_FAILURE;
    }

  if (strcmp (GSASL_VERSION, gsasl_check_version (NULL)) != 0)
    {
      printf ("FAIL: strcmp (GSASL_VERSION, gsasl_check_version (NULL))\n");
      exit_code = EXIT_FAILURE;
    }

  if (GSASL_VERSION_NUMBER != gvn)
    {
      printf ("FAIL: GSASL_VERSION_NUMBER != gvn\n");
      exit_code = EXIT_FAILURE;
    }

  if (out)
    {
      if (!gsasl_check_version (out))
	{
	  printf ("FAIL: gsasl_check_version(%s)\n", out);
	  exit_code = EXIT_FAILURE;
	}

      /* GSASL_VERSION may look like "1.0.4.10-b872" but the derived string
         should be "1.0.4" anyway.  */
      if (strncmp (GSASL_VERSION, out, strlen (out)) != 0)
	{
	  printf ("FAIL: strncmp (GSASL_VERSION, %s, strlen (%s))\n", out,
		  out);
	  exit_code = EXIT_FAILURE;
	}

      free (out);
    }

  if (gsasl_check_version ("4711.42.23"))
    {
      printf ("FAIL: gsasl_check_version(4711.42.23)\n");
      exit_code = EXIT_FAILURE;
    }

  if (gsasl_check_version ("UNKNOWN"))
    {
      printf ("FAIL: gsasl_check_version (UNKNOWN)\n");
      exit_code = EXIT_FAILURE;
    }

  return exit_code;
}
