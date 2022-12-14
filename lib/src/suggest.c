/* suggest.c --- Suggest client mechanism to use, from a set of mechanisms.
 * Copyright (C) 2002-2022 Simon Josefsson
 *
 * This file is part of GNU SASL Library.
 *
 * GNU SASL Library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * GNU SASL Library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License License along with GNU SASL Library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */

#include "internal.h"

/*
 * _GSASL_VALID_MECHANISM_CHARACTERS:
 *
 * A zero-terminated character array, or string, with all ASCII
 * characters that may be used within a SASL mechanism name.
 **/
const char *_GSASL_VALID_MECHANISM_CHARACTERS =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";

/**
 * gsasl_mechanism_name_p:
 * @mech: input variable with mechanism name string.
 *
 * Check if the mechanism name string @mech follows syntactical rules.
 * It does not check that the name is registered with IANA.  It does not
 * check that the mechanism name is actually implemented and supported.
 *
 * SASL mechanisms are named by strings, from 1 to 20 characters in
 * length, consisting of upper-case letters, digits, hyphens, and/or
 * underscores.
 *
 * Returns: non-zero when mechanism name string @mech conforms to
 *   rules, zero when it does not meet the requirements.
 *
 * Since: 2.0.0
 **/
int
gsasl_mechanism_name_p (const char *mech)
{
  size_t l;

  if (mech == NULL)
    return 0;

  l = strlen (mech);

  if (l < GSASL_MIN_MECHANISM_SIZE)
    return 0;

  if (l > GSASL_MAX_MECHANISM_SIZE)
    return 0;

  while (*mech)
    if (strchr (_GSASL_VALID_MECHANISM_CHARACTERS, *mech++) == NULL)
      return 0;

  return 1;
}

/**
 * gsasl_client_suggest_mechanism:
 * @ctx: libgsasl handle.
 * @mechlist: input character array with SASL mechanism names,
 *   separated by invalid characters (e.g. SPC).
 *
 * Given a list of mechanisms, suggest which to use.
 *
 * Return value: Returns name of "best" SASL mechanism supported by
 *   the libgsasl client which is present in the input string, or
 *   NULL if no supported mechanism is found.
 **/
const char *
gsasl_client_suggest_mechanism (Gsasl * ctx, const char *mechlist)
{
  size_t mechlist_len, target_mech, i;

  mechlist_len = mechlist ? strlen (mechlist) : 0;
  target_mech = ctx->n_client_mechs;	/* ~ no target */

  for (i = 0; i < mechlist_len;)
    {
      size_t len;

      len = strspn (mechlist + i, _GSASL_VALID_MECHANISM_CHARACTERS);
      if (!len)
	++i;
      else
	{
	  size_t j;

	  /* Assumption: the mechs array is sorted by preference
	   * from low security to high security. */
	  for (j = (target_mech < ctx->n_client_mechs ? target_mech + 1 : 0);
	       j < ctx->n_client_mechs; ++j)
	    {
	      if ((strlen (ctx->client_mechs[j].name) == len)
		  && (strncmp (ctx->client_mechs[j].name, mechlist + i,
			       len) == 0))
		{
		  Gsasl_session *sctx;

		  if (gsasl_client_start (ctx, ctx->client_mechs[j].name,
					  &sctx) == GSASL_OK)
		    {
		      gsasl_finish (sctx);
		      target_mech = j;
		    }

		  break;
		}
	    }
	  i += len + 1;
	}
    }

  return target_mech < ctx->n_client_mechs ?
    ctx->client_mechs[target_mech].name : NULL;
}
