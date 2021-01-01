/* symbols.c --- Test if all exported symbols are available.
 * Copyright (C) 2010-2021 Simon Josefsson
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

#include <gsasl.h>

#include "utils.h"

static void
assert_symbol_exists (const void *p)
{
  if (!p)
    fail ("null symbol?!\n");
}

void
doit (void)
{
  /* LIBGSASL_1.1 */
  assert_symbol_exists ((const void *) GSASL_VALID_MECHANISM_CHARACTERS);
  assert_symbol_exists ((const void *) gsasl_base64_from);
  assert_symbol_exists ((const void *) gsasl_base64_to);
  assert_symbol_exists ((const void *) gsasl_callback);
  assert_symbol_exists ((const void *) gsasl_callback_hook_get);
  assert_symbol_exists ((const void *) gsasl_callback_hook_set);
  assert_symbol_exists ((const void *) gsasl_callback_set);
  assert_symbol_exists ((const void *) gsasl_check_version);
  assert_symbol_exists ((const void *) gsasl_client_mechlist);
  assert_symbol_exists ((const void *) gsasl_client_start);
  assert_symbol_exists ((const void *) gsasl_client_suggest_mechanism);
  assert_symbol_exists ((const void *) gsasl_client_support_p);
  assert_symbol_exists ((const void *) gsasl_decode);
  assert_symbol_exists ((const void *) gsasl_done);
  assert_symbol_exists ((const void *) gsasl_encode);
  assert_symbol_exists ((const void *) gsasl_finish);
  assert_symbol_exists ((const void *) gsasl_free);
  assert_symbol_exists ((const void *) gsasl_init);
  assert_symbol_exists ((const void *) gsasl_mechanism_name);
  assert_symbol_exists ((const void *) gsasl_nonce);
  assert_symbol_exists ((const void *) gsasl_property_fast);
  assert_symbol_exists ((const void *) gsasl_property_get);
  assert_symbol_exists ((const void *) gsasl_property_set);
  assert_symbol_exists ((const void *) gsasl_property_set_raw);
  assert_symbol_exists ((const void *) gsasl_random);
  assert_symbol_exists ((const void *) gsasl_register);
  assert_symbol_exists ((const void *) gsasl_saslprep);
  assert_symbol_exists ((const void *) gsasl_server_mechlist);
  assert_symbol_exists ((const void *) gsasl_server_start);
  assert_symbol_exists ((const void *) gsasl_server_support_p);
  assert_symbol_exists ((const void *) gsasl_session_hook_get);
  assert_symbol_exists ((const void *) gsasl_session_hook_set);
  assert_symbol_exists ((const void *) gsasl_simple_getpass);
  assert_symbol_exists ((const void *) gsasl_step64);
  assert_symbol_exists ((const void *) gsasl_step);
  assert_symbol_exists ((const void *) gsasl_strerror);
  assert_symbol_exists ((const void *) gsasl_strerror_name);

  /* LIBGSASL_1.10 */
  assert_symbol_exists ((const void *) gsasl_hex_from);
  assert_symbol_exists ((const void *) gsasl_hex_to);
  assert_symbol_exists ((const void *) gsasl_hash_length);
  assert_symbol_exists ((const void *) gsasl_scram_secrets_from_password);
  assert_symbol_exists ((const void *)
			gsasl_scram_secrets_from_salted_password);

  success ("all symbols exists\n");
}
