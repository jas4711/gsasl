/* internal.h --- Internal header with hidden library handle structures.
 * Copyright (C) 2002-2021 Simon Josefsson
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

#ifndef INTERNAL_H
# define INTERNAL_H

# ifdef HAVE_CONFIG_H
#  include "config.h"
# endif

/* Get specifications. */
# include "gsasl.h"

/* Get malloc, free, ... */
# include <stdlib.h>

/* Get strlen, strcpy, ... */
# include <string.h>

/* Main library handle. */
struct Gsasl
{
  size_t n_client_mechs;
  Gsasl_mechanism *client_mechs;
  size_t n_server_mechs;
  Gsasl_mechanism *server_mechs;
  /* Callback. */
  Gsasl_callback_function cb;
  void *application_hook;
};

/* Per-session library handle. */
struct Gsasl_session
{
  Gsasl *ctx;
  int clientp;
  Gsasl_mechanism *mech;
  void *mech_data;
  void *application_hook;

  /* Properties. */
  char *anonymous_token;
  char *authid;
  char *authzid;
  char *password;
  char *passcode;
  char *pin;
  char *suggestedpin;
  char *service;
  char *hostname;
  char *gssapi_display_name;
  char *realm;
  char *digest_md5_hashed_password;
  char *qops;
  char *qop;
  char *scram_iter;
  char *scram_salt;
  char *scram_salted_password;
  char *scram_serverkey;
  char *scram_storedkey;
  char *cb_tls_unique;
  char *saml20_idp_identifier;
  char *saml20_redirect_url;
  char *openid20_redirect_url;
  char *openid20_outcome_data;
  /* If you add anything here, remember to change change
     gsasl_finish() in xfinish.c and map() in property.c.  */
};

#endif /* INTERNAL_H */
