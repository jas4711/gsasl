/* error.c --- Error handling functionality.
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

/* I18n of error codes. */
#include "gettext.h"
#define _(String) dgettext (PACKAGE, String)
#define gettext_noop(String) String
#define N_(String) gettext_noop (String)

#define ERR(name, desc) { name, #name, desc }

/* *INDENT-OFF* */
static struct
{
  int rc;
  const char *name;
  const char *description;
} errors[] = {
  ERR (GSASL_OK, N_("Libgsasl success")),
  ERR (GSASL_NEEDS_MORE, N_("SASL mechanism needs more data")),
  ERR (GSASL_UNKNOWN_MECHANISM, N_("Unknown SASL mechanism")),
  ERR (GSASL_MECHANISM_CALLED_TOO_MANY_TIMES,
       N_("SASL mechanism called too many times")),
  { 4, NULL, NULL },
  { 5, NULL, NULL },
  { 6, NULL, NULL },
  ERR (GSASL_MALLOC_ERROR, N_("Memory allocation error in SASL library")),
  ERR (GSASL_BASE64_ERROR, N_("Base 64 coding error in SASL library")),
  ERR (GSASL_CRYPTO_ERROR, N_("Low-level crypto error in SASL library")),
  { 10, NULL, NULL },
  { 11, NULL, NULL },
  { 12, NULL, NULL },
  { 13, NULL, NULL },
  { 14, NULL, NULL },
  { 15, NULL, NULL },
  { 16, NULL, NULL },
  { 17, NULL, NULL },
  { 18, NULL, NULL },
  { 19, NULL, NULL },
  { 20, NULL, NULL },
  { 21, NULL, NULL },
  { 22, NULL, NULL },
  { 23, NULL, NULL },
  { 24, NULL, NULL },
  { 25, NULL, NULL },
  { 26, NULL, NULL },
  { 27, NULL, NULL },
  { 28, NULL, NULL },
  ERR (GSASL_SASLPREP_ERROR,
       N_("Could not prepare internationalized (non-ASCII) string.")),
  ERR (GSASL_MECHANISM_PARSE_ERROR,
       N_("SASL mechanism could not parse input")),
  ERR (GSASL_AUTHENTICATION_ERROR, N_("Error authenticating user")),
  { 32, NULL, NULL },
  ERR (GSASL_INTEGRITY_ERROR, N_("Integrity error in application payload")),
  { 34, NULL, NULL },
  ERR (GSASL_NO_CLIENT_CODE,
       N_("Client-side functionality not available in library "
	  "(application error)")),
  ERR (GSASL_NO_SERVER_CODE,
       N_("Server-side functionality not available in library "
	  "(application error)")),
  ERR (GSASL_GSSAPI_RELEASE_BUFFER_ERROR,
       N_("GSSAPI library could not deallocate memory in "
	  "gss_release_buffer() in SASL library.  This is a serious "
	  "internal error.")),
  ERR (GSASL_GSSAPI_IMPORT_NAME_ERROR,
       N_("GSSAPI library could not understand a peer name in "
	  "gss_import_name() in SASL library.  This is most likely due "
	  "to incorrect service and/or hostnames.")),
  ERR (GSASL_GSSAPI_INIT_SEC_CONTEXT_ERROR,
       N_("GSSAPI error in client while negotiating security context in "
	  "gss_init_sec_context() in SASL library.  This is most likely "
	  "due insufficient credentials or malicious interactions.")),
  ERR (GSASL_GSSAPI_ACCEPT_SEC_CONTEXT_ERROR,
       N_("GSSAPI error in server while negotiating security context in "
	  "gss_accept_sec_context() in SASL library.  This is most likely due "
	  "insufficient credentials or malicious interactions.")),
  ERR (GSASL_GSSAPI_UNWRAP_ERROR,
       N_("GSSAPI error while decrypting or decoding data in gss_unwrap() in "
	  "SASL library.  This is most likely due to data corruption.")),
  ERR (GSASL_GSSAPI_WRAP_ERROR,
       N_("GSSAPI error while encrypting or encoding data in gss_wrap() in "
	  "SASL library.")),
  ERR (GSASL_GSSAPI_ACQUIRE_CRED_ERROR,
       N_("GSSAPI error acquiring credentials in gss_acquire_cred() in "
	  "SASL library.  This is most likely due to not having the proper "
	  "Kerberos key available in /etc/krb5.keytab on the server.")),
  ERR (GSASL_GSSAPI_DISPLAY_NAME_ERROR,
       N_("GSSAPI error creating a display name denoting the client in "
	  "gss_display_name() in SASL library.  This is probably because "
	  "the client supplied bad data.")),
  ERR (GSASL_GSSAPI_UNSUPPORTED_PROTECTION_ERROR,
       N_("Other entity requested integrity or confidentiality protection "
	  "in GSSAPI mechanism but this is currently not implemented.")),
  { 46, NULL, NULL },
  { 47, NULL, NULL },
  ERR (GSASL_SECURID_SERVER_NEED_ADDITIONAL_PASSCODE,
       N_("SecurID needs additional passcode.")),
  ERR (GSASL_SECURID_SERVER_NEED_NEW_PIN,
       N_("SecurID needs new pin.")),
  { 50, NULL, NULL },
  ERR (GSASL_NO_CALLBACK,
       N_("No callback specified by caller (application error).")),
  ERR (GSASL_NO_ANONYMOUS_TOKEN,
       N_("Authentication failed because the anonymous token was "
	  "not provided.")),
  ERR (GSASL_NO_AUTHID,
       N_("Authentication failed because the authentication identity was "
	  "not provided.")),
  ERR (GSASL_NO_AUTHZID,
       N_("Authentication failed because the authorization identity was "
	  "not provided.")),
  ERR (GSASL_NO_PASSWORD,
       N_("Authentication failed because the password was not provided.")),
  ERR (GSASL_NO_PASSCODE,
       N_("Authentication failed because the passcode was not provided.")),
  ERR (GSASL_NO_PIN,
       N_("Authentication failed because the pin code was not provided.")),
  ERR (GSASL_NO_SERVICE,
       N_("Authentication failed because the service name was not provided.")),
  ERR (GSASL_NO_HOSTNAME,
       N_("Authentication failed because the host name was not provided.")),
  ERR (GSASL_GSSAPI_ENCAPSULATE_TOKEN_ERROR,
       N_("GSSAPI error encapsulating token.")),
  ERR (GSASL_GSSAPI_DECAPSULATE_TOKEN_ERROR,
       N_("GSSAPI error decapsulating token.")),
  ERR (GSASL_GSSAPI_INQUIRE_MECH_FOR_SASLNAME_ERROR,
       N_("GSSAPI error getting OID for SASL mechanism name.")),
  ERR (GSASL_GSSAPI_TEST_OID_SET_MEMBER_ERROR,
       N_("GSSAPI error testing for OID in OID set.")),
  ERR (GSASL_GSSAPI_RELEASE_OID_SET_ERROR,
       N_("GSSAPI error releasing OID set.")),
  ERR (GSASL_NO_CB_TLS_UNIQUE,
       N_("Authentication failed because a tls-unique CB was not provided.")),
  ERR (GSASL_NO_SAML20_IDP_IDENTIFIER,
       N_("Callback failed to provide SAML20 IdP identifier.")),
  ERR (GSASL_NO_SAML20_REDIRECT_URL,
       N_("Callback failed to provide SAML20 redirect URL.")),
  ERR (GSASL_NO_OPENID20_REDIRECT_URL,
       N_("Callback failed to provide OPENID20 redirect URL.")),
  ERR (GSASL_NO_CB_TLS_EXPORTER,
       N_("Authentication failed because a tls-exporter channel binding was not provided."))
};
/* *INDENT-ON* */

/**
 * gsasl_strerror:
 * @err: libgsasl error code
 *
 * Convert return code to human readable string explanation of the
 * reason for the particular error code.
 *
 * This string can be used to output a diagnostic message to the user.
 *
 * This function is one of few in the library that can be used without
 * a successful call to gsasl_init().
 *
 * Return value: Returns a pointer to a statically allocated string
 *   containing an explanation of the error code @err.
 **/
const char *
gsasl_strerror (int err)
{
  static const char *unknown = N_("Libgsasl unknown error");
  const char *p;

  bindtextdomain (PACKAGE, LOCALEDIR);

  if (err < 0 || err >= (int) (sizeof (errors) / sizeof (errors[0])))
    return _(unknown);

  p = errors[err].description;
  if (!p)
    p = unknown;

  return _(p);
}


/**
 * gsasl_strerror_name:
 * @err: libgsasl error code
 *
 * Convert return code to human readable string representing the error
 * code symbol itself.  For example, gsasl_strerror_name(%GSASL_OK)
 * returns the string "GSASL_OK".
 *
 * This string can be used to output a diagnostic message to the user.
 *
 * This function is one of few in the library that can be used without
 * a successful call to gsasl_init().
 *
 * Return value: Returns a pointer to a statically allocated string
 *   containing a string version of the error code @err, or NULL if
 *   the error code is not known.
 *
 * Since: 0.2.29
 **/
const char *
gsasl_strerror_name (int err)
{
  if (err < 0 || err >= (int) (sizeof (errors) / sizeof (errors[0])))
    return NULL;

  return errors[err].name;
}
