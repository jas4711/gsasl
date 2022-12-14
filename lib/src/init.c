/* init.c --- Entry point for libgsasl.
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

/* Get gc_init. */
#include <gc.h>

/* Get mechanism headers. */
#include "cram-md5/cram-md5.h"
#include "external/external.h"
#include "gssapi/x-gssapi.h"
#include "gs2/gs2.h"
#include "anonymous/anonymous.h"
#include "plain/plain.h"
#include "securid/securid.h"
#include "digest-md5/digest-md5.h"
#include "scram/scram.h"
#include "saml20/saml20.h"
#include "openid20/openid20.h"

#include "login/login.h"
#include "ntlm/x-ntlm.h"

static int
register_builtin_mechs (Gsasl * ctx)
{
  int rc = GSASL_OK;

#ifdef USE_ANONYMOUS
  rc = gsasl_register (ctx, &_gsasl_anonymous_mechanism);
  if (rc != GSASL_OK)
    return rc;
#endif /* USE_ANONYMOUS */

#ifdef USE_EXTERNAL
  rc = gsasl_register (ctx, &_gsasl_external_mechanism);
  if (rc != GSASL_OK)
    return rc;
#endif /* USE_EXTERNAL */

#ifdef USE_LOGIN
  rc = gsasl_register (ctx, &_gsasl_login_mechanism);
  if (rc != GSASL_OK)
    return rc;
#endif /* USE_LOGIN */

#ifdef USE_PLAIN
  rc = gsasl_register (ctx, &_gsasl_plain_mechanism);
  if (rc != GSASL_OK)
    return rc;
#endif /* USE_PLAIN */

#ifdef USE_SECURID
  rc = gsasl_register (ctx, &_gsasl_securid_mechanism);
  if (rc != GSASL_OK)
    return rc;
#endif /* USE_SECURID */

#ifdef USE_NTLM
  rc = gsasl_register (ctx, &_gsasl_ntlm_mechanism);
  if (rc != GSASL_OK)
    return rc;
#endif /* USE_NTLM */

#ifdef USE_DIGEST_MD5
  rc = gsasl_register (ctx, &_gsasl_digest_md5_mechanism);
  if (rc != GSASL_OK)
    return rc;
#endif /* USE_DIGEST_MD5 */

#ifdef USE_CRAM_MD5
  rc = gsasl_register (ctx, &_gsasl_cram_md5_mechanism);
  if (rc != GSASL_OK)
    return rc;
#endif /* USE_CRAM_MD5 */

#ifdef USE_SCRAM_SHA1
  rc = gsasl_register (ctx, &_gsasl_scram_sha1_mechanism);
  if (rc != GSASL_OK)
    return rc;

  rc = gsasl_register (ctx, &_gsasl_scram_sha1_plus_mechanism);
  if (rc != GSASL_OK)
    return rc;
#endif /* USE_SCRAM_SHA1 */

#ifdef USE_SCRAM_SHA256
  rc = gsasl_register (ctx, &_gsasl_scram_sha256_mechanism);
  if (rc != GSASL_OK)
    return rc;

  rc = gsasl_register (ctx, &_gsasl_scram_sha256_plus_mechanism);
  if (rc != GSASL_OK)
    return rc;
#endif /* USE_SCRAM_SHA256 */

#ifdef USE_SAML20
  rc = gsasl_register (ctx, &_gsasl_saml20_mechanism);
  if (rc != GSASL_OK)
    return rc;
#endif /* USE_SAML20 */

#ifdef USE_OPENID20
  rc = gsasl_register (ctx, &_gsasl_openid20_mechanism);
  if (rc != GSASL_OK)
    return rc;
#endif /* USE_OPENID20 */

#ifdef USE_GSSAPI
  rc = gsasl_register (ctx, &_gsasl_gssapi_mechanism);
  if (rc != GSASL_OK)
    return rc;
#endif /* USE_GSSAPI */

#ifdef USE_GS2
  rc = gsasl_register (ctx, &_gsasl_gs2_krb5_mechanism);
  if (rc != GSASL_OK)
    return rc;
#endif /* USE_GSSAPI */

  return GSASL_OK;
}

/**
 * gsasl_init:
 * @ctx: pointer to libgsasl handle.
 *
 * This functions initializes libgsasl.  The handle pointed to by ctx
 * is valid for use with other libgsasl functions iff this function is
 * successful.  It also register all builtin SASL mechanisms, using
 * gsasl_register().
 *
 * Return value: GSASL_OK iff successful, otherwise
 * %GSASL_MALLOC_ERROR.
 **/
int
gsasl_init (Gsasl ** ctx)
{
  int rc;

  if (gc_init () != GC_OK)
    return GSASL_CRYPTO_ERROR;

  *ctx = (Gsasl *) calloc (1, sizeof (**ctx));
  if (*ctx == NULL)
    return GSASL_MALLOC_ERROR;

  rc = register_builtin_mechs (*ctx);
  if (rc != GSASL_OK)
    {
      gsasl_done (*ctx);
      return rc;
    }

  return GSASL_OK;
}
