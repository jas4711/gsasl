/* anonymous.h --- Prototypes for ANONYMOUS mechanism as defined in RFC 2245.
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
 * License along with GNU SASL Library; if not, write to the Free
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */

#ifndef ANONYMOUS_H
# define ANONYMOUS_H

# include <gsasl.h>

# define GSASL_ANONYMOUS_NAME "ANONYMOUS"

extern Gsasl_mechanism _gsasl_anonymous_mechanism;

extern int _gsasl_anonymous_client_step (Gsasl_session * sctx,
					 void *mech_data,
					 const char *input, size_t input_len,
					 char **output, size_t *output_len);

extern int _gsasl_anonymous_server_step (Gsasl_session * sctx,
					 void *mech_data,
					 const char *input, size_t input_len,
					 char **output, size_t *output_len);

#endif /* ANONYMOUS_H */
