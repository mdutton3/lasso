/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Valery Febvre <vfebvre@easter-eggs.com>
 *          Nicolas Clapies <nclapies@entrouvert.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef __LASSO_PROTOCOLS_H__
#define __LASSO_PROTOCOLS_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <lasso/xml/lib_authn_request.h>
#include <lasso/xml/lib_authn_response.h>
#include <lasso/xml/lib_federation_termination_notification.h>
#include <lasso/xml/lib_logout_request.h>
#include <lasso/xml/lib_logout_response.h>
#include <lasso/xml/lib_register_name_identifier_request.h>
#include <lasso/xml/lib_register_name_identifier_response.h>

typedef struct _lassoAuthnRequestCtx lassoAuthnRequestCtx;
struct _lassoAuthnRequestCtx {
  gboolean  must_authenticate;
  gboolean  signature_is_valid;
};

LASSO_EXPORT gint lasso_authn_request_signature_verify(xmlChar *query,
						       const xmlChar *public_key_file,
						       const xmlChar *private_key_file);

LASSO_EXPORT gboolean lasso_authn_request_must_authenticate(xmlChar  *query,
							    gboolean  is_authenticated);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif  /* __LASSO_PROTOCOLS_H__ */
