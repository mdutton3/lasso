/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Valery Febvre   <vfebvre@easter-eggs.com>
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

#include <lasso/protocols/protocols.h>

gint lasso_authn_request_signature_verify(xmlChar *query,
					  const xmlChar *public_key_file,
					  const xmlChar *private_key_file)
{
  return (lasso_str_verify(query, public_key_file, private_key_file));
}

gboolean
lasso_authn_request_must_authenticate(xmlChar  *query,
				      gboolean  is_authenticated)
{
  GData    *gd;
  gboolean  must_authenticate = FALSE;
  /* default values for ForceAuthn and IsPassive */
  gboolean forceAuthn = FALSE;
  gboolean isPassive  = TRUE;

  gd = lasso_query_to_dict(query);
  /* Get ForceAuthn and IsPassive */
  if (xmlStrEqual(lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "ForceAuthn"), 0), "true")){
    forceAuthn = TRUE;
  }
  if (xmlStrEqual((xmlChar *)lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "IsPassive"), 0), "false")) {
    isPassive = FALSE;
  }

  if ((forceAuthn == TRUE || is_authenticated == FALSE) && isPassive == FALSE) {
    must_authenticate = TRUE;
  }

  g_datalist_clear(&gd);
  return (must_authenticate);
}

lassoAuthnRequestCtx *
lasso_process_authn_request_query(xmlChar       *query,
				  gboolean       verify_signature,
				  const xmlChar *public_key_file,
				  const xmlChar *private_key_file,
				  gboolean       is_authenticated) {
  lassoAuthnRequestCtx *ctx;
  GData                *gd;
  /* default values for ForceAuthn and IsPassive */
  gboolean forceAuthn = FALSE;
  gboolean isPassive  = TRUE;

  ctx = g_new (lassoAuthnRequestCtx, 1);

  if (verify_signature == TRUE) {
    /* private_key_file is an IDP private key only used to rebuild digestValue
       and verify signatureValue in query */
    ctx->signature_is_valid = lasso_str_verify(query,
					       public_key_file,
					       private_key_file);
  }
  else {
    ctx->signature_is_valid = -1;
  }

  gd = lasso_query_to_dict(query);
  /* Get ForceAuthn and IsPassive */
  if (xmlStrEqual(lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "ForceAuthn"), 0), "true")){
    forceAuthn = TRUE;
  }
  if (xmlStrEqual((xmlChar *)lasso_g_ptr_array_index((GPtrArray *)g_datalist_get_data(&gd, "IsPassive"), 0), "false")) {
    isPassive = FALSE;
  }

  ctx->must_authenticate = FALSE;
  if ((forceAuthn == TRUE || is_authenticated == FALSE) && isPassive == FALSE) {
    ctx->must_authenticate = TRUE;
  }

  g_datalist_clear(&gd);
  return (ctx);
}
