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

#include "errors.h"
#include <stdio.h>
#include <string.h>

const char*
lasso_strerror(int error_code)
{
  char msg[256];

  switch (error_code) {
  case LASSO_XML_ERROR_NODE_NOTFOUND:
    return "Unable to get '%s' child of '%s' element.\n";
  case LASSO_XML_ERROR_NODE_CONTENT_NOTFOUND:
    return "Unable to get content of '%s' element.\n";
  case LASSO_XML_ERROR_ATTR_NOTFOUND:
    return "Unable to get '%s' attribute of '%s' element.\n";
  case LASSO_XML_ERROR_ATTR_VALUE_NOTFOUND:
    return "Unable to get '%s' attribute value of '%s' element.\n";

  case LASSO_DS_ERROR_CONTEXT_CREATION_FAILED:
    return "Failed to create signature context.\n";
  case LASSO_DS_ERROR_PUBLIC_KEY_LOAD_FAILED:
    return "Failed to load public key %s.\n";
  case LASSO_DS_ERROR_PRIVATE_KEY_LOAD_FAILED:
    return "Failed to load private key %s.\n";
  case LASSO_DS_ERROR_CERTIFICATE_LOAD_FAILED:
    return "Failed to load certificate %s.\n";
  case LASSO_DS_ERROR_SIGNATURE_FAILED:
    return "Failed to sign the node %s.\n";
  case LASSO_DS_ERROR_SIGNATURE_NOTFOUND:
    return "Signature element not found in %s.\n";
  case LASSO_DS_ERROR_KEYS_MNGR_CREATION_FAILED:
    return "Failed to create keys manager.\n";
  case LASSO_DS_ERROR_KEYS_MNGR_INIT_FAILED:
    return "Failed to initialize keys manager.\n";
  case LASSO_DS_ERROR_SIGNATURE_VERIFICATION_FAILED:
    return "Failed to verify signature of %s.\n";
  case LASSO_DS_ERROR_INVALID_SIGNATURE:
    return "The signature of %s is invalid.\n";

  case LASSO_SERVER_ERROR_PROVIDER_NOTFOUND:
    return "Failed to get LassoProvider object with providerID %s in LassoServer object.\n";

  case LASSO_LOGOUT_ERROR_UNSUPPORTED_PROFILE:
    return "Unsupported logout protocol profile\n";

  case LASSO_PROFILE_ERROR_INVALID_QUERY:
    return "Error while parsing query message\n";

  case LASSO_PARAM_ERROR_BADTYPE_OR_NULL_OBJ:
    return "An object type provided as parameter is invalid or object is NULL.\n";
  case LASSO_PARAM_ERROR_INVALID_VALUE:
    return "A parameter value is invalid.\n";
  case LASSO_PARAM_ERROR_ERR_CHECK_FAILED:
    return "The error return location should be either NULL or contains a NULL error.\n";

  default:
    sprintf(msg, "Undefined error code %d.", error_code);
    return(strdup(msg));
  }
}
