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
    return "Failed to sign the node.\n";
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

  case LASSO_PARAM_ERROR_INVALID_OBJ_TYPE:
    return "The type of an object provided as parameter is invalid.\n";
  case LASSO_PARAM_ERROR_INVALID_VALUE:
    return "The value of a parameter is invalid.\n";

  default:
    sprintf(msg, "Undefined error code %d !!!", error_code);
    return(strdup(msg));
  }
}
