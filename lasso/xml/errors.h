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

#define LASSO_XML_ERROR_NODE_NOTFOUND         -10
#define LASSO_XML_ERROR_NODE_CONTENT_NOTFOUND -11
#define LASSO_XML_ERROR_ATTR_NOTFOUND         -12
#define LASSO_XML_ERROR_ATTR_VALUE_NOTFOUND   -13

#define LASSO_DS_ERROR_CONTEXT_CREATION_FAILED       -101
#define LASSO_DS_ERROR_PUBLIC_KEY_LOAD_FAILED        -102
#define LASSO_DS_ERROR_PRIVATE_KEY_LOAD_FAILED       -103
#define LASSO_DS_ERROR_CERTIFICATE_LOAD_FAILED       -104
#define LASSO_DS_ERROR_SIGNATURE_FAILED              -105
#define LASSO_DS_ERROR_SIGNATURE_NOTFOUND            -106
#define LASSO_DS_ERROR_KEYS_MNGR_CREATION_FAILED     -107
#define LASSO_DS_ERROR_KEYS_MNGR_INIT_FAILED         -108
#define LASSO_DS_ERROR_SIGNATURE_VERIFICATION_FAILED -109
#define LASSO_DS_ERROR_INVALID_SIGNATURE             -110

#define LASSO_SERVER_ERROR_PROVIDER_NOTFOUND   -201
#define LASSO_SERVER_ERROR_ADD_PROVIDER_FAILED -202

#define LASSO_PARAM_ERROR_BADTYPE_OR_NULL_OBJ -501
#define LASSO_PARAM_ERROR_INVALID_VALUE       -502
#define LASSO_PARAM_ERROR_ERR_CHECK_FAILED    -503

#define LASSO_ERROR_UNDEFINED  -999

const char* lasso_strerror(int error_code);
