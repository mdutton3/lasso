/* -*- Mode: c; c-basic-offset: 8 -*-
 *
 * $Id$
 *
 * SWIG bindings for Lasso Library
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 *
 * Authors: Romain Chantereau <rchantereau@entrouvert.com>
 *          Emmanuel Raviart <eraviart@entrouvert.com>
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


#include <lasso/lasso_config.h>
#include <lasso/lasso.h>


/***********************************************************************
 ***********************************************************************
 * Profiles
 ***********************************************************************
 ***********************************************************************/


/***********************************************************************
 * Profile
 ***********************************************************************/


LassoAuthnRequest* lasso_profile_get_authn_request_ref(LassoProfile *profile)
{
	if (profile->request_type == lassoMessageTypeAuthnRequest)
		return LASSO_AUTHN_REQUEST(profile->request);
	else
		return NULL;
}

LassoAuthnResponse* lasso_profile_get_authn_response_ref(LassoProfile *profile)
{
	if (profile->response_type == lassoMessageTypeAuthnResponse)
		return LASSO_AUTHN_RESPONSE(profile->response);
	else
		return NULL;
}

LassoRequest* lasso_profile_get_request_ref(LassoProfile *profile)
{
	if (profile->request_type == lassoMessageTypeRequest)
		return LASSO_REQUEST(profile->request);
	else
		return NULL;
}

LassoResponse* lasso_profile_get_response_ref(LassoProfile *profile)
{
	if (profile->response_type == lassoMessageTypeResponse)
		return LASSO_RESPONSE(profile->response);
	else
		return NULL;
}
