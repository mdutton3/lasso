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


#include <lasso_config.h>
#include <lasso.h>


/***********************************************************************
 ***********************************************************************
 * Profiles
 ***********************************************************************
 ***********************************************************************/


/***********************************************************************
 * Server
 ***********************************************************************/


LassoServer *new_LassoServer(gchar *metadata, gchar *public_key, gchar *private_key,
			     gchar *certificate, guint signature_method)
{
	return lasso_server_new(metadata, public_key, private_key, certificate,signature_method);
}

void delete_LassoServer(LassoServer *server)
{
	lasso_server_destroy(server);
}


/***********************************************************************
 * Identity
 ***********************************************************************/


LassoIdentity *new_LassoIdentity()
{
	return lasso_identity_new();
}

void delete_LassoIdentity(LassoIdentity *identity)
{
	lasso_identity_destroy(identity);
}


/***********************************************************************
 * Session
 ***********************************************************************/


LassoSession *new_LassoSession()
{
	return lasso_session_new();
}

void delete_LassoSession(LassoSession *session)
{
	lasso_session_destroy(session);
}


/***********************************************************************
 * Login
 ***********************************************************************/


LassoLogin *new_LassoLogin(LassoServer *server)
{
	return lasso_login_new(server);
}

void delete_LassoLogin(LassoLogin *login)
{
	lasso_login_destroy(login);
}


/***********************************************************************
 * Logout
 ***********************************************************************/


LassoLogout *new_LassoLogout(LassoServer *server, lassoProviderType provider_type)
{
	return lasso_logout_new(server, provider_type);
}

void delete_LassoLogout(LassoLogout *logout)
{
	lasso_logout_destroy(logout);
}


/***********************************************************************
 * Lecp
 ***********************************************************************/


LassoLecp *new_LassoLecp(LassoServer *server)
{
	return lasso_lecp_new(server);
}

void delete_LassoLecp(LassoLecp *lecp)
{
	lasso_lecp_destroy(lecp);
}
