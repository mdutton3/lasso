/*
 * Lasso library C unit tests
 *
 * Copyright (C) 2004-2007 Entr'ouvert
 * http://lasso.entrouvert.org
 *
 * Authors: See AUTHORS file in top-level directory.
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

#include <stdlib.h>
#include <string.h>

#include <check.h>
#include <glib.h>

#include "../lasso/lasso.h"
#include "../lasso/utils.h"
#include "../lasso/backward_comp.h"
#include "../lasso/xml/saml-2.0/saml2_xsd.h"
#include "../bindings/ghashtable.h"

#include "./tests.h"

inline static char*
generateIdentityProviderContextDump()
{
	LassoServer *serverContext;
	GList *providers;
	char *ret;

	serverContext = lasso_server_new(
			TESTSDATADIR "/idp6-saml2/metadata.xml",
			TESTSDATADIR "/idp6-saml2/private-key.pem",
			NULL, /* Secret key to unlock private key */
			NULL);
	lasso_server_add_provider(
			serverContext,
			LASSO_PROVIDER_ROLE_SP,
			TESTSDATADIR "/sp5-saml2/metadata.xml",
			NULL,
			NULL);
	providers = g_hash_table_get_values(serverContext->providers);
	lasso_provider_set_encryption_mode(LASSO_PROVIDER(providers->data), LASSO_ENCRYPTION_MODE_ASSERTION | LASSO_ENCRYPTION_MODE_NAMEID);
	ret = lasso_server_dump(serverContext);

	g_object_unref(serverContext);

	return ret;
}

inline static char*
generateServiceProviderContextDump()
{
	LassoServer *serverContext;
	char *ret;

	serverContext = lasso_server_new(
			TESTSDATADIR "/sp5-saml2/metadata.xml",
			TESTSDATADIR "/sp5-saml2/private-key.pem",
			NULL, /* Secret key to unlock private key */
			NULL);
	lasso_server_add_provider(
			serverContext,
			LASSO_PROVIDER_ROLE_IDP,
			TESTSDATADIR "/idp6-saml2/metadata.xml",
			NULL,
			NULL);

	ret = lasso_server_dump(serverContext);
	g_object_unref(serverContext);
	return ret;
}

Suite*
assertion_query_suite()
{
	Suite *s = suite_create("Assertion Query");
	TCase *tc_metadata_access = tcase_create("Extended metadata access");
	suite_add_tcase(s, tc_metadata_access);

	return s;
}
