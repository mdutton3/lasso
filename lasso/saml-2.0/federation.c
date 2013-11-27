/* $Id$
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */


#include "../xml/private.h"
#include "../id-ff/federation.h"
#include "federationprivate.h"

#include "../xml/saml-2.0/saml2_name_id.h"


static LassoNode*
lasso_saml20_federation_build_name_identifier(const gchar *nameQualifier,
		const gchar *format, const gchar *content)
{
	LassoSaml2NameID *name_id;

	name_id = LASSO_SAML2_NAME_ID(lasso_saml2_name_id_new());
	if (content == NULL) {
		name_id->content = lasso_build_unique_id(32);
	} else {
		name_id->content = g_strdup(content);
	}
	name_id->NameQualifier = g_strdup(nameQualifier);
	name_id->Format = g_strdup(format);

	return LASSO_NODE(name_id);
}


void
lasso_saml20_federation_build_local_name_identifier(LassoFederation *federation,
		const gchar *nameQualifier, const gchar *format, const gchar *content)
{
	federation->local_nameIdentifier = lasso_saml20_federation_build_name_identifier(
			nameQualifier, format, content);
}


