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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef __LASSO_SAML_NAME_IDENTIFIER_H__
#define __LASSO_SAML_NAME_IDENTIFIER_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "xml.h"

#define LASSO_TYPE_SAML_NAME_IDENTIFIER (lasso_saml_name_identifier_get_type())
#define LASSO_SAML_NAME_IDENTIFIER(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SAML_NAME_IDENTIFIER, \
				    LassoSamlNameIdentifier))
#define LASSO_SAML_NAME_IDENTIFIER_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_SAML_NAME_IDENTIFIER, \
				 LassoSamlNameIdentifierClass))
#define LASSO_IS_SAML_NAME_IDENTIFIER(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SAML_NAME_IDENTIFIER))
#define LASSO_IS_SAML_NAME_IDENTIFIER_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SAML_NAME_IDENTIFIER))
#define LASSO_SAML_NAME_IDENTIFIER_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_SAML_NAME_IDENTIFIER, \
				    LassoSamlNameIdentifierClass))

typedef struct _LassoSamlNameIdentifier LassoSamlNameIdentifier;
typedef struct _LassoSamlNameIdentifierClass LassoSamlNameIdentifierClass;

/**
 * LassoSamlNameIdentifier:
 *
 * @NameQualifier is the provider ID of the provider that created the name
 * identifier.
 *
 * @Format is a string constant defined by the Liberty
 * Alliance.  The following constants are defined:
 * #LASSO_LIB_NAME_IDENTIFIER_FORMAT_FEDERATED,
 * #LASSO_LIB_NAME_IDENTIFIER_FORMAT_ONE_TIME,
 * #LASSO_LIB_NAME_IDENTIFIER_FORMAT_ENCRYPTED (when providers transmit name
 * identifiers) and
 * #LASSO_LIB_NAME_IDENTIFIER_FORMAT_ENTITYID.
 *
 */
struct _LassoSamlNameIdentifier {
	LassoNode parent;

	/*< public >*/
	char *NameQualifier;
	char *Format;
	char *content;
};

struct _LassoSamlNameIdentifierClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_saml_name_identifier_get_type(void);
LASSO_EXPORT LassoSamlNameIdentifier* lasso_saml_name_identifier_new(void);

LASSO_EXPORT LassoSamlNameIdentifier* lasso_saml_name_identifier_new_from_xmlNode(
		xmlNode *xmlnode);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SAML_NAME_IDENTIFIER_H__ */
