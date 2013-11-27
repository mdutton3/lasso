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

#ifndef __LASSO_SAML_ATTRIBUTE_H__
#define __LASSO_SAML_ATTRIBUTE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "saml_attribute_designator.h"

#define LASSO_TYPE_SAML_ATTRIBUTE (lasso_saml_attribute_get_type())
#define LASSO_SAML_ATTRIBUTE(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SAML_ATTRIBUTE, LassoSamlAttribute))
#define LASSO_SAML_ATTRIBUTE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_SAML_ATTRIBUTE, LassoSamlAttributeClass))
#define LASSO_IS_SAML_ATTRIBUTE(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SAML_ATTRIBUTE))
#define LASSO_IS_SAML_ATTRIBUTE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SAML_ATTRIBUTE))
#define LASSO_SAML_ATTRIBUTE_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_SAML_ATTRIBUTE, LassoSamlAttributeClass))

typedef struct _LassoSamlAttribute LassoSamlAttribute;
typedef struct _LassoSamlAttributeClass LassoSamlAttributeClass;

struct _LassoSamlAttribute {
	LassoSamlAttributeDesignator parent;

	/*< public >*/
	gchar *attributeName;
	gchar *attributeNameSpace;
	GList *AttributeValue; /* of LassoNode */
};

struct _LassoSamlAttributeClass {
	LassoSamlAttributeDesignatorClass parent;
};

LASSO_EXPORT GType lasso_saml_attribute_get_type(void);
LASSO_EXPORT LassoSamlAttribute* lasso_saml_attribute_new(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SAML_ATTRIBUTE_H__ */
