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

#ifndef __LASSO_SAML_SUBJECT_LOCALITY_H__
#define __LASSO_SAML_SUBJECT_LOCALITY_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "xml.h"

#define LASSO_TYPE_SAML_SUBJECT_LOCALITY (lasso_saml_subject_locality_get_type())
#define LASSO_SAML_SUBJECT_LOCALITY(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SAML_SUBJECT_LOCALITY, \
				    LassoSamlSubjectLocality))
#define LASSO_SAML_SUBJECT_LOCALITY_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_SAML_SUBJECT_LOCALITY, \
				 LassoSamlSubjectLocalityClass))
#define LASSO_IS_SAML_SUBJECT_LOCALITY(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SAML_SUBJECT_LOCALITY))
#define LASSO_IS_SAML_SUBJECT_LOCALITY_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SAML_SUBJECT_LOCALITY))
#define LASSO_SAML_SUBJECT_LOCALITY_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_SAML_SUBJECT_LOCALITY, \
				    LassoSamlSubjectLocalityClass))

typedef struct _LassoSamlSubjectLocality LassoSamlSubjectLocality;
typedef struct _LassoSamlSubjectLocalityClass LassoSamlSubjectLocalityClass;

struct _LassoSamlSubjectLocality {
	LassoNode parent;

	/*< public >*/
	/* <attribute name="IPAddress" type="string" use="optional"/> */
	char *IPAddress;
	/* <attribute name="DNSAddress" type="string" use="optional"/> */
	char *DNSAddress;
};

struct _LassoSamlSubjectLocalityClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_saml_subject_locality_get_type(void);
LASSO_EXPORT LassoNode* lasso_saml_subject_locality_new(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SAML_SUBJECT_LOCALITY_H__ */
