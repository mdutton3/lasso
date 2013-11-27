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

#ifndef __LASSO_SAML_SUBJECT_H__
#define __LASSO_SAML_SUBJECT_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "xml.h"
#include "saml_name_identifier.h"
#include "saml_subject_confirmation.h"
#include "saml-2.0/saml2_encrypted_element.h"

#define LASSO_TYPE_SAML_SUBJECT (lasso_saml_subject_get_type())
#define LASSO_SAML_SUBJECT(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SAML_SUBJECT, LassoSamlSubject))
#define LASSO_SAML_SUBJECT_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_SAML_SUBJECT, LassoSamlSubjectClass))
#define LASSO_IS_SAML_SUBJECT(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SAML_SUBJECT))
#define LASSO_IS_SAML_SUBJECT_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SAML_SUBJECT))
#define LASSO_SAML_SUBJECT_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_SAML_SUBJECT, LassoSamlSubjectClass))

typedef struct _LassoSamlSubject LassoSamlSubject;
typedef struct _LassoSamlSubjectClass LassoSamlSubjectClass;

struct _LassoSamlSubject {
	LassoNode parent;

	/*< public >*/
	LassoSamlNameIdentifier *NameIdentifier;
	LassoSamlSubjectConfirmation *SubjectConfirmation;
	LassoSaml2EncryptedElement *EncryptedNameIdentifier;
};

struct _LassoSamlSubjectClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_saml_subject_get_type(void);
LASSO_EXPORT LassoNode* lasso_saml_subject_new(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SAML_SUBJECT_H__ */
