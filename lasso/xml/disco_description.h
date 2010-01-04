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

#ifndef __LASSO_DISCO_DESCRIPTION_H__
#define __LASSO_DISCO_DESCRIPTION_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "xml.h"

#define LASSO_TYPE_DISCO_DESCRIPTION (lasso_disco_description_get_type())
#define LASSO_DISCO_DESCRIPTION(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_DISCO_DESCRIPTION, LassoDiscoDescription))
#define LASSO_DISCO_DESCRIPTION_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_DISCO_DESCRIPTION, \
				 LassoDiscoDescriptionClass))
#define LASSO_IS_DISCO_DESCRIPTION(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_DISCO_DESCRIPTION))
#define LASSO_IS_DISCO_DESCRIPTION_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_DISCO_DESCRIPTION))
#define LASSO_DISCO_DESCRIPTION_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_DISCO_DESCRIPTION, \
				    LassoDiscoDescriptionClass))

typedef struct _LassoDiscoDescription LassoDiscoDescription;
typedef struct _LassoDiscoDescriptionClass LassoDiscoDescriptionClass;

struct _LassoDiscoDescription {
	LassoNode parent;

	/*
	 * - The service instance description SHOULD list of all of the security mechanisms that
	 *   the service instance supports.
	 * - The client SHOULD pick the first mechanism (in the order listed) that it supports;
	 *   the description SHOULD list them in order of preference, to avoid situations where the
	 *   client fails to gain access to the service because it picked the wrong security
	 *   mechanism.
	 */
	GList *SecurityMechID; /* of strings */
	GList *CredentialRef; /* of strings */

	/* WsdlRef group */
	gchar *WsdlURI;
	gchar *ServiceNameRef;

	/* BriefSoapHttpDescription group */
	gchar *Endpoint;
	gchar *SoapAction;

	char *id;
};

struct _LassoDiscoDescriptionClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_disco_description_get_type (void);

LASSO_EXPORT LassoDiscoDescription *lasso_disco_description_copy(
	LassoDiscoDescription *description);

LASSO_EXPORT LassoDiscoDescription* lasso_disco_description_new();

LASSO_EXPORT LassoDiscoDescription* lasso_disco_description_new_with_WsdlRef(
	const gchar *securityMechID,
	const gchar *wsdlURI,
	const gchar *serviceNameRef);

LASSO_EXPORT LassoDiscoDescription* lasso_disco_description_new_with_BriefSoapHttpDescription(
	const gchar *securityMechID,
	const gchar *endpoint,
	const gchar *soapAction);

LASSO_EXPORT gboolean lasso_disco_description_has_saml_authentication(
	LassoDiscoDescription *description);

LASSO_EXPORT gboolean lasso_disco_description_has_x509_authentication(
	LassoDiscoDescription *description);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_DISCO_DESCRIPTION_H__ */
