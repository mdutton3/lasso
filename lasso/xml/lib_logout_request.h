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

#ifndef __LASSO_LIB_LOGOUT_REQUEST_H__
#define __LASSO_LIB_LOGOUT_REQUEST_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "samlp_request_abstract.h"
#include "saml_name_identifier.h"

#define LASSO_TYPE_LIB_LOGOUT_REQUEST (lasso_lib_logout_request_get_type())
#define LASSO_LIB_LOGOUT_REQUEST(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_LIB_LOGOUT_REQUEST, LassoLibLogoutRequest))
#define LASSO_LIB_LOGOUT_REQUEST_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_LIB_LOGOUT_REQUEST, \
				 LassoLibLogoutRequestClass))
#define LASSO_IS_LIB_LOGOUT_REQUEST(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_LIB_LOGOUT_REQUEST))
#define LASSO_IS_LIB_LOGOUT_REQUEST_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_LIB_LOGOUT_REQUEST))
#define LASSO_LIB_LOGOUT_REQUEST_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_LIB_LOGOUT_REQUEST, \
				    LassoLibLogoutRequestClass))

typedef struct _LassoLibLogoutRequest LassoLibLogoutRequest;
typedef struct _LassoLibLogoutRequestClass LassoLibLogoutRequestClass;

struct _LassoLibLogoutRequest {
	LassoSamlpRequestAbstract parent;

	/*< public >*/
	/* <xs:element ref="Extension" minOccurs="0" maxOccurs="unbounded"/> */
	GList *Extension; /* of xmlNode* */
	char *ProviderID;
	LassoSamlNameIdentifier *NameIdentifier;
	char *SessionIndex;
	char *RelayState;
	char *consent;
	char *NotOnOrAfter;
};

struct _LassoLibLogoutRequestClass {
	LassoSamlpRequestAbstractClass parent;
};

LASSO_EXPORT GType lasso_lib_logout_request_get_type(void);
LASSO_EXPORT LassoNode* lasso_lib_logout_request_new(void);

LASSO_EXPORT LassoNode* lasso_lib_logout_request_new_full(
		char *providerID, LassoSamlNameIdentifier *nameIdentifier,
		LassoSignatureType sign_type, LassoSignatureMethod sign_method);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_LIB_LOGOUT_REQUEST_H__ */
