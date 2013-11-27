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

#ifndef __LASSO_SAMLP2_STATUS_RESPONSE_H__
#define __LASSO_SAMLP2_STATUS_RESPONSE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "samlp2_status.h"
#include "saml2_name_id.h"
#include "samlp2_extensions.h"

#define LASSO_TYPE_SAMLP2_STATUS_RESPONSE (lasso_samlp2_status_response_get_type())
#define LASSO_SAMLP2_STATUS_RESPONSE(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SAMLP2_STATUS_RESPONSE, \
				LassoSamlp2StatusResponse))
#define LASSO_SAMLP2_STATUS_RESPONSE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_SAMLP2_STATUS_RESPONSE, \
				LassoSamlp2StatusResponseClass))
#define LASSO_IS_SAMLP2_STATUS_RESPONSE(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SAMLP2_STATUS_RESPONSE))
#define LASSO_IS_SAMLP2_STATUS_RESPONSE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SAMLP2_STATUS_RESPONSE))
#define LASSO_SAMLP2_STATUS_RESPONSE_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_SAMLP2_STATUS_RESPONSE, \
				LassoSamlp2StatusResponseClass))

typedef struct _LassoSamlp2StatusResponse LassoSamlp2StatusResponse;
typedef struct _LassoSamlp2StatusResponseClass LassoSamlp2StatusResponseClass;


struct _LassoSamlp2StatusResponse {
	LassoNode parent;

	/*< public >*/
	/* elements */
	LassoSaml2NameID *Issuer;
	LassoSamlp2Extensions *Extensions;
	LassoSamlp2Status *Status;
	/* attributes */
	char *ID;
	char *InResponseTo;
	char *Version;
	char *IssueInstant;
	char *Destination;
	char *Consent;
	/*< private >*/
	/* ds:Signature stuffs */
	LassoSignatureType sign_type;
	LassoSignatureMethod sign_method;
	char *private_key_file;
	char *certificate_file;

};


struct _LassoSamlp2StatusResponseClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_samlp2_status_response_get_type(void);
LASSO_EXPORT LassoNode* lasso_samlp2_status_response_new(void);



#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SAMLP2_STATUS_RESPONSE_H__ */
