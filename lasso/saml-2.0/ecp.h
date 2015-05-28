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

#ifndef __LASSO_ECP_H__
#define __LASSO_ECP_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml/xml.h"

#include "../id-ff/profile.h"
#include "../xml//saml-2.0/samlp2_idp_list.h"

#define LASSO_TYPE_ECP (lasso_ecp_get_type())
#define LASSO_ECP(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_ECP, LassoEcp))
#define LASSO_ECP_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_ECP, LassoEcpClass))
#define LASSO_IS_ECP(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_ECP))
#define LASSO_IS_ECP_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_ECP))
#define LASSO_ECP_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_ECP, LassoEcpClass))

typedef struct _LassoEcp LassoEcp;
typedef struct _LassoEcpClass LassoEcpClass;
typedef struct _LassoEcpPrivate LassoEcpPrivate;

struct _LassoEcp {
	LassoProfile parent;

	/*< public >*/
	gchar *assertion_consumer_url;
	gchar *message_id;
	gchar *response_consumer_url;
	gchar *relaystate;
	LassoSaml2NameID *issuer;
	gchar *provider_name;
	gboolean is_passive;
	LassoSamlp2IDPList *sp_idp_list;
	GList *known_sp_provided_idp_entries_supporting_ecp; /* of LassoSamlp2IDPEntry */
	GList *known_idp_entity_ids_supporting_ecp;	         /* of strings */

	/*< private >*/
	LassoEcpPrivate *private_data;
};

struct _LassoEcpClass {
	LassoProfileClass parent_class;
};

LASSO_EXPORT GType lasso_ecp_get_type(void);

LASSO_EXPORT LassoEcp* lasso_ecp_new(LassoServer *server);

LASSO_EXPORT lasso_error_t lasso_ecp_process_authn_request_msg(LassoEcp *ecp,
		const char *authn_request_msg);

LASSO_EXPORT lasso_error_t lasso_ecp_process_response_msg(LassoEcp *ecp,
		const char *response_msg);

LASSO_EXPORT void lasso_ecp_destroy(LassoEcp *ecp);

LASSO_EXPORT gboolean lasso_ecp_is_provider_in_sp_idplist(LassoEcp *ecp, const gchar *entity_id);

LASSO_EXPORT gboolean lasso_ecp_is_idp_entry_known_idp_supporting_ecp(LassoEcp *ecp, const LassoSamlp2IDPEntry *idp_entry);

LASSO_EXPORT void lasso_ecp_set_known_sp_provided_idp_entries_supporting_ecp(LassoEcp *ecp);

LASSO_EXPORT gboolean lasso_ecp_has_sp_idplist(LassoEcp *ecp);

LASSO_EXPORT gchar *lasso_ecp_get_endpoint_url_by_entity_id(LassoEcp *ecp, const gchar *entity_id);

LASSO_EXPORT int lasso_ecp_process_sp_idp_list(LassoEcp *ecp, const LassoSamlp2IDPList *sp_idp_list);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_ECP_H__ */
