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

#include "saml2_login_private.h"
#include "identity.h"
#include "server.h"
#include "session.h"
#include "../id-ff/login.h"
#include "../xml/saml-2.0/saml2_assertion.h"
#include "../xml/ws/wsa_endpoint_reference.h"
#include "../xml/id-wsf-2.0/disco_svc_metadata.h"
#include "../xml/id-wsf-2.0/disco_abstract.h"
#include "../xml/id-wsf-2.0/disco_provider_id.h"
#include "../xml/id-wsf-2.0/disco_service_type.h"
#include "../xml/id-wsf-2.0/disco_service_context.h"
#include "../xml/id-wsf-2.0/disco_security_context.h"
#include "../xml/id-wsf-2.0/sec_token.h"
#include "../xml/saml-2.0/saml2_attribute.h"
#include "../xml/saml-2.0/saml2_attribute_statement.h"
#include "../xml/saml-2.0/saml2_attribute_value.h"
#include "../xml/saml-2.0/samlp2_response.h"

void
lasso_saml20_login_assertion_add_discovery(LassoLogin *login, LassoSaml2Assertion *assertion)
{
	GList *svcMDIDs;
	GList *svcMDs;
	LassoIdWsf2DiscoSvcMetadata *svcMD;
	LassoWsAddrEndpointReference *epr;
	LassoWsAddrMetadata *metadata;
	LassoSaml2AttributeStatement *attributeStatement;
	LassoSaml2Attribute *attribute;
	LassoSaml2AttributeValue *attributeValue;
	LassoIdWsf2DiscoSecurityContext *security_context;
	LassoIdWsf2SecToken *sec_token;
	LassoSaml2Assertion *assertion_identity_token;
	LassoIdWsf2DiscoServiceContext *service_context;
	LassoIdWsf2DiscoEndpointContext *endpoint_context;

	/* Get metadatas ids to which the user is associated */
	svcMDIDs = lasso_identity_get_svc_md_ids(LASSO_PROFILE(login)->identity);
	/* Get the metadatas of type discovery to which the user is associated */
	svcMDs = lasso_server_get_svc_metadatas_with_id_and_type(LASSO_PROFILE(login)->server,
		svcMDIDs, LASSO_IDWSF2_DISCO_HREF);
	if (svcMDs == NULL) {
		/* If the user hasn't been associated to any discovery metadatas, */
		/* get a default one */
		svcMDs = lasso_server_get_svc_metadatas_with_id_and_type(
			LASSO_PROFILE(login)->server, NULL, LASSO_IDWSF2_DISCO_HREF);
		if (svcMDs != NULL && LASSO_IS_IDWSF2_DISCO_SVC_METADATA(svcMDs->data)) {
			/* Then associate the user to these metadatas for later use */
			lasso_identity_add_svc_md_id(LASSO_PROFILE(login)->identity,
				LASSO_IDWSF2_DISCO_SVC_METADATA(svcMDs->data)->svcMDID);
		} else {
			return;
		}
	}

	/* FIXME : foreach on the whole list and build on epr for each svcMD */
	svcMD = svcMDs->data;

	/* Check the metadatas contain the infos needed to build an EPR */
	if (svcMD == NULL || svcMD->ServiceContext == NULL || svcMD->ServiceContext->data == NULL) {
		g_list_foreach(svcMDs, (GFunc)lasso_node_destroy, NULL);
		g_list_free(svcMDs);
		return;
	}

	/* Build EndpointReference */

	epr = lasso_wsa_endpoint_reference_new();
	service_context = svcMD->ServiceContext->data;
	endpoint_context = service_context->EndpointContext->data;

	epr->Address = lasso_wsa_attributed_uri_new_with_string(
		(gchar*)endpoint_context->Address->data);

	metadata = lasso_wsa_metadata_new();

	/* Abstract */
	metadata->any = g_list_append(metadata->any,
			lasso_idwsf2_disco_abstract_new_with_string(svcMD->Abstract));
	/* ProviderID */
	metadata->any = g_list_append(metadata->any,
			lasso_idwsf2_disco_provider_id_new_with_string(svcMD->ProviderID));
	/* ServiceType */
	metadata->any = g_list_append(metadata->any,
			lasso_idwsf2_disco_service_type_new_with_string(
				(char*)service_context->ServiceType->data));
	/* Framework */
	if (endpoint_context->Framework != NULL) {
		metadata->any = g_list_append(metadata->any,
			g_object_ref(endpoint_context->Framework->data));
	}

	/* Identity token */
	assertion_identity_token = LASSO_SAML2_ASSERTION(lasso_saml2_assertion_new());
	assertion_identity_token->Subject = g_object_ref(assertion->Subject);

	sec_token = lasso_idwsf2_sec_token_new();
	sec_token->any = LASSO_NODE(assertion_identity_token);

	security_context = lasso_idwsf2_disco_security_context_new();
	security_context->SecurityMechID = g_list_append(
		security_context->SecurityMechID, g_strdup(LASSO_SECURITY_MECH_TLS_BEARER));
	security_context->Token = g_list_append(security_context->Token, sec_token);

	metadata->any = g_list_append(metadata->any, security_context);

	/* End of metadata construction */
	epr->Metadata = metadata;

	/* Add the EPR to the assertion as a SAML attribute */
	attributeValue = lasso_saml2_attribute_value_new();
	attributeValue->any = g_list_append(attributeValue->any, epr);

	attribute = LASSO_SAML2_ATTRIBUTE(lasso_saml2_attribute_new());
	attribute->Name = g_strdup(LASSO_SAML2_ATTRIBUTE_NAME_EPR);
	attribute->NameFormat = g_strdup(LASSO_SAML2_ATTRIBUTE_NAME_FORMAT_URI);
	attribute->AttributeValue = g_list_append(attribute->AttributeValue, attributeValue);

	attributeStatement = LASSO_SAML2_ATTRIBUTE_STATEMENT(lasso_saml2_attribute_statement_new());
	attributeStatement->Attribute = g_list_append(attributeStatement->Attribute, attribute);

	assertion->AttributeStatement = g_list_append(assertion->AttributeStatement,
		attributeStatement);

	/* Free resources */
	g_list_foreach(svcMDs, (GFunc)lasso_node_destroy, NULL);
	g_list_free(svcMDs);
}

gint
lasso_saml20_login_copy_assertion_epr(LassoLogin *login)
{
	LassoProfile *profile = LASSO_PROFILE(login);
	LassoSession *session = profile->session;
	LassoSaml2Assertion *assertion;
	LassoSaml2AttributeStatement *attribute_statement;
	LassoSaml2Attribute *attribute;
	LassoSaml2AttributeValue *attribute_value;
	LassoWsAddrEndpointReference *epr;
	GList *i;

	g_return_val_if_fail(LASSO_IS_SESSION(session), LASSO_PROFILE_ERROR_SESSION_NOT_FOUND);

	assertion = LASSO_SAML2_ASSERTION(
		LASSO_SAMLP2_RESPONSE(profile->response)->Assertion->data);

	for (i = g_list_first(assertion->AttributeStatement); i; i = g_list_next(i)) {
		GList *j;
		attribute_statement = LASSO_SAML2_ATTRIBUTE_STATEMENT(i->data);
		if (attribute_statement == NULL) {
			continue;
		}

		for (j = g_list_first(attribute_statement->Attribute); j; j = g_list_next(j)) {
			GList *k;
			attribute = LASSO_SAML2_ATTRIBUTE(j->data);
			if (attribute == NULL || attribute->Name == NULL) {
				continue;
			}
			if (strcmp(attribute->Name, LASSO_SAML2_ATTRIBUTE_NAME_EPR) != 0) {
				continue;
			}
			for (k = g_list_first(attribute->AttributeValue); k; k = g_list_next(k)) {
				GList *l;
				attribute_value = LASSO_SAML2_ATTRIBUTE_VALUE(k->data);
				if (attribute_value == NULL) {
					continue;
				}
				for (l = g_list_first(attribute_value->any);
						l; l = g_list_next(l)) {
					if (LASSO_IS_WSA_ENDPOINT_REFERENCE(l->data)) {
						epr = LASSO_WSA_ENDPOINT_REFERENCE(l->data);
						lasso_session_add_endpoint_reference(session, epr);
						return 0;
					}
				}
			}
		}
	}

	return 0;
}
