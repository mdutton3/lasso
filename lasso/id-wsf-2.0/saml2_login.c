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

#include "./saml2_login.h"
#include "identity.h"
#include "server.h"
#include "session.h"
#include "../id-ff/login.h"
#include "../saml-2.0/saml2_helper.h"
#include "../xml/saml-2.0/saml2_assertion.h"
#include "../xml/ws/wsa_endpoint_reference.h"
#include "../xml/id-wsf-2.0/disco_abstract.h"
#include "../xml/id-wsf-2.0/disco_provider_id.h"
#include "../xml/id-wsf-2.0/disco_service_type.h"
#include "../xml/id-wsf-2.0/disco_service_context.h"
#include "../xml/id-wsf-2.0/disco_security_context.h"
#include "../xml/id-wsf-2.0/sec_token.h"
#include "../xml/id-wsf-2.0/sbf_framework.h"
#include "../id-wsf/wsf_utils.h"
#include "../xml/saml-2.0/saml2_attribute.h"
#include "../xml/saml-2.0/saml2_attribute_statement.h"
#include "../xml/saml-2.0/saml2_attribute_value.h"
#include "../xml/saml-2.0/samlp2_response.h"
#include "./idwsf2_helper.h"
#include "../xml/private.h"


/**
 * lasso_login_idwsf2_add_discovery_bootstrap_epr:
 * @login: a #LassoLogin object
 *
 * Add the needed bootstrap attribute to the #LassoSaml2Assertion currently container in the
 * #LassoLogin object. This function should be called after lasso_login_build_assertion() by an IdP
 * also having the Discovery service role.
 *
 * Return value: 0 if successfull, otherwise #LASSO_PROFILE_ERROR_MISSING_ASSERTION if no assertion is present
 * in the #LassoLogin object, #LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ if login is not a #LassoLogin
 * object.
 */
int
lasso_login_idwsf2_add_discovery_bootstrap_epr(LassoLogin *login, const char *url, const char *abstract, const char *security_mech_id)
{
	LassoWsAddrEndpointReference *epr = NULL;
	LassoWsAddrMetadata *metadata = NULL;
	LassoSaml2AttributeStatement *attributeStatement = NULL;
	LassoSaml2Attribute *attribute = NULL;
	LassoSaml2AttributeValue *attributeValue = NULL;
	LassoIdWsf2DiscoSecurityContext *security_context = NULL;
	LassoIdWsf2SecToken *sec_token = NULL;
	LassoSaml2Assertion *assertion_identity_token = NULL;
	LassoSaml2Assertion *assertion = NULL;
	LassoServer *server = NULL;
	int rc = 0;
	const char *security_mechanisms[] = { security_mech_id, NULL };

	lasso_bad_param(LOGIN, login);
	lasso_null_param(url);
	lasso_null_param(abstract);

	/* Check for the presence of an assertion */
	assertion = (LassoSaml2Assertion*) lasso_login_get_assertion (login);
	if (! LASSO_IS_SAML2_ASSERTION (assertion)) {
		lasso_release_gobject(assertion);
		return LASSO_PROFILE_ERROR_MISSING_ASSERTION;
	}
	lasso_extract_node_or_fail(server, login->parent.server, SERVER,
			LASSO_PROFILE_ERROR_MISSING_SERVER);
	/* Warn if the assertion is not a fresh one, we should not modify received assertion */
	if (lasso_node_get_original_xmlnode((LassoNode*)assertion) != NULL) {
		g_warning("%s should only be called after lasso_login_build_assertion", __func__);
	}


	/* Build EndpointReference */
	epr = lasso_wsa_endpoint_reference_new_for_idwsf2_service(
			url, LASSO_IDWSF2_DISCOVERY_HREF, server->parent.ProviderID, abstract);

	/* Security/Identity token */
	assertion_identity_token = LASSO_SAML2_ASSERTION(lasso_saml2_assertion_new());
	assertion_identity_token->ID = lasso_build_unique_id(32);
	assertion_identity_token->Issuer = (LassoSaml2NameID*)lasso_saml2_name_id_new_with_string(server->parent.ProviderID);
	lasso_assign_gobject(assertion_identity_token->Subject,
			assertion->Subject);
	lasso_saml2_assertion_set_basic_conditions(assertion_identity_token,
			5, 2*LASSO_DURATION_DAY, FALSE);

	/* Do we sign the assertion ? */
	if (lasso_security_mech_id_is_saml_authentication(security_mech_id) || lasso_security_mech_id_is_bearer_authentication(security_mech_id)) {
		lasso_check_good_rc(lasso_server_saml2_assertion_setup_signature(login->parent.server,
				assertion_identity_token));
	}

	rc = lasso_wsa_endpoint_reference_add_security_token(epr, (LassoNode*)assertion_identity_token, security_mechanisms);
	goto_cleanup_if_fail(rc == 0);

	/* Add the EPR to the assertion as a SAML attribute */
	rc = lasso_saml2_assertion_add_attribute_with_node(assertion,
		LASSO_SAML2_ATTRIBUTE_NAME_EPR, LASSO_SAML2_ATTRIBUTE_NAME_FORMAT_URI, (LassoNode*)epr);
	

cleanup:
	lasso_release_gobject(assertion);
	lasso_release_gobject(epr);
	lasso_release_gobject(metadata);
	lasso_release_gobject(attributeStatement);
	lasso_release_gobject(attribute);
	lasso_release_gobject(attributeValue);
	lasso_release_gobject(security_context);
	lasso_release_gobject(sec_token);
	lasso_release_gobject(assertion_identity_token);
	return rc;
}

/**
 * lasso_login_idwsf2_get_discovery_bootstrap_epr:
 * @login: a #LassoLogin object
 *
 * Extract the Discovery boostrap EPR from the attribute named #LASSO_SAML2_ATTRIBUTE_NAME_EPR.
 *
 * Return value: a caller owned #LassoWsAddrEndpointReference object, or NULL if none can be found.
 */
LassoWsAddrEndpointReference *
lasso_login_idwsf2_get_discovery_bootstrap_epr(LassoLogin *login)
{
	LassoProfile *profile = NULL;
	LassoSession *session = NULL;
	LassoSaml2Assertion *assertion = NULL;
	LassoSaml2AttributeStatement *attribute_statement = NULL;
	LassoSaml2Attribute *attribute = NULL;
	LassoSaml2AttributeValue *attribute_value = NULL;
	GList *i = NULL, *j = NULL, *k = NULL;
	LassoWsAddrEndpointReference *rc = NULL;

	g_return_val_if_fail (LASSO_IS_LOGIN (login), NULL);
	profile = &login->parent;
	lasso_extract_node_or_fail (session, profile->session, SESSION, NULL);
	assertion = (LassoSaml2Assertion*)lasso_login_get_assertion(login);
	if (! LASSO_IS_SAML2_ASSERTION (assertion)) {
		return NULL;
	}

	lasso_foreach (i, assertion->AttributeStatement)
	{
		if (! LASSO_IS_SAML2_ATTRIBUTE_STATEMENT (i->data))
			continue;

		attribute_statement = LASSO_SAML2_ATTRIBUTE_STATEMENT(i->data);

		lasso_foreach (j, attribute_statement->Attribute)
		{
			if (! LASSO_IS_SAML2_ATTRIBUTE(j->data))
				continue;

			attribute = LASSO_SAML2_ATTRIBUTE(j->data);
			if (g_strcmp0(attribute->Name, LASSO_SAML2_ATTRIBUTE_NAME_EPR) != 0)
				continue;
			/* There should only one attribute value, and the EPR should be the first
			 * contained node */
			if (! attribute->AttributeValue)
				continue;

			if (! LASSO_IS_SAML2_ATTRIBUTE_VALUE (attribute->AttributeValue->data))
				continue;
			attribute_value = (LassoSaml2AttributeValue*)attribute->AttributeValue->data;
			lasso_foreach (k, attribute_value->any) {
				if (! k->data) {
					message(G_LOG_LEVEL_CRITICAL, "found a NULL in attribute_value->any");
					break; /* NULL here ? bad... */
				}
				if (! LASSO_IS_WSA_ENDPOINT_REFERENCE (k->data))
					continue;
				rc = (LassoWsAddrEndpointReference*)g_object_ref(k->data);
				goto cleanup;
			}
		}
	}

cleanup:
	return rc;
}
