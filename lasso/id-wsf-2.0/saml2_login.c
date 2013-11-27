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

#include "saml2_login.h"
#include "../xml/id-wsf-2.0/idwsf2_strings.h"
#include "identity.h"
#include "server.h"
#include "session.h"
#include "../id-ff/login.h"
#include "../saml-2.0/saml2_helper.h"
#include "../saml-2.0/provider.h"
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
#include "idwsf2_helper.h"
#include "../xml/private.h"


/**
 * lasso_server_create_assertion_as_idwsf2_security_token:
 * @server: a #LassoServer object
 * @name_id: a #LassoSaml2NameID object
 * @tolerance: tolerance around the normal duration which is accepted
 * @duration: life duration for this assertion in seconds
 * @cipher: whether to cipher the NameID
 * @audience:(allow-none)(optional): if @cipher is true, the provider for which to encrypt the NameID
 *
 * Create a new assertion usable as a security token in an ID-WSF 2.0 EndpointReference. See
 * lasso_saml2_assertion_set_basic_conditions() for detail about @tolerance and @duration.
 *
 * Return value:(transfer full)(allow-none): a newly allocated #LassoSaml2Assertion object, or NULL.
 */
LassoSaml2Assertion*
lasso_server_create_assertion_as_idwsf2_security_token(LassoServer *server,
		LassoSaml2NameID *name_id,
		int tolerance,
		int duration,
		gboolean cipher,
		LassoProvider *audience)
{
	LassoSaml2Assertion *assertion;
	int rc = 0;

	if (! LASSO_IS_SERVER(server))
		return NULL;
	if (! LASSO_IS_SAML2_NAME_ID(name_id))
		return NULL;
	if (cipher && ! LASSO_IS_PROVIDER(audience))
		return NULL;

	assertion = (LassoSaml2Assertion*)lasso_saml2_assertion_new();
	assertion->ID = lasso_build_unique_id(32);
	assertion->Issuer = (LassoSaml2NameID*)lasso_saml2_name_id_new_with_string(server->parent.ProviderID);
	assertion->Subject = (LassoSaml2Subject*)lasso_saml2_subject_new();
	if (cipher) {
		LassoSaml2EncryptedElement *encrypted_id =
			lasso_provider_saml2_node_encrypt(audience, (LassoNode*)name_id);
		if (! encrypted_id) {
			lasso_release_gobject(assertion);
			goto cleanup;
		}
		lasso_assign_new_gobject(assertion->Subject->EncryptedID, encrypted_id);
	} else {
		lasso_assign_new_gobject(assertion->Subject->NameID, name_id);
	}
	lasso_saml2_assertion_set_basic_conditions(assertion,
			tolerance, duration, FALSE);
	rc = lasso_server_saml2_assertion_setup_signature(server, assertion);
	if (rc != 0) {
		lasso_release_gobject(assertion);
	}
cleanup:
	return assertion;
}




/**
 * lasso_login_idwsf2_add_discovery_bootstrap_epr:
 * @login: a #LassoLogin object
 * @url: the Disco service address
 * @abstract: the Disco service description
 * @security_mechanisms:(allow-none)(element-type utf8): the list of supported security mechanisms
 * @tolerance:(default -1): see lasso_saml2_assertion_set_basic_conditions().
 * @duration:(default 0): see lasso_saml2_assertion_set_basic_conditions().
 *
 * Add the needed bootstrap attribute to the #LassoSaml2Assertion currently container in the
 * #LassoLogin object. This function should be called after lasso_login_build_assertion() by an IdP
 * also having the Discovery service role.
 *
 * The default @tolerance and @duration are respectively ten minutes and two days.
 *
 * Return value: 0 if successfull, otherwise #LASSO_PROFILE_ERROR_MISSING_ASSERTION if no assertion is present
 * in the #LassoLogin object, #LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ if login is not a #LassoLogin
 * object.
 */
int
lasso_login_idwsf2_add_discovery_bootstrap_epr(LassoLogin *login, const char *url,
		const char *abstract, GList *security_mechanisms, int tolerance, int duration)
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
	LassoSaml2NameID *name_id = NULL;
	int rc = 0;

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
		message(G_LOG_LEVEL_WARNING, "%s should only be called after lasso_login_build_assertion", __func__);
	}


	/* Build EndpointReference */
	epr = lasso_wsa_endpoint_reference_new_for_idwsf2_service(
			url, LASSO_IDWSF2_DISCOVERY_HREF, server->parent.ProviderID, abstract);

	/* Security/Identity token */
	if (duration <= 0) {
		duration = 2 * LASSO_DURATION_DAY;
	}
	if (tolerance < 0) {
		tolerance = 10*LASSO_DURATION_MINUTE;
	}
	/* If the NameID is encrypted try to get to he unencrypted one */
	if (assertion->Subject->NameID) {
		name_id = assertion->Subject->NameID;
	} else if (assertion->Subject->EncryptedID &&
			LASSO_IS_SAML2_NAME_ID(assertion->Subject->EncryptedID->original_data)) {
		name_id = (LassoSaml2NameID*)assertion->Subject->EncryptedID->original_data;
	}
	goto_cleanup_if_fail_with_rc (name_id, LASSO_PROFILE_ERROR_MISSING_NAME_IDENTIFIER);
	assertion_identity_token = lasso_server_create_assertion_as_idwsf2_security_token(server,
			name_id, tolerance, duration, TRUE, &server->parent);

	/* Add the assertion to the EPR */
	rc = lasso_wsa_endpoint_reference_add_security_token(epr,
			(LassoNode*)assertion_identity_token, security_mechanisms);
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
 * lasso_saml2_assertion_idwsf2_get_discovery_bootstrap_epr:
 * @assertion: a #LassoSaml2Assertion object
 *
 * Extract the Discovery bootstrap EPR from @assertion.
 *
 * Return value:(transfer none): a #LassoWsAddrEndpointReference or NULL if no bootstrap EPR is found.
 */
LassoWsAddrEndpointReference*
lasso_saml2_assertion_idwsf2_get_discovery_bootstrap_epr(LassoSaml2Assertion *assertion)
{
	LassoSaml2AttributeStatement *attribute_statement = NULL;
	LassoSaml2Attribute *attribute = NULL;
	LassoSaml2AttributeValue *attribute_value = NULL;
	GList *i = NULL, *j = NULL, *k = NULL;
	LassoWsAddrEndpointReference *rc = NULL;

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
			if (lasso_strisnotequal(attribute->Name,LASSO_SAML2_ATTRIBUTE_NAME_EPR))
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

/**
 * lasso_login_idwsf2_get_discovery_bootstrap_epr:
 * @login: a #LassoLogin object
 *
 * Extract the Discovery boostrap EPR from the attribute named #LASSO_SAML2_ATTRIBUTE_NAME_EPR.
 *
 * Return value:(transfer none): a caller owned #LassoWsAddrEndpointReference object, or NULL if none can be found.
 */
LassoWsAddrEndpointReference *
lasso_login_idwsf2_get_discovery_bootstrap_epr(LassoLogin *login)
{
	LassoProfile *profile = NULL;
	LassoSaml2Assertion *assertion = NULL;
	LassoWsAddrEndpointReference *rc = NULL;

	g_return_val_if_fail (LASSO_IS_LOGIN (login), NULL);
	profile = &login->parent;
	assertion = (LassoSaml2Assertion*)lasso_login_get_assertion(login);
	rc = lasso_saml2_assertion_idwsf2_get_discovery_bootstrap_epr(assertion);
	lasso_release_gobject(assertion);

	return rc;
}
