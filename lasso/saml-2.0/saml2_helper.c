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

#include "./saml2_helper.h"

#include "../xml/saml-2.0/saml2_audience_restriction.h"
#include "../xml/saml-2.0/saml2_one_time_use.h"
#include "../xml/saml-2.0/saml2_proxy_restriction.h"
#include "../xml/saml-2.0/saml2_attribute.h"
#include "../xml/saml-2.0/saml2_attribute_statement.h"
#include "../xml/saml-2.0/saml2_attribute_value.h"
#include "../xml/private.h"
#include "../utils.h"
#include "./provider.h"
#include <time.h>

/**
 * lasso_saml2_assertion_has_audience_restriction:
 * @saml2_assertion: a #LassoSaml2Assertion object
 *
 * Verify that a #LassoSaml2AudienceRestriction is present in the assertion.
 *
 * Return value: TRUE if a #LassoSaml2AudienceRestriction is present in the Conditions of the
 * #LassoSaml2Assertion.
 */
gboolean
lasso_saml2_assertion_has_audience_restriction(LassoSaml2Assertion *saml2_assertion)
{
	GList *it;

	g_return_val_if_fail (LASSO_IS_SAML2_ASSERTION(saml2_assertion), FALSE);
	if (! LASSO_IS_SAML2_CONDITIONS(saml2_assertion->Conditions))
		return FALSE;

	lasso_foreach(it, saml2_assertion->Conditions->Condition)
	{
		if (LASSO_IS_SAML2_AUDIENCE_RESTRICTION(it->data)) {
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * lasso_saml2_assertion_is_audience_restricted:
 * @saml2_assertion: a #LassoSaml2Assertion object
 * @providerID: the providerID that will be compared to the audience restriction declarations.
 *
 * Verify that the assertion is restricted to the given providerID.
 *
 * Return value: TRUE if @providerID is part of a #LassoSaml2AudienceRestriction element in the
 * assertion, FALSE otherwise.
 */
gboolean
lasso_saml2_assertion_is_audience_restricted(LassoSaml2Assertion *saml2_assertion, char* providerID)
{
	GList *it;

	g_return_val_if_fail (LASSO_IS_SAML2_ASSERTION(saml2_assertion), FALSE);
	if (! LASSO_IS_SAML2_CONDITIONS(saml2_assertion->Conditions))
		return FALSE;
	lasso_foreach(it, saml2_assertion->Conditions->Condition)
	{
		if (LASSO_IS_SAML2_AUDIENCE_RESTRICTION(it->data)) {
			LassoSaml2AudienceRestriction *saml2_audience_restriction;
			saml2_audience_restriction = (LassoSaml2AudienceRestriction*)it->data;
			if (g_strcmp0(saml2_audience_restriction->Audience, providerID) == 0)
				return TRUE;
		}
	}
	return FALSE;
}

/**
 * lasso_saml2_name_id_build_persistent:
 * @id: the identifier for the princiapl
 * @idpID: the entity ID of the IdP
 * @providerID: the entity ID of the provider
 *
 * Create a new #LassoSaml2NameID object, which the #LASSO_SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT
 * format, @id as content, @idpID as NameQualifier and @providerID as SPNameQualifier.
 *
 * Return value: a newly created #LassoSaml2NameID
 */
LassoSaml2NameID*
lasso_saml2_name_id_build_persistent(const char *id, const char *idpID, const char *providerID)
{
	LassoSaml2NameID *saml2_name_id;

	saml2_name_id = (LassoSaml2NameID*)lasso_saml2_name_id_new();
	saml2_name_id->content = g_strdup(id);
	saml2_name_id->Format = g_strdup(LASSO_SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT);
	saml2_name_id->NameQualifier = g_strdup(idpID);
	saml2_name_id->SPNameQualifier = g_strdup(providerID);

	return saml2_name_id;
}

/**
 * lasso_saml2_name_id_build_encrypted_persistent
 * @id: the identifier for the principal
 * @idpID: the entity ID of the IdP
 * @provider: the provider for which the NameID is created.
 *
 * Create a new #LassoSaml2NameID issued by @idpID and targeted at @provider, and encrypt it using
 * @provider public key.
 *
 * Return value: a newly created #LassoSaml2EncryptedElement object.
 */
LassoSaml2EncryptedElement* lasso_saml2_encrypted_element_build_encrypted_persistent_name_id(
		const char *id, const char *idpID, const LassoProvider *provider)
{
	LassoSaml2NameID *saml2_name_id;
	LassoSaml2EncryptedElement *encrypted_element;

	saml2_name_id = lasso_saml2_name_id_build_persistent(id, idpID, provider->ProviderID);
	encrypted_element = lasso_provider_saml2_node_encrypt(provider, (LassoNode*)saml2_name_id);
	lasso_release_gobject(saml2_name_id);

	return encrypted_element;
}

static LassoSaml2Conditions*
lasso_saml2_assertion_get_conditions(LassoSaml2Assertion *saml2_assertion, gboolean create)
{
	if (! LASSO_IS_SAML2_CONDITIONS(saml2_assertion->Conditions) && create) {
		lasso_assign_new_gobject (saml2_assertion->Conditions,
				(LassoSaml2Conditions*)lasso_saml2_conditions_new());
	}
	return saml2_assertion->Conditions;
}

static LassoSaml2Subject*
lasso_saml2_assertion_get_subject(LassoSaml2Assertion *saml2_assertion, gboolean create)
{
	if (! LASSO_IS_SAML2_SUBJECT(saml2_assertion->Subject) && create) {
		lasso_assign_new_gobject(saml2_assertion->Subject,
				(LassoSaml2Subject*)lasso_saml2_subject_new());
	}
	return saml2_assertion->Subject;
}

static LassoSaml2SubjectConfirmation*
lasso_saml2_assertion_get_subject_confirmation(LassoSaml2Assertion *saml2_assertion, gboolean create)
{
	LassoSaml2Subject *subject;

	subject = lasso_saml2_assertion_get_subject (saml2_assertion, create);
	if (subject == NULL)
		return NULL;

	if (! LASSO_IS_SAML2_SUBJECT_CONFIRMATION(subject->SubjectConfirmation) && create) {
		lasso_assign_new_gobject(subject->SubjectConfirmation,
				(LassoSaml2SubjectConfirmation*)lasso_saml2_subject_confirmation_new());
	}

	return subject->SubjectConfirmation;
}

LassoSaml2SubjectConfirmationData*
lasso_saml2_assertion_get_subject_confirmation_data(LassoSaml2Assertion *saml2_assertion, gboolean create)
{
	LassoSaml2SubjectConfirmation *subject_confirmation;

	subject_confirmation = lasso_saml2_assertion_get_subject_confirmation (saml2_assertion, create);
	if (subject_confirmation == NULL)
		return NULL;

	if (! LASSO_IS_SAML2_SUBJECT_CONFIRMATION_DATA(subject_confirmation->SubjectConfirmationData) && create) {
		lasso_assign_new_gobject(subject_confirmation->SubjectConfirmationData,
				(LassoSaml2SubjectConfirmationData*)lasso_saml2_subject_confirmation_data_new());
	}

	return subject_confirmation->SubjectConfirmationData;
}

/**
 * lasso_saml2_assertion_set_subject_name_id:
 * @saml2_assertion: a #LassoSaml2Assertion object
 * @node: a #LassoSaml2NameID or #LassoSaml2EncryptedElement
 *
 * Set the subject NameID, which can be a simple #LassoSaml2NameID object or an encrypted
 * #LassoSaml2NameID as a #LassoSaml2EncryptedElement.
 */
void
lasso_saml2_assertion_set_subject_name_id(LassoSaml2Assertion *saml2_assertion, LassoNode *node)
{
	LassoSaml2Subject *saml2_subject;

	g_return_if_fail (LASSO_IS_SAML2_ASSERTION (saml2_assertion));

	saml2_subject = lasso_saml2_assertion_get_subject (saml2_assertion, TRUE);
	if (LASSO_IS_SAML2_NAME_ID(node)) {
		lasso_assign_gobject (saml2_subject->NameID, node);
	} else if (LASSO_IS_SAML2_ENCRYPTED_ELEMENT(node)) {
		lasso_assign_gobject(saml2_subject->EncryptedID, node)
	} else {
		g_warning("Cannot set subject name id, since node is neither an EncryptedElement or a NameID");
	}
}

/**
 * lasso_saml2_assertion_set_subject_confirmation_name_id:
 * @saml2_assertion: a #LassoSaml2Assertion object
 * @node: a #LassoSaml2NameID or #LassoSaml2EncryptedElement
 *
 * Set the subject NameID, which can be a simple #LassoSaml2NameID object or an encrypted
 * #LassoSaml2NameID as a #LassoSaml2EncryptedElement.
 */
void
lasso_saml2_assertion_set_subject_confirmation_name_id(LassoSaml2Assertion *saml2_assertion, LassoNode *node)
{
	LassoSaml2SubjectConfirmation *saml2_subject_confirmation;

	g_return_if_fail (LASSO_IS_SAML2_ASSERTION (saml2_assertion));

	saml2_subject_confirmation = lasso_saml2_assertion_get_subject_confirmation (saml2_assertion, TRUE);
	if (LASSO_IS_SAML2_NAME_ID(node)) {
		lasso_assign_gobject (saml2_subject_confirmation->NameID, node);
	} else if (LASSO_IS_SAML2_ENCRYPTED_ELEMENT(node)) {
		lasso_assign_gobject(saml2_subject_confirmation->EncryptedID, node)
	} else {
		g_warning("Cannot set subject name id, since node is neither an EncryptedElement or a NameID");
	}
}

#define set_notbefore_and_notonorafter(node, tolerance, length) \
	if (tolerance != -1 && length != -1) \
	{ \
		time_t now, a, b; \
		now = time(NULL); \
		a = now - tolerance; \
		b = now + length + tolerance; \
		lasso_assign_new_string (node->NotBefore, \
				lasso_time_to_iso_8601_gmt (a)); \
		lasso_assign_new_string (node->NotOnOrAfter, \
				lasso_time_to_iso_8601_gmt (b)); \
	}

/**
 * lasso_saml2_set_subject_confirmation_data:
 * @saml2_assertion: a #LassoSaml2Assertion object
 * @tolerance: tolerance to the range of time when the subject can be confirmed
 * @length: length of the range of time when the subject can be confirmed
 * @Recipient: the URL where the assertion can be consumed
 * @InResponseTo: the identifier of the request which resulted in this assertion
 * @Address: the address IP from which the subject should submit this assertion.
 *
 */
void
lasso_saml2_assertion_set_subject_confirmation_data(LassoSaml2Assertion *saml2_assertion,
		time_t tolerance, time_t length, const char *Recipient,
		const char *InResponseTo, const char *Address)
{
	LassoSaml2SubjectConfirmationData *saml2_subject_confirmation_data;

	g_return_if_fail(LASSO_IS_SAML2_ASSERTION (saml2_assertion));

	saml2_subject_confirmation_data = lasso_saml2_assertion_get_subject_confirmation_data (saml2_assertion, TRUE);
	set_notbefore_and_notonorafter (saml2_subject_confirmation_data, tolerance, length);
	lasso_assign_string (saml2_subject_confirmation_data->Recipient, Recipient);
	lasso_assign_string (saml2_subject_confirmation_data->InResponseTo, InResponseTo);
	lasso_assign_string (saml2_subject_confirmation_data->Address, Address);
}

/**
 * lasso_saml2_assertion_set_basic_conditions:
 * @tolerance:(default -1): tolerance to the range of time when the assertion is valid
 * @length:(default -1): length of the range of time when the assertion is valid
 * @one_time_use:(default FALSE): can the assertion be kept or should it be used immediately
 *
 * Set conditions limiting usage of the assertion.
 *
 * @tolerance and @length are time quantity measured in seconds, it defines the time range in which
 * the assertion is valid, it is computed as [now()-tolerance, now()+length+tolerance].
 * @one_time_use allows the issuer to limit caching of the assertion.
 * @proxy_count specify how many proxy hop can be traversed before this assertion should lose any trust.
 *
 */
void
lasso_saml2_assertion_set_basic_conditions(LassoSaml2Assertion *saml2_assertion, time_t tolerance,
		time_t length, gboolean one_time_use)
{
	LassoSaml2Conditions *saml2_conditions;

	g_return_if_fail (LASSO_IS_SAML2_ASSERTION (saml2_assertion));

	saml2_conditions = lasso_saml2_assertion_get_conditions (saml2_assertion, TRUE);
	set_notbefore_and_notonorafter (saml2_assertion->Conditions, tolerance, length);
	if (one_time_use) {
		lasso_list_add_new_gobject (saml2_conditions->OneTimeUse, lasso_saml2_one_time_use_new());
	}
}

/**
 * lasso_saml2_assertion_add_audience_restriction:
 * @saml2_assertion: a #LassoSaml2Assertion object
 * @providerId: the provider id to restrict audience to
 *
 * Add an audience restriction to a #LassoSaml2Assertion.
 *
 */
void
lasso_saml2_assertion_add_audience_restriction(LassoSaml2Assertion *saml2_assertion, const char *providerID)
{
	LassoSaml2AudienceRestriction *audience_restriction;
	LassoSaml2Conditions *conditions;

	g_return_if_fail (LASSO_IS_SAML2_ASSERTION(saml2_assertion));

	conditions = lasso_saml2_assertion_get_conditions (saml2_assertion, TRUE);
	audience_restriction = (LassoSaml2AudienceRestriction*)
			lasso_saml2_audience_restriction_new();
	lasso_assign_string(audience_restriction->Audience, providerID);
	lasso_list_add_new_gobject(conditions->AudienceRestriction, audience_restriction);
}

/**
 * lasso_saml2_assertion_add_proxy_limit:
 * @saml2_assertion: a #LassoSaml2Assertion object
 * @proxy_count:(default -1): the number of hops in the proxy chain, a negative value means no limitation
 * @proxy_audiences:(allow-none)(element-type string): a list of audience restriction for newly issued assertion
 * based on the @saml2_assertion assertion. An empty list means no audience restriction.
 *
 * A #LassoSaml2ProxyRestriction to the conditions of consumption of @saml2_assertion.
 */
void
lasso_saml2_assertion_add_proxy_limit (LassoSaml2Assertion *saml2_assertion, int proxy_count,
		GList *proxy_audiences)
{
	LassoSaml2Conditions *saml2_conditions;
	LassoSaml2ProxyRestriction *saml2_proxy_restriction;

	g_return_if_fail (LASSO_IS_SAML2_ASSERTION (saml2_assertion));
	saml2_conditions = lasso_saml2_assertion_get_conditions (saml2_assertion, TRUE);
	saml2_proxy_restriction = (LassoSaml2ProxyRestriction*)lasso_saml2_proxy_restriction_new ();
	if (proxy_count >= 0) {
		saml2_proxy_restriction->Count = g_strdup_printf("%i", proxy_count);
	}
	if (proxy_audiences) {
		lasso_assign_string (saml2_proxy_restriction->Audience, proxy_audiences->data);
		if (proxy_audiences->next) {
			g_warning ("Trying to set multiple proxy_audience restriction is not possible with currrent version of Lasso");
		}
	}
}

/**
 * lasso_saml2_validation_conditions:
 * @saml2_assertion: a #LassoSaml2Assertion object
 * @relaying_party_providerID:(allow-none): the providerID of the current relaying party, use to
 * check for audience restrictions.
 *
 * Check the validation of the assertion with respect to the conditions of consumption that it
 * contains. System functions are used for getting current time and checking eventual time
 * constraints.
 *
 * Return value: LASSO_SAML2_ASSERTION_VALID if the assertion is valid,
 * LASSO_SAML2_ASSERTION_INVALID is some check failed, LASSO_SAML2_ASSERTION_INDETERMINATE if
 * somehting was impossible to eveluate.
 */
LassoSaml2AssertionValidationState
lasso_saml2_assertion_validate_conditions(LassoSaml2Assertion *saml2_assertion, const char *relaying_party_providerID)
{
	/* FIXME: should allow to give a tolerance for date matching */
	LassoSaml2Conditions *saml2_conditions;
	time_t a, b, now;
	gboolean did_audience = FALSE;
	gboolean found_audience = FALSE;

	g_return_val_if_fail (LASSO_SAML2_ASSERTION (saml2_assertion), LASSO_SAML2_ASSERTION_INDETERMINATE);
	saml2_conditions = lasso_saml2_assertion_get_conditions(saml2_assertion, FALSE);

	if (saml2_conditions == NULL)
		return LASSO_SAML2_ASSERTION_VALID;

	now = time(NULL);

	if (saml2_conditions->NotBefore) {
		a = lasso_iso_8601_gmt_to_time_t (saml2_conditions->NotBefore);
		if (a == -1)
			return LASSO_SAML2_ASSERTION_INDETERMINATE;
		if (now < a) {
			return LASSO_SAML2_ASSERTION_INVALID;
		}
	}
	if (saml2_conditions->NotOnOrAfter) {
		b = lasso_iso_8601_gmt_to_time_t (saml2_conditions->NotOnOrAfter);
		if (b == -1)
			return LASSO_SAML2_ASSERTION_INDETERMINATE;
		if (now >= b) {
			return LASSO_SAML2_ASSERTION_INVALID;
		}
	}
	/* FIXME: treat other kinds of conditions when they appear */
	if (saml2_conditions->Condition) {
		return LASSO_SAML2_ASSERTION_INDETERMINATE;
	}
	lasso_foreach_full_begin (LassoSaml2AudienceRestriction*, saml2_audience_restriction, it,
			saml2_conditions->AudienceRestriction)
		did_audience = TRUE;
		if (g_strcmp0(saml2_audience_restriction->Audience, relaying_party_providerID)) {
			found_audience = TRUE;
		}
	lasso_foreach_full_end()
	if (did_audience ^ found_audience) {
		return LASSO_SAML2_ASSERTION_INVALID;
	}

	return LASSO_SAML2_ASSERTION_VALID;
}

/**
 * lasso_saml2_assertion_get_issuer_provider:
 * @saml2_assertion: a #LassoSaml2 assertion
 * @server: a #LassoServer object
 *
 * Return the #LassoProvider object for the provider who created this assertion.
 *
 * Return value: a #LassoProvider object, or NULL if the Issuer element is missing, or the given
 * provider unknown to the #LassoServer object.
 */
LassoProvider*
lasso_saml2_assertion_get_issuer_provider(const LassoSaml2Assertion *saml2_assertion, const LassoServer *server)
{
	LassoSaml2NameID *issuer;

	g_return_val_if_fail (LASSO_IS_SAML2_ASSERTION (saml2_assertion), NULL);
	issuer = saml2_assertion->Issuer;
	g_return_val_if_fail (LASSO_IS_SAML2_NAME_ID (issuer), NULL);
	g_return_val_if_fail (g_strcmp0(issuer->Format, LASSO_SAML2_NAME_IDENTIFIER_FORMAT_ENTITY) == 0, NULL);
	return lasso_server_get_provider (server, issuer->content);
}


/**
 * lasso_server_saml2_assertion_setup_signature:
 * @server: a #LassoServer object
 * @saml2_assertion: a #LassoSaml2Assertion object
 *
 * Configure signature on a saml2:Assertion element.
 *
 * Return value: 0 if successfull, an error code otherwise.
 */
int
lasso_server_saml2_assertion_setup_signature(LassoServer *server,
		LassoSaml2Assertion *saml2_assertion)
{
	lasso_bad_param(SERVER, server);
	lasso_bad_param(SAML2_ASSERTION, saml2_assertion);

	if (server->certificate) {
		saml2_assertion->sign_type = LASSO_SIGNATURE_TYPE_WITHX509;
	} else {
		saml2_assertion->sign_type = LASSO_SIGNATURE_TYPE_SIMPLE;
	}
	saml2_assertion->sign_method = server->signature_method;
	lasso_assign_string(saml2_assertion->private_key_file,
			server->private_key);
	lasso_assign_string(saml2_assertion->certificate_file,
			server->certificate);

	return 0;
}

/**
 * lasso_saml2_assertion_add_attribute_with_node:
 * @assertion: a #LassoSaml2Assertion object
 * @name: the attribute name
 * @name_format: the attribute name format (the namespace of the name)
 * @content: a #LassoNode object to put as content of the attribute
 *
 * Add a new attribute declaration and set this node as the content.
 *
 * Return value: 0 if successful, an error code otherwise.
 */
int
lasso_saml2_assertion_add_attribute_with_node(LassoSaml2Assertion *assertion, const char *name,
		const char *name_format, LassoNode *content)
{
	LassoSaml2AttributeValue *attribute_value = NULL;
	LassoSaml2Attribute *attribute = NULL;
	LassoSaml2AttributeStatement *attribute_statement = NULL;
	int rc = 0;

	lasso_bad_param(SAML2_ASSERTION, assertion);
	lasso_check_non_empty_string(name);
	lasso_check_non_empty_string(name_format);
	lasso_bad_param(NODE, content);

	attribute_value = lasso_saml2_attribute_value_new();
	lasso_list_add_gobject(attribute_value->any, content);

	attribute = LASSO_SAML2_ATTRIBUTE(lasso_saml2_attribute_new());
	lasso_assign_string(attribute->Name, name);
	lasso_assign_string(attribute->NameFormat, LASSO_SAML2_ATTRIBUTE_NAME_FORMAT_URI);
	lasso_list_add_new_gobject(attribute->AttributeValue, attribute_value);

	attribute_statement = LASSO_SAML2_ATTRIBUTE_STATEMENT(lasso_saml2_attribute_statement_new());
	lasso_list_add_new_gobject(attribute_statement->Attribute, attribute);

	lasso_list_add_new_gobject(assertion->AttributeStatement, attribute_statement);
cleanup:
	return rc;
}
