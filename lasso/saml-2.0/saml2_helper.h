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

#ifndef __LASSO_SAML20_SAML2_HELPER_H__
#define __LASSO_SAML20_SAML2_HELPER_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../export.h"

#include "../xml/saml-2.0/saml2_assertion.h"
#include "../xml/saml-2.0/saml2_name_id.h"
#include "../xml/saml-2.0/saml2_encrypted_element.h"
#include "../id-ff/provider.h"
#include "../id-ff/server.h"

typedef enum {
	LASSO_SAML2_ASSERTION_VALID,
	LASSO_SAML2_ASSERTION_INVALID,
	LASSO_SAML2_ASSERTION_INDETERMINATE
} LassoSaml2AssertionValidationState;

/**
 * LASSO_DURATION_MINUTE:
 *
 * Number of seconds in a minute.
 */
#define LASSO_DURATION_MINUTE 60
/**
 * LASSO_DURATION_HOUR:
 *
 * Number of seconds in a hour.
 */
#define LASSO_DURATION_HOUR 3600
/**
 * LASSO_DURATION_DAY:
 *
 * Number of seconds in a day.
 */
#define LASSO_DURATION_DAY 24*LASSO_DURATION_HOUR
/**
 * LASSO_DURATION_WEEK:
 *
 * Number of seconds in a week.
 */
#define LASSO_DURATION_WEEK 7*LASSO_DURATION_DAY

LASSO_EXPORT gboolean lasso_saml2_assertion_has_audience_restriction(
		LassoSaml2Assertion *saml2_assertion);

LASSO_EXPORT gboolean lasso_saml2_assertion_is_audience_restricted(
		LassoSaml2Assertion *saml2_assertion, char* providerID);

LASSO_EXPORT LassoSaml2NameID* lasso_saml2_name_id_build_persistent(const char *id,
		const char *idpID, const char *providerID);

LASSO_EXPORT LassoSaml2EncryptedElement*
	lasso_saml2_encrypted_element_build_encrypted_persistent_name_id(const char *id,
		const char *idpID, const LassoProvider *provider);

LASSO_EXPORT void lasso_saml2_assertion_set_subject_name_id(LassoSaml2Assertion *saml2_assertion,
		LassoNode *node);

LASSO_EXPORT void lasso_saml2_assertion_set_subject_confirmation_name_id(
		LassoSaml2Assertion *saml2_assertion, LassoNode *node);

LASSO_EXPORT void lasso_saml2_assertion_set_subject_confirmation_data(
		LassoSaml2Assertion *saml2_assertion, time_t tolerance, time_t length,
		const char *Recipient, const char *InResponseTo, const char *Address);

LASSO_EXPORT void lasso_saml2_assertion_set_basic_conditions(LassoSaml2Assertion *saml2_assertion,
		time_t tolerance, time_t length, gboolean one_time_use);

LASSO_EXPORT void lasso_saml2_assertion_add_audience_restriction(
		LassoSaml2Assertion *saml2_assertion, const char *providerID);

LASSO_EXPORT void lasso_saml2_assertion_add_proxy_limit (LassoSaml2Assertion *saml2_assertion,
		int proxy_count, GList *proxy_audiences);

LASSO_EXPORT LassoSaml2AssertionValidationState lasso_saml2_assertion_validate_conditions(
		LassoSaml2Assertion *saml2_assertion, const char *relaying_party_providerID);

LASSO_EXPORT LassoProvider* lasso_saml2_assertion_get_issuer_provider(
		const LassoSaml2Assertion *saml2_assertion, const LassoServer *server);

LASSO_EXPORT lasso_error_t lasso_server_saml2_assertion_setup_signature(LassoServer *server,
		LassoSaml2Assertion *saml2_assertion);

LASSO_EXPORT lasso_error_t lasso_saml2_assertion_add_attribute_with_node(LassoSaml2Assertion *assertion, const
		char *name, const char *nameformat, LassoNode *content);

LASSO_EXPORT LassoSaml2SubjectConfirmationData*
	lasso_saml2_assertion_get_subject_confirmation_data(LassoSaml2Assertion *saml2_assertion,
			gboolean create);

LASSO_EXPORT const char* lasso_saml2_assertion_get_in_response_to(LassoSaml2Assertion *assertion);

LASSO_EXPORT lasso_error_t lasso_saml2_encrypted_element_server_decrypt(
		LassoSaml2EncryptedElement* encrypted_element, LassoServer *server,
		LassoNode** decrypted_node);

LASSO_EXPORT lasso_error_t lasso_saml2_assertion_decrypt_subject(LassoSaml2Assertion *assertion,
		LassoServer *server);

LASSO_EXPORT LassoSaml2AssertionValidationState lasso_saml2_assertion_validate_time_checks(
		LassoSaml2Assertion *saml2_assertion,
		unsigned int tolerance,
		time_t now);

LASSO_EXPORT LassoSaml2AssertionValidationState lasso_saml2_assertion_validate_audience(
		LassoSaml2Assertion *saml2_assertion,
		const gchar *audience);

LASSO_EXPORT gboolean lasso_saml2_assertion_has_one_time_use(LassoSaml2Assertion *saml2_assertion);

LASSO_EXPORT LassoSaml2AssertionValidationState lasso_saml2_assertion_allows_proxying(
		LassoSaml2Assertion *saml2_assertion);

LASSO_EXPORT LassoSaml2AssertionValidationState lasso_saml2_assertion_allows_proxying_to(
		LassoSaml2Assertion *saml2_assertion, const char *audience);

LASSO_EXPORT void lasso_saml2_assertion_set_one_time_use(LassoSaml2Assertion *saml2_assertion,
		gboolean one_time_use);

LASSO_EXPORT LassoSaml2NameID* lasso_saml2_name_id_new_with_persistent_format(const char *id,
		const char *idpID, const char *providerID);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SAML20_SAML2_HELPER_H__ */
