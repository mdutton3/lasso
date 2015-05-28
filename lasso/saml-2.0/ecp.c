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

/*
 * SAML2 Profile for ECP (Section 4.2) defines these steps for an ECP
 * transaction
 *
 * 1. ECP issues HTTP Request to SP
 * 2. SP issues <AuthnRequest> to ECP using PAOS
 * 3. ECP determines IdP
 * 4. ECP conveys <AuthnRequest> to IdP using SOAP
 * 5. IdP identifies principal
 * 6. IdP issues <Response> to ECP, targeted at SP using SOAP
 * 7. ECP conveys <Response> to SP using PAOS
 * 8. SP grants or denies access to principal
 */

/**
 * SECTION:ecp
 * @short_description: Enhanced Client or Proxy Profile (SAMLv2)
 *
 * # Introduction
 *
 * The #LassoEcp object is used to implement a SAMLv2 ECP client.
 * If you want to support ECP in a SP see [ecp-sp].
 * If you want to support ECP in a IdP see [ecp-idp].
 *
 * # ECP Operational Steps
 *
 * SAML2 Profile for ECP (Section 4.2) defines these steps for an ECP
 * transaction
 *
 * 1. ECP issues HTTP Request to SP
 * 2. SP issues &lt;samlp:AuthnRequest&gt; to ECP using PAOS
 * 3. ECP determines IdP
 * 4. ECP conveys &lt;samlp:AuthnRequest&gt; to IdP using SOAP
 * 5. IdP identifies principal
 * 6. IdP issues &lt;samlp:Response&gt; to ECP, targeted at SP using SOAP
 * 7. ECP conveys &lt;samlp:Response&gt; to SP using PAOS
 * 8. SP grants or denies access to principal
 *
 *
 *
 *
 **/

/**
 * SECTION:ecp-sp
 * @short_description: How to support ECP in an SP
 *
 *
 * |[<!-- language="C" -->
 * login = lasso_login_new(server);
 * ]|
 */

/**
 * SECTION:ecp-idp
 * @short_description: How to support ECP in an IdP
 *
 *
 * |[<!-- language="C" -->
 * login = lasso_login_new(server);
 * ]|
 */

#include "../xml/private.h"
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include "profileprivate.h"
#include "../id-ff/serverprivate.h"

#include "ecpprivate.h"

#include "ecp.h"
#include "../utils.h"

#include "../xml/soap-1.1/soap_envelope.h"
#include "../xml/soap-1.1/soap_header.h"
#include "../xml/soap-1.1/soap_body.h"
#include "../xml/soap-1.1/soap_fault.h"
#include "../xml/misc_text_node.h"
#include "../xml/paos_request.h"
#include "../xml/paos_response.h"
#include "../xml/ecp/ecp_request.h"
#include "../xml/ecp/ecp_response.h"
#include "../xml/ecp/ecp_relaystate.h"
#include "../xml/lib_authn_request.h"
#include "../xml/saml-2.0/samlp2_response.h"
#include "../xml/saml-2.0/samlp2_authn_request.h"

/*****************************************************************************/
/* Prototypes                                                                */
/*****************************************************************************/

static gboolean
is_provider_in_sp_idplist(GList *idp_list, const gchar *entity_id);

static gboolean
is_idp_entry_in_entity_id_list(GList *entity_id_list, const LassoSamlp2IDPEntry *idp_entry);

static GList *
intersect_sp_idplist_with_entity_id_list(GList *sp_provided_idp_entries, GList *known_idp_entity_ids_supporting_ecp);

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

/**
 * lasso_ecp_destroy:
 * @ecp: a #LassoEcp
 *
 * Destroys a #LassoEcp object
 *
 **/
void
lasso_ecp_destroy(LassoEcp *ecp)
{
	lasso_node_destroy(LASSO_NODE(ecp));
}

/**
 * lasso_ecp_is_provider_in_sp_idplist:
 * @ecp: a #LassoEcp
 * @entity_id: EntityID to check if member of #LassoEcp.IDPList
 *
 * Check to see if the provider with @entity_id is in the
 * ecp IDPList returned by the SP.
 *
 * Return value: TRUE if @entity_id is in #LassoEcp.IDPList, FALSE otherwise
 */
gboolean
lasso_ecp_is_provider_in_sp_idplist(LassoEcp *ecp, const gchar *entity_id) {
	return is_provider_in_sp_idplist(ecp->sp_idp_list->IDPEntry, entity_id);
}

/**
 * lasso_ecp_is_idp_entry_known_idp_supporting_ecp:
 * @ecp: a #LassoEcp
 * @idp_entry: #LassoSamlp2IDPEntry to check if member of @entity_id_list
 *
 * Check to see if the @idp_entry is in the @entity_id_list
 *
 *
 * Return value: TRUE if @entity_id is in @idp_list, FALSE otherwise
 */
gboolean
lasso_ecp_is_idp_entry_known_idp_supporting_ecp(LassoEcp *ecp, const LassoSamlp2IDPEntry *idp_entry) {
	return is_idp_entry_in_entity_id_list(ecp->known_idp_entity_ids_supporting_ecp, idp_entry);
}

/**
 * lasso_ecp_set_known_sp_provided_idp_entries_supporting_ecp:
 * @ecp: a #LassoEcp
 *
 * The SP may provide a list of #LassoSamlp2IDPEntry
 * (#LassoEcp.sp_idp_list) which it trusts. The ECP client
 * has a list of IDP EntityID's it knows supports ECP
 * (#LassoEcp.known_idp_entity_ids_supporting_ecp).  The set of
 * possible IDP's which can service the SP's authn request are the
 * interesection of these two lists (the IDP's the SP approves and
 * IDP's the ECP knows about). This find the common members between
 * the two lists and assign them to
 * #LassoEcp.known_sp_provided_idp_entries_supporting_ecp.
 */
void
lasso_ecp_set_known_sp_provided_idp_entries_supporting_ecp(LassoEcp *ecp)
{
	lasso_assign_new_list_of_strings(ecp->known_sp_provided_idp_entries_supporting_ecp,
		intersect_sp_idplist_with_entity_id_list(ecp->sp_idp_list ? ecp->sp_idp_list->IDPEntry : NULL,
												 ecp->known_idp_entity_ids_supporting_ecp));
}

/**
 * lasso_ecp_has_sp_idplist:
 * @ecp: a #LassoEcp
 *
 * Returns TRUE if the SP provided an IDP List, FALSE otherwise.
 */
gboolean
lasso_ecp_has_sp_idplist(LassoEcp *ecp)
{
	return ecp->sp_idp_list && ecp->sp_idp_list->IDPEntry != NULL;
}

/**
 * lasso_ecp_get_endpoint_url_by_entity_id:
 * @ecp: a #LassoEcp
 * @entity_id: the EntityID of the IdP
 *
 * Returns the SingleSignOnService SOAP endpoint URL for the specified
 * @entity_id. If the provider cannot be found or if the provider does
 * not have a matching endpoint NULL will be returned.
 *
 * Returns: url (must be freed by caller)
 */
gchar *
lasso_ecp_get_endpoint_url_by_entity_id(LassoEcp *ecp, const gchar *entity_id)
{
	LassoProfile *profile;

	profile = LASSO_PROFILE(ecp);

	return lasso_server_get_endpoint_url_by_id(profile->server, entity_id,
											   "SingleSignOnService SOAP");
}

/**
 * lasso_ecp_process_sp_idp_list:
 * @ecp: a #LassoEcp
 *
 * The SP may optionally send a list of IdP's it trusts in ecp:IDPList.
 * The ecp:IDPList may not be complete if the IDPList.GetComplete is
 * non-NULL. If so the IDPList.GetComplete is a URL where a complete
 * IDPList may be fetched.
 *
 * Whenever the IDPList is updated this function needs to be called
 * because it sets the
 * #LassoEcp.known_sp_provided_idp_entries_supporting_ecp and the
 * default IdP URL (#LassoProfile.msg_url).
 *
 * The #LassoEcp client has a list of IdP's it knows supports ECP
 * (#LassoEcp.known_idp_entity_ids_supporting_ecp). The set of IdP's
 * available to select from should be those in common between SP
 * provided IdP list and those known by this ECP client to support
 * ECP.
 *
 * This routine sets the
 * #LassoEcp.known_sp_provided_idp_entries_supporting_ecp list to the
 * common members (e.g. intersection) of the SP provided IdP list and
 * the list of known IdP's supporting ECP.
 *
 * A default IdP will be selected and it's endpoint URL will be
 * assigned to #LassoProfile.msg_url.
 *
 * If the SP provided an IDP list then the default URL will be taken
 * from first IDPEntry in
 * #LassoEcp.known_sp_provided_idp_entries_supporting_ecp otherwise
 * it will be taken from #LassoEcp.known_idp_entity_ids_supporting_ecp.
 *
 */
int
lasso_ecp_process_sp_idp_list(LassoEcp *ecp, const LassoSamlp2IDPList *sp_idp_list)
{
	int rc = 0;
	LassoProfile *profile;
	gchar *provider_id = NULL;
	gchar *url;

	profile = LASSO_PROFILE(ecp);

	lasso_assign_gobject(ecp->sp_idp_list, sp_idp_list);

	/* Build a list of IdP's which are common between the SP and those we know support ECP */
	lasso_ecp_set_known_sp_provided_idp_entries_supporting_ecp(ecp);

	/* Select a default IdP */
	provider_id = NULL;
	if (lasso_ecp_has_sp_idplist(ecp)) {
		/* Select first IDP provided by SP that is in our IDP list */
		if (ecp->known_sp_provided_idp_entries_supporting_ecp) {
			provider_id = ((LassoSamlp2IDPEntry*)ecp->known_sp_provided_idp_entries_supporting_ecp->data)->ProviderID;
		}
	}
	if (!provider_id) {
		/* Select first IDP from our IDP list */
		if (ecp->known_idp_entity_ids_supporting_ecp) {
			provider_id = ecp->known_idp_entity_ids_supporting_ecp->data;
		}
	}

	/* If we have a default IdP assign it's ECP URL to the profile->msg_url */
	lasso_release_string(profile->msg_url)
	if (provider_id) {
		url = lasso_ecp_get_endpoint_url_by_entity_id(ecp, provider_id);
		lasso_assign_new_string(profile->msg_url, url);
	}
	return rc;
}

/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

/**
 * compare_idp_entry_to_entity_id:
 *
 * Helper function for is_provider_in_sp_idplist().
 */
static gboolean
compare_idp_entry_to_entity_id(gconstpointer a, gconstpointer b)
{
	const LassoSamlp2IDPEntry *idp_entry = LASSO_SAMLP2_IDP_ENTRY(a);
	const gchar *entity_id = b;

	return g_strcmp0(idp_entry->ProviderID, entity_id);
}

/**
 * is_provider_in_sp_idplist:
 * @idp_list: GList of LassoSamlp2IDPEntry
 * @entity_id: EntityID to check if member of @idp_list
 *
 * Check if the provider with @entity_id is in the #idp_list.
 *
 * Return value: TRUE if @entity_id is in @idp_list, FALSE otherwise
 */
static gboolean
is_provider_in_sp_idplist(GList *idp_list, const gchar *entity_id) {
	return g_list_find_custom(idp_list, entity_id, compare_idp_entry_to_entity_id) == NULL ? FALSE : TRUE;
}

/**
 * compare_entity_id_to_idp_entry:
 *
 * Helper function for is_idp_entry_in_entity_id_list().
 */
static gboolean
compare_entity_id_to_idp_entry(gconstpointer a, gconstpointer b)
{
	const gchar *entity_id = a;
	const LassoSamlp2IDPEntry *idp_entry = LASSO_SAMLP2_IDP_ENTRY(b);

	return g_strcmp0(entity_id, idp_entry->ProviderID);
}

/**
 * is_idp_entry_in_entity_id_list:
 * @entity_id_list: #GList of entity id's
 * @idp_entry: #LassoSamlp2IDPEntry to check if member of @entity_id_list
 *
 * Check if the provider with @entity_id is in the #idp_list.
 *
 * Return value: TRUE if @entity_id is in @idp_list, FALSE otherwise
 */
static gboolean
is_idp_entry_in_entity_id_list(GList *entity_id_list, const LassoSamlp2IDPEntry *idp_entry) {
	return g_list_find_custom(entity_id_list, idp_entry, compare_entity_id_to_idp_entry) == NULL ? FALSE : TRUE;
}

/*
 * intersect_sp_idplist_with_entity_id_list:
 * @sp_provided_idp_entries: #GList of #LassoSamlp2IDPEntry
 * @known_idp_entity_ids_supporting_ecp: #GList of entity id's
 *
 * The SP may provide a list of #LassoSamlp2IDPEntry which it
 * trusts. The ECP client has a list of IDP EntityID's it knows
 * supports ECP.  The set of possible IDP's which can service the SP's
 * authn request are the interesection of these two lists (the IDP's
 * the SP approves and IDP's the ECP knows about). This function
 * accepts the SP's IDPEntry list and returns a new list containing
 * only those the ECP client knows about. The returned list must be
 * freed with lasso_release_list_of_gobjects().
 *
 * Return value: GList of #LassoSamlp2IDPEntry
 * (caller must free with lasso_release_list_of_gobjects())
 */
static GList *
intersect_sp_idplist_with_entity_id_list(GList *sp_provided_idp_entries, GList *known_idp_entity_ids_supporting_ecp)
{
	GList *i;
	GList *new_list = NULL;

	lasso_foreach(i, sp_provided_idp_entries) {
		LassoSamlp2IDPEntry *idp_entry = i->data;
		if (is_idp_entry_in_entity_id_list(known_idp_entity_ids_supporting_ecp, idp_entry)) {
			lasso_list_add_gobject(new_list, idp_entry);
		}
	}
	return new_list;
}

/*****************************************************************************/
/* overridden parent class methods                                           */
/*****************************************************************************/

static void
dispose(GObject *object)
{
	LassoEcp *ecp = LASSO_ECP(object);

	if (ecp->private_data->dispose_has_run) {
		return;
	}
	ecp->private_data->dispose_has_run = TRUE;

	lasso_release_string(ecp->assertion_consumer_url);
	lasso_release_string(ecp->message_id);
	lasso_release_string(ecp->response_consumer_url);
	lasso_release_string(ecp->relaystate);
	lasso_release_gobject(ecp->issuer);
	lasso_release_string(ecp->provider_name);
	lasso_release_gobject(ecp->sp_idp_list);
	lasso_release_list_of_gobjects(ecp->known_sp_provided_idp_entries_supporting_ecp);
	lasso_release_list_of_strings(ecp->known_idp_entity_ids_supporting_ecp);

	G_OBJECT_CLASS(parent_class)->dispose(G_OBJECT(ecp));
}

static void
finalize(GObject *object)
{
	LassoEcp *ecp = LASSO_ECP(object);
	lasso_release(ecp->private_data);

	G_OBJECT_CLASS(parent_class)->finalize(object);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoEcp *ecp)
{
	ecp->private_data = g_new0(LassoEcpPrivate, 1);
}

static void
class_init(LassoEcpClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);
	parent_class = g_type_class_peek_parent(klass);

	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "Ecp");
	lasso_node_class_set_ns(nclass, LASSO_LASSO_HREF, LASSO_LASSO_PREFIX);
	G_OBJECT_CLASS(klass)->dispose = dispose;
	G_OBJECT_CLASS(klass)->finalize = finalize;
}
/**
 * lasso_ecp_process_authn_request_msg:
 * @ecp: this #LassoEcp object
 * @authn_request_msg: the PAOS authn request received from the SP
 *
 * This function implements the following ECP step:
 * ECP Step 3, ECP determines IdP
 * ECP Step 4, parse SP PAOS Authn request, build SOAP for IdP
 *
 * This is to be used in an ECP client. The @authn_request_msg is the
 * SOAP PAOS message received from the SP in response to a resource
 * request with an HTTP Accept header indicating PAOS support.
 *
 * The following actions are implemented:
 *
 * * Extract the samlp:AuthnRequest from the SOAP body and build a
 *   new SOAP message containing the samlp:AuthnRequest which will
 *   be forwarded to the IdP. This new SOAP message is stored in the
 *   #LassoProfile.msg_body.
 *
 * * Parse the SOAP header which will contain a paos:Request, a
 *   ecp:Request and optionally a ecp:RelayState. Some of the data
 *   in these headers need to be preserved for later processing steps.
 *
 *   1. The paos:Request.responseConsumerURL is copied to the
 *      #LassoEcp.response_consumer_url. This is necessary because the
 *      ECP client MUST assure it matches the
 *      ecp:Response.AssertionConsumerServiceURL returned by the IdP to
 *      prevent man-in-the-middle attacks. It must also match the
 *      samlp:AuthnRequest.AssertionConsumerServiceURL.
 *
 *   2. If the paos:Request contained a messageID it is copied to
 *      #LassoEcp.message_id so it can be returned in the subsequent
 *      paos:Response.refToMessageID. This allows a provider to
 *      correlate messages.
 *
 *   3. If an ecp:RelayState is present it is copied to
 *      #LassoEcp.relaystate. This is necessary because in step 7 when
 *      the ECP responds to the SP it must include RelayState provided in
 *      the request.
 *
 * * In addition the following items are copied to the #LassoEcp for
 *   informational purposes:
 *
 *   * #LassoEcp.issuer = ecp:Request.Issuer
 *
 *   * #LassoEcp.provider_name = ecp:Request.ProviderName
 *
 *   * #LassoEcp.is_passive = ecp:Request.IsPassive
 *
 *   * #LassoEcp.sp_idp_list = ecp:Request.IDPList
 *
 * # IdP Selection
 *
 * In Step 3. The ECP must determine the IdP to forward the
 * AuthnRequest to. There are two sets of IdP's which come into
 * play. The ECP client has a set of IdP's it knows about because
 * their metadata has been loaded into the #LassoServer object. The SP
 * may optionally send a list of IdP's in the ecp:Request that it
 * trusts.
 *
 * The selected IdP *must* be one of the IdP's loaded into the
 * #LassoServer object from metadata because the IdP endpoints must be
 * known. Furthermore the IdP *must* support the SingleSignOnService
 * using the SOAP binding. Therefore the known IdP's are filtered for
 * those that match this criteria and a list of their EntityID's are
 * assigned to #LassoEcp.known_idp_entity_ids_supporting_ecp. The
 * selected IdP *must* be a member of this list.
 *
 * The SP may optionally send a list of IdP's it trusts. If the SP
 * sends an IDPList the selected IdP should be a member of this list
 * and from above we know it must also be a member of the
 * #LassoEcp.known_idp_entity_ids_supporting_ecp. Therefore the
 * #LassoEcp.known_sp_provided_idp_entries_supporting_ecp list is set
 * to the common members (e.g. intersection) of the SP provided IdP
 * list and the list of known IdP's supporting ECP.
 *
 * When making an IdP selection if the SP provided an IdP List (use
 * #LassoEcp.lasso_ecp_has_sp_idplist()) then it should be selected
 * from the #LassoEcp.known_sp_provided_idp_entries_supporting_ecp
 * list. Otherwise the IdP should be selected from
 * #LassoEcp.known_idp_entity_ids_supporting_ecp.
 *
 * A default IdP will be selected using the above logic by picking the
 * first IdP in the appropriate list, it's endpoint URL will be
 * assigned to #LassoProfile.msg_url. The above processing is
 * implemented by #LassoEcp.lasso_ecp_process_sp_idp_list() and if the
 * SP IDPList is updated this routine should be called.
 *
 * A note about the 3 IdP lists. The #LassoEcp.sp_idp_list.IDPList
 * and #LassoEcp.known_sp_provided_idp_entries_supporting_ecp are
 * #GList's of #LassoSamlp2IDPEntry object which have a ProviderID,
 * Name, and Loc attribute. You may wish to use this SP provided
 * information when making a decision or presenting in a user
 * interface that allows a user to make a choice. The
 * #LassoEcp.known_idp_entity_ids_supporting_ecp is a #GList of
 * EntityID strings.
 *
 * Given the EntityID of an IdP you can get the ECP endpoint by
 * calling #LassoEcp.lasso_ecp_get_endpoint_url_by_entity_id()
 *
 * # Results
 *
 * After a successful return from this call you are ready to complete
 * Step 4. and forward the request the IdP.
 *
 * The URL to send to the request to will be #LassoProfile.msg_url (if
 * you accept the default IdP) and the body of the message to post
 * will be #LassoProfile.msg_body.
 *
 *
 * # Side Effects
 *
 * After a successful return the #LassoEcp object will be updated with:
 *
 * * ecp->response_consumer_url = paos_request->responseConsumerURL
 * * ecp->message_id = paos_request->messageID
 * * ecp->relaystate = ecp_relaystate->RelayState
 * * ecp->issuer = ecp_request->Issue
 * * ecp->provider_name = ecp_request->ProviderName
 * * ecp->is_passive = ecp_request->IsPassive
 * * ecp->known_idp_entity_ids_supporting_ecp
 * * ecp->sp_idp_list = ecp_request->IDPList
 * * ecp->known_sp_provided_idp_entries_supporting_ecp
 *
 */
int
lasso_ecp_process_authn_request_msg(LassoEcp *ecp, const char *authn_request_msg)
{
	int rc = 0;
	LassoSoapEnvelope *envelope = NULL;
	LassoSoapHeader *header = NULL;
	LassoSoapBody *body = NULL;
	LassoPaosRequest *paos_request = NULL;
	LassoEcpRequest *ecp_request = NULL;
	LassoEcpRelayState *ecp_relaystate = NULL;
	LassoSamlp2AuthnRequest *authn_request = NULL;
	GList *i;
	LassoProfile *profile;

	g_return_val_if_fail(LASSO_IS_ECP(ecp), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(authn_request_msg != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	profile = LASSO_PROFILE(ecp);

	/* Get the SOAP envelope */
	lasso_extract_node_or_fail(envelope, lasso_soap_envelope_new_from_message(authn_request_msg),
							   SOAP_ENVELOPE, LASSO_PROFILE_ERROR_INVALID_SOAP_MSG);

	/* Get the SOAP body */
	lasso_extract_node_or_fail(body, envelope->Body, SOAP_BODY,
							   LASSO_SOAP_ERROR_MISSING_BODY);
	goto_cleanup_if_fail_with_rc(body->any && LASSO_IS_NODE(body->any->data),
								 LASSO_SOAP_ERROR_MISSING_BODY);
	lasso_extract_node_or_fail(authn_request, body->any->data, SAMLP2_AUTHN_REQUEST,
							   LASSO_ECP_ERROR_MISSING_AUTHN_REQUEST);

	/* Get the SOAP header */
	lasso_extract_node_or_fail(header, envelope->Header, SOAP_HEADER,
							   LASSO_SOAP_ERROR_MISSING_HEADER);
	goto_cleanup_if_fail_with_rc(header->Other && LASSO_IS_NODE(header->Other->data),
								 LASSO_SOAP_ERROR_MISSING_HEADER);

	/*
	 * Get the following header elements:
	 *   * paos:Request (required)
	 *   * ecp:Request (required)
	 *   * ecp:RelayState (optional)
	 */
	lasso_foreach(i, header->Other) {
		if (!paos_request && LASSO_IS_PAOS_REQUEST(i->data)) {
			paos_request = (LassoPaosRequest *)i->data;
		} else if (!ecp_request && LASSO_IS_ECP_REQUEST(i->data)) {
			ecp_request = (LassoEcpRequest *)i->data;
		} else if (!ecp_relaystate && LASSO_IS_ECP_RELAYSTATE(i->data)) {
			ecp_relaystate = (LassoEcpRelayState *)i->data;
		}

		if (ecp_relaystate && ecp_request && paos_request) break;
	}

	goto_cleanup_if_fail_with_rc(paos_request, LASSO_PAOS_ERROR_MISSING_REQUEST);
	goto_cleanup_if_fail_with_rc(ecp_request, LASSO_ECP_ERROR_MISSING_REQUEST);

    /* Copy data for later use */
	if (paos_request->responseConsumerURL) {
		lasso_assign_string(ecp->response_consumer_url, paos_request->responseConsumerURL);
	} else {
		goto_cleanup_with_rc(LASSO_PAOS_ERROR_MISSING_RESPONSE_CONSUMER_URL);
	}

	if (paos_request->messageID) {
		lasso_assign_string(ecp->message_id, paos_request->messageID);
	}

	if (ecp_relaystate) {
		lasso_assign_string(ecp->relaystate, ecp_relaystate->RelayState);
	}

	lasso_assign_gobject(ecp->issuer, ecp_request->Issuer);
	lasso_assign_string(ecp->provider_name, ecp_request->ProviderName);
	ecp->is_passive = ecp_request->IsPassive;

	/*
	 * Build a SOAP envelope whose body contains the original
	 * AuthnRequest received from the SP. The obvious solution is to
	 * serialize into XML the LassoSamlp2AuthnRequest LassoNode that
	 * was serialized from XML when we parsed the PAOS request
	 * (e.g. lasso_node_export_to_soap(LASSO_NODE(authn_request))) but
	 * that won't work because XML serialization is not symmetric.
	 * Serializing from XML into a LassoNode and then serializing the
	 * LassoNode back into XML does not produce the originial XML
	 * content. This is mostly due to the presence of signatures. In
	 * order to forward the *exact* same XML AuthnRequest we received
	 * from the SP to the IdP we mark the LassoSamlp2AuthnRequest with
	 * a flag indicating it's xmlNode needs to be preserved
	 * (e.g. keep_xmlnode = TRUE). We copy the xmlNode into a special
	 * LassoNode (LassoMiscTextNode) which is capable of preserving
	 * the exact xmlNode thus insuring no modification was made to the
	 * content.
     *
     * We assign the SOAP message to the profile->msg_body so it's
     * available for transmitting to the IdP.
     */

	{
		xmlNodePtr xml;
		LassoMiscTextNode *misc;

		xml = lasso_node_get_original_xmlnode(LASSO_NODE(authn_request));

		misc = lasso_misc_text_node_new_with_xml_node(xml);
		lasso_assign_new_string(LASSO_PROFILE(ecp)->msg_body,
								lasso_node_export_to_soap(LASSO_NODE(misc)));
		lasso_release_gobject(misc);
	}


	/* Set up for IdP selection, build IdP lists, make default IdP choice */

	/* Filter our server's list of IdP's to only include those that support ECP */
	ecp->known_idp_entity_ids_supporting_ecp = lasso_server_get_filtered_provider_list(
		profile->server, LASSO_PROVIDER_ROLE_IDP, LASSO_MD_PROTOCOL_TYPE_SINGLE_SIGN_ON,
		LASSO_HTTP_METHOD_SOAP);

	/* Update the IdP lists and select a default URL */
	lasso_ecp_process_sp_idp_list(ecp, ecp_request->IDPList);

 cleanup:
	lasso_release_gobject(envelope);

	return rc;
}

/**
 * lasso_ecp_process_response_msg:
 * @ecp: this #LassoEcp object
 * @response_msg: the SOAP response from the IdP
 *
 *
 * The function implements ECP Step 7; parse IdP SOAP response and
 * build PAOS response for SP.
 *
 * See SAML Profile Section 4.2.4.5 PAOS Response Header Block: ECP to SP
 *
 * This is to be used in an ECP client. The @response_msg parameter
 * contains the SOAP response from the IdP. We extract the ECP Header
 * Block and body from it. We will generate a new PAOS message to send
 * to the SP, the SOAP header will contain a paos:Response. If we
 * received a paos:Request.MessageID in Step. 4 from the SP then we
 * will copy it back to the paos:Response.refToMessageID. If we
 * received a RelayState we will add that to the SOAP header as well.
 *
 * To prevent a man-in-the-middle attack we verify the
 * responseConsumerURL we received in Step 4 matches the
 * ecp:Response.AssertionConsumerServiceURL we just received back from
 * the IdP. If they do not match we return a
 * #LASSO_ECP_ERROR_ASSERTION_CONSUMER_URL_MISMATCH error and set the
 * #LassoProvider.msg_body to the appropriate SOAP fault.
 *
 * The new PAOS message for the SP we are buiding contains the IdP
 * response in the new SOAP body and the new SOAP headers will contain
 * a paso:Response and optionally an ecp:RelayState.
 *
 * After a successful return from this call you are ready to complete
 * Step 7. and forward the response to the SP.
 *
 * The PASO message is assigned to the #LassoProvider.msg_body and
 * the desination URL is assigned to the #LassoProvider.msg_url.
 *
 * # Side Effects
 *
 * After a successful return the #LassoEcp object will be updated with:
 *
 * * ecp->assertion_consumer_url = ecp_response->AssertionConsumerServiceURL
 * * ecp.profile.msg_url = ecp->assertion_consumer_url
 * * ecp.profile.msg_body_url = PAOS response to SP
 */
int
lasso_ecp_process_response_msg(LassoEcp *ecp, const char *response_msg)
{
	int rc = 0;
	LassoSoapEnvelope *envelope = NULL;
	LassoSoapHeader *header = NULL;
	LassoSoapBody *body = NULL;
	LassoPaosResponse *paos_response = NULL;
	LassoEcpResponse *ecp_response = NULL;
	LassoEcpRelayState *ecp_relaystate = NULL;
	LassoSamlp2Response *samlp2_response = NULL;
	GList *i;
	GList *headers = NULL;

	g_return_val_if_fail(LASSO_IS_ECP(ecp), LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ);
	g_return_val_if_fail(response_msg != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	/* Get the SOAP envelope */
	lasso_extract_node_or_fail(envelope, lasso_soap_envelope_new_from_message(response_msg),
							   SOAP_ENVELOPE, LASSO_PROFILE_ERROR_INVALID_SOAP_MSG);

	/* Get the SOAP body */
	lasso_extract_node_or_fail(body, envelope->Body, SOAP_BODY,
							   LASSO_SOAP_ERROR_MISSING_BODY);
	goto_cleanup_if_fail_with_rc(body->any && LASSO_IS_NODE(body->any->data),
								 LASSO_SOAP_ERROR_MISSING_BODY);
	lasso_extract_node_or_fail(samlp2_response, body->any->data, SAMLP2_RESPONSE,
							   LASSO_ECP_ERROR_MISSING_SAML_RESPONSE);

	/* Get the SOAP header */
	lasso_extract_node_or_fail(header, envelope->Header, SOAP_HEADER,
							   LASSO_SOAP_ERROR_MISSING_HEADER);
	goto_cleanup_if_fail_with_rc(header->Other && LASSO_IS_NODE(header->Other->data),
								 LASSO_SOAP_ERROR_MISSING_HEADER);

	/*
	 * Get the following header elements:
	 *   * ecp:Response (required)
	 */
	lasso_foreach(i, header->Other) {
		if (!ecp_response && LASSO_IS_ECP_RESPONSE(i->data)) {
			ecp_response = (LassoEcpResponse *)i->data;
		}

		if (ecp_response) break;
	}

	goto_cleanup_if_fail_with_rc(ecp_response, LASSO_ECP_ERROR_MISSING_RESPONSE);

	lasso_assign_string(ecp->assertion_consumer_url, ecp_response->AssertionConsumerServiceURL);

	/*
	 * The ECP MUST confirm the ecp:Response
     * AssertionConsumerServiceURL corresponds to the paos:Request
     * responseConsumerURL. Since the responseConsumerServiceURL MAY
     * be relative and the AssertionConsumerServiceURL is absolute
     * some processing/normalization may be required.
     *
     * If the values do not match the ECP MUST generate a SOAP fault
     * and MUST not return the SAML response.
	 */

	if (lasso_strisnotequal(ecp->response_consumer_url, ecp_response->AssertionConsumerServiceURL)) {
		goto_cleanup_with_rc(LASSO_ECP_ERROR_ASSERTION_CONSUMER_URL_MISMATCH);
	}

	/* Generate SOAP headers */
	paos_response = LASSO_PAOS_RESPONSE(lasso_paos_response_new(ecp->message_id));
	lasso_list_add_new_gobject(headers, paos_response);
	if (ecp->relaystate) {
		ecp_relaystate = LASSO_ECP_RELAYSTATE(lasso_ecp_relay_state_new(ecp->relaystate));
		lasso_list_add_new_gobject(headers, ecp_relaystate);
	}

	/*
	 * Create a SOAP document and assign it to the LassoEcp->msg_body.
	 * See comment in lasso_ecp_process_authn_request_msg() where the
	 * profile->msg_body is assigned for an explanation of what is
	 * being done here.
	 */
	{
		xmlNodePtr xml;
		LassoMiscTextNode *misc;

		xml = lasso_node_get_original_xmlnode(LASSO_NODE(samlp2_response));

		misc = lasso_misc_text_node_new_with_xml_node(xml);

		lasso_assign_new_string(LASSO_PROFILE(ecp)->msg_body,
								lasso_node_export_to_soap_with_headers(LASSO_NODE(misc),
																	   headers));
		lasso_release_gobject(misc);
	}

	/* Set the destination URL for the the PAOS response */
	lasso_assign_string(LASSO_PROFILE(ecp)->msg_url, ecp->response_consumer_url);

 cleanup:
	if (rc) {
		LassoSoapFault *fault = NULL;

		fault = lasso_soap_fault_new_full(LASSO_SOAP_FAULT_CODE_CLIENT, lasso_strerror(rc));
		lasso_assign_new_string(LASSO_PROFILE(ecp)->msg_body, lasso_node_export_to_soap(LASSO_NODE(fault)));
	}

	lasso_release_list_of_gobjects(headers);
	lasso_release_gobject(envelope);

	return rc;
}

GType
lasso_ecp_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoEcpClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoEcp),
			0,
			(GInstanceInitFunc) instance_init,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_PROFILE,
				"LassoEcp", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_ecp_new
 *
 * Creates a new #LassoEcp.
 *
 * Return value: a newly created #LassoEcp object; or NULL if an error
 *     occured
 **/
LassoEcp*
lasso_ecp_new(LassoServer *server)
{
	LassoEcp *ecp;

	ecp = g_object_new(LASSO_TYPE_ECP, NULL);
	LASSO_PROFILE(ecp)->server = g_object_ref(server);

	return ecp;
}
