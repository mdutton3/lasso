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

#include "../xml/private.h"
#include "name_id_management.h"
#include "providerprivate.h"
#include "profileprivate.h"
#include "serverprivate.h"
#include "../id-ff/providerprivate.h"
#include "../id-ff/profileprivate.h"
#include "../id-ff/identityprivate.h"
#include "../id-ff/serverprivate.h"
#include "../xml/xml_enc.h"
#include "../utils.h"
#include "../xml/saml-2.0/samlp2_manage_name_id_request.h"
#include "../xml/misc_text_node.h"

/**
 * SECTION:name_id_management
 * @short_description: Name Id Management Profile (SAMLv2)
 *
 **/

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

/**
 * lasso_name_id_management_init_request:
 * @name_id_management: a #LassoNameIdManagement
 * @remote_provider_id: the providerID of the remote provider.
 * @new_name_id: the new NameId or NULL to terminate a federation
 * @http_method: if set, then it get the protocol profile in metadata
 *     corresponding of this HTTP request method.
 *
 * Initializes a new Name Id Management Request. If @new_name_id is NULL, it is a Termination
 * request, if not and we are an IdP is a NameID change request, if we are a SP, it is a request to
 * add a SP provided Id to the NameID of the IdP. It can be useful if the SP do not want to store
 * the federation, instead he can export its own identifiers to the IdP.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_name_id_management_init_request(LassoNameIdManagement *name_id_management,
		char *remote_provider_id,
		char *new_name_id,
		LassoHttpMethod http_method)
{
	LassoProfile *profile = NULL;
	LassoProvider *remote_provider;
	LassoSamlp2ManageNameIDRequest *manage_name_id_request = NULL;
	LassoSamlp2RequestAbstract *request = NULL;
	gboolean do_encrypt = FALSE;
	int rc = 0;

	lasso_bad_param(NAME_ID_MANAGEMENT, name_id_management);
	profile = LASSO_PROFILE(name_id_management);
	remote_provider = lasso_server_get_provider(profile->server, remote_provider_id);
	if (! LASSO_IS_PROVIDER(remote_provider)) {
		return LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND;
	}

	request = (LassoSamlp2RequestAbstract*)lasso_samlp2_manage_name_id_request_new();
	manage_name_id_request = LASSO_SAMLP2_MANAGE_NAME_ID_REQUEST(request);
	lasso_check_good_rc(lasso_saml20_profile_init_request(profile, remote_provider_id, TRUE, request,
				http_method, LASSO_MD_PROTOCOL_TYPE_MANAGE_NAME_ID));

	lasso_assign_gobject(manage_name_id_request->NameID, (LassoSaml2NameID*)profile->nameIdentifier);
	do_encrypt = (lasso_provider_get_encryption_mode(remote_provider) == LASSO_ENCRYPTION_MODE_NAMEID);

	if (do_encrypt) {
		/* Encrypt old nameid */
		lasso_check_good_rc(lasso_saml20_profile_setup_encrypted_node(remote_provider,
					(LassoNode**)&manage_name_id_request->NameID,
					(LassoNode**)&manage_name_id_request->EncryptedID));
	}

	if (new_name_id) {
		if (do_encrypt) {
			LassoMiscTextNode *text_node;
			text_node =
				(LassoMiscTextNode*)lasso_misc_text_node_new_with_string(new_name_id);
			text_node->name = "NewEncryptedID";
			text_node->ns_href = LASSO_SAML2_PROTOCOL_HREF;
			text_node->ns_prefix = LASSO_SAML2_PROTOCOL_PREFIX;
			lasso_check_good_rc(lasso_saml20_profile_setup_encrypted_node(remote_provider,
						(LassoNode**)&text_node,
						(LassoNode**)&manage_name_id_request->NewEncryptedID));
			lasso_release_string(manage_name_id_request->NewID);
		} else {
			lasso_assign_string(manage_name_id_request->NewID, new_name_id);
		}
	} else {
		lasso_assign_new_gobject(manage_name_id_request->Terminate,
				LASSO_SAMLP2_TERMINATE(lasso_samlp2_terminate_new()));
		/* if we are the IdP we can apply termination immediately. */
		if (profile->server->parent.role & LASSO_PROVIDER_ROLE_IDP) {
			lasso_identity_remove_federation(profile->identity,
					profile->remote_providerID);
		}
	}

cleanup:
	lasso_release_gobject(request);

	return 0;
}


/**
 * lasso_name_id_management_build_request_msg:
 * @name_id_management: a #LassoNameIdManagement
 *
 * Builds the Name Id Management request message.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_name_id_management_build_request_msg(LassoNameIdManagement *name_id_management)
{
	lasso_bad_param(NAME_ID_MANAGEMENT, name_id_management);

	return lasso_saml20_profile_build_request_msg(&name_id_management->parent, "ManageNameIDService", name_id_management->parent.http_request_method, NULL);
}


/**
 * lasso_name_id_management_process_request_msg:
 * @name_id_management: a #LassoNameIdManagement
 * @request_msg: the Name Id Management request message
 *
 * Processes a Name Id Management request message.  Rebuilds a request object
 * from the message and check its signature.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_name_id_management_process_request_msg(LassoNameIdManagement *name_id_management,
		char *request_msg)
{
	LassoProfile *profile = NULL;
	LassoSamlp2ManageNameIDRequest *request = NULL;
	int rc = 0;

	lasso_bad_param(NAME_ID_MANAGEMENT, name_id_management);
	lasso_null_param(request_msg);

	profile = LASSO_PROFILE(name_id_management);
	request = (LassoSamlp2ManageNameIDRequest*)lasso_samlp2_manage_name_id_request_new();
	lasso_check_good_rc(lasso_saml20_profile_process_any_request(profile,
			(LassoNode*)request,
			request_msg));
	lasso_check_good_rc(lasso_saml20_profile_process_name_identifier_decryption(profile,
			&request->NameID, &request->EncryptedID));
	lasso_check_good_rc(lasso_saml20_profile_check_signature_status(profile));

cleanup:
	lasso_release_gobject(request);
	return rc;
}


/**
 * lasso_name_id_management_validate_request:
 * @name_id_management: a #LassoNameIdManagement
 *
 * Processes a Name Id Management request, performing requested actions against
 * principal federations.  Profile identity may have to be saved afterwards.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
int
lasso_name_id_management_validate_request(LassoNameIdManagement *name_id_management)
{
	LassoProfile *profile = NULL;
	LassoProvider *remote_provider = NULL;
	LassoSamlp2StatusResponse *response = NULL;
	LassoSaml2NameID *name_id = NULL;
	LassoFederation *federation = NULL;
	int rc = 0;

	lasso_bad_param(NAME_ID_MANAGEMENT, name_id_management);
	profile = LASSO_PROFILE(name_id_management);

	response = (LassoSamlp2StatusResponse*)lasso_samlp2_manage_name_id_response_new();
	rc = lasso_saml20_profile_validate_request(profile, TRUE, response, &remote_provider);
	if (rc)
		goto cleanup;

	/* Get the federation */
	federation = lasso_identity_get_federation(profile->identity,
			remote_provider->ProviderID);
	if (LASSO_IS_FEDERATION(federation) == FALSE) {
		rc = critical_error(LASSO_PROFILE_ERROR_FEDERATION_NOT_FOUND);
		goto cleanup;
	}

	/* Get the name identifier */
	name_id = LASSO_SAMLP2_MANAGE_NAME_ID_REQUEST(profile->request)->NameID;
	if (! LASSO_IS_SAML2_NAME_ID(name_id)) {
		message(G_LOG_LEVEL_CRITICAL,
				"Name identifier not found in name id management request");
		lasso_saml20_profile_set_response_status_requester(
				profile,
				"MissingNameID");
		rc = LASSO_PROFILE_ERROR_NAME_IDENTIFIER_NOT_FOUND;
		goto cleanup;
	}

	/* Check it matches */
	if (! lasso_federation_verify_name_identifier(federation, (LassoNode*)name_id)) {
		lasso_saml20_profile_set_response_status_responder(
				profile,
				LASSO_SAML2_STATUS_CODE_UNKNOWN_PRINCIPAL);
		rc = LASSO_PROFILE_ERROR_FEDERATION_NOT_FOUND;
		goto cleanup;
	}

	/* Ok it matches, now apply modifications */
	if (LASSO_SAMLP2_MANAGE_NAME_ID_REQUEST(profile->request)->Terminate) {
		/* defederation */
		lasso_identity_remove_federation(profile->identity, remote_provider->ProviderID);
	} else {
		/* name registration */
		LassoSaml2NameID *new_name_id;

		new_name_id = LASSO_SAML2_NAME_ID(lasso_saml2_name_id_new());
		new_name_id->Format = g_strdup(name_id->Format);
		new_name_id->NameQualifier = g_strdup(name_id->NameQualifier);
		new_name_id->SPNameQualifier = g_strdup(name_id->SPNameQualifier);
		if (remote_provider->role == LASSO_PROVIDER_ROLE_SP) {
			/* if the requester is the service provider, the new
			 * identifier MUST appear in subsequent <NameID>
			 * elements in the SPProvidedID attribute
			 *  -- saml-core-2.0-os.pdf, page 58
			 */
			new_name_id->SPProvidedID = g_strdup(
				LASSO_SAMLP2_MANAGE_NAME_ID_REQUEST(profile->request)->NewID);
			new_name_id->content = g_strdup(name_id->content);
		} else {
			/* If the requester is the identity provider, the new
			 * value will appear in subsequent <NameID> elements as
			 * the element's content.
			 * -- saml-core-2.0-os.pdf, page 58
			 */
			new_name_id->content = g_strdup(
				LASSO_SAMLP2_MANAGE_NAME_ID_REQUEST(profile->request)->NewID);
		}
		/* Get federation */
		lasso_assign_gobject(federation->local_nameIdentifier, new_name_id);
		/* Set identity is_dirty */
		lasso_identity_add_federation(profile->identity, federation);
	}
cleanup:
	lasso_release_gobject(response);
	return rc;
}

/**
 * lasso_name_id_management_build_response_msg:
 * @name_id_management: a #LassoNameIdManagement
 *
 * Builds the Name Id Management response message.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
int
lasso_name_id_management_build_response_msg(LassoNameIdManagement *name_id_management)
{
	LassoProfile *profile = NULL;
	LassoSamlp2StatusResponse *response;
	int rc = 0;

	lasso_bad_param(NAME_ID_MANAGEMENT, name_id_management);
	profile = &name_id_management->parent;

	/* no response set here means request denied */
	if (! LASSO_IS_SAMLP2_STATUS_RESPONSE(profile->response)) {
		response = (LassoSamlp2StatusResponse*)lasso_samlp2_manage_name_id_response_new();
		if (lasso_saml20_profile_check_signature_status(profile)) {
			lasso_check_good_rc(lasso_saml20_profile_init_response(profile, response,
						LASSO_SAML2_STATUS_CODE_REQUESTER,
						LASSO_LIB_STATUS_CODE_INVALID_SIGNATURE));
		} else {
			lasso_check_good_rc(lasso_saml20_profile_init_response(profile, response,
						LASSO_SAML2_STATUS_CODE_RESPONDER,
						LASSO_SAML2_STATUS_CODE_REQUEST_DENIED));
		}
		lasso_release_gobject(response);
	}

	/* use the same binding as for the request */
	rc = lasso_saml20_profile_build_response_msg(profile, "ManageNameIDService", profile->http_request_method, NULL);
cleanup:
	return rc;
}


/**
 * lasso_name_id_management_process_response_msg:
 * @name_id_management: a #LassoNameIdManagement
 * @response_msg: the response message
 *
 * Parses the response message and builds the corresponding response object.
 * Performs requested actions against principal federations.  Profile identity
 * may have to be saved afterwards.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
gint
lasso_name_id_management_process_response_msg(
		LassoNameIdManagement *name_id_management,
		gchar *response_msg)
{
	LassoProfile *profile = NULL;
	LassoSamlp2StatusResponse *response = NULL;
	int rc = 0;

	lasso_bad_param(NAME_ID_MANAGEMENT, name_id_management);
	lasso_null_param(response_msg);

	profile = &name_id_management->parent;
	response = (LassoSamlp2StatusResponse*)lasso_samlp2_manage_name_id_response_new();
	lasso_check_good_rc(lasso_saml20_profile_process_any_response(profile, response, NULL, response_msg));

	/* Stop here if signature validation failed. */
	lasso_check_good_rc(lasso_saml20_profile_check_signature_status(profile));

	if (LASSO_SAMLP2_MANAGE_NAME_ID_REQUEST(profile->request)->Terminate) {
		lasso_identity_remove_federation(profile->identity, profile->remote_providerID);
	} else {
		LassoSaml2NameID *new_name_id, *name_id;
		LassoFederation *federation;

		name_id = LASSO_SAMLP2_MANAGE_NAME_ID_REQUEST(profile->request)->NameID;

		new_name_id = LASSO_SAML2_NAME_ID(lasso_saml2_name_id_new());
		new_name_id->Format = g_strdup(name_id->Format);
		new_name_id->NameQualifier = g_strdup(name_id->NameQualifier);
		new_name_id->SPNameQualifier = g_strdup(name_id->SPNameQualifier);
		if (LASSO_PROVIDER(profile->server)->role == LASSO_PROVIDER_ROLE_SP) {
			/* if the requester is the service provider, the new
			 * identifier MUST appear in subsequent <NameID>
			 * elements in the SPProvidedID attribute
			 *  -- saml-core-2.0-os.pdf, page 58
			 */
			new_name_id->SPProvidedID = g_strdup(
				LASSO_SAMLP2_MANAGE_NAME_ID_REQUEST(profile->request)->NewID);
			new_name_id->content = g_strdup(name_id->content);
		} else {
			/* If the requester is the identity provider, the new
			 * value will appear in subsequent <NameID> elements as
			 * the element's content.
			 * -- saml-core-2.0-os.pdf, page 58
			 */
			new_name_id->content = g_strdup(
				LASSO_SAMLP2_MANAGE_NAME_ID_REQUEST(profile->request)->NewID);
		}

		/* Get federation */
		federation = g_hash_table_lookup(profile->identity->federations,
				profile->remote_providerID);
		if (LASSO_IS_FEDERATION(federation) == FALSE) {
			return critical_error(LASSO_PROFILE_ERROR_FEDERATION_NOT_FOUND);
		}

		if (federation->local_nameIdentifier)
			lasso_node_destroy(LASSO_NODE(federation->local_nameIdentifier));
		federation->local_nameIdentifier = g_object_ref(new_name_id);
		profile->identity->is_dirty = TRUE;

	}


cleanup:
	lasso_release_gobject(response);
	return rc;
}


/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static struct XmlSnippet schema_snippets[] = {
	{NULL, 0, 0, NULL, NULL, NULL}
};

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node, gboolean lasso_dump)
{
	xmlNode *xmlnode;

	xmlnode = parent_class->get_xmlNode(node, lasso_dump);
	xmlNodeSetName(xmlnode, (xmlChar*)"NameIdManagement");
	xmlSetProp(xmlnode, (xmlChar*)"NameIdManagementDumpVersion", (xmlChar*)"1");

	return xmlnode;
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
class_init(LassoNameIdManagementClass *klass)
{
	LassoNodeClass *nclass = LASSO_NODE_CLASS(klass);

	parent_class = g_type_class_peek_parent(klass);
	nclass->get_xmlNode = get_xmlNode;
	nclass->node_data = g_new0(LassoNodeClassData, 1);
	lasso_node_class_set_nodename(nclass, "NameIdManagement");
	lasso_node_class_add_snippets(nclass, schema_snippets);
}



GType
lasso_name_id_management_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoNameIdManagementClass),
			NULL, NULL,
			(GClassInitFunc) class_init,
			NULL, NULL,
			sizeof(LassoNameIdManagement),
			0,
			NULL,
			NULL
		};

		this_type = g_type_register_static(LASSO_TYPE_PROFILE,
				"LassoNameIdManagement", &this_info, 0);
	}
	return this_type;
}

/**
 * lasso_name_id_management_new:
 * @server: the #LassoServer
 *
 * Creates a new #LassoNameIdManagement.
 *
 * Return value: a newly created #LassoNameIdManagement object; or NULL if an error
 *     occured
 **/
LassoNameIdManagement*
lasso_name_id_management_new(LassoServer *server)
{
	LassoNameIdManagement *name_id_management;

	g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);

	name_id_management = g_object_new(LASSO_TYPE_NAME_ID_MANAGEMENT, NULL);
	/* fresh object dont need to check previous value */
	LASSO_PROFILE(name_id_management)->server = g_object_ref(server);

	return name_id_management;
}

/**
 * lasso_name_id_management_destroy:
 * @name_id_management: a #LassoNameIdManagement
 *
 * Destroys a #LassoNameIdManagement object.
 **/
void
lasso_name_id_management_destroy(LassoNameIdManagement *name_id_management)
{
	lasso_node_destroy(LASSO_NODE(name_id_management));
}

/**
 * lasso_name_id_management_new_from_dump:
 * @server: the #LassoServer
 * @dump: XML name_id_management dump
 *
 * Restores the @dump to a new #LassoLogout.
 *
 * Return value: a newly created #LassoLogout; or NULL if an error occured
 **/
LassoNameIdManagement*
lasso_name_id_management_new_from_dump(LassoServer *server, const char *dump)
{
	LassoNameIdManagement *name_id_management;

	name_id_management = (LassoNameIdManagement*)lasso_node_new_from_dump(dump);

	if (LASSO_IS_NAME_ID_MANAGEMENT(name_id_management)) {
		lasso_assign_gobject(name_id_management->parent.server, server);
	} else {
		lasso_release_gobject(name_id_management);
	}
	return name_id_management;
}

/**
 * lasso_name_id_management_dump:
 * @name_id_management: a #LassoLogout
 *
 * Dumps @name_id_management content to an XML string.
 *
 * Return value:(transfer full): the dump string.  It must be freed by the caller.
 **/
gchar*
lasso_name_id_management_dump(LassoNameIdManagement *name_id_management)
{
	return lasso_node_dump(LASSO_NODE(name_id_management));
}
