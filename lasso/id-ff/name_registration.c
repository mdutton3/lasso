/* $Id$
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Nicolas Clapies <nclapies@entrouvert.com>
 *          Valery Febvre <vfebvre@easter-eggs.com>
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

#include <lasso/id-ff/name_registration.h>

/*****************************************************************************/
/* public methods                                                            */
/*****************************************************************************/

/**
 * lasso_name_registration_build_request_msg:
 * @name_registration: the register name identifier object
 * 
 * This method build a register name identifier request message.
 * 
 * It gets the register name identifier protocol profile and:
 * 
 * - if it is a SOAP method, then it builds the register name identifier
 *   request SOAP message, optionaly signs his node, set the msg_body
 *   attribute, gets the SoapEndpoint url and set the msg_url attribute.
 *
 * - if it is a HTTP-Redirect method, then it builds the register name
 *   identifier request QUERY message (optionaly signs the request message),
 *   builds the request url with register name identifier url with register
 *   name identifier service url, set the msg_url attribute of the register
 *   name identifier object, set the msg_body to NULL.
 * 
 * Return value: 0 if OK else < 0
 **/
gint
lasso_name_registration_build_request_msg(LassoNameRegistration *name_registration)
{
	LassoProfile *profile;
	LassoProvider *remote_provider;
	char *url, *query;

	g_return_val_if_fail(LASSO_IS_NAME_REGISTRATION(name_registration), -1);

	profile = LASSO_PROFILE(name_registration);

	remote_provider = g_hash_table_lookup(profile->server->providers,
			profile->remote_providerID);
	if (remote_provider == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "XXX");
		return -1;
	}

	if (profile->http_request_method == LASSO_HTTP_METHOD_SOAP) {
		profile->msg_url = lasso_provider_get_metadata_one(remote_provider, "SoapEndpoint");
		profile->msg_body = lasso_node_export_to_soap(profile->request,
				profile->server->private_key, profile->server->certificate);
		return 0;
	}

	if (profile->http_request_method == LASSO_HTTP_METHOD_REDIRECT) {
		/* build and optionaly sign the query message and build the
		 * register name identifier request url */
		url = lasso_provider_get_metadata_one(remote_provider,
				"RegisterNameIdentifierServiceURL");
		if (url == NULL) {
			message(G_LOG_LEVEL_CRITICAL, "Unknown profile service URL");
			return -1;
		}
		query = lasso_node_export_to_query(profile->request,
				profile->server->signature_method,
				profile->server->private_key);
		if (query == NULL) {
			g_free(url);
			message(G_LOG_LEVEL_CRITICAL, "Error building request QUERY url");
			return -1;
		}
		/* build the msg_url */
		profile->msg_url = g_strdup_printf("%s?%s", url, query);
		profile->msg_body = NULL;
		g_free(url);
		g_free(query);
		return 0;
	}

	message(G_LOG_LEVEL_CRITICAL, "Invalid http method");
	return LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD;
}

gint
lasso_name_registration_build_response_msg(LassoNameRegistration *name_registration)
{
	LassoProfile *profile;
	LassoProvider *remote_provider;
	char *url, *query;

	g_return_val_if_fail(LASSO_IS_NAME_REGISTRATION(name_registration), -1);

	profile = LASSO_PROFILE(name_registration);

	remote_provider = g_hash_table_lookup(profile->server->providers,
			profile->remote_providerID);
	if (remote_provider == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "XXX");
		return -1;
	}

	if (profile->http_request_method == LASSO_HTTP_METHOD_SOAP) {
		profile->msg_url = NULL; /* XXX ??? */
		profile->msg_body = lasso_node_export_to_soap(profile->response, NULL, NULL);
		return 0;
	}

	if (profile->http_request_method == LASSO_HTTP_METHOD_REDIRECT) {
		url = lasso_provider_get_metadata_one(remote_provider,
				"RegisterNameIdentifierServiceReturnURL");
		if (url == NULL) {
			message(G_LOG_LEVEL_CRITICAL, "Unknown profile service URL");
			return -1;
		}
		query = lasso_node_export_to_query(profile->response,
				profile->server->signature_method,
				profile->server->private_key);
		if (query == NULL) {
			g_free(url);
			message(G_LOG_LEVEL_CRITICAL, "Error building request QUERY url");
			return -1;
		}
		/* build the msg_url */
		profile->msg_url = g_strdup_printf("%s?%s", url, query);
		g_free(url);
		g_free(query);
		profile->msg_body = NULL;

		return 0;
	}

	message(G_LOG_LEVEL_CRITICAL, "Invalid HTTP request method");
	return LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD;
}

void
lasso_name_registration_destroy(LassoNameRegistration *name_registration)
{
	g_object_unref(G_OBJECT(name_registration));
}

gint
lasso_name_registration_init_request(LassoNameRegistration *name_registration,
		char *remote_providerID, lassoHttpMethod http_method)
{
	LassoProfile *profile;
	LassoProvider *remote_provider;
	LassoFederation *federation;
	LassoSamlNameIdentifier *spNameIdentifier, *idpNameIdentifier, *oldNameIdentifier = NULL;

	g_return_val_if_fail(LASSO_IS_NAME_REGISTRATION(name_registration), -1);

	profile = LASSO_PROFILE(name_registration);

	/* verify if the identity and session exist */
	if (LASSO_IS_IDENTITY(profile->identity) == FALSE) {
		message(G_LOG_LEVEL_CRITICAL, "Identity not found");
		return -1;
	}

	/* set the remote provider id */
	if (remote_providerID == NULL)
		g_assert_not_reached(); /* was default; didn't make sense */

	profile->remote_providerID = g_strdup(remote_providerID);

	remote_provider = g_hash_table_lookup(profile->server->providers,
			profile->remote_providerID);
	if (remote_provider == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "XXX");
		return -1;
	}

	/* Get federation */
	federation = g_hash_table_lookup(profile->identity->federations,
			profile->remote_providerID);
	if (LASSO_IS_FEDERATION(federation) == FALSE) {
		message(G_LOG_LEVEL_CRITICAL, "Federation not found");
		return -1;
	}

	/* FIXME : depending on the requester provider type, verify the format
	 * of the old name identifier is only federated type */

	if (remote_provider->role == LASSO_PROVIDER_ROLE_IDP) {
		spNameIdentifier = lasso_saml_name_identifier_new();
		spNameIdentifier->content = lasso_build_unique_id(32);
		spNameIdentifier->NameQualifier = g_strdup(profile->remote_providerID);
		spNameIdentifier->Format = g_strdup(LASSO_LIB_NAME_IDENTIFIER_FORMAT_FEDERATED);

		idpNameIdentifier = g_object_ref(federation->remote_nameIdentifier);

		if (federation->local_nameIdentifier) {
			/* old name identifier is from SP,
			 * name_registration->oldNameIdentifier must be from SP */
			oldNameIdentifier = g_object_ref(federation->local_nameIdentifier);
		} else {
			/* oldNameIdentifier is none, no local name identifier at SP, old is IDP */
			oldNameIdentifier = g_object_ref(idpNameIdentifier);
		}

		profile->nameIdentifier = g_strdup(spNameIdentifier->content);
		name_registration->oldNameIdentifier = g_strdup(oldNameIdentifier->content);
	}
	if (remote_provider->role == LASSO_PROVIDER_ROLE_SP) {
		if (federation->local_nameIdentifier == NULL) {
			message(G_LOG_LEVEL_CRITICAL, "Local name identifier not found");
			return -1;
		}

		oldNameIdentifier = g_object_ref(federation->local_nameIdentifier);
		
		spNameIdentifier = NULL;
		if (federation->remote_nameIdentifier) {
			spNameIdentifier = g_object_ref(federation->remote_nameIdentifier);
		}

		idpNameIdentifier = lasso_saml_name_identifier_new();
		idpNameIdentifier->content = lasso_build_unique_id(32);
		idpNameIdentifier->NameQualifier = g_strdup(profile->remote_providerID);
		idpNameIdentifier->Format = g_strdup(LASSO_LIB_NAME_IDENTIFIER_FORMAT_FEDERATED);

		if (spNameIdentifier) {
			profile->nameIdentifier = g_strdup(spNameIdentifier->content);
			name_registration->oldNameIdentifier = g_strdup(profile->nameIdentifier);
		} else {
			profile->nameIdentifier = g_strdup(idpNameIdentifier->content);
			name_registration->oldNameIdentifier = g_strdup(oldNameIdentifier->content);
		}
	}

	if (oldNameIdentifier == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "Invalid provider type");
		return -1;
	}

	if (http_method == LASSO_HTTP_METHOD_ANY) {
		http_method = lasso_provider_get_first_http_method(
				LASSO_PROVIDER(profile->server),
				remote_provider,
				LASSO_MD_PROTOCOL_TYPE_REGISTER_NAME_IDENTIFIER);
	} else {
		if (lasso_provider_accept_http_method(LASSO_PROVIDER(profile->server),
					remote_provider,
					LASSO_MD_PROTOCOL_TYPE_REGISTER_NAME_IDENTIFIER,
					http_method,
					TRUE) == FALSE) {
			message(G_LOG_LEVEL_CRITICAL, "unsupported profile!");
			return LASSO_PROFILE_ERROR_UNSUPPORTED_PROFILE;
		}
	}

	profile->request = lasso_lib_register_name_identifier_request_new_full(
			LASSO_PROVIDER(profile->server)->ProviderID,
			idpNameIdentifier, spNameIdentifier, oldNameIdentifier);
	if (profile->request == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "Error creating the request");
		return -1;
	}

	profile->http_request_method = http_method;

	return 0;
}

gint lasso_name_registration_process_request_msg(LassoNameRegistration *name_registration,
		char *request_msg)
{
	LassoProfile *profile;
	LassoProvider *remote_provider;
	LassoMessageFormat format;
	LassoSamlNameIdentifier *nameIdentifier;

	g_return_val_if_fail(LASSO_IS_NAME_REGISTRATION(name_registration), -1);
	g_return_val_if_fail(request_msg != NULL, -1);

	profile = LASSO_PROFILE(name_registration);

	profile->request = lasso_lib_register_name_identifier_request_new();
	format = lasso_node_init_from_message(profile->request, request_msg);
	if (format == LASSO_MESSAGE_FORMAT_UNKNOWN || format == LASSO_MESSAGE_FORMAT_ERROR) {
		message(G_LOG_LEVEL_CRITICAL, "XXX");
		return LASSO_PROFILE_ERROR_INVALID_MSG;
	}

	remote_provider = g_hash_table_lookup(profile->server->providers,
			LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(profile->request)->ProviderID);
	if (LASSO_IS_PROVIDER(remote_provider) == FALSE) {
		message(G_LOG_LEVEL_CRITICAL, "Unknown provider");
		return -1;
	}

	if (format == LASSO_MESSAGE_FORMAT_SOAP)
		profile->http_request_method = LASSO_HTTP_METHOD_SOAP;
	if (format == LASSO_MESSAGE_FORMAT_QUERY)
		profile->http_request_method = LASSO_HTTP_METHOD_REDIRECT;

	if (lasso_provider_accept_http_method(LASSO_PROVIDER(profile->server),
				remote_provider,
				LASSO_MD_PROTOCOL_TYPE_REGISTER_NAME_IDENTIFIER,
				profile->http_request_method, FALSE) == FALSE) {
		message(G_LOG_LEVEL_CRITICAL, "XXX");
		return LASSO_PROFILE_ERROR_UNSUPPORTED_PROFILE;
	}

	nameIdentifier = LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(
			profile->request)->SPProvidedNameIdentifier;
	if (remote_provider->role == LASSO_PROVIDER_ROLE_IDP) {
		if (nameIdentifier) {
			profile->nameIdentifier = g_strdup(nameIdentifier->content);
			name_registration->oldNameIdentifier = g_strdup(profile->nameIdentifier);
		} else {
			profile->nameIdentifier = g_strdup(
				LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(
					profile->request)->IDPProvidedNameIdentifier->content);
			name_registration->oldNameIdentifier = g_strdup(
				LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(
					profile->request)->OldProvidedNameIdentifier->content);
		}
	}
	if (remote_provider->role == LASSO_PROVIDER_ROLE_SP) {
		profile->nameIdentifier = g_strdup(nameIdentifier->content);
		name_registration->oldNameIdentifier = g_strdup(
			LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(
				profile->request)->OldProvidedNameIdentifier->content);
	}


	return 0;
}

gint
lasso_name_registration_process_response_msg(LassoNameRegistration *name_registration,
		char *response_msg)
{
	LassoProfile *profile;
	LassoProvider *remote_provider;
	LassoFederation *federation;
	LassoSamlNameIdentifier *nameIdentifier = NULL;
	lassoHttpMethod response_method;
	LassoMessageFormat format;
	int rc;
	char *statusCodeValue;

	g_return_val_if_fail(LASSO_IS_NAME_REGISTRATION(name_registration), -1);
	g_return_val_if_fail(response_msg != NULL, -1);

	profile = LASSO_PROFILE(name_registration);

	/* build register name identifier response from message */
	profile->response = lasso_lib_register_name_identifier_response_new();
	format = lasso_node_init_from_message(profile->response, response_msg);
	if (format == LASSO_MESSAGE_FORMAT_UNKNOWN || format == LASSO_MESSAGE_FORMAT_ERROR) {
		message(G_LOG_LEVEL_CRITICAL, "XXX");
		return LASSO_PROFILE_ERROR_INVALID_MSG;
	}
	if (format == LASSO_MESSAGE_FORMAT_SOAP)
		response_method = LASSO_HTTP_METHOD_SOAP;
	if (format == LASSO_MESSAGE_FORMAT_QUERY)
		response_method = LASSO_HTTP_METHOD_REDIRECT;
 
	remote_provider = g_hash_table_lookup(profile->server->providers,
			LASSO_LIB_STATUS_RESPONSE(profile->response)->ProviderID);
	if (remote_provider == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "XXX");
		return -1;
	}

	/* verify signature */
	rc = lasso_provider_verify_signature(remote_provider, response_msg, "ResponseID");

	statusCodeValue = LASSO_LIB_STATUS_RESPONSE(profile->response)->Status->StatusCode->Value;
	if (strcmp(statusCodeValue, LASSO_SAML_STATUS_CODE_SUCCESS) != 0) {
		message(G_LOG_LEVEL_CRITICAL, "%s", statusCodeValue);
		return -1;
	}

	/* Update federation with the nameIdentifier attribute. NameQualifier
	 * is local ProviderID and format is Federated type */
	if (LASSO_IS_IDENTITY(profile->identity) == FALSE) {
		message(G_LOG_LEVEL_CRITICAL, "Identity not found");
		return -1;
	}

	federation = g_hash_table_lookup(profile->identity->federations,
			profile->remote_providerID);
	if (LASSO_IS_FEDERATION(federation) == FALSE) {
		message(G_LOG_LEVEL_CRITICAL, "Federation not found");
		return -1;
	}

	remote_provider = g_hash_table_lookup(profile->server->providers,
			profile->remote_providerID);
	if (remote_provider == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "Remote provider not found");
		return -1;
	}

	if (remote_provider->role == LASSO_PROVIDER_ROLE_SP) {
		nameIdentifier = LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(
				profile->request)->IDPProvidedNameIdentifier;
	}
	if (remote_provider->role == LASSO_PROVIDER_ROLE_IDP) {
		nameIdentifier = LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(
				profile->request)->SPProvidedNameIdentifier;
	}
	if (nameIdentifier == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "Invalid provider role");
		return -1;
	}

	lasso_federation_set_local_name_identifier(federation, nameIdentifier);
	profile->identity->is_dirty = TRUE;

	/* set the relay state */
	profile->msg_relayState = g_strdup(
			LASSO_LIB_STATUS_RESPONSE(profile->response)->RelayState);

	return 0;
}

gint
lasso_name_registration_validate_request(LassoNameRegistration *name_registration)
{
	LassoProfile *profile;
	LassoProvider *remote_provider;
	LassoFederation *federation;
	LassoLibRegisterNameIdentifierRequest *request;
	LassoSamlNameIdentifier *providedNameIdentifier = NULL;

	g_return_val_if_fail(LASSO_IS_NAME_REGISTRATION(name_registration), -1);

	profile = LASSO_PROFILE(name_registration);

	/* verify the register name identifier request */
	if (LASSO_IS_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(profile->request) == FALSE) {
		message(G_LOG_LEVEL_CRITICAL, "Register Name Identifier request not found");
		return -1;
	}

	request = LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(profile->request);

	/* set the remote provider id from the request */
	profile->remote_providerID = g_strdup(request->ProviderID);
	if (profile->remote_providerID == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "No provider id found in name registration request");
		return -1;
	}

	/* set register name identifier response */
	profile->response = lasso_lib_register_name_identifier_response_new_full(
			LASSO_PROVIDER(profile->server)->ProviderID,
			LASSO_SAML_STATUS_CODE_SUCCESS, 
			LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(profile->request));
	if (LASSO_IS_LIB_REGISTER_NAME_IDENTIFIER_RESPONSE(profile->response) == FALSE) {
		message(G_LOG_LEVEL_CRITICAL, "Error building response");
		return -1;
	}

	/* verify federation */
	federation = g_hash_table_lookup(profile->identity->federations,
			profile->remote_providerID);
	if (LASSO_IS_FEDERATION(federation) == FALSE) {
		message(G_LOG_LEVEL_CRITICAL, "Federation not found");
		return -1;
	}

	if (request->OldProvidedNameIdentifier == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "Old provided name identifier not found");
		return -1;
	}

	if (lasso_federation_verify_nameIdentifier(federation,
				request->OldProvidedNameIdentifier) == FALSE) {
		message(G_LOG_LEVEL_CRITICAL, "No name identifier");
		return -1;
	}

	remote_provider = g_hash_table_lookup(profile->server->providers,
			profile->remote_providerID);
	if (remote_provider == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "XXX");
		return -1;
	}

	/* update name identifier in federation */
	if (remote_provider->role == LASSO_PROVIDER_ROLE_SP) {
		providedNameIdentifier = request->SPProvidedNameIdentifier;
	}
	if (remote_provider->role == LASSO_PROVIDER_ROLE_IDP) {
		providedNameIdentifier = request->IDPProvidedNameIdentifier;
	}
	if (providedNameIdentifier == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "Sp provided name identifier not found");
		return -1;
	}

	lasso_federation_set_remote_name_identifier(federation, providedNameIdentifier);
	profile->identity->is_dirty = TRUE;

	return 0;
}



/*****************************************************************************/
/* private methods                                                           */
/*****************************************************************************/

static LassoNodeClass *parent_class = NULL;

static xmlNode*
get_xmlNode(LassoNode *node)
{
	xmlNode *xmlnode;
	LassoNameRegistration *name_registration = LASSO_NAME_REGISTRATION(node);

	xmlnode = parent_class->get_xmlNode(node);
	xmlNodeSetName(xmlnode, "NameRegistration");
	xmlSetProp(xmlnode, "NameRegistrationDumpVersion", "2");

	if (name_registration->oldNameIdentifier) {
		xmlNewTextChild(xmlnode, NULL, "OldNameIdentifier",
				name_registration->oldNameIdentifier);
	}

	return xmlnode;
}

static int
init_from_xml(LassoNode *node, xmlNode *xmlnode)
{
	LassoNameRegistration *name_registration = LASSO_NAME_REGISTRATION(node);
	xmlNode *t;

	if (parent_class->init_from_xml(node, xmlnode))
		return -1;

	t = xmlnode->children;
	while (t) {
		if (t->type != XML_ELEMENT_NODE) {
			t = t->next;
			continue;
		}
		if (strcmp(t->name, "OldNameIdentifier") == 0)
			name_registration->oldNameIdentifier = xmlNodeGetContent(t);

		t = t->next;
	}
	return 0;
}

/*****************************************************************************/
/* overrided parent class methods                                            */
/*****************************************************************************/

static void
finalize(GObject *object)
{  
	debug("Register Name Identifier object 0x%x finalized ...");
	G_OBJECT_CLASS(parent_class)->finalize(object);
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
instance_init(LassoNameRegistration *name_registration)
{
	name_registration->oldNameIdentifier = NULL;
}

static void
class_init(LassoNameRegistrationClass *klass)
{
	parent_class = g_type_class_peek_parent(klass);

	LASSO_NODE_CLASS(klass)->get_xmlNode = get_xmlNode;
	LASSO_NODE_CLASS(klass)->init_from_xml = init_from_xml;

	G_OBJECT_CLASS(klass)->finalize = finalize;
}

GType
lasso_name_registration_get_type()
{
	static GType this_type = 0;

	if (!this_type) {
		static const GTypeInfo this_info = {
			sizeof (LassoNameRegistrationClass),
			NULL,
			NULL,
			(GClassInitFunc) class_init,
			NULL,
			NULL,
			sizeof(LassoNameRegistration),
			0,
			(GInstanceInitFunc) instance_init,
		};

		this_type = g_type_register_static(LASSO_TYPE_PROFILE,
				"LassoNameRegistration", &this_info, 0);
	}
	return this_type;
}

LassoNameRegistration *
lasso_name_registration_new(LassoServer *server)
{
	LassoNameRegistration *name_registration;

	g_return_val_if_fail(LASSO_IS_SERVER(server), NULL);

	name_registration = g_object_new(LASSO_TYPE_NAME_REGISTRATION, NULL);
	LASSO_PROFILE(name_registration)->server = server;

	return name_registration;
}

LassoNameRegistration*
lasso_name_registration_new_from_dump(LassoServer *server, const char *dump)
{
	LassoNameRegistration *name_registration;
	xmlDoc *doc;

	name_registration = lasso_name_registration_new(server);
	doc = xmlParseMemory(dump, strlen(dump));
	init_from_xml(LASSO_NODE(name_registration), xmlDocGetRootElement(doc)); 

	return name_registration;
}

/**
 * lasso_name_registration_dump:
 * @name_registration: the register name identifier object
 * 
 * This method builds a dump of the register name identifier object
 * 
 * Return value: a newly allocated string or NULL
 **/
gchar *
lasso_name_registration_dump(LassoNameRegistration *name_registration)
{
	return lasso_node_dump(LASSO_NODE(name_registration), NULL, 1);
}

