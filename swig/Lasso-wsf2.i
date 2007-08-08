/* -*- Mode: c; c-basic-offset: 8 -*-
 *
 * $Id: Lasso-wsf.i,v 1.79 2006/03/06 14:01:29 Exp $
 *
 * SWIG bindings for Lasso Library
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

%include Lasso-wsf-soap.i

%{
#include <lasso/id-wsf-2.0/discovery.h>
#include <lasso/id-wsf-2.0/data_service.h>
%}

/* WSF prefix & href */
#ifndef SWIG_PHP_RENAMES
%rename(IDWSF2_DISCO_HREF) LASSO_IDWSF2_DISCO_HREF;
%rename(IDWSF2_DISCO_PREFIX) LASSO_IDWSF2_DISCO_PREFIX;
#endif
#define LASSO_IDWSF2_DISCO_HREF   "urn:liberty:disco:2006-08"
#define LASSO_IDWSF2_DISCO_PREFIX "disco"

/***********************************************************************
 ***********************************************************************
 * ID-WSF 2
 ***********************************************************************
 ***********************************************************************/


/***********************************************************************
 * lasso:IdWsf2Discovery
 ***********************************************************************/

#ifndef SWIG_PHP_RENAMES
%rename(IdWsf2Discovery) LassoIdWsf2Discovery;
#endif
typedef struct {
} LassoIdWsf2Discovery;
%extend LassoIdWsf2Discovery {

	/* Attributes inherited from LassoProfile */

	%newobject identity_get;
	LassoIdentity *identity;

	%newobject session_get;
	LassoSession *session;

	%immutable isIdentityDirty;
	gboolean isIdentityDirty;

	%immutable isSessionDirty;
	gboolean isSessionDirty;

	%immutable msgBody;
	char *msgBody;

	%immutable msgUrl;
	char *msgUrl;
	
	%immutable nameIdentifier;
	LassoSaml2NameID *nameIdentifier;

	%newobject request_get;
	LassoNode *request;

	%newobject response_get;
	LassoNode *response;

	%newobject server_get;
	LassoServer *server;
	
	/* Attributes */

	%newobject metadata_get;
	LassoIdWsf2DiscoSvcMetadata *metadata;

	%immutable svcMDID;
	char *svcMDID;

	/* Constructor, Destructor & Static Methods */

	LassoIdWsf2Discovery(LassoServer *server);

	~LassoIdWsf2Discovery();

	/* Methods inherited from LassoProfile */

	THROW_ERROR()
	int setIdentityFromDump(char *dump);
	END_THROW_ERROR()

	THROW_ERROR()
	int setSessionFromDump(char *dump);
	END_THROW_ERROR()

	/* Methods inherited from LassoIdWsf2Profile */

	THROW_ERROR()
	int buildRequestMsg();
	END_THROW_ERROR()

	THROW_ERROR()
	int buildResponseMsg();
	END_THROW_ERROR()

	/* Methods */
	
	%newobject metadataRegisterSelf;
	char* metadataRegisterSelf(const char *service_type, const char *abstract,
		const char *soap_endpoint, const char *svcMDID = NULL);

	THROW_ERROR()
	int initMetadataRegister(const char *service_type, const char *abstract,
		const char *disco_provider_id, const char *soap_endpoint);
	END_THROW_ERROR()

	THROW_ERROR()
	int processMetadataRegisterMsg(const char *message);
	END_THROW_ERROR()

	THROW_ERROR()
	int processMetadataRegisterResponseMsg(const char *message);
	END_THROW_ERROR()

	THROW_ERROR()
	int initMetadataAssociationAdd(const char *svcMDID);
	END_THROW_ERROR()

	THROW_ERROR()
	int processMetadataAssociationAddMsg(const char *message);
	END_THROW_ERROR()

	THROW_ERROR()
	int registerMetadata();
	END_THROW_ERROR()

	THROW_ERROR()
	int processMetadataAssociationAddResponseMsg(const char *message);
	END_THROW_ERROR()

	THROW_ERROR()
	int initQuery(const char *security_mech_id = NULL);
	END_THROW_ERROR()
	
	THROW_ERROR()
	int addRequestedServiceType(const char *service_type);
	END_THROW_ERROR()
	
	THROW_ERROR()
	int processQueryMsg(const char *message);
	END_THROW_ERROR()

	THROW_ERROR()
	int buildQueryResponseEprs();
	END_THROW_ERROR()

	THROW_ERROR()
	int processQueryResponseMsg(const char *message);
	END_THROW_ERROR()

	%newobject getService;
	LassoIdWsf2DataService* getService(const char *service_type = NULL);
}

%{

/* Attributes inherited from LassoProfile */

/* identity */
#define LassoIdWsf2Discovery_get_identity(self) lasso_profile_get_identity(LASSO_PROFILE(self))
#define LassoIdWsf2Discovery_identity_get(self) lasso_profile_get_identity(LASSO_PROFILE(self))
#define LassoIdWsf2Discovery_set_identity(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->identity, (value))
#define LassoIdWsf2Discovery_identity_set(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->identity, (value))

/* isIdentityDirty */
#define LassoIdWsf2Discovery_get_isIdentityDirty(self) lasso_profile_is_identity_dirty(LASSO_PROFILE(self))
#define LassoIdWsf2Discovery_isIdentityDirty_get(self) lasso_profile_is_identity_dirty(LASSO_PROFILE(self))

/* session */
#define LassoIdWsf2Discovery_get_session(self) lasso_profile_get_session(LASSO_PROFILE(self))
#define LassoIdWsf2Discovery_session_get(self) lasso_profile_get_session(LASSO_PROFILE(self))
#define LassoIdWsf2Discovery_set_session(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->session, (value))
#define LassoIdWsf2Discovery_session_set(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->session, (value))

/* isSessionDirty */
#define LassoIdWsf2Discovery_get_isSessionDirty(self) lasso_profile_is_session_dirty(LASSO_PROFILE(self))
#define LassoIdWsf2Discovery_isSessionDirty_get(self) lasso_profile_is_session_dirty(LASSO_PROFILE(self))

/* msgBody */
#define LassoIdWsf2Discovery_get_msgBody(self) LASSO_PROFILE(self)->msg_body
#define LassoIdWsf2Discovery_msgBody_get(self) LASSO_PROFILE(self)->msg_body

/* msgUrl */
#define LassoIdWsf2Discovery_get_msgUrl(self) LASSO_PROFILE(self)->msg_url
#define LassoIdWsf2Discovery_msgUrl_get(self) LASSO_PROFILE(self)->msg_url

/* nameIdentifier */
#define LassoIdWsf2Discovery_get_nameIdentifier(self) \
	LASSO_SAML2_NAME_ID(get_node(LASSO_PROFILE(self)->nameIdentifier))
#define LassoIdWsf2Discovery_nameIdentifier_get(self) \
	LASSO_SAML2_NAME_ID(get_node(LASSO_PROFILE(self)->nameIdentifier))

/* request */
#define LassoIdWsf2Discovery_get_request(self) get_node(LASSO_PROFILE(self)->request)
#define LassoIdWsf2Discovery_request_get(self) get_node(LASSO_PROFILE(self)->request)
#define LassoIdWsf2Discovery_set_request(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->request, (value))
#define LassoIdWsf2Discovery_request_set(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->request, (value))

/* response */
#define LassoIdWsf2Discovery_get_response(self) get_node(LASSO_PROFILE(self)->response)
#define LassoIdWsf2Discovery_response_get(self) get_node(LASSO_PROFILE(self)->response)
#define LassoIdWsf2Discovery_set_response(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->response, (value))
#define LassoIdWsf2Discovery_response_set(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->response, (value))

/* server */
#define LassoIdWsf2Discovery_get_server(self) get_node(LASSO_PROFILE(self)->server)
#define LassoIdWsf2Discovery_server_get(self) get_node(LASSO_PROFILE(self)->server)
#define LassoIdWsf2Discovery_set_server(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->server, (value))
#define LassoIdWsf2Discovery_server_set(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->server, (value))

/* Attributes */

/* metadata */
#define LassoIdWsf2Discovery_get_metadata(self) get_node(self->metadata)
#define LassoIdWsf2Discovery_metadata_get(self) get_node(self->metadata)
#define LassoIdWsf2Discovery_set_metadata(self, value) set_node((gpointer *) &self->metadata, value)
#define LassoIdWsf2Discovery_metadata_set(self, value) set_node((gpointer *) &self->metadata, value)

/* svcMDID */
#define LassoIdWsf2Discovery_get_svcMDID(self) self->svcMDID
#define LassoIdWsf2Discovery_svcMDID_get(self) self->svcMDID

/* Constructors, destructors & static methods implementations */

#define new_LassoIdWsf2Discovery lasso_idwsf2_discovery_new
#define delete_LassoIdWsf2Discovery(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoIdWsf2Profile */

#define LassoIdWsf2Discovery_setIdentityFromDump(self, dump) lasso_profile_set_identity_from_dump(LASSO_PROFILE(self), dump)
#define LassoIdWsf2Discovery_setSessionFromDump(self, dump) lasso_profile_set_session_from_dump(LASSO_PROFILE(self), dump)

#define LassoIdWsf2Discovery_buildRequestMsg(self) lasso_idwsf2_profile_build_request_msg(LASSO_IDWSF2_PROFILE(self))
#define LassoIdWsf2Discovery_buildResponseMsg(self) lasso_idwsf2_profile_build_response_msg(LASSO_IDWSF2_PROFILE(self))

/* Methods implementations */

#define LassoIdWsf2Discovery_metadataRegisterSelf lasso_idwsf2_discovery_metadata_register_self
#define LassoIdWsf2Discovery_initMetadataRegister lasso_idwsf2_discovery_init_metadata_register
#define LassoIdWsf2Discovery_processMetadataRegisterMsg lasso_idwsf2_discovery_process_metadata_register_msg
#define LassoIdWsf2Discovery_processMetadataRegisterResponseMsg lasso_idwsf2_discovery_process_metadata_register_response_msg
#define LassoIdWsf2Discovery_initMetadataAssociationAdd lasso_idwsf2_discovery_init_metadata_association_add
#define LassoIdWsf2Discovery_processMetadataAssociationAddMsg lasso_idwsf2_discovery_process_metadata_association_add_msg
#define LassoIdWsf2Discovery_processMetadataAssociationAddResponseMsg lasso_idwsf2_discovery_process_metadata_association_add_response_msg
#define LassoIdWsf2Discovery_initQuery lasso_idwsf2_discovery_init_query
#define LassoIdWsf2Discovery_addRequestedServiceType lasso_idwsf2_discovery_add_requested_service_type
#define LassoIdWsf2Discovery_processQueryMsg lasso_idwsf2_discovery_process_query_msg
#define LassoIdWsf2Discovery_buildQueryResponseEprs lasso_idwsf2_discovery_build_query_response_eprs
#define LassoIdWsf2Discovery_processQueryResponseMsg lasso_idwsf2_discovery_process_query_response_msg
#define LassoIdWsf2Discovery_registerMetadata lasso_idwsf2_discovery_register_metadata
#define LassoIdWsf2Discovery_getService(self, type) \
        get_node(lasso_idwsf2_discovery_get_service(self, type))

%}


/***********************************************************************
 * lasso:IdWsf2DataService
 ***********************************************************************/

#ifndef SWIG_PHP_RENAMES
%rename(IdWsf2DataService) LassoIdWsf2DataService;
#endif
typedef struct {
} LassoIdWsf2DataService;
%extend LassoIdWsf2DataService {

	/* Attributes inherited from LassoProfile */

	%immutable msgBody;
	char *msgBody;

	%immutable msgUrl;
	char *msgUrl;

	%immutable nameIdentifier;
	LassoSaml2NameID *nameIdentifier;

	%newobject request_get;
	LassoNode *request;

	%newobject response_get;
	LassoNode *response;

	%newobject server_get;
	LassoServer *server;

	/* Attributes */

	%newobject data;
	char *data;

	%immutable type;
	char *type;

	%immutable redirectUrl;
	char *redirectUrl;

	%immutable queryItems;
	LassoStringList *queryItems;

	/* Constructor, Destructor & Static Methods */

	LassoIdWsf2DataService(LassoServer *server);

	~LassoIdWsf2DataService();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();

	/* Methods inherited from LassoIdWsf2Profile */

	THROW_ERROR()
	int buildRequestMsg();
	END_THROW_ERROR()

	THROW_ERROR()
	int buildResponseMsg();
	END_THROW_ERROR()

	/* Methods */

	THROW_ERROR()
	int initQuery();
	END_THROW_ERROR()

	THROW_ERROR()
	int addQueryItem(const char *item_xpath, const char *item_id);		
	END_THROW_ERROR()

	THROW_ERROR()
	int processQueryMsg(const char *message);
	END_THROW_ERROR()

	THROW_ERROR()
	int parseQueryItems();
	END_THROW_ERROR()

	THROW_ERROR()
	int processQueryResponseMsg(const char *message);
	END_THROW_ERROR()

	%newobject getAttributeNode;
	char* getAttributeNode(const char *item_id = NULL);

	%newobject getAttributeString;
	char* getAttributeString(const char *item_id = NULL);

	THROW_ERROR()
	int initRedirectUserForConsent(const char *redirect_url);
	END_THROW_ERROR()
	
	THROW_ERROR()
	int initModify();
	END_THROW_ERROR()
	
	THROW_ERROR()
	int addModifyItem(const char *item_xpath, const char *item_id, const char *new_data,
		const gboolean overrideAllowed=FALSE);
	END_THROW_ERROR()

	THROW_ERROR()
	int processModifyMsg(const char *message);
	END_THROW_ERROR()
	
	THROW_ERROR()
	int parseModifyItems();
	END_THROW_ERROR()

	THROW_ERROR()
	int processModifyResponseMsg(const char *message);
	END_THROW_ERROR()
}

%{

/* Attributes inherited from LassoProfile */

/* msgBody */
#define LassoIdWsf2DataService_get_msgBody(self) LASSO_PROFILE(self)->msg_body
#define LassoIdWsf2DataService_msgBody_get(self) LASSO_PROFILE(self)->msg_body

/* msgUrl */
#define LassoIdWsf2DataService_get_msgUrl(self) LASSO_PROFILE(self)->msg_url
#define LassoIdWsf2DataService_msgUrl_get(self) LASSO_PROFILE(self)->msg_url

/* nameIdentifier */
#define LassoIdWsf2DataService_get_nameIdentifier(self) \
	LASSO_SAML2_NAME_ID(get_node(LASSO_PROFILE(self)->nameIdentifier))
#define LassoIdWsf2DataService_nameIdentifier_get(self) \
	LASSO_SAML2_NAME_ID(get_node(LASSO_PROFILE(self)->nameIdentifier))

/* request */
#define LassoIdWsf2DataService_get_request(self) get_node(LASSO_PROFILE(self)->request)
#define LassoIdWsf2DataService_request_get(self) get_node(LASSO_PROFILE(self)->request)
#define LassoIdWsf2DataService_set_request(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->request, (value))
#define LassoIdWsf2DataService_request_set(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->request, (value))

/* response */
#define LassoIdWsf2DataService_get_response(self) get_node(LASSO_PROFILE(self)->response)
#define LassoIdWsf2DataService_response_get(self) get_node(LASSO_PROFILE(self)->response)
#define LassoIdWsf2DataService_set_response(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->response, (value))
#define LassoIdWsf2DataService_response_set(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->response, (value))

/* server */
#define LassoIdWsf2DataService_get_server(self) get_node(LASSO_PROFILE(self)->server)
#define LassoIdWsf2DataService_server_get(self) get_node(LASSO_PROFILE(self)->server)
#define LassoIdWsf2DataService_set_server(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->server, (value))
#define LassoIdWsf2DataService_server_set(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->server, (value))

/* Attributes */

/* data */
#define LassoIdWsf2DataService_get_data(self) get_xml_string((self)->data)
#define LassoIdWsf2DataService_data_get(self) get_xml_string((self)->data)
#define LassoIdWsf2DataService_set_data(self, value) set_xml_string(&(self)->data, (value))
#define LassoIdWsf2DataService_data_set(self, value) set_xml_string(&(self)->data, (value))

/* type */
#define LassoIdWsf2DataService_get_type(self) self->type
#define LassoIdWsf2DataService_type_get(self) self->type

/* redirectUrl */
#define LassoIdWsf2DataService_get_redirectUrl(self) self->redirect_url
#define LassoIdWsf2DataService_redirectUrl_get(self) self->redirect_url

/* queryItems */
#define LassoIdWsf2DataService_get_queryItems(self) get_string_list((self)->query_items)
#define LassoIdWsf2DataService_queryItems_get(self) get_string_list((self)->query_items)

/* Constructors, destructors & static methods implementations */

#define new_LassoIdWsf2DataService lasso_idwsf2_data_service_new
#define delete_LassoIdWsf2DataService(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoIdWsf2DataService_dump(self) lasso_node_dump(LASSO_NODE(self))

/* Implementations of methods inherited from LassoIdWsf2Profile */

#define LassoIdWsf2DataService_buildRequestMsg(self) lasso_idwsf2_profile_build_request_msg(LASSO_IDWSF2_PROFILE(self))
#define LassoIdWsf2DataService_buildResponseMsg(self) lasso_idwsf2_profile_build_response_msg(LASSO_IDWSF2_PROFILE(self))

/* Methods implementations */
#define LassoIdWsf2DataService_initQuery lasso_idwsf2_data_service_init_query
#define LassoIdWsf2DataService_addQueryItem lasso_idwsf2_data_service_add_query_item
#define LassoIdWsf2DataService_processQueryMsg lasso_idwsf2_data_service_process_query_msg
#define LassoIdWsf2DataService_parseQueryItems lasso_idwsf2_data_service_parse_query_items
#define LassoIdWsf2DataService_processQueryResponseMsg lasso_idwsf2_data_service_process_query_response_msg
#define LassoIdWsf2DataService_getAttributeNode(self, itemId) \
	get_xml_string(lasso_idwsf2_data_service_get_attribute_node(self, itemId))
#define LassoIdWsf2DataService_getAttributeString lasso_idwsf2_data_service_get_attribute_string
#define LassoIdWsf2DataService_initRedirectUserForConsent lasso_idwsf2_data_service_init_redirect_user_for_consent
#define LassoIdWsf2DataService_initModify lasso_idwsf2_data_service_init_modify
#define LassoIdWsf2DataService_addModifyItem lasso_idwsf2_data_service_add_modify_item
#define LassoIdWsf2DataService_processModifyMsg lasso_idwsf2_data_service_process_modify_msg
#define LassoIdWsf2DataService_parseModifyItems lasso_idwsf2_data_service_parse_modify_items
#define LassoIdWsf2DataService_processModifyResponseMsg \
	lasso_idwsf2_data_service_process_modify_response_msg

%}

