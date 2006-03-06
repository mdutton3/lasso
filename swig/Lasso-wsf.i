/* -*- Mode: c; c-basic-offset: 8 -*-
 *
 * $Id$
 *
 * SWIG bindings for Lasso Library
 *
 * Copyright (C) 2004, 2005 Entr'ouvert
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

%include Lasso-wsf-disco.i
%include Lasso-wsf-dst.i
%include Lasso-wsf-is.i
%include Lasso-wsf-sa.i
%include Lasso-wsf-soap.i

%{
#include <lasso/id-wsf/authentication.h>
#include <lasso/id-wsf/discovery.h>
#include <lasso/id-wsf/interaction_profile_service.h>
#include <lasso/id-wsf/personal_profile_service.h>
#include <lasso/id-wsf/data_service.h>
%}


/***********************************************************************
 ***********************************************************************
 * Constants
 ***********************************************************************
 ***********************************************************************/

/* Liberty Security Mechanisms */
#ifndef SWIGPHP4
%rename(SECURITY_MECH_NULL) LASSO_SECURITY_MECH_NULL;

%rename(SECURITY_MECH_X509) LASSO_SECURITY_MECH_X509;
%rename(SECURITY_MECH_SAML) LASSO_SECURITY_MECH_SAML;
%rename(SECURITY_MECH_BEARER) LASSO_SECURITY_MECH_BEARER;

%rename(SECURITY_MECH_TLS) LASSO_SECURITY_MECH_TLS;
%rename(SECURITY_MECH_TLS_X509) LASSO_SECURITY_MECH_TLS_X509;
%rename(SECURITY_MECH_TLS_SAML) LASSO_SECURITY_MECH_TLS_SAML;
%rename(SECURITY_MECH_TLS_BEARER) LASSO_SECURITY_MECH_TLS_BEARER;

%rename(SECURITY_MECH_CLIENT_TLS) LASSO_SECURITY_MECH_CLIENT_TLS;
%rename(SECURITY_MECH_CLIENT_TLS_X509) LASSO_SECURITY_MECH_CLIENT_TLS_X509;
%rename(SECURITY_MECH_CLIENT_TLS_SAML) LASSO_SECURITY_MECH_CLIENT_TLS_SAML;
%rename(SECURITY_MECH_CLIENT_TLS_BEARER) LASSO_SECURITY_MECH_CLIENT_TLS_BEARER;
#endif
#define LASSO_SECURITY_MECH_NULL   "urn:liberty:security:2003-08:NULL:NULL"

#define LASSO_SECURITY_MECH_X509   "urn:liberty:security:2003-08:NULL:X509"
#define LASSO_SECURITY_MECH_SAML   "urn:liberty:security:2003-08:NULL:SAML"
#define LASSO_SECURITY_MECH_BEARER "urn:liberty:security:2004-04:NULL:Bearer"

#define LASSO_SECURITY_MECH_TLS        "urn:liberty:security:2003-08:TLS:null"
#define LASSO_SECURITY_MECH_TLS_X509   "urn:liberty:security:2003-08:TLS:X509"
#define LASSO_SECURITY_MECH_TLS_SAML   "urn:liberty:security:2003-08:TLS:SAML"
#define LASSO_SECURITY_MECH_TLS_BEARER "urn:liberty:security:2004-04:TLS:Bearer"

#define LASSO_SECURITY_MECH_CLIENT_TLS        "urn:liberty:security:2003-08:ClientTLS:null"
#define LASSO_SECURITY_MECH_CLIENT_TLS_X509   "urn:liberty:security:2003-08:ClientTLS:X509"
#define LASSO_SECURITY_MECH_CLIENT_TLS_SAML   "urn:liberty:security:2003-08:ClientTLS:SAML"
#define LASSO_SECURITY_MECH_CLIENT_TLS_BEARER "urn:liberty:security:2004-04:ClientTLS:Bearer"

/* WSF prefix & href */
#ifndef SWIGPHP4
%rename(EP_HREF) LASSO_EP_HREF;
%rename(EP_PREFIX) LASSO_EP_PREFIX;
%rename(PP_HREF) LASSO_PP_HREF;
%rename(PP_PREFIX) LASSO_PP_PREFIX;
#endif
#define LASSO_EP_HREF   "urn:liberty:id-sis-ep:2003-08"
#define LASSO_EP_PREFIX "ep"
#define LASSO_PP_HREF   "urn:liberty:id-sis-pp:2003-08"
#define LASSO_PP_PREFIX "pp"


/***********************************************************************
 ***********************************************************************
 * XML Elements in Utility Namespace
 ***********************************************************************
 ***********************************************************************/


/***********************************************************************
 * utility:Status
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(UtilityStatus) LassoUtilityStatus;
#endif
typedef struct {
	/* Attributes */

	char *code;

	char *comment;

#ifdef SWIGCSHARP
	/* "ref" is a C# reserved word. */
	%rename(reference) ref;
#endif
	char *ref;
} LassoUtilityStatus;
%extend LassoUtilityStatus {
	/* Attributes */

#ifndef SWIGPHP4
	%rename(status) Status;
#endif
	%newobject Status_get;
	LassoUtilityStatus *Status;

	/* Constructor, Destructor & Static Methods */

	LassoUtilityStatus(char *code);

	~LassoUtilityStatus();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes Implementations */

/* Status */
#define LassoUtilityStatus_get_Status(self) get_node((self)->Status)
#define LassoUtilityStatus_Status_get(self) get_node((self)->Status)
#define LassoUtilityStatus_set_Status(self, value) set_node((gpointer *) &(self)->Status, (value))
#define LassoUtilityStatus_Status_set(self, value) set_node((gpointer *) &(self)->Status, (value))

/* Constructors, destructors & static methods implementations */
#define new_LassoUtilityStatus lasso_utility_status_new
#define delete_LassoUtilityStatus(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoUtilityStatus_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 ***********************************************************************
 * ID-WSF
 ***********************************************************************
 ***********************************************************************/


/***********************************************************************
 * lasso:Discovery
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(Discovery) LassoDiscovery;
#endif
typedef struct {
} LassoDiscovery;
%extend LassoDiscovery {
	/* Attributes inherited from WsfProfile */

	%newobject identity_get;
	LassoIdentity *identity;

	%immutable isIdentityDirty;
	gboolean isIdentityDirty;

	%immutable isSessionDirty;
	gboolean isSessionDirty;

	%immutable msgBody;
	char *msgBody;

	%immutable msgUrl;
	char *msgUrl;

	%newobject request_get;
	LassoNode *request;

	%newobject response_get;
	LassoNode *response;

	%newobject server_get;
	LassoServer *server;

	%newobject soapEnvelopeRequest_get;
	LassoSoapEnvelope *soapEnvelopeRequest;

	%newobject soapEnvelopeResponse_get;
	LassoSoapEnvelope *soapEnvelopeResponse;

	/* Attributes */
	%newobject resourceId_get;
	LassoDiscoResourceID *resourceId;

	%newobject encryptedResourceId_get;
	LassoDiscoEncryptedResourceID *encryptedResourceId;

	/* Constructor, Destructor & Static Methods */

	LassoDiscovery(LassoServer *server);

	~LassoDiscovery();

	/* Methods inherited from WsfProfile */

	THROW_ERROR()
	int setIdentityFromDump(char *dump);
	END_THROW_ERROR()

	THROW_ERROR()
	int setSessionFromDump(char *dump);
	END_THROW_ERROR()

	THROW_ERROR()
	int buildRequestMsg();
	END_THROW_ERROR()

	THROW_ERROR()
	int buildResponseMsg();
	END_THROW_ERROR()

	/* Methods */

	THROW_ERROR()
	int initInsert(LassoDiscoResourceOffering *newOffering, const char *security_mech_id = NULL);
	END_THROW_ERROR()

	THROW_ERROR()
	int initRemove(const char *entryId);
	END_THROW_ERROR()

	THROW_ERROR()
	int buildModifyResponseMsg();
	END_THROW_ERROR()

	LassoDiscoInsertEntry* addInsertEntry(LassoDiscoServiceInstance *serviceInstance,
					      LassoDiscoResourceID *resourceID);

	THROW_ERROR()
	int addRemoveEntry(char *entryID);
	END_THROW_ERROR()

	LassoDiscoRequestedServiceType *addRequestedServiceType(char *serviceType,
								char *option = NULL);

	THROW_ERROR()
	int initModify(LassoDiscoResourceOffering *resourceOffering,
			LassoDiscoDescription *description);
	END_THROW_ERROR()

	THROW_ERROR()
	int initQuery(const char *security_mech_id = NULL);
	END_THROW_ERROR()

	THROW_ERROR()
	int processModifyMsg(const char *modify_msg, const gchar *security_mech_id = NULL);
	END_THROW_ERROR()

	THROW_ERROR()
	int processModifyResponseMsg(const char *modify_response_msg);
	END_THROW_ERROR()

	THROW_ERROR()
	int processQueryMsg(char *query_msg, const char *security_mech_id = NULL);
	END_THROW_ERROR()

	THROW_ERROR()
	int processQueryResponseMsg(char *query_response_msg);
	END_THROW_ERROR()

	%newobject getService;
	LassoDataService* getService(const char *service_type = NULL);
	
	%newobject getServices;
	LassoNodeList* getServices();
}

%{

/* Attributes inherited from WsfProfile implementations */

/* identity */
#define LassoDiscovery_get_identity(self) lasso_wsf_profile_get_identity(LASSO_WSF_PROFILE(self))
#define LassoDiscovery_identity_get(self) lasso_wsf_profile_get_identity(LASSO_WSF_PROFILE(self))
#define LassoDiscovery_set_identity(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->identity, (value))
#define LassoDiscovery_identity_set(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->identity, (value))

/* isIdentityDirty */
#define LassoDiscovery_get_isIdentityDirty(self) lasso_wsf_profile_is_identity_dirty(LASSO_WSF_PROFILE(self))
#define LassoDiscovery_isIdentityDirty_get(self) lasso_wsf_profile_is_identity_dirty(LASSO_WSF_PROFILE(self))

/* session */
#define LassoDiscovery_get_session(self) lasso_wsf_profile_get_session(LASSO_WSF_PROFILE(self))
#define LassoDiscovery_session_get(self) lasso_wsf_profile_get_session(LASSO_WSF_PROFILE(self))
#define LassoDiscovery_set_session(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->session, (value))
#define LassoDiscovery_session_set(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->session, (value))

/* isSessionDirty */
#define LassoDiscovery_get_isSessionDirty(self) lasso_wsf_profile_is_session_dirty(LASSO_WSF_PROFILE(self))
#define LassoDiscovery_isSessionDirty_get(self) lasso_wsf_profile_is_session_dirty(LASSO_WSF_PROFILE(self))

/* msgBody */
#define LassoDiscovery_get_msgBody(self) LASSO_WSF_PROFILE(self)->msg_body
#define LassoDiscovery_msgBody_get(self) LASSO_WSF_PROFILE(self)->msg_body

/* msgUrl */
#define LassoDiscovery_get_msgUrl(self) LASSO_WSF_PROFILE(self)->msg_url
#define LassoDiscovery_msgUrl_get(self) LASSO_WSF_PROFILE(self)->msg_url

/* request */
#define LassoDiscovery_get_request(self) get_node(LASSO_WSF_PROFILE(self)->request)
#define LassoDiscovery_request_get(self) get_node(LASSO_WSF_PROFILE(self)->request)
#define LassoDiscovery_set_request(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->request, (value))
#define LassoDiscovery_request_set(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->request, (value))

/* response */
#define LassoDiscovery_get_response(self) get_node(LASSO_WSF_PROFILE(self)->response)
#define LassoDiscovery_response_get(self) get_node(LASSO_WSF_PROFILE(self)->response)
#define LassoDiscovery_set_response(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->response, (value))
#define LassoDiscovery_response_set(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->response, (value))

/* server */
#define LassoDiscovery_get_server(self) get_node(LASSO_WSF_PROFILE(self)->server)
#define LassoDiscovery_server_get(self) get_node(LASSO_WSF_PROFILE(self)->server)
#define LassoDiscovery_set_server(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->server, (value))
#define LassoDiscovery_server_set(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->server, (value))

/* soapEnvelopeRequest */
#define LassoDiscovery_get_soapEnvelopeRequest(self) get_node(LASSO_WSF_PROFILE(self)->soap_envelope_request)
#define LassoDiscovery_soapEnvelopeRequest_get(self) get_node(LASSO_WSF_PROFILE(self)->soap_envelope_request)
#define LassoDiscovery_set_soapEnvelopeRequest(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->soap_envelope_request, (value))
#define LassoDiscovery_soapEnvelopeRequest_set(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->soap_envelope_request, (value))

/* soapEnvelopeResponse */
#define LassoDiscovery_get_soapEnvelopeResponse(self) get_node(LASSO_WSF_PROFILE(self)->soap_envelope_response)
#define LassoDiscovery_soapEnvelopeResponse_get(self) get_node(LASSO_WSF_PROFILE(self)->soap_envelope_response)
#define LassoDiscovery_set_soapEnvelopeResponse(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->soap_envelope_response, (value))
#define LassoDiscovery_soapEnvelopeResponse_set(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->soap_envelope_response, (value))

/* Attributes */

/* EncryptedResourceID */
#define LassoDiscovery_get_encryptedResourceId(self) get_node((self)->encrypted_resource_id)
#define LassoDiscovery_encryptedResourceId_get(self) get_node((self)->encrypted_resource_id)
#define LassoDiscovery_set_encryptedResourceId(self, value) set_node((gpointer *) &(self)->encrypted_resource_id, (value))
#define LassoDiscovery_encryptedResourceId_set(self, value) set_node((gpointer *) &(self)->encrypted_resource_id, (value))

/* ResourceID */
#define LassoDiscovery_get_resourceId(self) get_node((self)->resource_id)
#define LassoDiscovery_resourceId_get(self) get_node((self)->resource_id)
#define LassoDiscovery_set_resourceId(self, value) set_node((gpointer *) &(self)->resource_id, (value))
#define LassoDiscovery_resourceId_set(self, value) set_node((gpointer *) &(self)->resource_id, (value))



/* Constructors, destructors & static methods implementations */

#define new_LassoDiscovery lasso_discovery_new
#define delete_LassoDiscovery(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from WsfProfile */

int LassoDiscovery_setIdentityFromDump(LassoDiscovery *self, char *dump) {
	return lasso_wsf_profile_set_identity_from_dump(LASSO_WSF_PROFILE(self), dump);
}

int LassoDiscovery_setSessionFromDump(LassoDiscovery *self, char *dump) {
	return lasso_wsf_profile_set_session_from_dump(LASSO_WSF_PROFILE(self), dump);
}

#define LassoDiscovery_buildRequestMsg(self) lasso_wsf_profile_build_soap_request_msg(LASSO_WSF_PROFILE(self))

/* Methods implementations */

#define LassoDiscovery_buildResponseMsg lasso_discovery_build_response_msg
#define LassoDiscovery_addInsertEntry lasso_discovery_add_insert_entry
#define LassoDiscovery_addRemoveEntry lasso_discovery_add_remove_entry
#define LassoDiscovery_addRequestedServiceType lasso_discovery_add_requested_service_type
#define LassoDiscovery_addResourceOffering lasso_discovery_add_resource_offering
#define LassoDiscovery_initInsert lasso_discovery_init_insert
#define LassoDiscovery_initRemove lasso_discovery_init_remove
#define LassoDiscovery_buildModifyResponseMsg lasso_discovery_build_modify_response_msg
#define LassoDiscovery_initModify lasso_discovery_init_modify
#define LassoDiscovery_initQuery lasso_discovery_init_query
#define LassoDiscovery_processModifyMsg lasso_discovery_process_modify_msg
#define LassoDiscovery_processModifyResponseMsg lasso_discovery_process_modify_response_msg
#define LassoDiscovery_processQueryMsg lasso_discovery_process_query_msg
#define LassoDiscovery_processQueryResponseMsg lasso_discovery_process_query_response_msg
#define LassoDiscovery_getService(self, type) get_node(lasso_discovery_get_service(self, type))
#define LassoDiscovery_getServices(self) get_node_list(lasso_discovery_get_services(self));

%}


/***********************************************************************
 * lasso:InteractionProfileService
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(InteractionProfileService) LassoInteractionProfileService;
#endif
typedef struct {
} LassoInteractionProfileService;
%extend LassoInteractionProfileService {
	/* Attributes inherited from WsfProfile */

	%immutable msgBody;
	char *msgBody;

	%immutable msgUrl;
	char *msgUrl;

	%newobject request_get;
	LassoNode *request;

	%newobject response_get;
	LassoNode *response;

	%newobject server_get;
	LassoServer *server;

	/* Constructor, Destructor & Static Methods */

	LassoInteractionProfileService(LassoServer *server);

	~LassoInteractionProfileService();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();

	/* Methods inherited from WsfProfile */

	THROW_ERROR()
	int buildRequestMsg();
	END_THROW_ERROR()

	THROW_ERROR()
	int buildResponseMsg();
	END_THROW_ERROR()

	/* Methods */

	THROW_ERROR()
	int initRequest();
	END_THROW_ERROR()

	THROW_ERROR()
	int processRequestMsg(char *msg);
	END_THROW_ERROR()

	THROW_ERROR()
	int processResponseMsg(char *msg);
	END_THROW_ERROR()

}

%{

/* Attributes inherited from WsfProfile implementations */

/* msgBody */
#define LassoInteractionProfileService_get_msgBody(self) LASSO_WSF_PROFILE(self)->msg_body
#define LassoInteractionProfileService_msgBody_get(self) LASSO_WSF_PROFILE(self)->msg_body

/* msgUrl */
#define LassoInteractionProfileService_get_msgUrl(self) LASSO_WSF_PROFILE(self)->msg_url
#define LassoInteractionProfileService_msgUrl_get(self) LASSO_WSF_PROFILE(self)->msg_url

/* request */
#define LassoInteractionProfileService_get_request(self) get_node(LASSO_WSF_PROFILE(self)->request)
#define LassoInteractionProfileService_request_get(self) get_node(LASSO_WSF_PROFILE(self)->request)
#define LassoInteractionProfileService_set_request(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->request, (value))
#define LassoInteractionProfileService_request_set(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->request, (value))

/* response */
#define LassoInteractionProfileService_get_response(self) get_node(LASSO_WSF_PROFILE(self)->response)
#define LassoInteractionProfileService_response_get(self) get_node(LASSO_WSF_PROFILE(self)->response)
#define LassoInteractionProfileService_set_response(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->response, (value))
#define LassoInteractionProfileService_response_set(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->response, (value))

/* server */
#define LassoInteractionProfileService_get_server(self) get_node(LASSO_WSF_PROFILE(self)->server)
#define LassoInteractionProfileService_server_get(self) get_node(LASSO_WSF_PROFILE(self)->server)
#define LassoInteractionProfileService_set_server(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->server, (value))
#define LassoInteractionProfileService_server_set(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->server, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoInteractionProfileService lasso_interaction_profile_service_new
#define delete_LassoInteractionProfileService(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoInteractionProfileService_dump(self) lasso_node_dump(LASSO_NODE(self))

/* Implementations of methods inherited from WsfProfile */
#define LassoInteractionProfileService_buildRequestMsg(self) lasso_wsf_profile_build_soap_request_msg(LASSO_WSF_PROFILE(self))
#define LassoInteractionProfileService_buildResponseMsg(self) lasso_wsf_profile_build_soap_response_msg(LASSO_WSF_PROFILE(self))

/* Methods implementations */

#define LassoInteractionProfileService_initRequest lasso_interaction_profile_service_init_request
#define LassoInteractionProfileService_processRequestMsg lasso_interaction_profile_service_process_request_msg
#define LassoInteractionProfileService_processResponseMsg lasso_interaction_profile_service_process_response_msg

%}


/***********************************************************************
 * lasso:PersonalProfileService
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(PersonalProfileService) LassoPersonalProfileService;
#endif
typedef struct {
} LassoPersonalProfileService;
%extend LassoPersonalProfileService {
	/* Attributes inherited from WsfProfile */

	%immutable msgBody;
	char *msgBody;

	%immutable msgUrl;
	char *msgUrl;

	%newobject request_get;
	LassoNode *request;

	%newobject response_get;
	LassoNode *response;

	%newobject server_get;
	LassoServer *server;

	/* Attributes inherited from ProfileService */
	%newobject resourceId_get;
	LassoDiscoResourceID *resourceId;

	%newobject encryptedResourceId_get;
	LassoDiscoEncryptedResourceID *encryptedResourceId;

	%newobject resourceData_get;
	char *resourceData;


	/* Constructor, Destructor & Static Methods */

	LassoPersonalProfileService(LassoServer *server, LassoDiscoResourceOffering *offering);

	~LassoPersonalProfileService();

	/* Methods inherited from WsfProfile */

	THROW_ERROR()
	int buildRequestMsg();
	END_THROW_ERROR()

	/* Methods inherited from ProfileService */

	THROW_ERROR()
	gint initQuery(const char *select = NULL, const char *item_id = NULL, const char *security_mech_id = NULL);
	END_THROW_ERROR()

	LassoDstQueryItem *addQueryItem(const char *select, const char *item_id);
		
	THROW_ERROR()
	int processQueryMsg(const char *message, const char *security_mech_id = NULL);
	END_THROW_ERROR()

	THROW_ERROR()
	int buildResponseMsg();
	END_THROW_ERROR()

	THROW_ERROR()
	int processQueryResponseMsg(const char *message);
	END_THROW_ERROR()

	%newobject getAnswer;
	char* getAnswer(const char *select = NULL);

	%newobject getAnswerForItemId;
	char* getAnswerForItemId(const char *itemId);

	int initModify(char *select, const char *xmlString);

	LassoDstModification *addModification(char *select);

	THROW_ERROR()
	int processModifyMsg(char *soap_msg, const char *security_mech_id = NULL);
	END_THROW_ERROR()

	THROW_ERROR()
	int processModifyResponseMsg(char *soap_msg);
	END_THROW_ERROR()

	/* Methods */

	gchar* getEmail();
}

%{

/* Attributes inherited from WsfProfile implementations */

/* msgBody */
#define LassoPersonalProfileService_get_msgBody(self) LASSO_WSF_PROFILE(self)->msg_body
#define LassoPersonalProfileService_msgBody_get(self) LASSO_WSF_PROFILE(self)->msg_body

/* msgUrl */
#define LassoPersonalProfileService_get_msgUrl(self) LASSO_WSF_PROFILE(self)->msg_url
#define LassoPersonalProfileService_msgUrl_get(self) LASSO_WSF_PROFILE(self)->msg_url

/* request */
#define LassoPersonalProfileService_get_request(self) get_node(LASSO_WSF_PROFILE(self)->request)
#define LassoPersonalProfileService_request_get(self) get_node(LASSO_WSF_PROFILE(self)->request)
#define LassoPersonalProfileService_set_request(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->request, (value))
#define LassoPersonalProfileService_request_set(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->request, (value))

/* response */
#define LassoPersonalProfileService_get_response(self) get_node(LASSO_WSF_PROFILE(self)->response)
#define LassoPersonalProfileService_response_get(self) get_node(LASSO_WSF_PROFILE(self)->response)
#define LassoPersonalProfileService_set_response(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->response, (value))
#define LassoPersonalProfileService_response_set(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->response, (value))

/* server */
#define LassoPersonalProfileService_get_server(self) get_node(LASSO_WSF_PROFILE(self)->server)
#define LassoPersonalProfileService_server_get(self) get_node(LASSO_WSF_PROFILE(self)->server)
#define LassoPersonalProfileService_set_server(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->server, (value))
#define LassoPersonalProfileService_server_set(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->server, (value))

/* Attributes from ProfileService*/

/* EncryptedResourceID */
#define LassoPersonalProfileService_get_encryptedResourceId(self) get_node(LASSO_DATA_SERVICE(self)->encrypted_resource_id)
#define LassoPersonalProfileService_encryptedResourceId_get(self) get_node(LASSO_DATA_SERVICE(self)->encrypted_resource_id)
#define LassoPersonalProfileService_set_encryptedResourceId(self, value) set_node((gpointer *) &(LASSO_DATA_SERVICE(self))->encrypted_resource_id, (value))
#define LassoPersonalProfileService_encryptedResourceId_set(self, value) set_node((gpointer *) &(LASSO_DATA_SERVICE(self))->encrypted_resource_id, (value))

/* ResourceID */
#define LassoPersonalProfileService_get_resourceId(self) get_node(LASSO_DATA_SERVICE(self)->resource_id)
#define LassoPersonalProfileService_resourceId_get(self) get_node(LASSO_DATA_SERVICE(self)->resource_id)
#define LassoPersonalProfileService_set_resourceId(self, value) set_node((gpointer *) &(LASSO_DATA_SERVICE(self))->resource_id, (value))
#define LassoPersonalProfileService_resourceId_set(self, value) set_node((gpointer *) &(LASSO_DATA_SERVICE(self))->resource_id, (value))

/* resourceData */
#define LassoPersonalProfileService_get_resourceData(self) get_xml_string(LASSO_DATA_SERVICE(self)->resource_data)
#define LassoPersonalProfileService_resourceData_get(self) get_xml_string(LASSO_DATA_SERVICE(self)->resource_data)
#define LassoPersonalProfileService_set_resourceData(self, value) set_xml_string(&(LASSO_DATA_SERVICE(self))->resource_data, (value))
#define LassoPersonalProfileService_resourceData_set(self, value) set_xml_string(&(LASSO_DATA_SERVICE(self))->resource_data, (value))



/* Constructors, destructors & static methods implementations */

#define new_LassoPersonalProfileService lasso_personal_profile_service_new
#define delete_LassoPersonalProfileService(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from WsfProfile */
#define LassoPersonalProfileService_buildRequestMsg(self) lasso_wsf_profile_build_soap_request_msg(LASSO_WSF_PROFILE(self))

/* Implementations of methods inherited from DataService */
#define LassoPersonalProfileService_buildResponseMsg lasso_data_service_build_response_msg
#define LassoPersonalProfileService_addData lasso_data_service_add_data
#define LassoPersonalProfileService_addModification lasso_data_service_add_modification
#define LassoPersonalProfileService_addQueryItem lasso_data_service_add_query_item
#define LassoPersonalProfileService_initQuery lasso_data_service_init_query
#define LassoPersonalProfileService_processModifyMsg lasso_data_service_process_modify_msg
#define LassoPersonalProfileService_processModifyResponseMsg lasso_data_service_process_modify_response_msg
#define LassoPersonalProfileService_processQueryMsg lasso_data_service_process_query_msg
#define LassoPersonalProfileService_processQueryResponseMsg lasso_data_service_process_query_response_msg
#define LassoPersonalProfileService_validateQuery lasso_data_service_validate_query
#define LassoPersonalProfileService_getAnswer(self,select) get_xml_string(lasso_data_service_get_answer(LASSO_DATA_SERVICE(self), select))
#define LassoPersonalProfileService_getAnswerForItemId(self,itemId) get_xml_string(lasso_data_service_get_answer_for_item_id(LASSO_DATA_SERVICE(self), itemId))
#define LassoPersonalProfileService_initModify(self, select, xmlString) lasso_data_service_init_modify(LASSO_DATA_SERVICE(self), select, get_string_xml(xmlString))

/* Methods implementations */
#define LassoPersonalProfileService_getEmail lasso_personal_profile_service_get_email

%}


/***********************************************************************
 * lasso:DataService
 ***********************************************************************/

#ifndef SWIGPHP4
%rename(DataService) LassoDataService;
#endif
typedef struct {
} LassoDataService;
%extend LassoDataService {
	/* Attributes inherited from WsfProfile */

	%immutable msgBody;
	char *msgBody;

	%immutable msgUrl;
	char *msgUrl;

	%newobject request_get;
	LassoNode *request;

	%newobject response_get;
	LassoNode *response;

	%newobject server_get;
	LassoServer *server;

	/* Attributes */
	%newobject resourceId_get;
	LassoDiscoResourceID *resourceId;

	%newobject encryptedResourceId_get;
	LassoDiscoEncryptedResourceID *encryptedResourceId;

	%newobject resourceData_get;
	char *resourceData;

	%immutable providerId;
	char *providerId;
	
	%immutable abstractDescription;
	char *abstractDescription;

	/* Constructor, Destructor & Static Methods */

	LassoDataService(LassoServer *server);

	~LassoDataService();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();

	/* Methods inherited from WsfProfile */

	THROW_ERROR()
	int buildRequestMsg();
	END_THROW_ERROR()

	/* Methods */

	THROW_ERROR()
	gint initQuery(const char *select = NULL, const char *item_id = NULL,
		       const char *security_mech_id = NULL);
	END_THROW_ERROR()

	LassoDstQueryItem *addQueryItem(const char *select, const char *item_id);
		
	THROW_ERROR()
	int processQueryMsg(const char *message, const char *security_mech_id = NULL);
	END_THROW_ERROR()

	THROW_ERROR()
	int buildModifyResponseMsg();
	END_THROW_ERROR()

	THROW_ERROR()
	int buildResponseMsg();
	END_THROW_ERROR()

	THROW_ERROR()
	int processQueryResponseMsg(const char *message);
	END_THROW_ERROR()

	%newobject getAnswer;
	char* getAnswer(const char *select = NULL);

	%newobject getAnswerForItemId;
	char* getAnswerForItemId(const char *itemId);

	int initModify(char *select, const char *xmlString);

	LassoDstModification *addModification(char *select);

	THROW_ERROR()
	int processModifyMsg(char *soap_msg, const char *security_mech_id = NULL);
	END_THROW_ERROR()

	THROW_ERROR()
	int processModifyResponseMsg(const char *soap_msg);
	END_THROW_ERROR()

	gboolean isPrincipalOnline();
	void setPrincipalStatus(const char *status);
	void setPrincipalOnline();
	void setPrincipalOffline();

	%newobject getRedirectRequestUrl;
	char* getRedirectRequestUrl();

	int needRedirectUser(const char *redirectUrl);
}

%{

/* Attributes inherited from WsfProfile implementations */

/* msgBody */
#define LassoDataService_get_msgBody(self) LASSO_WSF_PROFILE(self)->msg_body
#define LassoDataService_msgBody_get(self) LASSO_WSF_PROFILE(self)->msg_body

/* msgUrl */
#define LassoDataService_get_msgUrl(self) LASSO_WSF_PROFILE(self)->msg_url
#define LassoDataService_msgUrl_get(self) LASSO_WSF_PROFILE(self)->msg_url

/* request */
#define LassoDataService_get_request(self) get_node(LASSO_WSF_PROFILE(self)->request)
#define LassoDataService_request_get(self) get_node(LASSO_WSF_PROFILE(self)->request)
#define LassoDataService_set_request(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->request, (value))
#define LassoDataService_request_set(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->request, (value))

/* response */
#define LassoDataService_get_response(self) get_node(LASSO_WSF_PROFILE(self)->response)
#define LassoDataService_response_get(self) get_node(LASSO_WSF_PROFILE(self)->response)
#define LassoDataService_set_response(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->response, (value))
#define LassoDataService_response_set(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->response, (value))

/* server */
#define LassoDataService_get_server(self) get_node(LASSO_WSF_PROFILE(self)->server)
#define LassoDataService_server_get(self) get_node(LASSO_WSF_PROFILE(self)->server)
#define LassoDataService_set_server(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->server, (value))
#define LassoDataService_server_set(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->server, (value))

/* Attributes */

/* providerId */
#define LassoDataService_get_providerId(self) self->provider_id
#define LassoDataService_providerId_get(self) self->provider_id

/* abstractDescription */
#define LassoDataService_get_abstractDescription(self) self->abstract_description
#define LassoDataService_abstractDescription_get(self) self->abstract_description

/* EncryptedResourceID */
#define LassoDataService_get_encryptedResourceId(self) get_node((self)->encrypted_resource_id)
#define LassoDataService_encryptedResourceId_get(self) get_node((self)->encrypted_resource_id)
#define LassoDataService_set_encryptedResourceId(self, value) set_node((gpointer *) &(self)->encrypted_resource_id, (value))
#define LassoDataService_encryptedResourceId_set(self, value) set_node((gpointer *) &(self)->encrypted_resource_id, (value))

/* ResourceID */
#define LassoDataService_get_resourceId(self) get_node((self)->resource_id)
#define LassoDataService_resourceId_get(self) get_node((self)->resource_id)
#define LassoDataService_set_resourceId(self, value) set_node((gpointer *) &(self)->resource_id, (value))
#define LassoDataService_resourceId_set(self, value) set_node((gpointer *) &(self)->resource_id, (value))

/* resourceData */
#define LassoDataService_get_resourceData(self) get_xml_string((self)->resource_data)
#define LassoDataService_resourceData_get(self) get_xml_string((self)->resource_data)
#define LassoDataService_set_resourceData(self, value) set_xml_string(&(self)->resource_data, (value))
#define LassoDataService_resourceData_set(self, value) set_xml_string(&(self)->resource_data, (value))


/* Constructors, destructors & static methods implementations */

#define new_LassoDataService lasso_data_service_new
#define delete_LassoDataService(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoDataService_dump(self) lasso_node_dump(LASSO_NODE(self))


/* Implementations of methods inherited from WsfProfile */
#define LassoDataService_buildRequestMsg(self) lasso_wsf_profile_build_soap_request_msg(LASSO_WSF_PROFILE(self))

#define LassoDataService_isPrincipalOnline(self) lasso_wsf_profile_principal_is_online(LASSO_WSF_PROFILE(self))
#define LassoDataService_setPrincipalStatus(self, status) lasso_wsf_profile_set_principal_status(LASSO_WSF_PROFILE(self), status)
#define LassoDataService_setPrincipalOnline(self) lasso_wsf_profile_set_principal_online(LASSO_WSF_PROFILE(self))
#define LassoDataService_setPrincipalOffline(self) lasso_wsf_profile_set_principal_offline(LASSO_WSF_PROFILE(self))

/* Methods implementations */
#define LassoDataService_buildModifyResponseMsg lasso_data_service_build_modify_response_msg
#define LassoDataService_buildResponseMsg lasso_data_service_build_response_msg
#define LassoDataService_addData lasso_data_service_add_data
#define LassoDataService_addModification lasso_data_service_add_modification
#define LassoDataService_addQueryItem lasso_data_service_add_query_item
#define LassoDataService_initModify(self, select, xmlString) lasso_data_service_init_modify(self, select, get_string_xml(xmlString))
#define LassoDataService_initQuery lasso_data_service_init_query
#define LassoDataService_processModifyMsg lasso_data_service_process_modify_msg
#define LassoDataService_processModifyResponseMsg lasso_data_service_process_modify_response_msg
#define LassoDataService_processQueryMsg lasso_data_service_process_query_msg
#define LassoDataService_processQueryResponseMsg lasso_data_service_process_query_response_msg
#define LassoDataService_validateQuery lasso_data_service_validate_query
#define LassoDataService_getAnswer(self,select) get_xml_string(lasso_data_service_get_answer(self, select))
#define LassoDataService_getAnswerForItemId(self,itemId) get_xml_string(lasso_data_service_get_answer_for_item_id(self, itemId))

#define LassoDataService_getRedirectRequestUrl lasso_data_service_get_redirect_request_url
#define LassoDataService_needRedirectUser lasso_data_service_need_redirect_user

%}

/***********************************************************************
 * LassoUserAccount
 ***********************************************************************/

%rename(UserAccount) LassoUserAccount;
typedef struct {
	char *login;

	char *password;

} LassoUserAccount;

/***********************************************************************
 * lasso:Authentication
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(Authentication) LassoAuthentication;
#endif
typedef struct {

} LassoAuthentication;
%extend LassoAuthentication {
	/* Attributes inherited from WsfProfile */

	%immutable msgBody;
	char *msgBody;

	%immutable msgUrl;
	char *msgUrl;

#ifndef SWIGPHP4
	%rename(soapEnvelopeRequest) soap_envelope_request;
#endif
	%newobject soap_envelope_request_get;
	LassoSoapEnvelope *soap_envelope_request;

#ifndef SWIGPHP4
	%rename(soapEnvelopeResponse) soap_envelope_response;
#endif
	%newobject soap_envelope_response_get;
	LassoSoapEnvelope *soap_envelope_response;

	%newobject request_get;
	LassoSaSASLRequest *request;

	%newobject response_get;
	LassoSaSASLResponse *response;

	%newobject server_get;
	LassoServer *server;

	/* Constructor, Destructor & Static Methods */

	LassoAuthentication(LassoServer *server);

	~LassoAuthentication();

	/* Methods inherited from LassoNode */

	/* Methods inherited from WsfProfile */

	THROW_ERROR()
	int buildRequestMsg();
	END_THROW_ERROR()

	THROW_ERROR()
	int buildResponseMsg();
	END_THROW_ERROR()

	/* Methods */
	int clientStart();

	int clientStep();

	THROW_ERROR()
	int getMechanismList();
	END_THROW_ERROR()

	int initRequest(LassoDiscoDescription *description, char *mechanisms, LassoUserAccount *account = NULL);

	int processRequestMsg(char *soap_msg);

	int processResponseMsg(char *soap_msg);

	int serverStart();

	int serverStep();
}

%{

/* Attributes inherited from WsfProfile implementations */
/* msgBody */
#define LassoAuthentication_get_msgBody(self) LASSO_WSF_PROFILE(self)->msg_body
#define LassoAuthentication_msgBody_get(self) LASSO_WSF_PROFILE(self)->msg_body

/* msgUrl */
#define LassoAuthentication_get_msgUrl(self) LASSO_WSF_PROFILE(self)->msg_url
#define LassoAuthentication_msgUrl_get(self) LASSO_WSF_PROFILE(self)->msg_url

/* soap envelope request */
#define LassoAuthentication_get_soap_envelope_request(self) get_node(LASSO_WSF_PROFILE(self)->soap_envelope_request)
#define LassoAuthentication_soap_envelope_request_get(self) get_node(LASSO_WSF_PROFILE(self)->soap_envelope_request)
#define LassoAuthentication_set_soap_envelope_request(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->soap_envelope_request, (value))
#define LassoAuthentication_soap_envelope_request_set(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->soap_envelope_request, (value))

/* soap envelope response */
#define LassoAuthentication_get_soap_envelope_response(self) get_node(LASSO_WSF_PROFILE(self)->soap_envelope_response)
#define LassoAuthentication_soap_envelope_response_get(self) get_node(LASSO_WSF_PROFILE(self)->soap_envelope_response)
#define LassoAuthentication_set_soap_envelope_response(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->soap_envelope_response, (value))
#define LassoAuthentication_soap_envelope_response_set(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->soap_envelope_response, (value))

/* request */
#define LassoAuthentication_get_request(self) get_node(LASSO_WSF_PROFILE(self)->request)
#define LassoAuthentication_request_get(self) get_node(LASSO_WSF_PROFILE(self)->request)
#define LassoAuthentication_set_request(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->request, (value))
#define LassoAuthentication_request_set(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->request, (value))

/* response */
#define LassoAuthentication_get_response(self) get_node(LASSO_WSF_PROFILE(self)->response)
#define LassoAuthentication_response_get(self) get_node(LASSO_WSF_PROFILE(self)->response)
#define LassoAuthentication_set_response(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->response, (value))
#define LassoAuthentication_response_set(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->response, (value))

/* server */
#define LassoAuthentication_get_server(self) get_node(LASSO_WSF_PROFILE(self)->server)
#define LassoAuthentication_server_get(self) get_node(LASSO_WSF_PROFILE(self)->server)
#define LassoAuthentication_set_server(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->server, (value))
#define LassoAuthentication_server_set(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->server, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoAuthentication lasso_authentication_new
#define delete_LassoAuthentication(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from WsfProfile */
#define LassoAuthentication_buildRequestMsg(self) lasso_wsf_profile_build_soap_request_msg(LASSO_WSF_PROFILE(self))
#define LassoAuthentication_buildResponseMsg(self) lasso_wsf_profile_build_soap_response_msg(LASSO_WSF_PROFILE(self))

/* Methods implementations */
#define LassoAuthentication_clientStart lasso_authentication_client_start
#define LassoAuthentication_clientStep lasso_authentication_client_step
#define LassoAuthentication_getMechanismList lasso_authentication_get_mechanism_list
#define LassoAuthentication_initRequest lasso_authentication_init_request
#define LassoAuthentication_processRequestMsg lasso_authentication_process_request_msg
#define LassoAuthentication_processResponseMsg lasso_authentication_process_response_msg
#define LassoAuthentication_serverStart lasso_authentication_server_start
#define LassoAuthentication_serverStep lasso_authentication_server_step

%}
