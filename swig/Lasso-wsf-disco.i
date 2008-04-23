/* -*- Mode: c; c-basic-offset: 8 -*-
 *
 * $Id$
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

%{
#include <lasso/xml/disco_authenticate_requester.h>
#include <lasso/xml/disco_authorize_requester.h>
#include <lasso/xml/disco_authenticate_session_context.h>
#include <lasso/xml/disco_encrypt_resource_id.h>
#include <lasso/xml/disco_send_single_logout.h>
#include <lasso/xml/disco_generate_bearer_token.h>
%}

/* WSF prefix & href */
#ifndef SWIG_PHP_RENAMES
%rename(DISCO_HREF) LASSO_DISCO_HREF;
%rename(DISCO_PREFIX) LASSO_DISCO_PREFIX;
#endif
#define LASSO_DISCO_HREF   "urn:liberty:disco:2003-08"
#define LASSO_DISCO_PREFIX "disco"

/* WSF status code */
#ifndef SWIG_PHP_RENAMES
%rename(DISCO_STATUS_CODE_OK) LASSO_DISCO_STATUS_CODE_OK;
%rename(DISCO_STATUS_CODE_FAILED) LASSO_DISCO_STATUS_CODE_FAILED;
%rename(DISCO_STATUS_CODE_REMOVE_ENTRY) LASSO_DISCO_STATUS_CODE_REMOVE_ENTRY;
%rename(DISCO_STATUS_CODE_FORBIDDEN) LASSO_DISCO_STATUS_CODE_FORBIDDEN;
%rename(DISCO_STATUS_CODE_NO_RESULTS) LASSO_DISCO_STATUS_CODE_NO_RESULTS;
%rename(DISCO_STATUS_CODE_DIRECTIVES) LASSO_DISCO_STATUS_CODE_DIRECTIVES;
#endif
#define LASSO_DISCO_STATUS_CODE_OK "OK"
#define LASSO_DISCO_STATUS_CODE_FAILED "Failed"
#define LASSO_DISCO_STATUS_CODE_REMOVE_ENTRY "RemoveEntry"
#define LASSO_DISCO_STATUS_CODE_FORBIDDEN "Forbidden"
#define LASSO_DISCO_STATUS_CODE_NO_RESULTS "NoResults"
#define LASSO_DISCO_STATUS_CODE_DIRECTIVES "Directive"

/***********************************************************************
 ***********************************************************************
 * XML Elements in Discovery Namespace
 ***********************************************************************
 ***********************************************************************/

/***********************************************************************
 * disco:AuthenticateRequester
 ***********************************************************************/


#ifndef SWIG_PHP_RENAMES
%rename(DiscoAuthenticateRequester) LassoDiscoAuthenticateRequester;
#endif
typedef struct {

#ifndef SWIG_PHP_RENAMES
	%rename(descriptionIdRefs) descriptionIDRefs;
#endif
	char *descriptionIDRefs;

} LassoDiscoAuthenticateRequester;
%extend LassoDiscoAuthenticateRequester {
	/* Attributes */

	/* Constructor, Destructor & Static Methods */

	LassoDiscoAuthenticateRequester();

	~LassoDiscoAuthenticateRequester();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes Implementations */

/* Constructors, destructors & static methods implementations */

#define new_LassoDiscoAuthenticateRequester lasso_disco_authenticate_requester_new
#define delete_LassoDiscoAuthenticateRequester(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoDiscoAuthenticateRequester_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * disco:AuthorizeRequester
 ***********************************************************************/


#ifndef SWIG_PHP_RENAMES
%rename(DiscoAuthorizeRequester) LassoDiscoAuthorizeRequester;
#endif
typedef struct {

#ifndef SWIG_PHP_RENAMES
	%rename(descriptionIdRefs) descriptionIDRefs;
#endif
	char *descriptionIDRefs;

} LassoDiscoAuthorizeRequester;
%extend LassoDiscoAuthorizeRequester {
	/* Attributes */

	/* Constructor, Destructor & Static Methods */

	LassoDiscoAuthorizeRequester();

	~LassoDiscoAuthorizeRequester();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes Implementations */

/* Constructors, destructors & static methods implementations */

#define new_LassoDiscoAuthorizeRequester lasso_disco_authorize_requester_new
#define delete_LassoDiscoAuthorizeRequester(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoDiscoAuthorizeRequester_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * disco:AuthenticateSessionContext
 ***********************************************************************/


#ifndef SWIG_PHP_RENAMES
%rename(DiscoAuthenticateSessionContext) LassoDiscoAuthenticateSessionContext;
#endif
typedef struct {

#ifndef SWIG_PHP_RENAMES
	%rename(descriptionIdRefs) descriptionIDRefs;
#endif
	char *descriptionIDRefs;

} LassoDiscoAuthenticateSessionContext;
%extend LassoDiscoAuthenticateSessionContext {
	/* Attributes */

	/* Constructor, Destructor & Static Methods */

	LassoDiscoAuthenticateSessionContext();

	~LassoDiscoAuthenticateSessionContext();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes Implementations */

/* Constructors, destructors & static methods implementations */

#define new_LassoDiscoAuthenticateSessionContext lasso_disco_authenticate_session_context_new
#define delete_LassoDiscoAuthenticateSessionContext(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoDiscoAuthenticateSessionContext_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * disco:EncryptResourceID
 ***********************************************************************/


#ifndef SWIG_PHP_RENAMES
%rename(DiscoEncryptResourceID) LassoDiscoEncryptResourceID;
#endif
typedef struct {

#ifndef SWIG_PHP_RENAMES
	%rename(descriptionIdRefs) descriptionIDRefs;
#endif
	char *descriptionIDRefs;

} LassoDiscoEncryptResourceID;
%extend LassoDiscoEncryptResourceID {
	/* Attributes */

	/* Constructor, Destructor & Static Methods */

	LassoDiscoEncryptResourceID();

	~LassoDiscoEncryptResourceID();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes Implementations */

/* Constructors, destructors & static methods implementations */

#define new_LassoDiscoEncryptResourceID lasso_disco_encrypt_resource_id_new
#define delete_LassoDiscoEncryptResourceID(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoDiscoEncryptResourceID_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * disco:SendSingleLogout
 ***********************************************************************/


#ifndef SWIG_PHP_RENAMES
%rename(DiscoSendSingleLogout) LassoDiscoSendSingleLogout;
#endif
typedef struct {

#ifndef SWIG_PHP_RENAMES
	%rename(descriptionIdRefs) descriptionIDRefs;
#endif
	char *descriptionIDRefs;

} LassoDiscoSendSingleLogout;
%extend LassoDiscoSendSingleLogout {
	/* Attributes */

	/* Constructor, Destructor & Static Methods */

	LassoDiscoSendSingleLogout();

	~LassoDiscoSendSingleLogout();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes Implementations */

/* Constructors, destructors & static methods implementations */

#define new_LassoDiscoSendSingleLogout lasso_disco_send_single_logout_new
#define delete_LassoDiscoSendSingleLogout(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoDiscoSendSingleLogout_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * disco:GenerateBearerToken
 ***********************************************************************/


#ifndef SWIG_PHP_RENAMES
%rename(DiscoGenerateBearerToken) LassoDiscoGenerateBearerToken;
#endif
typedef struct {

#ifndef SWIG_PHP_RENAMES
	%rename(descriptionIdRefs) descriptionIDRefs;
#endif
	char *descriptionIDRefs;

} LassoDiscoGenerateBearerToken;
%extend LassoDiscoGenerateBearerToken {
	/* Attributes */

	/* Constructor, Destructor & Static Methods */

	LassoDiscoGenerateBearerToken();

	~LassoDiscoGenerateBearerToken();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes Implementations */

/* Constructors, destructors & static methods implementations */

#define new_LassoDiscoGenerateBearerToken lasso_disco_generate_bearer_token_new
#define delete_LassoDiscoGenerateBearerToken(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoDiscoGenerateBearerToken_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * disco:Credentials
 ***********************************************************************/


#ifndef SWIG_PHP_RENAMES
%rename(DiscoCredentials) LassoDiscoCredentials;
#endif
typedef struct {
} LassoDiscoCredentials;
%extend LassoDiscoCredentials {
	/* Attributes */

	%newobject any_get;
	LassoNodeList *any;

	/* Constructor, Destructor & Static Methods */

	LassoDiscoCredentials();

	~LassoDiscoCredentials();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes Implementations */

/* any */
#define LassoDiscoCredentials_get_any(self) get_node_list((self)->any)
#define LassoDiscoCredentials_any_get(self) get_node_list((self)->any)
#define LassoDiscoCredentials_set_any(self, value) set_node_list(&(self)->any, (value))
#define LassoDiscoCredentials_any_set(self, value) set_node_list(&(self)->any, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoDiscoCredentials lasso_disco_credentials_new
#define delete_LassoDiscoCredentials(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoDiscoCredentials_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * disco:Description
 ***********************************************************************/


#ifndef SWIG_PHP_RENAMES
%rename(DiscoDescription) LassoDiscoDescription;
#endif
typedef struct {
	/* Attributes */

#ifndef SWIG_PHP_RENAMES
	%rename(endpoint) Endpoint;
#endif
	char *Endpoint;

	char *id;

#ifndef SWIG_PHP_RENAMES
	%rename(serviceNameRef) ServiceNameRef;
#endif
	char *ServiceNameRef;

#ifndef SWIG_PHP_RENAMES
	%rename(soapAction) SoapAction;
#endif
	char *SoapAction;

#ifndef SWIG_PHP_RENAMES
	%rename(wsdlUri) WsdlURI;
#endif
	char *WsdlURI;
} LassoDiscoDescription;
%extend LassoDiscoDescription {
	/* Attributes */

#ifndef SWIG_PHP_RENAMES
	%rename(credentialRef) CredentialRef;
#endif
	%newobject CredentialRef_get;
	LassoStringList *CredentialRef;

#ifndef SWIG_PHP_RENAMES
	%rename(securityMechId) SecurityMechID;
#endif
	%newobject SecurityMechID_get;
	LassoStringList *SecurityMechID;

	/* Constructor, Destructor & Static Methods */

	LassoDiscoDescription();

	~LassoDiscoDescription();

	%newobject newWithWsdlRef;
	static LassoDiscoDescription *newWithWsdlRef(gchar *securityMechID,
						     gchar *wsdlURI,
						     gchar *serviceNameRef);

	%newobject newWithBriefSoapHttpDescription;
	static LassoDiscoDescription *newWithBriefSoapHttpDescription(gchar *securityMechID,
								      gchar *endpoint,
								      gchar *soapAction = NULL);

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();

	/* Methods */

	void addSecurityMechId(const char *security_mech_id);
}

%{

/* Attributes Implementations */

/* CredentialRef */
#define LassoDiscoDescription_get_CredentialRef(self) get_string_list((self)->CredentialRef)
#define LassoDiscoDescription_CredentialRef_get(self) get_string_list((self)->CredentialRef)
#define LassoDiscoDescription_set_CredentialRef(self, value) set_string_list(&(self)->CredentialRef, (value))
#define LassoDiscoDescription_CredentialRef_set(self, value) set_string_list(&(self)->CredentialRef, (value))

/* SecurityMechID */
#define LassoDiscoDescription_get_SecurityMechID(self) get_string_list((self)->SecurityMechID)
#define LassoDiscoDescription_SecurityMechID_get(self) get_string_list((self)->SecurityMechID)
#define LassoDiscoDescription_set_SecurityMechID(self, value) set_string_list(&(self)->SecurityMechID, (value))
#define LassoDiscoDescription_SecurityMechID_set(self, value) set_string_list(&(self)->SecurityMechID, (value))

/* Constructors, destructors & static methods implementations */
#define LassoDiscoDescription_newWithWsdlRef lasso_disco_description_new_with_WsdlRef

#define LassoDiscoDescription_newWithBriefSoapHttpDescription lasso_disco_description_new_with_BriefSoapHttpDescription

#define new_LassoDiscoDescription lasso_disco_description_new
#define delete_LassoDiscoDescription(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoDiscoDescription_dump(self) lasso_node_dump(LASSO_NODE(self))

/* Implementations of methods */

void
LassoDiscoDescription_addSecurityMechId(LassoDiscoDescription *self, const char *security_mech_id);
void
LassoDiscoDescription_addSecurityMechId(LassoDiscoDescription *self, const char *security_mech_id) {
	self->SecurityMechID = g_list_append(self->SecurityMechID, g_strdup(security_mech_id));
}

%}


/***********************************************************************
 * disco:EncryptedResourceID
 ***********************************************************************/


#ifndef SWIG_PHP_RENAMES
%rename(DiscoEncryptedResourceID) LassoDiscoEncryptedResourceID;
#endif
typedef struct {
} LassoDiscoEncryptedResourceID;
%extend LassoDiscoEncryptedResourceID {
	/* Attributes */

	/* Constructor, Destructor & Static Methods */

	LassoDiscoEncryptedResourceID(char *content, char *key_file);

	~LassoDiscoEncryptedResourceID();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes Implementations */

/* Constructors, destructors & static methods implementations */

#define new_LassoDiscoEncryptedResourceID lasso_disco_encrypted_resource_id_new
#define delete_LassoDiscoEncryptedResourceID(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoDiscoEncryptedResourceID_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * disco:InsertEntry
 ***********************************************************************/


#ifndef SWIG_PHP_RENAMES
%rename(DiscoInsertEntry) LassoDiscoInsertEntry;
#endif
typedef struct {
} LassoDiscoInsertEntry;
%extend LassoDiscoInsertEntry {
	/* Attributes */

	%newobject any_get;
	LassoNodeList *any;

#ifndef SWIG_PHP_RENAMES
	%rename(resourceOffering) ResourceOffering;
#endif
	%newobject ResourceOffering_get;
	LassoDiscoResourceOffering *ResourceOffering;

	/* Constructor, Destructor & Static Methods */

	LassoDiscoInsertEntry(LassoDiscoResourceOffering *resourceOffering);

	~LassoDiscoInsertEntry();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes Implementations */

/* any */
#define LassoDiscoInsertEntry_get_any(self) get_node_list((self)->any)
#define LassoDiscoInsertEntry_any_get(self) get_node_list((self)->any)
#define LassoDiscoInsertEntry_set_any(self, value) set_node_list(&(self)->any, (value))
#define LassoDiscoInsertEntry_any_set(self, value) set_node_list(&(self)->any, (value))

/* ResourceOffering */
#define LassoDiscoInsertEntry_get_ResourceOffering(self) get_node((self)->ResourceOffering)
#define LassoDiscoInsertEntry_ResourceOffering_get(self) get_node((self)->ResourceOffering)
#define LassoDiscoInsertEntry_set_ResourceOffering(self, value) set_node((gpointer *) &(self)->ResourceOffering, (value))
#define LassoDiscoInsertEntry_ResourceOffering_set(self, value) set_node((gpointer *) &(self)->ResourceOffering, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoDiscoInsertEntry lasso_disco_insert_entry_new
#define delete_LassoDiscoInsertEntry(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoDiscoInsertEntry_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * disco:Modify
 ***********************************************************************/


#ifndef SWIG_PHP_RENAMES
%rename(DiscoModify) LassoDiscoModify;
#endif
typedef struct {
	/* Attributes */

	char *id;
} LassoDiscoModify;
%extend LassoDiscoModify {
	/* Attributes */

#ifndef SWIG_PHP_RENAMES
	%rename(insertEntry) InsertEntry;
#endif
	%newobject InsertEntry_get;
	LassoNodeList *InsertEntry;

#ifndef SWIG_PHP_RENAMES
	%rename(removeEntry) RemoveEntry;
#endif
	%newobject RemoveEntry_get;
	LassoNodeList *RemoveEntry;

#ifndef SWIG_PHP_RENAMES
	%rename(resourceId) ResourceID;
#endif
	%newobject ResourceID_get;
	LassoDiscoResourceID *ResourceID;

#ifndef SWIG_PHP_RENAMES
	%rename(encryptedResourceId) EncryptedResourceID;
#endif
	%newobject EncryptedResourceID_get;
	LassoDiscoEncryptedResourceID *EncryptedResourceID;

	/* Constructor, Destructor & Static Methods */

	LassoDiscoModify();

	~LassoDiscoModify();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();

	%newobject newFromMessage;
	static LassoDiscoModify *newFromMessage(char *message);

}

%{

/* Attributes Implementations */

/* InsertEntry */
#define LassoDiscoModify_get_InsertEntry(self) get_node_list((self)->InsertEntry)
#define LassoDiscoModify_InsertEntry_get(self) get_node_list((self)->InsertEntry)
#define LassoDiscoModify_set_InsertEntry(self, value) set_node_list(&(self)->InsertEntry, (value))
#define LassoDiscoModify_InsertEntry_set(self, value) set_node_list(&(self)->InsertEntry, (value))

/* RemoveEntry */
#define LassoDiscoModify_get_RemoveEntry(self) get_node_list((self)->RemoveEntry)
#define LassoDiscoModify_RemoveEntry_get(self) get_node_list((self)->RemoveEntry)
#define LassoDiscoModify_set_RemoveEntry(self, value) set_node_list(&(self)->RemoveEntry, (value))
#define LassoDiscoModify_RemoveEntry_set(self, value) set_node_list(&(self)->RemoveEntry, (value))

/* ResourceID */
#define LassoDiscoModify_get_ResourceID(self) get_node((self)->ResourceID)
#define LassoDiscoModify_ResourceID_get(self) get_node((self)->ResourceID)
#define LassoDiscoModify_set_ResourceID(self, value) set_node((gpointer *) &(self)->ResourceID, (value))
#define LassoDiscoModify_ResourceID_set(self, value) set_node((gpointer *) &(self)->ResourceID, (value))

/* EncryptedResourceID */
#define LassoDiscoModify_get_EncryptedResourceID(self) get_node((self)->EncryptedResourceID)
#define LassoDiscoModify_EncryptedResourceID_get(self) get_node((self)->EncryptedResourceID)
#define LassoDiscoModify_set_EncryptedResourceID(self, value) set_node((gpointer *) &(self)->EncryptedResourceID, (value))
#define LassoDiscoModify_EncryptedResourceID_set(self, value) set_node((gpointer *) &(self)->EncryptedResourceID, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoDiscoModify lasso_disco_modify_new
#define delete_LassoDiscoModify(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */
#define LassoDiscoModify_newFromMessage lasso_disco_modify_new_from_message

#define LassoDiscoModify_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * disco:ModifyResponse
 ***********************************************************************/


#ifndef SWIG_PHP_RENAMES
%rename(DiscoModifyResponse) LassoDiscoModifyResponse;
#endif
typedef struct {
	/* Attributes */

	char *id;

#ifndef SWIG_PHP_RENAMES
	%rename(newEntryIds) newEntryIDs;
#endif
	char *newEntryIDs;
} LassoDiscoModifyResponse;
%extend LassoDiscoModifyResponse {
	/* Attributes */

	/* FIXME: Missing from Lasso. */
/* #ifndef SWIG_PHP_RENAMES */
/* 	%rename(extension) Extension; */
/* #endif */
/* 	%newobject Extension_get; */
/* 	xmlNode *Extension; */

#ifndef SWIG_PHP_RENAMES
	%rename(status) Status;
#endif
	%newobject Status_get;
	LassoUtilityStatus *Status;

	/* Constructor, Destructor & Static Methods */

	LassoDiscoModifyResponse(LassoUtilityStatus *status);

	~LassoDiscoModifyResponse();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes Implementations */

/* Extension */
/* FIXME: Missing from Lasso. */
/* #define LassoDiscoModifyResponse_get_Extension(self) get_xml((self)->Extension) */
/* #define LassoDiscoModifyResponse_Extension_get(self) get_xml((self)->Extension) */
/* #define LassoDiscoModifyResponse_set_Extension(self, value) set_xml(&(self)->Extension, (value)) */
/* #define LassoDiscoModifyResponse_Extension_set(self, value) set_xml(&(self)->Extension, (value)) */

/* Status */
#define LassoDiscoModifyResponse_get_Status(self) get_node((self)->Status)
#define LassoDiscoModifyResponse_Status_get(self) get_node((self)->Status)
#define LassoDiscoModifyResponse_set_Status(self, value) set_node((gpointer *) &(self)->Status, (value))
#define LassoDiscoModifyResponse_Status_set(self, value) set_node((gpointer *) &(self)->Status, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoDiscoModifyResponse lasso_disco_modify_response_new
#define delete_LassoDiscoModifyResponse(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoDiscoModifyResponse_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * disco:Options
 ***********************************************************************/


#ifndef SWIG_PHP_RENAMES
%rename(DiscoOptions) LassoDiscoOptions;
#endif
typedef struct {
} LassoDiscoOptions;
%extend LassoDiscoOptions {
	/* Attributes */

#ifndef SWIG_PHP_RENAMES
	%rename(option) Option;
#endif
	%newobject Option_get;
	LassoStringList *Option;

	/* Constructor, Destructor & Static Methods */

	LassoDiscoOptions();

	~LassoDiscoOptions();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes Implementations */

/* Option */
#define LassoDiscoOptions_get_Option(self) get_string_list((self)->Option)
#define LassoDiscoOptions_Option_get(self) get_string_list((self)->Option)
#define LassoDiscoOptions_set_Option(self, value) set_string_list(&(self)->Option, (value))
#define LassoDiscoOptions_Option_set(self, value) set_string_list(&(self)->Option, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoDiscoOptions lasso_disco_options_new
#define delete_LassoDiscoOptions(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoDiscoOptions_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * disco:Query
 ***********************************************************************/


#ifndef SWIG_PHP_RENAMES
%rename(DiscoQuery) LassoDiscoQuery;
#endif
typedef struct {
	/* Attributes */

	char *id;
} LassoDiscoQuery;
%extend LassoDiscoQuery {
	/* Attributes */

#ifndef SWIG_PHP_RENAMES
	%rename(encryptedResourceId) EncryptedResourceID;
#endif
	%newobject EncryptedResourceID_get;
	LassoDiscoEncryptedResourceID *EncryptedResourceID;

#ifndef SWIG_PHP_RENAMES
	%rename(requestedServiceType) RequestedServiceType;
#endif
	%newobject RequestedServiceType_get;
	LassoNodeList *RequestedServiceType;

#ifndef SWIG_PHP_RENAMES
	%rename(resourceId) ResourceID;
#endif
	%newobject ResourceID_get;
	LassoDiscoResourceID *ResourceID;

	/* Constructor, Destructor & Static Methods */

	LassoDiscoQuery();

	~LassoDiscoQuery();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes Implementations */

/* EncryptedResourceID */
#define LassoDiscoQuery_get_EncryptedResourceID(self) get_node((self)->EncryptedResourceID)
#define LassoDiscoQuery_EncryptedResourceID_get(self) get_node((self)->EncryptedResourceID)
#define LassoDiscoQuery_set_EncryptedResourceID(self, value) set_node((gpointer *) &(self)->EncryptedResourceID, (value))
#define LassoDiscoQuery_EncryptedResourceID_set(self, value) set_node((gpointer *) &(self)->EncryptedResourceID, (value))

/* RequestedServiceType */
#define LassoDiscoQuery_get_RequestedServiceType(self) get_node_list((self)->RequestedServiceType)
#define LassoDiscoQuery_RequestedServiceType_get(self) get_node_list((self)->RequestedServiceType)
#define LassoDiscoQuery_set_RequestedServiceType(self, value) set_node_list(&(self)->RequestedServiceType, (value))
#define LassoDiscoQuery_RequestedServiceType_set(self, value) set_node_list(&(self)->RequestedServiceType, (value))

/* ResourceID */
#define LassoDiscoQuery_get_ResourceID(self) get_node((self)->ResourceID)
#define LassoDiscoQuery_ResourceID_get(self) get_node((self)->ResourceID)
#define LassoDiscoQuery_set_ResourceID(self, value) set_node((gpointer *) &(self)->ResourceID, (value))
#define LassoDiscoQuery_ResourceID_set(self, value) set_node((gpointer *) &(self)->ResourceID, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoDiscoQuery lasso_disco_query_new
#define delete_LassoDiscoQuery(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoDiscoQuery_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * disco:QueryResponse
 ***********************************************************************/


#ifndef SWIG_PHP_RENAMES
%rename(DiscoQueryResponse) LassoDiscoQueryResponse;
#endif
typedef struct {
	/* Attributes */

	char *id;
} LassoDiscoQueryResponse;
%extend LassoDiscoQueryResponse {
	/* Attributes */

#ifndef SWIG_PHP_RENAMES
	%rename(credentials) Credentials;
#endif
	%newobject Credentials_get;
	LassoDiscoCredentials *Credentials;

#ifndef SWIG_PHP_RENAMES
	%rename(resourceOffering) ResourceOffering;
#endif
	%newobject ResourceOffering_get;
	LassoNodeList *ResourceOffering;

#ifndef SWIG_PHP_RENAMES
	%rename(status) Status;
#endif
	%newobject Status_get;
	LassoUtilityStatus *Status;

	/* Constructor, Destructor & Static Methods */

	LassoDiscoQueryResponse(LassoUtilityStatus *status);

	~LassoDiscoQueryResponse();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes Implementations */

/* Credentials */
#define LassoDiscoQueryResponse_get_Credentials(self) get_node((self)->Credentials)
#define LassoDiscoQueryResponse_Credentials_get(self) get_node((self)->Credentials)
#define LassoDiscoQueryResponse_set_Credentials(self, value) set_node((gpointer *) &(self)->Credentials, (value))
#define LassoDiscoQueryResponse_Credentials_set(self, value) set_node((gpointer *) &(self)->Credentials, (value))

/* ResourceOffering */
#define LassoDiscoQueryResponse_get_ResourceOffering(self) get_node_list((self)->ResourceOffering)
#define LassoDiscoQueryResponse_ResourceOffering_get(self) get_node_list((self)->ResourceOffering)
#define LassoDiscoQueryResponse_set_ResourceOffering(self, value) set_node_list(&(self)->ResourceOffering, (value))
#define LassoDiscoQueryResponse_ResourceOffering_set(self, value) set_node_list(&(self)->ResourceOffering, (value))

/* Status */
#define LassoDiscoQueryResponse_get_Status(self) get_node((self)->Status)
#define LassoDiscoQueryResponse_Status_get(self) get_node((self)->Status)
#define LassoDiscoQueryResponse_set_Status(self, value) set_node((gpointer *) &(self)->Status, (value))
#define LassoDiscoQueryResponse_Status_set(self, value) set_node((gpointer *) &(self)->Status, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoDiscoQueryResponse lasso_disco_query_response_new
#define delete_LassoDiscoQueryResponse(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoDiscoQueryResponse_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * disco:RemoveEntry
 ***********************************************************************/


#ifndef SWIG_PHP_RENAMES
%rename(DiscoRemoveEntry) LassoDiscoRemoveEntry;
#endif
typedef struct {
	/* Attributes */

#ifndef SWIG_PHP_RENAMES
	%rename(entryId) entryID;
#endif
	char *entryID;
} LassoDiscoRemoveEntry;
%extend LassoDiscoRemoveEntry {
	/* Constructor, Destructor & Static Methods */

	LassoDiscoRemoveEntry(char *entryId);

	~LassoDiscoRemoveEntry();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Constructors, destructors & static methods implementations */

#define new_LassoDiscoRemoveEntry lasso_disco_remove_entry_new
#define delete_LassoDiscoRemoveEntry(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoDiscoRemoveEntry_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * disco:RequestedServiceType
 ***********************************************************************/


#ifndef SWIG_PHP_RENAMES
%rename(DiscoRequestedServiceType) LassoDiscoRequestedServiceType;
#endif
typedef struct {
	/* Attributes */

#ifndef SWIG_PHP_RENAMES
	%rename(serviceType) ServiceType;
#endif
	char *ServiceType;
} LassoDiscoRequestedServiceType;
%extend LassoDiscoRequestedServiceType {
	/* Attributes */

#ifndef SWIG_PHP_RENAMES
	%rename(options) Options;
#endif
	%newobject Options_get;
	LassoDiscoOptions *Options;

	/* Constructor, Destructor & Static Methods */

	LassoDiscoRequestedServiceType(char *serviceType);

	~LassoDiscoRequestedServiceType();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes Implementations */

/* Options */
#define LassoDiscoRequestedServiceType_get_Options(self) get_node((self)->Options)
#define LassoDiscoRequestedServiceType_Options_get(self) get_node((self)->Options)
#define LassoDiscoRequestedServiceType_set_Options(self, value) set_node((gpointer *) &(self)->Options, (value))
#define LassoDiscoRequestedServiceType_Options_set(self, value) set_node((gpointer *) &(self)->Options, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoDiscoRequestedServiceType lasso_disco_requested_service_type_new
#define delete_LassoDiscoRequestedServiceType(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoDiscoRequestedServiceType_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * disco:ResourceID
 ***********************************************************************/


#ifndef SWIG_PHP_RENAMES
%rename(DiscoResourceID) LassoDiscoResourceID;
#endif
typedef struct {
	/* Attributes */

	char *content;

	char *id;
} LassoDiscoResourceID;
%extend LassoDiscoResourceID {
	/* Constructor, Destructor & Static Methods */

	LassoDiscoResourceID(char *content);

	~LassoDiscoResourceID();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Constructors, destructors & static methods implementations */

#define new_LassoDiscoResourceID lasso_disco_resource_id_new
#define delete_LassoDiscoResourceID(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoDiscoResourceID_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * disco:ResourceOffering
 ***********************************************************************/


#ifndef SWIG_PHP_RENAMES
%rename(DiscoResourceOffering) LassoDiscoResourceOffering;
#endif
typedef struct {
	/* Attributes */

#ifndef SWIGPHP4
  /* XXX: SWIG 1.3.31 fails to compile the PHP 4 binding it generates if this
   * part is present */

#if !defined(SWIG_PHP_RENAMES) && !defined(SWIGCSHARP) && !defined(SWIGJAVA)
	/* "abstract" is a reserved word in PHP, C# and Java. */
	%rename(abstract) Abstract;
#endif
	char *Abstract;

#endif /* !SWIG_PHP4 */

#ifndef SWIG_PHP_RENAMES
	%rename(entryId) entryID;
#endif
	char *entryID;
} LassoDiscoResourceOffering;
%extend LassoDiscoResourceOffering {
	/* Attributes */

#ifndef SWIG_PHP_RENAMES
	%rename(encryptedResourceId) EncryptedResourceID;
#endif
	%newobject EncryptedResourceID_get;
	LassoDiscoEncryptedResourceID *EncryptedResourceID;

#ifndef SWIG_PHP_RENAMES
	%rename(options) Options;
#endif
	%newobject Options_get;
	LassoDiscoOptions *Options;

#ifndef SWIG_PHP_RENAMES
	%rename(resourceId) ResourceID;
#endif
	%newobject ResourceID_get;
	LassoDiscoResourceID *ResourceID;

#ifndef SWIG_PHP_RENAMES
	%rename(serviceInstance) ServiceInstance;
#endif
	%newobject ServiceInstance_get;
	LassoDiscoServiceInstance *ServiceInstance;

	/* Constructor, Destructor & Static Methods */

	LassoDiscoResourceOffering(LassoDiscoServiceInstance *serviceInstance);

	~LassoDiscoResourceOffering();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes Implementations */

/* EncryptedResourceID */
#define LassoDiscoResourceOffering_get_EncryptedResourceID(self) get_node((self)->EncryptedResourceID)
#define LassoDiscoResourceOffering_EncryptedResourceID_get(self) get_node((self)->EncryptedResourceID)
#define LassoDiscoResourceOffering_set_EncryptedResourceID(self, value) set_node((gpointer *) &(self)->EncryptedResourceID, (value))
#define LassoDiscoResourceOffering_EncryptedResourceID_set(self, value) set_node((gpointer *) &(self)->EncryptedResourceID, (value))

/* Options */
#define LassoDiscoResourceOffering_get_Options(self) get_node((self)->Options)
#define LassoDiscoResourceOffering_Options_get(self) get_node((self)->Options)
#define LassoDiscoResourceOffering_set_Options(self, value) set_node((gpointer *) &(self)->Options, (value))
#define LassoDiscoResourceOffering_Options_set(self, value) set_node((gpointer *) &(self)->Options, (value))

/* ResourceID */
#define LassoDiscoResourceOffering_get_ResourceID(self) get_node((self)->ResourceID)
#define LassoDiscoResourceOffering_ResourceID_get(self) get_node((self)->ResourceID)
#define LassoDiscoResourceOffering_set_ResourceID(self, value) set_node((gpointer *) &(self)->ResourceID, (value))
#define LassoDiscoResourceOffering_ResourceID_set(self, value) set_node((gpointer *) &(self)->ResourceID, (value))

/* ServiceInstance */
#define LassoDiscoResourceOffering_get_ServiceInstance(self) get_node((self)->ServiceInstance)
#define LassoDiscoResourceOffering_ServiceInstance_get(self) get_node((self)->ServiceInstance)
#define LassoDiscoResourceOffering_set_ServiceInstance(self, value) set_node((gpointer *) &(self)->ServiceInstance, (value))
#define LassoDiscoResourceOffering_ServiceInstance_set(self, value) set_node((gpointer *) &(self)->ServiceInstance, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoDiscoResourceOffering lasso_disco_resource_offering_new
#define delete_LassoDiscoResourceOffering(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoDiscoResourceOffering_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * disco:ServiceInstance
 ***********************************************************************/


#ifndef SWIG_PHP_RENAMES
%rename(DiscoServiceInstance) LassoDiscoServiceInstance;
#endif
typedef struct {
	/* Attributes */

#ifndef SWIG_PHP_RENAMES
	%rename(serviceType) ServiceType;
#endif
	char *ServiceType;

#ifndef SWIG_PHP_RENAMES
	%rename(providerId) ProviderID;
#endif
	char *ProviderID;
} LassoDiscoServiceInstance;
%extend LassoDiscoServiceInstance {
	/* Attributes */

#ifndef SWIG_PHP_RENAMES
	%rename(description) Description;
#endif
	%newobject Description_get;
	LassoNodeList *Description;

	/* Constructor, Destructor & Static Methods */

	LassoDiscoServiceInstance(char *serviceType, char *providerID,
				  LassoDiscoDescription *description);

	~LassoDiscoServiceInstance();

	void addDescription(LassoDiscoDescription *description) {
		if (LASSO_IS_DISCO_DESCRIPTION(description) == TRUE) {
			g_object_ref(description);
			self->Description = g_list_append(self->Description, description);
		}
	}

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes Implementations */

/* Description */
#define LassoDiscoServiceInstance_get_Description(self) get_node_list((self)->Description)
#define LassoDiscoServiceInstance_Description_get(self) get_node_list((self)->Description)
#define LassoDiscoServiceInstance_set_Description(self, value) set_node_list(&(self)->Description, (value))
#define LassoDiscoServiceInstance_Description_set(self, value) set_node_list(&(self)->Description, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoDiscoServiceInstance lasso_disco_service_instance_new
#define delete_LassoDiscoServiceInstance(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoDiscoServiceInstance_dump(self) lasso_node_dump(LASSO_NODE(self))

%}
