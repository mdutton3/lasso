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

%{

#include <lasso/id-wsf/discovery.h>
#include <lasso/id-wsf/interaction_profile_service.h>
#include <lasso/id-wsf/profile_service.h>
#include <lasso/xml/dst_new_data.h>
#include <lasso/xml/dst_modify.h>
#include <lasso/xml/dst_modify_response.h>
#include <lasso/xml/dst_query.h>
#include <lasso/xml/dst_query_response.h>
#include <lasso/xml/is_help.h>
#include <lasso/xml/is_inquiry.h>
#include <lasso/xml/is_inquiry_element.h>
#include <lasso/xml/is_interaction_request.h>
#include <lasso/xml/is_interaction_response.h>
#include <lasso/xml/is_interaction_statement.h>
#include <lasso/xml/is_item.h>
#include <lasso/xml/is_parameter.h>
#include <lasso/xml/is_redirect_request.h>
#include <lasso/xml/is_select.h>
#include <lasso/xml/is_text.h>
#include <lasso/xml/is_user_interaction.h>

%}


/***********************************************************************
 ***********************************************************************
 * Constants
 ***********************************************************************
 ***********************************************************************/


/* WSF prefix & href */
#ifndef SWIGPHP4
%rename(DISCO_HREF) LASSO_DISCO_HREF;
%rename(DISCO_PREFIX) LASSO_DISCO_PREFIX;
%rename(EP_HREF) LASSO_EP_HREF;
%rename(EP_PREFIX) LASSO_EP_PREFIX;
%rename(PP_HREF) LASSO_PP_HREF;
%rename(PP_PREFIX) LASSO_PP_PREFIX;
#endif
#define LASSO_DISCO_HREF   "urn:liberty:disco:2003-08"
#define LASSO_DISCO_PREFIX "disco"
#define LASSO_EP_HREF   "urn:liberty:ep:2003-08"
#define LASSO_EP_PREFIX "ep"
#define LASSO_PP_HREF   "urn:liberty:pp:2003-08"
#define LASSO_PP_PREFIX "pp"

/* WSF status code */
#ifndef SWIGPHP4
%rename(DST_STATUS_CODE_ACTION_NOT_AUTHORIZED) LASSO_DST_STATUS_CODE_ACTION_NOT_AUTHORIZED;
%rename(DST_STATUS_CODE_ACTION_NOT_SUPPORTED) LASSO_DST_STATUS_CODE_ACTION_NOT_SUPPORTED;
%rename(DST_STATUS_CODE_ALL_RETURNED) LASSO_DST_STATUS_CODE_ALL_RETURNED;
%rename(DST_STATUS_CODE_CHANGE_HISTORY_NOT_SUPPORTED) LASSO_DST_STATUS_CODE_CHANGE_HISTORY_NOT_SUPPORTED;
%rename(DST_STATUS_CODE_CHANGED_SINCE_RETURNS_ALL) LASSO_DST_STATUS_CODE_CHANGED_SINCE_RETURNS_ALL;
%rename(DST_STATUS_CODE_DATA_TOO_LONG) LASSO_DST_STATUS_CODE_DATA_TOO_LONG;
%rename(DST_STATUS_CODE_EXISTS_ALREADY) LASSO_DST_STATUS_CODE_EXISTS_ALREADY;
%rename(DST_STATUS_CODE_EXTENSION_NOT_SUPPORTED) LASSO_DST_STATUS_CODE_EXTENSION_NOT_SUPPORTED;
%rename(DST_STATUS_CODE_FAILED) LASSO_DST_STATUS_CODE_FAILED;
%rename(DST_STATUS_CODE_INVALID_DATA) LASSO_DST_STATUS_CODE_INVALID_DATA;
%rename(DST_STATUS_CODE_INVALID_RESOURCE_ID) LASSO_DST_STATUS_CODE_INVALID_RESOURCE_ID;
%rename(DST_STATUS_CODE_INVALID_SELECT) LASSO_DST_STATUS_CODE_INVALID_SELECT;
%rename(DST_STATUS_CODE_MISSING_NEW_DATA_ELEMENT) LASSO_DST_STATUS_CODE_MISSING_NEW_DATA_ELEMENT;
%rename(DST_STATUS_CODE_MISSING_RESOURCE_ID_ELEMENT) LASSO_DST_STATUS_CODE_MISSING_RESOURCE_ID_ELEMENT;
%rename(DST_STATUS_CODE_MISSING_SELECT) LASSO_DST_STATUS_CODE_MISSING_SELECT;
%rename(DST_STATUS_CODE_MODIFIED_SINCE) LASSO_DST_STATUS_CODE_MODIFIED_SINCE;
%rename(DST_STATUS_CODE_NO_MORE_ELEMENTS) LASSO_DST_STATUS_CODE_NO_MORE_ELEMENTS;
%rename(DST_STATUS_CODE_NO_MULTIPLE_ALLOWED) LASSO_DST_STATUS_CODE_NO_MULTIPLE_ALLOWED;
%rename(DST_STATUS_CODE_NO_MULTIPLE_RESOURCES) LASSO_DST_STATUS_CODE_NO_MULTIPLE_RESOURCES;
%rename(DST_STATUS_CODE_OK) LASSO_DST_STATUS_CODE_OK;
%rename(DST_STATUS_CODE_TIME_OUT) LASSO_DST_STATUS_CODE_TIME_OUT;
%rename(DST_STATUS_CODE_UNEXPECTED_ERROR) LASSO_DST_STATUS_CODE_UNEXPECTED_ERROR;
#endif
#define LASSO_DST_STATUS_CODE_ACTION_NOT_AUTHORIZED "ActionNotAuthorized"
#define LASSO_DST_STATUS_CODE_ACTION_NOT_SUPPORTED "ActionNotSupported"
#define LASSO_DST_STATUS_CODE_ALL_RETURNED "AllReturned"
#define LASSO_DST_STATUS_CODE_CHANGE_HISTORY_NOT_SUPPORTED "ChangeHistoryNotSupported"
#define LASSO_DST_STATUS_CODE_CHANGED_SINCE_RETURNS_ALL "ChangedSinceReturnsAll"
#define LASSO_DST_STATUS_CODE_DATA_TOO_LONG "DataTooLong"
#define LASSO_DST_STATUS_CODE_EXISTS_ALREADY "ExistsAlready"
#define LASSO_DST_STATUS_CODE_EXTENSION_NOT_SUPPORTED "ExtensionNotSupported"
#define LASSO_DST_STATUS_CODE_FAILED "Failed"
#define LASSO_DST_STATUS_CODE_INVALID_DATA "InvalidData"
#define LASSO_DST_STATUS_CODE_INVALID_RESOURCE_ID "InvalidResourceID"
#define LASSO_DST_STATUS_CODE_INVALID_SELECT "InvalidSelect"
#define LASSO_DST_STATUS_CODE_MISSING_NEW_DATA_ELEMENT "MissingNewDataElement"
#define LASSO_DST_STATUS_CODE_MISSING_RESOURCE_ID_ELEMENT "MissingResourceIDElement"
#define LASSO_DST_STATUS_CODE_MISSING_SELECT "MissingSelect"
#define LASSO_DST_STATUS_CODE_MODIFIED_SINCE "ModifiedSince"
#define LASSO_DST_STATUS_CODE_NO_MORE_ELEMENTS "NoMoreElements"
#define LASSO_DST_STATUS_CODE_NO_MULTIPLE_ALLOWED "NoMultipleAllowed"
#define LASSO_DST_STATUS_CODE_NO_MULTIPLE_RESOURCES "NoMultipleResources"
#define LASSO_DST_STATUS_CODE_OK "OK"
#define LASSO_DST_STATUS_CODE_TIME_OUT "TimeOut"
#define LASSO_DST_STATUS_CODE_UNEXPECTED_ERROR "UnexpectedError"


/***********************************************************************
 ***********************************************************************
 * XML Elements in Discovery Namespace
 ***********************************************************************
 ***********************************************************************/


/***********************************************************************
 * disco:Credentials
 ***********************************************************************/


#ifndef SWIGPHP4
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


#ifndef SWIGPHP4
%rename(DiscoDescription) LassoDiscoDescription;
#endif
typedef struct {
	/* Attributes */

#ifndef SWIGPHP4
	%rename(endpoint) Endpoint;
#endif
	char *Endpoint;

	char *id;

#ifndef SWIGPHP4
	%rename(serviceNameRef) ServiceNameRef;
#endif
	char *ServiceNameRef;

#ifndef SWIGPHP4
	%rename(soapAction) SoapAction;
#endif
	char *SoapAction;

#ifndef SWIGPHP4
	%rename(wsdlUri) WsdlURI;
#endif
	char *WsdlURI;
} LassoDiscoDescription;
%extend LassoDiscoDescription {
	/* Attributes */

#ifndef SWIGPHP4
	%rename(credentialRef) CredentialRef;
#endif
	%newobject CredentialRef_get;
	LassoStringList *CredentialRef;

#ifndef SWIGPHP4
	%rename(securityMechId) SecurityMechID;
#endif
	%newobject SecurityMechID_get;
	LassoStringList *SecurityMechID;

	/* Constructor, Destructor & Static Methods */

	LassoDiscoDescription(
			char *securityMechID, char *wsdlURI, char *serviceNameRef,
			char *endpoint, char *soapAction);

	~LassoDiscoDescription();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
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

#define new_LassoDiscoDescription lasso_disco_description_new
#define delete_LassoDiscoDescription(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoDiscoDescription_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * disco:EncryptedResourceID
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(DiscoEncryptedResourceID) LassoDiscoEncryptedResourceID;
#endif
typedef struct {
} LassoDiscoEncryptedResourceID;
%extend LassoDiscoEncryptedResourceID {
	/* Attributes */

	/* FIXME: Missing from Lasso. */
/* 	LassoXencEncryptedData *EncryptedData; */
/* 	LassoXencEncryptedKey *EncryptedKey; */

	/* Constructor, Destructor & Static Methods */

	LassoDiscoEncryptedResourceID();

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


#ifndef SWIGPHP4
%rename(DiscoInsertEntry) LassoDiscoInsertEntry;
#endif
typedef struct {
} LassoDiscoInsertEntry;
%extend LassoDiscoInsertEntry {
	/* Attributes */

	%newobject any_get;
	LassoNodeList *any;

#ifndef SWIGPHP4
	%rename(resourceOffering) ResourceOffering;
#endif
	%newobject ResourceOffering_get;
	LassoDiscoResourceOffering *ResourceOffering;

	/* Constructor, Destructor & Static Methods */

	LassoDiscoInsertEntry();

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


#ifndef SWIGPHP4
%rename(DiscoModify) LassoDiscoModify;
#endif
typedef struct {
	/* Attributes */

	char *id;
} LassoDiscoModify;
%extend LassoDiscoModify {
	/* Attributes */

#ifndef SWIGPHP4
	%rename(encryptedResourceId) EncryptedResourceID;
#endif
	%newobject EncryptedResourceID_get;
	LassoDiscoEncryptedResourceID *EncryptedResourceID;

#ifndef SWIGPHP4
	%rename(insertEntry) InsertEntry;
#endif
	%newobject InsertEntry_get;
	LassoNodeList *InsertEntry;

#ifndef SWIGPHP4
	%rename(removeEntry) RemoveEntry;
#endif
	%newobject RemoveEntry_get;
	LassoNodeList *RemoveEntry;

#ifndef SWIGPHP4
	%rename(resourceId) ResourceID;
#endif
	%newobject ResourceID_get;
	LassoDiscoResourceID *ResourceID;

	/* Constructor, Destructor & Static Methods */

	LassoDiscoModify();

	~LassoDiscoModify();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes Implementations */

/* EncryptedResourceID */
#define LassoDiscoModify_get_EncryptedResourceID(self) get_node((self)->EncryptedResourceID)
#define LassoDiscoModify_EncryptedResourceID_get(self) get_node((self)->EncryptedResourceID)
#define LassoDiscoModify_set_EncryptedResourceID(self, value) set_node((gpointer *) &(self)->EncryptedResourceID, (value))
#define LassoDiscoModify_EncryptedResourceID_set(self, value) set_node((gpointer *) &(self)->EncryptedResourceID, (value))

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

/* Constructors, destructors & static methods implementations */

#define new_LassoDiscoModify lasso_disco_modify_new
#define delete_LassoDiscoModify(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoDiscoModify_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * disco:ModifyResponse
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(DiscoModifyResponse) LassoDiscoModifyResponse;
#endif
typedef struct {
	/* Attributes */

	char *id;

#ifndef SWIGPHP4
	%rename(newEntryIds) newEntryIDs;
#endif
	char *newEntryIDs;
} LassoDiscoModifyResponse;
%extend LassoDiscoModifyResponse {
	/* Attributes */

	/* FIXME: Missing from Lasso. */
/* #ifndef SWIGPHP4 */
/* 	%rename(extension) Extension; */
/* #endif */
/* 	%newobject Extension_get; */
/* 	xmlNode *Extension; */

#ifndef SWIGPHP4
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


#ifndef SWIGPHP4
%rename(DiscoOptions) LassoDiscoOptions;
#endif
typedef struct {
} LassoDiscoOptions;
%extend LassoDiscoOptions {
	/* Attributes */

#ifndef SWIGPHP4
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


#ifndef SWIGPHP4
%rename(DiscoQuery) LassoDiscoQuery;
#endif
typedef struct {
	/* Attributes */

	char *id;
} LassoDiscoQuery;
%extend LassoDiscoQuery {
	/* Attributes */

#ifndef SWIGPHP4
	%rename(encryptedResourceId) EncryptedResourceID;
#endif
	%newobject EncryptedResourceID_get;
	LassoDiscoEncryptedResourceID *EncryptedResourceID;

#ifndef SWIGPHP4
	%rename(requestedServiceType) RequestedServiceType;
#endif
	%newobject RequestedServiceType_get;
	LassoNodeList *RequestedServiceType;

#ifndef SWIGPHP4
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


#ifndef SWIGPHP4
%rename(DiscoQueryResponse) LassoDiscoQueryResponse;
#endif
typedef struct {
	/* Attributes */

	char *id;
} LassoDiscoQueryResponse;
%extend LassoDiscoQueryResponse {
	/* Attributes */

#ifndef SWIGPHP4
	%rename(credentials) Credentials;
#endif
	%newobject Credentials_get;
	LassoDiscoCredentials *Credentials;

#ifndef SWIGPHP4
	%rename(resourceOffering) ResourceOffering;
#endif
	%newobject ResourceOffering_get;
	LassoNodeList *ResourceOffering;

#ifndef SWIGPHP4
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


#ifndef SWIGPHP4
%rename(DiscoRemoveEntry) LassoDiscoRemoveEntry;
#endif
typedef struct {
	/* Attributes */

#ifndef SWIGPHP4
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


#ifndef SWIGPHP4
%rename(DiscoRequestedServiceType) LassoDiscoRequestedServiceType;
#endif
typedef struct {
	/* Attributes */

#ifndef SWIGPHP4
	%rename(serviceType) ServiceType;
#endif
	char *ServiceType;
} LassoDiscoRequestedServiceType;
%extend LassoDiscoRequestedServiceType {
	/* Attributes */

#ifndef SWIGPHP4
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


#ifndef SWIGPHP4
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


#ifndef SWIGPHP4
%rename(DiscoResourceOffering) LassoDiscoResourceOffering;
#endif
typedef struct {
	/* Attributes */

#if !defined(SWIGPHP4) && !defined(SWIGCSHARP)
	/* "abstract" is a reserved word in C#. */
	%rename(abstract) Abstract;
#endif
	char *Abstract;

#ifndef SWIGPHP4
	%rename(entryId) entryID;
#endif
	char *entryID;
} LassoDiscoResourceOffering;
%extend LassoDiscoResourceOffering {
	/* Attributes */

#ifndef SWIGPHP4
	%rename(encryptedResourceId) EncryptedResourceID;
#endif
	%newobject EncryptedResourceID_get;
	LassoDiscoEncryptedResourceID *EncryptedResourceID;

#ifndef SWIGPHP4
	%rename(options) Options;
#endif
	%newobject Options_get;
	LassoDiscoOptions *Options;

#ifndef SWIGPHP4
	%rename(resourceId) ResourceID;
#endif
	%newobject ResourceID_get;
	LassoDiscoResourceID *ResourceID;

#ifndef SWIGPHP4
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


#ifndef SWIGPHP4
%rename(DiscoServiceInstance) LassoDiscoServiceInstance;
#endif
typedef struct {
	/* Attributes */

#ifndef SWIGPHP4
	%rename(serviceType) ServiceType;
#endif
	char *ServiceType;

#ifndef SWIGPHP4
	%rename(ProviderID) ProviderID;
#endif
	char *ProviderID;
} LassoDiscoServiceInstance;
%extend LassoDiscoServiceInstance {
	/* Attributes */

#ifndef SWIGPHP4
	%rename(description) Description;
#endif
	%newobject Description_get;
	LassoNodeList *Description;

	/* Constructor, Destructor & Static Methods */

	LassoDiscoServiceInstance(char *serviceType, char *providerID,
				  LassoDiscoDescription *description);

	~LassoDiscoServiceInstance();

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


/***********************************************************************
 ***********************************************************************
 * XML Elements in Data Services Template Namespace
 ***********************************************************************
 ***********************************************************************/


/***********************************************************************
 * dst:Data
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(DstData) LassoDstData;
#endif
typedef struct {
	/* Attributes */

	char *id;

#ifndef SWIGPHP4
	%rename(itemIdRef) itemIDRef;
#endif
	char *itemIDRef;
} LassoDstData;
%extend LassoDstData {
	/* Attributes */

	%newobject any_get;
	LassoStringList *any;

	/* Constructor, Destructor & Static Methods */

	LassoDstData();

	~LassoDstData();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes Implementations */

/* any */
#define LassoDstData_get_any(self) get_xml_list((self)->any)
#define LassoDstData_any_get(self) get_xml_list((self)->any)
#define LassoDstData_set_any(self, value) set_xml_list(&(self)->any, (value))
#define LassoDstData_any_set(self, value) set_xml_list(&(self)->any, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoDstData lasso_dst_data_new
#define delete_LassoDstData(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoDstData_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * dst:Modification
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(DstModification) LassoDstModification;
#endif
typedef struct {
	/* Attributes */

	char *id;

	char *notChangedSince;

	gboolean overrideAllowed;

#ifndef SWIGPHP4
	%rename(select) Select;
#endif
	char *Select;
} LassoDstModification;
%extend LassoDstModification {
	/* Attributes */

#ifndef SWIGPHP4
	%rename(newData) NewData;
#endif
	%newobject NewData_get;
	LassoDstNewData *NewData;

	/* Constructor, Destructor & Static Methods */

	LassoDstModification(char *select);

	~LassoDstModification();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes Implementations */

/* NewData */
#define LassoDstModification_get_NewData(self) get_node((self)->NewData)
#define LassoDstModification_NewData_get(self) get_node((self)->NewData)
#define LassoDstModification_set_NewData(self, value) set_node((gpointer *) &(self)->NewData, (value))
#define LassoDstModification_NewData_set(self, value) set_node((gpointer *) &(self)->NewData, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoDstModification lasso_dst_modification_new
#define delete_LassoDstModification(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoDstModification_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * dst:Modify
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(DstModify) LassoDstModify;
#endif
typedef struct {
	/* Attributes */

	char *id;

#ifndef SWIGPHP4
	%rename(itemId) itemID;
#endif
	char *itemID;
} LassoDstModify;
%extend LassoDstModify {
	/* Attributes */

#ifndef SWIGPHP4
	%rename(encryptedResourceId) EncryptedResourceID;
#endif
	%newobject EncryptedResourceID_get;
	LassoDiscoEncryptedResourceID *EncryptedResourceID;

#ifndef SWIGPHP4
	%rename(extension) Extension;
#endif
	%newobject Extension_get;
	LassoStringList *Extension;

#ifndef SWIGPHP4
	%rename(modification) Modification;
#endif
	%newobject Modification_get;
	LassoNodeList *Modification;

#ifndef SWIGPHP4
	%rename(resourceId) ResourceID;
#endif
	%newobject ResourceID_get;
	LassoDiscoResourceID *ResourceID;

	/* Constructor, Destructor & Static Methods */

	LassoDstModify(LassoDstModification *modification);

	~LassoDstModify();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes Implementations */

/* EncryptedResourceID */
#define LassoDstModify_get_EncryptedResourceID(self) get_node((self)->EncryptedResourceID)
#define LassoDstModify_EncryptedResourceID_get(self) get_node((self)->EncryptedResourceID)
#define LassoDstModify_set_EncryptedResourceID(self, value) set_node((gpointer *) &(self)->EncryptedResourceID, (value))
#define LassoDstModify_EncryptedResourceID_set(self, value) set_node((gpointer *) &(self)->EncryptedResourceID, (value))

/* Extension */
#define LassoDstModify_get_Extension(self) get_xml_list((self)->Extension)
#define LassoDstModify_Extension_get(self) get_xml_list((self)->Extension)
#define LassoDstModify_set_Extension(self, value) set_xml_list(&(self)->Extension, (value))
#define LassoDstModify_Extension_set(self, value) set_xml_list(&(self)->Extension, (value))

/* Modification */
#define LassoDstModify_get_Modification(self) get_node_list((self)->Modification)
#define LassoDstModify_Modification_get(self) get_node_list((self)->Modification)
#define LassoDstModify_set_Modification(self, value) set_node_list(&(self)->Modification, (value))
#define LassoDstModify_Modification_set(self, value) set_node_list(&(self)->Modification, (value))

/* ResourceID */
#define LassoDstModify_get_ResourceID(self) get_node((self)->ResourceID)
#define LassoDstModify_ResourceID_get(self) get_node((self)->ResourceID)
#define LassoDstModify_set_ResourceID(self, value) set_node((gpointer *) &(self)->ResourceID, (value))
#define LassoDstModify_ResourceID_set(self, value) set_node((gpointer *) &(self)->ResourceID, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoDstModify lasso_dst_modify_new
#define delete_LassoDstModify(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoDstModify_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * dst:ModifyResponse
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(DstModifyResponse) LassoDstModifyResponse;
#endif
typedef struct {
	/* Attributes */

	char *id;

#ifndef SWIGPHP4
	%rename(itemIdRef) itemIDRef;
#endif
	char *itemIDRef;

	char *timeStamp;
} LassoDstModifyResponse;
%extend LassoDstModifyResponse {
	/* Attributes */

#ifndef SWIGPHP4
	%rename(extension) Extension;
#endif
	%newobject Extension_get;
	LassoStringList *Extension;

#ifndef SWIGPHP4
	%rename(status) Status;
#endif
	%newobject Status_get;
	LassoUtilityStatus *Status;

	/* Constructor, Destructor & Static Methods */

	LassoDstModifyResponse(LassoUtilityStatus *status);

	~LassoDstModifyResponse();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes Implementations */

/* Extension */
#define LassoDstModifyResponse_get_Extension(self) get_xml_list((self)->Extension)
#define LassoDstModifyResponse_Extension_get(self) get_xml_list((self)->Extension)
#define LassoDstModifyResponse_set_Extension(self, value) set_xml_list(&(self)->Extension, (value))
#define LassoDstModifyResponse_Extension_set(self, value) set_xml_list(&(self)->Extension, (value))

/* Status */
#define LassoDstModifyResponse_get_Status(self) get_node((self)->Status)
#define LassoDstModifyResponse_Status_get(self) get_node((self)->Status)
#define LassoDstModifyResponse_set_Status(self, value) set_node((gpointer *) &(self)->Status, (value))
#define LassoDstModifyResponse_Status_set(self, value) set_node((gpointer *) &(self)->Status, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoDstModifyResponse lasso_dst_modify_response_new
#define delete_LassoDstModifyResponse(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoDstModifyResponse_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * dst:NewData
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(DstNewData) LassoDstNewData;
#endif
typedef struct {
} LassoDstNewData;
%extend LassoDstNewData {
	/* Attributes */

	%newobject any_get;
	LassoStringList *any;

	/* Constructor, Destructor & Static Methods */

	LassoDstNewData();

	~LassoDstNewData();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes Implementations */

/* any */
#define LassoDstNewData_get_any(self) get_xml_list((self)->any)
#define LassoDstNewData_any_get(self) get_xml_list((self)->any)
#define LassoDstNewData_set_any(self, value) set_xml_list(&(self)->any, (value))
#define LassoDstNewData_any_set(self, value) set_xml_list(&(self)->any, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoDstNewData lasso_dst_new_data_new
#define delete_LassoDstNewData(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoDstNewData_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * dst:Query
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(DstQuery) LassoDstQuery;
#endif
typedef struct {
	/* Attributes */

	char *id;

#ifndef SWIGPHP4
	%rename(itemId) itemID;
#endif
	char *itemID;
} LassoDstQuery;
%extend LassoDstQuery {
	/* Attributes */

#ifndef SWIGPHP4
	%rename(encryptedResourceId) EncryptedResourceID;
#endif
	%newobject EncryptedResourceID_get;
	LassoDiscoEncryptedResourceID *EncryptedResourceID;

#ifndef SWIGPHP4
	%rename(extension) Extension;
#endif
	%newobject Extension_get;
	LassoStringList *Extension;

#ifndef SWIGPHP4
	%rename(queryItem) QueryItem;
#endif
	%newobject QueryItem_get;
	LassoNodeList *QueryItem;

#ifndef SWIGPHP4
	%rename(resourceId) ResourceID;
#endif
	%newobject ResourceID_get;
	LassoDiscoResourceID *ResourceID;

	/* Constructor, Destructor & Static Methods */

	LassoDstQuery(LassoDstQueryItem *queryItem);

	~LassoDstQuery();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes Implementations */

/* EncryptedResourceID */
#define LassoDstQuery_get_EncryptedResourceID(self) get_node((self)->EncryptedResourceID)
#define LassoDstQuery_EncryptedResourceID_get(self) get_node((self)->EncryptedResourceID)
#define LassoDstQuery_set_EncryptedResourceID(self, value) set_node((gpointer *) &(self)->EncryptedResourceID, (value))
#define LassoDstQuery_EncryptedResourceID_set(self, value) set_node((gpointer *) &(self)->EncryptedResourceID, (value))

/* Extension */
#define LassoDstQuery_get_Extension(self) get_xml_list((self)->Extension)
#define LassoDstQuery_Extension_get(self) get_xml_list((self)->Extension)
#define LassoDstQuery_set_Extension(self, value) set_xml_list(&(self)->Extension, (value))
#define LassoDstQuery_Extension_set(self, value) set_xml_list(&(self)->Extension, (value))

/* QueryItem */
#define LassoDstQuery_get_QueryItem(self) get_node_list((self)->QueryItem)
#define LassoDstQuery_QueryItem_get(self) get_node_list((self)->QueryItem)
#define LassoDstQuery_set_QueryItem(self, value) set_node_list(&(self)->QueryItem, (value))
#define LassoDstQuery_QueryItem_set(self, value) set_node_list(&(self)->QueryItem, (value))

/* ResourceID */
#define LassoDstQuery_get_ResourceID(self) get_node((self)->ResourceID)
#define LassoDstQuery_ResourceID_get(self) get_node((self)->ResourceID)
#define LassoDstQuery_set_ResourceID(self, value) set_node((gpointer *) &(self)->ResourceID, (value))
#define LassoDstQuery_ResourceID_set(self, value) set_node((gpointer *) &(self)->ResourceID, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoDstQuery lasso_dst_query_new
#define delete_LassoDstQuery(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoDstQuery_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * dst:QueryItem
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(DstQueryItem) LassoDstQueryItem;
#endif
typedef struct {
	/* Attributes */

	char *changedSince;

	char *id;

	gboolean includeCommonAttributes;

#ifndef SWIGPHP4
	%rename(itemId) itemID;
#endif
	char *itemID;

#ifndef SWIGPHP4
	%rename(select) Select;
#endif
	char *Select;
} LassoDstQueryItem;
%extend LassoDstQueryItem {
	/* Constructor, Destructor & Static Methods */

	LassoDstQueryItem(char *select);

	~LassoDstQueryItem();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Constructors, destructors & static methods implementations */

#define new_LassoDstQueryItem lasso_dst_query_item_new
#define delete_LassoDstQueryItem(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoDstQueryItem_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * dst:QueryResponse
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(DstQueryResponse) LassoDstQueryResponse;
#endif
typedef struct {
	/* Attributes */

	char *id;

#ifndef SWIGPHP4
	%rename(itemIdRef) itemIDRef;
#endif
	char *itemIDRef;

	char *timeStamp;
} LassoDstQueryResponse;
%extend LassoDstQueryResponse {
	/* Attributes */

#ifndef SWIGPHP4
	%rename(data) Data;
#endif
	%newobject Data_get;
	LassoNodeList *Data;

#ifndef SWIGPHP4
	%rename(extension) Extension;
#endif
	%newobject Extension_get;
	LassoStringList *Extension;

#ifndef SWIGPHP4
	%rename(status) Status;
#endif
	%newobject Status_get;
	LassoUtilityStatus *Status;

	/* Constructor, Destructor & Static Methods */

	LassoDstQueryResponse(LassoUtilityStatus *status);

	~LassoDstQueryResponse();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes Implementations */

/* Data */
#define LassoDstQueryResponse_get_Data(self) get_node_list((self)->Data)
#define LassoDstQueryResponse_Data_get(self) get_node_list((self)->Data)
#define LassoDstQueryResponse_set_Data(self, value) set_node_list(&(self)->Data, (value))
#define LassoDstQueryResponse_Data_set(self, value) set_node_list(&(self)->Data, (value))

/* Extension */
#define LassoDstQueryResponse_get_Extension(self) get_xml_list((self)->Extension)
#define LassoDstQueryResponse_Extension_get(self) get_xml_list((self)->Extension)
#define LassoDstQueryResponse_set_Extension(self, value) set_xml_list(&(self)->Extension, (value))
#define LassoDstQueryResponse_Extension_set(self, value) set_xml_list(&(self)->Extension, (value))

/* Status */
#define LassoDstQueryResponse_get_Status(self) get_node((self)->Status)
#define LassoDstQueryResponse_Status_get(self) get_node((self)->Status)
#define LassoDstQueryResponse_set_Status(self, value) set_node((gpointer *) &(self)->Status, (value))
#define LassoDstQueryResponse_Status_set(self, value) set_node((gpointer *) &(self)->Status, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoDstQueryResponse lasso_dst_query_response_new
#define delete_LassoDstQueryResponse(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoDstQueryResponse_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 ***********************************************************************
 * XML Elements in Interaction Services Namespace
 ***********************************************************************
 ***********************************************************************/


/***********************************************************************
 * is:Help
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(IsHelp) LassoIsHelp;
#endif
typedef struct {
	/* Attributes */

	char *label;

	char *link;

	char *moreLink;
} LassoIsHelp;
%extend LassoIsHelp {
	/* Constructor, Destructor & Static Methods */

	LassoIsHelp();

	~LassoIsHelp();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Constructors, destructors & static methods implementations */

#define new_LassoIsHelp lasso_is_help_new
#define delete_LassoIsHelp(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoIsHelp_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * is:Inquiry
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(IsInquiry) LassoIsInquiry;
#endif
typedef struct {
	/* Attributes */

	char *id;

	char *title;
} LassoIsInquiry;
%extend LassoIsInquiry {
	/* Attributes */

#ifndef SWIGPHP4
	%rename(confirm) Confirm;
#endif
	%newobject Confirm_get;
	LassoNodeList *Confirm;

#ifndef SWIGPHP4
	%rename(help) Help;
#endif
	%newobject Help_get;
	LassoIsHelp *Help;

#ifndef SWIGPHP4
	%rename(select) Select;
#endif
	%newobject Select_get;
	LassoNodeList *Select;

#ifndef SWIGPHP4
	%rename(text) Text;
#endif
	%newobject Text_get;
	LassoNodeList *Text;

	/* Constructor, Destructor & Static Methods */

	LassoIsInquiry();

	~LassoIsInquiry();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes Implementations */

/* Confirm */
#define LassoIsInquiry_get_Confirm(self) get_node_list((self)->Confirm)
#define LassoIsInquiry_Confirm_get(self) get_node_list((self)->Confirm)
#define LassoIsInquiry_set_Confirm(self, value) set_node_list(&(self)->Confirm, (value))
#define LassoIsInquiry_Confirm_set(self, value) set_node_list(&(self)->Confirm, (value))

/* Help */
#define LassoIsInquiry_get_Help(self) get_node((self)->Help)
#define LassoIsInquiry_Help_get(self) get_node((self)->Help)
#define LassoIsInquiry_set_Help(self, value) set_node((gpointer *) &(self)->Help, (value))
#define LassoIsInquiry_Help_set(self, value) set_node((gpointer *) &(self)->Help, (value))

/* Select */
#define LassoIsInquiry_get_Select(self) get_node_list((self)->Select)
#define LassoIsInquiry_Select_get(self) get_node_list((self)->Select)
#define LassoIsInquiry_set_Select(self, value) set_node_list(&(self)->Select, (value))
#define LassoIsInquiry_Select_set(self, value) set_node_list(&(self)->Select, (value))

/* Text */
#define LassoIsInquiry_get_Text(self) get_node_list((self)->Text)
#define LassoIsInquiry_Text_get(self) get_node_list((self)->Text)
#define LassoIsInquiry_set_Text(self, value) set_node_list(&(self)->Text, (value))
#define LassoIsInquiry_Text_set(self, value) set_node_list(&(self)->Text, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoIsInquiry lasso_is_inquiry_new
#define delete_LassoIsInquiry(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoIsInquiry_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * is:InquiryElement
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(IsInquiryElement) LassoIsInquiryElement;
#endif
typedef struct {
	/* Attributes */

#ifndef SWIGPHP4
	%rename(hint) Hint;
#endif
	char *Hint;

#ifndef SWIGPHP4
	%rename(Label) Label;
#endif
	char *Label;

	char *name;

#ifndef SWIGPHP4
	%rename(value) Value;
#endif
	char *Value;
} LassoIsInquiryElement;
%extend LassoIsInquiryElement {
	/* Attributes */

#ifndef SWIGPHP4
	%rename(help) Help;
#endif
	%newobject Help_get;
	LassoIsHelp *Help;

	/* Constructor, Destructor & Static Methods */

	LassoIsInquiryElement(char *name);

	~LassoIsInquiryElement();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes Implementations */

/* Help */
#define LassoIsInquiryElement_get_Help(self) get_node((self)->Help)
#define LassoIsInquiryElement_Help_get(self) get_node((self)->Help)
#define LassoIsInquiryElement_set_Help(self, value) set_node((gpointer *) &(self)->Help, (value))
#define LassoIsInquiryElement_Help_set(self, value) set_node((gpointer *) &(self)->Help, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoIsInquiryElement lasso_is_inquiry_element_new
#define delete_LassoIsInquiryElement(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoIsInquiryElement_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * is:InteractionRequest
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(IsInteractionRequest) LassoIsInteractionRequest;
#endif
typedef struct {
	/* Attributes */

	char *id;

	/* FIXME: Missing from Lasso. */
	/* KeyInfo */

	char *language;

	int maxInteractTime;

	/* FIXME: Missing from Lasso. */
	/* signed */
} LassoIsInteractionRequest;
%extend LassoIsInteractionRequest {
	/* Attributes */

#ifndef SWIGPHP4
	%rename(encryptedResourceId) EncryptedResourceID;
#endif
	%newobject EncryptedResourceID_get;
	LassoDiscoEncryptedResourceID *EncryptedResourceID;

#ifndef SWIGPHP4
	%rename(inquiry) Inquiry;
#endif
	%newobject Inquiry_get;
	LassoNodeList *Inquiry;

#ifndef SWIGPHP4
	%rename(resourceId) ResourceID;
#endif
	%newobject ResourceID_get;
	LassoDiscoResourceID *ResourceID;

	/* Constructor, Destructor & Static Methods */

	LassoIsInteractionRequest();

	~LassoIsInteractionRequest();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes Implementations */

/* EncryptedResourceID */
#define LassoIsInteractionRequest_get_EncryptedResourceID(self) get_node((self)->EncryptedResourceID)
#define LassoIsInteractionRequest_EncryptedResourceID_get(self) get_node((self)->EncryptedResourceID)
#define LassoIsInteractionRequest_set_EncryptedResourceID(self, value) set_node((gpointer *) &(self)->EncryptedResourceID, (value))
#define LassoIsInteractionRequest_EncryptedResourceID_set(self, value) set_node((gpointer *) &(self)->EncryptedResourceID, (value))

/* Inquiry */
#define LassoIsInteractionRequest_get_Inquiry(self) get_node_list((self)->Inquiry)
#define LassoIsInteractionRequest_Inquiry_get(self) get_node_list((self)->Inquiry)
#define LassoIsInteractionRequest_set_Inquiry(self, value) set_node_list(&(self)->Inquiry, (value))
#define LassoIsInteractionRequest_Inquiry_set(self, value) set_node_list(&(self)->Inquiry, (value))

/* ResourceID */
#define LassoIsInteractionRequest_get_ResourceID(self) get_node((self)->ResourceID)
#define LassoIsInteractionRequest_ResourceID_get(self) get_node((self)->ResourceID)
#define LassoIsInteractionRequest_set_ResourceID(self, value) set_node((gpointer *) &(self)->ResourceID, (value))
#define LassoIsInteractionRequest_ResourceID_set(self, value) set_node((gpointer *) &(self)->ResourceID, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoIsInteractionRequest lasso_is_interaction_request_new
#define delete_LassoIsInteractionRequest(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoIsInteractionRequest_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * is:InteractionResponse
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(IsInteractionResponse) LassoIsInteractionResponse;
#endif
typedef struct {
} LassoIsInteractionResponse;
%extend LassoIsInteractionResponse {
	/* Attributes */

#ifndef SWIGPHP4
	%rename(interactionStatement) InteractionStatement;
#endif
	%newobject InteractionStatement_get;
	LassoNodeList *InteractionStatement;

#ifndef SWIGPHP4
	%rename(parameter) Parameter;
#endif
	%newobject Parameter_get;
	LassoNodeList *Parameter;

#ifndef SWIGPHP4
	%rename(status) Status;
#endif
	%newobject Status_get;
	LassoUtilityStatus *Status;

	/* Constructor, Destructor & Static Methods */

	LassoIsInteractionResponse(LassoUtilityStatus *status);

	~LassoIsInteractionResponse();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes Implementations */

/* InteractionStatement */
#define LassoIsInteractionResponse_get_InteractionStatement(self) get_node_list((self)->InteractionStatement)
#define LassoIsInteractionResponse_InteractionStatement_get(self) get_node_list((self)->InteractionStatement)
#define LassoIsInteractionResponse_set_InteractionStatement(self, value) set_node_list(&(self)->InteractionStatement, (value))
#define LassoIsInteractionResponse_InteractionStatement_set(self, value) set_node_list(&(self)->InteractionStatement, (value))

/* Parameter */
#define LassoIsInteractionResponse_get_Parameter(self) get_node_list((self)->Parameter)
#define LassoIsInteractionResponse_Parameter_get(self) get_node_list((self)->Parameter)
#define LassoIsInteractionResponse_set_Parameter(self, value) set_node_list(&(self)->Parameter, (value))
#define LassoIsInteractionResponse_Parameter_set(self, value) set_node_list(&(self)->Parameter, (value))

/* Status */
#define LassoIsInteractionResponse_get_Status(self) get_node((self)->Status)
#define LassoIsInteractionResponse_Status_get(self) get_node((self)->Status)
#define LassoIsInteractionResponse_set_Status(self, value) set_node((gpointer *) &(self)->Status, (value))
#define LassoIsInteractionResponse_Status_set(self, value) set_node((gpointer *) &(self)->Status, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoIsInteractionResponse lasso_is_interaction_response_new
#define delete_LassoIsInteractionResponse(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoIsInteractionResponse_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * is:InteractionStatement
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(IsInteractionStatement) LassoIsInteractionStatement;
#endif
typedef struct {
} LassoIsInteractionStatement;
%extend LassoIsInteractionStatement {
	/* Attributes */

#ifndef SWIGPHP4
	%rename(inquiry) Inquiry;
#endif
	%newobject Inquiry_get;
	LassoIsInquiry *Inquiry;

	/* FIXME: Missing from Lasso. */
	/* Signature */

	/* Constructor, Destructor & Static Methods */

	LassoIsInteractionStatement(LassoIsInquiry *inquiry);

	~LassoIsInteractionStatement();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes Implementations */

/* Inquiry */
#define LassoIsInteractionStatement_get_Inquiry(self) get_node((self)->Inquiry)
#define LassoIsInteractionStatement_Inquiry_get(self) get_node((self)->Inquiry)
#define LassoIsInteractionStatement_set_Inquiry(self, value) set_node((gpointer *) &(self)->Inquiry, (value))
#define LassoIsInteractionStatement_Inquiry_set(self, value) set_node((gpointer *) &(self)->Inquiry, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoIsInteractionStatement lasso_is_interaction_statement_new
#define delete_LassoIsInteractionStatement(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoIsInteractionStatement_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * is:Item
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(IsItem) LassoIsItem;
#endif
typedef struct {
	/* Attributes */

#ifndef SWIGPHP4
	%rename(hint) Hint;
#endif
	char *Hint;

	char *label;

	char *value;
} LassoIsItem;
%extend LassoIsItem {
	/* Constructor, Destructor & Static Methods */

	LassoIsItem(char *value);

	~LassoIsItem();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Constructors, destructors & static methods implementations */

#define new_LassoIsItem lasso_is_item_new
#define delete_LassoIsItem(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoIsItem_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * is:Parameter
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(IsParameter) LassoIsParameter;
#endif
typedef struct {
	/* Attributes */

	char *name;

	char *value;
} LassoIsParameter;
%extend LassoIsParameter {
	/* Constructor, Destructor & Static Methods */

	LassoIsParameter(char *name, char *value);

	~LassoIsParameter();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Constructors, destructors & static methods implementations */

#define new_LassoIsParameter lasso_is_parameter_new
#define delete_LassoIsParameter(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoIsParameter_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * is:RedirectRequest
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(IsRedirectRequest) LassoIsRedirectRequest;
#endif
typedef struct {
	/* Attributes */

#ifndef SWIGPHP4
	%rename(redirectUrl) redirectURL;
#endif
	char *redirectURL;
} LassoIsRedirectRequest;
%extend LassoIsRedirectRequest {
	/* Constructor, Destructor & Static Methods */

	LassoIsRedirectRequest(char *redirectUrl);

	~LassoIsRedirectRequest();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Constructors, destructors & static methods implementations */

#define new_LassoIsRedirectRequest lasso_is_redirect_request_new
#define delete_LassoIsRedirectRequest(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoIsRedirectRequest_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * is:Select
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(IsSelect) LassoIsSelect;
#endif
typedef struct {
	/* FIXME: IsSelect should inherit from IsInquiryElement in Lasso. */

	/* Attributes */

	gboolean multiple;
} LassoIsSelect;
%extend LassoIsSelect {
	/* Attributes */

#ifndef SWIGPHP4
	%rename(item) Item;
#endif
	%newobject Item_get;
	LassoNodeList *Item;

	/* Constructor, Destructor & Static Methods */

	LassoIsSelect(LassoIsItem *item1, LassoIsItem *item2);

	~LassoIsSelect();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes Implementations */

/* Item */
#define LassoIsSelect_get_Item(self) get_node_list((self)->Item)
#define LassoIsSelect_Item_get(self) get_node_list((self)->Item)
#define LassoIsSelect_set_Item(self, value) set_node_list(&(self)->Item, (value))
#define LassoIsSelect_Item_set(self, value) set_node_list(&(self)->Item, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoIsSelect lasso_is_select_new
#define delete_LassoIsSelect(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoIsSelect_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * is:Text
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(IsText) LassoIsText;
#endif
typedef struct {
	/* FIXME: IsText should inherit from IsInquiryElement in Lasso. */

	/* Attributes */

	char *format;

	int maxChars;

	int minChars;
} LassoIsText;
%extend LassoIsText {
	/* Constructor, Destructor & Static Methods */

	LassoIsText();

	~LassoIsText();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Constructors, destructors & static methods implementations */

#define new_LassoIsText lasso_is_text_new
#define delete_LassoIsText(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoIsText_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * is:UserInteraction
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(IsUserInteraction) LassoIsUserInteraction;
#endif
typedef struct {
	/* Attributes */

	/* FIXME: Missing from Lasso. */
	/* soap:actor */

	char *id;

	char *interact;

	int maxInteractTime;

	/* FIXME: Missing from Lasso. */
	/* soap:mustUnderstand */

	char *language;

	gboolean redirect;
} LassoIsUserInteraction;
%extend LassoIsUserInteraction {
	/* Attributes */

#ifndef SWIGPHP4
	%rename(interactionService) InteractionService;
#endif
	%newobject InteractionService_get;
	LassoNodeList *InteractionService;

	/* Constructor, Destructor & Static Methods */

	LassoIsUserInteraction();

	~LassoIsUserInteraction();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes Implementations */

/* InteractionService */
#define LassoIsUserInteraction_get_InteractionService(self) get_node_list((self)->InteractionService)
#define LassoIsUserInteraction_InteractionService_get(self) get_node_list((self)->InteractionService)
#define LassoIsUserInteraction_set_InteractionService(self, value) set_node_list(&(self)->InteractionService, (value))
#define LassoIsUserInteraction_InteractionService_set(self, value) set_node_list(&(self)->InteractionService, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoIsUserInteraction lasso_is_user_interaction_new
#define delete_LassoIsUserInteraction(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoIsUserInteraction_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


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

	LassoDiscovery(LassoServer *server);

	~LassoDiscovery();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();

	/* Methods inherited from WsfProfile */

	THROW_ERROR
	int buildRequestMsg();
	END_THROW_ERROR

	THROW_ERROR
	int buildResponseMsg();
	END_THROW_ERROR

	/* Methods */

	LassoDiscoInsertEntry* addInsertEntry(char *serviceType,
					      char *providerID,
					      LassoDiscoDescription *description,
					      LassoDiscoResourceID *resourceID,
					      LassoDiscoEncryptedResourceID *encryptedResourceID);

	THROW_ERROR
	int addRemoveEntry(char *entryID);
	END_THROW_ERROR

	LassoDiscoRequestedServiceType *addRequestedServiceType(char *serviceType,
								char *option);

	THROW_ERROR
	int addResourceOffering(LassoDiscoResourceOffering *resourceOffering);
	END_THROW_ERROR

	THROW_ERROR
	int initModify(LassoDiscoResourceOffering *resourceOffering,
			LassoDiscoDescription *description);
	END_THROW_ERROR

	THROW_ERROR
	int initQuery(LassoDiscoResourceOffering *resourceOffering,
		       LassoDiscoDescription *description);
	END_THROW_ERROR

	THROW_ERROR
	int processModifyMsg(char *modify_msg);
	END_THROW_ERROR

	THROW_ERROR
	int processModifyResponseMsg(char *modify_response_msg);
	END_THROW_ERROR

	THROW_ERROR
	int processQueryMsg(char *query_msg);
	END_THROW_ERROR

	THROW_ERROR
	int processQueryResponseMsg(char *query_response_msg);
	END_THROW_ERROR
}

%{

/* Attributes inherited from WsfProfile implementations */

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

/* Constructors, destructors & static methods implementations */

#define new_LassoDiscovery lasso_discovery_new
#define delete_LassoDiscovery(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoDiscovery_dump(self) lasso_node_dump(LASSO_NODE(self))

/* Implementations of methods inherited from WsfProfile */

gint LassoDiscovery_buildRequestMsg(LassoDiscovery *self) {
	return lasso_wsf_profile_build_request_msg(LASSO_WSF_PROFILE(self));
}

gint LassoDiscovery_buildResponseMsg(LassoDiscovery *self) {
	return lasso_wsf_profile_build_response_msg(LASSO_WSF_PROFILE(self));
}

/* Methods implementations */

#define LassoDiscovery_addInsertEntry lasso_discovery_add_insert_entry
#define LassoDiscovery_addRemoveEntry lasso_discovery_add_remove_entry
#define LassoDiscovery_addRequestedServiceType lasso_discovery_add_requested_service_type
#define LassoDiscovery_addResourceOffering lasso_discovery_add_resource_offering
#define LassoDiscovery_initModify lasso_discovery_init_modify
#define LassoDiscovery_initQuery lasso_discovery_init_query
#define LassoDiscovery_processModifyMsg lasso_discovery_process_modify_msg
#define LassoDiscovery_processModifyResponseMsg lasso_discovery_process_modify_response_msg
#define LassoDiscovery_processQueryMsg lasso_discovery_process_query_msg
#define LassoDiscovery_processQueryResponseMsg lasso_discovery_process_query_response_msg

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

	THROW_ERROR
	int buildRequestMsg();
	END_THROW_ERROR

	THROW_ERROR
	int buildResponseMsg();
	END_THROW_ERROR

	/* Methods */

	THROW_ERROR
	int initRequest();
	END_THROW_ERROR

	THROW_ERROR
	int processRequestMsg(char *msg);
	END_THROW_ERROR

	THROW_ERROR
	int processResponseMsg(char *msg);
	END_THROW_ERROR
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

gint LassoInteractionProfileService_buildRequestMsg(LassoInteractionProfileService *self) {
	return lasso_wsf_profile_build_request_msg(LASSO_WSF_PROFILE(self));
}

gint LassoInteractionProfileService_buildResponseMsg(LassoInteractionProfileService *self) {
	return lasso_wsf_profile_build_response_msg(LASSO_WSF_PROFILE(self));
}

/* Methods implementations */

#define LassoInteractionProfileService_initRequest lasso_interaction_profile_service_init_request
#define LassoInteractionProfileService_processRequestMsg lasso_interaction_profile_service_process_request_msg
#define LassoInteractionProfileService_processResponseMsg lasso_interaction_profile_service_process_response_msg

%}


/***********************************************************************
 * lasso:ProfileService
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(ProfileService) LassoProfileService;
#endif
typedef struct {
} LassoProfileService;
%extend LassoProfileService {
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

	LassoProfileService(LassoServer *server);

	~LassoProfileService();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();

	/* Methods inherited from WsfProfile */

	THROW_ERROR
	int buildRequestMsg();
	END_THROW_ERROR

	THROW_ERROR
	int buildResponseMsg();
	END_THROW_ERROR

	/* Methods */

	THROW_ERROR
	int addData(char *xmlNodeBuffer);
	END_THROW_ERROR

	LassoDstModification *addModification(char *select);

        LassoDstQueryItem *addQueryItem(char *select);
		
	LassoDstModification *initModify(char *prefix,
					 char *href,
					 LassoDiscoResourceOffering *resourceOffering,
					 LassoDiscoDescription *description,
					 char *select);
		
	LassoDstQueryItem *initQuery(char *prefix,
				     char *href,
				     LassoDiscoResourceOffering *resourceOffering,
				     LassoDiscoDescription *description,
				     char *select);

	THROW_ERROR
	int processModifyMsg(char *prefix, char *href, char *soap_msg);
	END_THROW_ERROR

	THROW_ERROR
	int processModifyResponseMsg(char *prefix, char *href, char *soap_msg);
	END_THROW_ERROR

	THROW_ERROR
	int processQueryMsg(char *prefix, char *href, char *soap_msg);
	END_THROW_ERROR

	THROW_ERROR
	int processQueryResponseMsg(char *prefix, char *href, char *soap_msg);
	END_THROW_ERROR
}

%{

/* Attributes inherited from WsfProfile implementations */

/* msgBody */
#define LassoProfileService_get_msgBody(self) LASSO_WSF_PROFILE(self)->msg_body
#define LassoProfileService_msgBody_get(self) LASSO_WSF_PROFILE(self)->msg_body

/* msgUrl */
#define LassoProfileService_get_msgUrl(self) LASSO_WSF_PROFILE(self)->msg_url
#define LassoProfileService_msgUrl_get(self) LASSO_WSF_PROFILE(self)->msg_url

/* request */
#define LassoProfileService_get_request(self) get_node(LASSO_WSF_PROFILE(self)->request)
#define LassoProfileService_request_get(self) get_node(LASSO_WSF_PROFILE(self)->request)
#define LassoProfileService_set_request(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->request, (value))
#define LassoProfileService_request_set(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->request, (value))

/* response */
#define LassoProfileService_get_response(self) get_node(LASSO_WSF_PROFILE(self)->response)
#define LassoProfileService_response_get(self) get_node(LASSO_WSF_PROFILE(self)->response)
#define LassoProfileService_set_response(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->response, (value))
#define LassoProfileService_response_set(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->response, (value))

/* server */
#define LassoProfileService_get_server(self) get_node(LASSO_WSF_PROFILE(self)->server)
#define LassoProfileService_server_get(self) get_node(LASSO_WSF_PROFILE(self)->server)
#define LassoProfileService_set_server(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->server, (value))
#define LassoProfileService_server_set(self, value) set_node((gpointer *) &LASSO_WSF_PROFILE(self)->server, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoProfileService lasso_profile_service_new
#define delete_LassoProfileService(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoProfileService_dump(self) lasso_node_dump(LASSO_NODE(self))


/* Implementations of methods inherited from WsfProfile */

gint LassoProfileService_buildRequestMsg(LassoProfileService *self) {
	return lasso_wsf_profile_build_request_msg(LASSO_WSF_PROFILE(self));
}

gint LassoProfileService_buildResponseMsg(LassoProfileService *self) {
	return lasso_wsf_profile_build_response_msg(LASSO_WSF_PROFILE(self));
}

/* Methods implementations */
#define LassoProfileService_addData lasso_profile_service_add_data
#define LassoProfileService_addModification lasso_profile_service_add_modification
#define LassoProfileService_addQueryItem lasso_profile_service_add_query_item
#define LassoProfileService_initModify lasso_profile_service_init_modify
#define LassoProfileService_initQuery lasso_profile_service_init_query
#define LassoProfileService_processModifyMsg lasso_profile_service_process_modify_msg
#define LassoProfileService_processModifyResponseMsg lasso_profile_service_process_modify_response_msg
#define LassoProfileService_processQueryMsg lasso_profile_service_process_query_msg
#define LassoProfileService_processQueryResponseMsg lasso_profile_service_process_query_response_msg

%}
