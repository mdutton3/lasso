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
#include <lasso/id-wsf/profile_service.h>
#include <lasso/xml/dst_new_data.h>
#include <lasso/xml/dst_modify.h>
#include <lasso/xml/dst_modify_response.h>
#include <lasso/xml/dst_query.h>
#include <lasso/xml/dst_query_response.h>
#include <lasso/xml/is_interaction_request.h>
#include <lasso/xml/is_interaction_response.h>
#include <lasso/xml/is_inquiry.h>

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
 * disco:Credentials
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

	LassoDiscoServiceInstance(
			char *serviceType, char *providerID, LassoDiscoDescription *description);

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

#define new_LassoDiscoServiceInstance LassoDiscoServiceInstance_new
LassoDiscoServiceInstance *LassoDiscoServiceInstance_new(char *serviceType,
							 char *providerID,
							 LassoDiscoDescription *description) {
	GList *l_desc = NULL;
	LassoDiscoServiceInstance *serviceInstance;

	l_desc = g_list_append(l_desc, description);
	serviceInstance = lasso_disco_service_instance_new(serviceType, providerID, l_desc);

	return serviceInstance;
}
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
 * dst:Modification
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(DstModification) LassoDstModification;
#endif
typedef struct {
} LassoDstModification;
%extend LassoDstModification {
	/* Attributes */
	%immutable select;
	char *select;

	%immutable newData;
	LassoDstNewData *newData;

	/* Constructor, Destructor & Static Methods */
	LassoDstModification(char *select);

	~LassoDstModification();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();

	/* Methods */

}

%{

/* Attributes Implementations */

/* newData */
#define LassoDstModification_get_newData LassoDstModification_newData_get
LassoDstNewData *LassoDstModification_newData_get(LassoDstModification *self) {
	if (LASSO_IS_DST_MODIFICATION(self) == TRUE) {
		if (self->NewData != NULL) {
			return LASSO_DST_NEW_DATA(self->NewData->data);
		}
	}
	return NULL;
}

/* select */
#define LassoDstModification_get_select LassoDstModification_select_get
char *LassoDstModification_select_get(LassoDstModification *self) {
	return self->Select;
}

/* Constructors, destructors & static methods implementations */

#define new_LassoDstModification lasso_dst_modification_new
#define delete_LassoDstModification(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoDstModification_dump(self) lasso_node_dump(LASSO_NODE(self))

/* Methods implementations */

%}


/***********************************************************************
 * dst:Modify
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(DstModify) LassoDstModify;
#endif
typedef struct {
} LassoDstModify;
%extend LassoDstModify {
	/* Attributes */

	%immutable resourceId;
	LassoDiscoResourceID *resourceId;

	%immutable modification;
	LassoDstModification *modification; /* FIXME : should return a list of Modification */

	char *itemId;

	/* Constructor, Destructor & Static Methods */

	LassoDstModify(LassoDstModification *modification);

	~LassoDstModify();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();

	/* Methods */
		

}

%{

/* Attributes Implementations */

/* resourceId */
#define LassoDstModify_get_resourceId LassoDstModify_resourceId_get
LassoDiscoResourceID *LassoDstModify_resourceId_get(LassoDstModify *self) {
	return self->ResourceID;
}

/* modification */
#define LassoDstModify_get_modification LassoDstModify_modification_get
LassoDstModification *LassoDstModify_modification_get(LassoDstModify *self) {
	return LASSO_DST_MODIFICATION(self->Modification->data);
}

/* itemId */
#define LassoDstModify_get_itemId LassoDstModify_itemId_get
char *LassoDstModify_itemId_get(LassoDstModify *self) {
	return self->itemID;
}

#define LassoDstModify_set_itemId LassoDstModify_itemId_set
void LassoDstModify_itemId_set(LassoDstModify *self, char *itemId) {
	LASSO_DST_MODIFY(self)->itemID = itemId;
}

/* Constructors, destructors & static methods implementations */

#define new_LassoDstModify lasso_dst_modify_new
#define delete_LassoDstModify(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoDstModify_dump(self) lasso_node_dump(LASSO_NODE(self))

/* Methods implementations */

%}


/***********************************************************************
 * dst:ModifyResponse
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(DstModifyResponse) LassoDstModifyResponse;
#endif
typedef struct {
} LassoDstModifyResponse;
%extend LassoDstModifyResponse {
	/* Attributes */

	LassoUtilityStatus *status;

	/* char *itemIdRef; */

	/* char *timeStamp; */

	/* Constructor, Destructor & Static Methods */

	LassoDstModifyResponse(LassoUtilityStatus *status);

	~LassoDstModifyResponse();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();

	/* Methods */

}

%{

/* Attributes Implementations */

/* status */
#define LassoDstModifyResponse_get_status LassoDstModifyResponse_status_get
LassoUtilityStatus *LassoDstModifyResponse_status_get(LassoDstModifyResponse *self) {
	return self->Status;
}

/* Constructors, destructors & static methods implementations */

#define new_LassoDstModifyResponse lasso_dst_modify_response_new
#define delete_LassoDstModifyResponse(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoDstModifyResponse_dump(self) lasso_node_dump(LASSO_NODE(self))

/* Methods implementations */

%}


/***********************************************************************
 * dst:Query
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(DstQuery) LassoDstQuery;
#endif
typedef struct {
} LassoDstQuery;
%extend LassoDstQuery {
	/* Attributes */

	%immutable resourceId;
	LassoDiscoResourceID *resourceId;

	%immutable queryItem;
	LassoDstQueryItem *queryItem; /* FIXME : must be a GList of LassoDstQueryItem */

	/* char *itemID; */

	/* Constructor, Destructor & Static Methods */

	LassoDstQuery(LassoDstQueryItem *queryItem);

	~LassoDstQuery();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();

	/* Methods */

}

%{

/* Attributes Implementations */

/* resourceId */
#define LassoDstQuery_get_resourceId LassoDstQuery_resourceId_get
LassoDiscoResourceID *LassoDstQuery_resourceId_get(LassoDstQuery *self) {
	return self->ResourceID;
}

/* queryItem */
#define LassoDstQuery_get_queryItem LassoDstQuery_queryItem_get
LassoDstQueryItem *LassoDstQuery_queryItem_get(LassoDstQuery *self) {
	return self->QueryItem->data;
}

/* Constructors, destructors & static methods implementations */

#define new_LassoDstQuery lasso_dst_query_new
#define delete_LassoDstQuery(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoDstQuery_dump(self) lasso_node_dump(LASSO_NODE(self))

/* Methods implementations */

%}


/***********************************************************************
 * dst:QueryItem
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(DstQueryItem) LassoDstQueryItem;
#endif
typedef struct {
} LassoDstQueryItem;
%extend LassoDstQueryItem {
	/* Attributes */

	%immutable select;
	char *select;

	/* Constructor, Destructor & Static Methods */

	LassoDstQueryItem(char *select);

	~LassoDstQueryItem();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();

	/* Methods */

}

%{

/* Attributes Implementations */

/* select */
#define LassoDstQuery_get_select LassoDstQueryItem_select_get
char *LassoDstQueryItem_select_get(LassoDstQueryItem *self) {
	return self->Select;
}

/* Constructors, destructors & static methods implementations */

#define new_LassoDstQueryItem lasso_dst_query_item_new
#define delete_LassoDstQueryItem(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoDstQueryItem_dump(self) lasso_node_dump(LASSO_NODE(self))

/* Methods implementations */

%}


/***********************************************************************
 * dst:QueryResponse
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(DstQueryResponse) LassoDstQueryResponse;
#endif
typedef struct {
} LassoDstQueryResponse;
%extend LassoDstQueryResponse {
	/* Attributes */

	%immutable status;
	LassoUtilityStatus *status;

	/* Constructor, Destructor & Static Methods */

	LassoDstQueryResponse(LassoUtilityStatus *status);

	~LassoDstQueryResponse();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes Implementations */

/* status */
#define LassoDstQueryResponse_get_status LassoDstQueryResponse_status_get
LassoUtilityStatus *LassoDstQueryResponse_status_get(LassoDstQueryResponse *self) {
	return self->Status;
}

/* Constructors, destructors & static methods implementations */

#define new_LassoDstQueryResponse lasso_dst_query_response_new
#define delete_LassoDstQueryResponse(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoDstQueryResponse_dump(self) lasso_node_dump(LASSO_NODE(self))

/* Methods implementations */

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
} LassoUtilityStatus;
%extend LassoUtilityStatus {
	/* Attributes */

	char *code;

	/* Constructor, Destructor & Static Methods */

	LassoUtilityStatus(char *code);

	~LassoUtilityStatus();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();

	/* Methods */

}

%{

/* Attributes Implementations */
/* status */
#define LassoUtilityStatus_get_code LassoUtilityStatus_code_get
char *LassoUtilityStatus_code_get(LassoUtilityStatus *self) {
	return self->code;
}

#define LassoUtilityStatus_set_code LassoUtilityStatus_code_set
void LassoUtilityStatus_code_set(LassoUtilityStatus *self, char *code) {
	self->code = g_strdup(code);
}

/* Constructors, destructors & static methods implementations */
#define new_LassoUtilityStatus lasso_utility_status_new
#define delete_LassoUtilityStatus(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoUtilityStatus_dump(self) lasso_node_dump(LASSO_NODE(self))

/* Methods implementations */

%}


/***********************************************************************
 ***********************************************************************
 * XML Elements in Interaction Services Namespace
 ***********************************************************************
 ***********************************************************************/


/***********************************************************************
 * is:InteractionRequest
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(IsInteractionRequest) LassoIsInteractionRequest;
#endif
typedef struct {
} LassoIsInteractionRequest;
%extend LassoIsInteractionRequest {
	/* Attributes */

	LassoDiscoResourceID *resourceID;

	LassoIsInquiry *inquiry;

	int maxInteractTime;

	/* Constructor, Destructor & Static Methods */

	LassoIsInteractionRequest();

	~LassoIsInteractionRequest();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();

	/* Methods */

}

%{

/* Attributes Implementations */

/* resourceID */
#define LassoIsInteractionRequest_get_resourceID LassoIsInteractionRequest_resourceID_get
LassoDiscoResourceID *LassoIsInteractionRequest_resourceID_get(LassoIsInteractionRequest *self) {
	return self->ResourceID;
}

#define LassoIsInteractionRequest_set_resourceID LassoIsInteractionRequest_resourceID_set
void LassoIsInteractionRequest_resourceID_set(LassoIsInteractionRequest *self, LassoDiscoResourceID *resourceID) {
	self->ResourceID = resourceID;
}

/* inquiry */
#define LassoIsInteractionRequest_get_inquiry LassoIsInteractionRequest_inquiry_get
LassoIsInquiry *LassoIsInteractionRequest_inquiry_get(LassoIsInteractionRequest *self) {
	if (self->Inquiry == NULL) {
		return NULL;
	}
	return LASSO_IS_INQUIRY(self->Inquiry->data);
}

#define LassoIsInteractionRequest_set_inquiry LassoIsInteractionRequest_inquiry_set
void LassoIsInteractionRequest_inquiry_set(LassoIsInteractionRequest *self, LassoIsInquiry *inquiry) {
	self->Inquiry = g_list_append(self->Inquiry, LASSO_NODE(inquiry));
}

/* maxInteractTime */
#define LassoIsInteractionRequest_get_maxInteractTime LassoIsInteractionRequest_maxInteractTime_get
int LassoIsInteractionRequest_maxInteractTime_get(LassoIsInteractionRequest *self) {
	return self->maxInteractTime;
}

#define LassoIsInteractionRequest_set_maxInteractTime LassoIsInteractionRequest_maxInteractTime_set
void LassoIsInteractionRequest_maxInteractTime_set(LassoIsInteractionRequest *self, int maxInteractTime) {
	self->maxInteractTime = maxInteractTime;
}

/* Constructors, destructors & static methods implementations */

#define new_LassoIsInteractionRequest lasso_is_interaction_request_new
#define delete_LassoIsInteractionRequest(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoIsInteractionRequest_dump(self) lasso_node_dump(LASSO_NODE(self))

/* Methods implementations */

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
	/* Attributes inherited from LassoProfile */

	%immutable query;
	LassoDiscoQuery *query;

	%immutable queryResponse;
	LassoDiscoQueryResponse *queryResponse;

	%immutable modify;
	LassoDiscoModify *modify;

	%immutable modifyResponse;
	LassoDiscoModifyResponse *modifyResponse;

	%immutable msgBody;
	char *msgBody;

	%immutable msgUrl;
	char *msgUrl;

	/* Constructor, Destructor & Static Methods */

	LassoDiscovery(LassoServer *server);

	~LassoDiscovery();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();

	/* Methods inherited from LassoWsfProfile */

	THROW_ERROR
	void buildRequestMsg();
	END_THROW_ERROR

	THROW_ERROR
	void buildResponseMsg();
	END_THROW_ERROR

	/* Methods */

	LassoDiscoInsertEntry* addInsertEntry(char *serviceType,
					      char *providerID,
					      LassoDiscoDescription *description,
					      LassoDiscoResourceID *resourceID,
					      LassoDiscoEncryptedResourceID *encryptedResourceID,
					      char *option);

	THROW_ERROR
	void addRemoveEntry(char *entryID);
	END_THROW_ERROR

	LassoDiscoRequestedServiceType *addRequestedServiceType(char *serviceType,
								char *option);

	THROW_ERROR
	void addResourceOffering(LassoDiscoResourceOffering *resourceOffering);
	END_THROW_ERROR

	THROW_ERROR
	void initModify(LassoDiscoResourceOffering *resourceOffering,
			LassoDiscoDescription *description);
	END_THROW_ERROR

	THROW_ERROR
	void initQuery(LassoDiscoResourceOffering *resourceOffering,
		       LassoDiscoDescription *description);
	END_THROW_ERROR

	THROW_ERROR
	void processModifyMsg(char *modify_msg);
	END_THROW_ERROR

	THROW_ERROR
	void processModifyResponseMsg(char *modify_response_msg);
	END_THROW_ERROR

	THROW_ERROR
	void processQueryMsg(char *query_msg);
	END_THROW_ERROR

	THROW_ERROR
	void processQueryResponseMsg(char *query_response_msg);
	END_THROW_ERROR
}

%{

/* Attributes inherited from LassoWsfProfile implementations casted to Discovery domain */

/* query */
#define LassoDiscovery_get_query LassoDiscovery_query_get
LassoDiscoQuery *LassoDiscovery_query_get(LassoDiscovery *self) {
	LassoWsfProfile *profile = LASSO_WSF_PROFILE(self);
	if (LASSO_IS_DISCO_QUERY(profile->request))
		return LASSO_DISCO_QUERY(profile->request);
	return NULL;
}

/* queryResponse */
#define LassoDiscovery_get_queryResponse LassoDiscovery_queryResponse_get
LassoDiscoQueryResponse *LassoDiscovery_queryResponse_get(LassoDiscovery *self) {
	LassoWsfProfile *profile = LASSO_WSF_PROFILE(self);
	if (LASSO_IS_DISCO_QUERY_RESPONSE(profile->response))
		return LASSO_DISCO_QUERY_RESPONSE(profile->response);
	return NULL;
}

/* modify */
#define LassoDiscovery_get_modify LassoDiscovery_modify_get
LassoDiscoModify *LassoDiscovery_modify_get(LassoDiscovery *self) {
	LassoWsfProfile *profile = LASSO_WSF_PROFILE(self);
	if (LASSO_IS_DISCO_MODIFY(profile->request))
		return LASSO_DISCO_MODIFY(profile->request);
	printf("booooooo\n");
	return NULL;
}

/* modifyResponse */
#define LassoDiscovery_get_modifyResponse LassoDiscovery_modifyResponse_get
LassoDiscoModifyResponse *LassoDiscovery_modifyResponse_get(LassoDiscovery *self) {
	LassoWsfProfile *profile = LASSO_WSF_PROFILE(self);

	if (LASSO_IS_DISCO_MODIFY_RESPONSE(profile->response) == TRUE) {
		return LASSO_DISCO_MODIFY_RESPONSE(profile->response);
	}
	return NULL;
}

/* msgBody */
#define LassoDiscovery_get_msgBody LassoDiscovery_msgBody_get
char *LassoDiscovery_msgBody_get(LassoDiscovery *self) {
	return LASSO_WSF_PROFILE(self)->msg_body;
}

/* msgUrl */
#define LassoDiscovery_get_msgUrl LassoDiscovery_msgUrl_get
char *LassoDiscovery_msgUrl_get(LassoDiscovery *self) {
	return LASSO_WSF_PROFILE(self)->msg_url;
}

/* Constructors, destructors & static methods implementations */

#define new_LassoDiscovery lasso_discovery_new
#define delete_LassoDiscovery(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoDiscovery_dump(self) lasso_node_dump(LASSO_NODE(self))

/* Methods inherited from LassoWsfProfile implementations */

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
 * lasso:ProfileService
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(ProfileService) LassoProfileService;
#endif
typedef struct {
} LassoProfileService;
%extend LassoProfileService {
	/* Attributes */

	%immutable query;
	LassoDstQuery *query;

	%immutable queryResponse;
	LassoDstQueryResponse *queryResponse;

	%immutable modify;
	LassoDstModify *modify;

	%immutable modifyResponse;
	LassoDstModifyResponse *modifyResponse;

	%immutable msgBody;
	char *msgBody;

	%immutable msgUrl;
	char *msgUrl;

	/* Constructor, Destructor & Static Methods */

	LassoProfileService(LassoServer *server);

	~LassoProfileService();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();

	/* Methods inherited from LassoWsfProfile */
	void buildRequestMsg();

	void buildResponseMsg();

	/* Methods */
	void addData(LassoNode *data);

	LassoDstModification *addModification(char *select);
		
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
	void processModifyMsg(char *prefix, char *href, char *soap_msg);
	END_THROW_ERROR

	THROW_ERROR
	void processModifyResponseMsg(char *prefix, char *href, char *soap_msg);
	END_THROW_ERROR

        LassoDstQueryItem *addQueryItem(char *select);

	THROW_ERROR
	void processQueryMsg(char *prefix, char *href, char *soap_msg);
	END_THROW_ERROR

	THROW_ERROR
	void processQueryResponseMsg(char *prefix, char *href, char *soap_msg);
	END_THROW_ERROR
}

%{

/* Attributes Implementations */

/* modify */
#define LassoProfileService_get_modify LassoProfileService_modify_get
LassoDstModify *LassoProfileService_modify_get(LassoProfileService *self) {
	LassoWsfProfile *profile = LASSO_WSF_PROFILE(self);
	if (LASSO_IS_PROFILE_SERVICE(self) == TRUE)
		return LASSO_DST_MODIFY(profile->request);
	return NULL;
}

/* modifyResponse */
#define LassoProfileService_get_modifyResponse LassoProfileService_modifyResponse_get
LassoDstModifyResponse *LassoProfileService_modifyResponse_get(LassoProfileService *self) {
	LassoWsfProfile *profile = LASSO_WSF_PROFILE(self);
	if (LASSO_IS_PROFILE_SERVICE(self) == TRUE)
		return LASSO_DST_MODIFY_RESPONSE(profile->response);
	return NULL;
}

/* msgUrl */
#define LassoProfileService_get_msgUrl LassoProfileService_msgUrl_get
char *LassoProfileService_msgUrl_get(LassoProfileService *self) {
	LassoWsfProfile *profile = LASSO_WSF_PROFILE(self);
	if (LASSO_IS_PROFILE_SERVICE(self) == TRUE)
		return profile->msg_url;
	return NULL;
}

/* msgBody */
#define LassoProfileService_get_msgBody LassoProfileService_msgBody_get
char *LassoProfileService_msgBody_get(LassoProfileService *self) {
	LassoWsfProfile *profile = LASSO_WSF_PROFILE(self);
	if (LASSO_IS_PROFILE_SERVICE(self) == TRUE)
		return profile->msg_body;
	return NULL;
}

/* Query */
#define LassoProfileService_get_query LassoProfileService_query_get
LassoDstQuery *LassoProfileService_query_get(LassoProfileService *self) {
	LassoWsfProfile *profile = LASSO_WSF_PROFILE(self);
	if (LASSO_IS_PROFILE_SERVICE(self) == TRUE) {
		return LASSO_DST_QUERY(profile->request);
	}
	return NULL;
}

/* QueryResponse */
#define LassoProfileService_get_queryResponse LassoProfileService_queryResponse_get
LassoDstQueryResponse *LassoProfileService_queryResponse_get(LassoProfileService *self) {
	LassoWsfProfile *profile = LASSO_WSF_PROFILE(self);
	if (LASSO_IS_PROFILE_SERVICE(self) == TRUE)
		return LASSO_DST_QUERY_RESPONSE(profile->response);
	return NULL;
}


/* Constructors, destructors & static methods implementations */

#define new_LassoProfileService lasso_profile_service_new
#define delete_LassoProfileService(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoProfileService_dump(self) lasso_node_dump(LASSO_NODE(self))


/* Methods inherited from LassoWsfProfile implementations */
void LassoProfileService_buildRequestMsg(LassoProfileService *self) {
	lasso_wsf_profile_build_request_msg(LASSO_WSF_PROFILE(self));
}

void LassoProfileService_buildResponseMsg(LassoProfileService *self) {
	lasso_wsf_profile_build_response_msg(LASSO_WSF_PROFILE(self));
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
