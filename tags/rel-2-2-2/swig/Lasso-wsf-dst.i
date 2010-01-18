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
#include <lasso/xml/dst_new_data.h>
#include <lasso/xml/dst_modify.h>
#include <lasso/xml/dst_modify_response.h>
#include <lasso/xml/dst_query.h>
#include <lasso/xml/dst_query_response.h>
%}

/* WSF status code */
#ifndef SWIG_PHP_RENAMES
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
 * XML Elements in Data Services Template Namespace
 ***********************************************************************
 ***********************************************************************/


/***********************************************************************
 * dst:Data
 ***********************************************************************/


#ifndef SWIG_PHP_RENAMES
%rename(DstData) LassoDstData;
#endif
typedef struct {
	/* Attributes */

	char *id;

#ifndef SWIG_PHP_RENAMES
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


#ifndef SWIG_PHP_RENAMES
%rename(DstModification) LassoDstModification;
#endif
typedef struct {
	/* Attributes */

	char *id;

	char *notChangedSince;

	gboolean overrideAllowed;

#ifndef SWIG_PHP_RENAMES
	%rename(select) Select;
#endif
	char *Select;
} LassoDstModification;
%extend LassoDstModification {
	/* Attributes */

#ifndef SWIG_PHP_RENAMES
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


#ifndef SWIG_PHP_RENAMES
%rename(DstModify) LassoDstModify;
#endif
typedef struct {
	/* Attributes */

	char *id;

#ifndef SWIG_PHP_RENAMES
	%rename(itemId) itemID;
#endif
	char *itemID;
} LassoDstModify;
%extend LassoDstModify {
	/* Attributes */

#ifndef SWIG_PHP_RENAMES
	%rename(encryptedResourceId) EncryptedResourceID;
#endif
	%newobject EncryptedResourceID_get;
	LassoDiscoEncryptedResourceID *EncryptedResourceID;

#ifndef SWIG_PHP_RENAMES
	%rename(extension) Extension;
#endif
	%newobject Extension_get;
	LassoStringList *Extension;

#ifndef SWIG_PHP_RENAMES
	%rename(modification) Modification;
#endif
	%newobject Modification_get;
	LassoNodeList *Modification;

#ifndef SWIG_PHP_RENAMES
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


#ifndef SWIG_PHP_RENAMES
%rename(DstModifyResponse) LassoDstModifyResponse;
#endif
typedef struct {
	/* Attributes */

	char *id;

#ifndef SWIG_PHP_RENAMES
	%rename(itemIdRef) itemIDRef;
#endif
	char *itemIDRef;

	char *timeStamp;
} LassoDstModifyResponse;
%extend LassoDstModifyResponse {
	/* Attributes */

#ifndef SWIG_PHP_RENAMES
	%rename(extension) Extension;
#endif
	%newobject Extension_get;
	LassoStringList *Extension;

#ifndef SWIG_PHP_RENAMES
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


#ifndef SWIG_PHP_RENAMES
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


#ifndef SWIG_PHP_RENAMES
%rename(DstQuery) LassoDstQuery;
#endif
typedef struct {
	/* Attributes */

	char *id;

#ifndef SWIG_PHP_RENAMES
	%rename(itemId) itemID;
#endif
	char *itemID;
} LassoDstQuery;
%extend LassoDstQuery {
	/* Attributes */

#ifndef SWIG_PHP_RENAMES
	%rename(encryptedResourceId) EncryptedResourceID;
#endif
	%newobject EncryptedResourceID_get;
	LassoDiscoEncryptedResourceID *EncryptedResourceID;

#ifndef SWIG_PHP_RENAMES
	%rename(extension) Extension;
#endif
	%newobject Extension_get;
	LassoStringList *Extension;

#ifndef SWIG_PHP_RENAMES
	%rename(queryItem) QueryItem;
#endif
	%newobject QueryItem_get;
	LassoNodeList *QueryItem;

#ifndef SWIG_PHP_RENAMES
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


#ifndef SWIG_PHP_RENAMES
%rename(DstQueryItem) LassoDstQueryItem;
#endif
typedef struct {
	/* Attributes */

	char *changedSince;

	char *id;

	gboolean includeCommonAttributes;

#ifndef SWIG_PHP_RENAMES
	%rename(itemId) itemID;
#endif
	char *itemID;

#ifndef SWIG_PHP_RENAMES
	%rename(select) Select;
#endif
	char *Select;
} LassoDstQueryItem;
%extend LassoDstQueryItem {
	/* Constructor, Destructor & Static Methods */

	LassoDstQueryItem(const char *select, const char *item_id = NULL);

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


#ifndef SWIG_PHP_RENAMES
%rename(DstQueryResponse) LassoDstQueryResponse;
#endif
typedef struct {
	/* Attributes */

	char *id;

#ifndef SWIG_PHP_RENAMES
	%rename(itemIdRef) itemIDRef;
#endif
	char *itemIDRef;

	char *timeStamp;
} LassoDstQueryResponse;
%extend LassoDstQueryResponse {
	/* Attributes */

#ifndef SWIG_PHP_RENAMES
	%rename(data) Data;
#endif
	%newobject Data_get;
	LassoNodeList *Data;

#ifndef SWIG_PHP_RENAMES
	%rename(extension) Extension;
#endif
	%newobject Extension_get;
	LassoStringList *Extension;

#ifndef SWIG_PHP_RENAMES
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
