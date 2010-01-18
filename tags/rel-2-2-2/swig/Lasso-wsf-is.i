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
 * XML Elements in Interaction Services Namespace
 ***********************************************************************
 ***********************************************************************/


/***********************************************************************
 * is:Help
 ***********************************************************************/


#ifndef SWIG_PHP_RENAMES
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


#ifndef SWIG_PHP_RENAMES
%rename(IsInquiry) LassoIsInquiry;
#endif
typedef struct {
	/* Attributes */

	char *id;

	char *title;
} LassoIsInquiry;
%extend LassoIsInquiry {
	/* Attributes */

#ifndef SWIG_PHP_RENAMES
	%rename(confirm) Confirm;
#endif
	%newobject Confirm_get;
	LassoNodeList *Confirm;

#ifndef SWIG_PHP_RENAMES
	%rename(help) Help;
#endif
	%newobject Help_get;
	LassoIsHelp *Help;

#ifndef SWIG_PHP_RENAMES
	%rename(select) Select;
#endif
	%newobject Select_get;
	LassoNodeList *Select;

#ifndef SWIG_PHP_RENAMES
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


#ifndef SWIG_PHP_RENAMES
%rename(IsInquiryElement) LassoIsInquiryElement;
#endif
typedef struct {
	/* Attributes */

#ifndef SWIG_PHP_RENAMES
	%rename(hint) Hint;
#endif
	char *Hint;

#ifndef SWIG_PHP_RENAMES
	%rename(Label) Label;
#endif
	char *Label;

	char *name;

#ifndef SWIG_PHP_RENAMES
	%rename(value) Value;
#endif
	char *Value;
} LassoIsInquiryElement;
%extend LassoIsInquiryElement {
	/* Attributes */

#ifndef SWIG_PHP_RENAMES
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


#ifndef SWIG_PHP_RENAMES
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

#ifndef SWIG_PHP_RENAMES
	%rename(encryptedResourceId) EncryptedResourceID;
#endif
	%newobject EncryptedResourceID_get;
	LassoDiscoEncryptedResourceID *EncryptedResourceID;

#ifndef SWIG_PHP_RENAMES
	%rename(inquiry) Inquiry;
#endif
	%newobject Inquiry_get;
	LassoNodeList *Inquiry;

#ifndef SWIG_PHP_RENAMES
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


#ifndef SWIG_PHP_RENAMES
%rename(IsInteractionResponse) LassoIsInteractionResponse;
#endif
typedef struct {
} LassoIsInteractionResponse;
%extend LassoIsInteractionResponse {
	/* Attributes */

#ifndef SWIG_PHP_RENAMES
	%rename(interactionStatement) InteractionStatement;
#endif
	%newobject InteractionStatement_get;
	LassoNodeList *InteractionStatement;

#ifndef SWIG_PHP_RENAMES
	%rename(parameter) Parameter;
#endif
	%newobject Parameter_get;
	LassoNodeList *Parameter;

#ifndef SWIG_PHP_RENAMES
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


#ifndef SWIG_PHP_RENAMES
%rename(IsInteractionStatement) LassoIsInteractionStatement;
#endif
typedef struct {
} LassoIsInteractionStatement;
%extend LassoIsInteractionStatement {
	/* Attributes */

#ifndef SWIG_PHP_RENAMES
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


#ifndef SWIG_PHP_RENAMES
%rename(IsItem) LassoIsItem;
#endif
typedef struct {
	/* Attributes */

#ifndef SWIG_PHP_RENAMES
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


#ifndef SWIG_PHP_RENAMES
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


#ifndef SWIG_PHP_RENAMES
%rename(IsRedirectRequest) LassoIsRedirectRequest;
#endif
typedef struct {
	/* Attributes */

#ifndef SWIG_PHP_RENAMES
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


#ifndef SWIG_PHP_RENAMES
%rename(IsSelect) LassoIsSelect;
#endif
typedef struct {
	/* FIXME: IsSelect should inherit from IsInquiryElement in Lasso. */

	/* Attributes */

	gboolean multiple;
} LassoIsSelect;
%extend LassoIsSelect {
	/* Attributes */

#ifndef SWIG_PHP_RENAMES
	%rename(item) Item;
#endif
	%newobject Item_get;
	LassoNodeList *Item;

	/* Constructor, Destructor & Static Methods */

	LassoIsSelect();

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


#ifndef SWIG_PHP_RENAMES
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


#ifndef SWIG_PHP_RENAMES
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

#ifndef SWIG_PHP_RENAMES
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
