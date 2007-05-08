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
#include <lasso/xml/wsse_security.h>
#include <lasso/xml/soap_body.h>
#include <lasso/xml/soap_envelope.h>
#include <lasso/xml/soap_header.h>
#include <lasso/xml/soap_binding_correlation.h>
#include <lasso/xml/soap_binding_provider.h>
%}


/***********************************************************************
 ***********************************************************************
 * XML Elements in Web Service Security Namespace
 ***********************************************************************
 ***********************************************************************/


/***********************************************************************
 * wsse:Security
 ***********************************************************************/


#ifndef SWIG_PHP_RENAMES
%rename(WsseSecurity) LassoWsseSecurity;
#endif
typedef struct {
	/* Attributes */

} LassoWsseSecurity;
%extend LassoWsseSecurity {

	%newobject any_get;
	LassoNodeList *any;

	/* Constructor, Destructor & Static Methods */

	LassoWsseSecurity();

	~LassoWsseSecurity();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Constructors, destructors & static methods implementations */

#define new_LassoWsseSecurity lasso_wsse_security_new
#define delete_LassoWsseSecurity(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoWsseSecurity_dump(self) lasso_node_dump(LASSO_NODE(self))

/* Attributes Implementations */

/* any */
#define LassoWsseSecurity_get_any(self) get_node_list((self)->any)
#define LassoWsseSecurity_any_get(self) get_node_list((self)->any)
#define LassoWsseSecurity_set_any(self, value) set_node_list(&(self)->any, (value))
#define LassoWsseSecurity_any_set(self, value) set_node_list(&(self)->any, (value))

%}


/***********************************************************************
 ***********************************************************************
 * XML Elements in soap-binding Namespace
 ***********************************************************************
 ***********************************************************************/

/***********************************************************************
 * soap-binding:Correlation
 ***********************************************************************/

#ifndef SWIG_PHP_RENAMES
%rename(SoapBindingCorrelation) LassoSoapBindingCorrelation;
#endif
typedef struct {
	/* Attributes */
#ifndef SWIG_PHP_RENAMES
	%rename(messageId) messageID;
#endif
	char *messageID;

#ifndef SWIG_PHP_RENAMES
	%rename(refToMessageId) refToMessageID;
#endif
	char *refToMessageID;

	char *timestamp;

} LassoSoapBindingCorrelation;
%extend LassoSoapBindingCorrelation {
	/* Attributes */

	/* Constructor, Destructor & Static Methods */

	LassoSoapBindingCorrelation(char *messageID, char *timestamp);

	~LassoSoapBindingCorrelation();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes Implementations */

/* Constructors, destructors & static methods implementations */
#define new_LassoSoapBindingCorrelation lasso_soap_binding_correlation_new
#define delete_LassoSoapBindingCorrelation(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSoapBindingCorrelation_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 ***********************************************************************
 * XML Elements in soap-env Namespace
 ***********************************************************************
 ***********************************************************************/

/***********************************************************************
 * soap-env:Body
 ***********************************************************************/

#ifndef SWIG_PHP_RENAMES
%rename(SoapBody) LassoSoapBody;
#endif
typedef struct {

} LassoSoapBody;
%extend LassoSoapBody {
	/* Attributes */

	%newobject any_get;
	LassoNodeList *any;

	/* Constructor, Destructor & Static Methods */

	LassoSoapBody();

	~LassoSoapBody();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes Implementations */

/* any */
#define LassoSoapBody_get_any(self) get_node_list((self)->any)
#define LassoSoapBody_any_get(self) get_node_list((self)->any)
#define LassoSoapBody_set_any(self, value) set_node_list(&(self)->any, (value))
#define LassoSoapBody_any_set(self, value) set_node_list(&(self)->any, (value))

/* Constructors, destructors & static methods implementations */
#define new_LassoSoapBody lasso_soap_body_new
#define delete_LassoSoapBody(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSoapBody_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * soap-env:Envelope
 ***********************************************************************/

#ifndef SWIG_PHP_RENAMES
%rename(SoapEnvelope) LassoSoapEnvelope;
#endif
typedef struct {

} LassoSoapEnvelope;
%extend LassoSoapEnvelope {
	/* Attributes */

#ifndef SWIG_PHP_RENAMES
	%rename(header) Header;
#endif
	%newobject Header_get;
	LassoSoapHeader *Header;

#ifndef SWIG_PHP_RENAMES
	%rename(body) Body;
#endif
	%newobject Body_get;
	LassoSoapBody *Body;

	/* Constructor, Destructor & Static Methods */

	LassoSoapEnvelope(LassoSoapBody *body);

	~LassoSoapEnvelope();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes Implementations */

/* Header */
#define LassoSoapEnvelope_get_Header(self) get_node(self->Header)
#define LassoSoapEnvelope_Header_get(self) get_node(self->Header)
#define LassoSoapEnvelope_set_Header(self, value) set_node((gpointer *) &self->Header, (value))
#define LassoSoapEnvelope_Header_set(self, value) set_node((gpointer *) &self->Header, (value))

/* Body */
#define LassoSoapEnvelope_get_Body(self) get_node(self->Body)
#define LassoSoapEnvelope_Body_get(self) get_node(self->Body)
#define LassoSoapEnvelope_set_Body(self, value) set_node((gpointer *) &self->Body, (value))
#define LassoSoapEnvelope_Body_set(self, value) set_node((gpointer *) &self->Body, (value))

/* Constructors, destructors & static methods implementations */
#define new_LassoSoapEnvelope lasso_soap_envelope_new
#define delete_LassoSoapEnvelope(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSoapEnvelope_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

/***********************************************************************
 * soap-env:Header
 ***********************************************************************/

#ifndef SWIG_PHP_RENAMES
%rename(SoapHeader) LassoSoapHeader;
#endif
typedef struct {

} LassoSoapHeader;
%extend LassoSoapHeader {
	/* Attributes */

#ifndef SWIG_PHP_RENAMES
	%rename(other) Other;
#endif
	%newobject Other_get;
	LassoNodeList *Other;

	/* Constructor, Destructor & Static Methods */

	LassoSoapHeader();

	~LassoSoapHeader();

	void addOther(LassoNode *node) {
		if LASSO_IS_NODE(node) {
			self->Other = g_list_append(self->Other, node);
		}
	}

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes Implementations */

/* Other */
#define LassoSoapHeader_get_Other(self) get_node_list((self)->Other)
#define LassoSoapHeader_Other_get(self) get_node_list((self)->Other)
#define LassoSoapHeader_set_Other(self, value) set_node_list(&(self)->Other, (value))
#define LassoSoapHeader_Other_set(self, value) set_node_list(&(self)->Other, (value))

/* Constructors, destructors & static methods implementations */
#define new_LassoSoapHeader lasso_soap_header_new
#define delete_LassoSoapHeader(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSoapHeader_dump(self) lasso_node_dump(LASSO_NODE(self))

%}
