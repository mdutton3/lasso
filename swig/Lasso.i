/* -*- Mode: c; c-basic-offset: 8 -*-
 *
 * $Id$
 *
 * SWIG bindings for Lasso Library
 *
 * Copyright (C) 2004, 2005 Entr'ouvert
 * http://lasso.entrouvert.org
 *
 * Authors: Romain Chantereau <rchantereau@entrouvert.com>
 *          Nicolas Clapies <nclapies@entrouvert.com>
 *          Valery Febvre <vfebvre@easter-eggs.com>
 *          Frederic Peters <fpeters@entrouvert.com>
 *          Emmanuel Raviart <eraviart@entrouvert.com>
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


%module Lasso


%include exception.i       
%include typemaps.i


%{

#if defined(SWIGRUBY) || defined (PHP_VERSION)
/* Ruby and PHP pollute the #define space with these names */
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION
#undef PACKAGE_BUGREPORT
#endif

#include <lasso/lasso_config.h>
#include <lasso/lasso.h>
#include <lasso/xml/lib_assertion.h>


/* 
 * Thanks to the patch in this Debian bug for the solution
 * to the crash inside vsnprintf on some architectures.
 *
 * "reuse of args inside the while(1) loop is in violation of the
 * specs and only happens to work by accident on other systems."
 *
 * http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=104325 
 */

#ifndef va_copy
#ifdef __va_copy
#define va_copy(dest,src) __va_copy(dest,src)
#else
#define va_copy(dest,src) (dest) = (src)
#endif
#endif

%}

#ifdef SWIGJAVA
#if SWIG_VERSION >= 0x010322
  %include "enumsimple.swg"
#endif
%pragma(java) jniclasscode=%{
  static {
    try {
      // Load a library whose "core" name is "jlasso".
      // Operating system specific stuff will be added to make an
      // actual filename from this: Under Unix this will become
      // libjlasso.so while under Windows it will likely become
      // something like jlasso.dll.
      System.loadLibrary("jlasso");
    }
    catch (UnsatisfiedLinkError e) {
      System.err.println("Native code library failed to load. \n" + e);
      System.exit(1);
    }
    // Initialize Lasso.
    init();
  }
%}
#else

#ifdef SWIGPYTHON
%{
	PyObject *lassoError;
	PyObject *LASSO_WARNING;
%}

%init %{
	lassoError = PyErr_NewException("_lasso.Error", NULL, NULL);
	Py_INCREF(lassoError);
	PyModule_AddObject(m, "Error", lassoError);

	LASSO_WARNING = PyErr_NewException("_lasso.Warning", lassoError, NULL);
	Py_INCREF(LASSO_WARNING);
	PyModule_AddObject(m, "Warning", LASSO_WARNING);
	
	lasso_init();
%}

%pythoncode %{
Error = _lasso.Error
Warning = _lasso.Warning
%}

#else
/* Apache fails when lasso_init is called too early in PHP binding. */
/* FIXME: To investigate. */
#ifndef SWIGPHP4
%init %{
	lasso_init();
%}
#endif
#endif
#endif


/***********************************************************************
 ***********************************************************************
 * Common
 ***********************************************************************
 ***********************************************************************/


#if defined(SWIGPYTHON)
%typemap(in,parse="z") char *, char [ANY] "";
#endif


#if defined(SWIGPHP4)
%{
/* ZVAL_STRING segfault when s is null */
#undef ZVAL_STRING
#define ZVAL_STRING(z, s, duplicate) {	\
		char *__s=(s);					\
        if (__s) {                      \
		  (z)->value.str.len = strlen(__s);	\
		  (z)->value.str.val = (duplicate?estrndup(__s, (z)->value.str.len):__s);	\
		} else {                        \
		  (z)->value.str.len = 0;	    \
		  (z)->value.str.val = empty_string; \
		}                               \
		(z)->type = IS_STRING;	        \
	}
%}
#endif

/* GLib types */

#define gboolean bool
%{
#define bool int
#define false 0
#define true 1
%}
#define gchar char
#define gint int
#define gpointer void*
#define GPtrArray void

/* Functions */

#ifndef SWIGPHP4
%rename(init) lasso_init;
#endif
int lasso_init(void);

#ifndef SWIGPHP4
%rename(shutdown) lasso_shutdown;
#endif
int lasso_shutdown(void);

/* Helper variables and functions */

#if !defined(SWIGJAVA) && !defined(SWIGCSHARP)

%{

typedef struct node_info {
	char *name;
	swig_type_info *swig;
} node_info;

static node_info node_infos[100]; /* FIXME: Size should be computed */

%}

%init %{

	node_info *info;

#define SET_NODE_INFO(nodeTypeName) info->name = #nodeTypeName;\
	info->swig = SWIGTYPE_p_##nodeTypeName;\
	info++

	info = node_infos;
	SET_NODE_INFO(LassoNode);

#if 0
	SET_NODE_INFO(LassoDiscoCredentials);
	SET_NODE_INFO(LassoDiscoDescription);
	SET_NODE_INFO(LassoDiscoEncryptedResourceID);
	SET_NODE_INFO(LassoDiscoInsertEntry);
	SET_NODE_INFO(LassoDiscoModify);
	SET_NODE_INFO(LassoDiscoModifyResponse);
	SET_NODE_INFO(LassoDiscoOptions);
	SET_NODE_INFO(LassoDiscoQuery);
	SET_NODE_INFO(LassoDiscoQueryResponse);
	SET_NODE_INFO(LassoDiscoRemoveEntry);
	SET_NODE_INFO(LassoDiscoRequestedServiceType);
	SET_NODE_INFO(LassoDiscoResourceID);
	SET_NODE_INFO(LassoDiscoResourceOffering);
	SET_NODE_INFO(LassoDiscoServiceInstance);

	SET_NODE_INFO(LassoDstModification);
	SET_NODE_INFO(LassoDstModify);
	SET_NODE_INFO(LassoDstModifyResponse);
	SET_NODE_INFO(LassoDstNewData);
	SET_NODE_INFO(LassoDstQuery);
	SET_NODE_INFO(LassoDstQueryItem);
	SET_NODE_INFO(LassoDstQueryResponse);
#endif

	SET_NODE_INFO(LassoLibAssertion);
	SET_NODE_INFO(LassoLibAuthnRequest);
	SET_NODE_INFO(LassoLibAuthnResponse);
	SET_NODE_INFO(LassoLibFederationTerminationNotification);
	SET_NODE_INFO(LassoLibLogoutRequest);
	SET_NODE_INFO(LassoLibLogoutResponse);
	SET_NODE_INFO(LassoLibRegisterNameIdentifierRequest);
	SET_NODE_INFO(LassoLibRegisterNameIdentifierResponse);
	SET_NODE_INFO(LassoLibStatusResponse);

#if 0
	SET_NODE_INFO(LassoPPMsgContact);
#endif

	SET_NODE_INFO(LassoSamlAdvice);
	SET_NODE_INFO(LassoSamlAssertion);
	SET_NODE_INFO(LassoSamlAttribute);
	SET_NODE_INFO(LassoSamlAttributeStatement);
	SET_NODE_INFO(LassoSamlAuthenticationStatement);
	SET_NODE_INFO(LassoSamlConditions);
	SET_NODE_INFO(LassoSamlNameIdentifier);
	SET_NODE_INFO(LassoSamlSubject);
	SET_NODE_INFO(LassoSamlSubjectConfirmation);
	SET_NODE_INFO(LassoSamlSubjectLocality);
	SET_NODE_INFO(LassoSamlSubjectStatement);

	SET_NODE_INFO(LassoSamlpRequest);
	SET_NODE_INFO(LassoSamlpResponse);
	SET_NODE_INFO(LassoSamlpStatus);
	SET_NODE_INFO(LassoSamlpStatusCode);

	info->name = NULL;
	info->swig = NULL;

%}

/* Accept any GObject class derivated from LassoNode as a LassoNode */
%typemap(in) LassoNode * {
	node_info *info;
#ifdef SWIGPERL5
	for (info = node_infos; info->swig; info++)
		if (SWIG_ConvertPtr($input, (void **) &$1, info->swig, 0) < 0)
			break;
	if (! info->swig)
		SWIG_croak("Type error in argument $argnum of $symname. Expected $1_mangle");
#else
#ifdef SWIGPHP4
	for (info = node_infos; info->swig; info++)
		if (SWIG_ConvertPtr(*$input, (void **) &$1, info->swig) < 0)
			break;
	if (! info->swig)
		zend_error(E_ERROR, "Type error in argument %d of $symname. Expected %s",
			   $argnum-argbase, $1_descriptor->name);
#else /* SWIGPYTHON */
	for (info = node_infos; info->swig; info++)
		if (SWIG_ConvertPtr($input, (void **) &$1, info->swig, $disown) != -1)
			break;
	if (! info->swig) {
		/* Display error message. */
		SWIG_ConvertPtr($input, (void **) &$1, $1_descriptor,
				SWIG_POINTER_EXCEPTION | $disown);
		SWIG_fail;
	}
#endif
#endif
}

%apply SWIGTYPE *DYNAMIC { LassoNode * };

/* Cast a LassoNode into the appropriate derivated class. */
%{
static swig_type_info *LassoNode_dynamic(void **nodePointer) {
	node_info *info;
	char *name;

	name = (char *) G_OBJECT_TYPE_NAME(*nodePointer);
	for (info = node_infos; info->swig; info++) {
		if (strcmp(info->name, name) == 0)
			return info->swig;
	}
	return NULL;
}
%}

/* Register the above casting function. */
DYNAMIC_CAST(SWIGTYPE_p_LassoNode, LassoNode_dynamic);

#endif

%{

static void add_key_to_array(char *key, gpointer pointer, GPtrArray *array)
{
        g_ptr_array_add(array, g_strdup(key));
}

static void add_node_to_array(gpointer node, GPtrArray *array)
{
	if (node != NULL)
		g_object_ref(node);
        g_ptr_array_add(array, node);
}

static void add_xml_to_array(xmlNode *xmlnode, GPtrArray *array)
{
	xmlOutputBufferPtr buf;
	gchar *xmlString;

	buf = xmlAllocOutputBuffer(NULL);
	if (buf == NULL)
		xmlString = NULL;
	else {
		xmlNodeDumpOutput(buf, NULL, xmlnode, 0, 1, NULL);
		xmlOutputBufferFlush(buf);
		if (buf->conv == NULL)
			xmlString = g_strdup(buf->buffer->content);
		else
			xmlString = g_strdup(buf->conv->content);
		xmlOutputBufferClose(buf);
	}
	g_ptr_array_add(array, xmlString);
}

static void free_node_array_item(gpointer node, gpointer unused)
{
	if (node != NULL)
		/* Test added to help debugging. */
		if (LASSO_IS_NODE(node))
			lasso_node_destroy(LASSO_NODE(node));
		else
			g_object_unref(node);
}

static void free_node_list_item(gpointer node, gpointer unused)
{
	if (node != NULL)
		/* Test added to help debugging. */
		if (LASSO_IS_NODE(node))
			lasso_node_destroy(LASSO_NODE(node));
		else
			g_object_unref(node);
}

static void free_xml_list_item(xmlNode *xmlnode, gpointer unused)
{
	if (xmlnode != NULL)
		xmlFreeNode(xmlnode);
}

static gpointer get_node(gpointer node)
{
	return node == NULL ? NULL : g_object_ref(node);
}

static GPtrArray *get_node_list(GList *nodeList) {
	GPtrArray *nodeArray;

	if (nodeList == NULL)
		return NULL;
	nodeArray = g_ptr_array_sized_new(g_list_length(nodeList));
	g_list_foreach(nodeList, (GFunc) add_node_to_array, nodeArray);
	return nodeArray;
}

static GPtrArray *get_xml_list(GList *xmlList) {
	GPtrArray *xmlArray;

	if (xmlList == NULL)
		return NULL;
	xmlArray = g_ptr_array_sized_new(g_list_length(xmlList));
	g_list_foreach(xmlList, (GFunc) add_xml_to_array, xmlArray);
	return xmlArray;
}

static void set_node(gpointer *nodePointer, gpointer value)
{
	if (*nodePointer != NULL)
		/* Test added to help debugging. */
		if (LASSO_IS_NODE(*nodePointer))
			lasso_node_destroy(LASSO_NODE(*nodePointer));
		else
			g_object_unref(*nodePointer);
	*nodePointer = value == NULL ? NULL : g_object_ref(value);
}

static void set_node_list(GList **nodeListPointer, GPtrArray *nodeArray) {
	if (*nodeListPointer != NULL) {
		g_list_foreach(*nodeListPointer, (GFunc) free_node_list_item, NULL);
		g_list_free(*nodeListPointer);
	}
	if (nodeArray == NULL)
		*nodeListPointer = NULL;
	else {
		gpointer node;
		int index;

		for (index = 0; index < nodeArray->len; index ++) {
			node = g_ptr_array_index(nodeArray, index);
			if (node != NULL)
				g_object_ref(node);
			*nodeListPointer = g_list_append(*nodeListPointer, node);
		}
	}
}

static void set_string(char **pointer, char *value)
{
	if (*pointer != NULL)
		free(*pointer);
	*pointer = value == NULL ? NULL : strdup(value);
}

static void set_xml_list(GList **xmlListPointer, GPtrArray *xmlArray) {
	if (*xmlListPointer != NULL) {
		g_list_foreach(*xmlListPointer, (GFunc) free_xml_list_item, NULL);
		g_list_free(*xmlListPointer);
	}
	if (xmlArray == NULL)
		*xmlListPointer = NULL;
	else {
		xmlDoc *doc;
		int index;
		xmlNode *node;
		char *xmlString;

		for (index = 0; index < xmlArray->len; index ++) {
			xmlString = g_ptr_array_index(xmlArray, index);
			if (xmlString == NULL)
				node = NULL;
			else {
				doc = xmlReadDoc(g_ptr_array_index(xmlArray, index), NULL, NULL,
						 XML_PARSE_NONET);
				if (doc == NULL)
					continue;
				node = xmlDocGetRootElement(doc);
				if (node != NULL)
					node = xmlCopyNode(node, 1);
				xmlFreeDoc(doc);
			}
			*xmlListPointer = g_list_append(*xmlListPointer, node);
		}
	}
}

%}


/***********************************************************************
 * Constants
 ***********************************************************************/


/* Version number */
#ifndef SWIGPHP4
%rename(VERSION_MAJOR) LASSO_VERSION_MAJOR;
%rename(VERSION_MINOR) LASSO_VERSION_MINOR;
%rename(VERSION_SUBMINOR) LASSO_VERSION_SUBMINOR;
#endif
/* Useless because some lines before, we explicitly tell to include lasso_config
 * in the generated wrap C source code.
 * #define LASSO_VERSION_MAJOR 0
#define LASSO_VERSION_MINOR 4
#define LASSO_VERSION_SUBMINOR 0*/


/* HttpMethod */
#ifndef SWIGPHP4
%rename(httpMethodAny) LASSO_HTTP_METHOD_ANY;
%rename(httpMethodIdpInitiated) LASSO_HTTP_METHOD_IDP_INITIATED;
%rename(httpMethodGet) LASSO_HTTP_METHOD_GET;
%rename(httpMethodPost) LASSO_HTTP_METHOD_POST;
%rename(httpMethodRedirect) LASSO_HTTP_METHOD_REDIRECT;
%rename(httpMethodSoap) LASSO_HTTP_METHOD_SOAP;
#endif
typedef enum {
	LASSO_HTTP_METHOD_NONE = -1,
	LASSO_HTTP_METHOD_ANY,
	LASSO_HTTP_METHOD_IDP_INITIATED,
	LASSO_HTTP_METHOD_GET,
	LASSO_HTTP_METHOD_POST,
	LASSO_HTTP_METHOD_REDIRECT,
	LASSO_HTTP_METHOD_SOAP
} LassoHttpMethod;

/* Consent */
#ifndef SWIGPHP4
%rename(libConsentObtained) LASSO_LIB_CONSENT_OBTAINED;
%rename(libConsentObtainedPrior) LASSO_LIB_CONSENT_OBTAINED_PRIOR;
%rename(libConsentObtainedCurrentImplicit) LASSO_LIB_CONSENT_OBTAINED_CURRENT_IMPLICIT;
%rename(libConsentObtainedCurrentExplicit) LASSO_LIB_CONSENT_OBTAINED_CURRENT_EXPLICIT;
%rename(libConsentUnavailable) LASSO_LIB_CONSENT_UNAVAILABLE;
%rename(libConsentInapplicable) LASSO_LIB_CONSENT_INAPPLICABLE;
#endif
#define LASSO_LIB_CONSENT_OBTAINED "urn:liberty:consent:obtained"
#define LASSO_LIB_CONSENT_OBTAINED_PRIOR "urn:liberty:consent:obtained:prior"
#define LASSO_LIB_CONSENT_OBTAINED_CURRENT_IMPLICIT "urn:liberty:consent:obtained:current:implicit"
#define LASSO_LIB_CONSENT_OBTAINED_CURRENT_EXPLICIT "urn:liberty:consent:obtained:current:explicit"
#define LASSO_LIB_CONSENT_UNAVAILABLE "urn:liberty:consent:unavailable"
#define LASSO_LIB_CONSENT_INAPPLICABLE "urn:liberty:consent:inapplicable"

/* NameIdPolicyType */
#ifndef SWIGPHP4
%rename(libNameIdPolicyTypeNone) LASSO_LIB_NAMEID_POLICY_TYPE_NONE;
%rename(libNameIdPolicyTypeOneTime) LASSO_LIB_NAMEID_POLICY_TYPE_ONE_TIME;
%rename(libNameIdPolicyTypeFederated) LASSO_LIB_NAMEID_POLICY_TYPE_FEDERATED;
%rename(libNameIdPolicyTypeAny) LASSO_LIB_NAMEID_POLICY_TYPE_ANY;
#endif
#define LASSO_LIB_NAMEID_POLICY_TYPE_NONE "none"
#define LASSO_LIB_NAMEID_POLICY_TYPE_ONE_TIME "onetime"
#define LASSO_LIB_NAMEID_POLICY_TYPE_FEDERATED "federated"
#define LASSO_LIB_NAMEID_POLICY_TYPE_ANY "any"

/* ProtocolProfile */
#ifndef SWIGPHP4
%rename(libProtocolProfileBrwsArt) LASSO_LIB_PROTOCOL_PROFILE_BRWS_ART;
%rename(libProtocolProfileBrwsPost) LASSO_LIB_PROTOCOL_PROFILE_BRWS_POST;
%rename(libProtocolProfileFedTermIdpHttp) LASSO_LIB_PROTOCOL_PROFILE_FED_TERM_IDP_HTTP;
%rename(libProtocolProfileFedTermIdpSoap) LASSO_LIB_PROTOCOL_PROFILE_FED_TERM_IDP_SOAP;
%rename(libProtocolProfileFedTermSpHttp) LASSO_LIB_PROTOCOL_PROFILE_FED_TERM_SP_HTTP;
%rename(libProtocolProfileFedTermSpSoap) LASSO_LIB_PROTOCOL_PROFILE_FED_TERM_SP_SOAP;
%rename(libProtocolProfileRniIdpHttp) LASSO_LIB_PROTOCOL_PROFILE_RNI_IDP_HTTP;
%rename(libProtocolProfileRniIdpSoap) LASSO_LIB_PROTOCOL_PROFILE_RNI_IDP_SOAP;
%rename(libProtocolProfileRniSpHttp) LASSO_LIB_PROTOCOL_PROFILE_RNI_SP_HTTP;
%rename(libProtocolProfileRniSpSoap) LASSO_LIB_PROTOCOL_PROFILE_RNI_SP_SOAP;
%rename(libProtocolProfileSloIdpHttp) LASSO_LIB_PROTOCOL_PROFILE_SLO_IDP_HTTP;
%rename(libProtocolProfileSloIdpSoap) LASSO_LIB_PROTOCOL_PROFILE_SLO_IDP_SOAP;
%rename(libProtocolProfileSloSpHttp) LASSO_LIB_PROTOCOL_PROFILE_SLO_SP_HTTP;
%rename(libProtocolProfileSloSpSoap) LASSO_LIB_PROTOCOL_PROFILE_SLO_SP_SOAP;
#endif
#define LASSO_LIB_PROTOCOL_PROFILE_BRWS_ART "http://projectliberty.org/profiles/brws-art"
#define LASSO_LIB_PROTOCOL_PROFILE_BRWS_POST "http://projectliberty.org/profiles/brws-post"
#define LASSO_LIB_PROTOCOL_PROFILE_FED_TERM_IDP_HTTP "http://projectliberty.org/profiles/fedterm-idp-http"
#define LASSO_LIB_PROTOCOL_PROFILE_FED_TERM_IDP_SOAP "http://projectliberty.org/profiles/fedterm-idp-soap"
#define LASSO_LIB_PROTOCOL_PROFILE_FED_TERM_SP_HTTP "http://projectliberty.org/profiles/fedterm-sp-http"
#define LASSO_LIB_PROTOCOL_PROFILE_FED_TERM_SP_SOAP "http://projectliberty.org/profiles/fedterm-sp-soap"
#define LASSO_LIB_PROTOCOL_PROFILE_RNI_IDP_HTTP "http://projectliberty.org/profiles/rni-idp-http"
#define LASSO_LIB_PROTOCOL_PROFILE_RNI_IDP_SOAP "http://projectliberty.org/profiles/rni-idp-soap"
#define LASSO_LIB_PROTOCOL_PROFILE_RNI_SP_HTTP "http://projectliberty.org/profiles/rni-sp-http"
#define LASSO_LIB_PROTOCOL_PROFILE_RNI_SP_SOAP "http://projectliberty.org/profiles/rni-sp-soap"
#define LASSO_LIB_PROTOCOL_PROFILE_SLO_IDP_HTTP "http://projectliberty.org/profiles/slo-idp-http"
#define LASSO_LIB_PROTOCOL_PROFILE_SLO_IDP_SOAP "http://projectliberty.org/profiles/slo-idp-soap"
#define LASSO_LIB_PROTOCOL_PROFILE_SLO_SP_HTTP "http://projectliberty.org/profiles/slo-sp-http"
#define LASSO_LIB_PROTOCOL_PROFILE_SLO_SP_SOAP "http://projectliberty.org/profiles/slo-sp-soap"

/* LoginProtocolProfile */
#ifndef SWIGPHP4
%rename(loginProtocolProfileBrwsArt) LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_ART;
%rename(loginProtocolProfileBrwsPost) LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_POST;
#endif
typedef enum {
	LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_ART = 1,
	LASSO_LOGIN_PROTOCOL_PROFILE_BRWS_POST,
} LassoLoginProtocolProfile;

/* MessageType */
#ifndef SWIGPHP4
%rename(messageTypeNone) LASSO_MESSAGE_TYPE_NONE;
%rename(messageTypeAuthnRequest) LASSO_MESSAGE_TYPE_AUTHN_REQUEST;
%rename(messageTypeAuthnResponse) LASSO_MESSAGE_TYPE_AUTHN_RESPONSE;
%rename(messageTypeRequest) LASSO_MESSAGE_TYPE_REQUEST;
%rename(messageTypeResponse) LASSO_MESSAGE_TYPE_RESPONSE;
%rename(messageTypeArtifact) LASSO_MESSAGE_TYPE_ARTIFACT;
#endif
typedef enum {
	LASSO_MESSAGE_TYPE_NONE = 0,
	LASSO_MESSAGE_TYPE_AUTHN_REQUEST,
	LASSO_MESSAGE_TYPE_AUTHN_RESPONSE,
	LASSO_MESSAGE_TYPE_REQUEST,
	LASSO_MESSAGE_TYPE_RESPONSE,
	LASSO_MESSAGE_TYPE_ARTIFACT
} LassoMessageType;

/* ProviderRole */
#ifndef SWIGPHP4
%rename(providerRoleNone) LASSO_PROVIDER_ROLE_NONE;
%rename(providerRoleSp) LASSO_PROVIDER_ROLE_SP;
%rename(providerRoleIdp) LASSO_PROVIDER_ROLE_IDP;
#endif
typedef enum {
	LASSO_PROVIDER_ROLE_NONE = 0,
	LASSO_PROVIDER_ROLE_SP,
	LASSO_PROVIDER_ROLE_IDP
} LassoProviderRole;

/* RequestType */
#ifndef SWIGPHP4
%rename(requestTypeInvalid) LASSO_REQUEST_TYPE_INVALID;
%rename(requestTypeLogin) LASSO_REQUEST_TYPE_LOGIN;
%rename(requestTypeLogout) LASSO_REQUEST_TYPE_LOGOUT;
%rename(requestTypeDefederation) LASSO_REQUEST_TYPE_DEFEDERATION;
%rename(requestTypeNameRegistration) LASSO_REQUEST_TYPE_NAME_REGISTRATION;
%rename(requestTypeNameIdentifierMapping) LASSO_REQUEST_TYPE_NAME_IDENTIFIER_MAPPING;
%rename(requestTypeLecp) LASSO_REQUEST_TYPE_LECP;
#endif
typedef enum {
	LASSO_REQUEST_TYPE_INVALID = 0,
	LASSO_REQUEST_TYPE_LOGIN = 1,
	LASSO_REQUEST_TYPE_LOGOUT = 2,
	LASSO_REQUEST_TYPE_DEFEDERATION = 3,
	LASSO_REQUEST_TYPE_NAME_REGISTRATION = 4,
	LASSO_REQUEST_TYPE_NAME_IDENTIFIER_MAPPING = 5,
	LASSO_REQUEST_TYPE_LECP = 6
} LassoRequestType;

/* SamlAuthenticationMethod */
#ifndef SWIGPHP4
%rename(samlAuthenticationMethodPassword) LASSO_SAML_AUTHENTICATION_METHOD_PASSWORD;
%rename(samlAuthenticationMethodKerberos) LASSO_SAML_AUTHENTICATION_METHOD_KERBEROS;
%rename(samlAuthenticationMethodSecureRemotePassword) LASSO_SAML_AUTHENTICATION_METHOD_SECURE_REMOTE_PASSWORD;
%rename(samlAuthenticationMethodHardwareToken) LASSO_SAML_AUTHENTICATION_METHOD_HARDWARE_TOKEN;
%rename(samlAuthenticationMethodSmartcardPki) LASSO_SAML_AUTHENTICATION_METHOD_SMARTCARD_PKI;
%rename(samlAuthenticationMethodSoftwarePki) LASSO_SAML_AUTHENTICATION_METHOD_SOFTWARE_PKI;
%rename(samlAuthenticationMethodPgp) LASSO_SAML_AUTHENTICATION_METHOD_PGP;
%rename(samlAuthenticationMethodSpki) LASSO_SAML_AUTHENTICATION_METHODS_PKI;
%rename(samlAuthenticationMethodXkms) LASSO_SAML_AUTHENTICATION_METHOD_XKMS;
%rename(samlAuthenticationMethodXmlDsig) LASSO_SAML_AUTHENTICATION_METHOD_XMLD_SIG;
%rename(samlAuthenticationMethodUnspecified) LASSO_SAML_AUTHENTICATION_METHOD_UNSPECIFIED;
#endif
#define LASSO_SAML_AUTHENTICATION_METHOD_PASSWORD "urn:oasis:names:tc:SAML:1.0:am:password"
#define LASSO_SAML_AUTHENTICATION_METHOD_KERBEROS "urn:ietf:rfc:1510"
#define LASSO_SAML_AUTHENTICATION_METHOD_SECURE_REMOTE_PASSWORD "urn:ietf:rfc:2945"
#define LASSO_SAML_AUTHENTICATION_METHOD_HARDWARE_TOKEN "urn:oasis:names:tc:SAML:1.0:am:HardwareToken"
#define LASSO_SAML_AUTHENTICATION_METHOD_SMARTCARD_PKI "urn:ietf:rfc:2246"
#define LASSO_SAML_AUTHENTICATION_METHOD_SOFTWARE_PKI "urn:oasis:names:tc:SAML:1.0:am:X509-PKI"
#define LASSO_SAML_AUTHENTICATION_METHOD_PGP "urn:oasis:names:tc:SAML:1.0:am:PGP"
#define LASSO_SAML_AUTHENTICATION_METHODS_PKI "urn:oasis:names:tc:SAML:1.0:am:SPKI"
#define LASSO_SAML_AUTHENTICATION_METHOD_XKMS "urn:oasis:names:tc:SAML:1.0:am:XKMS"
#define LASSO_SAML_AUTHENTICATION_METHOD_XMLD_SIG "urn:ietf:rfc:3075"
#define LASSO_SAML_AUTHENTICATION_METHOD_UNSPECIFIED "urn:oasis:names:tc:SAML:1.0:am:unspecified"

/* SignatureMethod */
#ifndef SWIGPHP4
%rename(signatureMethodRsaSha1) LASSO_SIGNATURE_METHOD_RSA_SHA1;
%rename(signatureMethodDsaSha1) LASSO_SIGNATURE_METHOD_DSA_SHA1;
#endif
typedef enum {
	LASSO_SIGNATURE_METHOD_RSA_SHA1 = 1,
	LASSO_SIGNATURE_METHOD_DSA_SHA1
} LassoSignatureMethod;


/***********************************************************************
 * Errors
 ***********************************************************************/


/* undefined */
#ifndef SWIGPHP4
%rename(ERROR_UNDEFINED) LASSO_ERROR_UNDEFINED;
#endif

/* generic XML */
#ifndef SWIGPHP4
%rename(XML_ERROR_NODE_NOT_FOUND) LASSO_XML_ERROR_NODE_NOT_FOUND;
%rename(XML_ERROR_NODE_CONTENT_NOT_FOUND) LASSO_XML_ERROR_NODE_CONTENT_NOT_FOUND;
%rename(XML_ERROR_ATTR_NOT_FOUND) LASSO_XML_ERROR_ATTR_NOT_FOUND;
%rename(XML_ERROR_ATTR_VALUE_NOT_FOUND) LASSO_XML_ERROR_ATTR_VALUE_NOT_FOUND;
#endif

/* XMLDSig */
#ifndef SWIGPHP4
%rename(DS_ERROR_SIGNATURE_NOT_FOUND) LASSO_DS_ERROR_SIGNATURE_NOT_FOUND;
%rename(DS_ERROR_INVALID_SIGNATURE) LASSO_DS_ERROR_INVALID_SIGNATURE;
%rename(DS_ERROR_SIGNATURE_TMPL_CREATION_FAILED) LASSO_DS_ERROR_SIGNATURE_TMPL_CREATION_FAILED;
%rename(DS_ERROR_CONTEXT_CREATION_FAILED) LASSO_DS_ERROR_CONTEXT_CREATION_FAILED;
%rename(DS_ERROR_PUBLIC_KEY_LOAD_FAILED) LASSO_DS_ERROR_PUBLIC_KEY_LOAD_FAILED;
%rename(DS_ERROR_PRIVATE_KEY_LOAD_FAILED) LASSO_DS_ERROR_PRIVATE_KEY_LOAD_FAILED;
%rename(DS_ERROR_CERTIFICATE_LOAD_FAILED) LASSO_DS_ERROR_CERTIFICATE_LOAD_FAILED;
%rename(DS_ERROR_SIGNATURE_FAILED) LASSO_DS_ERROR_SIGNATURE_FAILED;
%rename(DS_ERROR_KEYS_MNGR_CREATION_FAILED) LASSO_DS_ERROR_KEYS_MNGR_CREATION_FAILED;
%rename(DS_ERROR_KEYS_MNGR_INIT_FAILED) LASSO_DS_ERROR_KEYS_MNGR_INIT_FAILED;
%rename(DS_ERROR_SIGNATURE_VERIFICATION_FAILED) LASSO_DS_ERROR_SIGNATURE_VERIFICATION_FAILED;
%rename(DS_ERROR_CA_CERT_CHAIN_LOAD_FAILED) LASSO_DS_ERROR_CA_CERT_CHAIN_LOAD_FAILED;
%rename(DS_ERROR_INVALID_SIGALG) LASSO_DS_ERROR_INVALID_SIGALG;
%rename(DS_ERROR_DIGEST_COMPUTE_FAILED) LASSO_DS_ERROR_DIGEST_COMPUTE_FAILED;
#endif

/* Server */
#ifndef SWIGPHP4
%rename(SERVER_ERROR_PROVIDER_NOT_FOUND) LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND;
%rename(SERVER_ERROR_ADD_PROVIDER_FAILED) LASSO_SERVER_ERROR_ADD_PROVIDER_FAILED;
#endif

/* Single Logout */
#ifndef SWIGPHP4
%rename(LOGOUT_ERROR_UNSUPPORTED_PROFILE) LASSO_LOGOUT_ERROR_UNSUPPORTED_PROFILE;
#endif

/* Profile */
#ifndef SWIGPHP4
%rename(PROFILE_ERROR_INVALID_QUERY) LASSO_PROFILE_ERROR_INVALID_QUERY;
%rename(PROFILE_ERROR_INVALID_POST_MSG) LASSO_PROFILE_ERROR_INVALID_POST_MSG;
%rename(PROFILE_ERROR_INVALID_SOAP_MSG) LASSO_PROFILE_ERROR_INVALID_SOAP_MSG;
%rename(PROFILE_ERROR_MISSING_REQUEST) LASSO_PROFILE_ERROR_MISSING_REQUEST;
%rename(PROFILE_ERROR_INVALID_HTTP_METHOD) LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD;
%rename(PROFILE_ERROR_INVALID_PROTOCOLPROFILE) LASSO_PROFILE_ERROR_INVALID_PROTOCOLPROFILE;
%rename(PROFILE_ERROR_INVALID_MSG) LASSO_PROFILE_ERROR_INVALID_MSG;
%rename(PROFILE_ERROR_MISSING_REMOTE_PROVIDERID) LASSO_PROFILE_ERROR_MISSING_REMOTE_PROVIDERID;
%rename(PROFILE_ERROR_UNSUPPORTED_PROFILE) LASSO_PROFILE_ERROR_UNSUPPORTED_PROFILE;
%rename(PROFILE_ERROR_UNKNOWN_PROFILE_URL) LASSO_PROFILE_ERROR_UNKNOWN_PROFILE_URL;
%rename(PROFILE_ERROR_IDENTITY_NOT_FOUND) LASSO_PROFILE_ERROR_IDENTITY_NOT_FOUND;
%rename(PROFILE_ERROR_FEDERATION_NOT_FOUND) LASSO_PROFILE_ERROR_FEDERATION_NOT_FOUND;
%rename(PROFILE_ERROR_NAME_IDENTIFIER_NOT_FOUND) LASSO_PROFILE_ERROR_NAME_IDENTIFIER_NOT_FOUND;
%rename(PROFILE_ERROR_BUILDING_QUERY_FAILED) LASSO_PROFILE_ERROR_BUILDING_QUERY_FAILED;
%rename(PROFILE_ERROR_BUILDING_REQUEST_FAILED) LASSO_PROFILE_ERROR_BUILDING_REQUEST_FAILED;
%rename(PROFILE_ERROR_BUILDING_MESSAGE_FAILED) LASSO_PROFILE_ERROR_BUILDING_MESSAGE_FAILED;
%rename(PROFILE_ERROR_BUILDING_RESPONSE_FAILED) LASSO_PROFILE_ERROR_BUILDING_RESPONSE_FAILED;
%rename(PROFILE_ERROR_SESSION_NOT_FOUND) LASSO_PROFILE_ERROR_SESSION_NOT_FOUND;
%rename(PROFILE_ERROR_BAD_IDENTITY_DUMP) LASSO_PROFILE_ERROR_BAD_IDENTITY_DUMP;
%rename(PROFILE_ERROR_BAD_SESSION_DUMP) LASSO_PROFILE_ERROR_BAD_SESSION_DUMP;
#endif

/* functions/methods parameters checking */
#ifndef SWIGPHP4
%rename(PARAM_ERROR_BADTYPE_OR_NULL_OBJ) LASSO_PARAM_ERROR_BADTYPE_OR_NULL_OBJ;
%rename(PARAM_ERROR_INVALID_VALUE) LASSO_PARAM_ERROR_INVALID_VALUE;
%rename(PARAM_ERROR_ERR_CHECK_FAILED) LASSO_PARAM_ERROR_ERR_CHECK_FAILED;
#endif

/* Single Sign-On */
#ifndef SWIGPHP4
%rename(LOGIN_ERROR_FEDERATION_NOT_FOUND) LASSO_LOGIN_ERROR_FEDERATION_NOT_FOUND;
%rename(LOGIN_ERROR_CONSENT_NOT_OBTAINED) LASSO_LOGIN_ERROR_CONSENT_NOT_OBTAINED;
%rename(LASSO_LOGIN_ERROR_INVALID_NAMEIDPOLICY) LASSO_LOGIN_ERROR_INVALID_NAMEIDPOLICY;
%rename(LOGIN_ERROR_REQUEST_DENIE) LASSO_LOGIN_ERROR_REQUEST_DENIE;
%rename(LOGIN_ERROR_INVALID_SIGNATURE) LASSO_LOGIN_ERROR_INVALID_SIGNATURE;
%rename(LOGIN_ERROR_UNSIGNED_AUTHN_REQUEST) LASSO_LOGIN_ERROR_UNSIGNED_AUTHN_REQUEST;
%rename(LOGIN_ERROR_STATUS_NOT_SUCCESS) LASSO_LOGIN_ERROR_STATUS_NOT_SUCCESS;
#endif

/* Federation Termination Notification */
#ifndef SWIGPHP4
%rename(DEFEDERATION_ERROR_MISSING_NAME_IDENTIFIER) LASSO_DEFEDERATION_ERROR_MISSING_NAME_IDENTIFIER;
#endif

#ifndef SWIGPHP4
%rename(strerror) lasso_strerror;
#endif
%ignore lasso_strerror;

%include "../lasso/xml/errors.h"
%{
#include <lasso/xml/errors.h>
%}


/***********************************************************************
 * Exceptions Generation From Lasso Error Codes
 ***********************************************************************/


#ifdef SWIGPYTHON

%{

static void lasso_exception(int errorCode) {
	PyObject *errorTuple;

	if (errorCode > 0) {
		errorTuple = Py_BuildValue("(is)", errorCode, "Lasso Warning");
		PyErr_SetObject(LASSO_WARNING, errorTuple);
		Py_DECREF(errorTuple);
	}
	else {
		errorTuple = Py_BuildValue("(is)", errorCode, "Lasso Error");
		PyErr_SetObject(lassoError, errorTuple);
		Py_DECREF(errorTuple);
	}
}

%}

%define THROW_ERROR
%exception {
	int errorCode;
	errorCode = $action
	if (errorCode) {
		lasso_exception(errorCode);
		SWIG_fail;
	}
}
%enddef

#else

%{

static void build_exception_msg(int errorCode, char *errorMsg) {
	if (errorCode > 0)
		sprintf(errorMsg, "%d / Lasso Warning", errorCode);
	else
		sprintf(errorMsg, "%d / Lasso Error", errorCode);
}

%}

%define THROW_ERROR
%exception {
	int errorCode;
	errorCode = $action
	if (errorCode) {
		char errorMsg[256];
		build_exception_msg(errorCode, errorMsg);
		SWIG_exception(SWIG_UnknownError, errorMsg);
	}
}
%enddef

#endif

%define END_THROW_ERROR
%exception;
%enddef


/***********************************************************************
 * NodeArray
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(NodeArray) LassoNodeArray;
#endif
%{
typedef GPtrArray LassoNodeArray;
%}
typedef struct {
	%extend {
		/* Constructor, Destructor & Static Methods */

		LassoNodeArray();

		~LassoNodeArray();

		/* Methods */

		void append(LassoNode *item) {
			if (item != NULL)
				g_object_ref(item);
			g_ptr_array_add(self, item);
		}

		GPtrArray *cast() {
			return self;
		}

		static LassoNodeArray *frompointer(GPtrArray *nodeArray) {
			return (LassoNodeArray *) nodeArray;
		}

#if defined(SWIGPYTHON)
		%rename(__getitem__) getitem;
#endif
		%newobject getitem;
		%exception getitem {
			if (arg2 < 0 || arg2 >= arg1->len) {
				char errorMsg[256];
				sprintf(errorMsg, "%d", arg2);
				SWIG_exception(SWIG_IndexError, errorMsg);
			}
			$action
		}
		LassoNode *getitem(int index) {
			LassoNode *item;

			item = g_ptr_array_index(self, index);
			if (item != NULL)
				g_object_ref(item);
			return item;
		}
		%exception getitem;

#if defined(SWIGPYTHON)
		%rename(__len__) length;
#endif
		int length() {
			return self->len;
		}

#if defined(SWIGPYTHON)
		%rename(__setitem__) setitem;
#endif
		%exception setitem {
			if (arg2 < 0 || arg2 >= arg1->len) {
				char errorMsg[256];
				sprintf(errorMsg, "%d", arg2);
				SWIG_exception(SWIG_IndexError, errorMsg);
			}
			$action
		}
		void setitem(int index, LassoNode *item) {
			LassoNode **itemPointer = (LassoNode **) &g_ptr_array_index(self, index);
			if (*itemPointer != NULL)
				/* Test added to help debugging. */
				if (LASSO_IS_NODE(*itemPointer))
					lasso_node_destroy(LASSO_NODE(*itemPointer));
				else
					g_object_unref(*itemPointer);
			if (item == NULL)
				*itemPointer = NULL;
			else
				*itemPointer = g_object_ref(item);
		}
		%exception setitem;
	}
} LassoNodeArray;

%{

/* Constructors, destructors & static methods implementations */

#define new_LassoNodeArray g_ptr_array_new

void delete_LassoNodeArray(GPtrArray *self) {
	g_ptr_array_foreach(self, (GFunc) free_node_array_item, NULL);
	g_ptr_array_free(self, false);
}

%}


/***********************************************************************
 * StringArray
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(StringArray) LassoStringArray;
#endif
%{
typedef GPtrArray LassoStringArray;
%}
typedef struct {
	%extend {
		/* Constructor, Destructor & Static Methods */

		LassoStringArray();

		~LassoStringArray();

		/* Methods */

		void append(char *item) {
			if (item != NULL)
				item = g_strdup(item);
			g_ptr_array_add(self, item);
		}

		GPtrArray *cast() {
			return self;
		}

		static LassoStringArray *frompointer(GPtrArray *stringArray) {
			return (LassoStringArray *) stringArray;
		}

#if defined(SWIGPYTHON)
		%rename(__getitem__) getitem;
#endif
		%exception getitem {
			if (arg2 < 0 || arg2 >= arg1->len) {
				char errorMsg[256];
				sprintf(errorMsg, "%d", arg2);
				SWIG_exception(SWIG_IndexError, errorMsg);
			}
			$action
		}
		char *getitem(int index) {
			return g_ptr_array_index(self, index);
		}
		%exception getitem;

#if defined(SWIGPYTHON)
		%rename(__len__) length;
#endif
		int length() {
			return self->len;
		}

#if defined(SWIGPYTHON)
		%rename(__setitem__) setitem;
#endif
		%exception setitem {
			if (arg2 < 0 || arg2 >= arg1->len) {
				char errorMsg[256];
				sprintf(errorMsg, "%d", arg2);
				SWIG_exception(SWIG_IndexError, errorMsg);
			}
			$action
		}
		void setitem(int index, char *item) {
			char **itemPointer = (char **) &g_ptr_array_index(self, index);
			if (*itemPointer != NULL)
				free(*itemPointer);
			if (item == NULL)
				*itemPointer = NULL;
			else
				*itemPointer = g_strdup(item);
		}
		%exception setitem;
	}
} LassoStringArray;

%{

/* Constructors, destructors & static methods implementations */

#define new_LassoStringArray g_ptr_array_new
#define delete_LassoStringArray(self) g_ptr_array_free(self, true)

%}


/***********************************************************************
 ***********************************************************************
 * XML Elements without namespace
 ***********************************************************************
 ***********************************************************************/


/***********************************************************************
 * Node
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(Node) LassoNode;
#endif
typedef struct {
} LassoNode;
%extend LassoNode {
	/* Constructor, Destructor & Static Methods */

	LassoNode();

	~LassoNode();

	/* Methods */

	%newobject dump;
	char *dump();
}

%{

/* Constructors, destructors & static methods implementations */

#define new_LassoNode lasso_node_new
#define delete_LassoNode lasso_node_destroy

/* Methods implementations */

#define LassoNode_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 ***********************************************************************
 * XML Elements in SAML Namespace
 ***********************************************************************
 ***********************************************************************/


/***********************************************************************
 * saml:Advice
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(SamlAdvice) LassoSamlAdvice;
#endif
typedef struct {
	/* Attributes */

	/* char *AssertionIDReference; FIXME: unbounded */
} LassoSamlAdvice;
%extend LassoSamlAdvice {
	/* Attributes */

	/* LassoSamlAssertion *Assertion; FIXME: unbounded */

	/* Constructor, Destructor & Static Methods */

	LassoSamlAdvice();

	~LassoSamlAdvice();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Constructors, destructors & static methods implementations */

#define new_LassoSamlAdvice lasso_saml_advice_new
#define delete_LassoSamlAdvice(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSamlAdvice_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * saml:Assertion
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(SamlAssertion) LassoSamlAssertion;
#endif
typedef struct {
	/* Attributes */

#ifndef SWIGPHP4
	%rename(assertionId) AssertionID;
#endif
	char *AssertionID;

#ifndef SWIGPHP4
	%rename(certificateFile) certificate_file;
#endif
	char *certificate_file;

#ifndef SWIGPHP4
	%rename(issueInstant) IssueInstant;
#endif
	char *IssueInstant;

#ifndef SWIGPHP4
	%rename(issuer) Issuer;
#endif
	char *Issuer;

#ifndef SWIGPHP4
	%rename(majorVersion) MajorVersion;
#endif
	int MajorVersion;

#ifndef SWIGPHP4
	%rename(minorVersion) MinorVersion;
#endif
	int MinorVersion;

#ifndef SWIGPHP4
	%rename(privateKeyFile) private_key_file;
#endif
	char *private_key_file;

#ifndef SWIGPHP4
	%rename(signMethod) sign_method;
#endif
	LassoSignatureMethod sign_method;

#ifndef SWIGPHP4
	%rename(signType) sign_type;
#endif
	LassoSignatureType sign_type;
} LassoSamlAssertion;
%extend LassoSamlAssertion {
	/* Attributes */

#ifndef SWIGPHP4
	%rename(advice) Advice;
#endif
	%newobject Advice_get;
	LassoSamlAdvice *Advice;

#ifndef SWIGPHP4
	%rename(attributeStatement) AttributeStatement;
#endif
	%newobject AttributeStatement_get;
	LassoSamlAttributeStatement *AttributeStatement;

#ifndef SWIGPHP4
	%rename(authenticationStatement) AuthenticationStatement;
#endif
	%newobject AuthenticationStatement_get;
	LassoSamlAuthenticationStatement *AuthenticationStatement;

	/* LassoSamlAuthorizationDecisionsStatement *AuthorizationDecisionStatement;
	   FIXME: missing from lasso */

#ifndef SWIGPHP4
	%rename(conditions) Conditions;
#endif
	%newobject Conditions_get;
	LassoSamlConditions *Conditions;

	/* LassoSamlStatement *Statement; FIXME: missing from lasso */

#ifndef SWIGPHP4
	%rename(subjectStatement) SubjectStatement;
#endif
	%newobject SubjectStatement_get;
	LassoSamlSubjectStatement *SubjectStatement;

	/* Constructor, Destructor & Static Methods */

	LassoSamlAssertion();

	~LassoSamlAssertion();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes Implementations */

/* Advice */
#define LassoSamlAssertion_get_Advice(self) get_node((self)->Advice)
#define LassoSamlAssertion_Advice_get(self) get_node((self)->Advice)
#define LassoSamlAssertion_set_Advice(self, value) set_node((gpointer *) &(self)->Advice, (value))
#define LassoSamlAssertion_Advice_set(self, value) set_node((gpointer *) &(self)->Advice, (value))

/* AttributeStatement */
#define LassoSamlAssertion_get_AttributeStatement(self) get_node((self)->AttributeStatement)
#define LassoSamlAssertion_AttributeStatement_get(self) get_node((self)->AttributeStatement)
#define LassoSamlAssertion_set_AttributeStatement(self, value) set_node((gpointer *) &(self)->AttributeStatement, (value))
#define LassoSamlAssertion_AttributeStatement_set(self, value) set_node((gpointer *) &(self)->AttributeStatement, (value))

/* AuthenticationStatement */
#define LassoSamlAssertion_get_AuthenticationStatement(self) get_node((self)->AuthenticationStatement)
#define LassoSamlAssertion_AuthenticationStatement_get(self) get_node((self)->AuthenticationStatement)
#define LassoSamlAssertion_set_AuthenticationStatement(self, value) set_node((gpointer *) &(self)->AuthenticationStatement, (value))
#define LassoSamlAssertion_AuthenticationStatement_set(self, value) set_node((gpointer *) &(self)->AuthenticationStatement, (value))

/* Conditions */
#define LassoSamlAssertion_get_Conditions(self) get_node((self)->Conditions)
#define LassoSamlAssertion_Conditions_get(self) get_node((self)->Conditions)
#define LassoSamlAssertion_set_Conditions(self, value) set_node((gpointer *) &(self)->Conditions, (value))
#define LassoSamlAssertion_Conditions_set(self, value) set_node((gpointer *) &(self)->Conditions, (value))

/* SubjectStatement */
#define LassoSamlAssertion_get_SubjectStatement(self) get_node((self)->SubjectStatement)
#define LassoSamlAssertion_SubjectStatement_get(self) get_node((self)->SubjectStatement)
#define LassoSamlAssertion_set_SubjectStatement(self, value) set_node((gpointer *) &(self)->SubjectStatement, (value))
#define LassoSamlAssertion_SubjectStatement_set(self, value) set_node((gpointer *) &(self)->SubjectStatement, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoSamlAssertion lasso_saml_assertion_new
#define delete_LassoSamlAssertion(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSamlAssertion_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * saml:Attribute
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(SamlAttribute) LassoSamlAttribute;
#endif
typedef struct {
} LassoSamlAttribute;
%extend LassoSamlAttribute {
	/* Attributes inherited from SamlAttributeDesignator */

#ifndef SWIGPHP4
	%rename(attributeName) AttributeName;
#endif
	char *AttributeName;

#ifndef SWIGPHP4
	%rename(attributeNamespace) AttributeNamespace;
#endif
	char *AttributeNamespace;

	/* Attributes */

#ifndef SWIGPHP4
	%rename(attributeValue) AttributeValue;
#endif
	%newobject AttributeValue_get;
	LassoNodeArray *AttributeValue;

	/* Constructor, Destructor & Static Methods */

	LassoSamlAttribute();

	~LassoSamlAttribute();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Implementations of attributes inherited from SamlAttributeDesignator */

/* AttributeName */
#define LassoSamlAttribute_get_AttributeName(self) LASSO_SAML_ATTRIBUTE_DESIGNATOR(self)->AttributeName
#define LassoSamlAttribute_AttributeName_get(self) LASSO_SAML_ATTRIBUTE_DESIGNATOR(self)->AttributeName
#define LassoSamlAttribute_set_AttributeName(self, value) set_string(&LASSO_SAML_ATTRIBUTE_DESIGNATOR(self)->AttributeName, (value))
#define LassoSamlAttribute_AttributeName_set(self, value) set_string(&LASSO_SAML_ATTRIBUTE_DESIGNATOR(self)->AttributeName, (value))

/* AttributeNamespace */
#define LassoSamlAttribute_get_AttributeNamespace(self) LASSO_SAML_ATTRIBUTE_DESIGNATOR(self)->AttributeNamespace
#define LassoSamlAttribute_AttributeNamespace_get(self) LASSO_SAML_ATTRIBUTE_DESIGNATOR(self)->AttributeNamespace
#define LassoSamlAttribute_set_AttributeNamespace(self, value) set_string(&LASSO_SAML_ATTRIBUTE_DESIGNATOR(self)->AttributeNamespace, (value))
#define LassoSamlAttribute_AttributeNamespace_set(self, value) set_string(&LASSO_SAML_ATTRIBUTE_DESIGNATOR(self)->AttributeNamespace, (value))

/* Attributes implementations */

/* AttributeValue */
#define LassoSamlAttribute_get_AttributeValue(self) get_node_list((self)->AttributeValue)
#define LassoSamlAttribute_AttributeValue_get(self) get_node_list((self)->AttributeValue)
#define LassoSamlAttribute_set_AttributeValue(self, value) set_node_list(&(self)->AttributeValue, (value))
#define LassoSamlAttribute_AttributeValue_set(self, value) set_node_list(&(self)->AttributeValue, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoSamlAttribute lasso_saml_attribute_new
#define delete_LassoSamlAttribute(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSamlAttribute_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * saml:AttributeStatement
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(SamlAttributeStatement) LassoSamlAttributeStatement;
#endif
typedef struct {
} LassoSamlAttributeStatement;
%extend LassoSamlAttributeStatement {
	/* Attributes inherited from SamlSubjectStatementAbstract */

	/* GList *Attribute; FIXME: TODO */

#ifndef SWIGPHP4
	%rename(subject) Subject;
#endif
	%newobject Subject_get;
	LassoSamlSubject *Subject;

	/* LassoSamlAssertion *Assertion; FIXME: unbounded */

	/* Constructor, Destructor & Static Methods */

	LassoSamlAttributeStatement();

	~LassoSamlAttributeStatement();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Implementations of attributes inherited from SamlSubjectStatementAbstract */

/* Subject */
#define LassoSamlAttributeStatement_get_Subject(self) get_node(LASSO_SAML_SUBJECT_STATEMENT_ABSTRACT(self)->Subject)
#define LassoSamlAttributeStatement_Subject_get(self) get_node(LASSO_SAML_SUBJECT_STATEMENT_ABSTRACT(self)->Subject)
#define LassoSamlAttributeStatement_set_Subject(self, value) set_node((gpointer *) &LASSO_SAML_SUBJECT_STATEMENT_ABSTRACT(self)->Subject, (value))
#define LassoSamlAttributeStatement_Subject_set(self, value) set_node((gpointer *) &LASSO_SAML_SUBJECT_STATEMENT_ABSTRACT(self)->Subject, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoSamlAttributeStatement lasso_saml_attribute_statement_new
#define delete_LassoSamlAttributeStatement(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSamlAttributeStatement_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * saml:AuthenticationStatement
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(SamlAuthenticationStatement) LassoSamlAuthenticationStatement;
#endif
typedef struct {
	/* Attributes */

#ifndef SWIGPHP4
	%rename(authenticationInstant) AuthenticationInstant;
#endif
	char *AuthenticationInstant;

#ifndef SWIGPHP4
	%rename(authenticationMethod) AuthenticationMethod;
#endif
	char *AuthenticationMethod;
} LassoSamlAuthenticationStatement;
%extend LassoSamlAuthenticationStatement {
	/* Attributes */

	/* LassoSamlAuthorityBinding *AuthorityBinding; FIXME: unbounded */

#ifndef SWIGPHP4
	%rename(subjectLocality) SubjectLocality;
#endif
	%newobject SubjectLocality_get;
	LassoSamlSubjectLocality *SubjectLocality;

	/* Constructor, Destructor & Static Methods */

	LassoSamlAuthenticationStatement();

	~LassoSamlAuthenticationStatement();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes implementations */

/* SubjectLocality */
#define LassoSamlAuthenticationStatement_get_SubjectLocality(self) get_node((self)->SubjectLocality)
#define LassoSamlAuthenticationStatement_SubjectLocality_get(self) get_node((self)->SubjectLocality)
#define LassoSamlAuthenticationStatement_set_SubjectLocality(self, value) set_node((gpointer *) &(self)->SubjectLocality, (value))
#define LassoSamlAuthenticationStatement_SubjectLocality_set(self, value) set_node((gpointer *) &(self)->SubjectLocality, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoSamlAuthenticationStatement lasso_saml_authentication_statement_new
#define delete_LassoSamlAuthenticationStatement(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSamlAuthenticationStatement_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * saml:Conditions
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(SamlConditions) LassoSamlConditions;
#endif
typedef struct {
	/* Attributes */

#ifndef SWIGPHP4
	%rename(notBefore) NotBefore;
#endif
	char *NotBefore;

#ifndef SWIGPHP4
	%rename(notOnOrAfter) NotOnOrAfter;
#endif
	char *NotOnOrAfter;
} LassoSamlConditions;
%extend LassoSamlConditions {
	/* Attributes */

	/* LassoSamlCondition *Condition;  FIXME: missing from lasso, unbounded */
	/* LassoSamlAudienceRestrictionCondition *AudienceRestrictionCondition; FIXME: unbounded */

	/* Constructor, Destructor & Static Methods */

	LassoSamlConditions();

	~LassoSamlConditions();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Constructors, destructors & static methods implementations */

#define new_LassoSamlConditions lasso_saml_conditions_new
#define delete_LassoSamlConditions(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSamlConditions_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * saml:NameIdentifier
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(SamlNameIdentifier) LassoSamlNameIdentifier;
#endif
typedef struct {
	/* Attributes */

	char *content;

#ifndef SWIGPHP4
	%rename(format) Format;
#endif
	char *Format;

#ifndef SWIGPHP4
	%rename(nameQualifier) NameQualifier;
#endif
	char *NameQualifier;
} LassoSamlNameIdentifier;
%extend LassoSamlNameIdentifier {
	/* Constructor, Destructor & Static Methods */

	LassoSamlNameIdentifier();

	~LassoSamlNameIdentifier();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Constructors, destructors & static methods implementations */

#define new_LassoSamlNameIdentifier lasso_saml_name_identifier_new
#define delete_LassoSamlNameIdentifier(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSamlNameIdentifier_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * saml:Subject
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(SamlSubject) LassoSamlSubject;
#endif
typedef struct {
} LassoSamlSubject;
%extend LassoSamlSubject {
	/* Attributes */

#ifndef SWIGPHP4
	%rename(nameIdentifier) NameIdentifier;
#endif
	%newobject NameIdentifier_get;
	LassoSamlNameIdentifier *NameIdentifier;

#ifndef SWIGPHP4
	%rename(subjectConfirmation) SubjectConfirmation;
#endif
	%newobject SubjectConfirmation_get;
	LassoSamlSubjectConfirmation *SubjectConfirmation;

	/* Constructor, Destructor & Static Methods */

	LassoSamlSubject();

	~LassoSamlSubject();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes implementations */

/* NameIdentifier */
#define LassoSamlSubject_get_NameIdentifier(self) get_node((self)->NameIdentifier)
#define LassoSamlSubject_NameIdentifier_get(self) get_node((self)->NameIdentifier)
#define LassoSamlSubject_set_NameIdentifier(self, value) set_node((gpointer *) &(self)->NameIdentifier, (value))
#define LassoSamlSubject_NameIdentifier_set(self, value) set_node((gpointer *) &(self)->NameIdentifier, (value))

/* SubjectConfirmation */
#define LassoSamlSubject_get_SubjectConfirmation(self) get_node((self)->SubjectConfirmation)
#define LassoSamlSubject_SubjectConfirmation_get(self) get_node((self)->SubjectConfirmation)
#define LassoSamlSubject_set_SubjectConfirmation(self, value) set_node((gpointer *) &(self)->SubjectConfirmation, (value))
#define LassoSamlSubject_SubjectConfirmation_set(self, value) set_node((gpointer *) &(self)->SubjectConfirmation, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoSamlSubject lasso_saml_subject_new
#define delete_LassoSamlSubject(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSamlSubject_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * saml:SubjectConfirmation
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(SamlSubjectConfirmation) LassoSamlSubjectConfirmation;
#endif
typedef struct {
	/* Attributes */

	/* char *ConfirmationMethod; FIXME: unbounded */

#ifndef SWIGPHP4
	%rename(subjectConfirmationData) SubjectConfirmationData;
#endif
	char *SubjectConfirmationData;
} LassoSamlSubjectConfirmation;
%extend LassoSamlSubjectConfirmation {
	/* Constructor, Destructor & Static Methods */

	LassoSamlSubjectConfirmation();

	~LassoSamlSubjectConfirmation();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Constructors, destructors & static methods implementations */

#define new_LassoSamlSubjectConfirmation lasso_saml_subject_confirmation_new
#define delete_LassoSamlSubjectConfirmation(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSamlSubjectConfirmation_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * saml:SubjectLocality
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(SamlSubjectLocality) LassoSamlSubjectLocality;
#endif
typedef struct {
	/* Attributes */

#ifndef SWIGPHP4
	%rename(dnsAddress) DNSAddress;
#endif
	char *DNSAddress;

#ifndef SWIGPHP4
	%rename(ipAddress) IPAddress;
#endif
	char *IPAddress;
} LassoSamlSubjectLocality;
%extend LassoSamlSubjectLocality {
	/* Constructor, Destructor & Static Methods */

	LassoSamlSubjectLocality();

	~LassoSamlSubjectLocality();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Constructors, destructors & static methods implementations */

#define new_LassoSamlSubjectLocality lasso_saml_subject_locality_new
#define delete_LassoSamlSubjectLocality(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSamlSubjectLocality_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * saml:SubjectStatement
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(SamlSubjectStatement) LassoSamlSubjectStatement;
#endif
typedef struct {
} LassoSamlSubjectStatement;
%extend LassoSamlSubjectStatement {
	/* Attributes inherited from SamlSubjectStatementAbstract */

#ifndef SWIGPHP4
	%rename(subject) Subject;
#endif
	%newobject Subject_get;
	LassoSamlSubject *Subject;

	/* LassoSamlAssertion *Assertion; FIXME: unbounded */

	/* Constructor, Destructor & Static Methods */

	LassoSamlSubjectStatement();

	~LassoSamlSubjectStatement();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Implementations of attributes inherited from SamlSubjectStatementAbstract */

/* Subject */
#define LassoSamlSubjectStatement_get_Subject(self) get_node(LASSO_SAML_SUBJECT_STATEMENT_ABSTRACT(self)->Subject)
#define LassoSamlSubjectStatement_Subject_get(self) get_node(LASSO_SAML_SUBJECT_STATEMENT_ABSTRACT(self)->Subject)
#define LassoSamlSubjectStatement_set_Subject(self, value) set_node((gpointer *) &LASSO_SAML_SUBJECT_STATEMENT_ABSTRACT(self)->Subject, (value))
#define LassoSamlSubjectStatement_Subject_set(self, value) set_node((gpointer *) &LASSO_SAML_SUBJECT_STATEMENT_ABSTRACT(self)->Subject, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoSamlSubjectStatement lasso_saml_subject_statement_new
#define delete_LassoSamlSubjectStatement(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSamlSubjectStatement_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 ***********************************************************************
 * XML Elements in SAMLP Namespace
 ***********************************************************************
 ***********************************************************************/


/***********************************************************************
 * samlp:Request
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(SamlpRequest) LassoSamlpRequest;
#endif
typedef struct {
	/* Attributes */

#ifndef SWIGPHP4
	%rename(assertionArtifact) AssertionArtifact;
#endif
	char *AssertionArtifact;
} LassoSamlpRequest;
%extend LassoSamlpRequest {
	/* Constructor, Destructor & Static Methods */

	LassoSamlpRequest();

	~LassoSamlpRequest();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Constructors, destructors & static methods implementations */

#define new_LassoSamlpRequest lasso_samlp_request_new
#define delete_LassoSamlpRequest(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSamlpRequest_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * samlp:Response
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(SamlpResponse) LassoSamlpResponse;
#endif
typedef struct {
} LassoSamlpResponse;
%extend LassoSamlpResponse {
	/* Attributes */

	/* LassoSamlAssertion *Assertion; FIXME: unbounded */

#ifndef SWIGPHP4
	%rename(status) Status;
#endif
	%newobject Status_get;
	LassoSamlpStatus *Status;

	/* Constructor, Destructor & Static Methods */

	LassoSamlpResponse();

	~LassoSamlpResponse();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes Implementations */

/* Status */
#define LassoSamlpResponse_get_Status(self) get_node((self)->Status)
#define LassoSamlpResponse_Status_get(self) get_node((self)->Status)
#define LassoSamlpResponse_set_Status(self, value) set_node((gpointer *) &(self)->Status, (value))
#define LassoSamlpResponse_Status_set(self, value) set_node((gpointer *) &(self)->Status, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoSamlpResponse lasso_samlp_response_new
#define delete_LassoSamlpResponse(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSamlpResponse_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * samlp:Status
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(SamlpStatus) LassoSamlpStatus;
#endif
typedef struct {
	/* Attributes */

#ifndef SWIGPHP4
	%rename(statusMessage) StatusMessage;
#endif
	char *StatusMessage;
} LassoSamlpStatus;
%extend LassoSamlpStatus {
	/* Attributes */

#ifndef SWIGPHP4
	%rename(statusCode) StatusCode;
#endif
	%newobject StatusCode_get;
	LassoSamlpStatusCode *StatusCode;

	/* Constructor, Destructor & Static Methods */

	LassoSamlpStatus();

	~LassoSamlpStatus();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes Implementations */

/* StatusCode */
#define LassoSamlpStatus_get_StatusCode(self) get_node((self)->StatusCode)
#define LassoSamlpStatus_StatusCode_get(self) get_node((self)->StatusCode)
#define LassoSamlpStatus_set_StatusCode(self, value) set_node((gpointer *) &(self)->StatusCode, (value))
#define LassoSamlpStatus_StatusCode_set(self, value) set_node((gpointer *) &(self)->StatusCode, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoSamlpStatus lasso_samlp_status_new
#define delete_LassoSamlpStatus(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSamlpStatus_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * samlp:StatusCode
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(SamlpStatusCode) LassoSamlpStatusCode;
#endif
typedef struct {
	/* Attributes */

#ifndef SWIGPHP4
	%rename(value) Value;
#endif
	char *Value;
} LassoSamlpStatusCode;
%extend LassoSamlpStatusCode {
	/* Attributes */

#ifndef SWIGPHP4
	%rename(statusCode) StatusCode;
#endif
	%newobject StatusCode_get;
	LassoSamlpStatusCode *StatusCode;

	/* Constructor, Destructor & Static Methods */

	LassoSamlpStatusCode();

	~LassoSamlpStatusCode();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes Implementations */

/* StatusCode */
#define LassoSamlpStatusCode_get_StatusCode(self) get_node((self)->StatusCode)
#define LassoSamlpStatusCode_StatusCode_get(self) get_node((self)->StatusCode)
#define LassoSamlpStatusCode_set_StatusCode(self, value) set_node((gpointer *) &(self)->StatusCode, (value))
#define LassoSamlpStatusCode_StatusCode_set(self, value) set_node((gpointer *) &(self)->StatusCode, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoSamlpStatusCode lasso_samlp_status_code_new
#define delete_LassoSamlpStatusCode(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSamlpStatusCode_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 ***********************************************************************
 * XML Elements in Liberty Namespace
 ***********************************************************************
 ***********************************************************************/


/***********************************************************************
 * lib:Assertion
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(LibAssertion) LassoLibAssertion;
#endif
typedef struct {
} LassoLibAssertion;
%extend LassoLibAssertion {
	/* Attributes inherited from SamlAssertion */

#ifndef SWIGPHP4
	%rename(advice) Advice;
#endif
	%newobject Advice_get;
	LassoSamlAdvice *Advice;

#ifndef SWIGPHP4
	%rename(assertionId) AssertionID;
#endif
	char *AssertionID;

#ifndef SWIGPHP4
	%rename(attributeStatement) AttributeStatement;
#endif
	%newobject AttributeStatement_get;
	LassoSamlAttributeStatement *AttributeStatement;

#ifndef SWIGPHP4
	%rename(authenticationStatement) AuthenticationStatement;
#endif
	%newobject AuthenticationStatement_get;
	LassoSamlAuthenticationStatement *AuthenticationStatement;

	/* LassoSamlAuthorizationDecisionsStatement *AuthorizationDecisionStatement;
	   FIXME: missing from lasso */

#ifndef SWIGPHP4
	%rename(certificateFile) certificate_file;
#endif
	char *certificate_file;

#ifndef SWIGPHP4
	%rename(conditions) Conditions;
#endif
	%newobject Conditions_get;
	LassoSamlConditions *Conditions;

#ifndef SWIGPHP4
	%rename(issueInstant) IssueInstant;
#endif
	char *IssueInstant;

#ifndef SWIGPHP4
	%rename(issuer) Issuer;
#endif
	char *Issuer;

#ifndef SWIGPHP4
	%rename(majorVersion) MajorVersion;
#endif
	int MajorVersion;

#ifndef SWIGPHP4
	%rename(minorVersion) MinorVersion;
#endif
	int MinorVersion;

#ifndef SWIGPHP4
	%rename(privateKeyFile) private_key_file;
#endif
	char *private_key_file;

#ifndef SWIGPHP4
	%rename(signMethod) sign_method;
#endif
	LassoSignatureMethod sign_method;

#ifndef SWIGPHP4
	%rename(signType) sign_type;
#endif
	LassoSignatureType sign_type;

	/* LassoSamlStatement *Statement; FIXME: missing from lasso */

#ifndef SWIGPHP4
	%rename(subjectStatement) SubjectStatement;
#endif
	%newobject SubjectStatement_get;
	LassoSamlSubjectStatement *SubjectStatement;

	/* Constructor, Destructor & Static Methods */

	LassoLibAssertion(char *issuer, char *requestId, char *audience,
			  char *notBefore, char *notOnOrAfter);

	~LassoLibAssertion();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Implementations of attributes inherited from SamlAssertion */

/* Advice */
#define LassoLibAssertion_get_Advice(self) get_node(LASSO_SAML_ASSERTION(self)->Advice)
#define LassoLibAssertion_Advice_get(self) get_node(LASSO_SAML_ASSERTION(self)->Advice)
#define LassoLibAssertion_set_Advice(self, value) set_node((gpointer *) &LASSO_SAML_ASSERTION(self)->Advice, (value))
#define LassoLibAssertion_Advice_set(self, value) set_node((gpointer *) &LASSO_SAML_ASSERTION(self)->Advice, (value))

/* AssertionID */
#define LassoLibAssertion_get_AssertionID(self) LASSO_SAML_ASSERTION(self)->AssertionID
#define LassoLibAssertion_AssertionID_get(self) LASSO_SAML_ASSERTION(self)->AssertionID
#define LassoLibAssertion_set_AssertionID(self, value) set_string(&LASSO_SAML_ASSERTION(self)->AssertionID, (value))
#define LassoLibAssertion_AssertionID_set(self, value) set_string(&LASSO_SAML_ASSERTION(self)->AssertionID, (value))

/* AttributeStatement */
#define LassoLibAssertion_get_AttributeStatement(self) get_node(LASSO_SAML_ASSERTION(self)->AttributeStatement)
#define LassoLibAssertion_AttributeStatement_get(self) get_node(LASSO_SAML_ASSERTION(self)->AttributeStatement)
#define LassoLibAssertion_set_AttributeStatement(self, value) set_node((gpointer *) &LASSO_SAML_ASSERTION(self)->AttributeStatement, (value))
#define LassoLibAssertion_AttributeStatement_set(self, value) set_node((gpointer *) &LASSO_SAML_ASSERTION(self)->AttributeStatement, (value))

/* AuthenticationStatement */
#define LassoLibAssertion_get_AuthenticationStatement(self) get_node(LASSO_SAML_ASSERTION(self)->AuthenticationStatement)
#define LassoLibAssertion_AuthenticationStatement_get(self) get_node(LASSO_SAML_ASSERTION(self)->AuthenticationStatement)
#define LassoLibAssertion_set_AuthenticationStatement(self, value) set_node((gpointer *) &LASSO_SAML_ASSERTION(self)->AuthenticationStatement, (value))
#define LassoLibAssertion_AuthenticationStatement_set(self, value) set_node((gpointer *) &LASSO_SAML_ASSERTION(self)->AuthenticationStatement, (value))

/* certificate_file */
#define LassoLibAssertion_get_certificate_file(self) LASSO_SAML_ASSERTION(self)->certificate_file
#define LassoLibAssertion_certificate_file_get(self) LASSO_SAML_ASSERTION(self)->certificate_file
#define LassoLibAssertion_set_certificate_file(self, value) set_string(&LASSO_SAML_ASSERTION(self)->certificate_file, (value))
#define LassoLibAssertion_certificate_file_set(self, value) set_string(&LASSO_SAML_ASSERTION(self)->certificate_file, (value))

/* Conditions */
#define LassoLibAssertion_get_Conditions(self) get_node(LASSO_SAML_ASSERTION(self)->Conditions)
#define LassoLibAssertion_Conditions_get(self) get_node(LASSO_SAML_ASSERTION(self)->Conditions)
#define LassoLibAssertion_set_Conditions(self, value) set_node((gpointer *) &LASSO_SAML_ASSERTION(self)->Conditions, (value))
#define LassoLibAssertion_Conditions_set(self, value) set_node((gpointer *) &LASSO_SAML_ASSERTION(self)->Conditions, (value))

/* IssueInstant */
#define LassoLibAssertion_get_IssueInstant(self) LASSO_SAML_ASSERTION(self)->IssueInstant
#define LassoLibAssertion_IssueInstant_get(self) LASSO_SAML_ASSERTION(self)->IssueInstant
#define LassoLibAssertion_set_IssueInstant(self, value) set_string(&LASSO_SAML_ASSERTION(self)->IssueInstant, (value))
#define LassoLibAssertion_IssueInstant_set(self, value) set_string(&LASSO_SAML_ASSERTION(self)->IssueInstant, (value))

/* Issuer */
#define LassoLibAssertion_get_Issuer(self) LASSO_SAML_ASSERTION(self)->Issuer
#define LassoLibAssertion_Issuer_get(self) LASSO_SAML_ASSERTION(self)->Issuer
#define LassoLibAssertion_set_Issuer(self, value) set_string(&LASSO_SAML_ASSERTION(self)->Issuer, (value))
#define LassoLibAssertion_Issuer_set(self, value) set_string(&LASSO_SAML_ASSERTION(self)->Issuer, (value))

/* MajorVersion */
#define LassoLibAssertion_get_MajorVersion(self) LASSO_SAML_ASSERTION(self)->MajorVersion
#define LassoLibAssertion_MajorVersion_get(self) LASSO_SAML_ASSERTION(self)->MajorVersion
#define LassoLibAssertion_set_MajorVersion(self, value) LASSO_SAML_ASSERTION(self)->MajorVersion = (value)
#define LassoLibAssertion_MajorVersion_set(self, value) LASSO_SAML_ASSERTION(self)->MajorVersion = (value)

/* MinorVersion */
#define LassoLibAssertion_get_MinorVersion(self) LASSO_SAML_ASSERTION(self)->MinorVersion
#define LassoLibAssertion_MinorVersion_get(self) LASSO_SAML_ASSERTION(self)->MinorVersion
#define LassoLibAssertion_set_MinorVersion(self, value) LASSO_SAML_ASSERTION(self)->MinorVersion = (value)
#define LassoLibAssertion_MinorVersion_set(self, value) LASSO_SAML_ASSERTION(self)->MinorVersion = (value)

/* private_key_file */
#define LassoLibAssertion_get_private_key_file(self) LASSO_SAML_ASSERTION(self)->private_key_file
#define LassoLibAssertion_private_key_file_get(self) LASSO_SAML_ASSERTION(self)->private_key_file
#define LassoLibAssertion_set_private_key_file(self, value) set_string(&LASSO_SAML_ASSERTION(self)->private_key_file, (value))
#define LassoLibAssertion_private_key_file_set(self, value) set_string(&LASSO_SAML_ASSERTION(self)->private_key_file, (value))

/* sign_method */
#define LassoLibAssertion_get_sign_method(self) LASSO_SAML_ASSERTION(self)->sign_method
#define LassoLibAssertion_sign_method_get(self) LASSO_SAML_ASSERTION(self)->sign_method
#define LassoLibAssertion_set_sign_method(self, value) LASSO_SAML_ASSERTION(self)->sign_method = (value)
#define LassoLibAssertion_sign_method_set(self, value) LASSO_SAML_ASSERTION(self)->sign_method = (value)

/* sign_type */
#define LassoLibAssertion_get_sign_type(self) LASSO_SAML_ASSERTION(self)->sign_type
#define LassoLibAssertion_sign_type_get(self) LASSO_SAML_ASSERTION(self)->sign_type
#define LassoLibAssertion_set_sign_type(self, value) LASSO_SAML_ASSERTION(self)->sign_type = (value)
#define LassoLibAssertion_sign_type_set(self, value) LASSO_SAML_ASSERTION(self)->sign_type = (value)

/* SubjectStatement */
#define LassoLibAssertion_get_SubjectStatement(self) get_node(LASSO_SAML_ASSERTION(self)->SubjectStatement)
#define LassoLibAssertion_SubjectStatement_get(self) get_node(LASSO_SAML_ASSERTION(self)->SubjectStatement)
#define LassoLibAssertion_set_SubjectStatement(self, value) set_node((gpointer *) &LASSO_SAML_ASSERTION(self)->SubjectStatement, (value))
#define LassoLibAssertion_SubjectStatement_set(self, value) set_node((gpointer *) &LASSO_SAML_ASSERTION(self)->SubjectStatement, (value))

/* Implementations of methods inherited from SamlAssertion */

/* Constructors, destructors & static methods implementations */

#define new_LassoLibAssertion lasso_lib_assertion_new_full
#define delete_LassoLibAssertion(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoLibAssertion_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * lib:AuthnRequest
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(LibAuthnRequest) LassoLibAuthnRequest;
#endif
typedef struct {
	/* Attributes */

#ifndef SWIGPHP4
	%rename(affiliationId) AffiliationID;
#endif
	char *AffiliationID;

#ifndef SWIGPHP4
	%rename(assertionConsumerServiceId) AssertionConsumerServiceID;
#endif
	char *AssertionConsumerServiceID;

	char *consent;

#ifndef SWIGPHP4
	%rename(forceAuthn) ForceAuthn;
#endif
	gboolean ForceAuthn;

#ifndef SWIGPHP4
	%rename(isPassive) IsPassive;
#endif
	gboolean IsPassive;

#ifndef SWIGPHP4
	%rename(nameIdPolicy) NameIDPolicy;
#endif
	char *NameIDPolicy;

#ifndef SWIGPHP4
	%rename(protocolProfile) ProtocolProfile;
#endif
	char *ProtocolProfile;	

#ifndef SWIGPHP4
	%rename(providerId) ProviderID;
#endif
	char *ProviderID;

#ifndef SWIGPHP4
	%rename(relayState) RelayState;
#endif
	char *RelayState;

} LassoLibAuthnRequest;
%extend LassoLibAuthnRequest {
	/* Attributes */

	%newobject extension_get;
	LassoStringArray *extension;

	// FIXME: LassoLibRequestAuthnContext *RequestAuthnContext;
	// FIXME: LassoLibScoping *Scoping;

	/* Constructor, Destructor & Static Methods */

	LassoLibAuthnRequest();

	~LassoLibAuthnRequest();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes Implementations */

/* extension */
#define LassoLibAuthnRequest_get_extension(self) get_xml_list((self)->Extension)
#define LassoLibAuthnRequest_extension_get(self) get_xml_list((self)->Extension)
#define LassoLibAuthnRequest_set_extension(self, value) set_xml_list(&(self)->Extension, (value))
#define LassoLibAuthnRequest_extension_set(self, value) set_xml_list(&(self)->Extension, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoLibAuthnRequest lasso_lib_authn_request_new
#define delete_LassoLibAuthnRequest(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoLibAuthnRequest_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * lib:AuthnResponse
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(LibAuthnResponse) LassoLibAuthnResponse;
#endif
typedef struct {
	/* Attributes */

	char *consent;

#ifndef SWIGPHP4
	%rename(providerId) ProviderID;
#endif
	char *ProviderID;

#ifndef SWIGPHP4
	%rename(relayState) RelayState;
#endif
	char *RelayState;
} LassoLibAuthnResponse;
%extend LassoLibAuthnResponse {
	/* Attributes inherited from SamlpResponse */

	/* LassoSamlAssertion *Assertion; FIXME: unbounded */

	%newobject extension_get;
	LassoStringArray *extension;

#ifndef SWIGPHP4
	%rename(status) Status;
#endif
	%newobject Status_get;
	LassoSamlpStatus *Status;

	/* Constructor, Destructor & Static Methods */

	LassoLibAuthnResponse(char *providerID, LassoLibAuthnRequest *request);

	~LassoLibAuthnResponse();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes inherited from SamlpResponse implementations */

/* extension */
#define LassoLibAuthnResponse_get_extension(self) get_xml_list((self)->Extension)
#define LassoLibAuthnResponse_extension_get(self) get_xml_list((self)->Extension)
#define LassoLibAuthnResponse_set_extension(self, value) set_xml_list(&(self)->Extension, (value))
#define LassoLibAuthnResponse_extension_set(self, value) set_xml_list(&(self)->Extension, (value))

/* Status */
#define LassoLibAuthnResponse_get_Status(self) get_node(LASSO_SAMLP_RESPONSE(self)->Status)
#define LassoLibAuthnResponse_Status_get(self) get_node(LASSO_SAMLP_RESPONSE(self)->Status)
#define LassoLibAuthnResponse_set_Status(self, value) set_node((gpointer *) &LASSO_SAMLP_RESPONSE(self)->Status, (value))
#define LassoLibAuthnResponse_Status_set(self, value) set_node((gpointer *) &LASSO_SAMLP_RESPONSE(self)->Status, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoLibAuthnResponse lasso_lib_authn_response_new
#define delete_LassoLibAuthnResponse(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoLibAuthnResponse_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * lib:FederationTerminationNotification
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(LibFederationTerminationNotification) LassoLibFederationTerminationNotification;
#endif
typedef struct {
	/* Attributes */

	char *consent;

#ifndef SWIGPHP4
	%rename(providerId) ProviderID;
#endif
	char *ProviderID;

#ifndef SWIGPHP4
	%rename(relayState) RelayState;
#endif
	char *RelayState;	/* not in schema but allowed in redirects */
} LassoLibFederationTerminationNotification;
%extend LassoLibFederationTerminationNotification {
	/* Attributes */

	%newobject extension_get;
	LassoStringArray *extension;

#ifndef SWIGPHP4
	%rename(nameIdentifier) NameIdentifier;
#endif
	%newobject NameIdentifier_get;
	LassoSamlNameIdentifier *NameIdentifier;

	/* Constructor, Destructor & Static Methods */

	LassoLibFederationTerminationNotification(
			char *providerID, LassoSamlNameIdentifier *nameIdentifier,
			LassoSignatureType sign_type, LassoSignatureMethod sign_method);

	~LassoLibFederationTerminationNotification();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes implementations */

/* extension */
#define LassoLibFederationTerminationNotification_get_extension(self) get_xml_list((self)->Extension)
#define LassoLibFederationTerminationNotification_extension_get(self) get_xml_list((self)->Extension)
#define LassoLibFederationTerminationNotification_set_extension(self, value) set_xml_list(&(self)->Extension, (value))
#define LassoLibFederationTerminationNotification_extension_set(self, value) set_xml_list(&(self)->Extension, (value))

/* NameIdentifier */
#define LassoLibFederationTerminationNotification_get_NameIdentifier(self) get_node((self)->NameIdentifier)
#define LassoLibFederationTerminationNotification_NameIdentifier_get(self) get_node((self)->NameIdentifier)
#define LassoLibFederationTerminationNotification_set_NameIdentifier(self, value) set_node((gpointer *) &(self)->NameIdentifier, (value))
#define LassoLibFederationTerminationNotification_NameIdentifier_set(self, value) set_node((gpointer *) &(self)->NameIdentifier, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoLibFederationTerminationNotification lasso_lib_federation_termination_notification_new_full
#define delete_LassoLibFederationTerminationNotification(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoLibFederationTerminationNotification_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * lib:LogoutRequest
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(LibLogoutRequest) LassoLibLogoutRequest;
#endif
typedef struct {
	/* Attributes */

	char *consent;

#ifndef SWIGPHP4
	%rename(notOnOrAfter) NotOnOrAfter;
#endif
	char *NotOnOrAfter;

#ifndef SWIGPHP4
	%rename(providerId) ProviderID;
#endif
	char *ProviderID;

#ifndef SWIGPHP4
	%rename(relayState) RelayState;
#endif
	char *RelayState;

#ifndef SWIGPHP4
	%rename(sessionIndex) SessionIndex;
#endif
	char *SessionIndex;
} LassoLibLogoutRequest;
%extend LassoLibLogoutRequest {
	/* Attributes */

	%newobject extension_get;
	LassoStringArray *extension;

#ifndef SWIGPHP4
	%rename(nameIdentifier) NameIdentifier;
#endif
	%newobject NameIdentifier_get;
	LassoSamlNameIdentifier *NameIdentifier;

	/* Constructor, Destructor & Static Methods */

	LassoLibLogoutRequest(
			char *providerID, LassoSamlNameIdentifier *nameIdentifier,
			LassoSignatureType sign_type, LassoSignatureMethod sign_method);

	~LassoLibLogoutRequest();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes implementations */

/* extension */
#define LassoLibLogoutRequest_get_extension(self) get_xml_list((self)->Extension)
#define LassoLibLogoutRequest_extension_get(self) get_xml_list((self)->Extension)
#define LassoLibLogoutRequest_set_extension(self, value) set_xml_list(&(self)->Extension, (value))
#define LassoLibLogoutRequest_extension_set(self, value) set_xml_list(&(self)->Extension, (value))

/* nameIdentifier */
#define LassoLibLogoutRequest_get_NameIdentifier(self) get_node((self)->NameIdentifier)
#define LassoLibLogoutRequest_NameIdentifier_get(self) get_node((self)->NameIdentifier)
#define LassoLibLogoutRequest_set_NameIdentifier(self, value) set_node((gpointer *) &(self)->NameIdentifier, (value))
#define LassoLibLogoutRequest_NameIdentifier_set(self, value) set_node((gpointer *) &(self)->NameIdentifier, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoLibLogoutRequest lasso_lib_logout_request_new_full
#define delete_LassoLibLogoutRequest(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoLibLogoutRequest_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * lib:LogoutResponse
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(LibLogoutResponse) LassoLibLogoutResponse;
#endif
typedef struct {
} LassoLibLogoutResponse;
%extend LassoLibLogoutResponse {
	/* Attributes inherited from LibStatusResponse */

	%newobject extension_get;
	LassoStringArray *extension;

#ifndef SWIGPHP4
	%rename(providerId) ProviderID;
#endif
	char *ProviderID;

#ifndef SWIGPHP4
	%rename(relayState) RelayState;
#endif
	char *RelayState;

#ifndef SWIGPHP4
	%rename(status) Status;
#endif
	%newobject Status_get;
	LassoSamlpStatus *Status;

	/* Constructor, Destructor & Static Methods */

	LassoLibLogoutResponse(
			char *providerID, const char *statusCodeValue,
			LassoLibLogoutRequest *request,
			LassoSignatureType sign_type, LassoSignatureMethod sign_method);

	~LassoLibLogoutResponse();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Implementations of attributes inherited from LibStatusResponse */

/* extension */
#define LassoLibLogoutResponse_get_extension(self) get_xml_list(LASSO_LIB_STATUS_RESPONSE(self)->Extension)
#define LassoLibLogoutResponse_extension_get(self) get_xml_list(LASSO_LIB_STATUS_RESPONSE(self)->Extension)
#define LassoLibLogoutResponse_set_extension(self, value) set_xml_list(&LASSO_LIB_STATUS_RESPONSE(self)->Extension, (value))
#define LassoLibLogoutResponse_extension_set(self, value) set_xml_list(&LASSO_LIB_STATUS_RESPONSE(self)->Extension, (value))

/* providerId */
#define LassoLibLogoutResponse_get_ProviderID(self) LASSO_LIB_STATUS_RESPONSE(self)->ProviderID
#define LassoLibLogoutResponse_ProviderID_get(self) LASSO_LIB_STATUS_RESPONSE(self)->ProviderID
#define LassoLibLogoutResponse_set_ProviderID(self, value) set_string(&LASSO_LIB_STATUS_RESPONSE(self)->ProviderID, (value))
#define LassoLibLogoutResponse_ProviderID_set(self, value) set_string(&LASSO_LIB_STATUS_RESPONSE(self)->ProviderID, (value))

/* RelayState */
#define LassoLibLogoutResponse_get_RelayState(self) LASSO_LIB_STATUS_RESPONSE(self)->RelayState
#define LassoLibLogoutResponse_RelayState_get(self) LASSO_LIB_STATUS_RESPONSE(self)->RelayState
#define LassoLibLogoutResponse_set_RelayState(self, value) set_string(&LASSO_LIB_STATUS_RESPONSE(self)->RelayState, (value))
#define LassoLibLogoutResponse_RelayState_set(self, value) set_string(&LASSO_LIB_STATUS_RESPONSE(self)->RelayState, (value))

/* Status */
#define LassoLibLogoutResponse_get_Status(self) get_node(LASSO_LIB_STATUS_RESPONSE(self)->Status)
#define LassoLibLogoutResponse_Status_get(self) get_node(LASSO_LIB_STATUS_RESPONSE(self)->Status)
#define LassoLibLogoutResponse_set_Status(self, value) set_node((gpointer *) &LASSO_LIB_STATUS_RESPONSE(self)->Status, (value))
#define LassoLibLogoutResponse_Status_set(self, value) set_node((gpointer *) &LASSO_LIB_STATUS_RESPONSE(self)->Status, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoLibLogoutResponse lasso_lib_logout_response_new_full
#define delete_LassoLibLogoutResponse(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoLibLogoutResponse_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * lib:RegisterNameIdentifierRequest
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(LibRegisterNameIdentifierRequest) LassoLibRegisterNameIdentifierRequest;
#endif
typedef struct {
	/* Attributes */

#ifndef SWIGPHP4
	%rename(providerId) ProviderID;
#endif
	char *ProviderID;

#ifndef SWIGPHP4
	%rename(relayState) RelayState;
#endif
	char *RelayState;
} LassoLibRegisterNameIdentifierRequest;
%extend LassoLibRegisterNameIdentifierRequest {
	/* Attributes */

	%newobject extension_get;
	LassoStringArray *extension;

#ifndef SWIGPHP4
	%rename(idpProvidedNameIdentifier) IDPProvidedNameIdentifier;
#endif
	%newobject IDPProvidedNameIdentifier_get;
	LassoSamlNameIdentifier *IDPProvidedNameIdentifier;

#ifndef SWIGPHP4
	%rename(oldProvidedNameIdentifier) OldProvidedNameIdentifier;
#endif
	%newobject OldProvidedNameIdentifier_get;
	LassoSamlNameIdentifier *OldProvidedNameIdentifier;

#ifndef SWIGPHP4
	%rename(spProvidedNameIdentifier) SPProvidedNameIdentifier;
#endif
	%newobject SPProvidedNameIdentifier_get;
	LassoSamlNameIdentifier *SPProvidedNameIdentifier;

	/* Constructor, Destructor & Static Methods */

	LassoLibRegisterNameIdentifierRequest(
			char *providerID,
			LassoSamlNameIdentifier *idpNameIdentifier,
			LassoSamlNameIdentifier *spNameIdentifier,
			LassoSamlNameIdentifier *oldNameIdentifier,
			LassoSignatureType sign_type, LassoSignatureMethod sign_method);

	~LassoLibRegisterNameIdentifierRequest();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes implementations */

/* extension */
#define LassoLibRegisterNameIdentifierRequest_get_extension(self) get_xml_list((self)->Extension)
#define LassoLibRegisterNameIdentifierRequest_extension_get(self) get_xml_list((self)->Extension)
#define LassoLibRegisterNameIdentifierRequest_set_extension(self, value) set_xml_list(&(self)->Extension, (value))
#define LassoLibRegisterNameIdentifierRequest_extension_set(self, value) set_xml_list(&(self)->Extension, (value))

/* idpProvidedNameIdentifier */
#define LassoLibRegisterNameIdentifierRequest_get_IDPProvidedNameIdentifier(self) get_node((self)->IDPProvidedNameIdentifier)
#define LassoLibRegisterNameIdentifierRequest_IDPProvidedNameIdentifier_get(self) get_node((self)->IDPProvidedNameIdentifier)
#define LassoLibRegisterNameIdentifierRequest_set_IDPProvidedNameIdentifier(self, value) set_node((gpointer *) &(self)->IDPProvidedNameIdentifier, (value))
#define LassoLibRegisterNameIdentifierRequest_IDPProvidedNameIdentifier_set(self, value) set_node((gpointer *) &(self)->IDPProvidedNameIdentifier, (value))

/* oldProvidedNameIdentifier */
#define LassoLibRegisterNameIdentifierRequest_get_OldProvidedNameIdentifier(self) get_node((self)->OldProvidedNameIdentifier)
#define LassoLibRegisterNameIdentifierRequest_OldProvidedNameIdentifier_get(self) get_node((self)->OldProvidedNameIdentifier)
#define LassoLibRegisterNameIdentifierRequest_set_OldProvidedNameIdentifier(self, value) set_node((gpointer *) &(self)->OldProvidedNameIdentifier, (value))
#define LassoLibRegisterNameIdentifierRequest_OldProvidedNameIdentifier_set(self, value) set_node((gpointer *) &(self)->OldProvidedNameIdentifier, (value))

/* spProvidedNameIdentifier */
#define LassoLibRegisterNameIdentifierRequest_get_SPProvidedNameIdentifier(self) get_node((self)->SPProvidedNameIdentifier)
#define LassoLibRegisterNameIdentifierRequest_SPProvidedNameIdentifier_get(self) get_node((self)->SPProvidedNameIdentifier)
#define LassoLibRegisterNameIdentifierRequest_set_SPProvidedNameIdentifier(self, value) set_node((gpointer *) &(self)->SPProvidedNameIdentifier, (value))
#define LassoLibRegisterNameIdentifierRequest_SPProvidedNameIdentifier_set(self, value) set_node((gpointer *) &(self)->SPProvidedNameIdentifier, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoLibRegisterNameIdentifierRequest lasso_lib_register_name_identifier_request_new_full
#define delete_LassoLibRegisterNameIdentifierRequest(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoLibRegisterNameIdentifierRequest_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * lib:RegisterNameIdentifierResponse
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(LibRegisterNameIdentifierResponse) LassoLibRegisterNameIdentifierResponse;
#endif
typedef struct {
} LassoLibRegisterNameIdentifierResponse;
%extend LassoLibRegisterNameIdentifierResponse {
	/* Attributes inherited from LibStatusResponse */

	%newobject extension_get;
	LassoStringArray *extension;

#ifndef SWIGPHP4
	%rename(providerId) ProviderID;
#endif
	char *ProviderID;

#ifndef SWIGPHP4
	%rename(relayState) RelayState;
#endif
	char *RelayState;

#ifndef SWIGPHP4
	%rename(status) Status;
#endif
	%newobject Status_get;
	LassoSamlpStatus *Status;

	/* Constructor, Destructor & Static Methods */

	LassoLibRegisterNameIdentifierResponse(
			char *providerID, char *statusCodeValue,
			LassoLibRegisterNameIdentifierRequest *request,
			LassoSignatureType sign_type, LassoSignatureMethod sign_method);

	~LassoLibRegisterNameIdentifierResponse();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes inherited from LibStatusResponse implementations */

/* extension */
#define LassoLibRegisterNameIdentifierResponse_get_extension(self) get_xml_list(LASSO_LIB_STATUS_RESPONSE(self)->Extension)
#define LassoLibRegisterNameIdentifierResponse_extension_get(self) get_xml_list(LASSO_LIB_STATUS_RESPONSE(self)->Extension)
#define LassoLibRegisterNameIdentifierResponse_set_extension(self, value) set_xml_list(&LASSO_LIB_STATUS_RESPONSE(self)->Extension, (value))
#define LassoLibRegisterNameIdentifierResponse_extension_set(self, value) set_xml_list(&LASSO_LIB_STATUS_RESPONSE(self)->Extension, (value))

/* providerId */
#define LassoLibRegisterNameIdentifierResponse_get_ProviderID(self) LASSO_LIB_STATUS_RESPONSE(self)->ProviderID
#define LassoLibRegisterNameIdentifierResponse_ProviderID_get(self) LASSO_LIB_STATUS_RESPONSE(self)->ProviderID
#define LassoLibRegisterNameIdentifierResponse_set_ProviderID(self, value) set_string(&LASSO_LIB_STATUS_RESPONSE(self)->ProviderID, (value))
#define LassoLibRegisterNameIdentifierResponse_ProviderID_set(self, value) set_string(&LASSO_LIB_STATUS_RESPONSE(self)->ProviderID, (value))

/* RelayState */
#define LassoLibRegisterNameIdentifierResponse_get_RelayState(self) LASSO_LIB_STATUS_RESPONSE(self)->RelayState
#define LassoLibRegisterNameIdentifierResponse_RelayState_get(self) LASSO_LIB_STATUS_RESPONSE(self)->RelayState
#define LassoLibRegisterNameIdentifierResponse_set_RelayState(self, value) set_string(&LASSO_LIB_STATUS_RESPONSE(self)->RelayState, (value))
#define LassoLibRegisterNameIdentifierResponse_RelayState_set(self, value) set_string(&LASSO_LIB_STATUS_RESPONSE(self)->RelayState, (value))

/* Status */
#define LassoLibRegisterNameIdentifierResponse_get_Status(self) get_node(LASSO_LIB_STATUS_RESPONSE(self)->Status)
#define LassoLibRegisterNameIdentifierResponse_Status_get(self) get_node(LASSO_LIB_STATUS_RESPONSE(self)->Status)
#define LassoLibRegisterNameIdentifierResponse_set_Status(self, value) set_node((gpointer *) &LASSO_LIB_STATUS_RESPONSE(self)->Status, (value))
#define LassoLibRegisterNameIdentifierResponse_Status_set(self, value) set_node((gpointer *) &LASSO_LIB_STATUS_RESPONSE(self)->Status, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoLibRegisterNameIdentifierResponse lasso_lib_register_name_identifier_response_new_full
#define delete_LassoLibRegisterNameIdentifierResponse(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoLibRegisterNameIdentifierResponse_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 * lib:StatusResponse
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(LibStatusResponse) LassoLibStatusResponse;
#endif
typedef struct {
	/* Attributes */

#ifndef SWIGPHP4
	%rename(providerId) ProviderID;
#endif
	char *ProviderID;

#ifndef SWIGPHP4
	%rename(relayState) RelayState;
#endif
	char *RelayState;
} LassoLibStatusResponse;
%extend LassoLibStatusResponse {
	/* Attributes */

	%newobject extension_get;
	LassoStringArray *extension;

#ifndef SWIGPHP4
	%rename(status) Status;
#endif
	%newobject Status_get;
	LassoSamlpStatus *Status;

	/* Constructor, Destructor & Static Methods */

	LassoLibStatusResponse();

	~LassoLibStatusResponse();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes implementations */

/* extension */
#define LassoLibStatusResponse_get_extension(self) get_xml_list((self)->Extension)
#define LassoLibStatusResponse_extension_get(self) get_xml_list((self)->Extension)
#define LassoLibStatusResponse_set_extension(self, value) set_xml_list(&(self)->Extension, (value))
#define LassoLibStatusResponse_extension_set(self, value) set_xml_list(&(self)->Extension, (value))

/* Status */
#define LassoLibStatusResponse_get_Status(self) get_node((self)->Status)
#define LassoLibStatusResponse_Status_get(self) get_node((self)->Status)
#define LassoLibStatusResponse_set_Status(self, value) set_node((gpointer *) &(self)->Status, (value))
#define LassoLibStatusResponse_Status_set(self, value) set_node((gpointer *) &(self)->Status, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoLibStatusResponse lasso_lib_status_response_new
#define delete_LassoLibStatusResponse(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoLibStatusResponse_dump(self) lasso_node_dump(LASSO_NODE(self))

%}


/***********************************************************************
 ***********************************************************************
 * ID-FF
 ***********************************************************************
 ***********************************************************************/


/***********************************************************************
 * lasso:Provider
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(Provider) LassoProvider;
#endif
typedef struct {
#ifndef SWIGPHP4
	%rename(caCertChain) ca_cert_chain;
#endif
	char *ca_cert_chain;

#ifndef SWIGPHP4
	%rename(metadataFilename) metadata_filename;
#endif
	char *metadata_filename;

#ifndef SWIGPHP4
	%rename(providerId) ProviderID;
#endif
	char *ProviderID;

#ifndef SWIGPHP4
	%rename(publicKey) public_key;
#endif
	char *public_key;

	LassoProviderRole role;
} LassoProvider;
%extend LassoProvider {
	/* Constructor, Destructor & Static Methods */

	LassoProvider(LassoProviderRole role, const char *metadata,
			const char *public_key, const char *ca_cert_chain);

	~LassoProvider();

	%newobject newFromDump;
	static LassoProvider *newFromDump(char *dump);

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();

	/* Methods */

	gboolean acceptHttpMethod(
			LassoProvider *remote_provider, LassoMdProtocolType protocol_type,
			LassoHttpMethod http_method, gboolean initiate_profile);

	%newobject getAssertionConsumerServiceUrl;
	char* getAssertionConsumerServiceUrl(char *service_id);

	%newobject getBase64SuccinctId;
	char* getBase64SuccinctId();

	LassoHttpMethod getFirstHttpMethod(
			LassoProvider *remote_provider, LassoMdProtocolType protocol_type);

	// FIXME: GList* lasso_provider_get_metadata_list(char *name);

	%newobject getMetadataOne;
	char* getMetadataOne(char *name);

	gboolean hasProtocolProfile(LassoMdProtocolType protocol_type, char *protocol_profile);
}

%{

/* Constructors, destructors & static methods implementations */

#define new_LassoProvider lasso_provider_new
#define delete_LassoProvider(self) lasso_node_destroy(LASSO_NODE(self))
#ifdef PHP_VERSION
#define LassoProvider_newFromDump lasso_provider_new_from_dump
#else
#define Provider_newFromDump lasso_provider_new_from_dump
#endif

/* Implementations of methods inherited from LassoNode */

#define LassoProvider_dump(self) lasso_node_dump(LASSO_NODE(self))

/* Methods implementations */

#define LassoProvider_acceptHttpMethod lasso_provider_accept_http_method
#define LassoProvider_getAssertionConsumerServiceUrl lasso_provider_get_assertion_consumer_service_url
#define LassoProvider_getBase64SuccinctId lasso_provider_get_base64_succinct_id
#define LassoProvider_getFirstHttpMethod lasso_provider_get_first_http_method
#define LassoProvider_getMetadataOne lasso_provider_get_metadata_one
#define LassoProvider_hasProtocolProfile lasso_provider_has_protocol_profile

%}


/***********************************************************************
 * lasso:Server
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(Server) LassoServer;
#endif
typedef struct {
	char *certificate;

#ifndef SWIGPHP4
	%rename(privateKey) private_key;
#endif
	char *private_key;

#ifndef SWIGPHP4
	%rename(secretKey) secret_key;
#endif
	char *secret_key;

#ifndef SWIGPHP4
	%rename(signatureMethod) signature_method;
#endif
	LassoSignatureMethod signature_method;
} LassoServer;
%extend LassoServer {
	/* Attributes inherited from Provider */

#ifndef SWIGPHP4
	%rename(caCertChain) ca_cert_chain;
#endif
	char *ca_cert_chain;

#ifndef SWIGPHP4
	%rename(metadataFilename) metadata_filename;
#endif
	char *metadata_filename;

#ifndef SWIGPHP4
	%rename(providerId) ProviderID;
#endif
	char *ProviderID;

#ifndef SWIGPHP4
	%rename(publicKey) public_key;
#endif
	char *public_key;

	/* Attributes */

	%immutable providerIds;
	%newobject providerIds_get;
	LassoStringArray *providerIds;

	/* Constructor, destructor & static methods */

	LassoServer(char *metadata = NULL, char *privateKey = NULL, char *secretKey = NULL,
			char *certificate = NULL);

	~LassoServer();

	%newobject newFromDump;
	static LassoServer *newFromDump(char *dump);

	/* Methods inherited from Provider */

	gboolean acceptHttpMethod(
			LassoProvider *remote_provider, LassoMdProtocolType protocol_type,
			LassoHttpMethod http_method, gboolean initiate_profile);

	%newobject getAssertionConsumerServiceUrl;
	char* getAssertionConsumerServiceUrl(char *service_id);

	%newobject getBase64SuccinctId;
	char* getBase64SuccinctId();

	LassoHttpMethod getFirstHttpMethod(
			LassoProvider *remote_provider, LassoMdProtocolType protocol_type);

	// FIXME: GList* lasso_provider_get_metadata_list(char *name);

	%newobject getMetadataOne;
	char* getMetadataOne(char *name);

	gboolean hasProtocolProfile(LassoMdProtocolType protocol_type, char *protocol_profile);

	/* Methods */

        THROW_ERROR
	void addProvider(LassoProviderRole role, char *metadata, char *publicKey = NULL,
			char *caCertChain = NULL);
	END_THROW_ERROR

        THROW_ERROR
	void addService(char *service_type, char *service_endpoint);
	END_THROW_ERROR

	%newobject dump;
	char *dump();

	LassoProvider *getProvider(char *providerId);
}

%{

/* Implementations of attributes inherited from Provider */

/* providerId */
#define LassoServer_get_ProviderID(self) LASSO_PROVIDER(self)->ProviderID
#define LassoServer_ProviderID_get(self) LASSO_PROVIDER(self)->ProviderID
#define LassoServer_set_ProviderID(self, value) set_string(&LASSO_PROVIDER(self)->ProviderID, (value))
#define LassoServer_ProviderID_set(self, value) set_string(&LASSO_PROVIDER(self)->ProviderID, (value))

/* ca_cert_chain */
#define LassoServer_get_ca_cert_chain(self) LASSO_PROVIDER(self)->ca_cert_chain
#define LassoServer_ca_cert_chain_get(self) LASSO_PROVIDER(self)->ca_cert_chain
#define LassoServer_set_ca_cert_chain(self, value) set_string(&LASSO_PROVIDER(self)->ca_cert_chain, (value))
#define LassoServer_ca_cert_chain_set(self, value) set_string(&LASSO_PROVIDER(self)->ca_cert_chain, (value))

/* metadata_filename */
#define LassoServer_get_metadata_filename(self) LASSO_PROVIDER(self)->metadata_filename
#define LassoServer_metadata_filename_get(self) LASSO_PROVIDER(self)->metadata_filename
#define LassoServer_set_metadata_filename(self, value) set_string(&LASSO_PROVIDER(self)->metadata_filename, (value))
#define LassoServer_metadata_filename_set(self, value) set_string(&LASSO_PROVIDER(self)->metadata_filename, (value))

/* public_key */
#define LassoServer_get_public_key(self) LASSO_PROVIDER(self)->public_key
#define LassoServer_public_key_get(self) LASSO_PROVIDER(self)->public_key
#define LassoServer_set_public_key(self, value) set_string(&LASSO_PROVIDER(self)->public_key, (value))
#define LassoServer_public_key_set(self, value) set_string(&LASSO_PROVIDER(self)->public_key, (value))

/* Attributes implementations */

/* providerIds */
#define LassoServer_get_providerIds LassoServer_providerIds_get
LassoStringArray *LassoServer_providerIds_get(LassoServer *self) {
	GPtrArray *providerIds = g_ptr_array_sized_new(g_hash_table_size(self->providers));
	g_hash_table_foreach(self->providers, (GHFunc) add_key_to_array, providerIds);
	return providerIds;
}

/* Constructors, destructors & static methods implementations */

#define new_LassoServer lasso_server_new
#define delete_LassoServer(self) lasso_node_destroy(LASSO_NODE(self))
#ifdef PHP_VERSION
#define LassoServer_newFromDump lasso_server_new_from_dump
#else
#define Server_newFromDump lasso_server_new_from_dump
#endif

/* Implementations of methods inherited from Provider */

#define LassoServer_acceptHttpMethod(server, remote_provider, protocol_type, http_method, initiate_profile) lasso_provider_accept_http_method(LASSO_PROVIDER(server), remote_provider, protocol_type, http_method, initiate_profile)
#define LassoServer_getAssertionConsumerServiceUrl(server, service_id) lasso_provider_get_assertion_consumer_service_url(LASSO_PROVIDER(server), service_id)
#define LassoServer_getBase64SuccinctId(server) lasso_provider_get_base64_succinct_id(LASSO_PROVIDER(server))
#define LassoServer_getFirstHttpMethod(server, remote_provider, protocol_type) lasso_provider_get_first_http_method(LASSO_PROVIDER(server), remote_provider, protocol_type)
#define LassoServer_getMetadataOne(server, name) lasso_provider_get_metadata_one(LASSO_PROVIDER(server), name)
#define LassoServer_hasProtocolProfile(server, protocol_type, protocol_profile) lasso_provider_has_protocol_profile(LASSO_PROVIDER(server), protocol_type, protocol_profile)

/* Methods implementations */

#define LassoServer_addProvider lasso_server_add_provider
#define LassoServer_addService lasso_server_add_service
#define LassoServer_dump lasso_server_dump
#define LassoServer_getProvider lasso_server_get_provider

%}


/***********************************************************************
 * lasso:Federation
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(Federation) LassoFederation;
#endif
typedef struct {
	/* Attributes */

#ifndef SWIGPHP4
	%rename(remoteProviderId) remote_providerID;
#endif
	gchar *remote_providerID;
} LassoFederation;
%extend LassoFederation {
	/* Attributes */

#ifndef SWIGPHP4
	%rename(localNameIdentifier) local_nameIdentifier;
#endif
	%newobject local_nameIdentifier_get;
	LassoSamlNameIdentifier *local_nameIdentifier;

#ifndef SWIGPHP4
	%rename(remoteNameIdentifier) remote_nameIdentifier;
#endif
	%newobject remote_nameIdentifier_get;
	LassoSamlNameIdentifier *remote_nameIdentifier;

	/* Constructor, Destructor & Static Methods */

	LassoFederation(char *remoteProviderId);

	~LassoFederation();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();

	/* Methods */

	void buildLocalNameIdentifier(char *nameQualifier, char *format, char *content);

	gboolean verifyNameIdentifier(LassoSamlNameIdentifier *nameIdentifier);
}

%{

/* Attributes implementations */

/* localNameIdentifier */
#define LassoFederation_get_local_nameIdentifier(self) get_node((self)->local_nameIdentifier)
#define LassoFederation_local_nameIdentifier_get(self) get_node((self)->local_nameIdentifier)
#define LassoFederation_set_local_nameIdentifier(self, value) set_node((gpointer *) &(self)->local_nameIdentifier, (value))
#define LassoFederation_local_nameIdentifier_set(self, value) set_node((gpointer *) &(self)->local_nameIdentifier, (value))

/* remoteNameIdentifier */
#define LassoFederation_get_remote_nameIdentifier(self) get_node((self)->remote_nameIdentifier)
#define LassoFederation_remote_nameIdentifier_get(self) get_node((self)->remote_nameIdentifier)
#define LassoFederation_set_remote_nameIdentifier(self, value) set_node((gpointer *) &(self)->remote_nameIdentifier, (value))
#define LassoFederation_remote_nameIdentifier_set(self, value) set_node((gpointer *) &(self)->remote_nameIdentifier, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoFederation lasso_federation_new
#define delete_LassoFederation(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoFederation_dump(self) lasso_node_dump(LASSO_NODE(self))

/* Methods implementations */

#define LassoFederation_buildLocalNameIdentifier lasso_federation_build_local_name_identifier
#define LassoFederation_verifyNameIdentifier lasso_federation_verify_name_identifier

%}


/***********************************************************************
 * lasso:Identity
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(Identity) LassoIdentity;
#endif
typedef struct {
	/* Attributes */

#ifndef SWIGPHP4
	%rename(isDirty) is_dirty;
#endif
	%immutable is_dirty;
	gboolean is_dirty;
} LassoIdentity;
%extend LassoIdentity {
	/* Attributes */

	%immutable providerIds;
	%newobject providerIds_get;
	LassoStringArray *providerIds;

	/* Constructor, Destructor & Static Methods */

	LassoIdentity();

	~LassoIdentity();

	%newobject newFromDump;
	static LassoIdentity *newFromDump(char *dump);

	/* Methods */

        THROW_ERROR
	void addFederation(LassoFederation *federation);
	END_THROW_ERROR

	%newobject dump;
	char *dump();

	LassoFederation *getFederation(char *providerId);

        THROW_ERROR
	void removeFederation(char *providerId);
	END_THROW_ERROR
}

%{

/* Attributes implementations */

/* providerIds */
#define LassoIdentity_get_providerIds LassoIdentity_providerIds_get
LassoStringArray *LassoIdentity_providerIds_get(LassoIdentity *self) {
	GPtrArray *providerIds = g_ptr_array_sized_new(g_hash_table_size(self->federations));
	g_hash_table_foreach(self->federations, (GHFunc) add_key_to_array, providerIds);
	return providerIds;
}


/* Constructors, destructors & static methods implementations */

#define new_LassoIdentity lasso_identity_new
#define delete_LassoIdentity(self) lasso_node_destroy(LASSO_NODE(self))
#ifdef PHP_VERSION
#define LassoIdentity_newFromDump lasso_identity_new_from_dump
#else
#define Identity_newFromDump lasso_identity_new_from_dump
#endif

/* Methods implementations */

#define LassoIdentity_addFederation lasso_identity_add_federation
#define LassoIdentity_dump lasso_identity_dump
#define LassoIdentity_getFederation lasso_identity_get_federation
#define LassoIdentity_removeFederation lasso_identity_remove_federation

%}


/***********************************************************************
 * lasso:Session
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(Session) LassoSession;
#endif
typedef struct {
	/* Attributes */

#ifndef SWIGPHP4
	%rename(isDirty) is_dirty;
#endif
	%immutable is_dirty;
	gboolean is_dirty;
} LassoSession;
%extend LassoSession {
	/* Attributes */

	%immutable providerIds;
	%newobject providerIds_get;
	LassoStringArray *providerIds;

	/* Constructor, destructor & static methods */

	LassoSession();

	~LassoSession();

	%newobject newFromDump;
	static LassoSession *newFromDump(char *dump);

	/* Methods */

	%newobject dump;
	char *dump();
}

%{

/* Attributes implementations */

/* providerIds */
#define LassoSession_get_providerIds LassoSession_providerIds_get
LassoStringArray *LassoSession_providerIds_get(LassoSession *self) {
	GPtrArray *providerIds = g_ptr_array_sized_new(g_hash_table_size(self->assertions));
	g_hash_table_foreach(self->assertions, (GHFunc) add_key_to_array, providerIds);
	return providerIds;
}

/* Constructors, destructors & static methods implementations */

#define new_LassoSession lasso_session_new
#define delete_LassoSession(self) lasso_node_destroy(LASSO_NODE(self))
#ifdef PHP_VERSION
#define LassoSession_newFromDump lasso_session_new_from_dump
#else
#define Session_newFromDump lasso_session_new_from_dump
#endif

/* Methods implementations */

#define LassoSession_dump lasso_session_dump

%}


/***********************************************************************
 * lasso:Profile
 ***********************************************************************/


/* Functions */

#ifdef SWIGPHP4
%rename(lasso_getRequestTypeFromSoapMsg) lasso_profile_get_request_type_from_soap_msg;
#else
%rename(getRequestTypeFromSoapMsg) lasso_profile_get_request_type_from_soap_msg;
#endif
LassoRequestType lasso_profile_get_request_type_from_soap_msg(char *soap);

#ifdef SWIGPHP4
%rename(lasso_isLibertyQuery) lasso_profile_is_liberty_query;
#else
%rename(isLibertyQuery) lasso_profile_is_liberty_query;
#endif
gboolean lasso_profile_is_liberty_query(char *query);


/***********************************************************************
 * lasso:Defederation
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(Defederation) LassoDefederation;
#endif
typedef struct {
} LassoDefederation;
%extend LassoDefederation {
	/* Attributes inherited from Profile */

	%newobject identity_get;
	LassoIdentity *identity;

	%immutable isIdentityDirty;
	gboolean isIdentityDirty;

	%immutable isSessionDirty;
	gboolean isSessionDirty;

	%immutable msgBody;
	char *msgBody;

	%immutable msgRelayState;
	char *msgRelayState;

	%immutable msgUrl;
	char *msgUrl;

	%newobject nameIdentifier_get;
	LassoSamlNameIdentifier *nameIdentifier;

	char *remoteProviderId;

	%immutable request;
	LassoLibFederationTerminationNotification *request;

	%newobject session_get;
	LassoSession *session;

	/* Constructor, Destructor & Static Methods */

	LassoDefederation(LassoServer *server);

	~LassoDefederation();

	/* Methods inherited from Profile */

        THROW_ERROR
	void setIdentityFromDump(char *dump);
	END_THROW_ERROR

	THROW_ERROR
	void setSessionFromDump(char *dump);
	END_THROW_ERROR

	/* Methods */

	THROW_ERROR
	void buildNotificationMsg();
	END_THROW_ERROR

	THROW_ERROR
	void initNotification(char *remoteProviderId = NULL,
			      LassoHttpMethod httpMethod = LASSO_HTTP_METHOD_ANY);
	END_THROW_ERROR

	THROW_ERROR
	void processNotificationMsg(char *notificationMsg);
	END_THROW_ERROR

	THROW_ERROR
	void validateNotification();
	END_THROW_ERROR
}

%{

/* Attributes inherited from Profile implementations */

/* identity */
#define LassoDefederation_get_identity(self) lasso_profile_get_identity(LASSO_PROFILE(self))
#define LassoDefederation_identity_get(self) lasso_profile_get_identity(LASSO_PROFILE(self))
#define LassoDefederation_set_identity(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->identity, (value))
#define LassoDefederation_identity_set(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->identity, (value))

/* isIdentityDirty */
#define LassoDefederation_get_isIdentityDirty(self) lasso_profile_is_identity_dirty(LASSO_PROFILE(self))
#define LassoDefederation_isIdentityDirty_get(self) lasso_profile_is_identity_dirty(LASSO_PROFILE(self))

/* isSessionDirty */
#define LassoDefederation_get_isSessionDirty(self) lasso_profile_is_session_dirty(LASSO_PROFILE(self))
#define LassoDefederation_isSessionDirty_get(self) lasso_profile_is_session_dirty(LASSO_PROFILE(self))

/* msgBody */
#define LassoDefederation_get_msgBody(self) LASSO_PROFILE(self)->msg_body
#define LassoDefederation_msgBody_get(self) LASSO_PROFILE(self)->msg_body

/* msgRelayState */
#define LassoDefederation_get_msgRelayState(self) LASSO_PROFILE(self)->msg_relayState
#define LassoDefederation_msgRelayState_get(self) LASSO_PROFILE(self)->msg_relayState

/* msgUrl */
#define LassoDefederation_get_msgUrl(self) LASSO_PROFILE(self)->msg_url
#define LassoDefederation_msgUrl_get(self) LASSO_PROFILE(self)->msg_url

/* nameIdentifier */
#define LassoDefederation_get_nameIdentifier(self) get_node(LASSO_PROFILE(self)->nameIdentifier)
#define LassoDefederation_nameIdentifier_get(self) get_node(LASSO_PROFILE(self)->nameIdentifier)
#define LassoDefederation_set_nameIdentifier(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->nameIdentifier, (value))
#define LassoDefederation_nameIdentifier_set(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->nameIdentifier, (value))

/* remoteProviderId */
#define LassoDefederation_get_remoteProviderId(self) LASSO_PROFILE(self)->remote_providerID
#define LassoDefederation_remoteProviderId_get(self) LASSO_PROFILE(self)->remote_providerID
#define LassoDefederation_set_remoteProviderId(self, value) set_string(&LASSO_PROFILE(self)->remote_providerID, (value))
#define LassoDefederation_remoteProviderId_set(self, value) set_string(&LASSO_PROFILE(self)->remote_providerID, (value))

/* request */
#define LassoDefederation_get_request(self) LASSO_LIB_FEDERATION_TERMINATION_NOTIFICATION(LASSO_PROFILE(self)->request)
#define LassoDefederation_request_get(self) LASSO_LIB_FEDERATION_TERMINATION_NOTIFICATION(LASSO_PROFILE(self)->request)

/* responseStatus */
#define LassoDefederation_get_responseStatus(self) NULL /* FIXME: no set */
#define LassoDefederation_responseStatus_get(self) NULL /* FIXME: no set */
#define LassoDefederation_set_responseStatus(self, value) lasso_profile_set_response_status(LASSO_PROFILE(self), value)
#define LassoDefederation_responseStatus_set(self, value) lasso_profile_set_response_status(LASSO_PROFILE(self), value)

/* session */
#define LassoDefederation_get_session(self) lasso_profile_get_session(LASSO_PROFILE(self))
#define LassoDefederation_session_get(self) lasso_profile_get_session(LASSO_PROFILE(self))
#define LassoDefederation_set_session(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->session, (value))
#define LassoDefederation_session_set(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->session, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoDefederation lasso_defederation_new
#define delete_LassoDefederation(self) lasso_node_destroy(LASSO_NODE(self))

/* Methods inherited from Profile implementations */

int LassoDefederation_setIdentityFromDump(LassoDefederation *self, char *dump) {
	return lasso_profile_set_identity_from_dump(LASSO_PROFILE(self), dump);
}

int LassoDefederation_setSessionFromDump(LassoDefederation *self, char *dump) {
	return lasso_profile_set_session_from_dump(LASSO_PROFILE(self), dump);
}

/* Methods implementations */

#define LassoDefederation_buildNotificationMsg lasso_defederation_build_notification_msg
#define LassoDefederation_initNotification lasso_defederation_init_notification
#define LassoDefederation_processNotificationMsg lasso_defederation_process_notification_msg
#define LassoDefederation_validateNotification lasso_defederation_validate_notification

%}


/***********************************************************************
 * lasso:Login
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(Login) LassoLogin;
#endif
typedef struct {
	// FIXME: LassoSamlAssertion *assertion;

	%immutable assertionArtifact;
	char *assertionArtifact;

	%immutable protocolProfile;
	LassoLoginProtocolProfile protocolProfile;
} LassoLogin;
%extend LassoLogin {
	/* Attributes inherited from Profile */

	%immutable authnRequest;
	LassoLibAuthnRequest *authnRequest;

	%immutable authnResponse;
	LassoLibAuthnResponse *authnResponse;

	%newobject identity_get;
	LassoIdentity *identity;

	%immutable isIdentityDirty;
	gboolean isIdentityDirty;

	%immutable isSessionDirty;
	gboolean isSessionDirty;

	%immutable msgBody;
	char *msgBody;

	%immutable msgRelayState;
	char *msgRelayState;

	%immutable msgUrl;
	char *msgUrl;

	%newobject nameIdentifier_get;
	LassoSamlNameIdentifier *nameIdentifier;

	char *remoteProviderId;

	%immutable request;
	LassoSamlpRequest *request;

	%immutable response;
	LassoSamlpResponse *response;

	char *responseStatus;

	%newobject session_get;
	LassoSession *session;

	/* Constructor, Destructor & Static Methods */

	LassoLogin(LassoServer *server);

	~LassoLogin();

	%newobject newFromDump;
	static LassoLogin *newFromDump(LassoServer *server, char *dump);

	/* Methods inherited from Profile */

        THROW_ERROR
	void setIdentityFromDump(char *dump);
	END_THROW_ERROR

	THROW_ERROR
	void setSessionFromDump(char *dump);
	END_THROW_ERROR

	/* Methods */

	THROW_ERROR
	void acceptSso();
	END_THROW_ERROR

	THROW_ERROR
	void buildArtifactMsg(LassoHttpMethod httpMethod);
	END_THROW_ERROR

	THROW_ERROR
	int buildAssertion(char *authenticationMethod, char *authenticationInstant,
			char *reauthenticateOnOrAfter,
			char *notBefore, char *notOnOrAfter);
	END_THROW_ERROR

	THROW_ERROR
	void buildAuthnRequestMsg();
	END_THROW_ERROR

	THROW_ERROR
	void buildAuthnResponseMsg();
	END_THROW_ERROR

	THROW_ERROR
	void buildRequestMsg();
	END_THROW_ERROR

	THROW_ERROR
	void buildResponseMsg(char *remoteProviderId);
	END_THROW_ERROR

	%newobject dump;
	char *dump();

	THROW_ERROR
	void initAuthnRequest(char *remoteProviderId = NULL,
			 LassoHttpMethod httpMethod = LASSO_HTTP_METHOD_REDIRECT);
	END_THROW_ERROR

	THROW_ERROR
	void initRequest(char *responseMsg,
			 LassoHttpMethod httpMethod = LASSO_HTTP_METHOD_REDIRECT);
	END_THROW_ERROR

	THROW_ERROR
	void initIdpInitiatedAuthnRequest(char *remoteProviderID = NULL);
	END_THROW_ERROR

	gboolean mustAskForConsent();

	gboolean mustAuthenticate();

	THROW_ERROR
	void processAuthnRequestMsg(char *authnrequestMsg);
	END_THROW_ERROR

	THROW_ERROR
	void processAuthnResponseMsg(char *authnResponseMsg);
	END_THROW_ERROR

	THROW_ERROR
	void processRequestMsg(char *requestMsg);
	END_THROW_ERROR

	THROW_ERROR
	void processResponseMsg(char *responseMsg);
	END_THROW_ERROR

	THROW_ERROR
	int validateRequestMsg(gboolean authenticationResult, gboolean isConsentObtained);
	END_THROW_ERROR
}

%{

/* Attributes inherited from Profile implementations */

/* authnRequest */
#define LassoLogin_get_authnRequest LassoLogin_authnRequest_get
LassoLibAuthnRequest *LassoLogin_authnRequest_get(LassoLogin *self) {
	LassoProfile *profile = LASSO_PROFILE(self);
	if (LASSO_IS_LIB_AUTHN_REQUEST(profile->request))
		return LASSO_LIB_AUTHN_REQUEST(g_object_ref(profile->request));
	return NULL;
}

/* authnResponse */
#define LassoLogin_get_authnResponse LassoLogin_authnResponse_get
LassoLibAuthnResponse *LassoLogin_authnResponse_get(LassoLogin *self) {
	LassoProfile *profile = LASSO_PROFILE(self);
	if (LASSO_IS_LIB_AUTHN_RESPONSE(profile->response))
		return LASSO_LIB_AUTHN_RESPONSE(g_object_ref(profile->response));
	return NULL;
}

/* identity */
#define LassoLogin_get_identity(self) lasso_profile_get_identity(LASSO_PROFILE(self))
#define LassoLogin_identity_get(self) lasso_profile_get_identity(LASSO_PROFILE(self))
#define LassoLogin_set_identity(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->identity, (value))
#define LassoLogin_identity_set(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->identity, (value))

/* isIdentityDirty */
#define LassoLogin_get_isIdentityDirty(self) lasso_profile_is_identity_dirty(LASSO_PROFILE(self))
#define LassoLogin_isIdentityDirty_get(self) lasso_profile_is_identity_dirty(LASSO_PROFILE(self))

/* isSessionDirty */
#define LassoLogin_get_isSessionDirty(self) lasso_profile_is_session_dirty(LASSO_PROFILE(self))
#define LassoLogin_isSessionDirty_get(self) lasso_profile_is_session_dirty(LASSO_PROFILE(self))

/* msgBody */
#define LassoLogin_get_msgBody(self) LASSO_PROFILE(self)->msg_body
#define LassoLogin_msgBody_get(self) LASSO_PROFILE(self)->msg_body

/* msgRelayState */
#define LassoLogin_get_msgRelayState(self) LASSO_PROFILE(self)->msg_relayState
#define LassoLogin_msgRelayState_get(self) LASSO_PROFILE(self)->msg_relayState

/* msgUrl */
#define LassoLogin_get_msgUrl(self) LASSO_PROFILE(self)->msg_url
#define LassoLogin_msgUrl_get(self) LASSO_PROFILE(self)->msg_url

/* nameIdentifier */
#define LassoLogin_get_nameIdentifier(self) get_node(LASSO_PROFILE(self)->nameIdentifier)
#define LassoLogin_nameIdentifier_get(self) get_node(LASSO_PROFILE(self)->nameIdentifier)
#define LassoLogin_set_nameIdentifier(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->nameIdentifier, (value))
#define LassoLogin_nameIdentifier_set(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->nameIdentifier, (value))

/* remoteProviderId */
#define LassoLogin_get_remoteProviderId(self) LASSO_PROFILE(self)->remote_providerID
#define LassoLogin_remoteProviderId_get(self) LASSO_PROFILE(self)->remote_providerID
#define LassoLogin_set_remoteProviderId(self, value) set_string(&LASSO_PROFILE(self)->remote_providerID, (value))
#define LassoLogin_remoteProviderId_set(self, value) set_string(&LASSO_PROFILE(self)->remote_providerID, (value))

/* request */
#define LassoLogin_get_request LassoLogin_request_get
LassoSamlpRequest *LassoLogin_request_get(LassoLogin *self) {
	LassoProfile *profile = LASSO_PROFILE(self);
	if (LASSO_IS_SAMLP_REQUEST(profile->request))
		return LASSO_SAMLP_REQUEST(g_object_ref(profile->request));
	return NULL;
}

/* response */
#define LassoLogin_get_response LassoLogin_response_get
LassoSamlpResponse *LassoLogin_response_get(LassoLogin *self) {
	LassoProfile *profile = LASSO_PROFILE(self);
	if (LASSO_IS_SAMLP_RESPONSE(profile->response))
		return LASSO_SAMLP_RESPONSE(g_object_ref(profile->response));
	return NULL;
}

/* responseStatus */
#define LassoLogin_get_responseStatus(self) NULL /* FIXME: no set */
#define LassoLogin_responseStatus_get(self) NULL /* FIXME: no set */
#define LassoLogin_set_responseStatus(self, value) lasso_profile_set_response_status(LASSO_PROFILE(self), value)
#define LassoLogin_responseStatus_set(self, value) lasso_profile_set_response_status(LASSO_PROFILE(self), value)

/* session */
#define LassoLogin_get_session(self) lasso_profile_get_session(LASSO_PROFILE(self))
#define LassoLogin_session_get(self) lasso_profile_get_session(LASSO_PROFILE(self))
#define LassoLogin_set_session(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->session, (value))
#define LassoLogin_session_set(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->session, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoLogin lasso_login_new
#define delete_LassoLogin(self) lasso_node_destroy(LASSO_NODE(self))
#ifdef PHP_VERSION
#define LassoLogin_newFromDump lasso_login_new_from_dump
#else
#define Login_newFromDump lasso_login_new_from_dump
#endif

/* Methods inherited from Profile implementations */

int LassoLogin_setIdentityFromDump(LassoLogin *self, char *dump) {
	return lasso_profile_set_identity_from_dump(LASSO_PROFILE(self), dump);
}

int LassoLogin_setSessionFromDump(LassoLogin *self, char *dump) {
	return lasso_profile_set_session_from_dump(LASSO_PROFILE(self), dump);
}

/* Methods implementations */

#define LassoLogin_acceptSso lasso_login_accept_sso
#define LassoLogin_buildAssertion lasso_login_build_assertion
#define LassoLogin_buildArtifactMsg lasso_login_build_artifact_msg
#define LassoLogin_buildAuthnRequestMsg lasso_login_build_authn_request_msg
#define LassoLogin_buildAuthnResponseMsg lasso_login_build_authn_response_msg
#define LassoLogin_buildRequestMsg lasso_login_build_request_msg
#define LassoLogin_buildResponseMsg lasso_login_build_response_msg
#define LassoLogin_dump lasso_login_dump
#define LassoLogin_initAuthnRequest lasso_login_init_authn_request
#define LassoLogin_initRequest lasso_login_init_request
#define LassoLogin_initIdpInitiatedAuthnRequest lasso_login_init_idp_initiated_authn_request
#define LassoLogin_mustAskForConsent lasso_login_must_ask_for_consent
#define LassoLogin_mustAuthenticate lasso_login_must_authenticate
#define LassoLogin_processAuthnRequestMsg lasso_login_process_authn_request_msg
#define LassoLogin_processAuthnResponseMsg lasso_login_process_authn_response_msg
#define LassoLogin_processRequestMsg lasso_login_process_request_msg
#define LassoLogin_processResponseMsg lasso_login_process_response_msg
#define LassoLogin_validateRequestMsg lasso_login_validate_request_msg

%}


/***********************************************************************
 * lasso:Logout
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(Logout) LassoLogout;
#endif
typedef struct {
} LassoLogout;
%extend LassoLogout {
	/* Attributes inherited from Profile */

	%newobject identity_get;
	LassoIdentity *identity;

	%immutable isIdentityDirty;
	gboolean isIdentityDirty;

	%immutable isSessionDirty;
	gboolean isSessionDirty;

	%immutable msgBody;
	char *msgBody;

	%immutable msgRelayState;
	char *msgRelayState;

	%immutable msgUrl;
	char *msgUrl;

	%newobject nameIdentifier_get;
	LassoSamlNameIdentifier *nameIdentifier;

	char *remoteProviderId;

	%immutable request;
	LassoLibLogoutRequest *request;

	%immutable response;
	LassoLibLogoutResponse *response;

	char *responseStatus;

	%newobject session_get;
	LassoSession *session;

	/* Constructor, Destructor & Static Methods */

	LassoLogout(LassoServer *server);

	~LassoLogout();

	%newobject newFromDump;
	static LassoLogout *newFromDump(LassoServer *server, char *dump);

	/* Methods inherited from Profile */

        THROW_ERROR
	void setIdentityFromDump(char *dump);
	END_THROW_ERROR

	THROW_ERROR
	void setSessionFromDump(char *dump);
	END_THROW_ERROR

	/* Methods */

	THROW_ERROR
	void buildRequestMsg();
	END_THROW_ERROR

	THROW_ERROR
	void buildResponseMsg();
	END_THROW_ERROR

	%newobject dump;
	char *dump();

	%newobject getNextProviderId;
	char *getNextProviderId();

	THROW_ERROR
	void initRequest(char *remoteProviderId = NULL,
			 LassoHttpMethod httpMethod = LASSO_HTTP_METHOD_ANY);
	END_THROW_ERROR

	THROW_ERROR
	void processRequestMsg(char *requestMsg);
	END_THROW_ERROR

	THROW_ERROR
	void processResponseMsg(char *responseMsg);
	END_THROW_ERROR

	THROW_ERROR
	void resetProviderIdIndex();
	END_THROW_ERROR

	THROW_ERROR
	void validateRequest();
	END_THROW_ERROR
}

%{

/* Attributes inherited from Profile implementations */

/* identity */
#define LassoLogout_get_identity(self) lasso_profile_get_identity(LASSO_PROFILE(self))
#define LassoLogout_identity_get(self) lasso_profile_get_identity(LASSO_PROFILE(self))
#define LassoLogout_set_identity(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->identity, (value))
#define LassoLogout_identity_set(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->identity, (value))

/* isIdentityDirty */
#define LassoLogout_get_isIdentityDirty(self) lasso_profile_is_identity_dirty(LASSO_PROFILE(self))
#define LassoLogout_isIdentityDirty_get(self) lasso_profile_is_identity_dirty(LASSO_PROFILE(self))

/* isSessionDirty */
#define LassoLogout_get_isSessionDirty(self) lasso_profile_is_session_dirty(LASSO_PROFILE(self))
#define LassoLogout_isSessionDirty_get(self) lasso_profile_is_session_dirty(LASSO_PROFILE(self))

/* msgBody */
#define LassoLogout_get_msgBody(self) LASSO_PROFILE(self)->msg_body
#define LassoLogout_msgBody_get(self) LASSO_PROFILE(self)->msg_body

/* msgRelayState */
#define LassoLogout_get_msgRelayState(self) LASSO_PROFILE(self)->msg_relayState
#define LassoLogout_msgRelayState_get(self) LASSO_PROFILE(self)->msg_relayState

/* msgUrl */
#define LassoLogout_get_msgUrl(self) LASSO_PROFILE(self)->msg_url
#define LassoLogout_msgUrl_get(self) LASSO_PROFILE(self)->msg_url

/* nameIdentifier */
#define LassoLogout_get_nameIdentifier(self) get_node(LASSO_PROFILE(self)->nameIdentifier)
#define LassoLogout_nameIdentifier_get(self) get_node(LASSO_PROFILE(self)->nameIdentifier)
#define LassoLogout_set_nameIdentifier(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->nameIdentifier, (value))
#define LassoLogout_nameIdentifier_set(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->nameIdentifier, (value))

/* remoteProviderId */
#define LassoLogout_get_remoteProviderId(self) LASSO_PROFILE(self)->remote_providerID
#define LassoLogout_remoteProviderId_get(self) LASSO_PROFILE(self)->remote_providerID
#define LassoLogout_set_remoteProviderId(self, value) set_string(&LASSO_PROFILE(self)->remote_providerID, (value))
#define LassoLogout_remoteProviderId_set(self, value) set_string(&LASSO_PROFILE(self)->remote_providerID, (value))

/* request */
#define LassoLogout_get_request(self) LASSO_LIB_LOGOUT_REQUEST(LASSO_PROFILE(self)->request)
#define LassoLogout_request_get(self) LASSO_LIB_LOGOUT_REQUEST(LASSO_PROFILE(self)->request)

/* response */
#define LassoLogout_get_response(self) LASSO_LIB_LOGOUT_RESPONSE(LASSO_PROFILE(self)->response)
#define LassoLogout_response_get(self) LASSO_LIB_LOGOUT_RESPONSE(LASSO_PROFILE(self)->response)

/* responseStatus */
#define LassoLogout_get_responseStatus(self) NULL /* FIXME: no set */
#define LassoLogout_responseStatus_get(self) NULL /* FIXME: no set */
#define LassoLogout_set_responseStatus(self, value) lasso_profile_set_response_status(LASSO_PROFILE(self), value)
#define LassoLogout_responseStatus_set(self, value) lasso_profile_set_response_status(LASSO_PROFILE(self), value)

/* session */
#define LassoLogout_get_session(self) lasso_profile_get_session(LASSO_PROFILE(self))
#define LassoLogout_session_get(self) lasso_profile_get_session(LASSO_PROFILE(self))
#define LassoLogout_set_session(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->session, (value))
#define LassoLogout_session_set(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->session, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoLogout lasso_logout_new
#define delete_LassoLogout(self) lasso_node_destroy(LASSO_NODE(self))
#ifdef PHP_VERSION
#define LassoLogout_newFromDump lasso_logout_new_from_dump
#else
#define Logout_newFromDump lasso_logout_new_from_dump
#endif

/* Methods inherited from Profile implementations */

int LassoLogout_setIdentityFromDump(LassoLogout *self, char *dump) {
	return lasso_profile_set_identity_from_dump(LASSO_PROFILE(self), dump);
}

int LassoLogout_setSessionFromDump(LassoLogout *self, char *dump) {
	return lasso_profile_set_session_from_dump(LASSO_PROFILE(self), dump);
}

/* Methods implementations */

#define LassoLogout_buildRequestMsg lasso_logout_build_request_msg
#define LassoLogout_buildResponseMsg lasso_logout_build_response_msg
#define LassoLogout_dump lasso_logout_dump
#define LassoLogout_getNextProviderId lasso_logout_get_next_providerID
#define LassoLogout_initRequest lasso_logout_init_request
#define LassoLogout_processRequestMsg lasso_logout_process_request_msg
#define LassoLogout_processResponseMsg lasso_logout_process_response_msg
#define LassoLogout_resetProviderIdIndex lasso_logout_reset_providerID_index
#define LassoLogout_validateRequest lasso_logout_validate_request

%}


/***********************************************************************
 * lasso:LECP
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(Lecp) LassoLecp;
#endif
typedef struct {
	// FIXME: char *assertionConsumerServiceURL;
	// FIXME: LassoLibAuthnRequestEnvelope *authnRequestEnvelope;
	// FIXME: LassoLibAuthnResponseEnvelope *authnResponseEnvelope;
} LassoLecp;
%extend LassoLecp {
	/* Attributes inherited from Profile */

	%immutable authnRequest;
	LassoLibAuthnRequest *authnRequest;

	%immutable authnResponse;
	LassoLibAuthnResponse *authnResponse;

	%newobject identity_get;
	LassoIdentity *identity;

	%immutable isIdentityDirty;
	gboolean isIdentityDirty;

	%immutable isSessionDirty;
	gboolean isSessionDirty;

	%immutable msgBody;
	char *msgBody;

	%immutable msgRelayState;
	char *msgRelayState;

	%immutable msgUrl;
	char *msgUrl;

	%newobject nameIdentifier_get;
	LassoSamlNameIdentifier *nameIdentifier;

	char *remoteProviderId;

	%immutable request;
	LassoSamlpRequest *request;

	%immutable response;
	LassoSamlpResponse *response;

	char *responseStatus;

	%newobject session_get;
	LassoSession *session;

	/* Constructor, Destructor & Static Methods */

	LassoLecp(LassoServer *server);

	~LassoLecp();

	/* Methods inherited from Profile */

        THROW_ERROR
	void setIdentityFromDump(char *dump);
	END_THROW_ERROR

	THROW_ERROR
	void setSessionFromDump(char *dump);
	END_THROW_ERROR

	/* Methods inherited from Login */

	THROW_ERROR
	int buildAssertion(char *authenticationMethod, char *authenticationInstant,
			char *reauthenticateOnOrAfter,
			char *notBefore, char *notOnOrAfter);
	END_THROW_ERROR

	THROW_ERROR
	int validateRequestMsg(gboolean authenticationResult, gboolean isConsentObtained);
	END_THROW_ERROR

	/* Methods */

	THROW_ERROR
	void buildAuthnRequestEnvelopeMsg();
	END_THROW_ERROR

	THROW_ERROR
	void buildAuthnRequestMsg();
	END_THROW_ERROR

	THROW_ERROR
	void buildAuthnResponseEnvelopeMsg();
	END_THROW_ERROR

	THROW_ERROR
	void buildAuthnResponseMsg();
	END_THROW_ERROR

	THROW_ERROR
	void initAuthnRequest(char *remoteProviderId = NULL);
	END_THROW_ERROR

	THROW_ERROR
	void processAuthnRequestEnvelopeMsg(char *requestMsg);
	END_THROW_ERROR

	THROW_ERROR
	void processAuthnRequestMsg(char *authnRequestMsg);
	END_THROW_ERROR

	THROW_ERROR
	void processAuthnResponseEnvelopeMsg(char *responseMsg);
	END_THROW_ERROR
}

%{

/* Attributes inherited from Profile implementations */

/* authnRequest */
#define LassoLecp_get_authnRequest LassoLecp_authnRequest_get
LassoLibAuthnRequest *LassoLecp_authnRequest_get(LassoLecp *self) {
	LassoProfile *profile = LASSO_PROFILE(self);
	if (LASSO_IS_LIB_AUTHN_REQUEST(profile->request))
		return LASSO_LIB_AUTHN_REQUEST(g_object_ref(profile->request));
	return NULL;
}

/* authnResponse */
#define LassoLecp_get_authnResponse LassoLecp_authnResponse_get
LassoLibAuthnResponse *LassoLecp_authnResponse_get(LassoLecp *self) {
	LassoProfile *profile = LASSO_PROFILE(self);
	if (LASSO_IS_LIB_AUTHN_RESPONSE(profile->response))
		return LASSO_LIB_AUTHN_RESPONSE(g_object_ref(profile->response));
	return NULL;
}

/* identity */
#define LassoLecp_get_identity(self) lasso_profile_get_identity(LASSO_PROFILE(self))
#define LassoLecp_identity_get(self) lasso_profile_get_identity(LASSO_PROFILE(self))
#define LassoLecp_set_identity(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->identity, (value))
#define LassoLecp_identity_set(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->identity, (value))

/* isIdentityDirty */
#define LassoLecp_get_isIdentityDirty(self) lasso_profile_is_identity_dirty(LASSO_PROFILE(self))
#define LassoLecp_isIdentityDirty_get(self) lasso_profile_is_identity_dirty(LASSO_PROFILE(self))

/* isSessionDirty */
#define LassoLecp_get_isSessionDirty(self) lasso_profile_is_session_dirty(LASSO_PROFILE(self))
#define LassoLecp_isSessionDirty_get(self) lasso_profile_is_session_dirty(LASSO_PROFILE(self))

/* msgBody */
#define LassoLecp_get_msgBody(self) LASSO_PROFILE(self)->msg_body
#define LassoLecp_msgBody_get(self) LASSO_PROFILE(self)->msg_body

/* msgRelayState */
#define LassoLecp_get_msgRelayState(self) LASSO_PROFILE(self)->msg_relayState
#define LassoLecp_msgRelayState_get(self) LASSO_PROFILE(self)->msg_relayState

/* msgUrl */
#define LassoLecp_get_msgUrl(self) LASSO_PROFILE(self)->msg_url
#define LassoLecp_msgUrl_get(self) LASSO_PROFILE(self)->msg_url

/* nameIdentifier */
#define LassoLecp_get_nameIdentifier(self) get_node(LASSO_PROFILE(self)->nameIdentifier)
#define LassoLecp_nameIdentifier_get(self) get_node(LASSO_PROFILE(self)->nameIdentifier)
#define LassoLecp_set_nameIdentifier(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->nameIdentifier, (value))
#define LassoLecp_nameIdentifier_set(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->nameIdentifier, (value))

/* remoteProviderId */
#define LassoLecp_get_remoteProviderId(self) LASSO_PROFILE(self)->remote_providerID
#define LassoLecp_remoteProviderId_get(self) LASSO_PROFILE(self)->remote_providerID
#define LassoLecp_set_remoteProviderId(self, value) set_string(&LASSO_PROFILE(self)->remote_providerID, (value))
#define LassoLecp_remoteProviderId_set(self, value) set_string(&LASSO_PROFILE(self)->remote_providerID, (value))

/* request */
#define LassoLecp_get_request LassoLecp_request_get
LassoSamlpRequest *LassoLecp_request_get(LassoLecp *self) {
	LassoProfile *profile = LASSO_PROFILE(self);
	if (LASSO_IS_SAMLP_REQUEST(profile->request))
		return LASSO_SAMLP_REQUEST(g_object_ref(profile->request));
	return NULL;
}

/* response */
#define LassoLecp_get_response LassoLecp_response_get
LassoSamlpResponse *LassoLecp_response_get(LassoLecp *self) {
	LassoProfile *profile = LASSO_PROFILE(self);
	if (LASSO_IS_SAMLP_RESPONSE(profile->response))
		return LASSO_SAMLP_RESPONSE(g_object_ref(profile->response));
	return NULL;
}

/* responseStatus */
#define LassoLecp_get_responseStatus(self) NULL /* FIXME: no set */
#define LassoLecp_responseStatus_get(self) NULL /* FIXME: no set */
#define LassoLecp_set_responseStatus(self, value) lasso_profile_set_response_status(LASSO_PROFILE(self), value)
#define LassoLecp_responseStatus_set(self, value) lasso_profile_set_response_status(LASSO_PROFILE(self), value)

/* session */
#define LassoLecp_get_session(self) lasso_profile_get_session(LASSO_PROFILE(self))
#define LassoLecp_session_get(self) lasso_profile_get_session(LASSO_PROFILE(self))
#define LassoLecp_set_session(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->session, (value))
#define LassoLecp_session_set(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->session, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoLecp lasso_lecp_new
#define delete_LassoLecp(self) lasso_node_destroy(LASSO_NODE(self))

/* Methods inherited from Profile implementations */

int LassoLecp_setIdentityFromDump(LassoLecp *self, char *dump) {
	return lasso_profile_set_identity_from_dump(LASSO_PROFILE(self), dump);
}

int LassoLecp_setSessionFromDump(LassoLecp *self, char *dump) {
	return lasso_profile_set_session_from_dump(LASSO_PROFILE(self), dump);
}

/* Methods inherited from Login implementations */

int LassoLecp_buildAssertion(LassoLecp *self, char *authenticationMethod,
		char *authenticationInstant, char *reauthenticateOnOrAfter, char *notBefore,
		char *notOnOrAfter) {
	return lasso_login_build_assertion(LASSO_LOGIN(self), authenticationMethod,
			authenticationInstant, reauthenticateOnOrAfter, notBefore, notOnOrAfter);
}

int LassoLecp_validateRequestMsg(LassoLecp *self, gboolean authenticationResult,
		gboolean isConsentObtained) {
	return lasso_login_validate_request_msg(LASSO_LOGIN(self), authenticationResult,
			isConsentObtained);
}

/* Methods implementations */

#define LassoLecp_buildAuthnRequestEnvelopeMsg lasso_lecp_build_authn_request_envelope_msg
#define LassoLecp_buildAuthnRequestMsg lasso_lecp_build_authn_request_msg
#define LassoLecp_buildAuthnResponseEnvelopeMsg lasso_lecp_build_authn_response_envelope_msg
#define LassoLecp_buildAuthnResponseMsg lasso_lecp_build_authn_response_msg
#define LassoLecp_initAuthnRequest lasso_lecp_init_authn_request
#define LassoLecp_processAuthnRequestEnvelopeMsg lasso_lecp_process_authn_request_envelope_msg
#define LassoLecp_processAuthnRequestMsg lasso_lecp_process_authn_request_msg
#define LassoLecp_processAuthnResponseEnvelopeMsg lasso_lecp_process_authn_response_envelope_msg

%}

/***********************************************************************
 * lasso:NameIdentifierMapping
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(NameIdentifierMapping) LassoNameIdentifierMapping;
#endif
typedef struct {
	%immutable targetNameIdentifier;
	char *targetNameIdentifier;
} LassoNameIdentifierMapping;
%extend LassoNameIdentifierMapping {
	/* Attributes inherited from Profile */

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

	%newobject nameIdentifier_get;
	LassoSamlNameIdentifier *nameIdentifier;

	char *remoteProviderId;

	%newobject session_get;
	LassoSession *session;

	/* Constructor, Destructor & Static Methods */

	LassoNameIdentifierMapping(LassoServer *server);

	~LassoNameIdentifierMapping();

	/* Methods inherited from Profile */

        THROW_ERROR
	void setIdentityFromDump(char *dump);
	END_THROW_ERROR

	THROW_ERROR
	void setSessionFromDump(char *dump);
	END_THROW_ERROR

	/* Methods */

	THROW_ERROR
	void buildRequestMsg();
	END_THROW_ERROR

	THROW_ERROR
	void buildResponseMsg();
	END_THROW_ERROR

	%newobject dump;
	char *dump();

	THROW_ERROR
	void initRequest(char *targetNamespace, char *remoteProviderId = NULL);
	END_THROW_ERROR

	THROW_ERROR
	void processRequestMsg(char *requestMsg);
	END_THROW_ERROR

	THROW_ERROR
	void processResponseMsg(char *responseMsg);
	END_THROW_ERROR

	THROW_ERROR
	void validateRequest();
	END_THROW_ERROR
}

%{

/* Attributes inherited from Profile implementations */

/* identity */
#define LassoNameIdentifierMapping_get_identity(self) lasso_profile_get_identity(LASSO_PROFILE(self))
#define LassoNameIdentifierMapping_identity_get(self) lasso_profile_get_identity(LASSO_PROFILE(self))
#define LassoNameIdentifierMapping_set_identity(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->identity, (value))
#define LassoNameIdentifierMapping_identity_set(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->identity, (value))

/* isIdentityDirty */
#define LassoNameIdentifierMapping_get_isIdentityDirty(self) lasso_profile_is_identity_dirty(LASSO_PROFILE(self))
#define LassoNameIdentifierMapping_isIdentityDirty_get(self) lasso_profile_is_identity_dirty(LASSO_PROFILE(self))

/* isSessionDirty */
#define LassoNameIdentifierMapping_get_isSessionDirty(self) lasso_profile_is_session_dirty(LASSO_PROFILE(self))
#define LassoNameIdentifierMapping_isSessionDirty_get(self) lasso_profile_is_session_dirty(LASSO_PROFILE(self))

/* msgBody */
#define LassoNameIdentifierMapping_get_msgBody(self) LASSO_PROFILE(self)->msg_body
#define LassoNameIdentifierMapping_msgBody_get(self) LASSO_PROFILE(self)->msg_body

/* msgRelayState */
#define LassoNameIdentifierMapping_get_msgRelayState(self) LASSO_PROFILE(self)->msg_relayState
#define LassoNameIdentifierMapping_msgRelayState_get(self) LASSO_PROFILE(self)->msg_relayState

/* msgUrl */
#define LassoNameIdentifierMapping_get_msgUrl(self) LASSO_PROFILE(self)->msg_url
#define LassoNameIdentifierMapping_msgUrl_get(self) LASSO_PROFILE(self)->msg_url

/* nameIdentifier */
#define LassoNameIdentifierMapping_get_nameIdentifier(self) get_node(LASSO_PROFILE(self)->nameIdentifier)
#define LassoNameIdentifierMapping_nameIdentifier_get(self) get_node(LASSO_PROFILE(self)->nameIdentifier)
#define LassoNameIdentifierMapping_set_nameIdentifier(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->nameIdentifier, (value))
#define LassoNameIdentifierMapping_nameIdentifier_set(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->nameIdentifier, (value))

/* remoteProviderId */
#define LassoNameIdentifierMapping_get_remoteProviderId(self) LASSO_PROFILE(self)->remote_providerID
#define LassoNameIdentifierMapping_remoteProviderId_get(self) LASSO_PROFILE(self)->remote_providerID
#define LassoNameIdentifierMapping_set_remoteProviderId(self, value) set_string(&LASSO_PROFILE(self)->remote_providerID, (value))
#define LassoNameIdentifierMapping_remoteProviderId_set(self, value) set_string(&LASSO_PROFILE(self)->remote_providerID, (value))

/* session */
#define LassoNameIdentifierMapping_get_session LassoNameIdentifierMapping_session_get
LassoSession *LassoNameIdentifierMapping_session_get(LassoNameIdentifierMapping *self) {
	return lasso_profile_get_session(LASSO_PROFILE(self));
}
#define LassoNameIdentifierMapping_set_session(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->session, (value))
#define LassoNameIdentifierMapping_session_set(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->session, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoNameIdentifierMapping lasso_name_identifier_mapping_new
#define delete_LassoNameIdentifierMapping(self) lasso_node_destroy(LASSO_NODE(self))

/* Methods inherited from Profile implementations */

int LassoNameIdentifierMapping_setIdentityFromDump(LassoNameIdentifierMapping *self, char *dump) {
	return lasso_profile_set_identity_from_dump(LASSO_PROFILE(self), dump);
}

int LassoNameIdentifierMapping_setSessionFromDump(LassoNameIdentifierMapping *self, char *dump) {
	return lasso_profile_set_session_from_dump(LASSO_PROFILE(self), dump);
}

/* Methods implementations */

#define LassoNameIdentifierMapping_buildRequestMsg lasso_name_identifier_mapping_build_request_msg
#define LassoNameIdentifierMapping_buildResponseMsg lasso_name_identifier_mapping_build_response_msg
#define LassoNameIdentifierMapping_dump lasso_name_identifier_mapping_dump
#define LassoNameIdentifierMapping_initRequest lasso_name_identifier_mapping_init_request
#define LassoNameIdentifierMapping_processRequestMsg lasso_name_identifier_mapping_process_request_msg
#define LassoNameIdentifierMapping_processResponseMsg lasso_name_identifier_mapping_process_response_msg
#define LassoNameIdentifierMapping_validateRequest lasso_name_identifier_mapping_validate_request

%}


/***********************************************************************
 * lasso:NameRegistration
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(NameRegistration) LassoNameRegistration;
#endif
typedef struct {
} LassoNameRegistration;
%extend LassoNameRegistration {
	/* Attributes inherited from Profile */

	%newobject identity_get;
	LassoIdentity *identity;

	%immutable isIdentityDirty;
	gboolean isIdentityDirty;

	%immutable isSessionDirty;
	gboolean isSessionDirty;

	%immutable msgBody;
	char *msgBody;

	%immutable msgRelayState;
	char *msgRelayState;

	%immutable msgUrl;
	char *msgUrl;

	%newobject nameIdentifier_get;
	LassoSamlNameIdentifier *nameIdentifier;

	char *remoteProviderId;

	%immutable request;
	LassoLibRegisterNameIdentifierRequest *request;

	%immutable response;
	LassoLibRegisterNameIdentifierResponse *response;

	%newobject session_get;
	LassoSession *session;

	/* Attributes */

	%newobject oldNameIdentifier_get;
	LassoSamlNameIdentifier *oldNameIdentifier;

	/* Constructor, Destructor & Static Methods */

	LassoNameRegistration(LassoServer *server);

	~LassoNameRegistration();

	%newobject newFromDump;
	static LassoNameRegistration *newFromDump(LassoServer *server, char *dump);

	/* Methods inherited from Profile */

        THROW_ERROR
	void setIdentityFromDump(char *dump);
	END_THROW_ERROR

	THROW_ERROR
	void setSessionFromDump(char *dump);
	END_THROW_ERROR

	/* Methods */

	THROW_ERROR
	void buildRequestMsg();
	END_THROW_ERROR

	THROW_ERROR
	void buildResponseMsg();
	END_THROW_ERROR

	%newobject dump;
	char *dump();

	THROW_ERROR
	void initRequest(char *remoteProviderId,
			LassoHttpMethod httpMethod = LASSO_HTTP_METHOD_ANY);
	END_THROW_ERROR

	THROW_ERROR
	void processRequestMsg(char *requestMsg);
	END_THROW_ERROR

	THROW_ERROR
	void processResponseMsg(char *responseMsg);
	END_THROW_ERROR

	THROW_ERROR
	void validateRequest();
	END_THROW_ERROR
}

%{

/* Attributes inherited from Profile implementations */

/* identity */
#define LassoNameRegistration_get_identity(self) lasso_profile_get_identity(LASSO_PROFILE(self))
#define LassoNameRegistration_identity_get(self) lasso_profile_get_identity(LASSO_PROFILE(self))
#define LassoNameRegistration_set_identity(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->identity, (value))
#define LassoNameRegistration_identity_set(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->identity, (value))

/* isIdentityDirty */
#define LassoNameRegistration_get_isIdentityDirty(self) lasso_profile_is_identity_dirty(LASSO_PROFILE(self))
#define LassoNameRegistration_isIdentityDirty_get(self) lasso_profile_is_identity_dirty(LASSO_PROFILE(self))

/* isSessionDirty */
#define LassoNameRegistration_get_isSessionDirty(self) lasso_profile_is_session_dirty(LASSO_PROFILE(self))
#define LassoNameRegistration_isSessionDirty_get(self) lasso_profile_is_session_dirty(LASSO_PROFILE(self))

/* msgBody */
#define LassoNameRegistration_get_msgBody(self) LASSO_PROFILE(self)->msg_body
#define LassoNameRegistration_msgBody_get(self) LASSO_PROFILE(self)->msg_body

/* msgRelayState */
#define LassoNameRegistration_get_msgRelayState(self) LASSO_PROFILE(self)->msg_relayState
#define LassoNameRegistration_msgRelayState_get(self) LASSO_PROFILE(self)->msg_relayState

/* msgUrl */
#define LassoNameRegistration_get_msgUrl(self) LASSO_PROFILE(self)->msg_url
#define LassoNameRegistration_msgUrl_get(self) LASSO_PROFILE(self)->msg_url

/* nameIdentifier */
#define LassoNameRegistration_get_nameIdentifier(self) get_node(LASSO_PROFILE(self)->nameIdentifier)
#define LassoNameRegistration_nameIdentifier_get(self) get_node(LASSO_PROFILE(self)->nameIdentifier)
#define LassoNameRegistration_set_nameIdentifier(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->nameIdentifier, (value))
#define LassoNameRegistration_nameIdentifier_set(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->nameIdentifier, (value))

/* remoteProviderId */
#define LassoNameRegistration_get_remoteProviderId(self) LASSO_PROFILE(self)->remote_providerID
#define LassoNameRegistration_remoteProviderId_get(self) LASSO_PROFILE(self)->remote_providerID
#define LassoNameRegistration_set_remoteProviderId(self, value) set_string(&LASSO_PROFILE(self)->remote_providerID, (value))
#define LassoNameRegistration_remoteProviderId_set(self, value) set_string(&LASSO_PROFILE(self)->remote_providerID, (value))

/* request */
#define LassoNameRegistration_get_request(self) LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(LASSO_PROFILE(self)->request)
#define LassoNameRegistration_request_get(self) LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(LASSO_PROFILE(self)->request)

/* response */
#define LassoNameRegistration_get_response(self) LASSO_LIB_REGISTER_NAME_IDENTIFIER_RESPONSE(LASSO_PROFILE(self)->response)
#define LassoNameRegistration_response_get(self) LASSO_LIB_REGISTER_NAME_IDENTIFIER_RESPONSE(LASSO_PROFILE(self)->response)

/* session */
#define LassoNameRegistration_get_session(self) lasso_profile_get_session(LASSO_PROFILE(self))
#define LassoNameRegistration_session_get(self) lasso_profile_get_session(LASSO_PROFILE(self))
#define LassoNameRegistration_set_session(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->session, (value))
#define LassoNameRegistration_session_set(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->session, (value))

/* Attributes implementations */

/* oldNameIdentifier */
#define LassoNameRegistration_get_oldNameIdentifier(self) get_node((self)->oldNameIdentifier)
#define LassoNameRegistration_oldNameIdentifier_get(self) get_node((self)->oldNameIdentifier)
#define LassoNameRegistration_set_oldNameIdentifier(self, value) set_node((gpointer *) &(self)->oldNameIdentifier, (value))
#define LassoNameRegistration_oldNameIdentifier_set(self, value) set_node((gpointer *) &(self)->oldNameIdentifier, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoNameRegistration lasso_name_registration_new
#define delete_LassoNameRegistration(self) lasso_node_destroy(LASSO_NODE(self))
#ifdef PHP_VERSION
#define LassoNameRegistration_newFromDump lasso_name_registration_new_from_dump
#else
#define NameRegistration_newFromDump lasso_name_registration_new_from_dump
#endif

/* Methods inherited from Profile implementations */

int LassoNameRegistration_setIdentityFromDump(LassoNameRegistration *self, char *dump) {
	return lasso_profile_set_identity_from_dump(LASSO_PROFILE(self), dump);
}

int LassoNameRegistration_setSessionFromDump(LassoNameRegistration *self, char *dump) {
	return lasso_profile_set_session_from_dump(LASSO_PROFILE(self), dump);
}

/* Methods implementations */

#define LassoNameRegistration_buildRequestMsg lasso_name_registration_build_request_msg
#define LassoNameRegistration_buildResponseMsg lasso_name_registration_build_response_msg
#define LassoNameRegistration_dump lasso_name_registration_dump
#define LassoNameRegistration_initRequest lasso_name_registration_init_request
#define LassoNameRegistration_processRequestMsg lasso_name_registration_process_request_msg
#define LassoNameRegistration_processResponseMsg lasso_name_registration_process_response_msg
#define LassoNameRegistration_validateRequest lasso_name_registration_validate_request

%}

%include Lasso-wsf.i

