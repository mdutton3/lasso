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
    } catch (UnsatisfiedLinkError e) {
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

/* Utilities */

%{

void add_key_to_array(char *key, gpointer pointer, GPtrArray *array)
{
        g_ptr_array_add(array, g_strdup(key));
}

void free_xml_list_element(xmlNode *xmlnode, gpointer unused)
{
	xmlFreeNode(xmlnode);
}

gpointer get_object(gpointer value)
{
	return value == NULL ? NULL : g_object_ref(value);
}

void set_object(gpointer *pointer, gpointer value)
{
	if (*pointer != NULL)
		if (LASSO_IS_NODE(*pointer))
			lasso_node_destroy(LASSO_NODE(*pointer));
		else
			g_object_unref(*pointer);
	*pointer = value == NULL ? NULL : g_object_ref(value);
}

void set_string(char **pointer, char *value)
{
	if (*pointer != NULL)
		free(*pointer);
	*pointer = value == NULL ? NULL : strdup(value);
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

void lasso_exception(int errorCode) {
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

void build_exception_msg(int errorCode, char *errorMsg) {
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
		%newobject getitem;
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
			char **itemPtr = (char **) &g_ptr_array_index(self, index);
			if (*itemPtr != NULL)
				free(*itemPtr);
			if (item == NULL)
				*itemPtr = NULL;
			else
				*itemPtr = g_strdup(item);
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
	%rename(issuer) Issuer;
#endif
	char *Issuer;

#ifndef SWIGPHP4
	%rename(issueInstant) IssueInstant;
#endif
	char *IssueInstant;

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
	%rename(signType) sign_type;
#endif
	LassoSignatureType sign_type;

#ifndef SWIGPHP4
	%rename(signMethod) sign_method;
#endif
	LassoSignatureMethod sign_method;
} LassoSamlAssertion;
%extend LassoSamlAssertion {
	/* Attributes */

	// FIXME: LassoSamlConditions *Conditions;
	// FIXME: LassoSamlAdvice *Advice;
	// FIXME: LassoSamlStatement *Statement;
	// FIXME: LassoSamlSubjectStatement *SubjectStatement;
	// FIXME: LassoSamlAuthenticationStatement *AuthenticationStatement;
	// FIXME: LassoSamlAuthorizationDecisionsStatement *AuthorizationDecisionStatement;
	// FIXME: LassoSamlAttributeStatement *AttributeStatement;

	/* Constructor, Destructor & Static Methods */

	LassoSamlAssertion();

	~LassoSamlAssertion();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Constructors, destructors & static methods implementations */

#define new_LassoSamlAssertion lasso_saml_assertion_new
#define delete_LassoSamlAssertion(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSamlAssertion_dump(self) lasso_node_dump(LASSO_NODE(self))

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

	// FIXME: LassoSamlAssertion *Assertion;

#ifndef SWIGPHP4
	%rename(status) Status;
#endif
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
#define LassoSamlpResponse_get_Status(self) get_object((self)->Status)
#define LassoSamlpResponse_Status_get(self) get_object((self)->Status)
#define LassoSamlpResponse_set_Status(self, value) set_object((gpointer *) &(self)->Status, (value))
#define LassoSamlpResponse_Status_set(self, value) set_object((gpointer *) &(self)->Status, (value))

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
#define LassoSamlpStatus_get_StatusCode(self) get_object((self)->StatusCode)
#define LassoSamlpStatus_StatusCode_get(self) get_object((self)->StatusCode)
#define LassoSamlpStatus_set_StatusCode(self, value) set_object((gpointer *) &(self)->StatusCode, (value))
#define LassoSamlpStatus_StatusCode_set(self, value) set_object((gpointer *) &(self)->StatusCode, (value))

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
#define LassoSamlpStatusCode_get_StatusCode(self) get_object((self)->StatusCode)
#define LassoSamlpStatusCode_StatusCode_get(self) get_object((self)->StatusCode)
#define LassoSamlpStatusCode_set_StatusCode(self, value) set_object((gpointer *) &(self)->StatusCode, (value))
#define LassoSamlpStatusCode_StatusCode_set(self, value) set_object((gpointer *) &(self)->StatusCode, (value))

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

/* 	char *AssertionID; */
/* 	char *Issuer; */
/* 	char *IssueInstant; */
/* 	int MajorVersion; */
/* 	int MinorVersion; */

/* 	// FIXME: LassoSamlConditions *Conditions; */
/* 	// FIXME: LassoSamlAdvice *Advice; */
/* 	// FIXME: LassoSamlStatement *Statement; */
/* 	// FIXME: LassoSamlSubjectStatement *SubjectStatement; */
/* 	// FIXME: LassoSamlAuthenticationStatement *AuthenticationStatement; */
/* 	// FIXME: LassoSamlAuthorizationDecisionsStatement *AuthorizationDecisionStatement; */
/* 	// FIXME: LassoSamlAttributeStatement *AttributeStatement; */

/* 	char *certificate_file; */
/* 	char *private_key_file; */
/* 	LassoSignatureType sign_type; */
/* 	LassoSignatureMethod sign_method; */

	/* Constructor, Destructor & Static Methods */

	LassoLibAssertion(char *issuer, char *requestId, char *audience,
			  char *notBefore, char *notOnOrAfter);

	~LassoLibAssertion();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Implementations of methods inherited from SamlAssertion */

/* /\* AssertionID *\/ */
/* #define LassoLibAssertion_get_AssertionID(self) get_object((self)->AssertionID) */
/* #define LassoLibAssertion_AssertionID_get(self) get_object((self)->AssertionID) */
/* #define LassoLibAssertion_set_AssertionID(self, value) set_object((gpointer *) &(self)->AssertionID, (value)) */
/* #define LassoLibAssertion_AssertionID_set(self, value) set_object((gpointer *) &(self)->AssertionID, (value)) */

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

#ifndef SWIGPHP4
	%rename(extension) Extension;
#endif
	LassoStringArray *Extension;

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
#define LassoLibAuthnRequest_get_Extension LassoLibAuthnRequest_Extension_get
LassoStringArray *LassoLibAuthnRequest_Extension_get(LassoLibAuthnRequest *self) {
	return NULL; /* FIXME */
}
#define LassoLibAuthnRequest_set_Extension LassoLibAuthnRequest_Extension_set
void LassoLibAuthnRequest_Extension_set(LassoLibAuthnRequest *self, LassoStringArray *Extension) {
	if (self->Extension != NULL) {
		g_list_foreach(self->Extension, (GFunc) free_xml_list_element, NULL);
		g_list_free(self->Extension);
	}
	if (Extension == NULL)
		self->Extension = NULL;
	else {
		int index;
		for (index = 0; index < Extension->len; index ++) {
			xmlDoc *doc;
			xmlNode *node;
			doc = xmlReadDoc(g_ptr_array_index(Extension, index), NULL, NULL,
					XML_PARSE_NONET);
			if (doc == NULL)
				continue;
			node = xmlDocGetRootElement(doc);
			if (node != NULL) {
				xmlNode *extensionNode;
				xmlNs *libertyNamespace;
				extensionNode = xmlNewNode(NULL, "Extension");
				libertyNamespace = xmlNewNs(extensionNode, LASSO_LIB_HREF,
						LASSO_LIB_PREFIX);
				xmlSetNs(extensionNode, libertyNamespace);
				xmlAddChild(extensionNode, xmlCopyNode(node, 1));
				self->Extension = g_list_append(self->Extension, extensionNode);
						
			}
			xmlFreeDoc(doc);
		}
	}
}

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
	/* Attributes inherited from LassoSamlpResponse */

	// FIXME: LassoSamlAssertion *Assertion;

#ifndef SWIGPHP4
	%rename(extension) Extension;
#endif
	// FIXME: GList *Extension;

#ifndef SWIGPHP4
	%rename(status) Status;
#endif
	LassoSamlpStatus *Status;

	/* Constructor, Destructor & Static Methods */

	LassoLibAuthnResponse(char *providerID, LassoLibAuthnRequest *request);

	~LassoLibAuthnResponse();

	/* Methods inherited from LassoNode */

	%newobject dump;
	char *dump();
}

%{

/* Attributes inherited from LassoSamlpResponse implementations */

/* Status */
#define LassoLibAuthnResponse_get_Status(self) get_object(LASSO_SAMLP_RESPONSE(self)->Status)
#define LassoLibAuthnResponse_Status_get(self) get_object(LASSO_SAMLP_RESPONSE(self)->Status)
#define LassoLibAuthnResponse_set_Status(self, value) set_object((gpointer *) &LASSO_SAMLP_RESPONSE(self)->Status, (value))
#define LassoLibAuthnResponse_Status_set(self, value) set_object((gpointer *) &LASSO_SAMLP_RESPONSE(self)->Status, (value))

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

#ifndef SWIGPHP4
	%rename(extension) Extension;
#endif
	// FIXME: GList *Extension;

#ifndef SWIGPHP4
	%rename(nameIdentifier) NameIdentifier;
#endif
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

/* NameIdentifier */
#define LassoLibFederationTerminationNotification_get_NameIdentifier(self) get_object((self)->NameIdentifier)
#define LassoLibFederationTerminationNotification_NameIdentifier_get(self) get_object((self)->NameIdentifier)
#define LassoLibFederationTerminationNotification_set_NameIdentifier(self, value) set_object((gpointer *) &(self)->NameIdentifier, (value))
#define LassoLibFederationTerminationNotification_NameIdentifier_set(self, value) set_object((gpointer *) &(self)->NameIdentifier, (value))

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

#ifndef SWIGPHP4
	%rename(extension) Extension;
#endif
	// FIXME: GList *Extension;

#ifndef SWIGPHP4
	%rename(nameIdentifier) NameIdentifier;
#endif
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

/* nameIdentifier */
#define LassoLibLogoutRequest_get_NameIdentifier(self) get_object((self)->NameIdentifier)
#define LassoLibLogoutRequest_NameIdentifier_get(self) get_object((self)->NameIdentifier)
#define LassoLibLogoutRequest_set_NameIdentifier(self, value) set_object((gpointer *) &(self)->NameIdentifier, (value))
#define LassoLibLogoutRequest_NameIdentifier_set(self, value) set_object((gpointer *) &(self)->NameIdentifier, (value))

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
	/* Attributes inherited from LassoLibStatusResponse */

#ifndef SWIGPHP4
	%rename(extension) Extension;
#endif
	// FIXME: GList *Extension;

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

/* Implementations of attributes inherited from LassoLibStatusResponse */

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
#define LassoLibLogoutResponse_get_Status(self) get_object(LASSO_LIB_STATUS_RESPONSE(self)->Status)
#define LassoLibLogoutResponse_Status_get(self) get_object(LASSO_LIB_STATUS_RESPONSE(self)->Status)
#define LassoLibLogoutResponse_set_Status(self, value) set_object((gpointer *) &LASSO_LIB_STATUS_RESPONSE(self)->Status, (value))
#define LassoLibLogoutResponse_Status_set(self, value) set_object((gpointer *) &LASSO_LIB_STATUS_RESPONSE(self)->Status, (value))

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

#ifndef SWIGPHP4
	%rename(extension) Extension;
#endif
	// FIXME: GList *Extension;

#ifndef SWIGPHP4
	%rename(idpProvidedNameIdentifier) IDPProvidedNameIdentifier;
#endif
	LassoSamlNameIdentifier *IDPProvidedNameIdentifier;

#ifndef SWIGPHP4
	%rename(oldProvidedNameIdentifier) OldProvidedNameIdentifier;
#endif
	LassoSamlNameIdentifier *OldProvidedNameIdentifier;

#ifndef SWIGPHP4
	%rename(spProvidedNameIdentifier) SPProvidedNameIdentifier;
#endif
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

/* idpProvidedNameIdentifier */
#define LassoLibRegisterNameIdentifierRequest_get_IDPProvidedNameIdentifier(self) get_object((self)->IDPProvidedNameIdentifier)
#define LassoLibRegisterNameIdentifierRequest_IDPProvidedNameIdentifier_get(self) get_object((self)->IDPProvidedNameIdentifier)
#define LassoLibRegisterNameIdentifierRequest_set_IDPProvidedNameIdentifier(self, value) set_object((gpointer *) &(self)->IDPProvidedNameIdentifier, (value))
#define LassoLibRegisterNameIdentifierRequest_IDPProvidedNameIdentifier_set(self, value) set_object((gpointer *) &(self)->IDPProvidedNameIdentifier, (value))

/* oldProvidedNameIdentifier */
#define LassoLibRegisterNameIdentifierRequest_get_OldProvidedNameIdentifier(self) get_object((self)->OldProvidedNameIdentifier)
#define LassoLibRegisterNameIdentifierRequest_OldProvidedNameIdentifier_get(self) get_object((self)->OldProvidedNameIdentifier)
#define LassoLibRegisterNameIdentifierRequest_set_OldProvidedNameIdentifier(self, value) set_object((gpointer *) &(self)->OldProvidedNameIdentifier, (value))
#define LassoLibRegisterNameIdentifierRequest_OldProvidedNameIdentifier_set(self, value) set_object((gpointer *) &(self)->OldProvidedNameIdentifier, (value))

/* spProvidedNameIdentifier */
#define LassoLibRegisterNameIdentifierRequest_get_SPProvidedNameIdentifier(self) get_object((self)->SPProvidedNameIdentifier)
#define LassoLibRegisterNameIdentifierRequest_SPProvidedNameIdentifier_get(self) get_object((self)->SPProvidedNameIdentifier)
#define LassoLibRegisterNameIdentifierRequest_set_SPProvidedNameIdentifier(self, value) set_object((gpointer *) &(self)->SPProvidedNameIdentifier, (value))
#define LassoLibRegisterNameIdentifierRequest_SPProvidedNameIdentifier_set(self, value) set_object((gpointer *) &(self)->SPProvidedNameIdentifier, (value))

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
	/* Attributes inherited from LassoLibStatusResponse */

#ifndef SWIGPHP4
	%rename(extension) Extension;
#endif
	// FIXME: GList *Extension;

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

/* Attributes inherited from LassoLibStatusResponse implementations */

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
#define LassoLibRegisterNameIdentifierResponse_get_Status(self) get_object(LASSO_LIB_STATUS_RESPONSE(self)->Status)
#define LassoLibRegisterNameIdentifierResponse_Status_get(self) get_object(LASSO_LIB_STATUS_RESPONSE(self)->Status)
#define LassoLibRegisterNameIdentifierResponse_set_Status(self, value) set_object((gpointer *) &LASSO_LIB_STATUS_RESPONSE(self)->Status, (value))
#define LassoLibRegisterNameIdentifierResponse_Status_set(self, value) set_object((gpointer *) &LASSO_LIB_STATUS_RESPONSE(self)->Status, (value))

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

#ifndef SWIGPHP4
	%rename(extension) Extension;
#endif
	// FIXME: GList *Extension;

#ifndef SWIGPHP4
	%rename(status) Status;
#endif
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

/* Status */
#define LassoLibStatusResponse_get_Status(self) get_object((self)->Status)
#define LassoLibStatusResponse_Status_get(self) get_object((self)->Status)
#define LassoLibStatusResponse_set_Status(self, value) set_object((gpointer *) &(self)->Status, (value))
#define LassoLibStatusResponse_Status_set(self, value) set_object((gpointer *) &(self)->Status, (value))

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
	/* Attributes inherited from LassoProvider */

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

	/* Methods inherited from LassoProvider */

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

/* Implementations of attributes inherited from LassoProvider */

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

/* Implementations of methods inherited from LassoProvider */

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
	LassoSamlNameIdentifier *local_nameIdentifier;

#ifndef SWIGPHP4
	%rename(remoteNameIdentifier) remote_nameIdentifier;
#endif
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
#define LassoFederation_get_local_nameIdentifier(self) get_object((self)->local_nameIdentifier)
#define LassoFederation_local_nameIdentifier_get(self) get_object((self)->local_nameIdentifier)
#define LassoFederation_set_local_nameIdentifier(self, value) set_object((gpointer *) &(self)->local_nameIdentifier, (value))
#define LassoFederation_local_nameIdentifier_set(self, value) set_object((gpointer *) &(self)->local_nameIdentifier, (value))

/* remoteNameIdentifier */
#define LassoFederation_get_remote_nameIdentifier(self) get_object((self)->remote_nameIdentifier)
#define LassoFederation_remote_nameIdentifier_get(self) get_object((self)->remote_nameIdentifier)
#define LassoFederation_set_remote_nameIdentifier(self, value) set_object((gpointer *) &(self)->remote_nameIdentifier, (value))
#define LassoFederation_remote_nameIdentifier_set(self, value) set_object((gpointer *) &(self)->remote_nameIdentifier, (value))

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
	/* Attributes inherited from LassoProfile */

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

	LassoSamlNameIdentifier *nameIdentifier;

	%newobject remoteProviderId_get;
	char *remoteProviderId;

	%immutable request;
	LassoLibFederationTerminationNotification *request;

	%newobject session_get;
	LassoSession *session;

	/* Constructor, Destructor & Static Methods */

	LassoDefederation(LassoServer *server);

	~LassoDefederation();

	/* Methods inherited from LassoProfile */

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

/* Attributes inherited from LassoProfile implementations */

/* identity */
#define LassoDefederation_get_identity(self) lasso_profile_get_identity(LASSO_PROFILE(self))
#define LassoDefederation_identity_get(self) lasso_profile_get_identity(LASSO_PROFILE(self))
#define LassoDefederation_set_identity(self, value) set_object((gpointer *) &LASSO_PROFILE(self)->identity, (value))
#define LassoDefederation_identity_set(self, value) set_object((gpointer *) &LASSO_PROFILE(self)->identity, (value))

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
#define LassoDefederation_get_nameIdentifier(self) get_object(LASSO_PROFILE(self)->nameIdentifier)
#define LassoDefederation_nameIdentifier_get(self) get_object(LASSO_PROFILE(self)->nameIdentifier)
#define LassoDefederation_set_nameIdentifier(self, value) set_object((gpointer *) &LASSO_PROFILE(self)->nameIdentifier, (value))
#define LassoDefederation_nameIdentifier_set(self, value) set_object((gpointer *) &LASSO_PROFILE(self)->nameIdentifier, (value))

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
#define LassoDefederation_set_session(self, value) set_object((gpointer *) &LASSO_PROFILE(self)->session, (value))
#define LassoDefederation_session_set(self, value) set_object((gpointer *) &LASSO_PROFILE(self)->session, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoDefederation lasso_defederation_new
#define delete_LassoDefederation(self) lasso_node_destroy(LASSO_NODE(self))

/* Methods inherited from LassoProfile implementations */

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
	/* Attributes inherited from LassoProfile */

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

	LassoSamlNameIdentifier *nameIdentifier;

	%newobject remoteProviderId_get;
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

	/* Methods inherited from LassoProfile */

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

/* Attributes inherited from LassoProfile implementations */

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
#define LassoLogin_set_identity(self, value) set_object((gpointer *) &LASSO_PROFILE(self)->identity, (value))
#define LassoLogin_identity_set(self, value) set_object((gpointer *) &LASSO_PROFILE(self)->identity, (value))

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
#define LassoLogin_get_nameIdentifier(self) get_object(LASSO_PROFILE(self)->nameIdentifier)
#define LassoLogin_nameIdentifier_get(self) get_object(LASSO_PROFILE(self)->nameIdentifier)
#define LassoLogin_set_nameIdentifier(self, value) set_object((gpointer *) &LASSO_PROFILE(self)->nameIdentifier, (value))
#define LassoLogin_nameIdentifier_set(self, value) set_object((gpointer *) &LASSO_PROFILE(self)->nameIdentifier, (value))

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
#define LassoLogin_set_session(self, value) set_object((gpointer *) &LASSO_PROFILE(self)->session, (value))
#define LassoLogin_session_set(self, value) set_object((gpointer *) &LASSO_PROFILE(self)->session, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoLogin lasso_login_new
#define delete_LassoLogin(self) lasso_node_destroy(LASSO_NODE(self))
#ifdef PHP_VERSION
#define LassoLogin_newFromDump lasso_login_new_from_dump
#else
#define Login_newFromDump lasso_login_new_from_dump
#endif

/* Methods inherited from LassoProfile implementations */

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
	/* Attributes inherited from LassoProfile */

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

	LassoSamlNameIdentifier *nameIdentifier;

	%newobject remoteProviderId_get;
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

	/* Methods inherited from LassoProfile */

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

/* Attributes inherited from LassoProfile implementations */

/* identity */
#define LassoLogout_get_identity(self) lasso_profile_get_identity(LASSO_PROFILE(self))
#define LassoLogout_identity_get(self) lasso_profile_get_identity(LASSO_PROFILE(self))
#define LassoLogout_set_identity(self, value) set_object((gpointer *) &LASSO_PROFILE(self)->identity, (value))
#define LassoLogout_identity_set(self, value) set_object((gpointer *) &LASSO_PROFILE(self)->identity, (value))

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
#define LassoLogout_get_nameIdentifier(self) get_object(LASSO_PROFILE(self)->nameIdentifier)
#define LassoLogout_nameIdentifier_get(self) get_object(LASSO_PROFILE(self)->nameIdentifier)
#define LassoLogout_set_nameIdentifier(self, value) set_object((gpointer *) &LASSO_PROFILE(self)->nameIdentifier, (value))
#define LassoLogout_nameIdentifier_set(self, value) set_object((gpointer *) &LASSO_PROFILE(self)->nameIdentifier, (value))

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
#define LassoLogout_set_session(self, value) set_object((gpointer *) &LASSO_PROFILE(self)->session, (value))
#define LassoLogout_session_set(self, value) set_object((gpointer *) &LASSO_PROFILE(self)->session, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoLogout lasso_logout_new
#define delete_LassoLogout(self) lasso_node_destroy(LASSO_NODE(self))
#ifdef PHP_VERSION
#define LassoLogout_newFromDump lasso_logout_new_from_dump
#else
#define Logout_newFromDump lasso_logout_new_from_dump
#endif

/* Methods inherited from LassoProfile implementations */

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
	/* Attributes inherited from LassoProfile */

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

	LassoSamlNameIdentifier *nameIdentifier;

	%newobject remoteProviderId_get;
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

	/* Methods inherited from LassoProfile */

        THROW_ERROR
	void setIdentityFromDump(char *dump);
	END_THROW_ERROR

	THROW_ERROR
	void setSessionFromDump(char *dump);
	END_THROW_ERROR

	/* Methods inherited from LassoLogin */

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

/* Attributes inherited from LassoProfile implementations */

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
#define LassoLecp_set_identity(self, value) set_object((gpointer *) &LASSO_PROFILE(self)->identity, (value))
#define LassoLecp_identity_set(self, value) set_object((gpointer *) &LASSO_PROFILE(self)->identity, (value))

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
#define LassoLecp_get_nameIdentifier(self) get_object(LASSO_PROFILE(self)->nameIdentifier)
#define LassoLecp_nameIdentifier_get(self) get_object(LASSO_PROFILE(self)->nameIdentifier)
#define LassoLecp_set_nameIdentifier(self, value) set_object((gpointer *) &LASSO_PROFILE(self)->nameIdentifier, (value))
#define LassoLecp_nameIdentifier_set(self, value) set_object((gpointer *) &LASSO_PROFILE(self)->nameIdentifier, (value))

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
#define LassoLecp_set_session(self, value) set_object((gpointer *) &LASSO_PROFILE(self)->session, (value))
#define LassoLecp_session_set(self, value) set_object((gpointer *) &LASSO_PROFILE(self)->session, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoLecp lasso_lecp_new
#define delete_LassoLecp(self) lasso_node_destroy(LASSO_NODE(self))

/* Methods inherited from LassoProfile implementations */

int LassoLecp_setIdentityFromDump(LassoLecp *self, char *dump) {
	return lasso_profile_set_identity_from_dump(LASSO_PROFILE(self), dump);
}

int LassoLecp_setSessionFromDump(LassoLecp *self, char *dump) {
	return lasso_profile_set_session_from_dump(LASSO_PROFILE(self), dump);
}

/* Methods inherited from LassoLogin implementations */

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
	/* Attributes inherited from LassoProfile */

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

	LassoSamlNameIdentifier *nameIdentifier;

	%newobject remoteProviderId_get;
	char *remoteProviderId;

	%newobject session_get;
	LassoSession *session;

	/* Constructor, Destructor & Static Methods */

	LassoNameIdentifierMapping(LassoServer *server);

	~LassoNameIdentifierMapping();

	/* Methods inherited from LassoProfile */

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

/* Attributes inherited from LassoProfile implementations */

/* identity */
#define LassoNameIdentifierMapping_get_identity(self) lasso_profile_get_identity(LASSO_PROFILE(self))
#define LassoNameIdentifierMapping_identity_get(self) lasso_profile_get_identity(LASSO_PROFILE(self))
#define LassoNameIdentifierMapping_set_identity(self, value) set_object((gpointer *) &LASSO_PROFILE(self)->identity, (value))
#define LassoNameIdentifierMapping_identity_set(self, value) set_object((gpointer *) &LASSO_PROFILE(self)->identity, (value))

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
#define LassoNameIdentifierMapping_get_nameIdentifier(self) get_object(LASSO_PROFILE(self)->nameIdentifier)
#define LassoNameIdentifierMapping_nameIdentifier_get(self) get_object(LASSO_PROFILE(self)->nameIdentifier)
#define LassoNameIdentifierMapping_set_nameIdentifier(self, value) set_object((gpointer *) &LASSO_PROFILE(self)->nameIdentifier, (value))
#define LassoNameIdentifierMapping_nameIdentifier_set(self, value) set_object((gpointer *) &LASSO_PROFILE(self)->nameIdentifier, (value))

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
#define LassoNameIdentifierMapping_set_session(self, value) set_object((gpointer *) &LASSO_PROFILE(self)->session, (value))
#define LassoNameIdentifierMapping_session_set(self, value) set_object((gpointer *) &LASSO_PROFILE(self)->session, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoNameIdentifierMapping lasso_name_identifier_mapping_new
#define delete_LassoNameIdentifierMapping(self) lasso_node_destroy(LASSO_NODE(self))

/* Methods inherited from LassoProfile implementations */

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
	/* Attributes inherited from LassoProfile */

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

	LassoSamlNameIdentifier *nameIdentifier;

	%newobject remoteProviderId_get;
	char *remoteProviderId;

	%immutable request;
	LassoLibRegisterNameIdentifierRequest *request;

	%immutable response;
	LassoLibRegisterNameIdentifierResponse *response;

	%newobject session_get;
	LassoSession *session;

	/* Attributes */

	LassoSamlNameIdentifier *oldNameIdentifier;

	/* Constructor, Destructor & Static Methods */

	LassoNameRegistration(LassoServer *server);

	~LassoNameRegistration();

	%newobject newFromDump;
	static LassoNameRegistration *newFromDump(LassoServer *server, char *dump);

	/* Methods inherited from LassoProfile */

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

/* Attributes inherited from LassoProfile implementations */

/* identity */
#define LassoNameRegistration_get_identity(self) lasso_profile_get_identity(LASSO_PROFILE(self))
#define LassoNameRegistration_identity_get(self) lasso_profile_get_identity(LASSO_PROFILE(self))
#define LassoNameRegistration_set_identity(self, value) set_object((gpointer *) &LASSO_PROFILE(self)->identity, (value))
#define LassoNameRegistration_identity_set(self, value) set_object((gpointer *) &LASSO_PROFILE(self)->identity, (value))

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
#define LassoNameRegistration_get_nameIdentifier(self) get_object(LASSO_PROFILE(self)->nameIdentifier)
#define LassoNameRegistration_nameIdentifier_get(self) get_object(LASSO_PROFILE(self)->nameIdentifier)
#define LassoNameRegistration_set_nameIdentifier(self, value) set_object((gpointer *) &LASSO_PROFILE(self)->nameIdentifier, (value))
#define LassoNameRegistration_nameIdentifier_set(self, value) set_object((gpointer *) &LASSO_PROFILE(self)->nameIdentifier, (value))

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
#define LassoNameRegistration_set_session(self, value) set_object((gpointer *) &LASSO_PROFILE(self)->session, (value))
#define LassoNameRegistration_session_set(self, value) set_object((gpointer *) &LASSO_PROFILE(self)->session, (value))

/* Attributes implementations */

/* oldNameIdentifier */
#define LassoNameRegistration_get_oldNameIdentifier(self) get_object((self)->oldNameIdentifier)
#define LassoNameRegistration_oldNameIdentifier_get(self) get_object((self)->oldNameIdentifier)
#define LassoNameRegistration_set_oldNameIdentifier(self, value) set_object((gpointer *) &(self)->oldNameIdentifier, (value))
#define LassoNameRegistration_oldNameIdentifier_set(self, value) set_object((gpointer *) &(self)->oldNameIdentifier, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoNameRegistration lasso_name_registration_new
#define delete_LassoNameRegistration(self) lasso_node_destroy(LASSO_NODE(self))
#ifdef PHP_VERSION
#define LassoNameRegistration_newFromDump lasso_name_registration_new_from_dump
#else
#define NameRegistration_newFromDump lasso_name_registration_new_from_dump
#endif

/* Methods inherited from LassoProfile implementations */

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

