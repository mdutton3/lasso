/* -*- Mode: c; c-basic-offset: 8 -*-
 *
 * $Id$
 *
 * SWIG bindings for Lasso Library
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 *
 * Authors: Romain Chantereau <rchantereau@entrouvert.com>
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
/* FIXME: IMHO, Lasso errors should not be defined in lasso/xml/ */
/*        and should be included in lasso.h. */
#include <lasso/xml/errors.h>


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
	PyObject *lassoSyntaxError;
%}

%init %{
	lassoError = PyErr_NewException("_lasso.Error", NULL, NULL);
	Py_INCREF(lassoError);
	PyModule_AddObject(m, "Error", lassoError);

	lassoSyntaxError = PyErr_NewException("_lasso.SyntaxError", lassoError, NULL);
	Py_INCREF(lassoSyntaxError);
	PyModule_AddObject(m, "SyntaxError", lassoSyntaxError);
	
	lasso_init();
%}

%pythoncode %{
Error = _lasso.Error
SyntaxError = _lasso.SyntaxError
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


#define gint int
#define guint unsigned int
#define gchar char
#define guchar unsigned char

#define gboolean bool
%{
#define bool int
#define false 0
#define true 1
%}

#define gshort short
#define gushort unsigned short
#define gulong unsigned long

#define gint8 int8_t
#define gint16 int16_t
#define gint32 int32_t
#define gint64 int64_t

#define guint8 u_int8_t
#define guint16 u_int16_t
#define guint32 u_int32_t
#define guint64 u_int64_t

#define gfloat float
#define gdouble double
#define gldouble long double
#define gpointer void*
#define GPtrArray void

#define xmlChar char

/* SWIG instructions telling how to deallocate Lasso structures */

%typemap(newfree) gchar * "g_free($1);";
%typemap(newfree) xmlChar * "xmlFree($1);";

/* Functions */

#ifndef SWIGPHP4
%rename(init) lasso_init;
#endif
int lasso_init(void);

#ifndef SWIGPHP4
%rename(shutdown) lasso_shutdown;
#endif
int lasso_shutdown(void);


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
%rename(httpMethodAny) lassoHttpMethodAny;
%rename(httpMethodGet) lassoHttpMethodGet;
%rename(httpMethodPost) lassoHttpMethodPost;
%rename(httpMethodRedirect) lassoHttpMethodRedirect;
%rename(httpMethodSoap) lassoHttpMethodSoap;
#endif
typedef enum {
	lassoHttpMethodAny = 0,
	lassoHttpMethodGet,
	lassoHttpMethodPost,
	lassoHttpMethodRedirect,
	lassoHttpMethodSoap
} lassoHttpMethod;

/* Consent */
#ifndef SWIGPHP4
%rename(libConsentObtained) lassoLibConsentObtained;
%rename(libConsentObtainedPrior) lassoLibConsentObtainedPrior;
%rename(libConsentObtainedCurrentImplicit) lassoLibConsentObtainedCurrentImplicit;
%rename(libConsentObtainedCurrentExplicit) lassoLibConsentObtainedCurrentExplicit;
%rename(libConsentUnavailable) lassoLibConsentUnavailable;
%rename(libConsentInapplicable) lassoLibConsentInapplicable;
#endif
#define lassoLibConsentObtained "urn:liberty:consent:obtained"
#define lassoLibConsentObtainedPrior "urn:liberty:consent:obtained:prior"
#define lassoLibConsentObtainedCurrentImplicit "urn:liberty:consent:obtained:current:implicit"
#define lassoLibConsentObtainedCurrentExplicit "urn:liberty:consent:obtained:current:explicit"
#define lassoLibConsentUnavailable "urn:liberty:consent:unavailable"
#define lassoLibConsentInapplicable "urn:liberty:consent:inapplicable"

/* NameIdPolicyType */
#ifndef SWIGPHP4
%rename(libNameIdPolicyTypeNone) lassoLibNameIDPolicyTypeNone;
%rename(libNameIdPolicyTypeOneTime) lassoLibNameIDPolicyTypeOneTime;
%rename(libNameIdPolicyTypeFederated) lassoLibNameIDPolicyTypeFederated;
%rename(libNameIdPolicyTypeAny) lassoLibNameIDPolicyTypeAny;
#endif
#define lassoLibNameIDPolicyTypeNone "none"
#define lassoLibNameIDPolicyTypeOneTime "onetime"
#define lassoLibNameIDPolicyTypeFederated "federated"
#define lassoLibNameIDPolicyTypeAny "any"

/* ProtocolProfile */
#ifndef SWIGPHP4
%rename(libProtocolProfileBrwsArt) lassoLibProtocolProfileBrwsArt;
%rename(libProtocolProfileBrwsPost) lassoLibProtocolProfileBrwsPost;
%rename(libProtocolProfileFedTermIdpHttp) lassoLibProtocolProfileFedTermIdpHttp;
%rename(libProtocolProfileFedTermIdpSoap) lassoLibProtocolProfileFedTermIdpSoap;
%rename(libProtocolProfileFedTermSpHttp) lassoLibProtocolProfileFedTermSpHttp;
%rename(libProtocolProfileFedTermSpSoap) lassoLibProtocolProfileFedTermSpSoap;
%rename(libProtocolProfileRniIdpHttp) lassoLibProtocolProfileRniIdpHttp;
%rename(libProtocolProfileRniIdpSoap) lassoLibProtocolProfileRniIdpSoap;
%rename(libProtocolProfileRniSpHttp) lassoLibProtocolProfileRniSpHttp;
%rename(libProtocolProfileRniSpSoap) lassoLibProtocolProfileRniSpSoap;
%rename(libProtocolProfileSloIdpHttp) lassoLibProtocolProfileSloIdpHttp;
%rename(libProtocolProfileSloIdpSoap) lassoLibProtocolProfileSloIdpSoap;
%rename(libProtocolProfileSloSpHttp) lassoLibProtocolProfileSloSpHttp;
%rename(libProtocolProfileSloSpSoap) lassoLibProtocolProfileSloSpSoap;
#endif
#define lassoLibProtocolProfileBrwsArt "http://projectliberty.org/profiles/brws-art"
#define lassoLibProtocolProfileBrwsPost "http://projectliberty.org/profiles/brws-post"
#define lassoLibProtocolProfileFedTermIdpHttp "http://projectliberty.org/profiles/fedterm-idp-http"
#define lassoLibProtocolProfileFedTermIdpSoap "http://projectliberty.org/profiles/fedterm-idp-soap"
#define lassoLibProtocolProfileFedTermSpHttp "http://projectliberty.org/profiles/fedterm-sp-http"
#define lassoLibProtocolProfileFedTermSpSoap "http://projectliberty.org/profiles/fedterm-sp-soap"
#define lassoLibProtocolProfileRniIdpHttp "http://projectliberty.org/profiles/rni-idp-http"
#define lassoLibProtocolProfileRniIdpSoap "http://projectliberty.org/profiles/rni-idp-soap"
#define lassoLibProtocolProfileRniSpHttp "http://projectliberty.org/profiles/rni-sp-http"
#define lassoLibProtocolProfileRniSpSoap "http://projectliberty.org/profiles/rni-sp-soap"
#define lassoLibProtocolProfileSloIdpHttp "http://projectliberty.org/profiles/slo-idp-http"
#define lassoLibProtocolProfileSloIdpSoap "http://projectliberty.org/profiles/slo-idp-soap"
#define lassoLibProtocolProfileSloSpHttp "http://projectliberty.org/profiles/slo-sp-http"
#define lassoLibProtocolProfileSloSpSoap "http://projectliberty.org/profiles/slo-sp-soap"

/* LoginProtocolProfile */
#ifndef SWIGPHP4
%rename(loginProtocolProfileBrwsArt) lassoLoginProtocolProfileBrwsArt;
%rename(loginProtocolProfileBrwsPost) lassoLoginProtocolProfileBrwsPost;
#endif
typedef enum {
	lassoLoginProtocolProfileBrwsArt = 1,
	lassoLoginProtocolProfileBrwsPost,
} lassoLoginProtocolProfile;

/* MessageType */
#ifndef SWIGPHP4
%rename(messageTypeNone) lassoMessageTypeNone;
%rename(messageTypeAuthnRequest) lassoMessageTypeAuthnRequest;
%rename(messageTypeAuthnResponse) lassoMessageTypeAuthnResponse;
%rename(messageTypeRequest) lassoMessageTypeRequest;
%rename(messageTypeResponse) lassoMessageTypeResponse;
%rename(messageTypeArtifact) lassoMessageTypeArtifact;
#endif
typedef enum {
	lassoMessageTypeNone = 0,
	lassoMessageTypeAuthnRequest,
	lassoMessageTypeAuthnResponse,
	lassoMessageTypeRequest,
	lassoMessageTypeResponse,
	lassoMessageTypeArtifact
} lassoMessageType;

/* ProviderType */
#ifndef SWIGPHP4
%rename(providerTypeNone) lassoProviderTypeNone;
%rename(providerTypeSp) lassoProviderTypeSp;
%rename(providerTypeIdp) lassoProviderTypeIdp;
#endif
typedef enum {
	lassoProviderTypeNone = 0,
	lassoProviderTypeSp,
	lassoProviderTypeIdp
} lassoProviderType;

/* RequestType */
#ifndef SWIGPHP4
%rename(requestTypeInvalid) lassoRequestTypeInvalid;
%rename(requestTypeLogin) lassoRequestTypeLogin;
%rename(requestTypeLogout) lassoRequestTypeLogout;
%rename(requestTypeDefederation) lassoRequestTypeDefederation;
%rename(requestTypeRegisterNameIdentifier) lassoRequestTypeRegisterNameIdentifier; /* FIXME ABI : Obsolete */
%rename(requestTypeNameRegistration) lassoRequestTypeNameRegistration;
%rename(requestTypeNameIdentifierMapping) lassoRequestTypeNameIdentifierMapping;
%rename(requestTypeLecp) lassoRequestTypeLecp;
#endif
typedef enum {
	lassoRequestTypeInvalid = 0,
	lassoRequestTypeLogin = 1,
	lassoRequestTypeLogout = 2,
	lassoRequestTypeDefederation = 3,
	lassoRequestTypeRegisterNameIdentifier = 4, /* FIXME ABI : Obsolete */
	lassoRequestTypeNameRegistration = 4,
	lassoRequestTypeNameIdentifierMapping = 5,
	lassoRequestTypeLecp = 6
} lassoRequestType;

/* SamlAuthenticationMethod */
#ifndef SWIGPHP4
%rename(samlAuthenticationMethodPassword) lassoSamlAuthenticationMethodPassword;
%rename(samlAuthenticationMethodKerberos) lassoSamlAuthenticationMethodKerberos;
%rename(samlAuthenticationMethodSecureRemotePassword) lassoSamlAuthenticationMethodSecureRemotePassword;
%rename(samlAuthenticationMethodHardwareToken) lassoSamlAuthenticationMethodHardwareToken;
%rename(samlAuthenticationMethodSmartcardPki) lassoSamlAuthenticationMethodSmartcardPki;
%rename(samlAuthenticationMethodSoftwarePki) lassoSamlAuthenticationMethodSoftwarePki;
%rename(samlAuthenticationMethodPgp) lassoSamlAuthenticationMethodPgp;
%rename(samlAuthenticationMethodSpki) lassoSamlAuthenticationMethodSPki;
%rename(samlAuthenticationMethodXkms) lassoSamlAuthenticationMethodXkms;
%rename(samlAuthenticationMethodXmlDsig) lassoSamlAuthenticationMethodXmlDSig;
%rename(samlAuthenticationMethodUnspecified) lassoSamlAuthenticationMethodUnspecified;
#endif
#define lassoSamlAuthenticationMethodPassword "urn:oasis:names:tc:SAML:1.0:am:password"
#define lassoSamlAuthenticationMethodKerberos "urn:ietf:rfc:1510"
#define lassoSamlAuthenticationMethodSecureRemotePassword "urn:ietf:rfc:2945"
#define lassoSamlAuthenticationMethodHardwareToken "urn:oasis:names:tc:SAML:1.0:am:HardwareToken"
#define lassoSamlAuthenticationMethodSmartcardPki "urn:ietf:rfc:2246"
#define lassoSamlAuthenticationMethodSoftwarePki "urn:oasis:names:tc:SAML:1.0:am:X509-PKI"
#define lassoSamlAuthenticationMethodPgp "urn:oasis:names:tc:SAML:1.0:am:PGP"
#define lassoSamlAuthenticationMethodSPki "urn:oasis:names:tc:SAML:1.0:am:SPKI"
#define lassoSamlAuthenticationMethodXkms "urn:oasis:names:tc:SAML:1.0:am:XKMS"
#define lassoSamlAuthenticationMethodXmlDSig "urn:ietf:rfc:3075"
#define lassoSamlAuthenticationMethodUnspecified "urn:oasis:names:tc:SAML:1.0:am:unspecified"

/* SignatureMethod */
#ifndef SWIGPHP4
%rename(signatureMethodRsaSha1) lassoSignatureMethodRsaSha1;
%rename(signatureMethodDsaSha1) lassoSignatureMethodDsaSha1;
#endif
typedef enum {
	lassoSignatureMethodRsaSha1 = 1,
	lassoSignatureMethodDsaSha1
} lassoSignatureMethod;


/***********************************************************************
 * Errors
 ***********************************************************************/


/* generic XML */
#ifndef SWIGPHP4
%rename(XML_ERROR_NODE_NOT_FOUND) LASSO_XML_ERROR_NODE_NOT_FOUND;
%rename(XML_ERROR_NODE_CONTENT_NOT_FOUND) LASSO_XML_ERROR_NODE_CONTENT_NOT_FOUND;
%rename(XML_ERROR_ATTR_NOT_FOUND) LASSO_XML_ERROR_ATTR_NOT_FOUND;
%rename(XML_ERROR_ATTR_VALUE_NOT_FOUND) LASSO_XML_ERROR_ATTR_VALUE_NOT_FOUND;
#endif
#define LASSO_XML_ERROR_NODE_NOT_FOUND -10
#define LASSO_XML_ERROR_NODE_CONTENT_NOT_FOUND -11
#define LASSO_XML_ERROR_ATTR_NOT_FOUND -12
#define LASSO_XML_ERROR_ATTR_VALUE_NOT_FOUND -13

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
%rename(LASSO_DS_ERROR_INVALID_SIGALG) LASSO_DS_ERROR_INVALID_SIGALG;
#endif
#define LASSO_DS_ERROR_SIGNATURE_NOT_FOUND 101
#define LASSO_DS_ERROR_INVALID_SIGNATURE 102

#define LASSO_DS_ERROR_SIGNATURE_TMPL_CREATION_FAILED -101
#define LASSO_DS_ERROR_CONTEXT_CREATION_FAILED -102
#define LASSO_DS_ERROR_PUBLIC_KEY_LOAD_FAILED -103
#define LASSO_DS_ERROR_PRIVATE_KEY_LOAD_FAILED -104
#define LASSO_DS_ERROR_CERTIFICATE_LOAD_FAILED -105
#define LASSO_DS_ERROR_SIGNATURE_FAILED -106
#define LASSO_DS_ERROR_KEYS_MNGR_CREATION_FAILED -107
#define LASSO_DS_ERROR_KEYS_MNGR_INIT_FAILED -108
#define LASSO_DS_ERROR_SIGNATURE_VERIFICATION_FAILED -109
#define LASSO_DS_ERROR_CA_CERT_CHAIN_LOAD_FAILED -110
#define LASSO_DS_ERROR_INVALID_SIGALG -111

/* server */
#ifndef SWIGPHP4
%rename(SERVER_ERROR_PROVIDER_NOT_FOUND) LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND;
%rename(SERVER_ERROR_ADD_PROVIDER_FAILED) LASSO_SERVER_ERROR_ADD_PROVIDER_FAILED;
#endif
#define LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND -201
#define LASSO_SERVER_ERROR_ADD_PROVIDER_FAILED -202

/* logout */
#ifndef SWIGPHP4
%rename(LOGOUT_ERROR_UNSUPPORTED_PROFILE) LASSO_LOGOUT_ERROR_UNSUPPORTED_PROFILE;
#endif
#define LASSO_LOGOUT_ERROR_UNSUPPORTED_PROFILE -301

/* profile */
#ifndef SWIGPHP4
%rename(PROFILE_ERROR_INVALID_QUERY) LASSO_PROFILE_ERROR_INVALID_QUERY;
%rename(PROFILE_ERROR_MISSING_REQUEST) LASSO_PROFILE_ERROR_MISSING_REQUEST;
#endif
#define LASSO_PROFILE_ERROR_INVALID_QUERY -401
#define LASSO_PROFILE_ERROR_MISSING_REQUEST -402

/* functions/methods parameters checking */
#ifndef SWIGPHP4
%rename(PARAM_ERROR_BADTYPE_OR_NULL_OBJ) LASSO_PARAM_ERROR_BADTYPE_OR_NULL_OBJ;
%rename(PARAM_ERROR_INVALID_VALUE) LASSO_PARAM_ERROR_INVALID_VALUE;
%rename(PARAM_ERROR_ERR_CHECK_FAILED) LASSO_PARAM_ERROR_ERR_CHECK_FAILED;
#endif
#define LASSO_PARAM_ERROR_BADTYPE_OR_NULL_OBJ -501
#define LASSO_PARAM_ERROR_INVALID_VALUE -502
#define LASSO_PARAM_ERROR_ERR_CHECK_FAILED -503

/* login */
#ifndef SWIGPHP4
%rename(LOGIN_ERROR_FEDERATION_NOT_FOUND) LASSO_LOGIN_ERROR_FEDERATION_NOT_FOUND;
%rename(LOGIN_ERROR_CONSENT_NOT_OBTAINED) LASSO_LOGIN_ERROR_CONSENT_NOT_OBTAINED;
%rename(LASSO_LOGIN_ERROR_INVALID_NAMEIDPOLICY) LASSO_LOGIN_ERROR_INVALID_NAMEIDPOLICY;
#endif
#define LASSO_LOGIN_ERROR_FEDERATION_NOT_FOUND 601
#define LASSO_LOGIN_ERROR_CONSENT_NOT_OBTAINED 602

#define LASSO_LOGIN_ERROR_INVALID_NAMEIDPOLICY -601

/* others */
#ifndef SWIGPHP4
%rename(ERROR_UNDEFINED) LASSO_ERROR_UNDEFINED;
#endif
#define LASSO_ERROR_UNDEFINED -999


/***********************************************************************
 * Exceptions Generation From Lasso Error Codes
 ***********************************************************************/


#ifdef SWIGPYTHON

%{

void lasso_exception(int errorCode) {
	PyObject *errorTuple;

	switch(errorCode) {
	case LASSO_PROFILE_ERROR_INVALID_QUERY:
		errorTuple = Py_BuildValue("(is)", errorCode, "Lasso Syntax Error");
		PyErr_SetObject(lassoSyntaxError, errorTuple);
		Py_DECREF(errorTuple);
		break;
	default:
		errorTuple = Py_BuildValue("(is)", errorCode, "Lasso Error");
		PyErr_SetObject(lassoError, errorTuple);
		Py_DECREF(errorTuple);
		break;
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

int get_exception_type(int errorCode) {
	int exceptionType;

	switch(errorCode) {
	case LASSO_PROFILE_ERROR_INVALID_QUERY:
		exceptionType = SWIG_SyntaxError;
		break;
	default:
		exceptionType = SWIG_UnknownError;
		break;
	}
	return exceptionType;
}

%}

%define THROW_ERROR
%exception {
	int errorCode;
	errorCode = $action
	if (errorCode) {
		char errorMessage[256];
		sprintf(errorMessage, "%d / Lasso Error", errorCode);
		SWIG_exception(get_exception_type(errorCode), errorMessage);
	}
}
%enddef

#endif

%define END_THROW_ERROR
%exception;
%enddef


/***********************************************************************
 * ProviderIds
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(ProviderIds) LassoProviderIds;
#endif
%nodefault LassoProviderIds;
%{
typedef GPtrArray LassoProviderIds;
%}
typedef struct {
	%extend {
		/* Methods */

		GPtrArray *cast() {
			return self;
		}

		static LassoProviderIds *frompointer(GPtrArray *providerIds) {
			return (LassoProviderIds *) providerIds;
		}

#if defined(SWIGPYTHON)
		%rename(__getitem__) getItem;
#endif
		gchar *getItem(int index) {
			return g_ptr_array_index(self, index);
		}

#if defined(SWIGPYTHON)
		%rename(__len__) length;
#endif
		gint length() {
			return self->len;
		}
	}
} LassoProviderIds;


/***********************************************************************
 ***********************************************************************
 * Xml
 ***********************************************************************
 ***********************************************************************/


/***********************************************************************
 * Node
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(Node) LassoNode;
#endif
typedef struct {
	%extend {
		/* Constructor, Destructor & Static Methods */

		LassoNode();

		~LassoNode();

		/* Methods */

		%newobject dump;
		gchar *dump();
	}
} LassoNode;

%{

/* Constructors, destructors & static methods implementations */

#define new_LassoNode lasso_node_new
#define delete_LassoNode lasso_node_destroy

/* Methods implementations */

gchar* LassoNode_dump(LassoNode *self) {
	return lasso_node_export(LASSO_NODE(self));
}

%}


/***********************************************************************
 ***********************************************************************
 * Protocols
 ***********************************************************************
 ***********************************************************************/


/***********************************************************************
 * Assertion
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(Assertion) LassoAssertion;
#endif
typedef struct {
	%extend {
		/* Constructor, Destructor & Static Methods */

		LassoAssertion(xmlChar *issuer, xmlChar *requestId);

		~LassoAssertion();

		/* Methods */

		%newobject dump;
		gchar *dump();
	}
} LassoAssertion;

%{

/* Constructors, destructors & static methods implementations */

#define new_LassoAssertion lasso_assertion_new

void delete_LassoAssertion(LassoAssertion *self) {
	lasso_node_destroy(LASSO_NODE(self));
}

/* Methods implementations */

gchar* LassoAssertion_dump(LassoAssertion *self) {
	return lasso_node_export(LASSO_NODE(self));
}

%}


/***********************************************************************
 * AuthnRequest
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(AuthnRequest) LassoAuthnRequest;
#endif
%nodefault LassoAuthnRequest;
typedef struct {
	%extend {
		/* Attributes inherited from LassoLibAuthnRequest */

		xmlChar *affiliationId;
		xmlChar *assertionConsumerServiceId;
		xmlChar *consent;
		gboolean forceAuthn;
		gboolean isPassive;
		xmlChar *nameIdPolicy;
		xmlChar *protocolProfile;
		xmlChar *providerId;
		xmlChar *relayState;
	}
} LassoAuthnRequest;

%{

/* Attributes Implementations */

/* affiliationId */
#define LassoAuthnRequest_get_affiliationId LassoAuthnRequest_affiliationId_get
xmlChar *LassoAuthnRequest_affiliationId_get(LassoAuthnRequest *self) {
	return NULL; /* FIXME */
}
#define LassoAuthnRequest_set_affiliationId LassoAuthnRequest_affiliationId_set
void LassoAuthnRequest_affiliationId_set(LassoAuthnRequest *self, xmlChar *affiliationId) {
	 lasso_lib_authn_request_set_affiliationID(LASSO_LIB_AUTHN_REQUEST(self), affiliationId);
}

/* assertionConsumerServiceId */
#define LassoAuthnRequest_get_assertionConsumerServiceId LassoAuthnRequest_assertionConsumerServiceId_get
xmlChar *LassoAuthnRequest_assertionConsumerServiceId_get(LassoAuthnRequest *self) {
	return NULL; /* FIXME */
}
#define LassoAuthnRequest_set_assertionConsumerServiceId LassoAuthnRequest_assertionConsumerServiceId_set
void LassoAuthnRequest_assertionConsumerServiceId_set(LassoAuthnRequest *self,
						      xmlChar *assertionConsumerServiceId) {
	lasso_lib_authn_request_set_assertionConsumerServiceID(LASSO_LIB_AUTHN_REQUEST(self),
							       assertionConsumerServiceId);
}

/* consent */
#define LassoAuthnRequest_get_consent LassoAuthnRequest_consent_get
xmlChar *LassoAuthnRequest_consent_get(LassoAuthnRequest *self) {
	return NULL; /* FIXME */
}
#define LassoAuthnRequest_set_consent LassoAuthnRequest_consent_set
void LassoAuthnRequest_consent_set(LassoAuthnRequest *self, xmlChar *consent) {
	 lasso_lib_authn_request_set_consent(LASSO_LIB_AUTHN_REQUEST(self), consent);
}

/* forceAuthn */
#define LassoAuthnRequest_get_forceAuthn LassoAuthnRequest_forceAuthn_get
gboolean LassoAuthnRequest_forceAuthn_get(LassoAuthnRequest *self) {
	return 0; /* FIXME */
}
#define LassoAuthnRequest_set_forceAuthn LassoAuthnRequest_forceAuthn_set
void LassoAuthnRequest_forceAuthn_set(LassoAuthnRequest *self, gboolean forceAuthn) {
	 lasso_lib_authn_request_set_forceAuthn(LASSO_LIB_AUTHN_REQUEST(self), forceAuthn);
}

/* isPassive */
#define LassoAuthnRequest_get_isPassive LassoAuthnRequest_isPassive_get
gboolean LassoAuthnRequest_isPassive_get(LassoAuthnRequest *self) {
	return 0; /* FIXME */
}
#define LassoAuthnRequest_set_isPassive LassoAuthnRequest_isPassive_set
void LassoAuthnRequest_isPassive_set(LassoAuthnRequest *self, gboolean isPassive) {
	 lasso_lib_authn_request_set_isPassive(LASSO_LIB_AUTHN_REQUEST(self), isPassive);
}

/* nameIdPolicy */
#define LassoAuthnRequest_get_nameIdPolicy LassoAuthnRequest_nameIdPolicy_get
xmlChar *LassoAuthnRequest_nameIdPolicy_get(LassoAuthnRequest *self) {
	return NULL; /* FIXME */
}
#define LassoAuthnRequest_set_nameIdPolicy LassoAuthnRequest_nameIdPolicy_set
void LassoAuthnRequest_nameIdPolicy_set(LassoAuthnRequest *self, xmlChar *nameIdPolicy) {
	 lasso_lib_authn_request_set_nameIDPolicy(LASSO_LIB_AUTHN_REQUEST(self), nameIdPolicy);
}

/* protocolProfile */
#define LassoAuthnRequest_get_protocolProfile LassoAuthnRequest_protocolProfile_get
xmlChar *LassoAuthnRequest_protocolProfile_get(LassoAuthnRequest *self) {
	return NULL; /* FIXME */
}
#define LassoAuthnRequest_set_protocolProfile LassoAuthnRequest_protocolProfile_set
void LassoAuthnRequest_protocolProfile_set(LassoAuthnRequest *self, xmlChar *protocolProfile) {
	 lasso_lib_authn_request_set_protocolProfile(LASSO_LIB_AUTHN_REQUEST(self),
						     protocolProfile);
}

/* providerId */
#define LassoAuthnRequest_get_providerId LassoAuthnRequest_providerId_get
xmlChar *LassoAuthnRequest_providerId_get(LassoAuthnRequest *self) {
	return NULL; /* FIXME */
}
#define LassoAuthnRequest_set_providerId LassoAuthnRequest_providerId_set
void LassoAuthnRequest_providerId_set(LassoAuthnRequest *self, xmlChar *providerId) {
	 lasso_lib_authn_request_set_providerID(LASSO_LIB_AUTHN_REQUEST(self), providerId);
}

/* relayState */
#define LassoAuthnRequest_get_relayState LassoAuthnRequest_relayState_get
xmlChar *LassoAuthnRequest_relayState_get(LassoAuthnRequest *self) {
	return NULL; /* FIXME */
}
#define LassoAuthnRequest_set_relayState LassoAuthnRequest_relayState_set
void LassoAuthnRequest_relayState_set(LassoAuthnRequest *self, xmlChar *relayState) {
	 lasso_lib_authn_request_set_relayState(LASSO_LIB_AUTHN_REQUEST(self), relayState);
}

%}


/***********************************************************************
 * AuthnResponse
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(AuthnResponse) LassoAuthnResponse;
#endif
%nodefault LassoAuthnResponse;
typedef struct {
} LassoAuthnResponse;


/***********************************************************************
 * FederationTerminationNotification
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(FederationTerminationNotification) LassoFederationTerminationNotification;
#endif
%nodefault LassoFederationTerminationNotification;
typedef struct {
	/* FIXME: Add a relayState when Lasso supports it. */
} LassoFederationTerminationNotification;


/***********************************************************************
 * LogoutRequest
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(LogoutRequest) LassoLogoutRequest;
#endif
%nodefault LassoLogoutRequest;
typedef struct {
	%extend {
		/* Attributes inherited from LassoLibLogoutRequest */

		xmlChar *relayState;
	}
} LassoLogoutRequest;

%{

/* Attributes Implementations */

/* relayState */
#define LassoLogoutRequest_get_relayState LassoLogoutRequest_relayState_get
xmlChar *LassoLogoutRequest_relayState_get(LassoLogoutRequest *self) {
	return NULL; /* FIXME */
}
#define LassoLogoutRequest_set_relayState LassoLogoutRequest_relayState_set
void LassoLogoutRequest_relayState_set(LassoLogoutRequest *self, xmlChar *relayState) {
	 lasso_lib_logout_request_set_relayState(LASSO_LIB_LOGOUT_REQUEST(self), relayState);
}

%}


/***********************************************************************
 * LogoutResponse
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(LogoutResponse) LassoLogoutResponse;
#endif
%nodefault LassoLogoutResponse;
typedef struct {
} LassoLogoutResponse;


/***********************************************************************
 * Provider
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(Provider) LassoProvider;
#endif
%nodefault LassoProvider;
typedef struct {
	%immutable metadata;
	LassoNode *metadata;

	%extend {
		/* Attributes */

		%immutable providerId;
		%newobject providerId_get;
		gchar *providerId;
	}
} LassoProvider;

%{

/* Attributes implementations */

/* providerId */
#define LassoProvider_get_providerId  LassoProvider_providerId_get
gchar *LassoProvider_providerId_get(LassoProvider *self) {
	return lasso_provider_get_providerID(self);
}

 %}


/***********************************************************************
 * Providers
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(Providers) LassoProviders;
#endif
%nodefault LassoProviders;
%{
typedef GPtrArray LassoProviders;
%}
typedef struct {
	%extend {
		/* Methods */

		GPtrArray *cast() {
			return self;
		}

		static LassoProviders *frompointer(GPtrArray *providers) {
			return (LassoProviders *) providers;
		}

#if defined(SWIGPYTHON)
		%rename(__getitem__) getItem;
#endif
		LassoProvider *getItem(int index) {
			return g_ptr_array_index(self, index);
		}

#if defined(SWIGPYTHON)
		%rename(__len__) length;
#endif
		gint length() {
			return self->len;
		}
	}
} LassoProviders;


/***********************************************************************
 * Request
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(Request) LassoRequest;
#endif
%nodefault LassoRequest;
typedef struct {
} LassoRequest;


/***********************************************************************
 * Response
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(Response) LassoResponse;
#endif
%nodefault LassoResponse;
typedef struct {
} LassoResponse;


/***********************************************************************
 ***********************************************************************
 * Profiles
 ***********************************************************************
 ***********************************************************************/


/***********************************************************************
 * Server
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(Server) LassoServer;
#endif
typedef struct {
	%extend {
		/* Attributes inherited from LassoProvider */

		%immutable metadata;
		LassoNode *metadata;

		/* Attributes */

		%immutable providerId;
		gchar *providerId;

		%immutable providers;
		LassoProviders *providers;

		/* Constructor, destructor & static methods */

		LassoServer(gchar *metadata = NULL, gchar *privateKey = NULL,
			    gchar *secretKey = NULL, gchar *certificate = NULL);

		~LassoServer();

		%newobject newFromDump;
		static LassoServer *newFromDump(gchar *dump);

		/* Methods */

	        THROW_ERROR
		void addProvider(gchar *metadata, gchar *publicKey = NULL,
				 gchar *caCertChain = NULL);
		END_THROW_ERROR

		%newobject dump;
		gchar *dump();
	}
} LassoServer;

%{

/* Attributes inherited from LassoProvider implementations */

/* metadata */
#define LassoServer_get_metadata LassoServer_metadata_get
LassoNode *LassoServer_metadata_get(LassoServer *self) {
	return LASSO_PROVIDER(self)->metadata;
}

/* Attributes implementations */

/* providerId */
#define LassoServer_get_providerId LassoServer_providerId_get
gchar *LassoServer_providerId_get(LassoServer *self) {
	return self->providerID;
}

/* providers */
#define LassoServer_get_providers LassoServer_providers_get
LassoProviders *LassoServer_providers_get(LassoServer *self) {
	return self->providers;
}

/* Constructors, destructors & static methods implementations */

#define new_LassoServer lasso_server_new
#define delete_LassoServer lasso_server_destroy
#ifdef PHP_VERSION
#define LassoServer_newFromDump lasso_server_new_from_dump
#else
#define Server_newFromDump lasso_server_new_from_dump
#endif

/* Methods implementations */

#define LassoServer_addProvider lasso_server_add_provider
#define LassoServer_dump lasso_server_dump

%}


/***********************************************************************
 * Identity
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(Identity) LassoIdentity;
#endif
typedef struct {
	%extend {
		/* Attributes */

		%immutable isDirty;
		gboolean isDirty;

		%immutable providerIds;
		LassoProviderIds *providerIds;

		/* Constructor, Destructor & Static Methods */

		LassoIdentity();

		~LassoIdentity();

		%newobject newFromDump;
		static LassoIdentity *newFromDump(gchar *dump);

		/* Methods */

		%newobject dump;
		gchar *dump();
	}
} LassoIdentity;

%{

/* Attributes implementations */

/* isDirty */
#define LassoIdentity_get_isDirty LassoIdentity_isDirty_get
gboolean LassoIdentity_isDirty_get(LassoIdentity *self) {
	return self->is_dirty;
}

/* providerIDs */
#define LassoIdentity_get_providerIds LassoIdentity_providerIds_get
LassoProviderIds *LassoIdentity_providerIds_get(LassoIdentity *self) {
	return self->providerIDs;
}


/* Constructors, destructors & static methods implementations */

#define new_LassoIdentity lasso_identity_new
#define delete_LassoIdentity lasso_identity_destroy
#ifdef PHP_VERSION
#define LassoIdentity_newFromDump lasso_identity_new_from_dump
#else
#define Identity_newFromDump lasso_identity_new_from_dump
#endif

/* Methods implementations */

#define LassoIdentity_dump lasso_identity_dump

%}


/***********************************************************************
 * Session
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(Session) LassoSession;
#endif
typedef struct {
	%extend {
		/* Attributes */

		%immutable isDirty;
		gboolean isDirty;

		%immutable providerIds;
		LassoProviderIds *providerIds;

		/* Constructor, destructor & static methods */

		LassoSession();

		~LassoSession();

		%newobject newFromDump;
		static LassoSession *newFromDump(gchar *dump);

		/* Methods */

		%newobject dump;
		gchar *dump();

		%newobject getAuthenticationMethod;
		gchar *getAuthenticationMethod(gchar *remoteProviderId = NULL);
	}
} LassoSession;

%{

/* Attributes implementations */

/* isDirty */
#define LassoSession_get_isDirty LassoSession_isDirty_get
gboolean LassoSession_isDirty_get(LassoSession *self) {
	return self->is_dirty;
}

/* providerIDs */
#define LassoSession_get_providerIds LassoSession_providerIds_get
LassoProviderIds *LassoSession_providerIds_get(LassoSession *self) {
	return self->providerIDs;
}

/* Constructors, destructors & static methods implementations */

#define new_LassoSession lasso_session_new
#define delete_LassoSession lasso_session_destroy
#ifdef PHP_VERSION
#define LassoSession_newFromDump lasso_session_new_from_dump
#else
#define Session_newFromDump lasso_session_new_from_dump
#endif

/* Methods implementations */

#define LassoSession_dump lasso_session_dump
#define LassoSession_getAuthenticationMethod lasso_session_get_authentication_method

%}


/***********************************************************************
 * Profile
 ***********************************************************************/


/* Functions */

#ifdef SWIGPHP4
%rename(lasso_getRequestTypeFromSoapMsg) lasso_profile_get_request_type_from_soap_msg;
#else
%rename(getRequestTypeFromSoapMsg) lasso_profile_get_request_type_from_soap_msg;
#endif
lassoRequestType lasso_profile_get_request_type_from_soap_msg(gchar *soap);


/***********************************************************************
 * Defederation
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(Defederation) LassoDefederation;
#endif
typedef struct {
	%extend {
		/* Attributes inherited from LassoProfile */

		%newobject identity_get;
		LassoIdentity *identity;

		%immutable isIdentityDirty;
		gboolean isIdentityDirty;

		%immutable isSessionDirty;
		gboolean isSessionDirty;

		%immutable msgBody;
		gchar *msgBody;

		%immutable msgRelayState;
		gchar *msgRelayState;

		%immutable msgUrl;
		gchar *msgUrl;

		%immutable nameIdentifier;
		gchar *nameIdentifier;

		%newobject remoteProviderId_get;
		gchar *remoteProviderId;

		%immutable request;
		LassoFederationTerminationNotification *request;

		%newobject session_get;
		LassoSession *session;

		/* Constructor, Destructor & Static Methods */

		LassoDefederation(LassoServer *server, lassoProviderType providerType);

		~LassoDefederation();

		/* Methods inherited from LassoProfile */

	        THROW_ERROR
		void setIdentityFromDump(gchar *dump);
		END_THROW_ERROR

		THROW_ERROR
		void setSessionFromDump(gchar *dump);
		END_THROW_ERROR

		/* Methods */

		THROW_ERROR
		void buildNotificationMsg();
		END_THROW_ERROR

		THROW_ERROR
		void initNotification(gchar *remoteProviderId = NULL,
				      lassoHttpMethod httpMethod = lassoHttpMethodAny);
		END_THROW_ERROR

		THROW_ERROR
		void processNotificationMsg(gchar *notificationMsg, lassoHttpMethod httpMethod);
		END_THROW_ERROR

		THROW_ERROR
		void validateNotification();
		END_THROW_ERROR
	}
} LassoDefederation;

%{

/* Attributes inherited from LassoProfile implementations */

/* identity */
#define LassoDefederation_get_identity LassoDefederation_identity_get
LassoIdentity *LassoDefederation_identity_get(LassoDefederation *self) {
	return lasso_profile_get_identity(LASSO_PROFILE(self));
}
#define LassoDefederation_set_identity LassoDefederation_identity_set
gint LassoDefederation_identity_set(LassoDefederation *self, LassoIdentity *identity) {
	return lasso_profile_set_identity(LASSO_PROFILE(self), identity);
}

/* isIdentityDirty */
#define LassoDefederation_get_isIdentityDirty LassoDefederation_isIdentityDirty_get
gboolean LassoDefederation_isIdentityDirty_get(LassoDefederation *self) {
	return lasso_profile_is_identity_dirty(LASSO_PROFILE(self));
}

/* isSessionDirty */
#define LassoDefederation_get_isSessionDirty LassoDefederation_isSessionDirty_get
gboolean LassoDefederation_isSessionDirty_get(LassoDefederation *self) {
	return lasso_profile_is_session_dirty(LASSO_PROFILE(self));
}

/* msgBody */
#define LassoDefederation_get_msgBody LassoDefederation_msgBody_get
gchar *LassoDefederation_msgBody_get(LassoDefederation *self) {
	return LASSO_PROFILE(self)->msg_body;
}

/* msgRelayState */
#define LassoDefederation_get_msgRelayState LassoDefederation_msgRelayState_get
gchar *LassoDefederation_msgRelayState_get(LassoDefederation *self) {
	return LASSO_PROFILE(self)->msg_relayState;
}

/* msgUrl */
#define LassoDefederation_get_msgUrl LassoDefederation_msgUrl_get
gchar *LassoDefederation_msgUrl_get(LassoDefederation *self) {
	return LASSO_PROFILE(self)->msg_url;
}

/* nameIdentifier */
#define LassoDefederation_get_nameIdentifier LassoDefederation_nameIdentifier_get
gchar *LassoDefederation_nameIdentifier_get(LassoDefederation *self) {
	return LASSO_PROFILE(self)->nameIdentifier;
}

/* remoteProviderId */
#define LassoDefederation_get_remoteProviderId LassoDefederation_remoteProviderId_get
gchar *LassoDefederation_remoteProviderId_get(LassoDefederation *self) {
	return lasso_profile_get_remote_providerID(LASSO_PROFILE(self));
}
#define LassoDefederation_set_remoteProviderId LassoDefederation_remoteProviderId_set
void LassoDefederation_remoteProviderId_set(LassoDefederation *self, gchar *remoteProviderId) {
	lasso_profile_set_remote_providerID(LASSO_PROFILE(self), remoteProviderId);
}

/* request */
#define LassoDefederation_get_request LassoDefederation_request_get
LassoFederationTerminationNotification *LassoDefederation_request_get(LassoDefederation *self) {
	return LASSO_FEDERATION_TERMINATION_NOTIFICATION(LASSO_PROFILE(self)->request);
}

/* responseStatus */
#define LassoDefederation_get_responseStatus LassoDefederation_responseStatus_get
gchar *LassoDefederation_responseStatus_get(LassoDefederation *self) {
	return NULL; /* FIXME */
}
#define LassoDefederation_set_responseStatus LassoDefederation_responseStatus_set
void LassoDefederation_responseStatus_set(LassoDefederation *self, gchar *responseStatus) {
	lasso_profile_set_response_status(LASSO_PROFILE(self), responseStatus);
}

/* session */
#define LassoDefederation_get_session LassoDefederation_session_get
LassoSession *LassoDefederation_session_get(LassoDefederation *self) {
	return lasso_profile_get_session(LASSO_PROFILE(self));
}
#define LassoDefederation_set_session LassoDefederation_session_set
gint LassoDefederation_session_set(LassoDefederation *self, LassoSession *session) {
	return lasso_profile_set_session(LASSO_PROFILE(self), session);
}

/* Constructors, destructors & static methods implementations */

#define new_LassoDefederation lasso_defederation_new
#define delete_LassoDefederation lasso_defederation_destroy

/* Methods inherited from LassoProfile implementations */

gint LassoDefederation_setIdentityFromDump(LassoDefederation *self, gchar *dump) {
	return lasso_profile_set_identity_from_dump(LASSO_PROFILE(self), dump);
}

gint LassoDefederation_setSessionFromDump(LassoDefederation *self, gchar *dump) {
	return lasso_profile_set_session_from_dump(LASSO_PROFILE(self), dump);
}

/* Methods implementations */

#define LassoDefederation_buildNotificationMsg lasso_defederation_build_notification_msg
#define LassoDefederation_initNotification lasso_defederation_init_notification
#define LassoDefederation_processNotificationMsg lasso_defederation_process_notification_msg
#define LassoDefederation_validateNotification lasso_defederation_validate_notification

%}


/***********************************************************************
 * Login
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(Login) LassoLogin;
#endif
typedef struct {
	%immutable assertionArtifact;
	gchar *assertionArtifact;

	%immutable protocolProfile;
	lassoLoginProtocolProfile protocolProfile;

	%extend {
		/* Attributes inherited from LassoProfile */

		%immutable authnRequest;
		LassoAuthnRequest *authnRequest;

		%immutable authnResponse;
		LassoAuthnResponse *authnResponse;

		%newobject identity_get;
		LassoIdentity *identity;

		%immutable isIdentityDirty;
		gboolean isIdentityDirty;

		%immutable isSessionDirty;
		gboolean isSessionDirty;

		%immutable msgBody;
		gchar *msgBody;

		%immutable msgRelayState;
		gchar *msgRelayState;

		%immutable msgUrl;
		gchar *msgUrl;

		%immutable nameIdentifier;
		gchar *nameIdentifier;

		%newobject remoteProviderId_get;
		gchar *remoteProviderId;

		%immutable request;
		LassoRequest *request;

		%immutable response;
		LassoResponse *response;

		gchar *responseStatus;

		%newobject session_get;
		LassoSession *session;

		/* Constructor, Destructor & Static Methods */

		LassoLogin(LassoServer *server);

		~LassoLogin();

		%newobject newFromDump;
		static LassoLogin *newFromDump(LassoServer *server, gchar *dump);

		/* Methods inherited from LassoProfile */

	        THROW_ERROR
		void setIdentityFromDump(gchar *dump);
		END_THROW_ERROR

		THROW_ERROR
		void setSessionFromDump(gchar *dump);
		END_THROW_ERROR

		/* Methods */

		THROW_ERROR
		void acceptSso();
		END_THROW_ERROR

		THROW_ERROR
		void buildArtifactMsg(gboolean authenticationResult, gboolean isConsentObtained,
				      gchar *authenticationMethod, gchar *reauthenticateOnOrAfter,
				      lassoHttpMethod httpMethod);
		END_THROW_ERROR

		THROW_ERROR
		void buildAuthnRequestMsg(gchar *remoteProviderId = NULL);
		END_THROW_ERROR

		THROW_ERROR
		void buildAuthnResponseMsg(gint authenticationResult, gboolean isConsentObtained,
					   gchar *authenticationMethod,
					   gchar *reauthenticateOnOrAfter);
		END_THROW_ERROR

		THROW_ERROR
		void buildRequestMsg();
		END_THROW_ERROR

		THROW_ERROR
		void buildResponseMsg(gchar *remoteProviderId);
		END_THROW_ERROR

		%newobject dump;
		gchar *dump();

		THROW_ERROR
		void initAuthnRequest(lassoHttpMethod httpMethod);
		END_THROW_ERROR

		THROW_ERROR
		void initRequest(gchar *responseMsg,
				 lassoHttpMethod httpMethod = lassoHttpMethodRedirect);
		END_THROW_ERROR

		gboolean mustAskForConsent();

		gboolean mustAuthenticate();

		THROW_ERROR
		void processAuthnRequestMsg(gchar *authnrequestMsg, lassoHttpMethod httpMethod);
		END_THROW_ERROR

		THROW_ERROR
		void processAuthnResponseMsg(gchar *authnResponseMsg);
		END_THROW_ERROR

		THROW_ERROR
		void processRequestMsg(gchar *requestMsg);
		END_THROW_ERROR

		THROW_ERROR
		void processResponseMsg(gchar *responseMsg);
		END_THROW_ERROR
	}
} LassoLogin;

%{

/* Attributes inherited from LassoProfile implementations */

/* authnRequest */
#define LassoLogin_get_authnRequest LassoLogin_authnRequest_get
LassoAuthnRequest *LassoLogin_authnRequest_get(LassoLogin *self) {
	LassoProfile *profile = LASSO_PROFILE(self);
	if (profile->request_type == lassoMessageTypeAuthnRequest)
		return LASSO_AUTHN_REQUEST(profile->request);
	else
		return NULL;
}

/* authnResponse */
#define LassoLogin_get_authnResponse LassoLogin_authnResponse_get
LassoAuthnResponse *LassoLogin_authnResponse_get(LassoLogin *self) {
	LassoProfile *profile = LASSO_PROFILE(self);
	if (profile->response_type == lassoMessageTypeAuthnResponse)
		return LASSO_AUTHN_RESPONSE(profile->response);
	else
		return NULL;
}

/* identity */
#define LassoLogin_get_identity LassoLogin_identity_get
LassoIdentity *LassoLogin_identity_get(LassoLogin *self) {
	return lasso_profile_get_identity(LASSO_PROFILE(self));
}
#define LassoLogin_set_identity LassoLogin_identity_set
gint LassoLogin_identity_set(LassoLogin *self, LassoIdentity *identity) {
	return lasso_profile_set_identity(LASSO_PROFILE(self), identity);
}

/* isIdentityDirty */
#define LassoLogin_get_isIdentityDirty LassoLogin_isIdentityDirty_get
gboolean LassoLogin_isIdentityDirty_get(LassoLogin *self) {
	return lasso_profile_is_identity_dirty(LASSO_PROFILE(self));
}

/* isSessionDirty */
#define LassoLogin_get_isSessionDirty LassoLogin_isSessionDirty_get
gboolean LassoLogin_isSessionDirty_get(LassoLogin *self) {
	return lasso_profile_is_session_dirty(LASSO_PROFILE(self));
}

/* msgBody */
#define LassoLogin_get_msgBody LassoLogin_msgBody_get
gchar *LassoLogin_msgBody_get(LassoLogin *self) {
	return LASSO_PROFILE(self)->msg_body;
}

/* msgRelayState */
#define LassoLogin_get_msgRelayState LassoLogin_msgRelayState_get
gchar *LassoLogin_msgRelayState_get(LassoLogin *self) {
	return LASSO_PROFILE(self)->msg_relayState;
}

/* msgUrl */
#define LassoLogin_get_msgUrl LassoLogin_msgUrl_get
gchar *LassoLogin_msgUrl_get(LassoLogin *self) {
	return LASSO_PROFILE(self)->msg_url;
}

/* nameIdentifier */
#define LassoLogin_get_nameIdentifier LassoLogin_nameIdentifier_get
gchar *LassoLogin_nameIdentifier_get(LassoLogin *self) {
	return LASSO_PROFILE(self)->nameIdentifier;
}

/* remoteProviderId */
#define LassoLogin_get_remoteProviderId LassoLogin_remoteProviderId_get
gchar *LassoLogin_remoteProviderId_get(LassoLogin *self) {
	return lasso_profile_get_remote_providerID(LASSO_PROFILE(self));
}
#define LassoLogin_set_remoteProviderId LassoLogin_remoteProviderId_set
void LassoLogin_remoteProviderId_set(LassoLogin *self, gchar *remoteProviderId) {
	lasso_profile_set_remote_providerID(LASSO_PROFILE(self), remoteProviderId);
}

/* request */
#define LassoLogin_get_request LassoLogin_request_get
LassoRequest *LassoLogin_request_get(LassoLogin *self) {
	LassoProfile *profile = LASSO_PROFILE(self);
	if (profile->request_type == lassoMessageTypeRequest)
		return LASSO_REQUEST(profile->request);
	else
		return NULL;
}

/* response */
#define LassoLogin_get_response LassoLogin_response_get
LassoResponse *LassoLogin_response_get(LassoLogin *self) {
	LassoProfile *profile = LASSO_PROFILE(self);
	if (profile->response_type == lassoMessageTypeResponse)
		return LASSO_RESPONSE(profile->response);
	else
		return NULL;
}

/* responseStatus */
#define LassoLogin_get_responseStatus LassoLogin_responseStatus_get
gchar *LassoLogin_responseStatus_get(LassoLogin *self) {
	return NULL; /* FIXME */
}
#define LassoLogin_set_responseStatus LassoLogin_responseStatus_set
void LassoLogin_responseStatus_set(LassoLogin *self, gchar *responseStatus) {
	lasso_profile_set_response_status(LASSO_PROFILE(self), responseStatus);
}

/* session */
#define LassoLogin_get_session LassoLogin_session_get
LassoSession *LassoLogin_session_get(LassoLogin *self) {
	return lasso_profile_get_session(LASSO_PROFILE(self));
}
#define LassoLogin_set_session LassoLogin_session_set
gint LassoLogin_session_set(LassoLogin *self, LassoSession *session) {
	return lasso_profile_set_session(LASSO_PROFILE(self), session);
}

/* Constructors, destructors & static methods implementations */

#define new_LassoLogin lasso_login_new
#define delete_LassoLogin lasso_login_destroy
#ifdef PHP_VERSION
#define LassoLogin_newFromDump lasso_login_new_from_dump
#else
#define Login_newFromDump lasso_login_new_from_dump
#endif

/* Methods inherited from LassoProfile implementations */

gint LassoLogin_setIdentityFromDump(LassoLogin *self, gchar *dump) {
	return lasso_profile_set_identity_from_dump(LASSO_PROFILE(self), dump);
}

gint LassoLogin_setSessionFromDump(LassoLogin *self, gchar *dump) {
	return lasso_profile_set_session_from_dump(LASSO_PROFILE(self), dump);
}

/* Methods implementations */

#define LassoLogin_acceptSso lasso_login_accept_sso
#define LassoLogin_buildArtifactMsg lasso_login_build_artifact_msg
#define LassoLogin_buildAuthnRequestMsg lasso_login_build_authn_request_msg
#define LassoLogin_buildAuthnResponseMsg lasso_login_build_authn_response_msg
#define LassoLogin_buildRequestMsg lasso_login_build_request_msg
#define LassoLogin_buildResponseMsg lasso_login_build_response_msg
#define LassoLogin_dump lasso_login_dump
#define LassoLogin_initAuthnRequest lasso_login_init_authn_request
#define LassoLogin_initRequest lasso_login_init_request
#define LassoLogin_mustAskForConsent lasso_login_must_ask_for_consent
#define LassoLogin_mustAuthenticate lasso_login_must_authenticate
#define LassoLogin_processAuthnRequestMsg lasso_login_process_authn_request_msg
#define LassoLogin_processAuthnResponseMsg lasso_login_process_authn_response_msg
#define LassoLogin_processRequestMsg lasso_login_process_request_msg
#define LassoLogin_processResponseMsg lasso_login_process_response_msg

%}


/***********************************************************************
 * Logout
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(Logout) LassoLogout;
#endif
typedef struct {
	%extend {
		/* Attributes inherited from LassoProfile */

		%newobject identity_get;
		LassoIdentity *identity;

		%immutable isIdentityDirty;
		gboolean isIdentityDirty;

		%immutable isSessionDirty;
		gboolean isSessionDirty;

		%immutable msgBody;
		gchar *msgBody;

		%immutable msgRelayState;
		gchar *msgRelayState;

		%immutable msgUrl;
		gchar *msgUrl;

		%immutable nameIdentifier;
		gchar *nameIdentifier;

		%newobject remoteProviderId_get;
		gchar *remoteProviderId;

		%immutable request;
		LassoLogoutRequest *request;

		%immutable response;
		LassoLogoutResponse *response;

		gchar *responseStatus;

		%newobject session_get;
		LassoSession *session;

		/* Constructor, Destructor & Static Methods */

		LassoLogout(LassoServer *server, lassoProviderType providerType);

		~LassoLogout();

		%newobject newFromDump;
		static LassoLogout *newFromDump(LassoServer *server, gchar *dump);

		/* Methods inherited from LassoProfile */

	        THROW_ERROR
		void setIdentityFromDump(gchar *dump);
		END_THROW_ERROR

		THROW_ERROR
		void setSessionFromDump(gchar *dump);
		END_THROW_ERROR

		/* Methods */

		THROW_ERROR
		void buildRequestMsg();
		END_THROW_ERROR

		THROW_ERROR
		void buildResponseMsg();
		END_THROW_ERROR

		%newobject dump;
		gchar *dump();

		%newobject getNextProviderId;
		gchar *getNextProviderId();

		THROW_ERROR
		void initRequest(gchar *remoteProviderId = NULL,
				 lassoHttpMethod httpMethod = lassoHttpMethodAny);
		END_THROW_ERROR

		THROW_ERROR
		void processRequestMsg(gchar *requestMsg, lassoHttpMethod httpMethod);
		END_THROW_ERROR

		THROW_ERROR
		void processResponseMsg(gchar *responseMsg, lassoHttpMethod httpMethod);
		END_THROW_ERROR

		THROW_ERROR
		void resetProviderIdIndex();
		END_THROW_ERROR

		THROW_ERROR
		void validateRequest();
		END_THROW_ERROR
	}
} LassoLogout;

%{

/* Attributes inherited from LassoProfile implementations */

/* identity */
#define LassoLogout_get_identity LassoLogout_identity_get
LassoIdentity *LassoLogout_identity_get(LassoLogout *self) {
	return lasso_profile_get_identity(LASSO_PROFILE(self));
}
#define LassoLogout_set_identity LassoLogout_identity_set
gint LassoLogout_identity_set(LassoLogout *self, LassoIdentity *identity) {
	return lasso_profile_set_identity(LASSO_PROFILE(self), identity);
}

/* isIdentityDirty */
#define LassoLogout_get_isIdentityDirty LassoLogout_isIdentityDirty_get
gboolean LassoLogout_isIdentityDirty_get(LassoLogout *self) {
	return lasso_profile_is_identity_dirty(LASSO_PROFILE(self));
}

/* isSessionDirty */
#define LassoLogout_get_isSessionDirty LassoLogout_isSessionDirty_get
gboolean LassoLogout_isSessionDirty_get(LassoLogout *self) {
	return lasso_profile_is_session_dirty(LASSO_PROFILE(self));
}

/* msgBody */
#define LassoLogout_get_msgBody LassoLogout_msgBody_get
gchar *LassoLogout_msgBody_get(LassoLogout *self) {
	return LASSO_PROFILE(self)->msg_body;
}

/* msgRelayState */
#define LassoLogout_get_msgRelayState LassoLogout_msgRelayState_get
gchar *LassoLogout_msgRelayState_get(LassoLogout *self) {
	return LASSO_PROFILE(self)->msg_relayState;
}

/* msgUrl */
#define LassoLogout_get_msgUrl LassoLogout_msgUrl_get
gchar *LassoLogout_msgUrl_get(LassoLogout *self) {
	return LASSO_PROFILE(self)->msg_url;
}

/* nameIdentifier */
#define LassoLogout_get_nameIdentifier LassoLogout_nameIdentifier_get
gchar *LassoLogout_nameIdentifier_get(LassoLogout *self) {
	return LASSO_PROFILE(self)->nameIdentifier;
}

/* remoteProviderId */
#define LassoLogout_get_remoteProviderId LassoLogout_remoteProviderId_get
gchar *LassoLogout_remoteProviderId_get(LassoLogout *self) {
	return lasso_profile_get_remote_providerID(LASSO_PROFILE(self));
}
#define LassoLogout_set_remoteProviderId LassoLogout_remoteProviderId_set
void LassoLogout_remoteProviderId_set(LassoLogout *self, gchar *remoteProviderId) {
	lasso_profile_set_remote_providerID(LASSO_PROFILE(self), remoteProviderId);
}

/* request */
#define LassoLogout_get_request LassoLogout_request_get
LassoLogoutRequest *LassoLogout_request_get(LassoLogout *self) {
	return LASSO_LOGOUT_REQUEST(LASSO_PROFILE(self)->request);
}

/* response */
#define LassoLogout_get_response LassoLogout_response_get
LassoLogoutResponse *LassoLogout_response_get(LassoLogout *self) {
	return LASSO_LOGOUT_RESPONSE(LASSO_PROFILE(self)->response);
}

/* responseStatus */
#define LassoLogout_get_responseStatus LassoLogout_responseStatus_get
gchar *LassoLogout_responseStatus_get(LassoLogout *self) {
	return NULL; /* FIXME */
}
#define LassoLogout_set_responseStatus LassoLogout_responseStatus_set
void LassoLogout_responseStatus_set(LassoLogout *self, gchar *responseStatus) {
	lasso_profile_set_response_status(LASSO_PROFILE(self), responseStatus);
}

/* session */
#define LassoLogout_get_session LassoLogout_session_get
LassoSession *LassoLogout_session_get(LassoLogout *self) {
	return lasso_profile_get_session(LASSO_PROFILE(self));
}
#define LassoLogout_set_session LassoLogout_session_set
gint LassoLogout_session_set(LassoLogout *self, LassoSession *session) {
	return lasso_profile_set_session(LASSO_PROFILE(self), session);
}

/* Constructors, destructors & static methods implementations */

#define new_LassoLogout lasso_logout_new
#define delete_LassoLogout lasso_logout_destroy
#ifdef PHP_VERSION
#define LassoLogout_newFromDump lasso_logout_new_from_dump
#else
#define Logout_newFromDump lasso_logout_new_from_dump
#endif

/* Methods inherited from LassoProfile implementations */

gint LassoLogout_setIdentityFromDump(LassoLogout *self, gchar *dump) {
	return lasso_profile_set_identity_from_dump(LASSO_PROFILE(self), dump);
}

gint LassoLogout_setSessionFromDump(LassoLogout *self, gchar *dump) {
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
 * LECP
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(Lecp) LassoLecp;
#endif
typedef struct {
	%extend {
		/* Attributes inherited from LassoProfile */

		%immutable authnRequest;
		LassoAuthnRequest *authnRequest;

		%immutable authnResponse;
		LassoAuthnResponse *authnResponse;

		%newobject identity_get;
		LassoIdentity *identity;

		%immutable isIdentityDirty;
		gboolean isIdentityDirty;

		%immutable isSessionDirty;
		gboolean isSessionDirty;

		%immutable msgBody;
		gchar *msgBody;

		%immutable msgRelayState;
		gchar *msgRelayState;

		%immutable msgUrl;
		gchar *msgUrl;

		%immutable nameIdentifier;
		gchar *nameIdentifier;

		%newobject remoteProviderId_get;
		gchar *remoteProviderId;

		%immutable request;
		LassoRequest *request;

		%immutable response;
		LassoResponse *response;

		gchar *responseStatus;

		%newobject session_get;
		LassoSession *session;

		/* Constructor, Destructor & Static Methods */

		LassoLecp(LassoServer *server);

		~LassoLecp();

		/* Methods inherited from LassoProfile */

	        THROW_ERROR
		void setIdentityFromDump(gchar *dump);
		END_THROW_ERROR

		THROW_ERROR
		void setSessionFromDump(gchar *dump);
		END_THROW_ERROR

		/* Methods */

		THROW_ERROR
		void buildAuthnRequestEnvelopeMsg();
		END_THROW_ERROR

		THROW_ERROR
		void buildAuthnRequestMsg(gchar *remoteProviderId = NULL);
		END_THROW_ERROR

		THROW_ERROR
		void buildAuthnResponseEnvelopeMsg(gboolean authenticationResult,
						   gboolean isConsentObtained,
						   gchar *authenticationMethod,
						   gchar *reauthenticateOnOrAfter);
		END_THROW_ERROR

		THROW_ERROR
		void buildAuthnResponseMsg();
		END_THROW_ERROR

		THROW_ERROR
		void initAuthnRequest();
		END_THROW_ERROR

		THROW_ERROR
		void processAuthnRequestEnvelopeMsg(gchar *requestMsg);
		END_THROW_ERROR

		THROW_ERROR
		void processAuthnRequestMsg(gchar *authnRequestMsg, lassoHttpMethod httpMethod);
		END_THROW_ERROR

		THROW_ERROR
		void processAuthnResponseEnvelopeMsg(gchar *responseMsg);
		END_THROW_ERROR
	}
} LassoLecp;

%{

/* Attributes inherited from LassoProfile implementations */

/* authnRequest */
#define LassoLecp_get_authnRequest LassoLecp_authnRequest_get
LassoAuthnRequest *LassoLecp_authnRequest_get(LassoLecp *self) {
	LassoProfile *profile = LASSO_PROFILE(self);
	if (profile->request_type == lassoMessageTypeAuthnRequest)
		return LASSO_AUTHN_REQUEST(profile->request);
	else
		return NULL;
}

/* authnResponse */
#define LassoLecp_get_authnResponse LassoLecp_authnResponse_get
LassoAuthnResponse *LassoLecp_authnResponse_get(LassoLecp *self) {
	LassoProfile *profile = LASSO_PROFILE(self);
	if (profile->response_type == lassoMessageTypeAuthnResponse)
		return LASSO_AUTHN_RESPONSE(profile->response);
	else
		return NULL;
}

/* identity */
#define LassoLecp_get_identity LassoLecp_identity_get
LassoIdentity *LassoLecp_identity_get(LassoLecp *self) {
	return lasso_profile_get_identity(LASSO_PROFILE(self));
}
#define LassoLecp_set_identity LassoLecp_identity_set
gint LassoLecp_identity_set(LassoLecp *self, LassoIdentity *identity) {
	return lasso_profile_set_identity(LASSO_PROFILE(self), identity);
}

/* isIdentityDirty */
#define LassoLecp_get_isIdentityDirty LassoLecp_isIdentityDirty_get
gboolean LassoLecp_isIdentityDirty_get(LassoLecp *self) {
	return lasso_profile_is_identity_dirty(LASSO_PROFILE(self));
}

/* isSessionDirty */
#define LassoLecp_get_isSessionDirty LassoLecp_isSessionDirty_get
gboolean LassoLecp_isSessionDirty_get(LassoLecp *self) {
	return lasso_profile_is_session_dirty(LASSO_PROFILE(self));
}

/* msgBody */
#define LassoLecp_get_msgBody LassoLecp_msgBody_get
gchar *LassoLecp_msgBody_get(LassoLecp *self) {
	return LASSO_PROFILE(self)->msg_body;
}

/* msgRelayState */
#define LassoLecp_get_msgRelayState LassoLecp_msgRelayState_get
gchar *LassoLecp_msgRelayState_get(LassoLecp *self) {
	return LASSO_PROFILE(self)->msg_relayState;
}

/* msgUrl */
#define LassoLecp_get_msgUrl LassoLecp_msgUrl_get
gchar *LassoLecp_msgUrl_get(LassoLecp *self) {
	return LASSO_PROFILE(self)->msg_url;
}

/* nameIdentifier */
#define LassoLecp_get_nameIdentifier LassoLecp_nameIdentifier_get
gchar *LassoLecp_nameIdentifier_get(LassoLecp *self) {
	return LASSO_PROFILE(self)->nameIdentifier;
}

/* remoteProviderId */
#define LassoLecp_get_remoteProviderId LassoLecp_remoteProviderId_get
gchar *LassoLecp_remoteProviderId_get(LassoLecp *self) {
	return lasso_profile_get_remote_providerID(LASSO_PROFILE(self));
}
#define LassoLecp_set_remoteProviderId LassoLecp_remoteProviderId_set
void LassoLecp_remoteProviderId_set(LassoLecp *self, gchar *remoteProviderId) {
	lasso_profile_set_remote_providerID(LASSO_PROFILE(self), remoteProviderId);
}

/* request */
#define LassoLecp_get_request LassoLecp_request_get
LassoRequest *LassoLecp_request_get(LassoLecp *self) {
	LassoProfile *profile = LASSO_PROFILE(self);
	if (profile->request_type == lassoMessageTypeRequest)
		return LASSO_REQUEST(profile->request);
	else
		return NULL;
}

/* response */
#define LassoLecp_get_response LassoLecp_response_get
LassoResponse *LassoLecp_response_get(LassoLecp *self) {
	LassoProfile *profile = LASSO_PROFILE(self);
	if (profile->response_type == lassoMessageTypeResponse)
		return LASSO_RESPONSE(profile->response);
	else
		return NULL;
}

/* responseStatus */
#define LassoLecp_get_responseStatus LassoLecp_responseStatus_get
gchar *LassoLecp_responseStatus_get(LassoLecp *self) {
	return NULL; /* FIXME */
}
#define LassoLecp_set_responseStatus LassoLecp_responseStatus_set
void LassoLecp_responseStatus_set(LassoLecp *self, gchar *responseStatus) {
	lasso_profile_set_response_status(LASSO_PROFILE(self), responseStatus);
}

/* session */
#define LassoLecp_get_session LassoLecp_session_get
LassoSession *LassoLecp_session_get(LassoLecp *self) {
	return lasso_profile_get_session(LASSO_PROFILE(self));
}
#define LassoLecp_set_session LassoLecp_session_set
gint LassoLecp_session_set(LassoLecp *self, LassoSession *session) {
	return lasso_profile_set_session(LASSO_PROFILE(self), session);
}

/* Constructors, destructors & static methods implementations */

#define new_LassoLecp lasso_lecp_new
#define delete_LassoLecp lasso_lecp_destroy

/* Methods inherited from LassoProfile implementations */

gint LassoLecp_setIdentityFromDump(LassoLecp *self, gchar *dump) {
	return lasso_profile_set_identity_from_dump(LASSO_PROFILE(self), dump);
}

gint LassoLecp_setSessionFromDump(LassoLecp *self, gchar *dump) {
	return lasso_profile_set_session_from_dump(LASSO_PROFILE(self), dump);
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
 * NameIdentifierMapping
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(NameIdentifierMapping) LassoNameIdentifierMapping;
#endif
typedef struct {
	%extend {
		/* Attributes inherited from LassoProfile */

		%newobject identity_get;
		LassoIdentity *identity;

		%immutable isIdentityDirty;
		gboolean isIdentityDirty;

		%immutable isSessionDirty;
		gboolean isSessionDirty;

		%immutable msgBody;
		gchar *msgBody;

		%immutable msgUrl;
		gchar *msgUrl;

		%immutable nameIdentifier;
		gchar *nameIdentifier;

		%immutable targetNameIdentifier;
		gchar *targetNameIdentifier;

		%newobject remoteProviderId_get;
		gchar *remoteProviderId;

		%newobject session_get;
		LassoSession *session;

		/* Constructor, Destructor & Static Methods */

		LassoNameIdentifierMapping(LassoServer *server, lassoProviderType provider_type);

		~LassoNameIdentifierMapping();

		/* Methods inherited from LassoProfile */

	        THROW_ERROR
		void setIdentityFromDump(gchar *dump);
		END_THROW_ERROR

		THROW_ERROR
		void setSessionFromDump(gchar *dump);
		END_THROW_ERROR

		/* Methods */

		THROW_ERROR
		void buildRequestMsg();
		END_THROW_ERROR

		THROW_ERROR
		void buildResponseMsg();
		END_THROW_ERROR

		%newobject dump;
		gchar *dump();

		THROW_ERROR
		void initRequest(gchar *targetNameSpace, gchar *remoteProviderId = NULL);
		END_THROW_ERROR

		THROW_ERROR
		void processRequestMsg(gchar *requestMsg, lassoHttpMethod httpMethod);
		END_THROW_ERROR

		THROW_ERROR
		void processResponseMsg(gchar *responseMsg, lassoHttpMethod httpMethod);
		END_THROW_ERROR

		THROW_ERROR
		void validateRequest();
		END_THROW_ERROR
	}
} LassoNameIdentifierMapping;

%{

/* Attributes inherited from LassoProfile implementations */

/* identity */
#define LassoNameIdentifierMapping_get_identity LassoNameIdentifierMapping_identity_get
LassoIdentity *LassoNameIdentifierMapping_identity_get(LassoNameIdentifierMapping *self) {
	return lasso_profile_get_identity(LASSO_PROFILE(self));
}
#define LassoNameIdentifierMapping_set_identity LassoNameIdentifierMapping_identity_set
gint LassoNameIdentifierMapping_identity_set(LassoNameIdentifierMapping *self, LassoIdentity *identity) {
	return lasso_profile_set_identity(LASSO_PROFILE(self), identity);
}

/* isIdentityDirty */
#define LassoNameIdentifierMapping_get_isIdentityDirty LassoNameIdentifierMapping_isIdentityDirty_get
gboolean LassoNameIdentifierMapping_isIdentityDirty_get(LassoNameIdentifierMapping *self) {
	return lasso_profile_is_identity_dirty(LASSO_PROFILE(self));
}

/* isSessionDirty */
#define LassoNameIdentifierMapping_get_isSessionDirty LassoNameIdentifierMapping_isSessionDirty_get
gboolean LassoNameIdentifierMapping_isSessionDirty_get(LassoNameIdentifierMapping *self) {
	return lasso_profile_is_session_dirty(LASSO_PROFILE(self));
}

/* msgBody */
#define LassoNameIdentifierMapping_get_msgBody LassoNameIdentifierMapping_msgBody_get
gchar *LassoNameIdentifierMapping_msgBody_get(LassoNameIdentifierMapping *self) {
	return LASSO_PROFILE(self)->msg_body;
}

/* msgUrl */
#define LassoNameIdentifierMapping_get_msgUrl LassoNameIdentifierMapping_msgUrl_get
gchar *LassoNameIdentifierMapping_msgUrl_get(LassoNameIdentifierMapping *self) {
	return LASSO_PROFILE(self)->msg_url;
}

/* nameIdentifier */
#define LassoNameIdentifierMapping_get_nameIdentifier LassoNameIdentifierMapping_nameIdentifier_get
gchar *LassoNameIdentifierMapping_nameIdentifier_get(LassoNameIdentifierMapping *self) {
	return LASSO_PROFILE(self)->nameIdentifier;
}

/* targetNameIdentifier */
#define LassoNameIdentifierMapping_get_targetNameIdentifier LassoNameIdentifierMapping_targetNameIdentifier_get
gchar *LassoNameIdentifierMapping_targetNameIdentifier_get(LassoNameIdentifierMapping *self) {
	return self->targetNameIdentifier;
}

/* remoteProviderId */
#define LassoNameIdentifierMapping_get_remoteProviderId LassoNameIdentifierMapping_remoteProviderId_get
gchar *LassoNameIdentifierMapping_remoteProviderId_get(LassoNameIdentifierMapping *self) {
	return lasso_profile_get_remote_providerID(LASSO_PROFILE(self));
}
#define LassoNameIdentifierMapping_set_remoteProviderId LassoNameIdentifierMapping_remoteProviderId_set
void LassoNameIdentifierMapping_remoteProviderId_set(LassoNameIdentifierMapping *self, gchar *remoteProviderId) {
	lasso_profile_set_remote_providerID(LASSO_PROFILE(self), remoteProviderId);
}

/* session */
#define LassoNameIdentifierMapping_get_session LassoNameIdentifierMapping_session_get
LassoSession *LassoNameIdentifierMapping_session_get(LassoNameIdentifierMapping *self) {
	return lasso_profile_get_session(LASSO_PROFILE(self));
}
#define LassoNameIdentifierMapping_set_session LassoNameIdentifierMapping_session_set
gint LassoNameIdentifierMapping_session_set(LassoNameIdentifierMapping *self, LassoSession *session) {
	return lasso_profile_set_session(LASSO_PROFILE(self), session);
}

/* Constructors, destructors & static methods implementations */

#define new_LassoNameIdentifierMapping lasso_name_identifier_mapping_new
#define delete_LassoNameIdentifierMapping lasso_name_identifier_mapping_destroy

/* Methods inherited from LassoProfile implementations */

gint LassoNameIdentifierMapping_setIdentityFromDump(LassoNameIdentifierMapping *self, gchar *dump) {
	return lasso_profile_set_identity_from_dump(LASSO_PROFILE(self), dump);
}

gint LassoNameIdentifierMapping_setSessionFromDump(LassoNameIdentifierMapping *self, gchar *dump) {
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
 * NameRegistration
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(NameRegistration) LassoNameRegistration;
#endif
typedef struct {
	%extend {
		/* Attributes inherited from LassoProfile */

		%newobject identity_get;
		LassoIdentity *identity;

		%immutable isIdentityDirty;
		gboolean isIdentityDirty;

		%immutable isSessionDirty;
		gboolean isSessionDirty;

		%immutable msgBody;
		gchar *msgBody;

		%immutable msgRelayState;
		gchar *msgRelayState;

		%immutable msgUrl;
		gchar *msgUrl;

		%immutable nameIdentifier;
		gchar *nameIdentifier;

		%immutable oldNameIdentifier;
		gchar *oldNameIdentifier;

		%newobject remoteProviderId_get;
		gchar *remoteProviderId;

		%newobject session_get;
		LassoSession *session;

		/* Constructor, Destructor & Static Methods */

		LassoNameRegistration(LassoServer *server, lassoProviderType providerType);

		~LassoNameRegistration();

		%newobject newFromDump;
		static LassoNameRegistration *newFromDump(LassoServer *server, gchar *dump);

		/* Methods inherited from LassoProfile */

	        THROW_ERROR
		void setIdentityFromDump(gchar *dump);
		END_THROW_ERROR

		THROW_ERROR
		void setSessionFromDump(gchar *dump);
		END_THROW_ERROR

		/* Methods */

		THROW_ERROR
		void buildRequestMsg();
		END_THROW_ERROR

		THROW_ERROR
		void buildResponseMsg();
		END_THROW_ERROR

		%newobject dump;
		gchar *dump();

		THROW_ERROR
		void initRequest(gchar *remoteProviderId = NULL);
		END_THROW_ERROR

		THROW_ERROR
		void processRequestMsg(gchar *requestMsg, lassoHttpMethod httpMethod);
		END_THROW_ERROR

		THROW_ERROR
		void processResponseMsg(gchar *responseMsg, lassoHttpMethod httpMethod);
		END_THROW_ERROR

		THROW_ERROR
		void validateRequest();
		END_THROW_ERROR
	}
} LassoNameRegistration;

%{

/* Attributes inherited from LassoProfile implementations */

/* identity */
#define LassoNameRegistration_get_identity LassoNameRegistration_identity_get
LassoIdentity *LassoNameRegistration_identity_get(LassoNameRegistration *self) {
	return lasso_profile_get_identity(LASSO_PROFILE(self));
}
#define LassoNameRegistration_set_identity LassoNameRegistration_identity_set
gint LassoNameRegistration_identity_set(LassoNameRegistration *self, LassoIdentity *identity) {
	return lasso_profile_set_identity(LASSO_PROFILE(self), identity);
}

/* isIdentityDirty */
#define LassoNameRegistration_get_isIdentityDirty LassoNameRegistration_isIdentityDirty_get
gboolean LassoNameRegistration_isIdentityDirty_get(LassoNameRegistration *self) {
	return lasso_profile_is_identity_dirty(LASSO_PROFILE(self));
}

/* isSessionDirty */
#define LassoNameRegistration_get_isSessionDirty LassoNameRegistration_isSessionDirty_get
gboolean LassoNameRegistration_isSessionDirty_get(LassoNameRegistration *self) {
	return lasso_profile_is_session_dirty(LASSO_PROFILE(self));
}

/* msgBody */
#define LassoNameRegistration_get_msgBody LassoNameRegistration_msgBody_get
gchar *LassoNameRegistration_msgBody_get(LassoNameRegistration *self) {
	return LASSO_PROFILE(self)->msg_body;
}

/* msgRelayState */
#define LassoNameRegistration_get_msgRelayState LassoNameRegistration_msgRelayState_get
gchar *LassoNameRegistration_msgRelayState_get(LassoNameRegistration *self) {
	return LASSO_PROFILE(self)->msg_relayState;
}

/* msgUrl */
#define LassoNameRegistration_get_msgUrl LassoNameRegistration_msgUrl_get
gchar *LassoNameRegistration_msgUrl_get(LassoNameRegistration *self) {
	return LASSO_PROFILE(self)->msg_url;
}

/* nameIdentifier */
#define LassoNameRegistration_get_nameIdentifier LassoNameRegistration_nameIdentifier_get
gchar *LassoNameRegistration_nameIdentifier_get(LassoNameRegistration *self) {
	return LASSO_PROFILE(self)->nameIdentifier;
}

/* oldNameIdentifier */
#define LassoNameRegistration_get_oldNameIdentifier LassoNameRegistration_oldNameIdentifier_get
gchar *LassoNameRegistration_oldNameIdentifier_get(LassoNameRegistration *self) {
	return self->oldNameIdentifier;
}

/* remoteProviderId */
#define LassoNameRegistration_get_remoteProviderId LassoNameRegistration_remoteProviderId_get
gchar *LassoNameRegistration_remoteProviderId_get(LassoNameRegistration *self) {
	return lasso_profile_get_remote_providerID(LASSO_PROFILE(self));
}
#define LassoNameRegistration_set_remoteProviderId LassoNameRegistration_remoteProviderId_set
void LassoNameRegistration_remoteProviderId_set(LassoNameRegistration *self, gchar *remoteProviderId) {
	lasso_profile_set_remote_providerID(LASSO_PROFILE(self), remoteProviderId);
}

/* session */
#define LassoNameRegistration_get_session LassoNameRegistration_session_get
LassoSession *LassoNameRegistration_session_get(LassoNameRegistration *self) {
	return lasso_profile_get_session(LASSO_PROFILE(self));
}
#define LassoNameRegistration_set_session LassoNameRegistration_session_set
gint LassoNameRegistration_session_set(LassoNameRegistration *self, LassoSession *session) {
	return lasso_profile_set_session(LASSO_PROFILE(self), session);
}

/* Constructors, destructors & static methods implementations */

#define new_LassoNameRegistration lasso_name_registration_new
#define delete_LassoNameRegistration lasso_name_registration_destroy
#ifdef PHP_VERSION
#define LassoNameRegistration_newFromDump lasso_name_registration_new_from_dump
#else
#define NameRegistration_newFromDump lasso_name_registration_new_from_dump
#endif

/* Methods inherited from LassoProfile implementations */

gint LassoNameRegistration_setIdentityFromDump(LassoNameRegistration *self, gchar *dump) {
	return lasso_profile_set_identity_from_dump(LASSO_PROFILE(self), dump);
}

gint LassoNameRegistration_setSessionFromDump(LassoNameRegistration *self, gchar *dump) {
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
