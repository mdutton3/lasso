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
/* Apache fails when lasso_init is called too early in PHP binding. */
/* FIXME: To investigate. */
#ifndef SWIGPHP
%init %{
	lasso_init();
%}
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

#define xmlChar char

/* SWIG instructions telling how to deallocate Lasso structures */

%typemap(newfree) gchar * "g_free($1);";
%typemap(newfree) xmlChar * "xmlFree($1);";

/* Functions */

#ifndef SWIGPHP
%rename(init) lasso_init;
#endif
int lasso_init(void);

#ifndef SWIGPHP
%rename(shutdown) lasso_shutdown;
#endif
int lasso_shutdown(void);


/***********************************************************************
 * Constants
 ***********************************************************************/

/* Version number */
#ifndef SWIGPHP
%rename(VERSION_MAJOR) LASSO_VERSION_MAJOR;
%rename(VERSION_MINOR) LASSO_VERSION_MINOR;
%rename(VERSION_SUBMINOR) LASSO_VERSION_SUBMINOR;
#endif
#define LASSO_VERSION_MAJOR 0
#define LASSO_VERSION_MINOR 3
#define LASSO_VERSION_SUBMINOR 0


/* HttpMethod */
#ifndef SWIGPHP
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
#ifndef SWIGPHP
%rename(libConsentObtained) lassoLibConsentObtained;
%rename(libConsentUnavailable) lassoLibConsentUnavailable;
%rename(libConsentInapplicable) lassoLibConsentInapplicable;
#endif
%constant xmlChar *lassoLibConsentObtained = "urn:liberty:consent:obtained";
%constant xmlChar *lassoLibConsentUnavailable  = "urn:liberty:consent:unavailable";
%constant xmlChar *lassoLibConsentInapplicable = "urn:liberty:consent:inapplicable";

/* NameIdPolicyType */
#ifndef SWIGPHP
%rename(libNameIdPolicyTypeNone) lassoLibNameIDPolicyTypeNone;
%rename(libNameIdPolicyTypeOneTime) lassoLibNameIDPolicyTypeOneTime;
%rename(libNameIdPolicyTypeFederated) lassoLibNameIDPolicyTypeFederated;
%rename(libNameIdPolicyTypeAny) lassoLibNameIDPolicyTypeAny;
#endif
%constant xmlChar *lassoLibNameIDPolicyTypeNone = "none";
%constant xmlChar *lassoLibNameIDPolicyTypeOneTime = "onetime";
%constant xmlChar *lassoLibNameIDPolicyTypeFederated = "federated";
%constant xmlChar *lassoLibNameIDPolicyTypeAny = "any";

/* ProtocolProfile */
#ifndef SWIGPHP
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
%constant xmlChar *lassoLibProtocolProfileBrwsArt = "http://projectliberty.org/profiles/brws-art";
%constant xmlChar *lassoLibProtocolProfileBrwsPost = "http://projectliberty.org/profiles/brws-post";
%constant xmlChar *lassoLibProtocolProfileFedTermIdpHttp = "http://projectliberty.org/profiles/fedterm-idp-http";
%constant xmlChar *lassoLibProtocolProfileFedTermIdpSoap = "http://projectliberty.org/profiles/fedterm-idp-soap";
%constant xmlChar *lassoLibProtocolProfileFedTermSpHttp = "http://projectliberty.org/profiles/fedterm-sp-http";
%constant xmlChar *lassoLibProtocolProfileFedTermSpSoap = "http://projectliberty.org/profiles/fedterm-sp-soap";
%constant xmlChar *lassoLibProtocolProfileRniIdpHttp = "http://projectliberty.org/profiles/rni-idp-http";
%constant xmlChar *lassoLibProtocolProfileRniIdpSoap = "http://projectliberty.org/profiles/rni-idp-soap";
%constant xmlChar *lassoLibProtocolProfileRniSpHttp = "http://projectliberty.org/profiles/rni-sp-http";
%constant xmlChar *lassoLibProtocolProfileRniSpSoap = "http://projectliberty.org/profiles/rni-sp-soap";
%constant xmlChar *lassoLibProtocolProfileSloIdpHttp = "http://projectliberty.org/profiles/slo-idp-http";
%constant xmlChar *lassoLibProtocolProfileSloIdpSoap = "http://projectliberty.org/profiles/slo-idp-soap";
%constant xmlChar *lassoLibProtocolProfileSloSpHttp = "http://projectliberty.org/profiles/slo-sp-http";
%constant xmlChar *lassoLibProtocolProfileSloSpSoap = "http://projectliberty.org/profiles/slo-sp-soap";

/* LoginProtocolProfile */
#ifndef SWIGPHP
%rename(loginProtocolProfileBrwsArt) lassoLoginProtocolProfileBrwsArt;
%rename(loginProtocolProfileBrwsPost) lassoLoginProtocolProfileBrwsPost;
#endif
typedef enum {
	lassoLoginProtocolProfileBrwsArt = 1,
	lassoLoginProtocolProfileBrwsPost,
} lassoLoginProtocolProfile;

/* MessageType */
#ifndef SWIGPHP
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
#ifndef SWIGPHP
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
#ifndef SWIGPHP
%rename(requestTypeInvalid) lassoRequestTypeInvalid;
%rename(requestTypeLogin) lassoRequestTypeLogin;
%rename(requestTypeLogout) lassoRequestTypeLogout;
%rename(requestTypeDefederation) lassoRequestTypeDefederation;
%rename(requestTypeRegisterNameIdentifier) lassoRequestTypeRegisterNameIdentifier;
%rename(requestTypeNameIdentifierMapping) lassoRequestTypeNameIdentifierMapping;
%rename(requestTypeLecp) lassoRequestTypeLecp;
#endif
typedef enum {
	lassoRequestTypeInvalid = 0,
	lassoRequestTypeLogin,
	lassoRequestTypeLogout,
	lassoRequestTypeDefederation,
	lassoRequestTypeRegisterNameIdentifier,
	lassoRequestTypeNameIdentifierMapping,
	lassoRequestTypeLecp
} lassoRequestType;

/* SamlAuthenticationMethod */
#ifndef SWIGPHP
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
%constant xmlChar *lassoSamlAuthenticationMethodPassword = "urn:oasis:names:tc:SAML:1.0:am:password";
%constant xmlChar *lassoSamlAuthenticationMethodKerberos = "urn:ietf:rfc:1510";
%constant xmlChar *lassoSamlAuthenticationMethodSecureRemotePassword = "urn:ietf:rfc:2945";
%constant xmlChar *lassoSamlAuthenticationMethodHardwareToken = "urn:oasis:names:tc:SAML:1.0:am:HardwareToken";
%constant xmlChar *lassoSamlAuthenticationMethodSmartcardPki = "urn:ietf:rfc:2246";
%constant xmlChar *lassoSamlAuthenticationMethodSoftwarePki = "urn:oasis:names:tc:SAML:1.0:am:X509-PKI";
%constant xmlChar *lassoSamlAuthenticationMethodPgp = "urn:oasis:names:tc:SAML:1.0:am:PGP";
%constant xmlChar *lassoSamlAuthenticationMethodSPki = "urn:oasis:names:tc:SAML:1.0:am:SPKI";
%constant xmlChar *lassoSamlAuthenticationMethodXkms = "urn:oasis:names:tc:SAML:1.0:am:XKMS";
%constant xmlChar *lassoSamlAuthenticationMethodXmlDSig = "urn:ietf:rfc:3075";
%constant xmlChar *lassoSamlAuthenticationMethodUnspecified = "urn:oasis:names:tc:SAML:1.0:am:unspecified";

/* SignatureMethod */
#ifndef SWIGPHP
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


#ifndef SWIGPHP
%rename(XML_ERROR_NODE_NOT_FOUND) LASSO_XML_ERROR_NODE_NOT_FOUND;
%rename(XML_ERROR_NODE_CONTENT_NOT_FOUND) LASSO_XML_ERROR_NODE_CONTENT_NOT_FOUND;
%rename(XML_ERROR_ATTR_NOT_FOUND) LASSO_XML_ERROR_ATTR_NOT_FOUND;
%rename(XML_ERROR_ATTR_VALUE_NOT_FOUND) LASSO_XML_ERROR_ATTR_VALUE_NOT_FOUND;
#endif
#define LASSO_XML_ERROR_NODE_NOT_FOUND -10
#define LASSO_XML_ERROR_NODE_CONTENT_NOT_FOUND -11
#define LASSO_XML_ERROR_ATTR_NOT_FOUND -12
#define LASSO_XML_ERROR_ATTR_VALUE_NOT_FOUND -13

#ifndef SWIGPHP
%rename(DS_ERROR_SIGNATURE_TMPL_CREATION_FAILED) LASSO_DS_ERROR_SIGNATURE_TMPL_CREATION_FAILED;
%rename(DS_ERROR_CONTEXT_CREATION_FAILED) LASSO_DS_ERROR_CONTEXT_CREATION_FAILED;
%rename(DS_ERROR_PUBLIC_KEY_LOAD_FAILED) LASSO_DS_ERROR_PUBLIC_KEY_LOAD_FAILED;
%rename(DS_ERROR_PRIVATE_KEY_LOAD_FAILED) LASSO_DS_ERROR_PRIVATE_KEY_LOAD_FAILED;
%rename(DS_ERROR_CERTIFICATE_LOAD_FAILED) LASSO_DS_ERROR_CERTIFICATE_LOAD_FAILED;
%rename(DS_ERROR_SIGNATURE_FAILED) LASSO_DS_ERROR_SIGNATURE_FAILED;
%rename(DS_ERROR_SIGNATURE_NOT_FOUND) LASSO_DS_ERROR_SIGNATURE_NOT_FOUND;
%rename(DS_ERROR_KEYS_MNGR_CREATION_FAILED) LASSO_DS_ERROR_KEYS_MNGR_CREATION_FAILED;
%rename(DS_ERROR_KEYS_MNGR_INIT_FAILED) LASSO_DS_ERROR_KEYS_MNGR_INIT_FAILED;
%rename(DS_ERROR_SIGNATURE_VERIFICATION_FAILED) LASSO_DS_ERROR_SIGNATURE_VERIFICATION_FAILED;
%rename(DS_ERROR_INVALID_SIGNATURE) LASSO_DS_ERROR_INVALID_SIGNATURE;
#endif
#define LASSO_DS_ERROR_SIGNATURE_TMPL_CREATION_FAILED -101
#define LASSO_DS_ERROR_CONTEXT_CREATION_FAILED -102
#define LASSO_DS_ERROR_PUBLIC_KEY_LOAD_FAILED -103
#define LASSO_DS_ERROR_PRIVATE_KEY_LOAD_FAILED -104
#define LASSO_DS_ERROR_CERTIFICATE_LOAD_FAILED -105
#define LASSO_DS_ERROR_SIGNATURE_FAILED -106
#define LASSO_DS_ERROR_SIGNATURE_NOT_FOUND -107
#define LASSO_DS_ERROR_KEYS_MNGR_CREATION_FAILED -108
#define LASSO_DS_ERROR_KEYS_MNGR_INIT_FAILED -109
#define LASSO_DS_ERROR_SIGNATURE_VERIFICATION_FAILED -110
#define LASSO_DS_ERROR_INVALID_SIGNATURE -111

#ifndef SWIGPHP
%rename(SERVER_ERROR_PROVIDER_NOT_FOUND) LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND;
%rename(SERVER_ERROR_ADD_PROVIDER_FAILED) LASSO_SERVER_ERROR_ADD_PROVIDER_FAILED;
#endif
#define LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND -201
#define LASSO_SERVER_ERROR_ADD_PROVIDER_FAILED -202

#ifndef SWIGPHP
%rename(LOGOUT_ERROR_UNSUPPORTED_PROFILE) LASSO_LOGOUT_ERROR_UNSUPPORTED_PROFILE;
#endif
#define LASSO_LOGOUT_ERROR_UNSUPPORTED_PROFILE -301

#ifndef SWIGPHP
%rename(PROFILE_ERROR_INVALID_QUERY) LASSO_PROFILE_ERROR_INVALID_QUERY;
%rename(PROFILE_ERROR_MISSING_REQUEST) LASSO_PROFILE_ERROR_MISSING_REQUEST;
#endif
#define LASSO_PROFILE_ERROR_INVALID_QUERY -401
#define LASSO_PROFILE_ERROR_MISSING_REQUEST -402

#ifndef SWIGPHP
%rename(PARAM_ERROR_BADTYPE_OR_NULL_OBJ) LASSO_PARAM_ERROR_BADTYPE_OR_NULL_OBJ;
%rename(PARAM_ERROR_INVALID_VALUE) LASSO_PARAM_ERROR_INVALID_VALUE;
%rename(PARAM_ERROR_ERR_CHECK_FAILED) LASSO_PARAM_ERROR_ERR_CHECK_FAILED;
#endif
#define LASSO_PARAM_ERROR_BADTYPE_OR_NULL_OBJ -501
#define LASSO_PARAM_ERROR_INVALID_VALUE -502
#define LASSO_PARAM_ERROR_ERR_CHECK_FAILED -503

#ifndef SWIGPHP
%rename(ERROR_UNDEFINED) LASSO_ERROR_UNDEFINED;
#endif
#define LASSO_ERROR_UNDEFINED -999

/* Generate a language independant exception from Lasso error codes. */

%{

int get_exception_type(int errorCode)
{
	if (errorCode == LASSO_PROFILE_ERROR_INVALID_QUERY) 
		return SWIG_SyntaxError;
	else
		return SWIG_UnknownError;
}

%}

/* Wrappers for Lasso functions that return an error code. */

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

%define END_THROW_ERROR
%exception;
%enddef


/***********************************************************************
 ***********************************************************************
 * Protocols
 ***********************************************************************
 ***********************************************************************/

/***********************************************************************
 * Assertion
 ***********************************************************************/


#ifndef SWIG_PHP
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
#define delete_LassoAssertion lasso_assertion_destroy

/* Methods implementations */
void delete_LassoAssertion(LassoAssertion *self){
	lasso_node_destroy(LASSO_NODE(self));
}

gchar* LassoAssertion_dump(LassoAssertion *self){
	return lasso_node_export(LASSO_NODE(self));
}
%}


/***********************************************************************
 * AuthnRequest
 ***********************************************************************/


#ifndef SWIGPHP
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
xmlChar *LassoAuthnRequest_affiliationId_get(LassoAuthnRequest *self) {
	return NULL; /* FIXME */
}
void LassoAuthnRequest_affiliationId_set(LassoAuthnRequest *self, xmlChar *affiliationId) {
	 lasso_lib_authn_request_set_affiliationID(LASSO_LIB_AUTHN_REQUEST(self), affiliationId);
}

/* assertionConsumerServiceId */
xmlChar *LassoAuthnRequest_assertionConsumerServiceId_get(LassoAuthnRequest *self) {
	return NULL; /* FIXME */
}
void LassoAuthnRequest_assertionConsumerServiceId_set(LassoAuthnRequest *self,
						      xmlChar *assertionConsumerServiceId) {
	lasso_lib_authn_request_set_assertionConsumerServiceID(LASSO_LIB_AUTHN_REQUEST(self),
							       assertionConsumerServiceId);
}

/* consent */
xmlChar *LassoAuthnRequest_consent_get(LassoAuthnRequest *self) {
	return NULL; /* FIXME */
}
void LassoAuthnRequest_consent_set(LassoAuthnRequest *self, xmlChar *consent) {
	 lasso_lib_authn_request_set_consent(LASSO_LIB_AUTHN_REQUEST(self), consent);
}

/* forceAuthn */
gboolean LassoAuthnRequest_forceAuthn_get(LassoAuthnRequest *self) {
	return 0; /* FIXME */
}
void LassoAuthnRequest_forceAuthn_set(LassoAuthnRequest *self, gboolean forceAuthn) {
	 lasso_lib_authn_request_set_forceAuthn(LASSO_LIB_AUTHN_REQUEST(self), forceAuthn);
}

/* isPassive */
gboolean LassoAuthnRequest_isPassive_get(LassoAuthnRequest *self) {
	return 0; /* FIXME */
}
void LassoAuthnRequest_isPassive_set(LassoAuthnRequest *self, gboolean isPassive) {
	 lasso_lib_authn_request_set_isPassive(LASSO_LIB_AUTHN_REQUEST(self), isPassive);
}

/* nameIdPolicy */
xmlChar *LassoAuthnRequest_nameIdPolicy_get(LassoAuthnRequest *self) {
	return NULL; /* FIXME */
}
void LassoAuthnRequest_nameIdPolicy_set(LassoAuthnRequest *self, xmlChar *nameIdPolicy) {
	 lasso_lib_authn_request_set_nameIDPolicy(LASSO_LIB_AUTHN_REQUEST(self), nameIdPolicy);
}

/* protocolProfile */
xmlChar *LassoAuthnRequest_protocolProfile_get(LassoAuthnRequest *self) {
	return NULL; /* FIXME */
}
void LassoAuthnRequest_protocolProfile_set(LassoAuthnRequest *self, xmlChar *protocolProfile) {
	 lasso_lib_authn_request_set_protocolProfile(LASSO_LIB_AUTHN_REQUEST(self),
						     protocolProfile);
}

/* providerId */
xmlChar *LassoAuthnRequest_providerId_get(LassoAuthnRequest *self) {
	return NULL; /* FIXME */
}
void LassoAuthnRequest_providerId_set(LassoAuthnRequest *self, xmlChar *providerId) {
	 lasso_lib_authn_request_set_providerID(LASSO_LIB_AUTHN_REQUEST(self), providerId);
}

/* relayState */
xmlChar *LassoAuthnRequest_relayState_get(LassoAuthnRequest *self) {
	return NULL; /* FIXME */
}
void LassoAuthnRequest_relayState_set(LassoAuthnRequest *self, xmlChar *relayState) {
	 lasso_lib_authn_request_set_relayState(LASSO_LIB_AUTHN_REQUEST(self), relayState);
}

%}


/***********************************************************************
 * AuthnResponse
 ***********************************************************************/


#ifndef SWIGPHP
%rename(AuthnResponse) LassoAuthnResponse;
#endif
%nodefault LassoAuthnResponse;
typedef struct {
} LassoAuthnResponse;


/***********************************************************************
 * FederationTerminationNotification
 ***********************************************************************/


#ifndef SWIGPHP
%rename(FederationTerminationNotification) LassoFederationTerminationNotification;
#endif
%nodefault LassoFederationTerminationNotification;
typedef struct {
	/* FIXME: Add a relayState when Lasso supports it. */
} LassoFederationTerminationNotification;


/***********************************************************************
 * LogoutRequest
 ***********************************************************************/


#ifndef SWIGPHP
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
xmlChar *LassoLogoutRequest_relayState_get(LassoLogoutRequest *self) {
	return NULL; /* FIXME */
}
void LassoLogoutRequest_relayState_set(LassoLogoutRequest *self, xmlChar *relayState) {
	 lasso_lib_logout_request_set_relayState(LASSO_LIB_LOGOUT_REQUEST(self), relayState);
}

%}


/***********************************************************************
 * LogoutResponse
 ***********************************************************************/


#ifndef SWIGPHP
%rename(LogoutResponse) LassoLogoutResponse;
#endif
%nodefault LassoLogoutResponse;
typedef struct {
} LassoLogoutResponse;


/***********************************************************************
 * Request
 ***********************************************************************/


#ifndef SWIGPHP
%rename(Request) LassoRequest;
#endif
%nodefault LassoRequest;
typedef struct {
} LassoRequest;


/***********************************************************************
 * Response
 ***********************************************************************/


#ifndef SWIGPHP
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


#ifndef SWIGPHP
%rename(Server) LassoServer;
#endif
typedef struct {
	%extend {
		/* Attributes */

		%immutable providerId;
		gchar *providerId;

		/* Constructor, destructor & static methods */

		LassoServer(gchar *metadata = NULL, gchar *publicKey = NULL,
			    gchar *privateKey = NULL, gchar *certificate = NULL,
			    lassoSignatureMethod signatureMethod = lassoSignatureMethodRsaSha1);

		~LassoServer();

		%newobject newFromDump;
		static LassoServer *newFromDump(gchar *dump);

		/* Methods */

	        THROW_ERROR
		void addProvider(gchar *metadata, gchar *publicKey = NULL,
				 gchar *caCertificate = NULL);
		END_THROW_ERROR

		%newobject dump;
		gchar *dump();
	}
} LassoServer;

%{

/* Attributes implementations */

/* providerID */
gchar *LassoServer_providerId_get(LassoServer *self) {
	return self->providerID;
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


#ifndef SWIG_PHP
%rename(Identity) LassoIdentity;
#endif
typedef struct {
	%extend {
		/* Attributes */

		%immutable isDirty;
		gboolean isDirty;

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
gboolean LassoIdentity_isDirty_get(LassoIdentity *self) {
	return self->is_dirty;
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


#ifndef SWIG_PHP
%rename(Session) LassoSession;
#endif
typedef struct {
	%extend {
		/* Attributes */

		%immutable isDirty;
		gboolean isDirty;

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
gboolean LassoSession_isDirty_get(LassoSession *self) {
	return self->is_dirty;
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

#ifdef SWIGPHP
%rename(lasso_getRequestTypeFromSoapMsg) lasso_profile_get_request_type_from_soap_msg;
#else
%rename(getRequestTypeFromSoapMsg) lasso_profile_get_request_type_from_soap_msg;
#endif
lassoRequestType lasso_profile_get_request_type_from_soap_msg(gchar *soap);


/***********************************************************************
 * Defederation
 ***********************************************************************/


#ifndef SWIGPHP
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
		void initNotification(gchar *remoteProviderId,
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
LassoIdentity *LassoDefederation_identity_get(LassoDefederation *self) {
	return lasso_profile_get_identity(LASSO_PROFILE(self));
}
gint LassoDefederation_identity_set(LassoDefederation *self, LassoIdentity *identity) {
	return lasso_profile_set_identity(LASSO_PROFILE(self), identity);
}

/* isIdentityDirty */
gboolean LassoDefederation_isIdentityDirty_get(LassoDefederation *self) {
	return lasso_profile_is_identity_dirty(LASSO_PROFILE(self));
}

/* isSessionDirty */
gboolean LassoDefederation_isSessionDirty_get(LassoDefederation *self) {
	return lasso_profile_is_session_dirty(LASSO_PROFILE(self));
}

/* msgBody */
gchar *LassoDefederation_msgBody_get(LassoDefederation *self) {
	return LASSO_PROFILE(self)->msg_body;
}

/* msgRelayState */
gchar *LassoDefederation_msgRelayState_get(LassoDefederation *self) {
	return LASSO_PROFILE(self)->msg_relayState;
}

/* msgUrl */
gchar *LassoDefederation_msgUrl_get(LassoDefederation *self) {
	return LASSO_PROFILE(self)->msg_url;
}

/* nameIdentifier */
gchar *LassoDefederation_nameIdentifier_get(LassoDefederation *self) {
	return LASSO_PROFILE(self)->nameIdentifier;
}

/* remoteProviderId */
gchar *LassoDefederation_remoteProviderId_get(LassoDefederation *self) {
	return NULL; /* FIXME */
}
void LassoDefederation_remoteProviderId_set(LassoDefederation *self, gchar *remoteProviderId) {
	lasso_profile_set_remote_providerID(LASSO_PROFILE(self), remoteProviderId);
}

/* request */
LassoFederationTerminationNotification *LassoDefederation_request_get(LassoDefederation *self) {
	return LASSO_FEDERATION_TERMINATION_NOTIFICATION(LASSO_PROFILE(self)->request);
}

/* responseStatus */
gchar *LassoDefederation_responseStatus_get(LassoDefederation *self) {
	return NULL; /* FIXME */
}
void LassoDefederation_responseStatus_set(LassoDefederation *self, gchar *responseStatus) {
	lasso_profile_set_response_status(LASSO_PROFILE(self), responseStatus);
}

/* session */
LassoSession *LassoDefederation_session_get(LassoDefederation *self) {
	return lasso_profile_get_session(LASSO_PROFILE(self));
}
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


#ifndef SWIGPHP
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

		gchar *remoteProviderId;

		%immutable request;
		LassoRequest *request;

		%immutable response;
		LassoResponse *response;

		%immutable responseDump;
		gchar *responseDump;

		gchar *responseStatus;

		%newobject session_get;
		LassoSession *session;

		/* Attributes */

		%newobject assertion_get;
		LassoAssertion *assertion;


		/* Constructor, Destructor & Static Methods */

		LassoLogin(LassoServer *server);

		~LassoLogin();

		%newobject newFromDump;
		static LassoLogin *newFromDump(LassoServer *server, gchar *dump);

		/* Methods inherited from LassoProfile */

	        THROW_ERROR
		void setAssertionFromDump(gchar *dump);
		END_THROW_ERROR

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
		void buildArtifactMsg(gint authenticationResult, gchar *authenticationMethod,
				      gchar *reauthenticateOnOrAfter, lassoHttpMethod httpMethod);
		END_THROW_ERROR

		THROW_ERROR
		void buildAuthnRequestMsg(gchar *remoteProviderId);
		END_THROW_ERROR

		THROW_ERROR
		void buildAuthnResponseMsg(gint authenticationResult, gchar *authenticationMethod,
					   gchar *reauthenticateOnOrAfter);
		END_THROW_ERROR

		THROW_ERROR
		void buildRequestMsg();
		END_THROW_ERROR

		THROW_ERROR
		void buildResponseMsg();
		END_THROW_ERROR

		%newobject dump;
		gchar *dump();

		THROW_ERROR
		void initAuthnRequest(lassoHttpMethod httpMethod);
		END_THROW_ERROR

		THROW_ERROR
		void initFromAuthnRequestMsg(gchar *authnrequestMsg, lassoHttpMethod httpMethod);
		END_THROW_ERROR

		THROW_ERROR
		void initRequest(gchar *responseMsg,
				 lassoHttpMethod httpMethod = lassoHttpMethodRedirect);
		END_THROW_ERROR

		gboolean mustAuthenticate();

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
LassoAuthnRequest *LassoLogin_authnRequest_get(LassoLogin *self) {
	LassoProfile *profile = LASSO_PROFILE(self);
	if (profile->request_type == lassoMessageTypeAuthnRequest)
		return LASSO_AUTHN_REQUEST(profile->request);
	else
		return NULL;
}

/* authnResponse */
LassoAuthnResponse *LassoLogin_authnResponse_get(LassoLogin *self) {
	LassoProfile *profile = LASSO_PROFILE(self);
	if (profile->response_type == lassoMessageTypeAuthnResponse)
		return LASSO_AUTHN_RESPONSE(profile->response);
	else
		return NULL;
}

/* identity */
LassoIdentity *LassoLogin_identity_get(LassoLogin *self) {
	return lasso_profile_get_identity(LASSO_PROFILE(self));
}
gint LassoLogin_identity_set(LassoLogin *self, LassoIdentity *identity) {
	return lasso_profile_set_identity(LASSO_PROFILE(self), identity);
}

/* isIdentityDirty */
gboolean LassoLogin_isIdentityDirty_get(LassoLogin *self) {
	return lasso_profile_is_identity_dirty(LASSO_PROFILE(self));
}

/* isSessionDirty */
gboolean LassoLogin_isSessionDirty_get(LassoLogin *self) {
	return lasso_profile_is_session_dirty(LASSO_PROFILE(self));
}

/* msgBody */
gchar *LassoLogin_msgBody_get(LassoLogin *self) {
	return LASSO_PROFILE(self)->msg_body;
}

/* msgRelayState */
gchar *LassoLogin_msgRelayState_get(LassoLogin *self) {
	return LASSO_PROFILE(self)->msg_relayState;
}

/* msgUrl */
gchar *LassoLogin_msgUrl_get(LassoLogin *self) {
	return LASSO_PROFILE(self)->msg_url;
}

/* nameIdentifier */
gchar *LassoLogin_nameIdentifier_get(LassoLogin *self) {
	return LASSO_PROFILE(self)->nameIdentifier;
}

/* remoteProviderId */
gchar *LassoLogin_remoteProviderId_get(LassoLogin *self) {
	return NULL; /* FIXME */
}
void LassoLogin_remoteProviderId_set(LassoLogin *self, gchar *remoteProviderId) {
	lasso_profile_set_remote_providerID(LASSO_PROFILE(self), remoteProviderId);
}

/* request */
LassoRequest *LassoLogin_request_get(LassoLogin *self) {
	LassoProfile *profile = LASSO_PROFILE(self);
	if (profile->request_type == lassoMessageTypeRequest)
		return LASSO_REQUEST(profile->request);
	else
		return NULL;
}

/* response */
LassoResponse *LassoLogin_response_get(LassoLogin *self) {
	LassoProfile *profile = LASSO_PROFILE(self);
	if (profile->response_type == lassoMessageTypeResponse)
		return LASSO_RESPONSE(profile->response);
	else
		return NULL;
}

/* responseDump */
gchar *LassoLogin_responseDump_get(LassoLogin *self) {
	return self->response_dump;
}

/* responseStatus */
gchar *LassoLogin_responseStatus_get(LassoLogin *self) {
	return NULL; /* FIXME */
}
void LassoLogin_responseStatus_set(LassoLogin *self, gchar *responseStatus) {
	lasso_profile_set_response_status(LASSO_PROFILE(self), responseStatus);
}

/* session */
LassoSession *LassoLogin_session_get(LassoLogin *self) {
	return lasso_profile_get_session(LASSO_PROFILE(self));
}
gint LassoLogin_session_set(LassoLogin *self, LassoSession *session) {
	return lasso_profile_set_session(LASSO_PROFILE(self), session);
}

/* Attributes from LassoLogin implementations */

/* assertion */
LassoAssertion *LassoLogin_assertion_get(LassoLogin *self) {
	return lasso_login_get_assertion(self);
}
gint LassoLogin_assertion_set(LassoLogin *self, LassoAssertion *assertion) {
	return lasso_login_set_assertion(self, assertion);
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

/* Methods */

/* assertion */
gint LassoLogin_setAssertionFromDump(LassoLogin *self, gchar *dump) {
	return lasso_login_set_assertion_from_dump(self, dump);
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
#define LassoLogin_initFromAuthnRequestMsg lasso_login_init_from_authn_request_msg
#define LassoLogin_initRequest lasso_login_init_request
#define LassoLogin_mustAuthenticate lasso_login_must_authenticate
#define LassoLogin_processAuthnResponseMsg lasso_login_process_authn_response_msg
#define LassoLogin_processRequestMsg lasso_login_process_request_msg
#define LassoLogin_processResponseMsg lasso_login_process_response_msg

%}


/***********************************************************************
 * Logout
 ***********************************************************************/


#ifndef SWIGPHP
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
LassoIdentity *LassoLogout_identity_get(LassoLogout *self) {
	return lasso_profile_get_identity(LASSO_PROFILE(self));
}
gint LassoLogout_identity_set(LassoLogout *self, LassoIdentity *identity) {
	return lasso_profile_set_identity(LASSO_PROFILE(self), identity);
}

/* isIdentityDirty */
gboolean LassoLogout_isIdentityDirty_get(LassoLogout *self) {
	return lasso_profile_is_identity_dirty(LASSO_PROFILE(self));
}

/* isSessionDirty */
gboolean LassoLogout_isSessionDirty_get(LassoLogout *self) {
	return lasso_profile_is_session_dirty(LASSO_PROFILE(self));
}

/* msgBody */
gchar *LassoLogout_msgBody_get(LassoLogout *self) {
	return LASSO_PROFILE(self)->msg_body;
}

/* msgRelayState */
gchar *LassoLogout_msgRelayState_get(LassoLogout *self) {
	return LASSO_PROFILE(self)->msg_relayState;
}

/* msgUrl */
gchar *LassoLogout_msgUrl_get(LassoLogout *self) {
	return LASSO_PROFILE(self)->msg_url;
}

/* nameIdentifier */
gchar *LassoLogout_nameIdentifier_get(LassoLogout *self) {
	return LASSO_PROFILE(self)->nameIdentifier;
}

/* remoteProviderId */
gchar *LassoLogout_remoteProviderId_get(LassoLogout *self) {
	return NULL; /* FIXME */
}
void LassoLogout_remoteProviderId_set(LassoLogout *self, gchar *remoteProviderId) {
	lasso_profile_set_remote_providerID(LASSO_PROFILE(self), remoteProviderId);
}

/* request */
LassoLogoutRequest *LassoLogout_request_get(LassoLogout *self) {
	return LASSO_LOGOUT_REQUEST(LASSO_PROFILE(self)->request);
}

/* response */
LassoLogoutResponse *LassoLogout_response_get(LassoLogout *self) {
	return LASSO_LOGOUT_RESPONSE(LASSO_PROFILE(self)->response);
}

/* responseStatus */
gchar *LassoLogout_responseStatus_get(LassoLogout *self) {
	return NULL; /* FIXME */
}
void LassoLogout_responseStatus_set(LassoLogout *self, gchar *responseStatus) {
	lasso_profile_set_response_status(LASSO_PROFILE(self), responseStatus);
}

/* session */
LassoSession *LassoLogout_session_get(LassoLogout *self) {
	return lasso_profile_get_session(LASSO_PROFILE(self));
}
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


#ifndef SWIGPHP
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
		void buildAuthnRequestMsg(gchar *remoteProviderId);
		END_THROW_ERROR

		THROW_ERROR
		void buildAuthnResponseEnvelopeMsg(gint authenticationResult,
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
		void initFromAuthnRequestMsg(gchar *authnRequestMsg, lassoHttpMethod httpMethod);
		END_THROW_ERROR

		THROW_ERROR
		void processAuthnRequestEnvelopeMsg(gchar *requestMsg);
		END_THROW_ERROR

		THROW_ERROR
		void processAuthnResponseEnvelopeMsg(gchar *responseMsg);
		END_THROW_ERROR
	}
} LassoLecp;

%{

/* Attributes inherited from LassoProfile implementations */

/* authnRequest */
LassoAuthnRequest *LassoLecp_authnRequest_get(LassoLecp *self) {
	LassoProfile *profile = LASSO_PROFILE(self);
	if (profile->request_type == lassoMessageTypeAuthnRequest)
		return LASSO_AUTHN_REQUEST(profile->request);
	else
		return NULL;
}

/* authnResponse */
LassoAuthnResponse *LassoLecp_authnResponse_get(LassoLecp *self) {
	LassoProfile *profile = LASSO_PROFILE(self);
	if (profile->response_type == lassoMessageTypeAuthnResponse)
		return LASSO_AUTHN_RESPONSE(profile->response);
	else
		return NULL;
}

/* identity */
LassoIdentity *LassoLecp_identity_get(LassoLecp *self) {
	return lasso_profile_get_identity(LASSO_PROFILE(self));
}
gint LassoLecp_identity_set(LassoLecp *self, LassoIdentity *identity) {
	return lasso_profile_set_identity(LASSO_PROFILE(self), identity);
}

/* isIdentityDirty */
gboolean LassoLecp_isIdentityDirty_get(LassoLecp *self) {
	return lasso_profile_is_identity_dirty(LASSO_PROFILE(self));
}

/* isSessionDirty */
gboolean LassoLecp_isSessionDirty_get(LassoLecp *self) {
	return lasso_profile_is_session_dirty(LASSO_PROFILE(self));
}

/* msgBody */
gchar *LassoLecp_msgBody_get(LassoLecp *self) {
	return LASSO_PROFILE(self)->msg_body;
}

/* msgRelayState */
gchar *LassoLecp_msgRelayState_get(LassoLecp *self) {
	return LASSO_PROFILE(self)->msg_relayState;
}

/* msgUrl */
gchar *LassoLecp_msgUrl_get(LassoLecp *self) {
	return LASSO_PROFILE(self)->msg_url;
}

/* nameIdentifier */
gchar *LassoLecp_nameIdentifier_get(LassoLecp *self) {
	return LASSO_PROFILE(self)->nameIdentifier;
}

/* remoteProviderId */
gchar *LassoLecp_remoteProviderId_get(LassoLecp *self) {
	return NULL; /* FIXME */
}
void LassoLecp_remoteProviderId_set(LassoLecp *self, gchar *remoteProviderId) {
	lasso_profile_set_remote_providerID(LASSO_PROFILE(self), remoteProviderId);
}

/* request */
LassoRequest *LassoLecp_request_get(LassoLecp *self) {
	LassoProfile *profile = LASSO_PROFILE(self);
	if (profile->request_type == lassoMessageTypeRequest)
		return LASSO_REQUEST(profile->request);
	else
		return NULL;
}

/* response */
LassoResponse *LassoLecp_response_get(LassoLecp *self) {
	LassoProfile *profile = LASSO_PROFILE(self);
	if (profile->response_type == lassoMessageTypeResponse)
		return LASSO_RESPONSE(profile->response);
	else
		return NULL;
}

/* responseStatus */
gchar *LassoLecp_responseStatus_get(LassoLecp *self) {
	return NULL; /* FIXME */
}
void LassoLecp_responseStatus_set(LassoLecp *self, gchar *responseStatus) {
	lasso_profile_set_response_status(LASSO_PROFILE(self), responseStatus);
}

/* session */
LassoSession *LassoLecp_session_get(LassoLecp *self) {
	return lasso_profile_get_session(LASSO_PROFILE(self));
}
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
#define LassoLecp_initFromAuthnRequestMsg lasso_lecp_init_from_authn_request_msg
#define LassoLecp_processAuthnRequestEnvelopeMsg lasso_lecp_process_authn_request_envelope_msg
#define LassoLecp_processAuthnResponseEnvelopeMsg lasso_lecp_process_authn_response_envelope_msg

%}
