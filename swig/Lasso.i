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
%init %{
	lasso_init();
%}
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

%rename(init) lasso_init;
int lasso_init(void);

%rename(shutdown) lasso_shutdown;
int lasso_shutdown(void);


/***********************************************************************
 * Constants
 ***********************************************************************/


/* HttpMethod */
%rename(httpMethodAny) lassoHttpMethodAny;
%rename(httpMethodGet) lassoHttpMethodGet;
%rename(httpMethodPost) lassoHttpMethodPost;
%rename(httpMethodRedirect) lassoHttpMethodRedirect;
%rename(httpMethodSoap) lassoHttpMethodSoap;
typedef enum {
	lassoHttpMethodAny = 0,
	lassoHttpMethodGet,
	lassoHttpMethodPost,
	lassoHttpMethodRedirect,
	lassoHttpMethodSoap
} lassoHttpMethod;

/* Consent */
%rename(libConsentObtained) lassoLibConsentObtained;
%rename(libConsentUnavailable) lassoLibConsentUnavailable;
%rename(libConsentInapplicable) lassoLibConsentInapplicable;
%constant xmlChar *lassoLibConsentObtained = "urn:liberty:consent:obtained";
%constant xmlChar *lassoLibConsentUnavailable  = "urn:liberty:consent:unavailable";
%constant xmlChar *lassoLibConsentInapplicable = "urn:liberty:consent:inapplicable";

/* NameIdPolicyType */
%rename(libNameIdPolicyTypeNone) lassoLibNameIDPolicyTypeNone;
%rename(libNameIdPolicyTypeOneTime) lassoLibNameIDPolicyTypeOneTime;
%rename(libNameIdPolicyTypeFederated) lassoLibNameIDPolicyTypeFederated;
%rename(libNameIdPolicyTypeAny) lassoLibNameIDPolicyTypeAny;
%constant xmlChar *lassoLibNameIDPolicyTypeNone = "none";
%constant xmlChar *lassoLibNameIDPolicyTypeOneTime = "onetime";
%constant xmlChar *lassoLibNameIDPolicyTypeFederated = "federated";
%constant xmlChar *lassoLibNameIDPolicyTypeAny = "any";

/* ProtocolProfile */
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
%rename(loginProtocolProfileBrwsArt) lassoLoginProtocolProfileBrwsArt;
%rename(loginProtocolProfileBrwsPost) lassoLoginProtocolProfileBrwsPost;
typedef enum {
	lassoLoginProtocolProfileBrwsArt = 1,
	lassoLoginProtocolProfileBrwsPost,
} lassoLoginProtocolProfile;

/* MessageType */
%rename(messageTypeNone) lassoMessageTypeNone;
%rename(messageTypeAuthnRequest) lassoMessageTypeAuthnRequest;
%rename(messageTypeAuthnResponse) lassoMessageTypeAuthnResponse;
%rename(messageTypeRequest) lassoMessageTypeRequest;
%rename(messageTypeResponse) lassoMessageTypeResponse;
%rename(messageTypeArtifact) lassoMessageTypeArtifact;
typedef enum {
	lassoMessageTypeNone = 0,
	lassoMessageTypeAuthnRequest,
	lassoMessageTypeAuthnResponse,
	lassoMessageTypeRequest,
	lassoMessageTypeResponse,
	lassoMessageTypeArtifact
} lassoMessageType;

/* ProviderType */
%rename(providerTypeNone) lassoProviderTypeNone;
%rename(providerTypeSp) lassoProviderTypeSp;
%rename(providerTypeIdp) lassoProviderTypeIdp;
typedef enum {
	lassoProviderTypeNone = 0,
	lassoProviderTypeSp,
	lassoProviderTypeIdp
} lassoProviderType;

/* RequestType */
%rename(requestTypeInvalid) lassoRequestTypeInvalid;
%rename(requestTypeLogin) lassoRequestTypeLogin;
%rename(requestTypeLogout) lassoRequestTypeLogout;
%rename(requestTypeDefederation) lassoRequestTypeDefederation;
%rename(requestTypeRegisterNameIdentifier) lassoRequestTypeRegisterNameIdentifier;
%rename(requestTypeNameIdentifierMapping) lassoRequestTypeNameIdentifierMapping;
%rename(requestTypeLecp) lassoRequestTypeLecp;
typedef enum {
	lassoRequestTypeInvalid = 0,
	lassoRequestTypeLogin,
	lassoRequestTypeLogout,
	lassoRequestTypeDefederation,
	lassoRequestTypeRegisterNameIdentifier,
	lassoRequestTypeNameIdentifierMapping,
	lassoRequestTypeLecp
} lassoRequestType;

/* SamelAuthenticationMethod */
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
%rename(signatureMethodRsaSha1) lassoSignatureMethodRsaSha1;
%rename(signatureMethodDsaSha1) lassoSignatureMethodDsaSha1;
typedef enum {
	lassoSignatureMethodRsaSha1 = 1,
	lassoSignatureMethodDsaSha1
} lassoSignatureMethod;


/***********************************************************************
 * Errors
 ***********************************************************************/


%rename(XML_ERROR_NODE_NOT_FOUND) LASSO_XML_ERROR_NODE_NOT_FOUND;
#define LASSO_XML_ERROR_NODE_NOT_FOUND -10
%rename(XML_ERROR_NODE_CONTENT_NOT_FOUND) LASSO_XML_ERROR_NODE_CONTENT_NOT_FOUND;
#define LASSO_XML_ERROR_NODE_CONTENT_NOT_FOUND -11
%rename(XML_ERROR_ATTR_NOT_FOUND) LASSO_XML_ERROR_ATTR_NOT_FOUND;
#define LASSO_XML_ERROR_ATTR_NOT_FOUND -12
%rename(XML_ERROR_ATTR_VALUE_NOT_FOUND) LASSO_XML_ERROR_ATTR_VALUE_NOT_FOUND;
#define LASSO_XML_ERROR_ATTR_VALUE_NOT_FOUND -13

%rename(DS_ERROR_SIGNATURE_TMPL_CREATION_FAILED) LASSO_DS_ERROR_SIGNATURE_TMPL_CREATION_FAILED;
#define LASSO_DS_ERROR_SIGNATURE_TMPL_CREATION_FAILED -101
%rename(DS_ERROR_CONTEXT_CREATION_FAILED) LASSO_DS_ERROR_CONTEXT_CREATION_FAILED;
#define LASSO_DS_ERROR_CONTEXT_CREATION_FAILED -102
%rename(DS_ERROR_PUBLIC_KEY_LOAD_FAILED) LASSO_DS_ERROR_PUBLIC_KEY_LOAD_FAILED;
#define LASSO_DS_ERROR_PUBLIC_KEY_LOAD_FAILED -103
%rename(DS_ERROR_PRIVATE_KEY_LOAD_FAILED) LASSO_DS_ERROR_PRIVATE_KEY_LOAD_FAILED;
#define LASSO_DS_ERROR_PRIVATE_KEY_LOAD_FAILED -104
%rename(DS_ERROR_CERTIFICATE_LOAD_FAILED) LASSO_DS_ERROR_CERTIFICATE_LOAD_FAILED;
#define LASSO_DS_ERROR_CERTIFICATE_LOAD_FAILED -105
%rename(DS_ERROR_SIGNATURE_FAILED) LASSO_DS_ERROR_SIGNATURE_FAILED;
#define LASSO_DS_ERROR_SIGNATURE_FAILED -106
%rename(DS_ERROR_SIGNATURE_NOT_FOUND) LASSO_DS_ERROR_SIGNATURE_NOT_FOUND;
#define LASSO_DS_ERROR_SIGNATURE_NOT_FOUND -107
%rename(DS_ERROR_KEYS_MNGR_CREATION_FAILED) LASSO_DS_ERROR_KEYS_MNGR_CREATION_FAILED;
#define LASSO_DS_ERROR_KEYS_MNGR_CREATION_FAILED -108
%rename(DS_ERROR_KEYS_MNGR_INIT_FAILED) LASSO_DS_ERROR_KEYS_MNGR_INIT_FAILED;
#define LASSO_DS_ERROR_KEYS_MNGR_INIT_FAILED -109
%rename(DS_ERROR_SIGNATURE_VERIFICATION_FAILED) LASSO_DS_ERROR_SIGNATURE_VERIFICATION_FAILED;
#define LASSO_DS_ERROR_SIGNATURE_VERIFICATION_FAILED -110
%rename(DS_ERROR_INVALID_SIGNATURE) LASSO_DS_ERROR_INVALID_SIGNATURE;
#define LASSO_DS_ERROR_INVALID_SIGNATURE -111

%rename(SERVER_ERROR_PROVIDER_NOT_FOUND) LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND;
#define LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND -201
%rename(SERVER_ERROR_ADD_PROVIDER_FAILED) LASSO_SERVER_ERROR_ADD_PROVIDER_FAILED;
#define LASSO_SERVER_ERROR_ADD_PROVIDER_FAILED -202

%rename(LOGOUT_ERROR_UNSUPPORTED_PROFILE) LASSO_LOGOUT_ERROR_UNSUPPORTED_PROFILE;
#define LASSO_LOGOUT_ERROR_UNSUPPORTED_PROFILE -301

%rename(PROFILE_ERROR_INVALID_QUERY) LASSO_PROFILE_ERROR_INVALID_QUERY;
#define LASSO_PROFILE_ERROR_INVALID_QUERY -401

%rename(PARAM_ERROR_BADTYPE_OR_NULL_OBJ) LASSO_PARAM_ERROR_BADTYPE_OR_NULL_OBJ;
#define LASSO_PARAM_ERROR_BADTYPE_OR_NULL_OBJ -501
%rename(PARAM_ERROR_INVALID_VALUE) LASSO_PARAM_ERROR_INVALID_VALUE;
#define LASSO_PARAM_ERROR_INVALID_VALUE -502
%rename(PARAM_ERROR_ERR_CHECK_FAILED) LASSO_PARAM_ERROR_ERR_CHECK_FAILED;
#define LASSO_PARAM_ERROR_ERR_CHECK_FAILED -503

%rename(ERROR_UNDEFINED) LASSO_ERROR_UNDEFINED;
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
 * AuthnRequest
 ***********************************************************************/


%rename(AuthnRequest) LassoAuthnRequest;
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


%rename(AuthnResponse) LassoAuthnResponse;
%nodefault LassoAuthnResponse;
typedef struct {
} LassoAuthnResponse;

/* Methods */

%newobject lasso_authn_response_get_status;
xmlChar *lasso_authn_response_get_status(LassoAuthnResponse *response);


/***********************************************************************
 * Request
 ***********************************************************************/


%rename(Request) LassoRequest;
%nodefault LassoRequest;
typedef struct {
} LassoRequest;


/***********************************************************************
 * Response
 ***********************************************************************/


%rename(Response) LassoResponse;
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


%rename(Server) LassoServer;
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
#define Server_newFromDump lasso_server_new_from_dump

/* Methods implementations */

#define LassoServer_addProvider lasso_server_add_provider
#define LassoServer_dump lasso_server_dump

%}

/* Constructors */

%newobject lasso_server_new;
LassoServer *lasso_server_new(gchar *metadata = NULL, gchar *publicKey = NULL,
			      gchar *privateKey = NULL, gchar *certificate = NULL,
			      lassoSignatureMethod signatureMethod = lassoSignatureMethodRsaSha1);

%newobject lasso_server_new_from_dump;
LassoServer *lasso_server_new_from_dump(gchar *dump);

/* Destructor */

void lasso_server_destroy(LassoServer *server);

/* Methods */

gint lasso_server_add_provider(LassoServer *server, gchar *metadata, gchar *publicKey = NULL,
			       gchar *caCertificate = NULL);

%newobject lasso_server_dump;
gchar *lasso_server_dump(LassoServer *server);


/***********************************************************************
 * Identity
 ***********************************************************************/


%rename(Identity) LassoIdentity;
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
#define Identity_newFromDump lasso_identity_new_from_dump

/* Methods implementations */

#define LassoIdentity_dump lasso_identity_dump

%}

/* Constructors */

%newobject lasso_identity_new;
LassoIdentity *lasso_identity_new(void);

%newobject lasso_identity_new_from_dump;
LassoIdentity *lasso_identity_new_from_dump(gchar *dump);

/* Destructor */

void lasso_identity_destroy(LassoIdentity *identity);

/* Methods */

%newobject lasso_identity_dump;
gchar *lasso_identity_dump(LassoIdentity *identity);


/***********************************************************************
 * Session
 ***********************************************************************/


%rename(Session) LassoSession;
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
		gchar *getAuthenticationMethod(gchar *remoteProviderId);
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
#define Session_newFromDump lasso_session_new_from_dump

/* Methods implementations */

#define LassoSession_dump lasso_session_dump
#define LassoSession_getAuthenticationMethod lasso_session_get_authentication_method

%}

/* Constructors */

%newobject lasso_session_new;
LassoSession *lasso_session_new(void);

%newobject lasso_session_new_from_dump;
LassoSession *lasso_session_new_from_dump(gchar *dump);

/* Destructor */

void lasso_session_destroy(LassoSession *session);

/* Methods */

%newobject lasso_session_dump;
gchar *lasso_session_dump(LassoSession *session);

%newobject lasso_session_get_authentication_method;
gchar *lasso_session_get_authentication_method(LassoSession *session, gchar *remoteProviderId);


/***********************************************************************
 * Profile
 ***********************************************************************/


%{

/* Attributes Implementations */

/* authnRequest */
LassoAuthnRequest *LassoProfile_authnRequest_get(LassoProfile *profile) {
	if (profile->request_type == lassoMessageTypeAuthnRequest)
		return LASSO_AUTHN_REQUEST(profile->request);
	else
		return NULL;
}

/* authnResponse */
LassoAuthnResponse *LassoProfile_authnResponse_get(LassoProfile *profile) {
	if (profile->response_type == lassoMessageTypeAuthnResponse)
		return LASSO_AUTHN_RESPONSE(profile->response);
	else
		return NULL;
}

/* request */
LassoRequest *LassoProfile_request_get(LassoProfile *profile) {
	if (profile->request_type == lassoMessageTypeRequest)
		return LASSO_REQUEST(profile->request);
	else
		return NULL;
}

/* response */
LassoResponse *LassoProfile_response_get(LassoProfile *profile) {
	if (profile->response_type == lassoMessageTypeResponse)
		return LASSO_RESPONSE(profile->response);
	else
		return NULL;
}

%}

/* Functions */

%rename(getRequestTypeFromSoapMsg) lasso_profile_get_request_type_from_soap_msg;
lassoRequestType lasso_profile_get_request_type_from_soap_msg(gchar *soap);


/***********************************************************************
 * Defederation
 ***********************************************************************/


%rename(Defederation) LassoDefederation;
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

/* authnRequest */
LassoAuthnRequest *LassoDefederation_authnRequest_get(LassoDefederation *self) {
	return LassoProfile_authnRequest_get(LASSO_PROFILE(self));
}

/* authnResponse */
LassoAuthnResponse *LassoDefederation_authnResponse_get(LassoDefederation *self) {
	return LassoProfile_authnResponse_get(LASSO_PROFILE(self));
}

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
LassoRequest *LassoDefederation_request_get(LassoDefederation *self) {
	return LassoProfile_request_get(LASSO_PROFILE(self));
}

/* response */
LassoResponse *LassoDefederation_response_get(LassoDefederation *self) {
	return LassoProfile_response_get(LASSO_PROFILE(self));
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

/* Constructors */

%newobject lasso_defederation_new;
LassoDefederation *lasso_defederation_new(LassoServer *server, lassoProviderType providerType);

/* Destructor */

void lasso_defederation_destroy(LassoDefederation *defederation);

/* Methods */

gint lasso_defederation_build_notification_msg(LassoDefederation *defederation);

gint lasso_defederation_init_notification(LassoDefederation *defederation,
					  gchar *remoteProviderId,
					  lassoHttpMethod httpMethod);

gint lasso_defederation_process_notification_msg(LassoDefederation *defederation,
						 gchar *notificationMsg,
						 lassoHttpMethod httpMethod);

gint lasso_defederation_validate_notification(LassoDefederation *defederation);


/***********************************************************************
 * Login
 ***********************************************************************/


%rename(Login) LassoLogin;
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
	return LassoProfile_authnRequest_get(LASSO_PROFILE(self));
}

/* authnResponse */
LassoAuthnResponse *LassoLogin_authnResponse_get(LassoLogin *self) {
	return LassoProfile_authnResponse_get(LASSO_PROFILE(self));
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
	return LassoProfile_request_get(LASSO_PROFILE(self));
}

/* response */
LassoResponse *LassoLogin_response_get(LassoLogin *self) {
	return LassoProfile_response_get(LASSO_PROFILE(self));
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

/* Constructors, destructors & static methods implementations */

#define new_LassoLogin lasso_login_new
#define delete_LassoLogin lasso_login_destroy
#define Login_newFromDump lasso_login_new_from_dump

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
#define LassoLogin_dump lasso_login_dump
#define LassoLogin_initAuthnRequest lasso_login_init_authn_request
#define LassoLogin_initFromAuthnRequestMsg lasso_login_init_from_authn_request_msg
#define LassoLogin_initRequest lasso_login_init_request
#define LassoLogin_mustAuthenticate lasso_login_must_authenticate
#define LassoLogin_processAuthnResponseMsg lasso_login_process_authn_response_msg
#define LassoLogin_processRequestMsg lasso_login_process_request_msg
#define LassoLogin_processResponseMsg lasso_login_process_response_msg

%}

/* Constructors */

%newobject lasso_login_new;
LassoLogin *lasso_login_new(LassoServer *server);

%newobject lasso_login_new_from_dump;
LassoLogin *lasso_login_new_from_dump(LassoServer *server, gchar *dump);

/* Destructor */

void lasso_login_destroy(LassoLogin *login);

/* Methods */

gint lasso_login_accept_sso(LassoLogin *login);

gint lasso_login_build_artifact_msg(LassoLogin *login, gint authenticationResult,
				    const gchar *authenticationMethod,
				    const gchar *reauthenticateOnOrAfter,
				    lassoHttpMethod httpMethod);

gint lasso_login_build_authn_request_msg(LassoLogin *login, const gchar *remoteProviderId);

gint lasso_login_build_authn_response_msg(LassoLogin  *login, gint authenticationResult,
					  const gchar *authenticationMethod,
					  const gchar *reauthenticateOnOrAfter);

gint lasso_login_build_request_msg(LassoLogin *login);

%newobject lasso_login_dump;
gchar *lasso_login_dump(LassoLogin *login);

gint lasso_login_init_authn_request(LassoLogin *login, lassoHttpMethod httpMethod);

gint lasso_login_init_from_authn_request_msg(LassoLogin *login, gchar *authnRequestMsg,
					     lassoHttpMethod  httpMethod);

gint lasso_login_init_request(LassoLogin *login, gchar *responseMsg,
			      lassoHttpMethod httpMethod);

gboolean lasso_login_must_authenticate(LassoLogin *login);

gint lasso_login_process_authn_response_msg(LassoLogin *login, gchar *authnResponseMsg);

gint lasso_login_process_request_msg(LassoLogin *login, gchar *requestMsg);

gint lasso_login_process_response_msg(LassoLogin  *login, gchar *responseMsg);


/***********************************************************************
 * Logout
 ***********************************************************************/


%rename(Logout) LassoLogout;
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
		void resetSessionIndex();
		END_THROW_ERROR

		THROW_ERROR
		void validateRequest();
		END_THROW_ERROR
	}
} LassoLogout;

%{

/* Attributes inherited from LassoProfile implementations */

/* authnRequest */
LassoAuthnRequest *LassoLogout_authnRequest_get(LassoLogout *self) {
	return LassoProfile_authnRequest_get(LASSO_PROFILE(self));
}

/* authnResponse */
LassoAuthnResponse *LassoLogout_authnResponse_get(LassoLogout *self) {
	return LassoProfile_authnResponse_get(LASSO_PROFILE(self));
}

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
LassoRequest *LassoLogout_request_get(LassoLogout *self) {
	return LassoProfile_request_get(LASSO_PROFILE(self));
}

/* response */
LassoResponse *LassoLogout_response_get(LassoLogout *self) {
	return LassoProfile_response_get(LASSO_PROFILE(self));
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
#define Logout_newFromDump lasso_logout_new_from_dump

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
#define LassoLogout_resetSessionIndex lasso_logout_reset_session_index
#define LassoLogout_validateRequest lasso_logout_validate_request

%}

/* Constructors */

%newobject lasso_logout_new;
LassoLogout *lasso_logout_new(LassoServer *server, lassoProviderType providerType);

%newobject lasso_logout_new_from_dump;
LassoLogout *lasso_logout_new_from_dump(LassoServer *server, gchar *dump);

/* Destructor */

void lasso_logout_destroy(LassoLogout *logout);

/* Methods */

gint lasso_logout_build_request_msg(LassoLogout *logout);

gint lasso_logout_build_response_msg(LassoLogout *logout);

%newobject lasso_logout_dump;
gchar *lasso_logout_dump(LassoLogout *logout);

%newobject lasso_logout_get_next_providerID;
gchar *lasso_logout_get_next_providerID(LassoLogout *logout);

gint lasso_logout_init_request(LassoLogout *logout, gchar *remoteProviderId,
			       lassoHttpMethod httpMethod);

gint lasso_logout_process_request_msg(LassoLogout *logout, gchar *requestMsg,
				      lassoHttpMethod httpMethod);

gint lasso_logout_process_response_msg(LassoLogout *logout, gchar *responseMsg,
				       lassoHttpMethod httpMethod);

gint lasso_logout_reset_session_index(LassoLogout *logout);

gint lasso_logout_validate_request(LassoLogout *logout);


/***********************************************************************
 * LECP
 ***********************************************************************/


%rename(Lecp) LassoLecp;
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
	return LassoProfile_authnRequest_get(LASSO_PROFILE(self));
}

/* authnResponse */
LassoAuthnResponse *LassoLecp_authnResponse_get(LassoLecp *self) {
	return LassoProfile_authnResponse_get(LASSO_PROFILE(self));
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
	return LassoProfile_request_get(LASSO_PROFILE(self));
}

/* response */
LassoResponse *LassoLecp_response_get(LassoLecp *self) {
	return LassoProfile_response_get(LASSO_PROFILE(self));
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

/* Constructors */

%newobject lasso_lecp_new;
LassoLecp *lasso_lecp_new(LassoServer *server);

/* Destructor */

void lasso_lecp_destroy(LassoLecp *lecp);

/* Methods */

gint lasso_lecp_build_authn_request_envelope_msg(LassoLecp *lecp);

gint lasso_lecp_build_authn_request_msg(LassoLecp *lecp, const gchar *remoteProviderId);

gint lasso_lecp_build_authn_response_envelope_msg(LassoLecp *lecp, gint authenticationResult,
						  const gchar *authenticationMethod,
						  const gchar *reauthenticateOnOrAfter);

gint lasso_lecp_build_authn_response_msg(LassoLecp *lecp);

gint lasso_lecp_init_authn_request(LassoLecp *lecp);

gint lasso_lecp_init_from_authn_request_msg(LassoLecp *lecp, gchar *authnRequestMsg,
					    lassoHttpMethod httpMethod);

gint lasso_lecp_process_authn_request_envelope_msg(LassoLecp *lecp, gchar *requestMsg);
  
gint lasso_lecp_process_authn_response_envelope_msg(LassoLecp *lecp, gchar *responseMsg);
