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

/* SWIG instructions telling how to deallocate Lasso structures */

%typemap(newfree) gchar * "g_free($1);";

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

void add_key_to_array(gchar *key, gpointer pointer, GPtrArray *array)
{
        g_ptr_array_add(array, g_strdup(key));
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
} lassoHttpMethod;

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
} lassoLoginProtocolProfile;

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
} lassoMessageType;

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
} lassoRequestType;

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
} lassoSignatureMethod;


/***********************************************************************
 * Errors
 ***********************************************************************/

/* XXX: why can't those be taken from errors.h ? */

/* others */
#ifndef SWIGPHP4
%rename(ERROR_UNDEFINED) LASSO_ERROR_UNDEFINED;
#endif
#define LASSO_ERROR_UNDEFINED                         -1


/* generic XML */
#ifndef SWIGPHP4
%rename(XML_ERROR_NODE_NOT_FOUND) LASSO_XML_ERROR_NODE_NOT_FOUND;
%rename(XML_ERROR_NODE_CONTENT_NOT_FOUND) LASSO_XML_ERROR_NODE_CONTENT_NOT_FOUND;
%rename(XML_ERROR_ATTR_NOT_FOUND) LASSO_XML_ERROR_ATTR_NOT_FOUND;
%rename(XML_ERROR_ATTR_VALUE_NOT_FOUND) LASSO_XML_ERROR_ATTR_VALUE_NOT_FOUND;
#endif
#define LASSO_XML_ERROR_NODE_NOT_FOUND                 -10
#define LASSO_XML_ERROR_NODE_CONTENT_NOT_FOUND         -11
#define LASSO_XML_ERROR_ATTR_NOT_FOUND                 -12
#define LASSO_XML_ERROR_ATTR_VALUE_NOT_FOUND           -13

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
#define LASSO_DS_ERROR_SIGNATURE_NOT_FOUND             101
#define LASSO_DS_ERROR_INVALID_SIGNATURE               102
#define LASSO_DS_ERROR_SIGNATURE_TMPL_CREATION_FAILED -103
#define LASSO_DS_ERROR_CONTEXT_CREATION_FAILED        -104
#define LASSO_DS_ERROR_PUBLIC_KEY_LOAD_FAILED         -105
#define LASSO_DS_ERROR_PRIVATE_KEY_LOAD_FAILED        -106
#define LASSO_DS_ERROR_CERTIFICATE_LOAD_FAILED        -107
#define LASSO_DS_ERROR_SIGNATURE_FAILED               -108
#define LASSO_DS_ERROR_KEYS_MNGR_CREATION_FAILED      -109
#define LASSO_DS_ERROR_KEYS_MNGR_INIT_FAILED          -110
#define LASSO_DS_ERROR_SIGNATURE_VERIFICATION_FAILED  -111
#define LASSO_DS_ERROR_CA_CERT_CHAIN_LOAD_FAILED      -112
#define LASSO_DS_ERROR_INVALID_SIGALG                 -113
#define LASSO_DS_ERROR_DIGEST_COMPUTE_FAILED          -114

/* server */
#ifndef SWIGPHP4
%rename(SERVER_ERROR_PROVIDER_NOT_FOUND) LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND;
%rename(SERVER_ERROR_ADD_PROVIDER_FAILED) LASSO_SERVER_ERROR_ADD_PROVIDER_FAILED;
#endif
#define LASSO_SERVER_ERROR_PROVIDER_NOT_FOUND         -201
#define LASSO_SERVER_ERROR_ADD_PROVIDER_FAILED        -202

/* logout */
#ifndef SWIGPHP4
%rename(LOGOUT_ERROR_UNSUPPORTED_PROFILE) LASSO_LOGOUT_ERROR_UNSUPPORTED_PROFILE;
#endif
#define LASSO_LOGOUT_ERROR_UNSUPPORTED_PROFILE        -301

/* profile */
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
#define LASSO_PROFILE_ERROR_INVALID_QUERY             -401
#define LASSO_PROFILE_ERROR_INVALID_POST_MSG          -402
#define LASSO_PROFILE_ERROR_INVALID_SOAP_MSG          -403
#define LASSO_PROFILE_ERROR_MISSING_REQUEST           -404
#define LASSO_PROFILE_ERROR_INVALID_HTTP_METHOD       -405
#define LASSO_PROFILE_ERROR_INVALID_PROTOCOLPROFILE   -406
#define LASSO_PROFILE_ERROR_INVALID_MSG               -407
#define LASSO_PROFILE_ERROR_MISSING_REMOTE_PROVIDERID -408
#define LASSO_PROFILE_ERROR_UNSUPPORTED_PROFILE       -409
#define LASSO_PROFILE_ERROR_UNKNOWN_PROFILE_URL       -410
#define LASSO_PROFILE_ERROR_IDENTITY_NOT_FOUND        -411
#define LASSO_PROFILE_ERROR_FEDERATION_NOT_FOUND      -412
#define LASSO_PROFILE_ERROR_NAME_IDENTIFIER_NOT_FOUND -413
#define LASSO_PROFILE_ERROR_BUILDING_QUERY_FAILED     -414
#define LASSO_PROFILE_ERROR_BUILDING_REQUEST_FAILED   -415
#define LASSO_PROFILE_ERROR_BUILDING_MESSAGE_FAILED   -416
#define LASSO_PROFILE_ERROR_BUILDING_RESPONSE_FAILED  -417
#define LASSO_PROFILE_ERROR_SESSION_NOT_FOUND         -418
#define LASSO_PROFILE_ERROR_BAD_IDENTITY_DUMP         -419
#define LASSO_PROFILE_ERROR_BAD_SESSION_DUMP          -420


/* functions/methods parameters checking */
#ifndef SWIGPHP4
%rename(PARAM_ERROR_BADTYPE_OR_NULL_OBJ) LASSO_PARAM_ERROR_BADTYPE_OR_NULL_OBJ;
%rename(PARAM_ERROR_INVALID_VALUE) LASSO_PARAM_ERROR_INVALID_VALUE;
%rename(PARAM_ERROR_ERR_CHECK_FAILED) LASSO_PARAM_ERROR_ERR_CHECK_FAILED;
#endif
#define LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ        -501
#define LASSO_PARAM_ERROR_INVALID_VALUE               -502
#define LASSO_PARAM_ERROR_CHECK_FAILED                -503

/* Single Sign-On */
#ifndef SWIGPHP4
%rename(LOGIN_ERROR_FEDERATION_NOT_FOUND) LASSO_LOGIN_ERROR_FEDERATION_NOT_FOUND;
%rename(LOGIN_ERROR_CONSENT_NOT_OBTAINED) LASSO_LOGIN_ERROR_CONSENT_NOT_OBTAINED;
%rename(LASSO_LOGIN_ERROR_INVALID_NAMEIDPOLICY) LASSO_LOGIN_ERROR_INVALID_NAMEIDPOLICY;
%rename(LOGIN_ERROR_REQUEST_DENIE) LASSO_LOGIN_ERROR_REQUEST_DENIE;
%rename(LOGIN_ERROR_INVALID_SIGNATURE) LASSO_LOGIN_ERROR_INVALID_SIGNATURE;
%rename(LOGIN_ERROR_UNSIGNED_AUTHN_REQUEST) LASSO_LOGIN_ERROR_UNSIGNED_AUTHN_REQUEST;
#endif
#define LASSO_LOGIN_ERROR_FEDERATION_NOT_FOUND         601
#define LASSO_LOGIN_ERROR_CONSENT_NOT_OBTAINED         602
#define LASSO_LOGIN_ERROR_INVALID_NAMEIDPOLICY        -603
#define LASSO_LOGIN_ERROR_REQUEST_DENIE	               604
#define LASSO_LOGIN_ERROR_INVALID_SIGNATURE            605
#define LASSO_LOGIN_ERROR_UNSIGNED_AUTHN_REQUEST       606

/* Federation Termination Notification */
#ifndef SWIGPHP4
%rename(DEFEDERATION_ERROR_MISSING_NAME_IDENTIFIER) LASSO_DEFEDERATION_ERROR_MISSING_NAME_IDENTIFIER;
#endif
#define LASSO_DEFEDERATION_ERROR_MISSING_NAME_IDENTIFIER  -700



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
 * ProviderIds
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(ProviderIds) LassoProviderIds;
#endif
%{
typedef GPtrArray LassoProviderIds;
%}
typedef struct {
	%extend {
		/* Constructor, Destructor & Static Methods */

		LassoProviderIds();

		~LassoProviderIds();

		/* Methods */

		GPtrArray *cast() {
			return self;
		}

		static LassoProviderIds *frompointer(GPtrArray *providerIds) {
			return (LassoProviderIds *) providerIds;
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
		gchar *getitem(int index) {
			return g_strdup(g_ptr_array_index(self, index));
		}
		%exception getitem;

#if defined(SWIGPYTHON)
		%rename(__len__) length;
#endif
		gint length() {
			return self->len;
		}
	}
} LassoProviderIds;

%{

/* Constructors, destructors & static methods implementations */

LassoProviderIds *new_LassoProviderIds() {
	return g_ptr_array_new();
}

void delete_LassoProviderIds(LassoProviderIds *self) {
	g_ptr_array_free(self, true);
}

%}


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
	return lasso_node_dump(LASSO_NODE(self), NULL, 1);
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
%rename(LibAssertion) LassoLibAssertion;
#endif
typedef struct {
	%extend {
		/* Constructor, Destructor & Static Methods */

		LassoLibAssertion(char *issuer, char *requestId, char *audience,
				char *notBefore, char *notOnOrAfter);

		~LassoLibAssertion();

		/* Methods */

		%newobject dump;
		gchar *dump();
	}
} LassoLibAssertion;

%{

/* Constructors, destructors & static methods implementations */

#define new_LassoLibAssertion lasso_lib_assertion_new_full

void delete_LassoLibAssertion(LassoLibAssertion *self) {
	lasso_node_destroy(LASSO_NODE(self));
}

/* Methods implementations */

gchar* LassoLibAssertion_dump(LassoLibAssertion *self) {
	return lasso_node_dump(LASSO_NODE(self), NULL, 1);
}

%}


/***********************************************************************
 * AuthnRequest
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(LibAuthnRequest) LassoLibAuthnRequest;
#endif
%nodefault LassoLibAuthnRequest;
typedef struct {
	%extend {
		/* XXX shouldn't need all of this now */
		/* Attributes from LassoLibAuthnRequest */

		gchar *affiliationId;
		gchar *assertionConsumerServiceId;
		gchar *consent;
		gboolean forceAuthn;
		gboolean isPassive;
		gchar *nameIdPolicy;
		gchar *protocolProfile;
		gchar *providerId;
		gchar *relayState;
	}
} LassoLibAuthnRequest;

%{

/* Attributes Implementations */

/* affiliationId */
#define LassoLibAuthnRequest_get_affiliationId LassoLibAuthnRequest_affiliationId_get
gchar *LassoLibAuthnRequest_affiliationId_get(LassoLibAuthnRequest *self) {
	return NULL; /* FIXME */
}
#define LassoLibAuthnRequest_set_affiliationId LassoLibAuthnRequest_affiliationId_set
void LassoLibAuthnRequest_affiliationId_set(LassoLibAuthnRequest *self, gchar *affiliationId) {
	LASSO_LIB_AUTHN_REQUEST(self)->AffiliationID = strdup(affiliationId);
}

/* assertionConsumerServiceId */
#define LassoLibAuthnRequest_get_assertionConsumerServiceId LassoLibAuthnRequest_assertionConsumerServiceId_get
gchar *LassoLibAuthnRequest_assertionConsumerServiceId_get(LassoLibAuthnRequest *self) {
	return NULL; /* FIXME */
}
#define LassoLibAuthnRequest_set_assertionConsumerServiceId LassoLibAuthnRequest_assertionConsumerServiceId_set
void LassoLibAuthnRequest_assertionConsumerServiceId_set(LassoLibAuthnRequest *self,
						      gchar *assertionConsumerServiceId) {
	LASSO_LIB_AUTHN_REQUEST(self)->AssertionConsumerServiceID = strdup(
							       assertionConsumerServiceId);
}

/* consent */
#define LassoLibAuthnRequest_get_consent LassoLibAuthnRequest_consent_get
gchar *LassoLibAuthnRequest_consent_get(LassoLibAuthnRequest *self) {
	return NULL; /* FIXME */
}
#define LassoLibAuthnRequest_set_consent LassoLibAuthnRequest_consent_set
void LassoLibAuthnRequest_consent_set(LassoLibAuthnRequest *self, gchar *consent) {
	 LASSO_LIB_AUTHN_REQUEST(self)->consent = strdup(consent);
}

/* forceAuthn */
#define LassoLibAuthnRequest_get_forceAuthn LassoLibAuthnRequest_forceAuthn_get
gboolean LassoLibAuthnRequest_forceAuthn_get(LassoLibAuthnRequest *self) {
	return 0; /* FIXME */
}
#define LassoLibAuthnRequest_set_forceAuthn LassoLibAuthnRequest_forceAuthn_set
void LassoLibAuthnRequest_forceAuthn_set(LassoLibAuthnRequest *self, gboolean forceAuthn) {
	 LASSO_LIB_AUTHN_REQUEST(self)->ForceAuthn = forceAuthn;
}

/* isPassive */
#define LassoLibAuthnRequest_get_isPassive LassoLibAuthnRequest_isPassive_get
gboolean LassoLibAuthnRequest_isPassive_get(LassoLibAuthnRequest *self) {
	return self->IsPassive;
}
#define LassoLibAuthnRequest_set_isPassive LassoLibAuthnRequest_isPassive_set
void LassoLibAuthnRequest_isPassive_set(LassoLibAuthnRequest *self, gboolean isPassive) {
	self->IsPassive = isPassive;
}

/* nameIdPolicy */
#define LassoLibAuthnRequest_get_nameIdPolicy LassoLibAuthnRequest_nameIdPolicy_get
gchar *LassoLibAuthnRequest_nameIdPolicy_get(LassoLibAuthnRequest *self) {
	return g_strdup(self->NameIDPolicy);
}
#define LassoLibAuthnRequest_set_nameIdPolicy LassoLibAuthnRequest_nameIdPolicy_set
void LassoLibAuthnRequest_nameIdPolicy_set(LassoLibAuthnRequest *self, gchar *nameIdPolicy) {
	self->NameIDPolicy = g_strdup(nameIdPolicy);
}

/* protocolProfile */
#define LassoLibAuthnRequest_get_protocolProfile LassoLibAuthnRequest_protocolProfile_get
gchar *LassoLibAuthnRequest_protocolProfile_get(LassoLibAuthnRequest *self) {
	return g_strdup(self->ProtocolProfile);
}
#define LassoLibAuthnRequest_set_protocolProfile LassoLibAuthnRequest_protocolProfile_set
void LassoLibAuthnRequest_protocolProfile_set(LassoLibAuthnRequest *self, gchar *protocolProfile) {
	self->ProtocolProfile = g_strdup(protocolProfile);
}

/* providerId */
#define LassoLibAuthnRequest_get_providerId LassoLibAuthnRequest_providerId_get
gchar *LassoLibAuthnRequest_providerId_get(LassoLibAuthnRequest *self) {
	return g_strdup(self->ProviderID);
}
#define LassoLibAuthnRequest_set_providerId LassoLibAuthnRequest_providerId_set
void LassoLibAuthnRequest_providerId_set(LassoLibAuthnRequest *self, gchar *providerId) {
	self->ProviderID = g_strdup(providerId);
}

/* relayState */
#define LassoLibAuthnRequest_get_relayState LassoLibAuthnRequest_relayState_get
gchar *LassoLibAuthnRequest_relayState_get(LassoLibAuthnRequest *self) {
	return g_strdup(self->RelayState);
}
#define LassoLibAuthnRequest_set_relayState LassoLibAuthnRequest_relayState_set
void LassoLibAuthnRequest_relayState_set(LassoLibAuthnRequest *self, gchar *relayState) {
	self->RelayState = g_strdup(relayState);
}

%}


/***********************************************************************
 * AuthnResponse
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(LibAuthnResponse) LassoLibAuthnResponse;
#endif
%nodefault LassoLibAuthnResponse;
typedef struct {
} LassoLibAuthnResponse;


/***********************************************************************
 * FederationTerminationNotification
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(LibFederationTerminationNotification) LassoLibFederationTerminationNotification;
#endif
%nodefault LassoLibFederationTerminationNotification;
typedef struct {
	/* FIXME: Add a relayState when Lasso supports it. */
} LassoLibFederationTerminationNotification;


/***********************************************************************
 * LogoutRequest
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(LibLogoutRequest) LassoLibLogoutRequest;
#endif
%nodefault LassoLibLogoutRequest;
typedef struct {
	%extend {
		/* Attributes inherited from LassoLibLogoutRequest */
		char *relayState;
	}
} LassoLibLogoutRequest;

%{

/* Attributes Implementations */

/* relayState */
#define LassoLibLogoutRequest_get_relayState LassoLibLogoutRequest_relayState_get
gchar *LassoLibLogoutRequest_relayState_get(LassoLibLogoutRequest *self) {
	return g_strdup(self->RelayState);
}
#define LassoLibLogoutRequest_set_relayState LassoLibLogoutRequest_relayState_set
void LassoLibLogoutRequest_relayState_set(LassoLibLogoutRequest *self, char *relayState) {
	 self->RelayState = g_strdup(relayState);
}



%}


/***********************************************************************
 * LogoutResponse
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(LibLogoutResponse) LassoLibLogoutResponse;
#endif
%nodefault LassoLibLogoutResponse;
typedef struct {
} LassoLibLogoutResponse;


/***********************************************************************
 * Provider
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(Provider) LassoProvider;
#endif
%nodefault LassoProvider;
typedef struct {
	/* XXX
	%immutable metadata;
	LassoNode *metadata;
	*/

	%immutable role;
	LassoProviderRole role;

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
	return g_strdup(self->ProviderID);
}

%}


/***********************************************************************
 * RegisterNameIdentifierRequest
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(LibRegisterNameIdentifierRequest) LassoLibRegisterNameIdentifierRequest;
#endif
%nodefault LassoLibRegisterNameIdentifierRequest;
typedef struct {
	%extend {
		/* Attributes inherited from LassoLibRegisterNameIdentifierRequest */

		gchar *relayState;
	}
} LassoLibRegisterNameIdentifierRequest;

%{

/* Attributes Implementations */

/* relayState */
#define LassoLibRegisterNameIdentifierRequest_get_relayState LassoLibRegisterNameIdentifierRequest_relayState_get
gchar *LassoLibRegisterNameIdentifierRequest_relayState_get(
		LassoLibRegisterNameIdentifierRequest *self) {
	return NULL; /* FIXME */
}
#define LassoLibRegisterNameIdentifierRequest_set_relayState LassoLibRegisterNameIdentifierRequest_relayState_set
void LassoLibRegisterNameIdentifierRequest_relayState_set(
		LassoLibRegisterNameIdentifierRequest *self, gchar *relayState)
{
	 LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(self)->RelayState = g_strdup(relayState);
}

%}


/***********************************************************************
 * RegisterNameIdentifierResponse
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(LibRegisterNameIdentifierResponse) LassoLibRegisterNameIdentifierResponse;
#endif
%nodefault LassoLibRegisterNameIdentifierResponse;
typedef struct {
} LassoLibRegisterNameIdentifierResponse;


/***********************************************************************
 * Request
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(SamlpRequest) LassoSamlpRequest;
#endif
%nodefault LassoSamlpRequest;
typedef struct {
} LassoSamlpRequest;


/***********************************************************************
 * Response
 ***********************************************************************/


#ifndef SWIGPHP4
%rename(SamlpResponse) LassoSamlpResponse;
#endif
%nodefault LassoSamlpResponse;
typedef struct {
} LassoSamlpResponse;


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

		%immutable providerIds;
		%newobject providerIds_get;
		LassoProviderIds *providerIds;

		/* Constructor, destructor & static methods */

		LassoServer(gchar *metadata = NULL, gchar *privateKey = NULL,
			    gchar *secretKey = NULL, gchar *certificate = NULL);

		~LassoServer();

		%newobject newFromDump;
		static LassoServer *newFromDump(gchar *dump);

		/* Methods */

	        THROW_ERROR
		void addProvider(LassoProviderRole role, gchar *metadata, gchar *publicKey = NULL,
				 gchar *caCertChain = NULL);
		END_THROW_ERROR

		%newobject dump;
		gchar *dump();

		LassoProvider *getProvider(gchar *providerId);
	}
} LassoServer;

%{

/* Attributes inherited from LassoProvider implementations */

/* metadata */
#define LassoServer_get_metadata LassoServer_metadata_get
LassoNode *LassoServer_metadata_get(LassoServer *self) {
	return NULL;
	/* XXX return LASSO_PROVIDER(self)->metadata; */
}

/* Attributes implementations */

/* providerId */
#define LassoServer_get_providerId LassoServer_providerId_get
gchar *LassoServer_providerId_get(LassoServer *self) {
	return LASSO_PROVIDER(self)->ProviderID;
}

/* providerIds */
#define LassoServer_get_providerIds LassoServer_providerIds_get
LassoProviderIds *LassoServer_providerIds_get(LassoServer *self) {
	GPtrArray *providerIds = g_ptr_array_sized_new(g_hash_table_size(self->providers));
	g_hash_table_foreach(self->providers, (GHFunc) add_key_to_array, providerIds);
	return providerIds;
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
#define LassoServer_getProvider lasso_server_get_provider

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
		%newobject providerIds_get;
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

/* providerIds */
#define LassoIdentity_get_providerIds LassoIdentity_providerIds_get
LassoProviderIds *LassoIdentity_providerIds_get(LassoIdentity *self) {
	GPtrArray *providerIds = g_ptr_array_sized_new(g_hash_table_size(self->federations));
	g_hash_table_foreach(self->federations, (GHFunc) add_key_to_array, providerIds);
	return providerIds;
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
		%newobject providerIds_get;
		LassoProviderIds *providerIds;

		/* Constructor, destructor & static methods */

		LassoSession();

		~LassoSession();

		%newobject newFromDump;
		static LassoSession *newFromDump(gchar *dump);

		/* Methods */

		%newobject dump;
		gchar *dump();
	}
} LassoSession;

%{

/* Attributes implementations */

/* isDirty */
#define LassoSession_get_isDirty LassoSession_isDirty_get
gboolean LassoSession_isDirty_get(LassoSession *self) {
	return self->is_dirty;
}

/* providerIds */
#define LassoSession_get_providerIds LassoSession_providerIds_get
LassoProviderIds *LassoSession_providerIds_get(LassoSession *self) {
	GPtrArray *providerIds = g_ptr_array_sized_new(g_hash_table_size(self->assertions));
	g_hash_table_foreach(self->assertions, (GHFunc) add_key_to_array, providerIds);
	return providerIds;
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

#ifdef SWIGPHP4
%rename(lasso_isLibertyQuery) lasso_profile_is_liberty_query;
#else
%rename(isLibertyQuery) lasso_profile_is_liberty_query;
#endif
gboolean lasso_profile_is_liberty_query(gchar *query);


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
		LassoLibFederationTerminationNotification *request;

		%newobject session_get;
		LassoSession *session;

		/* Constructor, Destructor & Static Methods */

		LassoDefederation(LassoServer *server);

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
				      lassoHttpMethod httpMethod = LASSO_HTTP_METHOD_ANY);
		END_THROW_ERROR

		THROW_ERROR
		void processNotificationMsg(gchar *notificationMsg);
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
	LASSO_PROFILE(self)->identity = identity;
	return 0;
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
	if (LASSO_PROFILE(self)->nameIdentifier)
		return g_strdup(LASSO_PROFILE(self)->nameIdentifier->content);
	return NULL;
}

/* remoteProviderId */
#define LassoDefederation_get_remoteProviderId LassoDefederation_remoteProviderId_get
gchar *LassoDefederation_remoteProviderId_get(LassoDefederation *self) {
	return g_strdup(LASSO_PROFILE(self)->remote_providerID);
}
#define LassoDefederation_set_remoteProviderId LassoDefederation_remoteProviderId_set
void LassoDefederation_remoteProviderId_set(LassoDefederation *self, gchar *remoteProviderId) {
	LASSO_PROFILE(self)->remote_providerID = g_strdup(remoteProviderId);
}

/* request */
#define LassoDefederation_get_request LassoDefederation_request_get
LassoLibFederationTerminationNotification *LassoDefederation_request_get(LassoDefederation *self) {
	return LASSO_LIB_FEDERATION_TERMINATION_NOTIFICATION(LASSO_PROFILE(self)->request);
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
	LASSO_PROFILE(self)->session = session;
	return 0;
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
		LassoSamlpRequest *request;

		%immutable response;
		LassoSamlpResponse *response;

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
		void buildArtifactMsg(lassoHttpMethod httpMethod);
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
		void buildResponseMsg(gchar *remoteProviderId);
		END_THROW_ERROR

		%newobject dump;
		gchar *dump();

		THROW_ERROR
		void initAuthnRequest(gchar *remoteProviderId = NULL,
				 lassoHttpMethod httpMethod = LASSO_HTTP_METHOD_REDIRECT);
		END_THROW_ERROR

		THROW_ERROR
		void initRequest(gchar *responseMsg,
				 lassoHttpMethod httpMethod = LASSO_HTTP_METHOD_REDIRECT);
		END_THROW_ERROR

		THROW_ERROR
		void initIdpInitiatedAuthnRequest(gchar *remoteProviderID = NULL);
		END_THROW_ERROR

		gboolean mustAskForConsent();

		gboolean mustAuthenticate();

		THROW_ERROR
		void processAuthnRequestMsg(gchar *authnrequestMsg);
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

		THROW_ERROR
		int validateRequestMsg(gboolean authenticationResult, gboolean isConsentObtained);
		END_THROW_ERROR

	}
} LassoLogin;

%{

/* Attributes inherited from LassoProfile implementations */

/* authnRequest */
#define LassoLogin_get_authnRequest LassoLogin_authnRequest_get
LassoLibAuthnRequest *LassoLogin_authnRequest_get(LassoLogin *self) {
	LassoProfile *profile = LASSO_PROFILE(self);
	if (LASSO_IS_LIB_AUTHN_REQUEST(profile->request))
		return LASSO_LIB_AUTHN_REQUEST(profile->request);
	return NULL;
}

/* authnResponse */
#define LassoLogin_get_authnResponse LassoLogin_authnResponse_get
LassoLibAuthnResponse *LassoLogin_authnResponse_get(LassoLogin *self) {
	LassoProfile *profile = LASSO_PROFILE(self);
	if (LASSO_IS_LIB_AUTHN_RESPONSE(profile->response))
		return LASSO_LIB_AUTHN_RESPONSE(profile->response);
	return NULL;
}

/* identity */
#define LassoLogin_get_identity LassoLogin_identity_get
LassoIdentity *LassoLogin_identity_get(LassoLogin *self) {
	return lasso_profile_get_identity(LASSO_PROFILE(self));
}
#define LassoLogin_set_identity LassoLogin_identity_set
gint LassoLogin_identity_set(LassoLogin *self, LassoIdentity *identity) {
	LASSO_PROFILE(self)->identity = identity;
	return 0;
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
	if (LASSO_PROFILE(self)->nameIdentifier)
		return g_strdup(LASSO_PROFILE(self)->nameIdentifier->content);
	return NULL;
}

/* remoteProviderId */
#define LassoLogin_get_remoteProviderId LassoLogin_remoteProviderId_get
gchar *LassoLogin_remoteProviderId_get(LassoLogin *self) {
	return g_strdup(LASSO_PROFILE(self)->remote_providerID);
}
#define LassoLogin_set_remoteProviderId LassoLogin_remoteProviderId_set
void LassoLogin_remoteProviderId_set(LassoLogin *self, gchar *remoteProviderId) {
	LASSO_PROFILE(self)->remote_providerID = g_strdup(remoteProviderId);
}

/* request */
#define LassoLogin_get_request LassoLogin_request_get
LassoSamlpRequest *LassoLogin_request_get(LassoLogin *self) {
	LassoProfile *profile = LASSO_PROFILE(self);
	if (LASSO_IS_SAMLP_REQUEST(profile->request))
		return LASSO_SAMLP_REQUEST(profile->request);
	return NULL;
}

/* response */
#define LassoLogin_get_response LassoLogin_response_get
LassoSamlpResponse *LassoLogin_response_get(LassoLogin *self) {
	LassoProfile *profile = LASSO_PROFILE(self);
	if (LASSO_IS_SAMLP_RESPONSE(profile->response))
		return LASSO_SAMLP_RESPONSE(profile->response);
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
	LASSO_PROFILE(self)->session = session;
	return 0;
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
		LassoLibLogoutRequest *request;

		%immutable response;
		LassoLibLogoutResponse *response;

		gchar *responseStatus;

		%newobject session_get;
		LassoSession *session;

		/* Constructor, Destructor & Static Methods */

		LassoLogout(LassoServer *server);

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
				 lassoHttpMethod httpMethod = LASSO_HTTP_METHOD_ANY);
		END_THROW_ERROR

		THROW_ERROR
		void processRequestMsg(gchar *requestMsg);
		END_THROW_ERROR

		THROW_ERROR
		void processResponseMsg(gchar *responseMsg);
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
	LASSO_PROFILE(self)->identity = identity;
	return 0;
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
	if (LASSO_PROFILE(self)->nameIdentifier)
		return g_strdup(LASSO_PROFILE(self)->nameIdentifier->content);
	return NULL;
}

/* remoteProviderId */
#define LassoLogout_get_remoteProviderId LassoLogout_remoteProviderId_get
gchar *LassoLogout_remoteProviderId_get(LassoLogout *self) {
	return g_strdup(LASSO_PROFILE(self)->remote_providerID);
}
#define LassoLogout_set_remoteProviderId LassoLogout_remoteProviderId_set
void LassoLogout_remoteProviderId_set(LassoLogout *self, gchar *remoteProviderId) {
	LASSO_PROFILE(self)->remote_providerID = g_strdup(remoteProviderId);
}

/* request */
#define LassoLogout_get_request LassoLogout_request_get
LassoLibLogoutRequest *LassoLogout_request_get(LassoLogout *self) {
	return LASSO_LIB_LOGOUT_REQUEST(LASSO_PROFILE(self)->request);
}

/* response */
#define LassoLogout_get_response LassoLogout_response_get
LassoLibLogoutResponse *LassoLogout_response_get(LassoLogout *self) {
	return LASSO_LIB_LOGOUT_RESPONSE(LASSO_PROFILE(self)->response);
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
	LASSO_PROFILE(self)->session = session;
	return 0;
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
		LassoSamlpRequest *request;

		%immutable response;
		LassoSamlpResponse *response;

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
		void initAuthnRequest(gchar *remoteProviderId = NULL);
		END_THROW_ERROR

		THROW_ERROR
		void processAuthnRequestEnvelopeMsg(gchar *requestMsg);
		END_THROW_ERROR

		THROW_ERROR
		void processAuthnRequestMsg(gchar *authnRequestMsg);
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
LassoLibAuthnRequest *LassoLecp_authnRequest_get(LassoLecp *self) {
	LassoProfile *profile = LASSO_PROFILE(self);
	if (LASSO_IS_LIB_AUTHN_REQUEST(profile->request))
		return LASSO_LIB_AUTHN_REQUEST(profile->request);
	return NULL;
}

/* authnResponse */
#define LassoLecp_get_authnResponse LassoLecp_authnResponse_get
LassoLibAuthnResponse *LassoLecp_authnResponse_get(LassoLecp *self) {
	LassoProfile *profile = LASSO_PROFILE(self);
	if (LASSO_IS_LIB_AUTHN_RESPONSE(profile->response))
		return LASSO_LIB_AUTHN_RESPONSE(profile->response);
	return NULL;
}

/* identity */
#define LassoLecp_get_identity LassoLecp_identity_get
LassoIdentity *LassoLecp_identity_get(LassoLecp *self) {
	return lasso_profile_get_identity(LASSO_PROFILE(self));
}
#define LassoLecp_set_identity LassoLecp_identity_set
gint LassoLecp_identity_set(LassoLecp *self, LassoIdentity *identity) {
	LASSO_PROFILE(self)->identity = identity;
	return 0;
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
	if (LASSO_PROFILE(self)->nameIdentifier)
		return g_strdup(LASSO_PROFILE(self)->nameIdentifier->content);
	return NULL;
}

/* remoteProviderId */
#define LassoLecp_get_remoteProviderId LassoLecp_remoteProviderId_get
gchar *LassoLecp_remoteProviderId_get(LassoLecp *self) {
	return g_strdup(LASSO_PROFILE(self)->remote_providerID);
}
#define LassoLecp_set_remoteProviderId LassoLecp_remoteProviderId_set
void LassoLecp_remoteProviderId_set(LassoLecp *self, gchar *remoteProviderId) {
	LASSO_PROFILE(self)->remote_providerID = g_strdup(remoteProviderId);
}

/* request */
#define LassoLecp_get_request LassoLecp_request_get
LassoSamlpRequest *LassoLecp_request_get(LassoLecp *self) {
	LassoProfile *profile = LASSO_PROFILE(self);
	if (LASSO_IS_SAMLP_REQUEST(profile->request))
		return LASSO_SAMLP_REQUEST(profile->request);
	return NULL;
}

/* response */
#define LassoLecp_get_response LassoLecp_response_get
LassoSamlpResponse *LassoLecp_response_get(LassoLecp *self) {
	LassoProfile *profile = LASSO_PROFILE(self);
	if (LASSO_IS_SAMLP_RESPONSE(profile->response))
		return LASSO_SAMLP_RESPONSE(profile->response);
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
	LASSO_PROFILE(self)->session = session;
	return 0;
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

#define LassoLecp_buildAssertion lasso_login_build_assertion
#define LassoLecp_buildAuthnRequestEnvelopeMsg lasso_lecp_build_authn_request_envelope_msg
#define LassoLecp_buildAuthnRequestMsg lasso_lecp_build_authn_request_msg
#define LassoLecp_buildAuthnResponseEnvelopeMsg lasso_lecp_build_authn_response_envelope_msg
#define LassoLecp_buildAuthnResponseMsg lasso_lecp_build_authn_response_msg
#define LassoLecp_initAuthnRequest lasso_lecp_init_authn_request
#define LassoLecp_processAuthnRequestEnvelopeMsg lasso_lecp_process_authn_request_envelope_msg
#define LassoLecp_processAuthnRequestMsg lasso_lecp_process_authn_request_msg
#define LassoLecp_processAuthnResponseEnvelopeMsg lasso_lecp_process_authn_response_envelope_msg
#define LassoLecp_validateRequestMsg lasso_login_validate_request_msg

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

		LassoNameIdentifierMapping(LassoServer *server);

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
		void initRequest(char *targetNamespace, char *remoteProviderId = NULL);
		END_THROW_ERROR

		THROW_ERROR
		void processRequestMsg(gchar *requestMsg);
		END_THROW_ERROR

		THROW_ERROR
		void processResponseMsg(gchar *responseMsg);
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
	LASSO_PROFILE(self)->identity = identity;
	return 0;
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
	if (LASSO_PROFILE(self)->nameIdentifier)
		return g_strdup(LASSO_PROFILE(self)->nameIdentifier->content);
	return NULL;
}

/* targetNameIdentifier */
#define LassoNameIdentifierMapping_get_targetNameIdentifier LassoNameIdentifierMapping_targetNameIdentifier_get
gchar *LassoNameIdentifierMapping_targetNameIdentifier_get(LassoNameIdentifierMapping *self) {
	return self->targetNameIdentifier;
}

/* remoteProviderId */
#define LassoNameIdentifierMapping_get_remoteProviderId LassoNameIdentifierMapping_remoteProviderId_get
gchar *LassoNameIdentifierMapping_remoteProviderId_get(LassoNameIdentifierMapping *self) {
	return g_strdup(LASSO_PROFILE(self)->remote_providerID);
}
#define LassoNameIdentifierMapping_set_remoteProviderId LassoNameIdentifierMapping_remoteProviderId_set
void LassoNameIdentifierMapping_remoteProviderId_set(LassoNameIdentifierMapping *self, gchar *remoteProviderId) {
	LASSO_PROFILE(self)->remote_providerID = g_strdup(remoteProviderId);
}

/* session */
#define LassoNameIdentifierMapping_get_session LassoNameIdentifierMapping_session_get
LassoSession *LassoNameIdentifierMapping_session_get(LassoNameIdentifierMapping *self) {
	return lasso_profile_get_session(LASSO_PROFILE(self));
}
#define LassoNameIdentifierMapping_set_session LassoNameIdentifierMapping_session_set
gint LassoNameIdentifierMapping_session_set(LassoNameIdentifierMapping *self, LassoSession *session) {
	LASSO_PROFILE(self)->session = session;
	return 0;
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

		%immutable request;
		LassoLibRegisterNameIdentifierRequest *request;

		%immutable response;
		LassoLibRegisterNameIdentifierResponse *response;

		%newobject session_get;
		LassoSession *session;

		/* Constructor, Destructor & Static Methods */

		LassoNameRegistration(LassoServer *server);

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
		void initRequest(char *remoteProviderId,
				lassoHttpMethod httpMethod = LASSO_HTTP_METHOD_ANY);
		END_THROW_ERROR

		THROW_ERROR
		void processRequestMsg(gchar *requestMsg);
		END_THROW_ERROR

		THROW_ERROR
		void processResponseMsg(gchar *responseMsg);
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
	LASSO_PROFILE(self)->identity = identity;
	return 0;
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
	if (LASSO_PROFILE(self)->nameIdentifier)
		return g_strdup(LASSO_PROFILE(self)->nameIdentifier->content);
	return NULL;
}

/* oldNameIdentifier */
#define LassoNameRegistration_get_oldNameIdentifier LassoNameRegistration_oldNameIdentifier_get
gchar *LassoNameRegistration_oldNameIdentifier_get(LassoNameRegistration *self) {
	if (self->oldNameIdentifier)
		return g_strdup(self->oldNameIdentifier->content);
	return NULL;
}

/* remoteProviderId */
#define LassoNameRegistration_get_remoteProviderId LassoNameRegistration_remoteProviderId_get
gchar *LassoNameRegistration_remoteProviderId_get(LassoNameRegistration *self) {
	return g_strdup(LASSO_PROFILE(self)->remote_providerID);
}
#define LassoNameRegistration_set_remoteProviderId LassoNameRegistration_remoteProviderId_set
void LassoNameRegistration_remoteProviderId_set(LassoNameRegistration *self, gchar *remoteProviderId) {
	LASSO_PROFILE(self)->remote_providerID = g_strdup(remoteProviderId);
}

/* request */
#define LassoNameRegistration_get_request LassoNameRegistration_request_get
LassoLibRegisterNameIdentifierRequest *LassoNameRegistration_request_get(LassoNameRegistration *self) {
	return LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(LASSO_PROFILE(self)->request);
}

/* response */
#define LassoNameRegistration_get_response LassoNameRegistration_response_get
LassoLibRegisterNameIdentifierResponse *LassoNameRegistration_response_get(LassoNameRegistration *self) {
	return LASSO_LIB_REGISTER_NAME_IDENTIFIER_RESPONSE(LASSO_PROFILE(self)->response);
}

/* session */
#define LassoNameRegistration_get_session LassoNameRegistration_session_get
LassoSession *LassoNameRegistration_session_get(LassoNameRegistration *self) {
	return lasso_profile_get_session(LASSO_PROFILE(self));
}
#define LassoNameRegistration_set_session LassoNameRegistration_session_set
gint LassoNameRegistration_session_set(LassoNameRegistration *self, LassoSession *session) {
	LASSO_PROFILE(self)->session = session;
	return 0;
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

%include Lasso-wsf.i

