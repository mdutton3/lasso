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

/* When lasso module is imported, lasso is initialized.
%init
%{
	lasso_init();
%}*/


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
#define gboolean int
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

int lasso_init(void);

int lasso_shutdown(void);


/***********************************************************************
 * Constants
 ***********************************************************************/


typedef enum {
	lassoHttpMethodGet = 1,
	lassoHttpMethodPost,
	lassoHttpMethodRedirect,
	lassoHttpMethodSoap
} lassoHttpMethod;

/* Consent */
%constant xmlChar *lassoLibConsentObtained = "urn:liberty:consent:obtained";
%constant xmlChar *lassoLibConsentUnavailable  = "urn:liberty:consent:unavailable";
%constant xmlChar *lassoLibConsentInapplicable = "urn:liberty:consent:inapplicable";

/* NameIDPolicyType */
%constant xmlChar *lassoLibNameIDPolicyTypeNone = "none";
%constant xmlChar *lassoLibNameIDPolicyTypeOneTime = "onetime";
%constant xmlChar *lassoLibNameIDPolicyTypeFederated = "federated";
%constant xmlChar *lassoLibNameIDPolicyTypeAny = "any";

/* ProtocolProfile */
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
%constant xmlChar *lassoLibProtocolProfileSloSpHttp = "http://projectliberty.org/profiles/slo-sp-http";
%constant xmlChar *lassoLibProtocolProfileSloSpSoap = "http://projectliberty.org/profiles/slo-sp-soap";
%constant xmlChar *lassoLibProtocolProfileSloIdpHttp = "http://projectliberty.org/profiles/slo-idp-http";
%constant xmlChar *lassoLibProtocolProfileSloIdpSoap = "http://projectliberty.org/profiles/slo-idp-soap";

typedef enum {
	lassoLoginProtocolProfileBrwsArt = 1,
	lassoLoginProtocolProfileBrwsPost,
} lassoLoginProtocolProfile;

typedef enum {
	lassoMessageTypeNone = 0,
	lassoMessageTypeAuthnRequest,
	lassoMessageTypeAuthnResponse,
	lassoMessageTypeRequest,
	lassoMessageTypeResponse,
	lassoMessageTypeArtifact
} lassoMessageType;

typedef enum {
	lassoProviderTypeNone = 0,
	lassoProviderTypeSp,
	lassoProviderTypeIdp
} lassoProviderType;

/* Request types (used by SOAP endpoint) */
typedef enum {
	lassoRequestTypeInvalid = 0,
	lassoRequestTypeLogin,
	lassoRequestTypeLogout,
	lassoRequestTypeDefederation,
	lassoRequestTypeRegisterNameIdentifier,
	lassoRequestTypeNameIdentifierMapping,
	lassoRequestTypeLecp
} lassoRequestType;

/* AuthenticationMethods */
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

typedef enum {
	lassoSignatureMethodRsaSha1 = 1,
	lassoSignatureMethodDsaSha1
} lassoSignatureMethod;


/***********************************************************************
 ***********************************************************************
 * XML
 ***********************************************************************
 ***********************************************************************/


/***********************************************************************
 * SamlpRequest
 ***********************************************************************/


%nodefault _LassoSamlpRequest;
typedef struct _LassoSamlpRequest {
	LassoSamlpRequestAbstract parent;
} LassoSamlpRequest;


/***********************************************************************
 * SamlpResponse
 ***********************************************************************/


%nodefault _LassoSamlpResponse;
typedef struct _LassoSamlpResponse {
	LassoSamlpResponseAbstract parent;
} LassoSamlpResponse;



/***********************************************************************
 * LibAuthnRequest
 ***********************************************************************/


%nodefault _LassoLibAuthnRequest;
typedef struct _LassoLibAuthnRequest {
	LassoSamlpRequestAbstract parent;
} LassoLibAuthnRequest;

/* Methods */

void lasso_lib_authn_request_set_affiliationID(LassoLibAuthnRequest *, const xmlChar *);
  
void lasso_lib_authn_request_set_assertionConsumerServiceID(LassoLibAuthnRequest *,
							    const xmlChar *);

void lasso_lib_authn_request_set_consent(LassoLibAuthnRequest *, const xmlChar *);

void lasso_lib_authn_request_set_forceAuthn(LassoLibAuthnRequest *, gboolean);

void lasso_lib_authn_request_set_isPassive(LassoLibAuthnRequest *, gboolean);

void lasso_lib_authn_request_set_nameIDPolicy(LassoLibAuthnRequest *node,
					      const xmlChar *nameIDPolicy);

void lasso_lib_authn_request_set_protocolProfile(LassoLibAuthnRequest *, const xmlChar *);

void lasso_lib_authn_request_set_providerID(LassoLibAuthnRequest *, const xmlChar *);

void lasso_lib_authn_request_set_relayState(LassoLibAuthnRequest *, const xmlChar *);

void lasso_lib_authn_request_set_requestAuthnContext(LassoLibAuthnRequest *,
						     LassoLibRequestAuthnContext *);

void lasso_lib_authn_request_set_scoping(LassoLibAuthnRequest *node, LassoLibScoping *scoping);


/***********************************************************************
 * LibAuthnResponse
 ***********************************************************************/


%nodefault _LassoLibAuthnResponse;
typedef struct _LassoLibAuthnResponse {
	LassoSamlpResponse parent;
} LassoLibAuthnResponse;


/***********************************************************************
 ***********************************************************************
 * Protocols
 ***********************************************************************
 ***********************************************************************/


/***********************************************************************
 * AuthnRequest
 ***********************************************************************/


%nodefault _LassoAuthnRequest;
typedef struct _LassoAuthnRequest {
	LassoLibAuthnRequest parent;
} LassoAuthnRequest;


/***********************************************************************
 * AuthnResponse
 ***********************************************************************/


%nodefault _LassoAuthnResponse;
typedef struct _LassoAuthnResponse {
	LassoLibAuthnResponse parent;
} LassoAuthnResponse;

/* Methods */

%newobject lasso_authn_response_get_status;
xmlChar* lasso_authn_response_get_status(LassoAuthnResponse *response);


/***********************************************************************
 * Request
 ***********************************************************************/


%nodefault _LassoRequest;
typedef struct _LassoRequest {
	LassoSamlpRequest parent;
} LassoRequest;


/***********************************************************************
 * Response
 ***********************************************************************/


%nodefault _LassoResponse;
typedef struct _LassoResponse {
	LassoSamlpResponse parent;
} LassoResponse;


/***********************************************************************
 ***********************************************************************
 * Profiles
 ***********************************************************************
 ***********************************************************************/


/***********************************************************************
 * Server
 ***********************************************************************/


typedef struct {
	LassoProvider parent;
	GPtrArray *providers;
	gchar *providerID;   
	gchar *private_key;
	gchar *certificate;
	guint signature_method;

	%extend {
		LassoServer(gchar *metadata, gchar *public_key, gchar *private_key,
			    gchar *certificate, lassoSignatureMethod signature_method) {
			return lasso_server_new(metadata, public_key, private_key, certificate,
						signature_method);
		}

		~LassoServer() {
			lasso_server_destroy(self);
		}
	}
} LassoServer;

/* Constructors */

%newobject lasso_server_new;
LassoServer* lasso_server_new(gchar *metadata, gchar *public_key, gchar *private_key,
			      gchar *certificate, lassoSignatureMethod signature_method);

%newobject lasso_server_new_from_dump;
LassoServer* lasso_server_new_from_dump(gchar *dump);

/* Destructor */

void lasso_server_destroy(LassoServer *server);

/* Methods */

gint lasso_server_add_provider(LassoServer *server, gchar *metadata, gchar *public_key,
			       gchar *ca_certificate);

%newobject lasso_server_dump;
gchar* lasso_server_dump(LassoServer *server);


/***********************************************************************
 * Identity
 ***********************************************************************/


typedef struct {
	GObject parent;
	GPtrArray *providerIDs; /* list of the remote provider ids for federations hash table */
	GHashTable *federations; /* hash for federations with remote ProviderID as key */
	gboolean is_dirty;

	%extend {
		LassoIdentity() {
			return lasso_identity_new();
		}

		~LassoIdentity() {
			lasso_identity_destroy(self);
		}
	}
} LassoIdentity;

/* Constructors */

%newobject lasso_identity_new;
LassoIdentity* lasso_identity_new(void);

%newobject lasso_identity_new_from_dump;
LassoIdentity* lasso_identity_new_from_dump(gchar *dump);

/* Destructor */

void lasso_identity_destroy(LassoIdentity *identity);

/* Methods */

%newobject lasso_identity_dump;
gchar* lasso_identity_dump(LassoIdentity *identity);


/***********************************************************************
 * Session
 ***********************************************************************/


typedef struct {
	GObject parent;
	GPtrArray *providerIDs; /* list of the remote provider ids for federations hash table */
	GHashTable *assertions;  /* hash for assertions with remote providerID as key */
	gboolean is_dirty;

	%extend {
		LassoSession() {
			return lasso_session_new();
		}

		~LassoSession() {
			lasso_session_destroy(self);
		}
	}
} LassoSession;

/* Constructors */

%newobject lasso_session_new;
LassoSession* lasso_session_new(void);

%newobject lasso_session_new_from_dump;
LassoSession* lasso_session_new_from_dump(gchar *dump);

/* Destructor */

void lasso_session_destroy(LassoSession *session);

/* Methods */

%newobject lasso_session_dump;
gchar* lasso_session_dump(LassoSession *session);

%newobject lasso_session_get_authentication_method;
gchar* lasso_session_get_authentication_method(LassoSession *session, gchar *remote_providerID);


/***********************************************************************
 * Profile
 ***********************************************************************/


%nodefault _LassoProfile;
typedef struct _LassoProfile {
	GObject parent;
	LassoServer *server;
	LassoNode *request;
	LassoNode *response;
	gchar *nameIdentifier;
	gchar *remote_providerID;
	gchar *msg_url;
	gchar *msg_body;
	gchar *msg_relayState;
	lassoMessageType request_type;
	lassoMessageType response_type;
} LassoProfile;

/* Methods */

LassoAuthnRequest* lasso_profile_get_authn_request_ref(LassoProfile *profile);

LassoAuthnResponse* lasso_profile_get_authn_response_ref(LassoProfile *profile);

%newobject lasso_profile_get_identity;
LassoIdentity* lasso_profile_get_identity(LassoProfile *profile);

LassoRequest* lasso_profile_get_request_ref(LassoProfile *profile);

LassoResponse* lasso_profile_get_response_ref(LassoProfile *profile);

%newobject lasso_profile_get_session;
LassoSession* lasso_profile_get_session(LassoProfile *profile);

gboolean lasso_profile_is_identity_dirty(LassoProfile *profile);

gboolean lasso_profile_is_session_dirty(LassoProfile *profile);

gint lasso_profile_set_remote_providerID(LassoProfile *profile, gchar *providerID);

void lasso_profile_set_response_status(LassoProfile *profile, const gchar *statusCodeValue);

gint lasso_profile_set_identity(LassoProfile  *profile, LassoIdentity *identity);

gint lasso_profile_set_identity_from_dump(LassoProfile *profile, const gchar *dump);

gint lasso_profile_set_session(LassoProfile *profile, LassoSession *session);

gint lasso_profile_set_session_from_dump(LassoProfile *profile, const gchar *dump);

/* Functions */

lassoRequestType lasso_profile_get_request_type_from_soap_msg(gchar *soap);


/***********************************************************************
 * Defederation
 ***********************************************************************/


typedef struct {
	LassoProfile parent;

	%extend {
		LassoDefederation(LassoServer *server, lassoProviderType provider_type) {
			return lasso_defederation_new(server, provider_type);
		}

		~LassoDefederation() {
			lasso_defederation_destroy(self);
		}
	}
} LassoDefederation;

/* Constructors */

%newobject lasso_defederation_new;
LassoDefederation* lasso_defederation_new(LassoServer *server, lassoProviderType provider_type);

/* Destructor */

void lasso_defederation_destroy(LassoDefederation *defederation);

/* Methods */

gint lasso_defederation_build_notification_msg(LassoDefederation *defederation);

gint lasso_defederation_init_notification(LassoDefederation *defederation,
					  gchar *remote_providerID);

gint lasso_defederation_process_notification_msg(LassoDefederation *defederation,
						 gchar *notification_msg,
						 lassoHttpMethod notification_method);

gint lasso_defederation_validate_notification(LassoDefederation *defederation);


/***********************************************************************
 * Login
 ***********************************************************************/


typedef struct {
	LassoProfile parent;
	lassoLoginProtocolProfile protocolProfile;
	gchar *assertionArtifact;
	gchar *response_dump;

	%extend {
		LassoLogin(LassoServer *server) {
			return lasso_login_new(server);
		}

		~LassoLogin() {
			lasso_login_destroy(self);
		}
	}
} LassoLogin;

/* Constructors */

%newobject lasso_login_new;
LassoLogin* lasso_login_new(LassoServer *server);

%newobject lasso_login_new_from_dump;
LassoLogin* lasso_login_new_from_dump(LassoServer *server, gchar *dump);

/* Destructor */

void lasso_login_destroy(LassoLogin *login);

/* Methods */

gint lasso_login_accept_sso(LassoLogin *login);

gint lasso_login_build_artifact_msg(LassoLogin *login, gint authentication_result,
				    const gchar *authenticationMethod,
				    const gchar *reauthenticateOnOrAfter,
				    lassoHttpMethod http_method);

gint lasso_login_build_authn_request_msg(LassoLogin *login, const gchar *remote_providerID);

gint lasso_login_build_authn_response_msg(LassoLogin  *login, gint authentication_result,
					  const gchar *authenticationMethod,
					  const gchar *reauthenticateOnOrAfter);

gint lasso_login_build_request_msg(LassoLogin *login);

%newobject lasso_login_dump;
gchar* lasso_login_dump(LassoLogin *login);

gint lasso_login_init_authn_request(LassoLogin *login, lassoHttpMethod http_method);

gint lasso_login_init_from_authn_request_msg(LassoLogin *login, gchar *authn_request_msg,
					     lassoHttpMethod  authn_request_http_method);

gint lasso_login_init_request(LassoLogin *login, gchar *response_msg,
			      lassoHttpMethod response_http_method);

gboolean lasso_login_must_authenticate(LassoLogin *login);

gint lasso_login_process_authn_response_msg(LassoLogin *login, gchar *authn_response_msg);

gint lasso_login_process_request_msg(LassoLogin *login, gchar *request_msg);

gint lasso_login_process_response_msg(LassoLogin  *login, gchar *response_msg);


/***********************************************************************
 * Logout
 ***********************************************************************/


typedef struct {
	LassoProfile parent;

	%extend {
		LassoLogout(LassoServer *server, lassoProviderType provider_type) {
			return lasso_logout_new(server, provider_type);
		}

		~LassoLogout() {
			lasso_logout_destroy(self);
		}
	}
} LassoLogout;

/* Constructors */

%newobject lasso_logout_new;
LassoLogout* lasso_logout_new(LassoServer *server, lassoProviderType provider_type);

/* Destructor */

void lasso_logout_destroy(LassoLogout *logout);

/* Methods */

gint lasso_logout_build_request_msg(LassoLogout *logout);

gint lasso_logout_build_response_msg(LassoLogout *logout);

%newobject lasso_logout_get_next_providerID;
gchar* lasso_logout_get_next_providerID (LassoLogout *logout);

gint lasso_logout_init_request(LassoLogout *logout, gchar *remote_providerID);

gint lasso_logout_process_request_msg(LassoLogout *logout, gchar *request_msg,
				      lassoHttpMethod request_method);

gint lasso_logout_process_response_msg(LassoLogout *logout, gchar *response_msg,
				       lassoHttpMethod response_method);

gint lasso_logout_validate_request(LassoLogout *logout);


/***********************************************************************
 * LECP
 ***********************************************************************/


typedef struct {
	LassoLogin parent;

	%extend {
		LassoLecp(LassoServer *server) {
			return lasso_lecp_new(server);
		}

		~LassoLecp() {
			lasso_lecp_destroy(self);
		}
	}
} LassoLecp;

/* Constructors */

%newobject lasso_lecp_new;
LassoLecp* lasso_lecp_new(LassoServer *server);

/* Destructor */

void lasso_lecp_destroy(LassoLecp *lecp);

/* Methods */

gint lasso_lecp_build_authn_request_envelope_msg(LassoLecp *lecp);

gint lasso_lecp_build_authn_request_msg(LassoLecp *lecp, const gchar *remote_providerID);

gint lasso_lecp_build_authn_response_envelope_msg(LassoLecp *lecp, gint authentication_result,
						  const gchar *authenticationMethod,
						  const gchar *reauthenticateOnOrAfter);

gint lasso_lecp_build_authn_response_msg(LassoLecp *lecp);

gint lasso_lecp_init_authn_request(LassoLecp *lecp);

gint lasso_lecp_init_from_authn_request_msg(LassoLecp *lecp, gchar *authn_request_msg,
					    lassoHttpMethod authn_request_method);

gint lasso_lecp_process_authn_request_envelope_msg(LassoLecp *lecp, gchar *request_msg);
  
gint lasso_lecp_process_authn_response_envelope_msg(LassoLecp *lecp, gchar *response_msg);
