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


#include <lasso_config.h>
#include <lasso.h>


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
%constant xmlChar *lassoLibProtocolProfileSSOGet = "http://projectliberty.org/profiles/sso-get";
%constant xmlChar *lassoLibProtocolProfileSSOPost = "http://projectliberty.org/profiles/sso-post";
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
	lassoRequestTypeFederationTermination,
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
			    gchar *certificate, guint signature_method);
		~LassoServer();
	}
} LassoServer;

/* Constructors */

%newobject lasso_server_new;
LassoServer* lasso_server_new(gchar *metadata, gchar *public_key, gchar *private_key,
			      gchar *certificate, guint signature_method);

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
		LassoIdentity();
		~LassoIdentity();
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
		LassoSession();
		~LassoSession();
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
 * Login
 ***********************************************************************/


typedef struct {
	LassoProfile parent;
	lassoLoginProtocolProfile protocolProfile;
	gchar *assertionArtifact;
	gchar *response_dump;

	%extend {
		LassoLogin(LassoServer *server);
		~LassoLogin();
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
				    const gchar *reauthenticateOnOrAfter, lassoHttpMethod method);

gint lasso_login_build_authn_request_msg(LassoLogin *login, const gchar *remote_providerID);

gint lasso_login_build_authn_response_msg(LassoLogin  *login, gint authentication_result,
					  const gchar *authenticationMethod,
					  const gchar *reauthenticateOnOrAfter);

gint lasso_login_build_request_msg(LassoLogin *login);

%newobject lasso_login_dump;
gchar* lasso_login_dump(LassoLogin *login);

gint lasso_login_init_authn_request(LassoLogin *login);

gint lasso_login_init_from_authn_request_msg(LassoLogin *login, gchar *authn_request_msg,
					     lassoHttpMethod  authn_request_method);

gint lasso_login_init_request(LassoLogin *login, gchar *response_msg,
			      lassoHttpMethod response_method);

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
		LassoLogout(LassoServer *server, lassoProviderType provider_type);
		~LassoLogout();
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
		LassoLecp(LassoServer *server);
		~LassoLecp();
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


#ifdef 0

/***********************************************************************
 ***********************************************************************
 * Unsorted
 ***********************************************************************
 ***********************************************************************/


/* xml/strings.h */
/* xml/tools.h */

/* protocols/authn_request_envelope.h */
/* protocols/auth_response_envelope.h */
/* environs/login.h */

/*
 */

#define LASSO_TYPE_FEDERATION_TERMINATION (lasso_federation_termination_get_type())
#define LASSO_FEDERATION_TERMINATION(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_FEDERATION_TERMINATION, LassoFederationTermination))
/*#define LASSO_FEDERATION_TERMINATION_CLASS(klass)
 * (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_FEDERATION_TERMINATION,
 * LassoFederationTerminationClass))*/
#define LASSO_IS_FEDERATION_TERMINATION(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_FEDERATION_TERMINATION))
#define LASSO_IS_FEDERATION_TERMINATION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_FEDERATION_TERMINATION))
/*#define LASSO_FEDERATION_TERMINATION_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS
 * ((o), LASSO_TYPE_FEDERATION_TERMINATION, LassoFederationTerminationClass)) */


typedef struct _LassoFederationTermination {
  LassoProfile parent;

  /*< private >*/
} LassoFederationTermination;

/*struct _LassoFederationTerminationClass {
  LassoProfileClass parent;

};*/

GType                       lasso_federation_termination_get_type (void);
LassoFederationTermination *lasso_federation_termination_new      (LassoServer *server,
										gint         provider_type);
  

gint lasso_federation_termination_build_notification_msg   (LassoFederationTermination *defederation);

void lasso_federation_termination_destroy                  (LassoFederationTermination *defederation);

gint lasso_federation_termination_init_notification        (LassoFederationTermination *defederation,
									 gchar                      *remote_providerID);

gint lasso_federation_termination_process_notification_msg (LassoFederationTermination *defederation,
									 gchar                      *request_msg,
									 lassoHttpMethod             request_method);
  
gint lasso_federation_termination_validate_notification    (LassoFederationTermination *defederation);


  
/*
 */

#define LASSO_TYPE_NAME_IDENTIFIER_MAPPING (lasso_name_identifier_mapping_get_type())
#define LASSO_NAME_IDENTIFIER_MAPPING(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_NAME_IDENTIFIER_MAPPING, LassoNameIdentifierMapping))
/*#define LASSO_NAME_IDENTIFIER_MAPPING_CLASS(klass)
 * (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_NAME_IDENTIFIER_MAPPING,
 * LassoNameIdentifierMappingClass))*/
#define LASSO_IS_NAME_IDENTIFIER_MAPPING(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_NAME_IDENTIFIER_MAPPING))
#define LASSO_IS_NAME_IDENTIFIER_MAPPING_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_NAME_IDENTIFIER_MAPPING))
/*#define LASSO_NAME_IDENTIFIER_MAPPING_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS
 * ((o), LASSO_TYPE_NAME_IDENTIFIER_MAPPING, LassoNameIdentifierMappingClass))
 * */

/*typedef struct _LassoNameIdentifierMappingClass
 * LassoNameIdentifierMappingClass;*/

typedef struct _LassoNameIdentifierMapping {
  LassoProfile parent;

  /*< private >*/
} LassoNameIdentifierMapping;

/*struct _LassoNameIdentifierMappingClass {
  LassoProfileClass parent;

};*/

GType                       lasso_name_identifier_mapping_get_type             (void);

LassoNameIdentifierMapping* lasso_name_identifier_mapping_new                  (LassoServer       *server,
											     LassoIdentity     *identity,
											     lassoProviderType  provider_type);
 
gint                        lasso_name_identifier_mapping_build_request_msg    (LassoNameIdentifierMapping *mapping);

gint                        lasso_name_identifier_mapping_build_response_msg   (LassoNameIdentifierMapping *mapping);

gint                        lasso_name_identifier_mapping_init_request         (LassoNameIdentifierMapping *mapping,
											     gchar                      *remote_providerID);

gint                        lasso_name_identifier_mapping_process_request_msg  (LassoNameIdentifierMapping *mapping,
											     gchar                      *request_msg,
											     lassoHttpMethod             request_method);

gint                        lasso_name_identifier_mapping_process_response_msg (LassoNameIdentifierMapping *mapping,
											     gchar                      *response_msg,
											     lassoHttpMethod             response_method);


/*
 */

#define LASSO_TYPE_REGISTER_NAME_IDENTIFIER (lasso_register_name_identifier_get_type())
#define LASSO_REGISTER_NAME_IDENTIFIER(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_REGISTER_NAME_IDENTIFIER, LassoRegisterNameIdentifier))
/*#define LASSO_REGISTER_NAME_IDENTIFIER_CLASS(klass)
 * (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_REGISTER_NAME_IDENTIFIER,
 * LassoRegisterNameIdentifierClass))*/
#define LASSO_IS_REGISTER_NAME_IDENTIFIER(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_REGISTER_NAME_IDENTIFIER))
#define LASSO_IS_REGISTER_NAME_IDENTIFIER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_REGISTER_NAME_IDENTIFIER))
/*#define LASSO_REGISTER_NAME_IDENTIFIER_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS
 * ((o), LASSO_TYPE_REGISTER_NAME_IDENTIFIER, LassoRegisterNameIdentifierClass))
 * */

/*typedef struct _LassoRegisterNameIdentifierClass
 * LassoRegisterNameIdentifierClass;*/

typedef struct _LassoRegisterNameIdentifier {
  LassoProfile parent;

  /*< private >*/
} LassoRegisterNameIdentifier;

/*struct _LassoRegisterNameIdentifierClass {
  LassoProfileClass parent;

};*/

GType                        lasso_register_name_identifier_get_type (void);

LassoRegisterNameIdentifier* lasso_register_name_identifier_new      (LassoServer       *server,
										   lassoProviderType  provider_type);
 
gint            lasso_register_name_identifier_build_request_msg     (LassoRegisterNameIdentifier *register_name_identifier);

gint            lasso_register_name_identifier_build_response_msg    (LassoRegisterNameIdentifier *register_name_identifier);

void            lasso_register_name_identifier_destroy               (LassoRegisterNameIdentifier *register_name_identifier);

gint            lasso_register_name_identifier_init_request          (LassoRegisterNameIdentifier *register_name_identifier,
										   gchar                       *remote_providerID);

/* gint            lasso_register_name_identifier_load_request_msg      (LassoRegisterNameIdentifier *register_name_identifier,
										   gchar                       *request_msg,
										   lassoHttpMethod              request_method);
gint            lasso_register_name_identifier_process_request       (LassoRegisterNameIdentifier *register_name_identifier);
*/

gint            lasso_register_name_identifier_process_response_msg  (LassoRegisterNameIdentifier *register_name_identifier,
										   gchar                       *response_msg,
										   lassoHttpMethod              response_method);
  


/*
 */

typedef enum {
  lassoCheckVersionExact = 0,
  lassoCheckVersionABICompatible
} lassoCheckVersionMode;

int lasso_check_version_ext(int major,
					 int minor,
					 int subminor,
					 lassoCheckVersionMode mode);



/*
 */

#define LASSO_TYPE_AUTHN_REQUEST_ENVELOPE (lasso_authn_request_envelope_get_type())
#define LASSO_AUTHN_REQUEST_ENVELOPE(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_AUTHN_REQUEST_ENVELOPE, LassoAuthnRequestEnvelope))
/*#define LASSO_AUTHN_REQUEST_ENVELOPE_CLASS(klass)
 * (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_AUTHN_REQUEST_ENVELOPE,
 * LassoAuthnRequestEnvelopeClass))*/
#define LASSO_IS_AUTHN_REQUEST_ENVELOPE(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_AUTHN_REQUEST_ENVELOPE))
#define LASSO_IS_AUTHN_REQUEST_ENVELOPE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_AUTHN_REQUEST_ENVELOPE))
/*#define LASSO_AUTHN_REQUEST_ENVELOPE_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS
 * ((o), LASSO_TYPE_AUTHN_REQUEST_ENVELOPE, LassoAuthnRequestEnvelopeClass)) */

/*typedef struct _LassoAuthnRequestEnvelopeClass
 * LassoAuthnRequestEnvelopeClass;*/

typedef struct _LassoAuthnRequestEnvelope {
  LassoLibAuthnRequestEnvelope parent;
  /*< public >*/
  /*< private >*/
} LassoAuthnRequestEnvelope;

/*struct _LassoAuthnRequestEnvelopeClass {
  LassoLibAuthnRequestEnvelopeClass parent;
};*/

GType      lasso_authn_request_envelope_get_type         (void);

LassoNode* lasso_authn_request_envelope_new              (LassoAuthnRequest *authnRequest,
								       xmlChar           *providerID,
								       xmlChar           *assertionConsumerServiceURL);

LassoNode* lasso_authn_request_envelope_get_authnRequest (LassoAuthnRequestEnvelope *request);

LassoNode* lasso_authn_request_envelope_new_from_export  (gchar               *buffer,
								       lassoNodeExportType  export_type);

/*
 */

#define LASSO_TYPE_AUTHN_RESPONSE_ENVELOPE (lasso_authn_response_envelope_get_type())
#define LASSO_AUTHN_RESPONSE_ENVELOPE(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_AUTHN_RESPONSE_ENVELOPE, LassoAuthnResponseEnvelope))
/*#define LASSO_AUTHN_RESPONSE_ENVELOPE_CLASS(klass)
 * (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_AUTHN_RESPONSE_ENVELOPE,
 * LassoAuthnResponseEnvelopeClass))*/
#define LASSO_IS_AUTHN_RESPONSE_ENVELOPE(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_AUTHN_RESPONSE_ENVELOPE))
#define LASSO_IS_AUTHN_RESPONSE_ENVELOPE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_AUTHN_RESPONSE_ENVELOPE))
/*#define LASSO_AUTHN_RESPONSE_ENVELOPE_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS
 * ((o), LASSO_TYPE_AUTHN_RESPONSE_ENVELOPE, LassoAuthnResponseEnvelopeClass))
 * */

/*typedef struct _LassoAuthnResponseEnvelopeClass
 * LassoAuthnResponseEnvelopeClass;*/

typedef struct _LassoAuthnResponseEnvelope {
  LassoLibAuthnResponseEnvelope parent;
  /*< public >*/
  /*< private >*/
} LassoAuthnResponseEnvelope;

/*struct _LassoAuthnResponseEnvelopeClass {
  LassoLibAuthnResponseEnvelopeClass parent;
};*/

GType      lasso_authn_response_envelope_get_type                        (void);

LassoNode* lasso_authn_response_envelope_new                             (LassoAuthnResponse *authnResponse,
										       xmlChar            *assertionConsumerServiceURL);

xmlChar*   lasso_authn_response_envelope_get_assertionConsumerServiceURL (LassoAuthnResponseEnvelope *response);

LassoNode* lasso_authn_response_envelope_get_authnResponse               (LassoAuthnResponseEnvelope *response);

LassoNode* lasso_authn_response_envelope_new_from_export                 (gchar               *buffer,
										       lassoNodeExportType  export_type);

/*
 */
#define LASSO_TYPE_FEDERATION (lasso_federation_get_type())
#define LASSO_FEDERATION(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_FEDERATION, LassoFederation))
/*#define LASSO_FEDERATION_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass),
 * LASSO_TYPE_FEDERATION, LassoFederationClass))*/
#define LASSO_IS_FEDERATION(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_FEDERATION))
#define LASSO_IS_FEDERATION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_FEDERATION))
/*#define LASSO_FEDERATION_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o),
 * LASSO_TYPE_FEDERATION, LassoFederationClass)) */

#define LASSO_FEDERATION_NODE "Federation"
#define LASSO_FEDERATION_REMOTE_PROVIDERID_NODE "RemoteProviderID"
#define LASSO_FEDERATION_LOCAL_NAME_IDENTIFIER_NODE "LocalNameIdentifier"
#define LASSO_FEDERATION_REMOTE_NAME_IDENTIFIER_NODE "RemoteNameIdentifier"

/*typedef struct _LassoFederationClass LassoFederationClass;*/
typedef struct _LassoFederationPrivate LassoFederationPrivate;

typedef struct _LassoFederation {
  GObject parent;
  
  gchar *remote_providerID;

  LassoNode *local_nameIdentifier;
  LassoNode *remote_nameIdentifier;

  /*< private >*/
  LassoFederationPrivate *private;
} LassoFederation;

/*struct _LassoFederationClass {
  GObjectClass parent;
};*/

GType            lasso_federation_get_type                     (void);

LassoFederation* lasso_federation_new                          (gchar *remote_providerID);

LassoFederation* lasso_federation_new_from_dump                (xmlChar *dump);

LassoFederation* lasso_federation_copy                         (LassoFederation *federation);

void             lasso_federation_destroy                      (LassoFederation *federation);

xmlChar*         lasso_federation_dump                         (LassoFederation *federation);

LassoNode*       lasso_federation_get_remote_nameIdentifier    (LassoFederation *federation);

LassoNode*       lasso_federation_get_local_nameIdentifier     (LassoFederation *federation);

void             lasso_federation_remove_local_nameIdentifier  (LassoFederation *federation);

void             lasso_federation_remove_remote_nameIdentifier (LassoFederation *federation);

void             lasso_federation_set_local_nameIdentifier     (LassoFederation *federation,
									     LassoNode       *nameIdentifier);

void             lasso_federation_set_remote_nameIdentifier    (LassoFederation *federation,
									     LassoNode       *nameIdentifier);

gboolean         lasso_federation_verify_nameIdentifier        (LassoFederation *federation,
									     LassoNode       *nameIdentifier);

/*
 */
#define LASSO_TYPE_FEDERATION_TERMINATION_NOTIFICATION (lasso_federation_termination_notification_get_type())
#define LASSO_FEDERATION_TERMINATION_NOTIFICATION(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_FEDERATION_TERMINATION_NOTIFICATION, LassoFederationTerminationNotification))
/*#define LASSO_FEDERATION_TERMINATION_NOTIFICATION_CLASS(klass)
 * (G_TYPE_CHECK_CLASS_CAST((klass),
 * LASSO_TYPE_FEDERATION_TERMINATION_NOTIFICATION,
 * LassoFederationTerminationNotificationClass))*/
#define LASSO_IS_FEDERATION_TERMINATION_NOTIFICATION(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_FEDERATION_TERMINATION_NOTIFICATION))
#define LASSO_IS_FEDERATION_TERMINATION_NOTIFICATION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_FEDERATION_TERMINATION_NOTIFICATION))
/*#define LASSO_FEDERATION_TERMINATION_NOTIFICATION_GET_CLASS(o)
 * (G_TYPE_INSTANCE_GET_CLASS ((o),
 * LASSO_TYPE_FEDERATION_TERMINATION_NOTIFICATION,
 * LassoFederationTerminationNotificationClass)) */

/*typedef struct _LassoFederationTerminationNotificationClass
 * LassoFederationTerminationNotificationClass;*/

typedef struct _LassoFederationTerminationNotification {
  LassoLibFederationTerminationNotification parent;
  /*< public >*/
  /*< private >*/
} LassoFederationTerminationNotification;

/*struct _LassoFederationTerminationNotificationClass {
  LassoLibFederationTerminationNotificationClass parent;
};*/

GType      lasso_federation_termination_notification_get_type          (void);

LassoNode* lasso_federation_termination_notification_new               (const xmlChar *providerID,
										     const xmlChar *nameIdentifier,
										     const xmlChar *nameQualifier,
										     const xmlChar *format);

LassoNode* lasso_federation_termination_notification_new_from_export   (const xmlChar       *export,
										     lassoNodeExportType  export_type);

/*
 */
#define LASSO_TYPE_LOGOUT_REQUEST (lasso_logout_request_get_type())
#define LASSO_LOGOUT_REQUEST(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_LOGOUT_REQUEST, LassoLogoutRequest))
/*#define LASSO_LOGOUT_REQUEST_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass),
 * LASSO_TYPE_LOGOUT_REQUEST, LassoLogoutRequestClass))*/
#define LASSO_IS_LOGOUT_REQUEST(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_LOGOUT_REQUEST))
#define LASSO_IS_LOGOUT_REQUEST_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_LOGOUT_REQUEST))
/*#define LASSO_LOGOUT_REQUEST_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o),
 * LASSO_TYPE_LOGOUT_REQUEST, LassoLogoutRequestClass)) */

/*typedef struct _LassoLogoutRequestClass LassoLogoutRequestClass;*/

typedef struct _LassoLogoutRequest {
  LassoLibLogoutRequest parent;
  /*< public >*/
  /*< private >*/
} LassoLogoutRequest;

/*struct _LassoLogoutRequestClass {
  LassoLibLogoutRequestClass parent;
};*/

GType      lasso_logout_request_get_type        (void);

LassoNode* lasso_logout_request_new             (gchar *providerID,
							      gchar *nameIdentifier,
							      gchar *nameQualifier,
							      gchar *format);

LassoNode* lasso_logout_request_new_from_export (gchar               *buffer,
							      lassoNodeExportType  export_type);

/*
 */
#define LASSO_TYPE_LOGOUT_RESPONSE (lasso_logout_response_get_type())
#define LASSO_LOGOUT_RESPONSE(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_LOGOUT_RESPONSE, LassoLogoutResponse))
/*#define LASSO_LOGOUT_RESPONSE_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass),
 * LASSO_TYPE_LOGOUT_RESPONSE, LassoLogoutResponseClass))*/
#define LASSO_IS_LOGOUT_RESPONSE(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_LOGOUT_RESPONSE))
#define LASSO_IS_LOGOUT_RESPONSE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_LOGOUT_RESPONSE))
/*#define LASSO_LOGOUT_RESPONSE_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o),
 * LASSO_TYPE_LOGOUT_RESPONSE, LassoLogoutResponseClass)) */

/*typedef struct _LassoLogoutResponseClass LassoLogoutResponseClass;*/

typedef struct _LassoLogoutResponse {
  LassoLibLogoutResponse parent;
  /*< public >*/
  /*< private >*/
} LassoLogoutResponse;

/*struct _LassoLogoutResponseClass {
  LassoLibLogoutResponseClass parent;
};*/

GType      lasso_logout_response_get_type                (void);

LassoNode* lasso_logout_response_new                     (gchar       *providerID,
								       const gchar *statusCodeValue,
								       LassoNode   *request);

LassoNode* lasso_logout_response_new_from_export         (gchar               *buffer,
								       lassoNodeExportType  export_type);

LassoNode* lasso_logout_response_new_from_request_export (gchar               *buffer,
								       lassoNodeExportType  export_type,
								       gchar               *providerID,
								       gchar               *statusCodeValue);

/*
 */
#define LASSO_TYPE_NAME_IDENTIFIER_MAPPING_REQUEST (lasso_name_identifier_mapping_request_get_type())
#define LASSO_NAME_IDENTIFIER_MAPPING_REQUEST(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_NAME_IDENTIFIER_MAPPING_REQUEST, LassoNameIdentifierMappingRequest))
/*#define LASSO_NAME_IDENTIFIER_MAPPING_REQUEST_CLASS(klass)
 * (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_NAME_IDENTIFIER_MAPPING_REQUEST,
 * LassoNameIdentifierMappingRequestClass))*/
#define LASSO_IS_NAME_IDENTIFIER_MAPPING_REQUEST(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_NAME_IDENTIFIER_MAPPING_REQUEST))
#define LASSO_IS_NAME_IDENTIFIER_MAPPING_REQUEST_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_NAME_IDENTIFIER_MAPPING_REQUEST))
/*#define LASSO_NAME_IDENTIFIER_MAPPING_REQUEST_GET_CLASS(o)
 * (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_NAME_IDENTIFIER_MAPPING_REQUEST,
 * LassoNameIdentifierMappingRequestClass)) */

/*typedef struct _LassoNameIdentifierMappingRequestClass
 * LassoNameIdentifierMappingRequestClass;*/

typedef struct _LassoNameIdentifierMappingRequest {
  LassoLibNameIdentifierMappingRequest parent;
  /*< public >*/
  /*< private >*/
} LassoNameIdentifierMappingRequest;

/*struct _LassoNameIdentifierMappingRequestClass {
  LassoLibNameIdentifierMappingRequestClass parent;
};*/

GType      lasso_name_identifier_mapping_request_get_type          (void);
LassoNode *lasso_name_identifier_mapping_request_new               (const xmlChar *providerID,
										 const xmlChar *nameIdentifier,
										 const xmlChar *nameQualifier,
										 const xmlChar *format);


LassoNode *lasso_name_identifier_mapping_request_new_from_query    (const xmlChar *query);
LassoNode *lasso_name_identifier_mapping_request_new_from_soap     (const xmlChar *buffer);

/*
 */

#define LASSO_TYPE_NAME_IDENTIFIER_MAPPING_RESPONSE (lasso_name_identifier_mapping_response_get_type())
#define LASSO_NAME_IDENTIFIER_MAPPING_RESPONSE(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_NAME_IDENTIFIER_MAPPING_RESPONSE, LassoNameIdentifierMappingResponse))
/*#define LASSO_NAME_IDENTIFIER_MAPPING_RESPONSE_CLASS(klass)
 * (G_TYPE_CHECK_CLASS_CAST((klass),
 * LASSO_TYPE_NAME_IDENTIFIER_MAPPING_RESPONSE,
 * LassoNameIdentifierMappingResponseClass))*/
#define LASSO_IS_NAME_IDENTIFIER_MAPPING_RESPONSE(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_NAME_IDENTIFIER_MAPPING_RESPONSE))
#define LASSO_IS_NAME_IDENTIFIER_MAPPING_RESPONSE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_NAME_IDENTIFIER_MAPPING_RESPONSE))
/*#define LASSO_NAME_IDENTIFIER_MAPPING_RESPONSE_GET_CLASS(o)
 * (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_NAME_IDENTIFIER_MAPPING_RESPONSE,
 * LassoNameIdentifierMappingResponseClass)) */

/*typedef struct _LassoNameIdentifierMappingResponseClass
 * LassoNameIdentifierMappingResponseClass;*/

typedef struct _LassoNameIdentifierMappingResponse {
  LassoLibNameIdentifierMappingResponse parent;
  /*< public >*/
  /*< private >*/
} LassoNameIdentifierMappingResponse;

/*struct _LassoNameIdentifierMappingResponseClass {
  LassoLibNameIdentifierMappingResponseClass parent;
};*/

GType      lasso_name_identifier_mapping_response_get_type               (void);
LassoNode* lasso_name_identifier_mapping_response_new                    (const xmlChar *providerID,
										       const xmlChar *statusCodeValue,
										       LassoNode     *request);

LassoNode *lasso_name_identifier_mapping_response_new_from_dump          (const xmlChar *buffer);
LassoNode *lasso_name_identifier_mapping_response_new_from_query         (const xmlChar *query);
LassoNode *lasso_name_identifier_mapping_response_new_from_request_soap  (const xmlChar *buffer,
										       const xmlChar *providerID,
										       const xmlChar *statusCodeValue);
LassoNode *lasso_name_identifier_mapping_response_new_from_soap          (const xmlChar *buffer);
LassoNode *lasso_name_identifier_mapping_response_new_from_request_query (const xmlChar *query,
										       const xmlChar *providerID,
										       const xmlChar *statusCodeValue);

/*
 */
#define LASSO_TYPE_PROVIDER (lasso_provider_get_type())
#define LASSO_PROVIDER(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_PROVIDER, LassoProvider))
/*#define LASSO_PROVIDER_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass),
 * LASSO_TYPE_PROVIDER, LassoProviderClass))*/
#define LASSO_IS_PROVIDER(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_PROVIDER))
#define LASSO_IS_PROVIDER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_PROVIDER))
/*#define LASSO_PROVIDER_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o),
 * LASSO_TYPE_PROVIDER, LassoProviderClass)) */

#define LASSO_PROVIDER_NODE                "Provider"
#define LASSO_PROVIDER_PUBLIC_KEY_NODE     "PublicKey"
#define LASSO_PROVIDER_CA_CERTIFICATE_NODE "CaCertificate"

/*typedef struct _LassoProviderClass LassoProviderClass;*/
typedef struct _LassoProviderPrivate LassoProviderPrivate;

typedef struct _LassoProvider {
  GObject parent;

  LassoNode *metadata;

  gchar *public_key;
  gchar *ca_certificate;

  /*< private >*/
  LassoProviderPrivate *private;
} LassoProvider;

/*struct _LassoProviderClass {
  GObjectClass parent;
};*/

GType          lasso_provider_get_type                                             (void);

LassoProvider* lasso_provider_new                                                  (gchar *metadata,
												 gchar *public_key,
												 gchar *ca_certificate);

LassoProvider* lasso_provider_new_from_metadata_node                               (LassoNode *metadata_node);

LassoProvider* lasso_provider_new_metadata_filename                                (gchar *metadata_filename);

LassoProvider* lasso_provider_copy                                                 (LassoProvider *provider);

void           lasso_provider_destroy                                              (LassoProvider *provider);

gchar*         lasso_provider_dump                                                 (LassoProvider *provider);

gchar*         lasso_provider_get_assertionConsumerServiceURL                      (LassoProvider      *provider,
												 lassoProviderType   provider_type,
												 GError            **err);

gchar*         lasso_provider_get_authnRequestsSigned                              (LassoProvider  *provider,
												 GError        **err);

gchar*         lasso_provider_get_federationTerminationNotificationProtocolProfile (LassoProvider      *provider,
												 lassoProviderType   provider_type,
												 GError            **err);

/*
gchar*         lasso_provider_get_federationTerminationReturnServiceURL            (LassoProvider      *provider,
												 lassoProviderType   provider_type,
												 GError            **err);
*/
gchar*         lasso_provider_get_federationTerminationServiceURL                  (LassoProvider      *provider,
												 lassoProviderType   provider_type,
												 GError            **err);

gchar*         lasso_provider_get_nameIdentifierMappingProtocolProfile             (LassoProvider      *provider,
												 lassoProviderType   provider_type,
												 GError            **err);

gchar*         lasso_provider_get_providerID                                       (LassoProvider  *provider);

gchar*         lasso_provider_get_registerNameIdentifierProtocolProfile            (LassoProvider      *provider,
												 lassoProviderType   provider_type,
												 GError            **err);

gchar*         lasso_provider_get_registerNameIdentifierServiceURL                 (LassoProvider      *provider,
												 lassoProviderType   provider_type,
												 GError            **err);

gchar*         lasso_provider_get_singleSignOnProtocolProfile                      (LassoProvider  *provider,
												 GError        **err);

gchar*         lasso_provider_get_singleSignOnServiceURL                           (LassoProvider  *provider,
												 GError        **err);

gchar*         lasso_provider_get_singleLogoutProtocolProfile                      (LassoProvider      *provider,
												 lassoProviderType   provider_type,
												 GError            **err);

gchar*         lasso_provider_get_singleLogoutServiceURL                           (LassoProvider      *provider,
												 lassoProviderType   provider_type,
												 GError            **err);

gchar*         lasso_provider_get_singleLogoutServiceReturnURL                     (LassoProvider      *provider,
												 lassoProviderType   provider_type,
												 GError            **err);

gchar*         lasso_provider_get_soapEndpoint                                     (LassoProvider      *provider,
												 lassoProviderType   provider_type,
												 GError            **err);

void           lasso_provider_set_public_key                                       (LassoProvider *provider,
												 gchar         *public_key);

void           lasso_provider_set_ca_certificate                                   (LassoProvider *provider,
												 gchar         *ca_certificate);
/*
 */

#define LASSO_TYPE_REGISTER_NAME_IDENTIFIER_REQUEST (lasso_register_name_identifier_request_get_type())
#define LASSO_REGISTER_NAME_IDENTIFIER_REQUEST(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_REGISTER_NAME_IDENTIFIER_REQUEST, LassoRegisterNameIdentifierRequest))
/*#define LASSO_REGISTER_NAME_IDENTIFIER_REQUEST_CLASS(klass)
 * (G_TYPE_CHECK_CLASS_CAST((klass),
 * LASSO_TYPE_REGISTER_NAME_IDENTIFIER_REQUEST,
 * LassoRegisterNameIdentifierRequestClass))*/
#define LASSO_IS_REGISTER_NAME_IDENTIFIER_REQUEST(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_REGISTER_NAME_IDENTIFIER_REQUEST))
#define LASSO_IS_REGISTER_NAME_IDENTIFIER_REQUEST_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_REGISTER_NAME_IDENTIFIER_REQUEST))
/*#define LASSO_REGISTER_NAME_IDENTIFIER_REQUEST_GET_CLASS(o)
 * (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_REGISTER_NAME_IDENTIFIER_REQUEST,
 * LassoRegisterNameIdentifierRequestClass)) */

/*typedef struct _LassoRegisterNameIdentifierRequestClass
 * LassoRegisterNameIdentifierRequestClass;*/

typedef struct _LassoRegisterNameIdentifierRequest {
  LassoLibRegisterNameIdentifierRequest parent;
  /*< public >*/
  /*< private >*/
} LassoRegisterNameIdentifierRequest;

/*struct _LassoRegisterNameIdentifierRequestClass {
  LassoLibRegisterNameIdentifierRequestClass parent;
};*/

GType      lasso_register_name_identifier_request_get_type              (void);

LassoNode* lasso_register_name_identifier_request_new                   (const xmlChar *providerID,
										      const xmlChar *idpProvidedNameIdentifier,
										      const xmlChar *idpNameQualifier,
										      const xmlChar *idpFormat,
										      const xmlChar *spProvidedNameIdentifier,
										      const xmlChar *spNameQualifier,
										      const xmlChar *spFormat,
										      const xmlChar *oldProvidedNameIdentifier,
										      const xmlChar *oldNameQualifier,
										      const xmlChar *oldFormat);

LassoNode* lasso_register_name_identifier_request_new_from_export       (gchar               *buffer,
										      lassoNodeExportType  export_type);

void lasso_register_name_identifier_request_rename_attributes_for_query (LassoRegisterNameIdentifierRequest *request);

/*
 */

#define LASSO_TYPE_REGISTER_NAME_IDENTIFIER_RESPONSE (lasso_register_name_identifier_response_get_type())
#define LASSO_REGISTER_NAME_IDENTIFIER_RESPONSE(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_REGISTER_NAME_IDENTIFIER_RESPONSE, LassoRegisterNameIdentifierResponse))
/*#define LASSO_REGISTER_NAME_IDENTIFIER_RESPONSE_CLASS(klass)
 * (G_TYPE_CHECK_CLASS_CAST((klass),
 * LASSO_TYPE_REGISTER_NAME_IDENTIFIER_RESPONSE,
 * LassoRegisterNameIdentifierResponseClass))*/
#define LASSO_IS_REGISTER_NAME_IDENTIFIER_RESPONSE(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_REGISTER_NAME_IDENTIFIER_RESPONSE))
#define LASSO_IS_REGISTER_NAME_IDENTIFIER_RESPONSE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_REGISTER_NAME_IDENTIFIER_RESPONSE))
/*#define LASSO_REGISTER_NAME_IDENTIFIER_RESPONSE_GET_CLASS(o)
 * (G_TYPE_INSTANCE_GET_CLASS ((o),
 * LASSO_TYPE_REGISTER_NAME_IDENTIFIER_RESPONSE,
 * LassoRegisterNameIdentifierResponseClass)) */

/*typedef struct _LassoRegisterNameIdentifierResponseClass
 * LassoRegisterNameIdentifierResponseClass;*/

typedef struct _LassoRegisterNameIdentifierResponse {
  LassoLibRegisterNameIdentifierResponse parent;
  /*< public >*/
  /*< private >*/
} LassoRegisterNameIdentifierResponse;

/*struct _LassoRegisterNameIdentifierResponseClass {
  LassoLibRegisterNameIdentifierResponseClass parent;
};*/

GType       lasso_register_name_identifier_response_get_type                (void);

LassoNode*  lasso_register_name_identifier_response_new                     (gchar     *providerID,
											  gchar     *statusCodeValue,
											  LassoNode *request);

LassoNode*  lasso_register_name_identifier_response_new_from_export         (gchar               *buffer,
											  lassoNodeExportType  export_type);

LassoNode*  lasso_register_name_identifier_response_new_from_request_export (gchar               *buffer,
											  lassoNodeExportType  export_type,
											  gchar               *providerID,
											  gchar               *statusCodeValue);


/*
 */

#define LASSO_TYPE_DS_SIGNATURE (lasso_ds_signature_get_type())
#define LASSO_DS_SIGNATURE(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_DS_SIGNATURE, LassoDsSignature))
/*#define LASSO_DS_SIGNATURE_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass),
 * LASSO_TYPE_DS_SIGNATURE, LassoDsSignatureClass))*/
#define LASSO_IS_DS_SIGNATURE(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_DS_SIGNATURE))
#define LASSO_IS_DS_SIGNATURE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_DS_SIGNATURE))
/*#define LASSO_DS_SIGNATURE_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o),
 * LASSO_TYPE_DS_SIGNATURE, LassoDsSignatureClass)) */

/*typedef struct _LassoDsSignatureClass LassoDsSignatureClass;*/

typedef struct _LassoDsSignature {
  LassoNode parent;
  /*< private >*/
} LassoDsSignature;

/*struct _LassoDsSignatureClass {
  LassoNodeClass parent;
};*/

GType lasso_ds_signature_get_type(void);
/*
LassoNode* lasso_ds_signature_new(LassoNode        *node,
					       xmlSecTransformId sign_method);
gint lasso_ds_signature_sign (LassoDsSignature  *node,
					   const xmlChar     *private_key_file,
					   const xmlChar     *certificate_file,
					   GError           **err);
*/

/*
 */

#define LASSO_XML_ERROR_NODE_NOTFOUND  -1
#define LASSO_XML_ERROR_NODE_CONTENT_NOTFOUND  -2
#define LASSO_XML_ERROR_ATTR_NOTFOUND  -3
#define LASSO_XML_ERROR_ATTR_VALUE_NOTFOUND  -4

#define LASSO_XML_ERROR_UNDEFINED  -99

#define LASSO_DS_ERROR_CONTEXT_CREATION_FAILED       -101
#define LASSO_DS_ERROR_PUBLIC_KEY_LOAD_FAILED        -102
#define LASSO_DS_ERROR_PRIVATE_KEY_LOAD_FAILED       -103
#define LASSO_DS_ERROR_CERTIFICATE_LOAD_FAILED       -104
#define LASSO_DS_ERROR_SIGNATURE_FAILED              -105
#define LASSO_DS_ERROR_SIGNATURE_NOTFOUND            -106
#define LASSO_DS_ERROR_KEYS_MNGR_CREATION_FAILED     -107
#define LASSO_DS_ERROR_KEYS_MNGR_INIT_FAILED         -108
#define LASSO_DS_ERROR_SIGNATURE_VERIFICATION_FAILED -109
#define LASSO_DS_ERROR_INVALID_SIGNATURE             -110

#define LASSO_PARAM_ERROR_INVALID_OBJ_TYPE -201
#define LASSO_PARAM_ERROR_INVALID_VALUE    -202

#define LASSO_ERR_ERROR_CHECK_FAILED  -666

/*const char* lasso_strerror(int error_code);*/
/*
 */
#define LASSO_TYPE_LIB_ASSERTION (lasso_lib_assertion_get_type())
#define LASSO_LIB_ASSERTION(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_LIB_ASSERTION, LassoLibAssertion))
/*#define LASSO_LIB_ASSERTION_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass),
 * LASSO_TYPE_LIB_ASSERTION, LassoLibAssertionClass))*/
#define LASSO_IS_LIB_ASSERTION(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_LIB_ASSERTION))
#define LASSO_IS_LIB_ASSERTION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_LIB_ASSERTION))
/*#define LASSO_LIB_ASSERTION_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o),
 * LASSO_TYPE_LIB_ASSERTION, LassoLibAssertionClass)) */

/*typedef struct _LassoLibAssertionClass LassoLibAssertionClass;*/

typedef struct _LassoLibAssertion {
  LassoSamlAssertion parent;
  /*< private >*/
} LassoLibAssertion;

/*struct _LassoLibAssertionClass {
  LassoSamlAssertionClass parent;
};*/

GType lasso_lib_assertion_get_type(void);
LassoNode* lasso_lib_assertion_new(void);

void lasso_lib_assertion_set_inResponseTo (LassoLibAssertion *,
							const xmlChar *);

/*
 */

#define LASSO_TYPE_LIB_AUTHENTICATION_STATEMENT (lasso_lib_authentication_statement_get_type())
#define LASSO_LIB_AUTHENTICATION_STATEMENT(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_LIB_AUTHENTICATION_STATEMENT, LassoLibAuthenticationStatement))
/*#define LASSO_LIB_AUTHENTICATION_STATEMENT_CLASS(klass)
 * (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_LIB_AUTHENTICATION_STATEMENT,
 * LassoLibAuthenticationStatementClass))*/
#define LASSO_IS_LIB_AUTHENTICATION_STATEMENT(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_LIB_AUTHENTICATION_STATEMENT))
#define LASSO_IS_LIB_AUTHENTICATION_STATEMENT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_LIB_AUTHENTICATION_STATEMENT))
/*#define LASSO_LIB_AUTHENTICATION_STATEMENT_GET_CLASS(o)
 * (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_LIB_AUTHENTICATION_STATEMENT,
 * LassoLibAuthenticationStatementClass)) */

/*typedef struct _LassoLibAuthenticationStatementClass
 * LassoLibAuthenticationStatementClass;*/

typedef struct _LassoLibAuthenticationStatement {
  LassoSamlAuthenticationStatement parent;
  /*< private >*/
} LassoLibAuthenticationStatement;

/*struct _LassoLibAuthenticationStatementClass {
  LassoSamlAuthenticationStatementClass parent;
};*/

GType lasso_lib_authentication_statement_get_type(void);
LassoNode* lasso_lib_authentication_statement_new(void);

void lasso_lib_authentication_statement_set_authnContext            (LassoLibAuthenticationStatement *node,
										  LassoLibAuthnContext *authnContext);

void lasso_lib_authentication_statement_set_reauthenticateOnOrAfter (LassoLibAuthenticationStatement *node,
										  const xmlChar *reauthenticateOnOrAfter);

void lasso_lib_authentication_statement_set_sessionIndex            (LassoLibAuthenticationStatement *node,
										  const xmlChar *sessionIndex);

/*
 */

#define LASSO_TYPE_LIB_AUTHN_CONTEXT (lasso_lib_authn_context_get_type())
#define LASSO_LIB_AUTHN_CONTEXT(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_LIB_AUTHN_CONTEXT, LassoLibAuthnContext))
/*#define LASSO_LIB_AUTHN_CONTEXT_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass),
 * LASSO_TYPE_LIB_AUTHN_CONTEXT, LassoLibAuthnContextClass))*/
#define LASSO_IS_LIB_AUTHN_CONTEXT(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_LIB_AUTHN_CONTEXT))
#define LASSO_IS_LIB_AUTHN_CONTEXT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_LIB_AUTHN_CONTEXT))
/*#define LASSO_LIB_AUTHN_CONTEXT_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o),
 * LASSO_TYPE_LIB_AUTHN_CONTEXT, LassoLibAuthnContextClass)) */

/*typedef struct _LassoLibAuthnContextClass LassoLibAuthnContextClass;*/

typedef struct _LassoLibAuthnContext {
  LassoNode parent;
  /*< private >*/
} LassoLibAuthnContext;

/*struct _LassoLibAuthnContextClass {
  LassoNodeClass parent;
};*/

GType lasso_lib_authn_context_get_type(void);
LassoNode* lasso_lib_authn_context_new(void);

void lasso_lib_authn_context_set_authnContextClassRef     (LassoLibAuthnContext *node,
									const xmlChar *authnContextClassRef);

void lasso_lib_authn_context_set_authnContextStatementRef (LassoLibAuthnContext *node,
									const xmlChar *authnContextStatementRef);


/*
 */

#define LASSO_TYPE_LIB_AUTHN_REQUEST_ENVELOPE (lasso_lib_authn_request_envelope_get_type())
#define LASSO_LIB_AUTHN_REQUEST_ENVELOPE(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_LIB_AUTHN_REQUEST_ENVELOPE, LassoLibAuthnRequestEnvelope))
/*#define LASSO_LIB_AUTHN_REQUEST_ENVELOPE_CLASS(klass)
 * (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_LIB_AUTHN_REQUEST_ENVELOPE,
 * LassoLibAuthnRequestEnvelopeClass))*/
#define LASSO_IS_LIB_AUTHN_REQUEST_ENVELOPE(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_LIB_AUTHN_REQUEST_ENVELOPE))
#define LASSO_IS_LIB_AUTHN_REQUEST_ENVELOPE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_LIB_AUTHN_REQUEST_ENVELOPE))
/*#define LASSO_LIB_AUTHN_REQUEST_ENVELOPE_GET_CLASS(o)
 * (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_LIB_AUTHN_REQUEST_ENVELOPE,
 * LassoLibAuthnRequestEnvelopeClass)) */

/*typedef struct _LassoLibAuthnRequestEnvelopeClass
 * LassoLibAuthnRequestEnvelopeClass;*/

typedef struct _LassoLibAuthnRequestEnvelope {
  LassoNode parent;

  /*< private >*/
} LassoLibAuthnRequestEnvelope;

/*struct _LassoLibAuthnRequestEnvelopeClass {
  LassoNodeClass parent;
};*/

GType      lasso_lib_authn_request_envelope_get_type         (void);

LassoNode* lasso_lib_authn_request_envelope_new              (void);

void       lasso_lib_authn_request_envelope_set_extension    (LassoLibAuthnRequestEnvelope *node,
									   LassoNode                    *extension);

void       lasso_lib_authn_request_envelope_set_authnRequest (LassoLibAuthnRequestEnvelope *node,
									   LassoLibAuthnRequest         *request);

void       lasso_lib_authn_request_envelope_set_assertionConsumerServiceURL (LassoLibAuthnRequestEnvelope *node,
											  const xmlChar *assertionConsumerServiceURL);

void       lasso_lib_authn_request_envelope_set_providerID   (LassoLibAuthnRequestEnvelope *node,
									   const xmlChar                *providerID);

void       lasso_lib_authn_request_envelope_set_providerName (LassoLibAuthnRequestEnvelope *node,
									   const xmlChar                *providerName);

void       lasso_lib_authn_request_envelope_set_idpList      (LassoLibAuthnRequestEnvelope *node,
									   LassoLibIDPList              *idpList);

void       lasso_lib_authn_request_envelope_set_isPassive    (LassoLibAuthnRequestEnvelope *node,
									   gboolean                      isPassive);

/*
 */
#define LASSO_TYPE_LIB_AUTHN_RESPONSE_ENVELOPE (lasso_lib_authn_response_envelope_get_type())
#define LASSO_LIB_AUTHN_RESPONSE_ENVELOPE(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_LIB_AUTHN_RESPONSE_ENVELOPE, LassoLibAuthnResponseEnvelope))
/*#define LASSO_LIB_AUTHN_RESPONSE_ENVELOPE_CLASS(klass)
 * (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_LIB_AUTHN_RESPONSE_ENVELOPE,
 * LassoLibAuthnResponseEnvelopeClass))*/
#define LASSO_IS_LIB_AUTHN_RESPONSE_ENVELOPE(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_LIB_AUTHN_RESPONSE_ENVELOPE))
#define LASSO_IS_LIB_AUTHN_RESPONSE_ENVELOPE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_LIB_AUTHN_RESPONSE_ENVELOPE))
/*#define LASSO_LIB_AUTHN_RESPONSE_ENVELOPE_GET_CLASS(o)
 * (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_LIB_AUTHN_RESPONSE_ENVELOPE,
 * LassoLibAuthnResponseEnvelopeClass)) */

/*typedef struct _LassoLibAuthnResponseEnvelopeClass
 * LassoLibAuthnResponseEnvelopeClass;*/

typedef struct _LassoLibAuthnResponseEnvelope {
  LassoNode parent;
  /*< private >*/
} LassoLibAuthnResponseEnvelope;

/*struct _LassoLibAuthnResponseEnvelopeClass {
  LassoNodeClass parent;
};*/

GType      lasso_lib_authn_response_envelope_get_type                        (void);

LassoNode* lasso_lib_authn_response_envelope_new                             (void);

void       lasso_lib_authn_response_envelope_set_extension                   (LassoLibAuthnResponseEnvelope *node,
											   LassoNode *extension);

void       lasso_lib_authn_response_envelope_set_authnResponse               (LassoLibAuthnResponseEnvelope *node,
											   LassoLibAuthnResponse *authnResponse);

void       lasso_lib_authn_response_envelope_set_assertionConsumerServiceURL (LassoLibAuthnResponseEnvelope *node,
											   const xmlChar *url);


/*
 */

#define LASSO_TYPE_LIB_FEDERATION_TERMINATION_NOTIFICATION (lasso_lib_federation_termination_notification_get_type())
#define LASSO_LIB_FEDERATION_TERMINATION_NOTIFICATION(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_LIB_FEDERATION_TERMINATION_NOTIFICATION, LassoLibFederationTerminationNotification))
/*#define LASSO_LIB_FEDERATION_TERMINATION_NOTIFICATION_CLASS(klass)
 * (G_TYPE_CHECK_CLASS_CAST((klass),
 * LASSO_TYPE_LIB_FEDERATION_TERMINATION_NOTIFICATION,
 * LassoLibFederationTerminationNotificationClass))*/
#define LASSO_IS_LIB_FEDERATION_TERMINATION_NOTIFICATION(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_LIB_FEDERATION_TERMINATION_NOTIFICATION))
#define LASSO_IS_LIB_FEDERATION_TERMINATION_NOTIFICATION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_LIB_FEDERATION_TERMINATION_NOTIFICATION))
/*#define LASSO_LIB_FEDERATION_TERMINATION_NOTIFICATION_GET_CLASS(o)
 * (G_TYPE_INSTANCE_GET_CLASS ((o),
 * LASSO_TYPE_LIB_FEDERATION_TERMINATION_NOTIFICATION,
 * LassoLibFederationTerminationNotificationClass)) */

/*typedef struct _LassoLibFederationTerminationNotificationClass
 * LassoLibFederationTerminationNotificationClass;*/

typedef struct _LassoLibFederationTerminationNotification {
  LassoSamlpRequestAbstract parent;
  /*< private >*/
} LassoLibFederationTerminationNotification;

/*struct _LassoLibFederationTerminationNotificationClass {
  LassoSamlpRequestAbstractClass parent;
};*/

GType lasso_lib_federation_termination_notification_get_type(void);
LassoNode* lasso_lib_federation_termination_notification_new(void);

void lasso_lib_federation_termination_notification_set_consent        (LassoLibFederationTerminationNotification *,
										    const xmlChar *);

void lasso_lib_federation_termination_notification_set_providerID     (LassoLibFederationTerminationNotification *,
										    const xmlChar *);

void lasso_lib_federation_termination_notification_set_nameIdentifier (LassoLibFederationTerminationNotification *,
										    LassoSamlNameIdentifier *);

/*
 */

#define LASSO_TYPE_LIB_IDP_ENTRIES (lasso_lib_idp_entries_get_type())
#define LASSO_LIB_IDP_ENTRIES(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_LIB_IDP_ENTRIES, LassoLibIDPEntries))
/*#define LASSO_LIB_IDP_ENTRIES_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass),
 * LASSO_TYPE_LIB_IDP_ENTRIES, LassoLibIDPEntriesClass))*/
#define LASSO_IS_LIB_IDP_ENTRIES(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_LIB_IDP_ENTRIES))
#define LASSO_IS_LIB_IDP_ENTRIES_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_LIB_IDP_ENTRIES))
/*#define LASSO_LIB_IDP_ENTRIES_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o),
 * LASSO_TYPE_LIB_IDP_ENTRIES, LassoLibIDPEntriesClass)) */

/*typedef struct _LassoLibIDPEntriesClass LassoLibIDPEntriesClass;*/

typedef struct _LassoLibIDPEntries{
  LassoNode parent;
  /*< private >*/
} LassoLibIDPEntries;

/*struct _LassoLibIDPEntriesClass {
  LassoNodeClass parent;
};*/

GType lasso_lib_idp_entries_get_type(void);
LassoNode* lasso_lib_idp_entries_new(void);

void lasso_lib_idp_entries_add_idpEntry (LassoLibIDPEntries *node,
						      LassoLibIDPEntry *idpEntry);
/*
 */
#define LASSO_TYPE_LIB_IDP_ENTRY (lasso_lib_idp_entry_get_type())
#define LASSO_LIB_IDP_ENTRY(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_LIB_IDP_ENTRY, LassoLibIDPEntry))
/*#define LASSO_LIB_IDP_ENTRY_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass),
 * LASSO_TYPE_LIB_IDP_ENTRY, LassoLibIDPEntryClass))*/
#define LASSO_IS_LIB_IDP_ENTRY(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_LIB_IDP_ENTRY))
#define LASSO_IS_LIB_IDP_ENTRY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_LIB_IDP_ENTRY))
/*#define LASSO_LIB_IDP_ENTRY_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o),
 * LASSO_TYPE_LIB_IDP_ENTRY, LassoLibIDPEntryClass)) */

/*typedef struct _LassoLibIDPEntryClass LassoLibIDPEntryClass;*/

typedef struct _LassoLibIDPEntry{
  LassoNode parent;
  /*< private >*/
} LassoLibIDPEntry;

/*struct _LassoLibIDPEntryClass {
  LassoNodeClass parent;
};*/

GType lasso_lib_idp_entry_get_type(void);
LassoNode* lasso_lib_idp_entry_new(void);

void lasso_lib_idp_entry_set_providerID   (LassoLibIDPEntry *node,
							const xmlChar *providerID);

void lasso_lib_idp_entry_set_providerName (LassoLibIDPEntry *node,
							const xmlChar *providerName);

void lasso_lib_idp_entry_set_loc          (LassoLibIDPEntry *node,
							const xmlChar *loc);

/*
 */

#define LASSO_TYPE_LIB_IDP_LIST (lasso_lib_idp_list_get_type())
#define LASSO_LIB_IDP_LIST(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_LIB_IDP_LIST, LassoLibIDPList))
/*#define LASSO_LIB_IDP_LIST_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass),
 * LASSO_TYPE_LIB_IDP_LIST, LassoLibIDPListClass))*/
#define LASSO_IS_LIB_IDP_LIST(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_LIB_IDP_LIST))
#define LASSO_IS_LIB_IDP_LIST_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_LIB_IDP_LIST))
#define LASSO_LIB_IDP_LIST_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_LIB_IDP_LIST, LassoLibIDPListClass)) 

/*typedef struct _LassoLibIDPListClass LassoLibIDPListClass;*/

typedef struct _LassoLibIDPList {
  LassoNode parent;
  /*< private >*/
} LassoLibIDPList;

/*struct _LassoLibIDPListClass {
  LassoNodeClass parent;
};*/

GType lasso_lib_idp_list_get_type(void);
LassoNode* lasso_lib_idp_list_new(void);

void lasso_lib_idp_list_set_getComplete (LassoLibIDPList *node,
						      const xmlChar *getComplete);

void lasso_lib_idp_list_set_idpEntries  (LassoLibIDPList *node,
						      LassoLibIDPEntries *idpEntries);

/*
 */
#define LASSO_TYPE_LIB_IDP_PROVIDED_NAME_IDENTIFIER (lasso_lib_idp_provided_name_identifier_get_type())
#define LASSO_LIB_IDP_PROVIDED_NAME_IDENTIFIER(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_LIB_IDP_PROVIDED_NAME_IDENTIFIER, LassoLibIDPProvidedNameIdentifier))
/*#define LASSO_LIB_IDP_PROVIDED_NAME_IDENTIFIER_CLASS(klass)
 * (G_TYPE_CHECK_CLASS_CAST((klass),
 * LASSO_TYPE_LIB_IDP_PROVIDED_NAME_IDENTIFIER,
 * LassoLibIDPProvidedNameIdentifierClass))*/
#define LASSO_IS_LIB_IDP_PROVIDED_NAME_IDENTIFIER(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_LIB_IDP_PROVIDED_NAME_IDENTIFIER))
#define LASSO_IS_LIB_IDP_PROVIDED_NAME_IDENTIFIER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_LIB_IDP_PROVIDED_NAME_IDENTIFIER))
/*#define LASSO_LIB_IDP_PROVIDED_NAME_IDENTIFIER_GET_CLASS(o)
 * (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_LIB_IDP_PROVIDED_NAME_IDENTIFIER,
 * LassoLibIDPProvidedNameIdentifierClass))*/

/*typedef struct _LassoLibIDPProvidedNameIdentifierClass
 * LassoLibIDPProvidedNameIdentifierClass;*/

typedef struct _LassoLibIDPProvidedNameIdentifier {
  LassoSamlNameIdentifier parent;
  /*< private >*/
} LassoLibIDPProvidedNameIdentifier;

/*struct _LassoLibIDPProvidedNameIdentifierClass {
  LassoSamlNameIdentifierClass parent;
};*/

GType lasso_lib_idp_provided_name_identifier_get_type(void);
LassoNode* lasso_lib_idp_provided_name_identifier_new(const xmlChar *content);

/*
 */

#define LASSO_TYPE_LIB_LOGOUT_REQUEST (lasso_lib_logout_request_get_type())
#define LASSO_LIB_LOGOUT_REQUEST(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_LIB_LOGOUT_REQUEST, LassoLibLogoutRequest))
/*#define LASSO_LIB_LOGOUT_REQUEST_CLASS(klass)
 * (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_LIB_LOGOUT_REQUEST,
 * LassoLibLogoutRequestClass))*/
#define LASSO_IS_LIB_LOGOUT_REQUEST(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_LIB_LOGOUT_REQUEST))
#define LASSO_IS_LIB_LOGOUT_REQUEST_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_LIB_LOGOUT_REQUEST))
/*#define LASSO_LIB_LOGOUT_REQUEST_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o),
 * LASSO_TYPE_LIB_LOGOUT_REQUEST, LassoLibLogoutRequestClass)) */

/*typedef struct _LassoLibLogoutRequestClass LassoLibLogoutRequestClass;*/

typedef struct _LassoLibLogoutRequest {
  LassoSamlpRequestAbstract parent;
  /*< private >*/
} LassoLibLogoutRequest;

/*struct _LassoLibLogoutRequestClass {
  LassoSamlpRequestAbstractClass parent;
};*/

GType lasso_lib_logout_request_get_type(void);
LassoNode* lasso_lib_logout_request_new(void);

void lasso_lib_logout_request_set_consent        (LassoLibLogoutRequest *,
							       const xmlChar *);

void lasso_lib_logout_request_set_nameIdentifier (LassoLibLogoutRequest *,
							       LassoSamlNameIdentifier *);

void lasso_lib_logout_request_set_providerID     (LassoLibLogoutRequest *,
							       const xmlChar *);

void lasso_lib_logout_request_set_relayState     (LassoLibLogoutRequest *,
							       const xmlChar *);

void lasso_lib_logout_request_set_sessionIndex   (LassoLibLogoutRequest *,
							       const xmlChar *);

/*
 */

#define LASSO_TYPE_LIB_LOGOUT_RESPONSE (lasso_lib_logout_response_get_type())
#define LASSO_LIB_LOGOUT_RESPONSE(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_LIB_LOGOUT_RESPONSE, LassoLibLogoutResponse))
/*#define LASSO_LIB_LOGOUT_RESPONSE_CLASS(klass)
 * (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_LIB_LOGOUT_RESPONSE,
 * LassoLibLogoutResponseClass))*/
#define LASSO_IS_LIB_LOGOUT_RESPONSE(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_LIB_LOGOUT_RESPONSE))
#define LASSO_IS_LIB_LOGOUT_RESPONSE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_LIB_LOGOUT_RESPONSE))
/*#define LASSO_LIB_LOGOUT_RESPONSE_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS
 * ((o), LASSO_TYPE_LIB_LOGOUT_RESPONSE, LassoLibLogoutResponseClass)) */

/*typedef struct _LassoLibLogoutResponseClass LassoLibLogoutResponseClass;*/

typedef struct _LassoLibLogoutResponse {
  LassoLibStatusResponse parent;
  /*< private >*/
} LassoLibLogoutResponse;

/*struct _LassoLibLogoutResponseClass {
  LassoLibStatusResponseClass parent;
};*/

GType lasso_lib_logout_response_get_type(void);
LassoNode* lasso_lib_logout_response_new(void);

/*
 */

#define LASSO_TYPE_LIB_NAME_IDENTIFIER_MAPPING_REQUEST (lasso_lib_name_identifier_mapping_request_get_type())
#define LASSO_LIB_NAME_IDENTIFIER_MAPPING_REQUEST(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_LIB_NAME_IDENTIFIER_MAPPING_REQUEST, LassoLibNameIdentifierMappingRequest))
/*#define LASSO_LIB_NAME_IDENTIFIER_MAPPING_REQUEST_CLASS(klass)
 * (G_TYPE_CHECK_CLASS_CAST((klass),
 * LASSO_TYPE_LIB_NAME_IDENTIFIER_MAPPING_REQUEST,
 * LassoLibNameIdentifierMappingRequestClass))*/
#define LASSO_IS_LIB_NAME_IDENTIFIER_MAPPING_REQUEST(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_LIB_NAME_IDENTIFIER_MAPPING_REQUEST))
#define LASSO_IS_LIB_NAME_IDENTIFIER_MAPPING_REQUEST_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_LIB_NAME_IDENTIFIER_MAPPING_REQUEST))
/*#define LASSO_LIB_NAME_IDENTIFIER_MAPPING_REQUEST_GET_CLASS(o)
 * (G_TYPE_INSTANCE_GET_CLASS ((o),
 * LASSO_TYPE_LIB_NAME_IDENTIFIER_MAPPING_REQUEST,
 * LassoLibNameIdentifierMappingRequestClass)) */

/*typedef struct _LassoLibNameIdentifierMappingRequestClass
 * LassoLibNameIdentifierMappingRequestClass;*/

typedef struct _LassoLibNameIdentifierMappingRequest {
  LassoSamlpRequestAbstract parent;
  /*< private >*/
} LassoLibNameIdentifierMappingRequest;

/*struct _LassoLibNameIdentifierMappingRequestClass {
  LassoSamlpRequestAbstractClass parent;
};*/

GType lasso_lib_name_identifier_mapping_request_get_type(void);
LassoNode* lasso_lib_name_identifier_mapping_request_new(void);

void lasso_lib_name_identifier_mapping_request_set_consent        (LassoLibNameIdentifierMappingRequest *,
										const xmlChar *);

void lasso_lib_name_identifier_mapping_request_set_providerID     (LassoLibNameIdentifierMappingRequest *,
										const xmlChar *);

void lasso_lib_name_identifier_mapping_request_set_nameIdentifier (LassoLibNameIdentifierMappingRequest *,
										LassoSamlNameIdentifier *);

/*
 */
#define LASSO_TYPE_LIB_NAME_IDENTIFIER_MAPPING_RESPONSE (lasso_lib_name_identifier_mapping_response_get_type())
#define LASSO_LIB_NAME_IDENTIFIER_MAPPING_RESPONSE(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_LIB_NAME_IDENTIFIER_MAPPING_RESPONSE, LassoLibNameIdentifierMappingResponse))
/*#define LASSO_LIB_NAME_IDENTIFIER_MAPPING_RESPONSE_CLASS(klass)
 * (G_TYPE_CHECK_CLASS_CAST((klass),
 * LASSO_TYPE_LIB_NAME_IDENTIFIER_MAPPING_RESPONSE,
 * LassoLibNameIdentifierMappingResponseClass))*/
#define LASSO_IS_LIB_NAME_IDENTIFIER_MAPPING_RESPONSE(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_LIB_NAME_IDENTIFIER_MAPPING_RESPONSE))
#define LASSO_IS_LIB_NAME_IDENTIFIER_MAPPING_RESPONSE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_LIB_NAME_IDENTIFIER_MAPPING_RESPONSE))
/*#define LASSO_LIB_NAME_IDENTIFIER_MAPPING_RESPONSE_GET_CLASS(o)
 * (G_TYPE_INSTANCE_GET_CLASS ((o),
 * LASSO_TYPE_LIB_NAME_IDENTIFIER_MAPPING_RESPONSE,
 * LassoLibNameIdentifierMappingResponseClass)) */

/*typedef struct _LassoLibNameIdentifierMappingResponseClass
 * LassoLibNameIdentifierMappingResponseClass;*/

typedef struct _LassoLibNameIdentifierMappingResponse {
  LassoSamlpResponseAbstract parent;
  /*< private >*/
} LassoLibNameIdentifierMappingResponse;

/*struct _LassoLibNameIdentifierMappingResponseClass {
  LassoSamlpResponseAbstractClass parent;
};*/

GType lasso_lib_name_identifier_mapping_response_get_type(void);
LassoNode* lasso_lib_name_identifier_mapping_response_new(void);

void lasso_lib_name_identifier_mapping_response_set_nameIdentifier (LassoLibNameIdentifierMappingResponse *node,
										 LassoSamlNameIdentifier *nameIdentifier);

void lasso_lib_name_identifier_mapping_response_set_providerID     (LassoLibNameIdentifierMappingResponse *node,
										 const xmlChar *providerID);

void lasso_lib_name_identifier_mapping_response_set_status         (LassoLibNameIdentifierMappingResponse *node,
										 LassoSamlpStatus *status);
/*
 */
#define LASSO_TYPE_LIB_OLD_PROVIDED_NAME_IDENTIFIER (lasso_lib_old_provided_name_identifier_get_type())
#define LASSO_LIB_OLD_PROVIDED_NAME_IDENTIFIER(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_LIB_OLD_PROVIDED_NAME_IDENTIFIER, LassoLibOLDProvidedNameIdentifier))
/*#define LASSO_LIB_OLD_PROVIDED_NAME_IDENTIFIER_CLASS(klass)
 * (G_TYPE_CHECK_CLASS_CAST((klass),
 * LASSO_TYPE_LIB_OLD_PROVIDED_NAME_IDENTIFIER,
 * LassoLibOLDProvidedNameIdentifierClass))*/
#define LASSO_IS_LIB_OLD_PROVIDED_NAME_IDENTIFIER(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_LIB_OLD_PROVIDED_NAME_IDENTIFIER))
#define LASSO_IS_LIB_OLD_PROVIDED_NAME_IDENTIFIER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_LIB_OLD_PROVIDED_NAME_IDENTIFIER))
/*#define LASSO_LIB_OLD_PROVIDED_NAME_IDENTIFIER_GET_CLASS(o)
 * (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_LIB_OLD_PROVIDED_NAME_IDENTIFIER,
 * LassoLibOLDProvidedNameIdentifierClass))*/

/*typedef struct _LassoLibOLDProvidedNameIdentifierClass
 * LassoLibOLDProvidedNameIdentifierClass;*/

typedef struct _LassoLibOLDProvidedNameIdentifier {
  LassoSamlNameIdentifier parent;
  /*< private >*/
} LassoLibOLDProvidedNameIdentifier;

/*struct _LassoLibOLDProvidedNameIdentifierClass {
  LassoSamlNameIdentifierClass parent;
};*/

GType lasso_lib_old_provided_name_identifier_get_type(void);
LassoNode* lasso_lib_old_provided_name_identifier_new(const xmlChar *content);

/*
 */
#define LASSO_TYPE_LIB_REGISTER_NAME_IDENTIFIER_REQUEST (lasso_lib_register_name_identifier_request_get_type())
#define LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_LIB_REGISTER_NAME_IDENTIFIER_REQUEST, LassoLibRegisterNameIdentifierRequest))
/*#define LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST_CLASS(klass)
 * (G_TYPE_CHECK_CLASS_CAST((klass),
 * LASSO_TYPE_LIB_REGISTER_NAME_IDENTIFIER_REQUEST,
 * LassoLibRegisterNameIdentifierRequestClass))*/
#define LASSO_IS_LIB_REGISTER_NAME_IDENTIFIER_REQUEST(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_LIB_REGISTER_NAME_IDENTIFIER_REQUEST))
#define LASSO_IS_LIB_REGISTER_NAME_IDENTIFIER_REQUEST_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_LIB_REGISTER_NAME_IDENTIFIER_REQUEST))
/*#define LASSO_LIB_REGISTER_NAME_IDENTIFIER_REQUEST_GET_CLASS(o)
 * (G_TYPE_INSTANCE_GET_CLASS ((o),
 * LASSO_TYPE_LIB_REGISTER_NAME_IDENTIFIER_REQUEST,
 * LassoLibRegisterNameIdentifierRequestClass)) */

/*typedef struct _LassoLibRegisterNameIdentifierRequestClass
 * LassoLibRegisterNameIdentifierRequestClass;*/

typedef struct _LassoLibRegisterNameIdentifierRequest {
  LassoSamlpRequestAbstract parent;
  /*< private >*/
} LassoLibRegisterNameIdentifierRequest;

/*struct _LassoLibRegisterNameIdentifierRequestClass {
  LassoSamlpRequestAbstractClass parent;
};*/

GType lasso_lib_register_name_identifier_request_get_type(void);
LassoNode* lasso_lib_register_name_identifier_request_new(void);

void lasso_lib_register_name_identifier_request_set_relayState                (LassoLibRegisterNameIdentifierRequest *,
											    const xmlChar *);

void lasso_lib_register_name_identifier_request_set_providerID                (LassoLibRegisterNameIdentifierRequest *,
											    const xmlChar *);

void lasso_lib_register_name_identifier_request_set_idpProvidedNameIdentifier (LassoLibRegisterNameIdentifierRequest *,
											    LassoLibIDPProvidedNameIdentifier *);

void lasso_lib_register_name_identifier_request_set_oldProvidedNameIdentifier (LassoLibRegisterNameIdentifierRequest *,
											    LassoLibOLDProvidedNameIdentifier *);

void lasso_lib_register_name_identifier_request_set_spProvidedNameIdentifier  (LassoLibRegisterNameIdentifierRequest *,
											    LassoLibSPProvidedNameIdentifier *);

/*
 */
#define LASSO_TYPE_LIB_REGISTER_NAME_IDENTIFIER_RESPONSE (lasso_lib_register_name_identifier_response_get_type())
#define LASSO_LIB_REGISTER_NAME_IDENTIFIER_RESPONSE(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_LIB_REGISTER_NAME_IDENTIFIER_RESPONSE, LassoLibRegisterNameIdentifierResponse))
/*#define LASSO_LIB_REGISTER_NAME_IDENTIFIER_RESPONSE_CLASS(klass)
 * (G_TYPE_CHECK_CLASS_CAST((klass),
 * LASSO_TYPE_LIB_REGISTER_NAME_IDENTIFIER_RESPONSE,
 * LassoLibRegisterNameIdentifierResponseClass))*/
#define LASSO_IS_LIB_REGISTER_NAME_IDENTIFIER_RESPONSE(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_LIB_REGISTER_NAME_IDENTIFIER_RESPONSE))
#define LASSO_IS_LIB_REGISTER_NAME_IDENTIFIER_RESPONSE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_LIB_REGISTER_NAME_IDENTIFIER_RESPONSE))
/*#define LASSO_LIB_REGISTER_NAME_IDENTIFIER_RESPONSE_GET_CLASS(o)
 * (G_TYPE_INSTANCE_GET_CLASS ((o),
 * LASSO_TYPE_LIB_REGISTER_NAME_IDENTIFIER_RESPONSE,
 * LassoLibRegisterNameIdentifierResponseClass)) */

/*typedef struct _LassoLibRegisterNameIdentifierResponseClass
 * LassoLibRegisterNameIdentifierResponseClass;*/

typedef struct _LassoLibRegisterNameIdentifierResponse {
  LassoLibStatusResponse parent;
  /*< private >*/
} LassoLibRegisterNameIdentifierResponse;

/*struct _LassoLibRegisterNameIdentifierResponseClass {
  LassoLibStatusResponseClass parent;
};*/

GType lasso_lib_register_name_identifier_response_get_type(void);
LassoNode* lasso_lib_register_name_identifier_response_new(void);

/*
 */

#define LASSO_TYPE_LIB_REQUEST_AUTHN_CONTEXT (lasso_lib_request_authn_context_get_type())
#define LASSO_LIB_REQUEST_AUTHN_CONTEXT(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_LIB_REQUEST_AUTHN_CONTEXT, LassoLibRequestAuthnContext))
/*#define LASSO_LIB_REQUEST_AUTHN_CONTEXT_CLASS(klass)
 * (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_LIB_REQUEST_AUTHN_CONTEXT,
 * LassoLibRequestAuthnContextClass))*/
#define LASSO_IS_LIB_REQUEST_AUTHN_CONTEXT(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_LIB_REQUEST_AUTHN_CONTEXT))
#define LASSO_IS_LIB_REQUEST_AUTHN_CONTEXT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_LIB_REQUEST_AUTHN_CONTEXT))
/*#define LASSO_LIB_REQUEST_AUTHN_CONTEXT_GET_CLASS(o)
 * (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_LIB_REQUEST_AUTHN_CONTEXT,
 * LassoLibRequestAuthnContextClass)) */

/*typedef struct _LassoLibRequestAuthnContextClass
 * LassoLibRequestAuthnContextClass;*/

typedef struct _LassoLibRequestAuthnContext {
  LassoNode parent;
  /*< private >*/
} LassoLibRequestAuthnContext;

/*struct _LassoLibRequestAuthnContextClass {
  LassoNodeClass parent;
};*/

GType lasso_lib_request_authn_context_get_type(void);
LassoNode* lasso_lib_request_authn_context_new(void);

/*void lasso_lib_request_authn_context_add_authnContextClassRef     (LassoLibRequestAuthnContext *node,
										const
                                                                                xmlChar
                                                                                *authnContextClassRef);*/

void lasso_lib_request_authn_context_add_authnContextStatementRef (LassoLibRequestAuthnContext *node,
										const xmlChar *authnContextStatementRef);

void lasso_lib_request_authn_context_set_authnContextComparison   (LassoLibRequestAuthnContext *node,
										const xmlChar *authnContextComparison);

/*
 */

#define LASSO_TYPE_LIB_SCOPING (lasso_lib_scoping_get_type())
#define LASSO_LIB_SCOPING(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_LIB_SCOPING, LassoLibScoping))
/*#define LASSO_LIB_SCOPING_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass),
 * LASSO_TYPE_LIB_SCOPING, LassoLibScopingClass))*/
#define LASSO_IS_LIB_SCOPING(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_LIB_SCOPING))
#define LASSO_IS_LIB_SCOPING_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_LIB_SCOPING))
/*#define LASSO_LIB_SCOPING_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o),
 * LASSO_TYPE_LIB_SCOPING, LassoLibScopingClass)) */

/*typedef struct _LassoLibScopingClass LassoLibScopingClass;*/

typedef struct _LassoLibScoping {
  LassoNode parent;
  /*< private >*/
} LassoLibScoping;

/*struct _LassoLibScopingClass {
  LassoNodeClass parent;
};*/

GType lasso_lib_scoping_get_type(void);
LassoNode* lasso_lib_scoping_new(void);

void lasso_lib_scoping_set_proxyCount (LassoLibScoping *node,
						    gint             proxyCount);

void lasso_lib_scoping_set_idpList    (LassoLibScoping *node,
						    LassoLibIDPList *idpList);

/*
 */

#define LASSO_TYPE_LIB_SP_PROVIDED_NAME_IDENTIFIER (lasso_lib_sp_provided_name_identifier_get_type())
#define LASSO_LIB_SP_PROVIDED_NAME_IDENTIFIER(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_LIB_SP_PROVIDED_NAME_IDENTIFIER, LassoLibSPProvidedNameIdentifier))
/*#define LASSO_LIB_SP_PROVIDED_NAME_IDENTIFIER_CLASS(klass)
 * (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_LIB_SP_PROVIDED_NAME_IDENTIFIER,
 * LassoLibSPProvidedNameIdentifierClass))*/
#define LASSO_IS_LIB_SP_PROVIDED_NAME_IDENTIFIER(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_LIB_SP_PROVIDED_NAME_IDENTIFIER))
#define LASSO_IS_LIB_SP_PROVIDED_NAME_IDENTIFIER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_LIB_SP_PROVIDED_NAME_IDENTIFIER))
/*#define LASSO_LIB_SP_PROVIDED_NAME_IDENTIFIER_GET_CLASS(o)
 * (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_LIB_SP_PROVIDED_NAME_IDENTIFIER,
 * LassoLibSPProvidedNameIdentifierClass))*/

/*typedef struct _LassoLibSPProvidedNameIdentifierClass
 * LassoLibSPProvidedNameIdentifierClass;*/

typedef struct _LassoLibSPProvidedNameIdentifier {
  LassoSamlNameIdentifier parent;
  /*< private >*/
} LassoLibSPProvidedNameIdentifier;

/*struct _LassoLibSPProvidedNameIdentifierClass {
  LassoSamlNameIdentifierClass parent;
};*/

GType lasso_lib_sp_provided_name_identifier_get_type(void);
LassoNode* lasso_lib_sp_provided_name_identifier_new(const xmlChar *content);

/*
 */
#define LASSO_TYPE_LIB_STATUS_RESPONSE (lasso_lib_status_response_get_type())
#define LASSO_LIB_STATUS_RESPONSE(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_LIB_STATUS_RESPONSE, LassoLibStatusResponse))
/*#define LASSO_LIB_STATUS_RESPONSE_CLASS(klass)
 * (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_LIB_STATUS_RESPONSE,
 * LassoLibStatusResponseClass))*/
#define LASSO_IS_LIB_STATUS_RESPONSE(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_LIB_STATUS_RESPONSE))
#define LASSO_IS_LIB_STATUS_RESPONSE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_LIB_STATUS_RESPONSE))
/*#define LASSO_LIB_STATUS_RESPONSE_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS
 * ((o), LASSO_TYPE_LIB_STATUS_RESPONSE, LassoLibStatusResponseClass)) */

/*typedef struct _LassoLibStatusResponseClass LassoLibStatusResponseClass;*/

typedef struct _LassoLibStatusResponse {
  LassoSamlpResponseAbstract parent;
  /*< private >*/
} LassoLibStatusResponse;

/*struct _LassoLibStatusResponseClass {
  LassoSamlpResponseAbstractClass parent;
};*/

GType lasso_lib_status_response_get_type(void);
LassoNode* lasso_lib_status_response_new(void);

void lasso_lib_status_response_set_providerID (LassoLibStatusResponse *node,
							    const xmlChar *providerID);

void lasso_lib_status_response_set_relayState (LassoLibStatusResponse *node,
							    const xmlChar *relayState);

void lasso_lib_status_response_set_status     (LassoLibStatusResponse *node,
							    LassoSamlpStatus *status);

/*
 */

#define LASSO_TYPE_LIB_SUBJECT (lasso_lib_subject_get_type())
#define LASSO_LIB_SUBJECT(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_LIB_SUBJECT, LassoLibSubject))
/*#define LASSO_LIB_SUBJECT_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass),
 * LASSO_TYPE_LIB_SUBJECT, LassoLibSubjectClass))*/
#define LASSO_IS_LIB_SUBJECT(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_LIB_SUBJECT))
#define LASSO_IS_LIB_SUBJECT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_LIB_SUBJECT))
/*#define LASSO_LIB_SUBJECT_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o),
 * LASSO_TYPE_LIB_SUBJECT, LassoLibSubjectClass)) */

/*typedef struct _LassoLibSubjectClass LassoLibSubjectClass;*/

typedef struct _LassoLibSubject {
  LassoSamlSubject parent;
  /*< private >*/
} LassoLibSubject;

/*struct _LassoLibSubjectClass {
  LassoSamlSubjectClass parent;
};*/

GType lasso_lib_subject_get_type(void);
LassoNode* lasso_lib_subject_new(void);

void lasso_lib_subject_set_idpProvidedNameIdentifier(LassoLibSubject *node,
								  LassoLibIDPProvidedNameIdentifier *idpProvidedNameIdentifier);


/*
 */

#define LASSO_TYPE_SAMLP_REQUEST_ABSTRACT (lasso_samlp_request_abstract_get_type())
#define LASSO_SAMLP_REQUEST_ABSTRACT(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SAMLP_REQUEST_ABSTRACT, LassoSamlpRequestAbstract))
/*#define LASSO_SAMLP_REQUEST_ABSTRACT_CLASS(klass)
 * (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_SAMLP_REQUEST_ABSTRACT,
 * LassoSamlpRequestAbstractClass))*/
#define LASSO_IS_SAMLP_REQUEST_ABSTRACT(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SAMLP_REQUEST_ABSTRACT))
#define LASSO_IS_SAMLP_REQUEST_ABSTRACT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SAMLP_REQUEST_ABSTRACT))
/*#define LASSO_SAMLP_REQUEST_ABSTRACT_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS
 * ((o), LASSO_TYPE_SAMLP_REQUEST_ABSTRACT, LassoSamlpRequestAbstractClass)) */

/*typedef struct _LassoSamlpRequestAbstractClass
 * LassoSamlpRequestAbstractClass;*/

typedef struct _LassoSamlpRequestAbstract {
  LassoNode parent;
  /*< private >*/
} LassoSamlpRequestAbstract;

/*struct _LassoSamlpRequestAbstractClass {
  LassoNodeClass parent;
};*/

GType lasso_samlp_request_abstract_get_type        (void);
LassoNode* lasso_samlp_request_abstract_new        (void);

void lasso_samlp_request_abstract_add_respondWith  (LassoSamlpRequestAbstract *node,
								 const xmlChar *respondWith);

void lasso_samlp_request_abstract_set_issueInstant (LassoSamlpRequestAbstract *node,
								 const xmlChar *issueInstant);

void lasso_samlp_request_abstract_set_majorVersion (LassoSamlpRequestAbstract *node,
								 const xmlChar *majorVersion);

void lasso_samlp_request_abstract_set_minorVersion (LassoSamlpRequestAbstract *node,
								 const xmlChar *minorVersion);

void lasso_samlp_request_abstract_set_requestID    (LassoSamlpRequestAbstract *node,
								 const xmlChar *requestID);

/*
 */

#define LASSO_TYPE_SAMLP_RESPONSE_ABSTRACT (lasso_samlp_response_abstract_get_type())
#define LASSO_SAMLP_RESPONSE_ABSTRACT(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SAMLP_RESPONSE_ABSTRACT, LassoSamlpResponseAbstract))
/*#define LASSO_SAMLP_RESPONSE_ABSTRACT_CLASS(klass)
 * (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_SAMLP_RESPONSE_ABSTRACT,
 * LassoSamlpResponseAbstractClass))*/
#define LASSO_IS_SAMLP_RESPONSE_ABSTRACT(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SAMLP_RESPONSE_ABSTRACT))
#define LASSO_IS_SAMLP_RESPONSE_ABSTRACT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SAMLP_RESPONSE_ABSTRACT))
/*#define LASSO_SAMLP_RESPONSE_ABSTRACT_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS
 * ((o), LASSO_TYPE_SAMLP_RESPONSE_ABSTRACT, LassoSamlpResponseAbstractClass))
 * */

/*typedef struct _LassoSamlpResponseAbstractClass
 * LassoSamlpResponseAbstractClass;*/

typedef struct _LassoSamlpResponseAbstract {
  LassoNode parent;
  /*< private >*/
} LassoSamlpResponseAbstract;

/*struct _LassoSamlpResponseAbstractClass {
  LassoNodeClass parent;
};*/

GType lasso_samlp_response_abstract_get_type        (void);

LassoNode* lasso_samlp_response_abstract_new        (void);

void lasso_samlp_response_abstract_set_inResponseTo (LassoSamlpResponseAbstract *node,
								  const xmlChar *inResponseTo);

void lasso_samlp_response_abstract_set_issueInstant (LassoSamlpResponseAbstract *node,
								  const xmlChar *issueInstant);

void lasso_samlp_response_abstract_set_majorVersion (LassoSamlpResponseAbstract *node,
								  const xmlChar *majorVersion);

void lasso_samlp_response_abstract_set_minorVersion (LassoSamlpResponseAbstract *node,
								  const xmlChar *minorVersion);

void lasso_samlp_response_abstract_set_recipient    (LassoSamlpResponseAbstract *node,
								  const xmlChar *recipient);

void lasso_samlp_response_abstract_set_responseID   (LassoSamlpResponseAbstract *node,
								  const xmlChar *responseID);

/*
 */
#define LASSO_TYPE_SAMLP_STATUS (lasso_samlp_status_get_type())
#define LASSO_SAMLP_STATUS(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SAMLP_STATUS, LassoSamlpStatus))
/*#define LASSO_SAMLP_STATUS_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass),
 * LASSO_TYPE_SAMLP_STATUS, LassoSamlpStatusClass))*/
#define LASSO_IS_SAMLP_STATUS(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SAMLP_STATUS))
#define LASSO_IS_SAMLP_STATUS_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SAMLP_STATUS))
/*#define LASSO_SAMLP_STATUS_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o),
 * LASSO_TYPE_SAMLP_STATUS, LassoSamlpStatusClass)) */

/*typedef struct _LassoSamlpStatusClass LassoSamlpStatusClass;*/

typedef struct _LassoSamlpStatus {
  LassoNode parent;
  /*< private >*/
} LassoSamlpStatus;

/*struct _LassoSamlpStatusClass {
  LassoNodeClass parent;
};*/

GType lasso_samlp_status_get_type(void);
LassoNode* lasso_samlp_status_new(void);

void lasso_samlp_status_set_statusCode    (LassoSamlpStatus *node,
							LassoSamlpStatusCode *statusCode);

/* TODO
void lasso_samlp_status_set_statusDetail(LassoSamlpStatus *node,
LassoSamlpStatusDetail *statusDetail);
*/

void lasso_samlp_status_set_statusMessage  (LassoSamlpStatus *node,
							 const xmlChar *statusMessage);

/*
 */
#define LASSO_TYPE_SAMLP_STATUS_CODE (lasso_samlp_status_code_get_type())
#define LASSO_SAMLP_STATUS_CODE(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SAMLP_STATUS_CODE, LassoSamlpStatusCode))
/*#define LASSO_SAMLP_STATUS_CODE_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass),
 * LASSO_TYPE_SAMLP_STATUS_CODE, LassoSamlpStatusCodeClass))*/
#define LASSO_IS_SAMLP_STATUS_CODE(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SAMLP_STATUS_CODE))
#define LASSO_IS_SAMLP_STATUS_CODE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SAMLP_STATUS_CODE))
/*#define LASSO_SAMLP_STATUS_CODE_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o),
 * LASSO_TYPE_SAMLP_STATUS_CODE, LassoSamlpStatusCodeClass)) */

/*typedef struct _LassoSamlpStatusCodeClass LassoSamlpStatusCodeClass;*/

typedef struct _LassoSamlpStatusCode {
  LassoNode parent;
  /*< private >*/
} LassoSamlpStatusCode;

/*struct _LassoSamlpStatusCodeClass {
  LassoNodeClass parent;
};*/

GType lasso_samlp_status_code_get_type(void);
LassoNode* lasso_samlp_status_code_new(void);

void lasso_samlp_status_code_set_value (LassoSamlpStatusCode *node,
						     const xmlChar *value);

/*
 */

#define LASSO_TYPE_SAML_ADVICE (lasso_saml_advice_get_type())
#define LASSO_SAML_ADVICE(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SAML_ADVICE, LassoSamlAdvice))
/*#define LASSO_SAML_ADVICE_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass),
 * LASSO_TYPE_SAML_ADVICE, LassoSamlAdviceClass))*/
#define LASSO_IS_SAML_ADVICE(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SAML_ADVICE))
#define LASSO_IS_SAML_ADVICE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SAML_ADVICE))
/*#define LASSO_SAML_ADVICE_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o),
 * LASSO_TYPE_SAML_ADVICE, LassoSamlAdviceClass)) */

/*typedef struct _LassoSamlAdviceClass LassoSamlAdviceClass;*/

typedef struct _LassoSamlAdvice {
  LassoNode parent;
  /*< private >*/
} LassoSamlAdvice;

/*struct _LassoSamlAdviceClass {
  LassoNodeClass parent;
};*/

GType lasso_saml_advice_get_type(void);
LassoNode* lasso_saml_advice_new(void);

void lasso_saml_advice_add_assertionIDReference (LassoSamlAdvice *node,
							      const xmlChar *assertionIDReference);

void lasso_saml_advice_add_assertion            (LassoSamlAdvice *node,
							      gpointer *assertion);

/*
 */

#define LASSO_TYPE_SAML_ASSERTION (lasso_saml_assertion_get_type())
#define LASSO_SAML_ASSERTION(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SAML_ASSERTION, LassoSamlAssertion))
/*#define LASSO_SAML_ASSERTION_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass),
 * LASSO_TYPE_SAML_ASSERTION, LassoSamlAssertionClass))*/
#define LASSO_IS_SAML_ASSERTION(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SAML_ASSERTION))
#define LASSO_IS_SAML_ASSERTION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SAML_ASSERTION))
/*#define LASSO_SAML_ASSERTION_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o),
 * LASSO_TYPE_SAML_ASSERTION, LassoSamlAssertionClass)) */

/*typedef struct _LassoSamlAssertionClass LassoSamlAssertionClass;*/

typedef struct _LassoSamlAssertion {
  LassoNode parent;
  /*< private >*/
} LassoSamlAssertion;

/*struct _LassoSamlAssertionClass {
  LassoNodeClass parent;
};*/

GType lasso_saml_assertion_get_type(void);
LassoNode* lasso_saml_assertion_new(void);

void lasso_saml_assertion_add_authenticationStatement (LassoSamlAssertion *node,
								    LassoSamlAuthenticationStatement *authenticationStatement);

void lasso_saml_assertion_add_statement               (LassoSamlAssertion *node,
								    LassoSamlStatementAbstract *statement);

void lasso_saml_assertion_add_subjectStatement        (LassoSamlAssertion *node,
								    LassoSamlSubjectStatementAbstract *subjectStatement);

void lasso_saml_assertion_set_advice                  (LassoSamlAssertion *node,
								    LassoSamlAdvice *advice);

void lasso_saml_assertion_set_assertionID             (LassoSamlAssertion *node,
								    const xmlChar *assertionID);

void lasso_saml_assertion_set_conditions              (LassoSamlAssertion *node,
								    LassoSamlConditions *conditions);

void lasso_saml_assertion_set_issueInstant            (LassoSamlAssertion *node,
								    const xmlChar *issueInstant);

void lasso_saml_assertion_set_issuer                  (LassoSamlAssertion *node,
								    const xmlChar *issuer);

void lasso_saml_assertion_set_majorVersion            (LassoSamlAssertion *node,
								    const xmlChar *majorVersion);

void lasso_saml_assertion_set_minorVersion            (LassoSamlAssertion *node,
								    const xmlChar *minorVersion);


/*
 */

#define LASSO_TYPE_SAML_AUDIENCE_RESTRICTION_CONDITION (lasso_saml_audience_restriction_condition_get_type())
#define LASSO_SAML_AUDIENCE_RESTRICTION_CONDITION(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SAML_AUDIENCE_RESTRICTION_CONDITION, LassoSamlAudienceRestrictionCondition))
/*#define LASSO_SAML_AUDIENCE_RESTRICTION_CONDITION_CLASS(klass)
 * (G_TYPE_CHECK_CLASS_CAST((klass),
 * LASSO_TYPE_SAML_AUDIENCE_RESTRICTION_CONDITION,
 * LassoSamlAudienceRestrictionConditionClass))*/
#define LASSO_IS_SAML_AUDIENCE_RESTRICTION_CONDITION(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SAML_AUDIENCE_RESTRICTION_CONDITION))
#define LASSO_IS_SAML_AUDIENCE_RESTRICTION_CONDITION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SAML_AUDIENCE_RESTRICTION_CONDITION))
/*#define LASSO_SAML_AUDIENCE_RESTRICTION_CONDITION_GET_CLASS(o)
 * (G_TYPE_INSTANCE_GET_CLASS ((o),
 * LASSO_TYPE_SAML_AUDIENCE_RESTRICTION_CONDITION,
 * LassoSamlAudienceRestrictionConditionClass)) */

/*typedef struct _LassoSamlAudienceRestrictionConditionClass
 * LassoSamlAudienceRestrictionConditionClass;*/

typedef struct _LassoSamlAudienceRestrictionCondition {
  LassoSamlConditionAbstract parent;
  /*< private >*/
} LassoSamlAudienceRestrictionCondition;

/*struct _LassoSamlAudienceRestrictionConditionClass {
  LassoSamlConditionAbstractClass parent;
};*/

GType lasso_saml_audience_restriction_condition_get_type(void);
LassoNode* lasso_saml_audience_restriction_condition_new(void);

void lasso_saml_audience_restriction_condition_add_audience (LassoSamlAudienceRestrictionCondition *node,
									  const xmlChar *audience);

/*
 */
#define LASSO_TYPE_SAML_AUTHENTICATION_STATEMENT (lasso_saml_authentication_statement_get_type())
#define LASSO_SAML_AUTHENTICATION_STATEMENT(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SAML_AUTHENTICATION_STATEMENT, LassoSamlAuthenticationStatement))
/*#define LASSO_SAML_AUTHENTICATION_STATEMENT_CLASS(klass)
 * (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_SAML_AUTHENTICATION_STATEMENT,
 * LassoSamlAuthenticationStatementClass))*/
#define LASSO_IS_SAML_AUTHENTICATION_STATEMENT(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SAML_AUTHENTICATION_STATEMENT))
#define LASSO_IS_SAML_AUTHENTICATION_STATEMENT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SAML_AUTHENTICATION_STATEMENT))
/*#define LASSO_SAML_AUTHENTICATION_STATEMENT_GET_CLASS(o)
 * (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_SAML_AUTHENTICATION_STATEMENT,
 * LassoSamlAuthenticationStatementClass)) */

/*typedef struct _LassoSamlAuthenticationStatementClass
 * LassoSamlAuthenticationStatementClass;*/

typedef struct _LassoSamlAuthenticationStatement {
  LassoSamlSubjectStatementAbstract parent;
  /*< private >*/
} LassoSamlAuthenticationStatement;

/*struct _LassoSamlAuthenticationStatementClass {
  LassoSamlSubjectStatementAbstractClass parent;
};*/

GType lasso_saml_authentication_statement_get_type(void);
LassoNode* lasso_saml_authentication_statement_new(void);

void lasso_saml_authentication_statement_add_authorityBinding      (LassoSamlAuthenticationStatement *node,
										 LassoSamlAuthorityBinding *authorityBinding);

void lasso_saml_authentication_statement_set_authenticationInstant (LassoSamlAuthenticationStatement *node,
										 const xmlChar *authenticationInstant);

void lasso_saml_authentication_statement_set_authenticationMethod  (LassoSamlAuthenticationStatement *node,
										 const xmlChar *authenticationMethod);

void lasso_saml_authentication_statement_set_subjectLocality       (LassoSamlAuthenticationStatement *node,
										 LassoSamlSubjectLocality *subjectLocality);

/*
 */
#define LASSO_TYPE_SAML_AUTHORITY_BINDING (lasso_saml_authority_binding_get_type())
#define LASSO_SAML_AUTHORITY_BINDING(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SAML_AUTHORITY_BINDING, LassoSamlAuthorityBinding))
/*#define LASSO_SAML_AUTHORITY_BINDING_CLASS(klass)
 * (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_SAML_AUTHORITY_BINDING,
 * LassoSamlAuthorityBindingClass))*/
#define LASSO_IS_SAML_AUTHORITY_BINDING(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SAML_AUTHORITY_BINDING))
#define LASSO_IS_SAML_AUTHORITY_BINDING_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SAML_AUTHORITY_BINDING))
/*#define LASSO_SAML_AUTHORITY_BINDING_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS
 * ((o), LASSO_TYPE_SAML_AUTHORITY_BINDING, LassoSamlAuthorityBindingClass)) */

/*typedef struct _LassoSamlAuthorityBindingClass
 * LassoSamlAuthorityBindingClass;*/

typedef struct _LassoSamlAuthorityBinding {
  LassoNode parent;
  /*< private >*/
} LassoSamlAuthorityBinding;

/*struct _LassoSamlAuthorityBindingClass {
  LassoNodeClass parent;
};*/

GType lasso_saml_authority_binding_get_type(void);
LassoNode* lasso_saml_authority_binding_new(void);

void lasso_saml_authority_binding_set_authorityKind (LassoSamlAuthorityBinding *node,
								  const xmlChar *authorityKind);

void lasso_saml_authority_binding_set_binding       (LassoSamlAuthorityBinding *node,
								  const xmlChar *binding);

void lasso_saml_authority_binding_set_location      (LassoSamlAuthorityBinding *node,
								  const xmlChar *location);

/*
 */

#define LASSO_TYPE_SAML_CONDITIONS (lasso_saml_conditions_get_type())
#define LASSO_SAML_CONDITIONS(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SAML_CONDITIONS, LassoSamlConditions))
/*#define LASSO_SAML_CONDITIONS_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass),
 * LASSO_TYPE_SAML_CONDITIONS, LassoSamlConditionsClass))*/
#define LASSO_IS_SAML_CONDITIONS(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SAML_CONDITIONS))
#define LASSO_IS_SAML_CONDITIONS_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SAML_CONDITIONS))
/*#define LASSO_SAML_CONDITIONS_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o),
 * LASSO_TYPE_SAML_CONDITIONS, LassoSamlConditionsClass)) */

/*typedef struct _LassoSamlConditionsClass LassoSamlConditionsClass;*/

typedef struct _LassoSamlConditions {
  LassoNode parent;
  /*< private >*/
} LassoSamlConditions;

/*struct _LassoSamlConditionsClass {
  LassoNodeClass parent;
};*/

GType lasso_saml_conditions_get_type(void);
LassoNode* lasso_saml_conditions_new(void);

void lasso_saml_conditions_add_condition    (LassoSamlConditions *node,
							  LassoSamlConditionAbstract *condition);

void lasso_saml_conditions_add_audienceRestrictionCondition(LassoSamlConditions *node,
									 LassoSamlAudienceRestrictionCondition *audienceRestrictionCondition);

void lasso_saml_conditions_set_notBefore    (LassoSamlConditions *node,
							  const xmlChar *notBefore);

void lasso_saml_conditions_set_notOnOrAfter (LassoSamlConditions *node,
							  const xmlChar *notOnOrAfter);

/*
 */
#define LASSO_TYPE_SAML_CONDITION_ABSTRACT (lasso_saml_condition_abstract_get_type())
#define LASSO_SAML_CONDITION_ABSTRACT(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SAML_CONDITION_ABSTRACT, LassoSamlConditionAbstract))
/*#define LASSO_SAML_CONDITION_ABSTRACT_CLASS(klass)
 * (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_SAML_CONDITION_ABSTRACT,
 * LassoSamlConditionAbstractClass))*/
#define LASSO_IS_SAML_CONDITION_ABSTRACT(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SAML_CONDITION_ABSTRACT))
#define LASSO_IS_SAML_CONDITION_ABSTRACT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SAML_CONDITION_ABSTRACT))
/*#define LASSO_SAML_CONDITION_ABSTRACT_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS
 * ((o), LASSO_TYPE_SAML_CONDITION_ABSTRACT, LassoSamlConditionAbstractClass))
 * */

/*typedef struct _LassoSamlConditionAbstractClass
 * LassoSamlConditionAbstractClass;*/

typedef struct _LassoSamlConditionAbstract {
  LassoNode parent;
  /*< private >*/
} LassoSamlConditionAbstract;

/*struct _LassoSamlConditionAbstractClass {
  LassoNodeClass parent;
};*/

GType lasso_saml_condition_abstract_get_type(void);
LassoNode* lasso_saml_condition_abstract_new(const xmlChar *name);

/*
 */
#define LASSO_TYPE_SAML_NAME_IDENTIFIER (lasso_saml_name_identifier_get_type())
#define LASSO_SAML_NAME_IDENTIFIER(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SAML_NAME_IDENTIFIER, LassoSamlNameIdentifier))
/*#define LASSO_SAML_NAME_IDENTIFIER_CLASS(klass)
 * (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_SAML_NAME_IDENTIFIER,
 * LassoSamlNameIdentifierClass))*/
#define LASSO_IS_SAML_NAME_IDENTIFIER(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SAML_NAME_IDENTIFIER))
#define LASSO_IS_SAML_NAME_IDENTIFIER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SAML_NAME_IDENTIFIER))
/*#define LASSO_SAML_NAME_IDENTIFIER_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS
 * ((o), LASSO_TYPE_SAML_NAME_IDENTIFIER, LassoSamlNameIdentifierClass)) */

/*typedef struct _LassoSamlNameIdentifierClass LassoSamlNameIdentifierClass;*/

typedef struct _LassoSamlNameIdentifier {
  LassoNode parent;
  /*< private >*/
} LassoSamlNameIdentifier;

/*struct _LassoSamlNameIdentifierClass {
  LassoNodeClass parent;
};*/

GType lasso_saml_name_identifier_get_type(void);
LassoNode* lasso_saml_name_identifier_new(const xmlChar *content);

void lasso_saml_name_identifier_set_format        (LassoSamlNameIdentifier *node,
								const xmlChar *format);

void lasso_saml_name_identifier_set_nameQualifier (LassoSamlNameIdentifier *node,
								const xmlChar *nameQualifier);

/*
 */

#define LASSO_TYPE_SAML_STATEMENT_ABSTRACT (lasso_saml_statement_abstract_get_type())
#define LASSO_SAML_STATEMENT_ABSTRACT(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SAML_STATEMENT_ABSTRACT, LassoSamlStatementAbstract))
/*#define LASSO_SAML_STATEMENT_ABSTRACT_CLASS(klass)
 * (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_SAML_STATEMENT_ABSTRACT,
 * LassoSamlStatementAbstractClass))*/
#define LASSO_IS_SAML_STATEMENT_ABSTRACT(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SAML_STATEMENT_ABSTRACT))
#define LASSO_IS_SAML_STATEMENT_ABSTRACT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SAML_STATEMENT_ABSTRACT))
/*#define LASSO_SAML_STATEMENT_ABSTRACT_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS
 * ((o), LASSO_TYPE_SAML_STATEMENT_ABSTRACT, LassoSamlStatementAbstractClass))
 * */

/*typedef struct _LassoSamlStatementAbstractClass
 * LassoSamlStatementAbstractClass;*/

typedef struct _LassoSamlStatementAbstract {
  LassoNode parent;
  /*< private >*/
} LassoSamlStatementAbstract;

/*struct _LassoSamlStatementAbstractClass {
  LassoNodeClass parent;
};*/

GType lasso_saml_statement_abstract_get_type(void);
LassoNode* lasso_saml_statement_abstract_new(const xmlChar *name);

/*
 */

#define LASSO_TYPE_SAML_SUBJECT (lasso_saml_subject_get_type())
#define LASSO_SAML_SUBJECT(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SAML_SUBJECT, LassoSamlSubject))
/*#define LASSO_SAML_SUBJECT_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass),
LASSO_TYPE_SAML_SUBJECT, LassoSamlSubjectClass)*/
#define LASSO_IS_SAML_SUBJECT(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SAML_SUBJECT))
#define LASSO_IS_SAML_SUBJECT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SAML_SUBJECT))
/*#define LASSO_SAML_SUBJECT_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o),
 * LASSO_TYPE_SAML_SUBJECT, LassoSamlSubjectClass)) */

/*typedef struct _LassoSamlSubjectClass LassoSamlSubjectClass;*/

typedef struct _LassoSamlSubject {
  LassoNode parent;
  /*< private >*/
} LassoSamlSubject;

/*struct _LassoSamlSubjectClass {
  LassoNodeClass parent;
};*/

GType lasso_saml_subject_get_type(void);
LassoNode* lasso_saml_subject_new(void);

void lasso_saml_subject_set_nameIdentifier      (LassoSamlSubject *node,
							      LassoSamlNameIdentifier *nameIdentifier);

void lasso_saml_subject_set_subjectConfirmation (LassoSamlSubject *node,
							      LassoSamlSubjectConfirmation *subjectConfirmation);

/*
 */

#define LASSO_TYPE_SAML_SUBJECT_CONFIRMATION (lasso_saml_subject_confirmation_get_type())
#define LASSO_SAML_SUBJECT_CONFIRMATION(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SAML_SUBJECT_CONFIRMATION, LassoSamlSubjectConfirmation))
/*#define LASSO_SAML_SUBJECT_CONFIRMATION_CLASS(klass)
 * (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_SAML_SUBJECT_CONFIRMATION,
 * LassoSamlSubjectConfirmationClass))*/
#define LASSO_IS_SAML_SUBJECT_CONFIRMATION(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SAML_SUBJECT_CONFIRMATION))
#define LASSO_IS_SAML_SUBJECT_CONFIRMATION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SAML_SUBJECT_CONFIRMATION))
/*#define LASSO_SAML_SUBJECT_CONFIRMATION_GET_CLASS(o)
 * (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_SAML_SUBJECT_CONFIRMATION,
 * LassoSamlSubjectConfirmationClass)) */

/*typedef struct _LassoSamlSubjectConfirmationClass
 * LassoSamlSubjectConfirmationClass;*/

typedef struct _LassoSamlSubjectConfirmation {
  LassoNode parent;
  /*< private >*/
} LassoSamlSubjectConfirmation;

/*struct _LassoSamlSubjectConfirmationClass {
  LassoNodeClass parent;
};*/

GType lasso_saml_subject_confirmation_get_type(void);
LassoNode* lasso_saml_subject_confirmation_new(void);

void lasso_saml_subject_confirmation_add_confirmationMethod        (LassoSamlSubjectConfirmation *node,
										 const xmlChar *confirmationMethod);

void lasso_saml_subject_confirmation_set_subjectConfirmationMethod (LassoSamlSubjectConfirmation *node,
										 const xmlChar *subjectConfirmationMethod);

/*
 */
#define LASSO_TYPE_SAML_SUBJECT_LOCALITY (lasso_saml_subject_locality_get_type())
#define LASSO_SAML_SUBJECT_LOCALITY(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SAML_SUBJECT_LOCALITY, LassoSamlSubjectLocality))
/*#define LASSO_SAML_SUBJECT_LOCALITY_CLASS(klass)
 * (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_SAML_SUBJECT_LOCALITY,
 * LassoSamlSubjectLocalityClass))*/
#define LASSO_IS_SAML_SUBJECT_LOCALITY(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SAML_SUBJECT_LOCALITY))
#define LASSO_IS_SAML_SUBJECT_LOCALITY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SAML_SUBJECT_LOCALITY))
/*#define LASSO_SAML_SUBJECT_LOCALITY_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS
 * ((o), LASSO_TYPE_SAML_SUBJECT_LOCALITY, LassoSamlSubjectLocalityClass)) */

/*typedef struct _LassoSamlSubjectLocalityClass LassoSamlSubjectLocalityClass;*/

typedef struct _LassoSamlSubjectLocality {
  LassoNode parent;
  /*< private >*/
} LassoSamlSubjectLocality;

/*struct _LassoSamlSubjectLocalityClass {
  LassoNodeClass parent;
};*/

GType lasso_saml_subject_locality_get_type(void);
LassoNode* lasso_saml_subject_locality_new(void);

void lasso_saml_subject_locality_set_dnsAddress (LassoSamlSubjectLocality *node,
							      const xmlChar *dnsAddress);

void lasso_saml_subject_locality_set_ipAddress  (LassoSamlSubjectLocality *node,
							      const xmlChar *ipAddress);

/*
 */

#define LASSO_TYPE_SAML_SUBJECT_STATEMENT_ABSTRACT (lasso_saml_subject_statement_abstract_get_type())
#define LASSO_SAML_SUBJECT_STATEMENT_ABSTRACT(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SAML_SUBJECT_STATEMENT_ABSTRACT, LassoSamlSubjectStatementAbstract))
/*#define LASSO_SAML_SUBJECT_STATEMENT_ABSTRACT_CLASS(klass)
 * (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_SAML_SUBJECT_STATEMENT_ABSTRACT,
 * LassoSamlSubjectStatementAbstractClass))*/
#define LASSO_IS_SAML_SUBJECT_STATEMENT_ABSTRACT(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SAML_SUBJECT_STATEMENT_ABSTRACT))
#define LASSO_IS_SAML_SUBJECT_STATEMENT_ABSTRACT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SAML_SUBJECT_STATEMENT_ABSTRACT))
/*#define LASSO_SAML_SUBJECT_STATEMENT_ABSTRACT_GET_CLASS(o)
 * (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_SAML_SUBJECT_STATEMENT_ABSTRACT,
 * LassoSamlSubjectStatementAbstractClass)) */

/*typedef struct _LassoSamlSubjectStatementAbstractClass
 * LassoSamlSubjectStatementAbstractClass;*/

typedef struct _LassoSamlSubjectStatementAbstract {
  LassoSamlStatementAbstract parent;
  /*< private >*/
} LassoSamlSubjectStatementAbstract;

/*struct _LassoSamlSubjectStatementAbstractClass {
  LassoSamlStatementAbstractClass parent;
};*/

GType lasso_saml_subject_statement_abstract_get_type(void);
LassoNode* lasso_saml_subject_statement_abstract_new(const xmlChar *name);

void lasso_saml_subject_statement_abstract_set_subject (LassoSamlSubjectStatementAbstract *node,
								     LassoSamlSubject *subject);


/*
 */

/*****************************************************************************/
/* Lasso                                                                     */
/*****************************************************************************/

/* prefix & href */
const xmlChar lassoLassoHRef[];
const xmlChar lassoLassoPrefix[];

/*****************************************************************************/
/* Liberty Alliance                                                          */
/*****************************************************************************/

/* prefix & href */
const xmlChar lassoLibHRef[];
const xmlChar lassoLibPrefix[];

/* Versioning */
const xmlChar lassoLibMajorVersion[];
const xmlChar lassoLibMinorVersion[];

/* NameIDPolicyType */
const xmlChar lassoLibNameIDPolicyTypeNone[];
const xmlChar lassoLibNameIDPolicyTypeOneTime[];
const xmlChar lassoLibNameIDPolicyTypeFederated[];
const xmlChar lassoLibNameIDPolicyTypeAny[];

/* AuthnContextComparison */
const xmlChar lassoLibAuthnContextComparisonExact[];
const xmlChar lassoLibAuthnContextComparisonMinimum[];
const xmlChar lassoLibAuthnContextComparisonBetter[];

/* StatusCodes */
const xmlChar lassoLibStatusCodeFederationDoesNotExist[];
const xmlChar lassoLibStatusCodeInvalidAssertionConsumerServiceIndex[];
const xmlChar lassoLibStatusCodeInvalidSignature[];
const xmlChar lassoLibStatusCodeNoAuthnContext[];
const xmlChar lassoLibStatusCodeNoAvailableIDP[];
const xmlChar lassoLibStatusCodeNoPassive[];
const xmlChar lassoLibStatusCodeNoSupportedIDP[];
const xmlChar lassoLibStatusCodeProxyCountExceeded[];
const xmlChar lassoLibStatusCodeUnknownPrincipal[];
const xmlChar lassoLibStatusCodeUnsignedAuthnRequest[];

/* ProtocolProfile */
const xmlChar lassoLibProtocolProfileSSOGet[];
const xmlChar lassoLibProtocolProfileSSOPost[];
const xmlChar lassoLibProtocolProfileBrwsArt[];
const xmlChar lassoLibProtocolProfileBrwsPost[];
const xmlChar lassoLibProtocolProfileFedTermIdpHttp[];
const xmlChar lassoLibProtocolProfileFedTermIdpSoap[];
const xmlChar lassoLibProtocolProfileFedTermSpHttp[];
const xmlChar lassoLibProtocolProfileFedTermSpSoap[];
const xmlChar lassoLibProtocolProfileRniIdpHttp[];
const xmlChar lassoLibProtocolProfileRniIdpSoap[];
const xmlChar lassoLibProtocolProfileRniSpHttp[];
const xmlChar lassoLibProtocolProfileRniSpSoap[];
const xmlChar lassoLibProtocolProfileSloSpHttp[];
const xmlChar lassoLibProtocolProfileSloSpSoap[];
const xmlChar lassoLibProtocolProfileSloIdpHttp[];
const xmlChar lassoLibProtocolProfileSloIdpSoap[];

/* NameIdentifier formats */
const xmlChar lassoLibNameIdentifierFormatFederated[];
const xmlChar lassoLibNameIdentifierFormatOneTime[];
const xmlChar lassoLibNameIdentifierFormatEncrypted[];
const xmlChar lassoLibNameIdentifierFormatEntityID[];

/* Consent */
const xmlChar lassoLibConsentObtained[];
const xmlChar lassoLibConsentUnavailable[];
const xmlChar lassoLibConsentInapplicable[];

/*****************************************************************************/
/* METADATA                                                                  */
/*****************************************************************************/

/* prefix & href */
const xmlChar lassoMetadataHRef[];
const xmlChar lassoMetadataPrefix[];

/*****************************************************************************/
/* SAML                                                                      */
/*****************************************************************************/

/* prefix & href */
const xmlChar lassoSamlAssertionHRef[];
const xmlChar lassoSamlAssertionPrefix[];
const xmlChar lassoSamlProtocolHRef[];
const xmlChar lassoSamlProtocolPrefix[];

/* Versioning */
const xmlChar lassoSamlMajorVersion[];
const xmlChar lassoSamlMinorVersion[];

/* StatusCodes */
const xmlChar lassoSamlStatusCodeRequestDenied[];
const xmlChar lassoSamlStatusCodeSuccess[];

/* AuthenticationMethods */
const xmlChar lassoSamlAuthenticationMethodPassword[];
const xmlChar lassoSamlAuthenticationMethodKerberos[];
const xmlChar lassoSamlAuthenticationMethodSecureRemotePassword[];
const xmlChar lassoSamlAuthenticationMethodHardwareToken[];
const xmlChar lassoSamlAuthenticationMethodSmartcardPki[];
const xmlChar lassoSamlAuthenticationMethodSoftwarePki[];
const xmlChar lassoSamlAuthenticationMethodPgp[];
const xmlChar lassoSamlAuthenticationMethodSPki[];
const xmlChar lassoSamlAuthenticationMethodXkms[];
const xmlChar lassoSamlAuthenticationMethodXmlDSig[];
const xmlChar lassoSamlAuthenticationMethodUnspecified[];

/* ConfirmationMethods */
const xmlChar lassoSamlConfirmationMethodArtifact01[];
const xmlChar lassoSamlConfirmationMethodBearer[];
const xmlChar lassoSamlConfirmationMethodHolderOfKey[];
const xmlChar lassoSamlConfirmationMethodSenderVouches[];

/*****************************************************************************/
/* SOAP                                                                      */
/*****************************************************************************/

/* prefix & href */
const xmlChar lassoSoapEnvHRef[];
const xmlChar lassoSoapEnvPrefix[];

/*
 */


xmlChar*   lasso_build_random_sequence  (guint8 size);

xmlChar*   lasso_build_unique_id        (guint8 size);

xmlChar*   lasso_doc_get_node_content   (xmlDocPtr      doc,
						      const xmlChar *name);

xmlChar*   lasso_g_ptr_array_index      (GPtrArray *a,
						      guint      i);

gchar*     lasso_get_current_time       (void);

GPtrArray* lasso_query_get_value        (const gchar   *query,
						      const xmlChar *param);

GData*     lasso_query_to_dict          (const gchar *query);

int        lasso_query_verify_signature (const gchar   *query,
						      const xmlChar *sender_public_key_file,
						      const xmlChar *recipient_private_key_file);

xmlChar*   lasso_sha1                   (xmlChar *str);

xmlChar*   lasso_str_escape             (xmlChar *str);

xmlChar*   lasso_str_hash               (xmlChar    *str,
						      const char *private_key_file);

xmlDocPtr  lasso_str_sign               (xmlChar              *str,
						      lassoSignatureMethod  sign_method,
						      const char           *private_key_file);

xmlChar*   lasso_str_unescape           (xmlChar *str);

/*
 */

#define LASSO_TYPE_NODE (lasso_node_get_type())
#define LASSO_NODE(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_NODE, LassoNode))
/*#define LASSO_NODE_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass),
 * LASSO_TYPE_NODE, LassoNodeClass))*/
#define LASSO_IS_NODE(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_NODE))
#define LASSO_IS_NODE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_NODE))
/*#define LASSO_NODE_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o),
 * LASSO_TYPE_NODE, LassoNodeClass)) */

typedef enum {
  lassoNodeExportTypeXml = 1,
  lassoNodeExportTypeBase64,
  lassoNodeExportTypeQuery,
  lassoNodeExportTypeSoap
} lassoNodeExportType;

typedef struct _xmlAttr LassoAttr;

/*typedef struct _LassoNodeClass LassoNodeClass;*/
typedef struct _LassoNodePrivate LassoNodePrivate;

/**
 * _LassoNode:
 * @parent: the parent object
 * @private: private pointer structure
 **/
typedef struct _LassoNode {
  GObject parent;
  /*< private >*/
  LassoNodePrivate *private;
} LassoNode;

/*struct _LassoNodeClass {
  GObjectClass parent_class;
  LassoNode*     (* copy)             (LassoNode     *node);
  void           (* destroy)          (LassoNode     *node);
  gchar*         (* dump)             (LassoNode     *node,
				       const xmlChar *encoding,
				       int            format);
  gchar*         (* export)           (LassoNode     *node);
  gchar*         (* export_to_base64) (LassoNode     *node);
  gchar*         (* export_to_query)  (LassoNode     *node,
				       lassoSignatureMethod  sign_method,
				       const gchar          *private_key_file);
  gchar*         (* export_to_soap)   (LassoNode     *node);
  LassoAttr*     (* get_attr)         (LassoNode      *node,
				       const xmlChar  *name,
				       GError        **err);
  xmlChar*       (* get_attr_value)   (LassoNode      *node,
				       const xmlChar  *name,
				       GError        **err);
  GPtrArray*     (* get_attrs)        (LassoNode     *node);
  LassoNode*     (* get_child)        (LassoNode      *node,
				       const xmlChar  *name,
				       const xmlChar  *href,
				       GError        **err);
  xmlChar*       (* get_child_content)(LassoNode      *node,
				       const xmlChar  *name,
				       const xmlChar  *href,
				       GError        **err);
  GPtrArray*     (* get_children)     (LassoNode     *node);
  xmlChar*       (* get_content)      (LassoNode      *node,
				       GError        **err);
  xmlChar*       (* get_name)         (LassoNode     *node);
  void           (* import)           (LassoNode     *node,
                                       const gchar   *buffer);
  void           (* import_from_node) (LassoNode     *node,
                                       LassoNode     *imported_node);
  void           (* rename_prop)      (LassoNode     *node,
				       const xmlChar *old_name,
				       const xmlChar *new_name);
  gint           (* verify_signature) (LassoNode     *node,
				       const gchar   *certificate_file,
				       GError       **err);
  void       (* add_child)     (LassoNode     *node,
				LassoNode     *child,
				gboolean       unbounded);
  gint       (* add_signature) (LassoNode      *node,
				gint            sign_method,
				const xmlChar  *private_key_file,
				const xmlChar  *certificate_file,
				GError        **err);
  gchar*     (* build_query)   (LassoNode     *node);
  xmlNodePtr (* get_xmlNode)   (LassoNode     *node);
  void       (* new_child)     (LassoNode     *node,
				const xmlChar *name,
				const xmlChar *content,
				gboolean       unbounded);
  GData*     (* serialize)     (LassoNode     *node,
				GData         *gd);
  void       (* set_name)      (LassoNode     *node,
				const xmlChar *name);
  void       (* set_ns)        (LassoNode     *node,
				const xmlChar *href,
				const xmlChar *prefix);
  void       (* set_prop)      (LassoNode     *node,
				const xmlChar *name,
				const xmlChar *value);
  void       (* set_xmlNode)   (LassoNode     *node,
				xmlNodePtr     libxml_node);
};
*/

GType          lasso_node_get_type         (void);

LassoNode*     lasso_node_new              (void);
LassoNode*     lasso_node_new_from_dump    (const xmlChar *buffer);
LassoNode*     lasso_node_new_from_xmlNode (xmlNodePtr node);

LassoNode*     lasso_node_copy             (LassoNode *node);

void           lasso_node_destroy          (LassoNode *node);

xmlChar*       lasso_node_dump             (LassoNode     *node,
							 const xmlChar *encoding,
							 int            format);

xmlChar*       lasso_node_export           (LassoNode *node);

xmlChar*       lasso_node_export_to_base64 (LassoNode *node);

gchar*         lasso_node_export_to_query  (LassoNode            *node,
							 lassoSignatureMethod  sign_method,
							 const gchar          *private_key_file);

xmlChar*       lasso_node_export_to_soap   (LassoNode *node);

LassoAttr*     lasso_node_get_attr         (LassoNode      *node,
							 const xmlChar  *name,
							 GError        **err);

xmlChar*       lasso_node_get_attr_value   (LassoNode      *node,
							 const xmlChar  *name,
							 GError        **err);

GPtrArray*     lasso_node_get_attrs        (LassoNode *node);

LassoNode*     lasso_node_get_child        (LassoNode      *node,
							 const xmlChar  *name,
							 const xmlChar  *href,
							 GError        **err);

xmlChar *      lasso_node_get_child_content(LassoNode      *node,
							 const xmlChar  *name,
							 const xmlChar  *href,
							 GError        **err);

GPtrArray*     lasso_node_get_children     (LassoNode *node);

xmlChar*       lasso_node_get_content      (LassoNode  *node,
							 GError    **err);

xmlChar*       lasso_node_get_name         (LassoNode *node);

void           lasso_node_import           (LassoNode     *node,
							 const xmlChar *buffer);

void           lasso_node_import_from_node (LassoNode *node,
							 LassoNode *imported_node);

void           lasso_node_rename_prop      (LassoNode     *node,
							 const xmlChar *old_name,
							 const xmlChar *new_name);

#endif
