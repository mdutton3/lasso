%{
#include <lasso/saml-2.0/profile.h>
%}

#define LASSO_SAML2_SUPPORT 1

/* Utility functions */

#ifdef SWIG_PHP_RENAMES
%rename(lasso_isSamlQuery) lasso_profile_is_saml_query;
#else
%rename(isSamlQuery) lasso_profile_is_saml_query;
#endif
gboolean lasso_profile_is_saml_query(char *query);


/* NameIdPolicy */
#ifndef SWIG_PHP_RENAMES
%rename(SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT) LASSO_SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT;
%rename(SAML2_NAME_IDENTIFIER_FORMAT_TRANSIENT) LASSO_SAML2_NAME_IDENTIFIER_FORMAT_TRANSIENT;
%rename(SAML2_NAME_IDENTIFIER_FORMAT_ENCRYPTED) LASSO_SAML2_NAME_IDENTIFIER_FORMAT_ENCRYPTED;
#endif
#define LASSO_SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT \
		"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
#define LASSO_SAML2_NAME_IDENTIFIER_FORMAT_TRANSIENT \
		"urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
#define LASSO_SAML2_NAME_IDENTIFIER_FORMAT_ENCRYPTED \
		"urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted"

/* Protocol Bindings */
#ifndef SWIG_PHP_RENAMES
%rename(SAML2_METADATA_BINDING_SOAP) LASSO_SAML2_METADATA_BINDING_SOAP;
%rename(SAML2_METADATA_BINDING_REDIRECT) LASSO_SAML2_METADATA_BINDING_REDIRECT;
%rename(SAML2_METADATA_BINDING_POST) LASSO_SAML2_METADATA_BINDING_POST;
%rename(SAML2_METADATA_BINDING_ARTIFACT) LASSO_SAML2_METADATA_BINDING_ARTIFACT;
%rename(SAML2_METADATA_BINDING_PAOS) LASSO_SAML2_METADATA_BINDING_PAOS;
#endif
#define LASSO_SAML2_METADATA_BINDING_SOAP "urn:oasis:names:tc:SAML:2.0:bindings:SOAP"
#define LASSO_SAML2_METADATA_BINDING_REDIRECT "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
#define LASSO_SAML2_METADATA_BINDING_POST "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
#define LASSO_SAML2_METADATA_BINDING_ARTIFACT "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"
#define LASSO_SAML2_METADATA_BINDING_PAOS "urn:oasis:names:tc:SAML:2.0:bindings:PAOS"


/* AuthnClassRef */
#ifndef SWIG_PHP_RENAMES
%rename(SAML2_AUTHN_CONTEXT_AUTHENTICATED_TELEPHONY) \
	LASSO_SAML2_AUTHN_CONTEXT_AUTHENTICATED_TELEPHONY;
%rename(SAML2_AUTHN_CONTEXT_INTERNET_PROTOCOL) \
	LASSO_SAML2_AUTHN_CONTEXT_INTERNET_PROTOCOL;
%rename(SAML2_AUTHN_CONTEXT_INTERNET_PROTOCOL_PASSWORD) \
	LASSO_SAML2_AUTHN_CONTEXT_INTERNET_PROTOCOL_PASSWORD;
%rename(SAML2_AUTHN_CONTEXT_KERBEROS) \
	LASSO_SAML2_AUTHN_CONTEXT_KERBEROS;
%rename(SAML2_AUTHN_CONTEXT_MOBILE_ONE_FACTOR_CONTRACT) \
	LASSO_SAML2_AUTHN_CONTEXT_MOBILE_ONE_FACTOR_CONTRACT;
%rename(SAML2_AUTHN_CONTEXT_MOBILE_ONE_FACTOR_UNREGISTERED) \
	LASSO_SAML2_AUTHN_CONTEXT_MOBILE_ONE_FACTOR_UNREGISTERED;
%rename(SAML2_AUTHN_CONTEXT_MOBILE_TWO_FACTOR_CONTRACT) \
	LASSO_SAML2_AUTHN_CONTEXT_MOBILE_TWO_FACTOR_CONTRACT;
%rename(SAML2_AUTHN_CONTEXT_MOBILE_TWO_FACTOR_UNREGISTERED) \
	LASSO_SAML2_AUTHN_CONTEXT_MOBILE_TWO_FACTOR_UNREGISTERED;
%rename(SAML2_AUTHN_CONTEXT_NOMAD_TELEPHONY) \
	LASSO_SAML2_AUTHN_CONTEXT_NOMAD_TELEPHONY;
%rename(SAML2_AUTHN_CONTEXT_PERSONALIZED_TELEPHONY) \
	LASSO_SAML2_AUTHN_CONTEXT_PERSONALIZED_TELEPHONY;
%rename(SAML2_AUTHN_CONTEXT_PGP) \
	LASSO_SAML2_AUTHN_CONTEXT_PGP;
%rename(SAML2_AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT) \
	LASSO_SAML2_AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT;
%rename(SAML2_AUTHN_CONTEXT_PASSWORD) \
	LASSO_SAML2_AUTHN_CONTEXT_PASSWORD;
%rename(SAML2_AUTHN_CONTEXT_PREVIOUS_SESSION) \
	LASSO_SAML2_AUTHN_CONTEXT_PREVIOUS_SESSION;
%rename(SAML2_AUTHN_CONTEXT_SMARTCARD) \
	LASSO_SAML2_AUTHN_CONTEXT_SMARTCARD;
%rename(SAML2_AUTHN_CONTEXT_SMARTCARD_PKI) \
	LASSO_SAML2_AUTHN_CONTEXT_SMARTCARD_PKI;
%rename(SAML2_AUTHN_CONTEXT_SOFTWARE_PKI) \
	LASSO_SAML2_AUTHN_CONTEXT_SOFTWARE_PKI;
%rename(SAML2_AUTHN_CONTEXT_SPKI) \
	LASSO_SAML2_AUTHN_CONTEXT_SPKI;
%rename(SAML2_AUTHN_CONTEXT_SECURE_REMOTE_PASSWORD) \
	LASSO_SAML2_AUTHN_CONTEXT_SECURE_REMOTE_PASSWORD;
%rename(SAML2_AUTHN_CONTEXT_TLS_CLIENT) \
	LASSO_SAML2_AUTHN_CONTEXT_TLS_CLIENT;
%rename(SAML2_AUTHN_CONTEXT_X509) \
	LASSO_SAML2_AUTHN_CONTEXT_X509;
%rename(SAML2_AUTHN_CONTEXT_TELEPHONY) \
	LASSO_SAML2_AUTHN_CONTEXT_TELEPHONY;
%rename(SAML2_AUTHN_CONTEXT_TIME_SYNC_TOKEN) \
	LASSO_SAML2_AUTHN_CONTEXT_TIME_SYNC_TOKEN;
%rename(SAML2_AUTHN_CONTEXT_XMLDSIG) \
	LASSO_SAML2_AUTHN_CONTEXT_XMLDSIG;
#endif
#define LASSO_SAML2_AUTHN_CONTEXT_AUTHENTICATED_TELEPHONY \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:AuthenticatedTelephony"
#define LASSO_SAML2_AUTHN_CONTEXT_INTERNET_PROTOCOL \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocol"
#define LASSO_SAML2_AUTHN_CONTEXT_INTERNET_PROTOCOL_PASSWORD \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocolPassword"
#define LASSO_SAML2_AUTHN_CONTEXT_KERBEROS \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos"
#define LASSO_SAML2_AUTHN_CONTEXT_MOBILE_ONE_FACTOR_CONTRACT \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:MobileOneFactorContract"
#define LASSO_SAML2_AUTHN_CONTEXT_MOBILE_ONE_FACTOR_UNREGISTERED \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:MobileOneFactorUnregistered"
#define LASSO_SAML2_AUTHN_CONTEXT_MOBILE_TWO_FACTOR_CONTRACT \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract"
#define LASSO_SAML2_AUTHN_CONTEXT_MOBILE_TWO_FACTOR_UNREGISTERED \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorUnregistered"
#define LASSO_SAML2_AUTHN_CONTEXT_NOMAD_TELEPHONY \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:NomadTelephony"
#define LASSO_SAML2_AUTHN_CONTEXT_PERSONALIZED_TELEPHONY \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:PersonalizedTelephony"
#define LASSO_SAML2_AUTHN_CONTEXT_PGP \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:PGP"
#define LASSO_SAML2_AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
#define LASSO_SAML2_AUTHN_CONTEXT_PASSWORD \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:Password"
#define LASSO_SAML2_AUTHN_CONTEXT_PREVIOUS_SESSION \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:PreviousSession"
#define LASSO_SAML2_AUTHN_CONTEXT_SMARTCARD \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard"
#define LASSO_SAML2_AUTHN_CONTEXT_SMARTCARD_PKI \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI"
#define LASSO_SAML2_AUTHN_CONTEXT_SOFTWARE_PKI \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:SoftwarePKI"
#define LASSO_SAML2_AUTHN_CONTEXT_SPKI \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:SPKI"
#define LASSO_SAML2_AUTHN_CONTEXT_SECURE_REMOTE_PASSWORD \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:SecureRemotePassword"
#define LASSO_SAML2_AUTHN_CONTEXT_TLS_CLIENT \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient"
#define LASSO_SAML2_AUTHN_CONTEXT_X509 \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:X509"
#define LASSO_SAML2_AUTHN_CONTEXT_TELEPHONY \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:Telephony"
#define LASSO_SAML2_AUTHN_CONTEXT_TIME_SYNC_TOKEN \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken"
#define LASSO_SAML2_AUTHN_CONTEXT_XMLDSIG \
	"urn:oasis:names:tc:SAML:2.0:ac:classes:XMLDSig"

/***********************************************************************
 * lasso:NameIdManagement
 ***********************************************************************/


#ifndef SWIG_PHP_RENAMES
%rename(NameIdManagement) LassoNameIdManagement;
#endif
typedef struct {
} LassoNameIdManagement;
%extend LassoNameIdManagement {
	/* Attributes inherited from LassoProfile */
	%immutable artifact;
	char *artifact;

	char *artifactMessage;

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
	LassoNode *nameIdentifier;

	char *remoteProviderId;

	%newobject request_get;
	LassoNode *request;

	%newobject response_get;
	LassoNode *response;

	%newobject server_get;
	LassoServer *server;

	%newobject session_get;
	LassoSession *session;

	/* Constructor, Destructor & Static Methods */

	LassoNameIdManagement(LassoServer *server);

	~LassoNameIdManagement();

	%newobject newFromDump;
	static LassoNameIdManagement *newFromDump(LassoServer *server, char *dump);

	/* Methods inherited from LassoProfile */

	THROW_ERROR()
	int setIdentityFromDump(char *dump);
	END_THROW_ERROR()

	THROW_ERROR()
	int setSessionFromDump(char *dump);
	END_THROW_ERROR()

	/* Methods */

	THROW_ERROR()
	int buildRequestMsg();
	END_THROW_ERROR()

	THROW_ERROR()
	int buildResponseMsg();
	END_THROW_ERROR()

	%newobject dump;
	char *dump();

	THROW_ERROR()
	int initRequest(char *remoteProviderId = NULL,
			char *new_name_id = NULL,
			 LassoHttpMethod httpMethod = LASSO_HTTP_METHOD_ANY);
	END_THROW_ERROR()

	THROW_ERROR()
	int processRequestMsg(char *requestMsg);
	END_THROW_ERROR()

	THROW_ERROR()
	int processResponseMsg(char *responseMsg);
	END_THROW_ERROR()

	THROW_ERROR()
	int validateRequest();
	END_THROW_ERROR()
}

%{

/* Implementations of attributes inherited from LassoProfile */

/* identity */
#define LassoNameIdManagement_get_identity(self) lasso_profile_get_identity(LASSO_PROFILE(self))
#define LassoNameIdManagement_identity_get(self) lasso_profile_get_identity(LASSO_PROFILE(self))
#define LassoNameIdManagement_set_identity(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->identity, (value))
#define LassoNameIdManagement_identity_set(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->identity, (value))

/* artifact */
#define LassoNameIdManagement_get_artifact(self) lasso_profile_get_artifact(LASSO_PROFILE(self))
#define LassoNameIdManagement_artifact_get(self) lasso_profile_get_artifact(LASSO_PROFILE(self))

/* artifactMessage */
#define LassoNameIdManagement_get_artifactMessage(self) lasso_profile_get_artifact_message(LASSO_PROFILE(self))
#define LassoNameIdManagement_artifactMessage_get(self) lasso_profile_get_artifact_message(LASSO_PROFILE(self))
#define LassoNameIdManagement_set_artifactMessage(self, value) lasso_profile_set_artifact_message(LASSO_PROFILE(self), value)
#define LassoNameIdManagement_artifactMessage_set(self, value) lasso_profile_set_artifact_message(LASSO_PROFILE(self), value)

/* isIdentityDirty */
#define LassoNameIdManagement_get_isIdentityDirty(self) lasso_profile_is_identity_dirty(LASSO_PROFILE(self))
#define LassoNameIdManagement_isIdentityDirty_get(self) lasso_profile_is_identity_dirty(LASSO_PROFILE(self))

/* isSessionDirty */
#define LassoNameIdManagement_get_isSessionDirty(self) lasso_profile_is_session_dirty(LASSO_PROFILE(self))
#define LassoNameIdManagement_isSessionDirty_get(self) lasso_profile_is_session_dirty(LASSO_PROFILE(self))

/* msgBody */
#define LassoNameIdManagement_get_msgBody(self) LASSO_PROFILE(self)->msg_body
#define LassoNameIdManagement_msgBody_get(self) LASSO_PROFILE(self)->msg_body

/* msgRelayState */
#define LassoNameIdManagement_get_msgRelayState(self) LASSO_PROFILE(self)->msg_relayState
#define LassoNameIdManagement_msgRelayState_get(self) LASSO_PROFILE(self)->msg_relayState

/* msgUrl */
#define LassoNameIdManagement_get_msgUrl(self) LASSO_PROFILE(self)->msg_url
#define LassoNameIdManagement_msgUrl_get(self) LASSO_PROFILE(self)->msg_url

/* nameIdentifier */
#define LassoNameIdManagement_get_nameIdentifier(self) get_node(LASSO_PROFILE(self)->nameIdentifier)
#define LassoNameIdManagement_nameIdentifier_get(self) get_node(LASSO_PROFILE(self)->nameIdentifier)
#define LassoNameIdManagement_set_nameIdentifier(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->nameIdentifier, (value))
#define LassoNameIdManagement_nameIdentifier_set(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->nameIdentifier, (value))

/* remoteProviderId */
#define LassoNameIdManagement_get_remoteProviderId(self) LASSO_PROFILE(self)->remote_providerID
#define LassoNameIdManagement_remoteProviderId_get(self) LASSO_PROFILE(self)->remote_providerID
#define LassoNameIdManagement_set_remoteProviderId(self, value) set_string(&LASSO_PROFILE(self)->remote_providerID, (value))
#define LassoNameIdManagement_remoteProviderId_set(self, value) set_string(&LASSO_PROFILE(self)->remote_providerID, (value))

/* request */
#define LassoNameIdManagement_get_request(self) get_node(LASSO_PROFILE(self)->request)
#define LassoNameIdManagement_request_get(self) get_node(LASSO_PROFILE(self)->request)
#define LassoNameIdManagement_set_request(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->request, (value))
#define LassoNameIdManagement_request_set(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->request, (value))

/* response */
#define LassoNameIdManagement_get_response(self) get_node(LASSO_PROFILE(self)->response)
#define LassoNameIdManagement_response_get(self) get_node(LASSO_PROFILE(self)->response)
#define LassoNameIdManagement_set_response(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->response, (value))
#define LassoNameIdManagement_response_set(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->response, (value))

/* server */
#define LassoNameIdManagement_get_server(self) get_node(LASSO_PROFILE(self)->server)
#define LassoNameIdManagement_server_get(self) get_node(LASSO_PROFILE(self)->server)
#define LassoNameIdManagement_set_server(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->server, (value))
#define LassoNameIdManagement_server_set(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->server, (value))

/* session */
#define LassoNameIdManagement_get_session(self) lasso_profile_get_session(LASSO_PROFILE(self))
#define LassoNameIdManagement_session_get(self) lasso_profile_get_session(LASSO_PROFILE(self))
#define LassoNameIdManagement_set_session(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->session, (value))
#define LassoNameIdManagement_session_set(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->session, (value))

/* Constructors, destructors & static methods implementations */

#define new_LassoNameIdManagement lasso_name_id_management_new
#define delete_LassoNameIdManagement(self) lasso_node_destroy(LASSO_NODE(self))
#define LassoNameIdManagement_newFromDump lasso_name_id_management_new_from_dump

/* Implementations of methods inherited from LassoProfile */

#define LassoNameIdManagement_setIdentityFromDump(self, dump) \
	lasso_profile_set_identity_from_dump(LASSO_PROFILE(self), dump)
#define LassoNameIdManagement_setSessionFromDump(self, dump) \
	lasso_profile_set_session_from_dump(LASSO_PROFILE(self), dump)

/* Methods implementations */

#define LassoNameIdManagement_buildRequestMsg lasso_name_id_management_build_request_msg
#define LassoNameIdManagement_buildResponseMsg lasso_name_id_management_build_response_msg
#define LassoNameIdManagement_dump lasso_name_id_management_dump
#define LassoNameIdManagement_getNextProviderId lasso_name_id_management_get_next_providerID
#define LassoNameIdManagement_initRequest lasso_name_id_management_init_request
#define LassoNameIdManagement_processRequestMsg lasso_name_id_management_process_request_msg
#define LassoNameIdManagement_processResponseMsg lasso_name_id_management_process_response_msg
#define LassoNameIdManagement_resetProviderIdIndex lasso_name_id_management_reset_providerID_index
#define LassoNameIdManagement_validateRequest lasso_name_id_management_validate_request

%}

/***********************************************************************
 * lasso:Ecp
 ***********************************************************************/


#ifndef SWIG_PHP_RENAMES
%rename(Ecp) LassoEcp;
#endif
typedef struct {
} LassoEcp;
%extend LassoEcp {
	%immutable msgBody;
	char *msgBody;

	%immutable msgRelayState;
	char *msgRelayState;

	%immutable msgUrl;
	char *msgUrl;

	%newobject request_get;
	LassoNode *request;

	%newobject response_get;
	LassoNode *response;

	%immutable assertionConsumerURL;
	char *assertionConsumerURL;

	/* Constructor, Destructor & Static Methods */

	LassoEcp(LassoServer *server);

	~LassoEcp();

	/* Methods inherited from Profile */

	/* Methods */

	THROW_ERROR()
	int processAuthnRequestMsg(char *authnRequestMsg);
	END_THROW_ERROR()

	THROW_ERROR()
	int processResponseMsg(char *responseMsg);
	END_THROW_ERROR()

}

%{

/* Implementations of attributes inherited from Profile */

/* msgBody */
#define LassoEcp_get_msgBody(self) LASSO_PROFILE(self)->msg_body
#define LassoEcp_msgBody_get(self) LASSO_PROFILE(self)->msg_body

/* msgRelayState */
#define LassoEcp_get_msgRelayState(self) LASSO_PROFILE(self)->msg_relayState
#define LassoEcp_msgRelayState_get(self) LASSO_PROFILE(self)->msg_relayState

/* msgUrl */
#define LassoEcp_get_msgUrl(self) LASSO_PROFILE(self)->msg_url
#define LassoEcp_msgUrl_get(self) LASSO_PROFILE(self)->msg_url

/* request */
#define LassoEcp_get_request(self) get_node(LASSO_PROFILE(self)->request)
#define LassoEcp_request_get(self) get_node(LASSO_PROFILE(self)->request)
#define LassoEcp_set_request(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->request, (value))
#define LassoEcp_request_set(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->request, (value))

/* response */
#define LassoEcp_get_response(self) get_node(LASSO_PROFILE(self)->response)
#define LassoEcp_response_get(self) get_node(LASSO_PROFILE(self)->response)
#define LassoEcp_set_response(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->response, (value))
#define LassoEcp_response_set(self, value) set_node((gpointer *) &LASSO_PROFILE(self)->response, (value))

/* assertionConsumerURL */
#define LassoEcp_get_assertionConsumerURL(self) self->assertionConsumerURL
#define LassoEcp_assertionConsumerURL_get(self) self->assertionConsumerURL

/* Constructors, destructors & static methods implementations */

#define new_LassoEcp lasso_ecp_new
#define delete_LassoEcp(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from Profile */

/* Methods implementations */
#define LassoEcp_processAuthnRequestMsg lasso_ecp_process_authn_request_msg
#define LassoEcp_processResponseMsg lasso_ecp_process_response_msg

%}
