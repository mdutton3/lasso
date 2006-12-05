
#ifndef SWIGPHP4
%rename(Samlp2AssertionIDRequest) LassoSamlp2AssertionIDRequest;
#endif
typedef struct {
#ifndef SWIGPHP4
	%rename(assertionIdRef) AssertionIDRef;
#endif
	char *AssertionIDRef;
} LassoSamlp2AssertionIDRequest;
%extend LassoSamlp2AssertionIDRequest {

	/* inherited from Samlp2RequestAbstract */
#ifndef SWIGPHP4
	%rename(issuer) Issuer;
#endif
	%newobject *Issuer_get;
	LassoSaml2NameID *Issuer;

#ifndef SWIGPHP4
	%rename(extensions) Extensions;
#endif
	%newobject *Extensions_get;
	LassoSamlp2Extensions *Extensions;

#ifndef SWIGPHP4
	%rename(iD) ID;
#endif
	char *ID;
#ifndef SWIGPHP4
	%rename(version) Version;
#endif
	char *Version;
#ifndef SWIGPHP4
	%rename(issueInstant) IssueInstant;
#endif
	char *IssueInstant;
#ifndef SWIGPHP4
	%rename(destination) Destination;
#endif
	char *Destination;
#ifndef SWIGPHP4
	%rename(consent) Consent;
#endif
	char *Consent;

	/* Constructor, Destructor & Static Methods */
	LassoSamlp2AssertionIDRequest();
	~LassoSamlp2AssertionIDRequest();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{

/* inherited from RequestAbstract */

/* Issuer */

#define LassoSamlp2AssertionIDRequest_get_Issuer(self) get_node(LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Issuer)
#define LassoSamlp2AssertionIDRequest_Issuer_get(self) get_node(LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Issuer)
#define LassoSamlp2AssertionIDRequest_set_Issuer(self,value) set_node((gpointer*)&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Issuer, (value))
#define LassoSamlp2AssertionIDRequest_Issuer_set(self,value) set_node((gpointer*)&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Issuer, (value))
                    

/* Extensions */

#define LassoSamlp2AssertionIDRequest_get_Extensions(self) get_node(LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Extensions)
#define LassoSamlp2AssertionIDRequest_Extensions_get(self) get_node(LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Extensions)
#define LassoSamlp2AssertionIDRequest_set_Extensions(self,value) set_node((gpointer*)&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Extensions, (value))
#define LassoSamlp2AssertionIDRequest_Extensions_set(self,value) set_node((gpointer*)&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Extensions, (value))
                    

/* ID */

#define LassoSamlp2AssertionIDRequest_get_ID(self) LASSO_SAMLP2_REQUEST_ABSTRACT(self)->ID
#define LassoSamlp2AssertionIDRequest_ID_get(self) LASSO_SAMLP2_REQUEST_ABSTRACT(self)->ID

#define LassoSamlp2AssertionIDRequest_set_ID(self,value) set_string(&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->ID, (value))
#define LassoSamlp2AssertionIDRequest_ID_set(self,value) set_string(&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->ID, (value))

/* Version */

#define LassoSamlp2AssertionIDRequest_get_Version(self) LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Version
#define LassoSamlp2AssertionIDRequest_Version_get(self) LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Version

#define LassoSamlp2AssertionIDRequest_set_Version(self,value) set_string(&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Version, (value))
#define LassoSamlp2AssertionIDRequest_Version_set(self,value) set_string(&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Version, (value))

/* IssueInstant */

#define LassoSamlp2AssertionIDRequest_get_IssueInstant(self) LASSO_SAMLP2_REQUEST_ABSTRACT(self)->IssueInstant
#define LassoSamlp2AssertionIDRequest_IssueInstant_get(self) LASSO_SAMLP2_REQUEST_ABSTRACT(self)->IssueInstant

#define LassoSamlp2AssertionIDRequest_set_IssueInstant(self,value) set_string(&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->IssueInstant, (value))
#define LassoSamlp2AssertionIDRequest_IssueInstant_set(self,value) set_string(&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->IssueInstant, (value))

/* Destination */

#define LassoSamlp2AssertionIDRequest_get_Destination(self) LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Destination
#define LassoSamlp2AssertionIDRequest_Destination_get(self) LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Destination

#define LassoSamlp2AssertionIDRequest_set_Destination(self,value) set_string(&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Destination, (value))
#define LassoSamlp2AssertionIDRequest_Destination_set(self,value) set_string(&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Destination, (value))

/* Consent */

#define LassoSamlp2AssertionIDRequest_get_Consent(self) LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Consent
#define LassoSamlp2AssertionIDRequest_Consent_get(self) LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Consent

#define LassoSamlp2AssertionIDRequest_set_Consent(self,value) set_string(&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Consent, (value))
#define LassoSamlp2AssertionIDRequest_Consent_set(self,value) set_string(&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Consent, (value))


/* Constructors, destructors & static methods implementations */

#define new_LassoSamlp2AssertionIDRequest lasso_samlp2_assertion_idrequest_new
#define delete_LassoSamlp2AssertionIDRequest(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSamlp2AssertionIDRequest_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

