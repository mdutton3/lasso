
#ifndef SWIGPHP4
%rename(Samlp2Response) LassoSamlp2Response;
#endif
typedef struct {
} LassoSamlp2Response;
%extend LassoSamlp2Response {

	/* inherited from Samlp2StatusResponse */
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
	%rename(status) Status;
#endif
	%newobject *Status_get;
	LassoSamlp2Status *Status;

#ifndef SWIGPHP4
	%rename(iD) ID;
#endif
	char *ID;
#ifndef SWIGPHP4
	%rename(inResponseTo) InResponseTo;
#endif
	char *InResponseTo;
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

#ifndef SWIGPHP4
	%rename(assertion) Assertion;
#endif
	%newobject Assertion_get;
	LassoNodeList *Assertion;

	/* Constructor, Destructor & Static Methods */
	LassoSamlp2Response();
	~LassoSamlp2Response();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{

/* inherited from StatusResponse */

/* Issuer */

#define LassoSamlp2Response_get_Issuer(self) get_node(LASSO_SAMLP2_STATUS_RESPONSE(self)->Issuer)
#define LassoSamlp2Response_Issuer_get(self) get_node(LASSO_SAMLP2_STATUS_RESPONSE(self)->Issuer)
#define LassoSamlp2Response_set_Issuer(self,value) set_node((gpointer*)&LASSO_SAMLP2_STATUS_RESPONSE(self)->Issuer, (value))
#define LassoSamlp2Response_Issuer_set(self,value) set_node((gpointer*)&LASSO_SAMLP2_STATUS_RESPONSE(self)->Issuer, (value))
                    

/* Extensions */

#define LassoSamlp2Response_get_Extensions(self) get_node(LASSO_SAMLP2_STATUS_RESPONSE(self)->Extensions)
#define LassoSamlp2Response_Extensions_get(self) get_node(LASSO_SAMLP2_STATUS_RESPONSE(self)->Extensions)
#define LassoSamlp2Response_set_Extensions(self,value) set_node((gpointer*)&LASSO_SAMLP2_STATUS_RESPONSE(self)->Extensions, (value))
#define LassoSamlp2Response_Extensions_set(self,value) set_node((gpointer*)&LASSO_SAMLP2_STATUS_RESPONSE(self)->Extensions, (value))
                    

/* Status */

#define LassoSamlp2Response_get_Status(self) get_node(LASSO_SAMLP2_STATUS_RESPONSE(self)->Status)
#define LassoSamlp2Response_Status_get(self) get_node(LASSO_SAMLP2_STATUS_RESPONSE(self)->Status)
#define LassoSamlp2Response_set_Status(self,value) set_node((gpointer*)&LASSO_SAMLP2_STATUS_RESPONSE(self)->Status, (value))
#define LassoSamlp2Response_Status_set(self,value) set_node((gpointer*)&LASSO_SAMLP2_STATUS_RESPONSE(self)->Status, (value))
                    

/* ID */

#define LassoSamlp2Response_get_ID(self) LASSO_SAMLP2_STATUS_RESPONSE(self)->ID
#define LassoSamlp2Response_ID_get(self) LASSO_SAMLP2_STATUS_RESPONSE(self)->ID

#define LassoSamlp2Response_set_ID(self,value) set_string(&LASSO_SAMLP2_STATUS_RESPONSE(self)->ID, (value))
#define LassoSamlp2Response_ID_set(self,value) set_string(&LASSO_SAMLP2_STATUS_RESPONSE(self)->ID, (value))

/* InResponseTo */

#define LassoSamlp2Response_get_InResponseTo(self) LASSO_SAMLP2_STATUS_RESPONSE(self)->InResponseTo
#define LassoSamlp2Response_InResponseTo_get(self) LASSO_SAMLP2_STATUS_RESPONSE(self)->InResponseTo

#define LassoSamlp2Response_set_InResponseTo(self,value) set_string(&LASSO_SAMLP2_STATUS_RESPONSE(self)->InResponseTo, (value))
#define LassoSamlp2Response_InResponseTo_set(self,value) set_string(&LASSO_SAMLP2_STATUS_RESPONSE(self)->InResponseTo, (value))

/* Version */

#define LassoSamlp2Response_get_Version(self) LASSO_SAMLP2_STATUS_RESPONSE(self)->Version
#define LassoSamlp2Response_Version_get(self) LASSO_SAMLP2_STATUS_RESPONSE(self)->Version

#define LassoSamlp2Response_set_Version(self,value) set_string(&LASSO_SAMLP2_STATUS_RESPONSE(self)->Version, (value))
#define LassoSamlp2Response_Version_set(self,value) set_string(&LASSO_SAMLP2_STATUS_RESPONSE(self)->Version, (value))

/* IssueInstant */

#define LassoSamlp2Response_get_IssueInstant(self) LASSO_SAMLP2_STATUS_RESPONSE(self)->IssueInstant
#define LassoSamlp2Response_IssueInstant_get(self) LASSO_SAMLP2_STATUS_RESPONSE(self)->IssueInstant

#define LassoSamlp2Response_set_IssueInstant(self,value) set_string(&LASSO_SAMLP2_STATUS_RESPONSE(self)->IssueInstant, (value))
#define LassoSamlp2Response_IssueInstant_set(self,value) set_string(&LASSO_SAMLP2_STATUS_RESPONSE(self)->IssueInstant, (value))

/* Destination */

#define LassoSamlp2Response_get_Destination(self) LASSO_SAMLP2_STATUS_RESPONSE(self)->Destination
#define LassoSamlp2Response_Destination_get(self) LASSO_SAMLP2_STATUS_RESPONSE(self)->Destination

#define LassoSamlp2Response_set_Destination(self,value) set_string(&LASSO_SAMLP2_STATUS_RESPONSE(self)->Destination, (value))
#define LassoSamlp2Response_Destination_set(self,value) set_string(&LASSO_SAMLP2_STATUS_RESPONSE(self)->Destination, (value))

/* Consent */

#define LassoSamlp2Response_get_Consent(self) LASSO_SAMLP2_STATUS_RESPONSE(self)->Consent
#define LassoSamlp2Response_Consent_get(self) LASSO_SAMLP2_STATUS_RESPONSE(self)->Consent

#define LassoSamlp2Response_set_Consent(self,value) set_string(&LASSO_SAMLP2_STATUS_RESPONSE(self)->Consent, (value))
#define LassoSamlp2Response_Consent_set(self,value) set_string(&LASSO_SAMLP2_STATUS_RESPONSE(self)->Consent, (value))


/* Assertion */

#define LassoSamlp2Response_get_Assertion(self) get_node_list((self)->Assertion)
#define LassoSamlp2Response_Assertion_get(self) get_node_list((self)->Assertion)
#define LassoSamlp2Response_set_Assertion(self, value) set_node_list(&(self)->Assertion, (value))
#define LassoSamlp2Response_Assertion_set(self, value) set_node_list(&(self)->Assertion, (value))


/* Constructors, destructors & static methods implementations */

#define new_LassoSamlp2Response lasso_samlp2_response_new
#define delete_LassoSamlp2Response(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSamlp2Response_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

