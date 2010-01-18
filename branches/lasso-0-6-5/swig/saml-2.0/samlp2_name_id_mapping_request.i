
#ifndef SWIGPHP4
%rename(Samlp2NameIDMappingRequest) LassoSamlp2NameIDMappingRequest;
#endif
typedef struct {
} LassoSamlp2NameIDMappingRequest;
%extend LassoSamlp2NameIDMappingRequest {

#ifndef SWIGPHP4
	%rename(baseID) BaseID;
#endif
	%newobject *BaseID_get;
	LassoSaml2BaseIDAbstract *BaseID;

#ifndef SWIGPHP4
	%rename(nameID) NameID;
#endif
	%newobject *NameID_get;
	LassoSaml2NameID *NameID;

#ifndef SWIGPHP4
	%rename(encryptedID) EncryptedID;
#endif
	%newobject *EncryptedID_get;
	LassoSaml2EncryptedElement *EncryptedID;

#ifndef SWIGPHP4
	%rename(nameIDPolicy) NameIDPolicy;
#endif
	%newobject *NameIDPolicy_get;
	LassoSamlp2NameIDPolicy *NameIDPolicy;

	/* inherited from Samlp2RequestAbstract */
#ifndef SWIGPHP4
	%rename(issuer) *Issuer;
#endif
	%newobject *Issuer_get;
	LassoSaml2NameID *Issuer;

#ifndef SWIGPHP4
	%rename(extensions) *Extensions;
#endif
	%newobject *Extensions_get;
	LassoSamlp2Extensions *Extensions;

#ifndef SWIGPHP4
	%rename(iD) *ID;
#endif
	char *ID;
#ifndef SWIGPHP4
	%rename(version) *Version;
#endif
	char *Version;
#ifndef SWIGPHP4
	%rename(issueInstant) *IssueInstant;
#endif
	char *IssueInstant;
#ifndef SWIGPHP4
	%rename(destination) *Destination;
#endif
	char *Destination;
#ifndef SWIGPHP4
	%rename(consent) *Consent;
#endif
	char *Consent;

	/* Constructor, Destructor & Static Methods */
	LassoSamlp2NameIDMappingRequest();
	~LassoSamlp2NameIDMappingRequest();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{

/* BaseID */

#define LassoSamlp2NameIDMappingRequest_get_BaseID(self) get_node((self)->BaseID)
#define LassoSamlp2NameIDMappingRequest_BaseID_get(self) get_node((self)->BaseID)
#define LassoSamlp2NameIDMappingRequest_set_BaseID(self,value) set_node((gpointer*)&(self)->BaseID, (value))
#define LassoSamlp2NameIDMappingRequest_BaseID_set(self,value) set_node((gpointer*)&(self)->BaseID, (value))
                    

/* NameID */

#define LassoSamlp2NameIDMappingRequest_get_NameID(self) get_node((self)->NameID)
#define LassoSamlp2NameIDMappingRequest_NameID_get(self) get_node((self)->NameID)
#define LassoSamlp2NameIDMappingRequest_set_NameID(self,value) set_node((gpointer*)&(self)->NameID, (value))
#define LassoSamlp2NameIDMappingRequest_NameID_set(self,value) set_node((gpointer*)&(self)->NameID, (value))
                    

/* EncryptedID */

#define LassoSamlp2NameIDMappingRequest_get_EncryptedID(self) get_node((self)->EncryptedID)
#define LassoSamlp2NameIDMappingRequest_EncryptedID_get(self) get_node((self)->EncryptedID)
#define LassoSamlp2NameIDMappingRequest_set_EncryptedID(self,value) set_node((gpointer*)&(self)->EncryptedID, (value))
#define LassoSamlp2NameIDMappingRequest_EncryptedID_set(self,value) set_node((gpointer*)&(self)->EncryptedID, (value))
                    

/* NameIDPolicy */

#define LassoSamlp2NameIDMappingRequest_get_NameIDPolicy(self) get_node((self)->NameIDPolicy)
#define LassoSamlp2NameIDMappingRequest_NameIDPolicy_get(self) get_node((self)->NameIDPolicy)
#define LassoSamlp2NameIDMappingRequest_set_NameIDPolicy(self,value) set_node((gpointer*)&(self)->NameIDPolicy, (value))
#define LassoSamlp2NameIDMappingRequest_NameIDPolicy_set(self,value) set_node((gpointer*)&(self)->NameIDPolicy, (value))
                    

/* inherited from RequestAbstract */

/* Issuer */

#define LassoSamlp2NameIDMappingRequest_get_Issuer(self) get_node(LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Issuer)
#define LassoSamlp2NameIDMappingRequest_Issuer_get(self) get_node(LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Issuer)
#define LassoSamlp2NameIDMappingRequest_set_Issuer(self,value) set_node((gpointer*)&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Issuer, (value))
#define LassoSamlp2NameIDMappingRequest_Issuer_set(self,value) set_node((gpointer*)&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Issuer, (value))
                    

/* Extensions */

#define LassoSamlp2NameIDMappingRequest_get_Extensions(self) get_node(LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Extensions)
#define LassoSamlp2NameIDMappingRequest_Extensions_get(self) get_node(LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Extensions)
#define LassoSamlp2NameIDMappingRequest_set_Extensions(self,value) set_node((gpointer*)&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Extensions, (value))
#define LassoSamlp2NameIDMappingRequest_Extensions_set(self,value) set_node((gpointer*)&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Extensions, (value))
                    

/* ID */

#define LassoSamlp2NameIDMappingRequest_get_ID(self) LASSO_SAMLP2_REQUEST_ABSTRACT(self)->ID
#define LassoSamlp2NameIDMappingRequest_ID_get(self) LASSO_SAMLP2_REQUEST_ABSTRACT(self)->ID

#define LassoSamlp2NameIDMappingRequest_set_ID(self,value) set_string(&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->ID, (value))
#define LassoSamlp2NameIDMappingRequest_ID_set(self,value) set_string(&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->ID, (value))

/* Version */

#define LassoSamlp2NameIDMappingRequest_get_Version(self) LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Version
#define LassoSamlp2NameIDMappingRequest_Version_get(self) LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Version

#define LassoSamlp2NameIDMappingRequest_set_Version(self,value) set_string(&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Version, (value))
#define LassoSamlp2NameIDMappingRequest_Version_set(self,value) set_string(&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Version, (value))

/* IssueInstant */

#define LassoSamlp2NameIDMappingRequest_get_IssueInstant(self) LASSO_SAMLP2_REQUEST_ABSTRACT(self)->IssueInstant
#define LassoSamlp2NameIDMappingRequest_IssueInstant_get(self) LASSO_SAMLP2_REQUEST_ABSTRACT(self)->IssueInstant

#define LassoSamlp2NameIDMappingRequest_set_IssueInstant(self,value) set_string(&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->IssueInstant, (value))
#define LassoSamlp2NameIDMappingRequest_IssueInstant_set(self,value) set_string(&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->IssueInstant, (value))

/* Destination */

#define LassoSamlp2NameIDMappingRequest_get_Destination(self) LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Destination
#define LassoSamlp2NameIDMappingRequest_Destination_get(self) LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Destination

#define LassoSamlp2NameIDMappingRequest_set_Destination(self,value) set_string(&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Destination, (value))
#define LassoSamlp2NameIDMappingRequest_Destination_set(self,value) set_string(&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Destination, (value))

/* Consent */

#define LassoSamlp2NameIDMappingRequest_get_Consent(self) LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Consent
#define LassoSamlp2NameIDMappingRequest_Consent_get(self) LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Consent

#define LassoSamlp2NameIDMappingRequest_set_Consent(self,value) set_string(&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Consent, (value))
#define LassoSamlp2NameIDMappingRequest_Consent_set(self,value) set_string(&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Consent, (value))


/* Constructors, destructors & static methods implementations */

#define new_LassoSamlp2NameIDMappingRequest lasso_samlp2_name_id_mapping_request_new
#define delete_LassoSamlp2NameIDMappingRequest(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSamlp2NameIDMappingRequest_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

