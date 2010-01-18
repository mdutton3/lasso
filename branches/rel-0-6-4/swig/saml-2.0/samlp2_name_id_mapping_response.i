
#ifndef SWIGPHP4
%rename(Samlp2NameIDMappingResponse) LassoSamlp2NameIDMappingResponse;
#endif
typedef struct {
} LassoSamlp2NameIDMappingResponse;
%extend LassoSamlp2NameIDMappingResponse {

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

	/* inherited from Samlp2StatusResponse */
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
	%rename(status) *Status;
#endif
	%newobject *Status_get;
	LassoSamlp2Status *Status;

#ifndef SWIGPHP4
	%rename(iD) *ID;
#endif
	char *ID;
#ifndef SWIGPHP4
	%rename(inResponseTo) *InResponseTo;
#endif
	char *InResponseTo;
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
	LassoSamlp2NameIDMappingResponse();
	~LassoSamlp2NameIDMappingResponse();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{

/* NameID */

#define LassoSamlp2NameIDMappingResponse_get_NameID(self) get_node((self)->NameID)
#define LassoSamlp2NameIDMappingResponse_NameID_get(self) get_node((self)->NameID)
#define LassoSamlp2NameIDMappingResponse_set_NameID(self,value) set_node((gpointer*)&(self)->NameID, (value))
#define LassoSamlp2NameIDMappingResponse_NameID_set(self,value) set_node((gpointer*)&(self)->NameID, (value))
                    

/* EncryptedID */

#define LassoSamlp2NameIDMappingResponse_get_EncryptedID(self) get_node((self)->EncryptedID)
#define LassoSamlp2NameIDMappingResponse_EncryptedID_get(self) get_node((self)->EncryptedID)
#define LassoSamlp2NameIDMappingResponse_set_EncryptedID(self,value) set_node((gpointer*)&(self)->EncryptedID, (value))
#define LassoSamlp2NameIDMappingResponse_EncryptedID_set(self,value) set_node((gpointer*)&(self)->EncryptedID, (value))
                    

/* inherited from StatusResponse */

/* Issuer */

#define LassoSamlp2NameIDMappingResponse_get_Issuer(self) get_node(LASSO_SAMLP2_STATUS_RESPONSE(self)->Issuer)
#define LassoSamlp2NameIDMappingResponse_Issuer_get(self) get_node(LASSO_SAMLP2_STATUS_RESPONSE(self)->Issuer)
#define LassoSamlp2NameIDMappingResponse_set_Issuer(self,value) set_node((gpointer*)&LASSO_SAMLP2_STATUS_RESPONSE(self)->Issuer, (value))
#define LassoSamlp2NameIDMappingResponse_Issuer_set(self,value) set_node((gpointer*)&LASSO_SAMLP2_STATUS_RESPONSE(self)->Issuer, (value))
                    

/* Extensions */

#define LassoSamlp2NameIDMappingResponse_get_Extensions(self) get_node(LASSO_SAMLP2_STATUS_RESPONSE(self)->Extensions)
#define LassoSamlp2NameIDMappingResponse_Extensions_get(self) get_node(LASSO_SAMLP2_STATUS_RESPONSE(self)->Extensions)
#define LassoSamlp2NameIDMappingResponse_set_Extensions(self,value) set_node((gpointer*)&LASSO_SAMLP2_STATUS_RESPONSE(self)->Extensions, (value))
#define LassoSamlp2NameIDMappingResponse_Extensions_set(self,value) set_node((gpointer*)&LASSO_SAMLP2_STATUS_RESPONSE(self)->Extensions, (value))
                    

/* Status */

#define LassoSamlp2NameIDMappingResponse_get_Status(self) get_node(LASSO_SAMLP2_STATUS_RESPONSE(self)->Status)
#define LassoSamlp2NameIDMappingResponse_Status_get(self) get_node(LASSO_SAMLP2_STATUS_RESPONSE(self)->Status)
#define LassoSamlp2NameIDMappingResponse_set_Status(self,value) set_node((gpointer*)&LASSO_SAMLP2_STATUS_RESPONSE(self)->Status, (value))
#define LassoSamlp2NameIDMappingResponse_Status_set(self,value) set_node((gpointer*)&LASSO_SAMLP2_STATUS_RESPONSE(self)->Status, (value))
                    

/* ID */

#define LassoSamlp2NameIDMappingResponse_get_ID(self) LASSO_SAMLP2_STATUS_RESPONSE(self)->ID
#define LassoSamlp2NameIDMappingResponse_ID_get(self) LASSO_SAMLP2_STATUS_RESPONSE(self)->ID

#define LassoSamlp2NameIDMappingResponse_set_ID(self,value) set_string(&LASSO_SAMLP2_STATUS_RESPONSE(self)->ID, (value))
#define LassoSamlp2NameIDMappingResponse_ID_set(self,value) set_string(&LASSO_SAMLP2_STATUS_RESPONSE(self)->ID, (value))

/* InResponseTo */

#define LassoSamlp2NameIDMappingResponse_get_InResponseTo(self) LASSO_SAMLP2_STATUS_RESPONSE(self)->InResponseTo
#define LassoSamlp2NameIDMappingResponse_InResponseTo_get(self) LASSO_SAMLP2_STATUS_RESPONSE(self)->InResponseTo

#define LassoSamlp2NameIDMappingResponse_set_InResponseTo(self,value) set_string(&LASSO_SAMLP2_STATUS_RESPONSE(self)->InResponseTo, (value))
#define LassoSamlp2NameIDMappingResponse_InResponseTo_set(self,value) set_string(&LASSO_SAMLP2_STATUS_RESPONSE(self)->InResponseTo, (value))

/* Version */

#define LassoSamlp2NameIDMappingResponse_get_Version(self) LASSO_SAMLP2_STATUS_RESPONSE(self)->Version
#define LassoSamlp2NameIDMappingResponse_Version_get(self) LASSO_SAMLP2_STATUS_RESPONSE(self)->Version

#define LassoSamlp2NameIDMappingResponse_set_Version(self,value) set_string(&LASSO_SAMLP2_STATUS_RESPONSE(self)->Version, (value))
#define LassoSamlp2NameIDMappingResponse_Version_set(self,value) set_string(&LASSO_SAMLP2_STATUS_RESPONSE(self)->Version, (value))

/* IssueInstant */

#define LassoSamlp2NameIDMappingResponse_get_IssueInstant(self) LASSO_SAMLP2_STATUS_RESPONSE(self)->IssueInstant
#define LassoSamlp2NameIDMappingResponse_IssueInstant_get(self) LASSO_SAMLP2_STATUS_RESPONSE(self)->IssueInstant

#define LassoSamlp2NameIDMappingResponse_set_IssueInstant(self,value) set_string(&LASSO_SAMLP2_STATUS_RESPONSE(self)->IssueInstant, (value))
#define LassoSamlp2NameIDMappingResponse_IssueInstant_set(self,value) set_string(&LASSO_SAMLP2_STATUS_RESPONSE(self)->IssueInstant, (value))

/* Destination */

#define LassoSamlp2NameIDMappingResponse_get_Destination(self) LASSO_SAMLP2_STATUS_RESPONSE(self)->Destination
#define LassoSamlp2NameIDMappingResponse_Destination_get(self) LASSO_SAMLP2_STATUS_RESPONSE(self)->Destination

#define LassoSamlp2NameIDMappingResponse_set_Destination(self,value) set_string(&LASSO_SAMLP2_STATUS_RESPONSE(self)->Destination, (value))
#define LassoSamlp2NameIDMappingResponse_Destination_set(self,value) set_string(&LASSO_SAMLP2_STATUS_RESPONSE(self)->Destination, (value))

/* Consent */

#define LassoSamlp2NameIDMappingResponse_get_Consent(self) LASSO_SAMLP2_STATUS_RESPONSE(self)->Consent
#define LassoSamlp2NameIDMappingResponse_Consent_get(self) LASSO_SAMLP2_STATUS_RESPONSE(self)->Consent

#define LassoSamlp2NameIDMappingResponse_set_Consent(self,value) set_string(&LASSO_SAMLP2_STATUS_RESPONSE(self)->Consent, (value))
#define LassoSamlp2NameIDMappingResponse_Consent_set(self,value) set_string(&LASSO_SAMLP2_STATUS_RESPONSE(self)->Consent, (value))


/* Constructors, destructors & static methods implementations */

#define new_LassoSamlp2NameIDMappingResponse lasso_samlp2_name_id_mapping_response_new
#define delete_LassoSamlp2NameIDMappingResponse(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSamlp2NameIDMappingResponse_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

