
#ifndef SWIGPHP4
%rename(Samlp2StatusResponse) LassoSamlp2StatusResponse;
#endif
typedef struct {
	char *ID;
	char *InResponseTo;
	char *Version;
	char *IssueInstant;
	char *Destination;
	char *Consent;
} LassoSamlp2StatusResponse;
%extend LassoSamlp2StatusResponse {

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


	/* Constructor, Destructor & Static Methods */
	LassoSamlp2StatusResponse();
	~LassoSamlp2StatusResponse();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{

/* Issuer */

#define LassoSamlp2StatusResponse_get_Issuer(self) get_node((self)->Issuer)
#define LassoSamlp2StatusResponse_Issuer_get(self) get_node((self)->Issuer)
#define LassoSamlp2StatusResponse_set_Issuer(self,value) set_node((gpointer*)&(self)->Issuer, (value))
#define LassoSamlp2StatusResponse_Issuer_set(self,value) set_node((gpointer*)&(self)->Issuer, (value))
                    

/* Extensions */

#define LassoSamlp2StatusResponse_get_Extensions(self) get_node((self)->Extensions)
#define LassoSamlp2StatusResponse_Extensions_get(self) get_node((self)->Extensions)
#define LassoSamlp2StatusResponse_set_Extensions(self,value) set_node((gpointer*)&(self)->Extensions, (value))
#define LassoSamlp2StatusResponse_Extensions_set(self,value) set_node((gpointer*)&(self)->Extensions, (value))
                    

/* Status */

#define LassoSamlp2StatusResponse_get_Status(self) get_node((self)->Status)
#define LassoSamlp2StatusResponse_Status_get(self) get_node((self)->Status)
#define LassoSamlp2StatusResponse_set_Status(self,value) set_node((gpointer*)&(self)->Status, (value))
#define LassoSamlp2StatusResponse_Status_set(self,value) set_node((gpointer*)&(self)->Status, (value))
                    


/* Constructors, destructors & static methods implementations */

#define new_LassoSamlp2StatusResponse lasso_samlp2_status_response_new
#define delete_LassoSamlp2StatusResponse(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSamlp2StatusResponse_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

