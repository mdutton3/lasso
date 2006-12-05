
#ifndef SWIGPHP4
%rename(Samlp2RequestAbstract) LassoSamlp2RequestAbstract;
#endif
typedef struct {
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
} LassoSamlp2RequestAbstract;
%extend LassoSamlp2RequestAbstract {

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


	/* Constructor, Destructor & Static Methods */
	LassoSamlp2RequestAbstract();
	~LassoSamlp2RequestAbstract();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{

/* Issuer */

#define LassoSamlp2RequestAbstract_get_Issuer(self) get_node((self)->Issuer)
#define LassoSamlp2RequestAbstract_Issuer_get(self) get_node((self)->Issuer)
#define LassoSamlp2RequestAbstract_set_Issuer(self,value) set_node((gpointer*)&(self)->Issuer, (value))
#define LassoSamlp2RequestAbstract_Issuer_set(self,value) set_node((gpointer*)&(self)->Issuer, (value))
                    

/* Extensions */

#define LassoSamlp2RequestAbstract_get_Extensions(self) get_node((self)->Extensions)
#define LassoSamlp2RequestAbstract_Extensions_get(self) get_node((self)->Extensions)
#define LassoSamlp2RequestAbstract_set_Extensions(self,value) set_node((gpointer*)&(self)->Extensions, (value))
#define LassoSamlp2RequestAbstract_Extensions_set(self,value) set_node((gpointer*)&(self)->Extensions, (value))
                    


/* Constructors, destructors & static methods implementations */

#define new_LassoSamlp2RequestAbstract lasso_samlp2_request_abstract_new
#define delete_LassoSamlp2RequestAbstract(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSamlp2RequestAbstract_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

