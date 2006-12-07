
#ifndef SWIGPHP4
%rename(Saml2SubjectLocality) LassoSaml2SubjectLocality;
#endif
typedef struct {
#ifndef SWIGPHP4
	%rename(address) Address;
#endif
	char *Address;
#ifndef SWIGPHP4
	%rename(dnsName) DNSName;
#endif
	char *DNSName;
} LassoSaml2SubjectLocality;
%extend LassoSaml2SubjectLocality {


	/* Constructor, Destructor & Static Methods */
	LassoSaml2SubjectLocality();
	~LassoSaml2SubjectLocality();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{


/* Constructors, destructors & static methods implementations */

#define new_LassoSaml2SubjectLocality lasso_saml2_subject_locality_new
#define delete_LassoSaml2SubjectLocality(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSaml2SubjectLocality_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

