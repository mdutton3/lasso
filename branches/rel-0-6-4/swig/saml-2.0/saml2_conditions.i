
#ifndef SWIGPHP4
%rename(Saml2Conditions) LassoSaml2Conditions;
#endif
typedef struct {
	char *NotBefore;
	char *NotOnOrAfter;
} LassoSaml2Conditions;
%extend LassoSaml2Conditions {


	/* Constructor, Destructor & Static Methods */
	LassoSaml2Conditions();
	~LassoSaml2Conditions();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{


/* Constructors, destructors & static methods implementations */

#define new_LassoSaml2Conditions lasso_saml2_conditions_new
#define delete_LassoSaml2Conditions(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSaml2Conditions_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

