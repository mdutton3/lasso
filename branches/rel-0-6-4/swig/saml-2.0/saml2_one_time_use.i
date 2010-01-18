
#ifndef SWIGPHP4
%rename(Saml2OneTimeUse) LassoSaml2OneTimeUse;
#endif
typedef struct {
} LassoSaml2OneTimeUse;
%extend LassoSaml2OneTimeUse {

	/* inherited from Saml2ConditionAbstract */

	/* Constructor, Destructor & Static Methods */
	LassoSaml2OneTimeUse();
	~LassoSaml2OneTimeUse();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{


/* Constructors, destructors & static methods implementations */

#define new_LassoSaml2OneTimeUse lasso_saml2_one_time_use_new
#define delete_LassoSaml2OneTimeUse(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSaml2OneTimeUse_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

