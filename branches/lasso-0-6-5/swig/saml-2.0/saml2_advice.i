
#ifndef SWIGPHP4
%rename(Saml2Advice) LassoSaml2Advice;
#endif
typedef struct {
} LassoSaml2Advice;
%extend LassoSaml2Advice {


	/* Constructor, Destructor & Static Methods */
	LassoSaml2Advice();
	~LassoSaml2Advice();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{


/* Constructors, destructors & static methods implementations */

#define new_LassoSaml2Advice lasso_saml2_advice_new
#define delete_LassoSaml2Advice(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSaml2Advice_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

