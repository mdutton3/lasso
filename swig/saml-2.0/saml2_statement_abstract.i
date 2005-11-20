
#ifndef SWIGPHP4
%rename(Saml2StatementAbstract) LassoSaml2StatementAbstract;
#endif
typedef struct {
} LassoSaml2StatementAbstract;
%extend LassoSaml2StatementAbstract {


	/* Constructor, Destructor & Static Methods */
	LassoSaml2StatementAbstract();
	~LassoSaml2StatementAbstract();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{


/* Constructors, destructors & static methods implementations */

#define new_LassoSaml2StatementAbstract lasso_saml2_statement_abstract_new
#define delete_LassoSaml2StatementAbstract(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSaml2StatementAbstract_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

