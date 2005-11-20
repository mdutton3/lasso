
#ifndef SWIGPHP4
%rename(Saml2AttributeStatement) LassoSaml2AttributeStatement;
#endif
typedef struct {
} LassoSaml2AttributeStatement;
%extend LassoSaml2AttributeStatement {

	/* inherited from Saml2StatementAbstract */

	/* Constructor, Destructor & Static Methods */
	LassoSaml2AttributeStatement();
	~LassoSaml2AttributeStatement();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{


/* Constructors, destructors & static methods implementations */

#define new_LassoSaml2AttributeStatement lasso_saml2_attribute_statement_new
#define delete_LassoSaml2AttributeStatement(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSaml2AttributeStatement_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

