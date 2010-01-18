
#ifndef SWIGPHP4
%rename(Samlp2Extensions) LassoSamlp2Extensions;
#endif
typedef struct {
} LassoSamlp2Extensions;
%extend LassoSamlp2Extensions {


	/* Constructor, Destructor & Static Methods */
	LassoSamlp2Extensions();
	~LassoSamlp2Extensions();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{


/* Constructors, destructors & static methods implementations */

#define new_LassoSamlp2Extensions lasso_samlp2_extensions_new
#define delete_LassoSamlp2Extensions(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSamlp2Extensions_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

