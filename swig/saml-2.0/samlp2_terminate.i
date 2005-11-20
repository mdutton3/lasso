
#ifndef SWIGPHP4
%rename(Samlp2Terminate) LassoSamlp2Terminate;
#endif
typedef struct {
} LassoSamlp2Terminate;
%extend LassoSamlp2Terminate {


	/* Constructor, Destructor & Static Methods */
	LassoSamlp2Terminate();
	~LassoSamlp2Terminate();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{


/* Constructors, destructors & static methods implementations */

#define new_LassoSamlp2Terminate lasso_samlp2_terminate_new
#define delete_LassoSamlp2Terminate(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSamlp2Terminate_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

