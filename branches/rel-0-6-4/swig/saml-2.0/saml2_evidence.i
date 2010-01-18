
#ifndef SWIGPHP4
%rename(Saml2Evidence) LassoSaml2Evidence;
#endif
typedef struct {
} LassoSaml2Evidence;
%extend LassoSaml2Evidence {


	/* Constructor, Destructor & Static Methods */
	LassoSaml2Evidence();
	~LassoSaml2Evidence();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{


/* Constructors, destructors & static methods implementations */

#define new_LassoSaml2Evidence lasso_saml2_evidence_new
#define delete_LassoSaml2Evidence(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSaml2Evidence_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

