
#ifndef SWIGPHP4
%rename(Saml2Action) LassoSaml2Action;
#endif
typedef struct {
	char *content;
	char *Namespace;
} LassoSaml2Action;
%extend LassoSaml2Action {


	/* Constructor, Destructor & Static Methods */
	LassoSaml2Action();
	~LassoSaml2Action();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{


/* Constructors, destructors & static methods implementations */

#define new_LassoSaml2Action lasso_saml2_action_new
#define delete_LassoSaml2Action(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSaml2Action_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

