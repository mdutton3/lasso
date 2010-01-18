
#ifndef SWIGPHP4
%rename(Saml2ConditionAbstract) LassoSaml2ConditionAbstract;
#endif
typedef struct {
} LassoSaml2ConditionAbstract;
%extend LassoSaml2ConditionAbstract {


	/* Constructor, Destructor & Static Methods */
	LassoSaml2ConditionAbstract();
	~LassoSaml2ConditionAbstract();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{


/* Constructors, destructors & static methods implementations */

#define new_LassoSaml2ConditionAbstract lasso_saml2_condition_abstract_new
#define delete_LassoSaml2ConditionAbstract(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSaml2ConditionAbstract_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

