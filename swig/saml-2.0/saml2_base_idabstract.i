
#ifndef SWIGPHP4
%rename(Saml2BaseIDAbstract) LassoSaml2BaseIDAbstract;
#endif
typedef struct {
	char *NameQualifier;
	char *SPNameQualifier;
} LassoSaml2BaseIDAbstract;
%extend LassoSaml2BaseIDAbstract {


	/* Constructor, Destructor & Static Methods */
	LassoSaml2BaseIDAbstract();
	~LassoSaml2BaseIDAbstract();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{


/* Constructors, destructors & static methods implementations */

#define new_LassoSaml2BaseIDAbstract lasso_saml2_base_idabstract_new
#define delete_LassoSaml2BaseIDAbstract(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSaml2BaseIDAbstract_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

