
#ifndef SWIGPHP4
%rename(Saml2ProxyRestriction) LassoSaml2ProxyRestriction;
#endif
typedef struct {
	char *Audience;
	char *Count;
} LassoSaml2ProxyRestriction;
%extend LassoSaml2ProxyRestriction {

	/* inherited from Saml2ConditionAbstract */

	/* Constructor, Destructor & Static Methods */
	LassoSaml2ProxyRestriction();
	~LassoSaml2ProxyRestriction();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{


/* Constructors, destructors & static methods implementations */

#define new_LassoSaml2ProxyRestriction lasso_saml2_proxy_restriction_new
#define delete_LassoSaml2ProxyRestriction(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSaml2ProxyRestriction_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

