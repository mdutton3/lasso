
#ifndef SWIGPHP4
%rename(Samlp2RequestedAuthnContext) LassoSamlp2RequestedAuthnContext;
#endif
typedef struct {
	char *AuthnContextClassRef;
	char *AuthnContextDeclRef;
	char *Comparison;
} LassoSamlp2RequestedAuthnContext;
%extend LassoSamlp2RequestedAuthnContext {


	/* Constructor, Destructor & Static Methods */
	LassoSamlp2RequestedAuthnContext();
	~LassoSamlp2RequestedAuthnContext();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{


/* Constructors, destructors & static methods implementations */

#define new_LassoSamlp2RequestedAuthnContext lasso_samlp2_requested_authn_context_new
#define delete_LassoSamlp2RequestedAuthnContext(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSamlp2RequestedAuthnContext_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

