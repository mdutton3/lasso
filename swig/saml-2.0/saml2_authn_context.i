
#ifndef SWIGPHP4
%rename(Saml2AuthnContext) LassoSaml2AuthnContext;
#endif
typedef struct {
	char *AuthnContextClassRef;
	char *AuthnContextDeclRef;
	char *AuthenticatingAuthority;
} LassoSaml2AuthnContext;
%extend LassoSaml2AuthnContext {


	/* Constructor, Destructor & Static Methods */
	LassoSaml2AuthnContext();
	~LassoSaml2AuthnContext();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{


/* Constructors, destructors & static methods implementations */

#define new_LassoSaml2AuthnContext lasso_saml2_authn_context_new
#define delete_LassoSaml2AuthnContext(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSaml2AuthnContext_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

