
#ifndef SWIG_PHP_RENAMES
%rename(Saml2AuthnContext) LassoSaml2AuthnContext;
#endif
typedef struct {
#ifndef SWIG_PHP_RENAMES
	%rename(authnContextClassRef) AuthnContextClassRef;
#endif
	char *AuthnContextClassRef;
#ifndef SWIG_PHP_RENAMES
	%rename(authnContextDeclRef) AuthnContextDeclRef;
#endif
	char *AuthnContextDeclRef;
#ifndef SWIG_PHP_RENAMES
	%rename(authenticationAuthority) AuthenticationAuthority;
#endif
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

