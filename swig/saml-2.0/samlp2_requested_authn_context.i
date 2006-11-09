
#ifndef SWIGPHP4
%rename(Samlp2RequestedAuthnContext) LassoSamlp2RequestedAuthnContext;
#endif
typedef struct {
#ifndef SWIGPHP4
	%rename(comparison) Comparison;
#endif
	char *Comparison;
} LassoSamlp2RequestedAuthnContext;
%extend LassoSamlp2RequestedAuthnContext {
	%newobject authnContextClassRef_get;
	LassoStringList *authnContextClassRef;

	%newobject authnContextDeclRef_get;
	LassoStringList *authnContextDeclRef;

	/* Constructor, Destructor & Static Methods */
	LassoSamlp2RequestedAuthnContext();
	~LassoSamlp2RequestedAuthnContext();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{

/* authnContextClassRef */
#define LassoSamlp2RequestedAuthnContext_get_authnContextClassRef(self) get_string_list((self)->AuthnContextClassRef)
#define LassoSamlp2RequestedAuthnContext_authnContextClassRef_get(self) get_string_list((self)->AuthnContextClassRef)
#define LassoSamlp2RequestedAuthnContext_set_authnContextClassRef(self, value) set_string_list(&(self)->AuthnContextClassRef, (value))
#define LassoSamlp2RequestedAuthnContext_authnContextClassRef_set(self, value) set_string_list(&(self)->AuthnContextClassRef, (value))

/* authnContextDeclRef */
#define LassoSamlp2RequestedAuthnContext_get_authnContextDeclRef(self) get_string_list((self)->AuthnContextDeclRef)
#define LassoSamlp2RequestedAuthnContext_authnContextDeclRef_get(self) get_string_list((self)->AuthnContextDeclRef)
#define LassoSamlp2RequestedAuthnContext_set_authnContextDeclRef(self, value) set_string_list(&(self)->AuthnContextDeclRef, (value))
#define LassoSamlp2RequestedAuthnContext_authnContextDeclRef_set(self, value) set_string_list(&(self)->AuthnContextDeclRef, (value))


/* Constructors, destructors & static methods implementations */

#define new_LassoSamlp2RequestedAuthnContext lasso_samlp2_requested_authn_context_new
#define delete_LassoSamlp2RequestedAuthnContext(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSamlp2RequestedAuthnContext_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

