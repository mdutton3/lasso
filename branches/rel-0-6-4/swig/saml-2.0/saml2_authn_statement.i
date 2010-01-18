
#ifndef SWIGPHP4
%rename(Saml2AuthnStatement) LassoSaml2AuthnStatement;
#endif
typedef struct {
	char *AuthnInstant;
	char *SessionIndex;
	char *SessionNotOnOrAfter;
} LassoSaml2AuthnStatement;
%extend LassoSaml2AuthnStatement {

#ifndef SWIGPHP4
	%rename(subjectLocality) SubjectLocality;
#endif
	%newobject *SubjectLocality_get;
	LassoSaml2SubjectLocality *SubjectLocality;

#ifndef SWIGPHP4
	%rename(authnContext) AuthnContext;
#endif
	%newobject *AuthnContext_get;
	LassoSaml2AuthnContext *AuthnContext;

	/* inherited from Saml2StatementAbstract */

	/* Constructor, Destructor & Static Methods */
	LassoSaml2AuthnStatement();
	~LassoSaml2AuthnStatement();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{

/* SubjectLocality */

#define LassoSaml2AuthnStatement_get_SubjectLocality(self) get_node((self)->SubjectLocality)
#define LassoSaml2AuthnStatement_SubjectLocality_get(self) get_node((self)->SubjectLocality)
#define LassoSaml2AuthnStatement_set_SubjectLocality(self,value) set_node((gpointer*)&(self)->SubjectLocality, (value))
#define LassoSaml2AuthnStatement_SubjectLocality_set(self,value) set_node((gpointer*)&(self)->SubjectLocality, (value))
                    

/* AuthnContext */

#define LassoSaml2AuthnStatement_get_AuthnContext(self) get_node((self)->AuthnContext)
#define LassoSaml2AuthnStatement_AuthnContext_get(self) get_node((self)->AuthnContext)
#define LassoSaml2AuthnStatement_set_AuthnContext(self,value) set_node((gpointer*)&(self)->AuthnContext, (value))
#define LassoSaml2AuthnStatement_AuthnContext_set(self,value) set_node((gpointer*)&(self)->AuthnContext, (value))
                    


/* Constructors, destructors & static methods implementations */

#define new_LassoSaml2AuthnStatement lasso_saml2_authn_statement_new
#define delete_LassoSaml2AuthnStatement(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSaml2AuthnStatement_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

