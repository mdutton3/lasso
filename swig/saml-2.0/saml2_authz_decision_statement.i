
#ifndef SWIGPHP4
%rename(Saml2AuthzDecisionStatement) LassoSaml2AuthzDecisionStatement;
#endif
typedef struct {
#ifndef SWIGPHP4
	%rename(resource) Resource;
#endif
	char *Resource;
#ifndef SWIGPHP4
	%rename(decision) Decision;
#endif
	char *Decision;
} LassoSaml2AuthzDecisionStatement;
%extend LassoSaml2AuthzDecisionStatement {

#ifndef SWIGPHP4
	%rename(action) Action;
#endif
	%newobject *Action_get;
	LassoSaml2Action *Action;

#ifndef SWIGPHP4
	%rename(evidence) Evidence;
#endif
	%newobject *Evidence_get;
	LassoSaml2Evidence *Evidence;

	/* inherited from Saml2StatementAbstract */

	/* Constructor, Destructor & Static Methods */
	LassoSaml2AuthzDecisionStatement();
	~LassoSaml2AuthzDecisionStatement();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{

/* Action */

#define LassoSaml2AuthzDecisionStatement_get_Action(self) get_node((self)->Action)
#define LassoSaml2AuthzDecisionStatement_Action_get(self) get_node((self)->Action)
#define LassoSaml2AuthzDecisionStatement_set_Action(self,value) set_node((gpointer*)&(self)->Action, (value))
#define LassoSaml2AuthzDecisionStatement_Action_set(self,value) set_node((gpointer*)&(self)->Action, (value))
                    

/* Evidence */

#define LassoSaml2AuthzDecisionStatement_get_Evidence(self) get_node((self)->Evidence)
#define LassoSaml2AuthzDecisionStatement_Evidence_get(self) get_node((self)->Evidence)
#define LassoSaml2AuthzDecisionStatement_set_Evidence(self,value) set_node((gpointer*)&(self)->Evidence, (value))
#define LassoSaml2AuthzDecisionStatement_Evidence_set(self,value) set_node((gpointer*)&(self)->Evidence, (value))
                    


/* Constructors, destructors & static methods implementations */

#define new_LassoSaml2AuthzDecisionStatement lasso_saml2_authz_decision_statement_new
#define delete_LassoSaml2AuthzDecisionStatement(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSaml2AuthzDecisionStatement_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

