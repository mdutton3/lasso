
#ifndef SWIGPHP4
%rename(Saml2Assertion) LassoSaml2Assertion;
#endif
typedef struct {
	char *Version;
	char *ID;
	char *IssueInstant;
} LassoSaml2Assertion;
%extend LassoSaml2Assertion {

#ifndef SWIGPHP4
	%rename(issuer) Issuer;
#endif
	%newobject *Issuer_get;
	LassoSaml2NameID *Issuer;

#ifndef SWIGPHP4
	%rename(subject) Subject;
#endif
	%newobject *Subject_get;
	LassoSaml2Subject *Subject;

#ifndef SWIGPHP4
	%rename(conditions) Conditions;
#endif
	%newobject *Conditions_get;
	LassoSaml2Conditions *Conditions;

#ifndef SWIGPHP4
	%rename(advice) Advice;
#endif
	%newobject *Advice_get;
	LassoSaml2Advice *Advice;


	/* Constructor, Destructor & Static Methods */
	LassoSaml2Assertion();
	~LassoSaml2Assertion();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{

/* Issuer */

#define LassoSaml2Assertion_get_Issuer(self) get_node((self)->Issuer)
#define LassoSaml2Assertion_Issuer_get(self) get_node((self)->Issuer)
#define LassoSaml2Assertion_set_Issuer(self,value) set_node((gpointer*)&(self)->Issuer, (value))
#define LassoSaml2Assertion_Issuer_set(self,value) set_node((gpointer*)&(self)->Issuer, (value))
                    

/* Subject */

#define LassoSaml2Assertion_get_Subject(self) get_node((self)->Subject)
#define LassoSaml2Assertion_Subject_get(self) get_node((self)->Subject)
#define LassoSaml2Assertion_set_Subject(self,value) set_node((gpointer*)&(self)->Subject, (value))
#define LassoSaml2Assertion_Subject_set(self,value) set_node((gpointer*)&(self)->Subject, (value))
                    

/* Conditions */

#define LassoSaml2Assertion_get_Conditions(self) get_node((self)->Conditions)
#define LassoSaml2Assertion_Conditions_get(self) get_node((self)->Conditions)
#define LassoSaml2Assertion_set_Conditions(self,value) set_node((gpointer*)&(self)->Conditions, (value))
#define LassoSaml2Assertion_Conditions_set(self,value) set_node((gpointer*)&(self)->Conditions, (value))
                    

/* Advice */

#define LassoSaml2Assertion_get_Advice(self) get_node((self)->Advice)
#define LassoSaml2Assertion_Advice_get(self) get_node((self)->Advice)
#define LassoSaml2Assertion_set_Advice(self,value) set_node((gpointer*)&(self)->Advice, (value))
#define LassoSaml2Assertion_Advice_set(self,value) set_node((gpointer*)&(self)->Advice, (value))
                    


/* Constructors, destructors & static methods implementations */

#define new_LassoSaml2Assertion lasso_saml2_assertion_new
#define delete_LassoSaml2Assertion(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSaml2Assertion_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

