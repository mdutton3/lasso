
#ifndef SWIGPHP4
%rename(Saml2Conditions) LassoSaml2Conditions;
#endif
typedef struct {
#ifndef SWIGPHP4
	%rename(notBefore) NotBefore;
#endif
	char *NotBefore;
#ifndef SWIGPHP4
	%rename(notOnOrAfter) NotOnOrAfter;
#endif
	char *NotOnOrAfter;
} LassoSaml2Conditions;
%extend LassoSaml2Conditions {
#ifndef SWIGPHP4
	%rename(condition) Condition;
#endif
	%newobject Condition_get;
	LassoNodeList *Condition;

#ifndef SWIGPHP4
	%rename(audienceRestriction) AudienceRestriction;
#endif
	%newobject AudienceRestriction_get;
	LassoNodeList *AudienceRestriction;

	/* Constructor, Destructor & Static Methods */
	LassoSaml2Conditions();
	~LassoSaml2Conditions();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{

/* Condition */

#define LassoSaml2Conditions_get_Condition(self) get_node_list((self)->Condition)
#define LassoSaml2Conditions_Condition_get(self) get_node_list((self)->Condition)
#define LassoSaml2Conditions_set_Condition(self, value) set_node_list(&(self)->Condition, (value))
#define LassoSaml2Conditions_Condition_set(self, value) set_node_list(&(self)->Condition, (value))

/* AudienceRestriction */

#define LassoSaml2Conditions_get_AudienceRestriction(self) get_node_list((self)->AudienceRestriction)
#define LassoSaml2Conditions_AudienceRestriction_get(self) get_node_list((self)->AudienceRestriction)
#define LassoSaml2Conditions_set_AudienceRestriction(self, value) set_node_list(&(self)->AudienceRestriction, (value))
#define LassoSaml2Conditions_AudienceRestriction_set(self, value) set_node_list(&(self)->AudienceRestriction, (value))




/* Constructors, destructors & static methods implementations */

#define new_LassoSaml2Conditions lasso_saml2_conditions_new
#define delete_LassoSaml2Conditions(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSaml2Conditions_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

