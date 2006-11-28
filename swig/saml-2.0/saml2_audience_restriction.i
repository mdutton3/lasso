
#ifndef SWIGPHP4
%rename(Saml2AudienceRestriction) LassoSaml2AudienceRestriction;
#endif
typedef struct {
#ifndef SWIGPHP4
	%rename(audience) Audience;
#endif
	char *Audience;
} LassoSaml2AudienceRestriction;
%extend LassoSaml2AudienceRestriction {

	/* inherited from Saml2ConditionAbstract */

	/* Constructor, Destructor & Static Methods */
	LassoSaml2AudienceRestriction();
	~LassoSaml2AudienceRestriction();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{


/* Constructors, destructors & static methods implementations */

#define new_LassoSaml2AudienceRestriction lasso_saml2_audience_restriction_new
#define delete_LassoSaml2AudienceRestriction(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSaml2AudienceRestriction_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

