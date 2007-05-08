
#ifndef SWIG_PHP_RENAMES
%rename(Samlp2NameIDPolicy) LassoSamlp2NameIDPolicy;
#endif
typedef struct {
#ifndef SWIG_PHP_RENAMES
	%rename(format) Format;
#endif
	char *Format;
#ifndef SWIG_PHP_RENAMES
	%rename(spNameQualifier) SPNameQualifier;
#endif
	char *SPNameQualifier;
#ifndef SWIG_PHP_RENAMES
	%rename(allowCreate) AllowCreate;
#endif
	gboolean AllowCreate;
} LassoSamlp2NameIDPolicy;
%extend LassoSamlp2NameIDPolicy {


	/* Constructor, Destructor & Static Methods */
	LassoSamlp2NameIDPolicy();
	~LassoSamlp2NameIDPolicy();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{


/* Constructors, destructors & static methods implementations */

#define new_LassoSamlp2NameIDPolicy lasso_samlp2_name_id_policy_new
#define delete_LassoSamlp2NameIDPolicy(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSamlp2NameIDPolicy_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

