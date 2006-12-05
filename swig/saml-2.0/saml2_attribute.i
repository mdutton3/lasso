
#ifndef SWIGPHP4
%rename(Saml2Attribute) LassoSaml2Attribute;
#endif
typedef struct {
#ifndef SWIGPHP4
	%rename(name) Name;
#endif
	char *Name;
#ifndef SWIGPHP4
	%rename(nameFormat) NameFormat;
#endif
	char *NameFormat;
#ifndef SWIGPHP4
	%rename(friendlyName) FriendlyName;
#endif
	char *FriendlyName;
} LassoSaml2Attribute;
%extend LassoSaml2Attribute {


	/* Constructor, Destructor & Static Methods */
	LassoSaml2Attribute();
	~LassoSaml2Attribute();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{


/* Constructors, destructors & static methods implementations */

#define new_LassoSaml2Attribute lasso_saml2_attribute_new
#define delete_LassoSaml2Attribute(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSaml2Attribute_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

