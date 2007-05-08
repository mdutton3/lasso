
#ifndef SWIG_PHP_RENAMES
%rename(Saml2NameID) LassoSaml2NameID;
#endif
typedef struct {
	char *content;
#ifndef SWIG_PHP_RENAMES
	%rename(format) Format;
#endif
	char *Format;
#ifndef SWIG_PHP_RENAMES
	%rename(spProviderId) SPProviderID;
#endif
	char *SPProvidedID;
#ifndef SWIG_PHP_RENAMES
	%rename(nameQualifier) NameQualifier;
#endif
	char *NameQualifier;
#ifndef SWIG_PHP_RENAMES
	%rename(spNameQualifier) SPNameQualifier;
#endif
	char *SPNameQualifier;
} LassoSaml2NameID;
%extend LassoSaml2NameID {


	/* Constructor, Destructor & Static Methods */
	LassoSaml2NameID();
	~LassoSaml2NameID();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{


/* Constructors, destructors & static methods implementations */

#define new_LassoSaml2NameID lasso_saml2_name_id_new
#define delete_LassoSaml2NameID(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSaml2NameID_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

