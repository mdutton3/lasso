
#ifndef SWIGPHP4
%rename(Saml2KeyInfoConfirmationData) LassoSaml2KeyInfoConfirmationData;
#endif
typedef struct {
} LassoSaml2KeyInfoConfirmationData;
%extend LassoSaml2KeyInfoConfirmationData {


	/* Constructor, Destructor & Static Methods */
	LassoSaml2KeyInfoConfirmationData();
	~LassoSaml2KeyInfoConfirmationData();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{


/* Constructors, destructors & static methods implementations */

#define new_LassoSaml2KeyInfoConfirmationData lasso_saml2_key_info_confirmation_data_new
#define delete_LassoSaml2KeyInfoConfirmationData(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSaml2KeyInfoConfirmationData_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

