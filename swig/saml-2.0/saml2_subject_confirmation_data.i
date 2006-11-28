
#ifndef SWIGPHP4
%rename(Saml2SubjectConfirmationData) LassoSaml2SubjectConfirmationData;
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
#ifndef SWIGPHP4
	%rename(recipient) Recipient;
#endif
	char *Recipient;
#ifndef SWIGPHP4
	%rename(inResponseTo) InResponseTo;
#endif
	char *InResponseTo;
#ifndef SWIGPHP4
	%rename(address) Address;
#endif
	char *Address;
} LassoSaml2SubjectConfirmationData;
%extend LassoSaml2SubjectConfirmationData {


	/* Constructor, Destructor & Static Methods */
	LassoSaml2SubjectConfirmationData();
	~LassoSaml2SubjectConfirmationData();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{


/* Constructors, destructors & static methods implementations */

#define new_LassoSaml2SubjectConfirmationData lasso_saml2_subject_confirmation_data_new
#define delete_LassoSaml2SubjectConfirmationData(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSaml2SubjectConfirmationData_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

