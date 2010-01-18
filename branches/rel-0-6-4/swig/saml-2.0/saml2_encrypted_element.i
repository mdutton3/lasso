
#ifndef SWIGPHP4
%rename(Saml2EncryptedElement) LassoSaml2EncryptedElement;
#endif
typedef struct {
} LassoSaml2EncryptedElement;
%extend LassoSaml2EncryptedElement {


	/* Constructor, Destructor & Static Methods */
	LassoSaml2EncryptedElement();
	~LassoSaml2EncryptedElement();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{


/* Constructors, destructors & static methods implementations */

#define new_LassoSaml2EncryptedElement lasso_saml2_encrypted_element_new
#define delete_LassoSaml2EncryptedElement(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSaml2EncryptedElement_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

