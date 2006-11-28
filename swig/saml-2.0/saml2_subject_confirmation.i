
#ifndef SWIGPHP4
%rename(Saml2SubjectConfirmation) LassoSaml2SubjectConfirmation;
#endif
typedef struct {
#ifndef SWIGPHP4
	%rename(method) Method;
#endif
	char *Method;
} LassoSaml2SubjectConfirmation;
%extend LassoSaml2SubjectConfirmation {

#ifndef SWIGPHP4
	%rename(baseID) BaseID;
#endif
	%newobject *BaseID_get;
	LassoSaml2BaseIDAbstract *BaseID;

#ifndef SWIGPHP4
	%rename(nameID) NameID;
#endif
	%newobject *NameID_get;
	LassoSaml2NameID *NameID;

#ifndef SWIGPHP4
	%rename(encryptedID) EncryptedID;
#endif
	%newobject *EncryptedID_get;
	LassoSaml2EncryptedElement *EncryptedID;

#ifndef SWIGPHP4
	%rename(subjectConfirmationData) SubjectConfirmationData;
#endif
	%newobject *SubjectConfirmationData_get;
	LassoSaml2SubjectConfirmationData *SubjectConfirmationData;


	/* Constructor, Destructor & Static Methods */
	LassoSaml2SubjectConfirmation();
	~LassoSaml2SubjectConfirmation();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{

/* BaseID */

#define LassoSaml2SubjectConfirmation_get_BaseID(self) get_node((self)->BaseID)
#define LassoSaml2SubjectConfirmation_BaseID_get(self) get_node((self)->BaseID)
#define LassoSaml2SubjectConfirmation_set_BaseID(self,value) set_node((gpointer*)&(self)->BaseID, (value))
#define LassoSaml2SubjectConfirmation_BaseID_set(self,value) set_node((gpointer*)&(self)->BaseID, (value))
                    

/* NameID */

#define LassoSaml2SubjectConfirmation_get_NameID(self) get_node((self)->NameID)
#define LassoSaml2SubjectConfirmation_NameID_get(self) get_node((self)->NameID)
#define LassoSaml2SubjectConfirmation_set_NameID(self,value) set_node((gpointer*)&(self)->NameID, (value))
#define LassoSaml2SubjectConfirmation_NameID_set(self,value) set_node((gpointer*)&(self)->NameID, (value))
                    

/* EncryptedID */

#define LassoSaml2SubjectConfirmation_get_EncryptedID(self) get_node((self)->EncryptedID)
#define LassoSaml2SubjectConfirmation_EncryptedID_get(self) get_node((self)->EncryptedID)
#define LassoSaml2SubjectConfirmation_set_EncryptedID(self,value) set_node((gpointer*)&(self)->EncryptedID, (value))
#define LassoSaml2SubjectConfirmation_EncryptedID_set(self,value) set_node((gpointer*)&(self)->EncryptedID, (value))
                    

/* SubjectConfirmationData */

#define LassoSaml2SubjectConfirmation_get_SubjectConfirmationData(self) get_node((self)->SubjectConfirmationData)
#define LassoSaml2SubjectConfirmation_SubjectConfirmationData_get(self) get_node((self)->SubjectConfirmationData)
#define LassoSaml2SubjectConfirmation_set_SubjectConfirmationData(self,value) set_node((gpointer*)&(self)->SubjectConfirmationData, (value))
#define LassoSaml2SubjectConfirmation_SubjectConfirmationData_set(self,value) set_node((gpointer*)&(self)->SubjectConfirmationData, (value))
                    


/* Constructors, destructors & static methods implementations */

#define new_LassoSaml2SubjectConfirmation lasso_saml2_subject_confirmation_new
#define delete_LassoSaml2SubjectConfirmation(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSaml2SubjectConfirmation_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

