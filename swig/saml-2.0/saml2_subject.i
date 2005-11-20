
#ifndef SWIGPHP4
%rename(Saml2Subject) LassoSaml2Subject;
#endif
typedef struct {
} LassoSaml2Subject;
%extend LassoSaml2Subject {

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
	%rename(subjectConfirmation) SubjectConfirmation;
#endif
	%newobject *SubjectConfirmation_get;
	LassoSaml2SubjectConfirmation *SubjectConfirmation;


	/* Constructor, Destructor & Static Methods */
	LassoSaml2Subject();
	~LassoSaml2Subject();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{

/* BaseID */

#define LassoSaml2Subject_get_BaseID(self) get_node((self)->BaseID)
#define LassoSaml2Subject_BaseID_get(self) get_node((self)->BaseID)
#define LassoSaml2Subject_set_BaseID(self,value) set_node((gpointer*)&(self)->BaseID, (value))
#define LassoSaml2Subject_BaseID_set(self,value) set_node((gpointer*)&(self)->BaseID, (value))
                    

/* NameID */

#define LassoSaml2Subject_get_NameID(self) get_node((self)->NameID)
#define LassoSaml2Subject_NameID_get(self) get_node((self)->NameID)
#define LassoSaml2Subject_set_NameID(self,value) set_node((gpointer*)&(self)->NameID, (value))
#define LassoSaml2Subject_NameID_set(self,value) set_node((gpointer*)&(self)->NameID, (value))
                    

/* EncryptedID */

#define LassoSaml2Subject_get_EncryptedID(self) get_node((self)->EncryptedID)
#define LassoSaml2Subject_EncryptedID_get(self) get_node((self)->EncryptedID)
#define LassoSaml2Subject_set_EncryptedID(self,value) set_node((gpointer*)&(self)->EncryptedID, (value))
#define LassoSaml2Subject_EncryptedID_set(self,value) set_node((gpointer*)&(self)->EncryptedID, (value))
                    

/* SubjectConfirmation */

#define LassoSaml2Subject_get_SubjectConfirmation(self) get_node((self)->SubjectConfirmation)
#define LassoSaml2Subject_SubjectConfirmation_get(self) get_node((self)->SubjectConfirmation)
#define LassoSaml2Subject_set_SubjectConfirmation(self,value) set_node((gpointer*)&(self)->SubjectConfirmation, (value))
#define LassoSaml2Subject_SubjectConfirmation_set(self,value) set_node((gpointer*)&(self)->SubjectConfirmation, (value))
                    


/* Constructors, destructors & static methods implementations */

#define new_LassoSaml2Subject lasso_saml2_subject_new
#define delete_LassoSaml2Subject(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSaml2Subject_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

