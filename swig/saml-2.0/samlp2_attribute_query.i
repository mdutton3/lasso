
#ifndef SWIGPHP4
%rename(Samlp2AttributeQuery) LassoSamlp2AttributeQuery;
#endif
typedef struct {
} LassoSamlp2AttributeQuery;
%extend LassoSamlp2AttributeQuery {

#ifndef SWIGPHP4
	%rename(attribute) Attribute;
#endif
	%newobject *Attribute_get;
	LassoSaml2Attribute *Attribute;

	/* inherited from Samlp2SubjectQueryAbstract */
#ifndef SWIGPHP4
	%rename(subject) Subject;
#endif
	%newobject *Subject_get;
	LassoSaml2Subject *Subject;

	/* inherited from RequestAbstract */
#ifndef SWIGPHP4
	%rename(issuer) Issuer;
#endif
	%newobject *Issuer_get;
	LassoSaml2NameID *Issuer;

#ifndef SWIGPHP4
	%rename(extensions) Extensions;
#endif
	%newobject *Extensions_get;
	LassoSamlp2Extensions *Extensions;

#ifndef SWIGPHP4
	%rename(iD) ID;
#endif
	char *ID;
#ifndef SWIGPHP4
	%rename(version) Version;
#endif
	char *Version;
#ifndef SWIGPHP4
	%rename(issueInstant) IssueInstant;
#endif
	char *IssueInstant;
#ifndef SWIGPHP4
	%rename(destination) Destination;
#endif
	char *Destination;
#ifndef SWIGPHP4
	%rename(consent) Consent;
#endif
	char *Consent;

	/* Constructor, Destructor & Static Methods */
	LassoSamlp2AttributeQuery();
	~LassoSamlp2AttributeQuery();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{

/* Attribute */

#define LassoSamlp2AttributeQuery_get_Attribute(self) get_node((self)->Attribute)
#define LassoSamlp2AttributeQuery_Attribute_get(self) get_node((self)->Attribute)
#define LassoSamlp2AttributeQuery_set_Attribute(self,value) set_node((gpointer*)&(self)->Attribute, (value))
#define LassoSamlp2AttributeQuery_Attribute_set(self,value) set_node((gpointer*)&(self)->Attribute, (value))
                    

/* inherited from SubjectQueryAbstract */

/* Subject */

#define LassoSamlp2AttributeQuery_get_Subject(self) get_node(LASSO_SAMLP2_SUBJECT_QUERY_ABSTRACT(self)->Subject)
#define LassoSamlp2AttributeQuery_Subject_get(self) get_node(LASSO_SAMLP2_SUBJECT_QUERY_ABSTRACT(self)->Subject)
#define LassoSamlp2AttributeQuery_set_Subject(self,value) set_node((gpointer*)&LASSO_SAMLP2_SUBJECT_QUERY_ABSTRACT(self)->Subject, (value))
#define LassoSamlp2AttributeQuery_Subject_set(self,value) set_node((gpointer*)&LASSO_SAMLP2_SUBJECT_QUERY_ABSTRACT(self)->Subject, (value))
                    

/* inherited from RequestAbstract */

/* Issuer */

#define LassoSamlp2AttributeQuery_get_Issuer(self) get_node(LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Issuer)
#define LassoSamlp2AttributeQuery_Issuer_get(self) get_node(LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Issuer)
#define LassoSamlp2AttributeQuery_set_Issuer(self,value) set_node((gpointer*)&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Issuer, (value))
#define LassoSamlp2AttributeQuery_Issuer_set(self,value) set_node((gpointer*)&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Issuer, (value))
                    

/* Extensions */

#define LassoSamlp2AttributeQuery_get_Extensions(self) get_node(LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Extensions)
#define LassoSamlp2AttributeQuery_Extensions_get(self) get_node(LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Extensions)
#define LassoSamlp2AttributeQuery_set_Extensions(self,value) set_node((gpointer*)&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Extensions, (value))
#define LassoSamlp2AttributeQuery_Extensions_set(self,value) set_node((gpointer*)&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Extensions, (value))
                    

/* ID */

#define LassoSamlp2AttributeQuery_get_ID(self) LASSO_SAMLP2_REQUEST_ABSTRACT(self)->ID
#define LassoSamlp2AttributeQuery_ID_get(self) LASSO_SAMLP2_REQUEST_ABSTRACT(self)->ID

#define LassoSamlp2AttributeQuery_set_ID(self,value) set_string(&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->ID, (value))
#define LassoSamlp2AttributeQuery_ID_set(self,value) set_string(&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->ID, (value))

/* Version */

#define LassoSamlp2AttributeQuery_get_Version(self) LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Version
#define LassoSamlp2AttributeQuery_Version_get(self) LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Version

#define LassoSamlp2AttributeQuery_set_Version(self,value) set_string(&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Version, (value))
#define LassoSamlp2AttributeQuery_Version_set(self,value) set_string(&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Version, (value))

/* IssueInstant */

#define LassoSamlp2AttributeQuery_get_IssueInstant(self) LASSO_SAMLP2_REQUEST_ABSTRACT(self)->IssueInstant
#define LassoSamlp2AttributeQuery_IssueInstant_get(self) LASSO_SAMLP2_REQUEST_ABSTRACT(self)->IssueInstant

#define LassoSamlp2AttributeQuery_set_IssueInstant(self,value) set_string(&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->IssueInstant, (value))
#define LassoSamlp2AttributeQuery_IssueInstant_set(self,value) set_string(&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->IssueInstant, (value))

/* Destination */

#define LassoSamlp2AttributeQuery_get_Destination(self) LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Destination
#define LassoSamlp2AttributeQuery_Destination_get(self) LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Destination

#define LassoSamlp2AttributeQuery_set_Destination(self,value) set_string(&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Destination, (value))
#define LassoSamlp2AttributeQuery_Destination_set(self,value) set_string(&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Destination, (value))

/* Consent */

#define LassoSamlp2AttributeQuery_get_Consent(self) LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Consent
#define LassoSamlp2AttributeQuery_Consent_get(self) LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Consent

#define LassoSamlp2AttributeQuery_set_Consent(self,value) set_string(&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Consent, (value))
#define LassoSamlp2AttributeQuery_Consent_set(self,value) set_string(&LASSO_SAMLP2_REQUEST_ABSTRACT(self)->Consent, (value))


/* Constructors, destructors & static methods implementations */

#define new_LassoSamlp2AttributeQuery lasso_samlp2_attribute_query_new
#define delete_LassoSamlp2AttributeQuery(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSamlp2AttributeQuery_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

