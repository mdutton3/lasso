
#ifndef SWIGPHP4
%rename(Samlp2IDPEntry) LassoSamlp2IDPEntry;
#endif
typedef struct {
	char *ProviderID;
	char *Name;
	char *Loc;
} LassoSamlp2IDPEntry;
%extend LassoSamlp2IDPEntry {


	/* Constructor, Destructor & Static Methods */
	LassoSamlp2IDPEntry();
	~LassoSamlp2IDPEntry();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{


/* Constructors, destructors & static methods implementations */

#define new_LassoSamlp2IDPEntry lasso_samlp2_idp_entry_new
#define delete_LassoSamlp2IDPEntry(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSamlp2IDPEntry_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

