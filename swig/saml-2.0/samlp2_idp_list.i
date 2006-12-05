
#ifndef SWIGPHP4
%rename(Samlp2IDPList) LassoSamlp2IDPList;
#endif
typedef struct {
#ifndef SWIGPHP4
	%rename(getComplete) GetComplete;
#endif
	char *GetComplete;
} LassoSamlp2IDPList;
%extend LassoSamlp2IDPList {

#ifndef SWIGPHP4
	%rename(iDPEntry) IDPEntry;
#endif
	%newobject *IDPEntry_get;
	LassoSamlp2IDPEntry *IDPEntry;


	/* Constructor, Destructor & Static Methods */
	LassoSamlp2IDPList();
	~LassoSamlp2IDPList();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{

/* IDPEntry */

#define LassoSamlp2IDPList_get_IDPEntry(self) get_node((self)->IDPEntry)
#define LassoSamlp2IDPList_IDPEntry_get(self) get_node((self)->IDPEntry)
#define LassoSamlp2IDPList_set_IDPEntry(self,value) set_node((gpointer*)&(self)->IDPEntry, (value))
#define LassoSamlp2IDPList_IDPEntry_set(self,value) set_node((gpointer*)&(self)->IDPEntry, (value))
                    


/* Constructors, destructors & static methods implementations */

#define new_LassoSamlp2IDPList lasso_samlp2_idp_list_new
#define delete_LassoSamlp2IDPList(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSamlp2IDPList_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

