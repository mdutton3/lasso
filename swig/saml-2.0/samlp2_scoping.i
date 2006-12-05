
#ifndef SWIGPHP4
%rename(Samlp2Scoping) LassoSamlp2Scoping;
#endif
typedef struct {
#ifndef SWIGPHP4
	%rename(requesterId) RequesterID;
#endif
	char *RequesterID;
#ifndef SWIGPHP4
	%rename(proxyCount) ProxyCount;
#endif
	char *ProxyCount;
} LassoSamlp2Scoping;
%extend LassoSamlp2Scoping {

#ifndef SWIGPHP4
	%rename(iDPList) IDPList;
#endif
	%newobject *IDPList_get;
	LassoSamlp2IDPList *IDPList;


	/* Constructor, Destructor & Static Methods */
	LassoSamlp2Scoping();
	~LassoSamlp2Scoping();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{

/* IDPList */

#define LassoSamlp2Scoping_get_IDPList(self) get_node((self)->IDPList)
#define LassoSamlp2Scoping_IDPList_get(self) get_node((self)->IDPList)
#define LassoSamlp2Scoping_set_IDPList(self,value) set_node((gpointer*)&(self)->IDPList, (value))
#define LassoSamlp2Scoping_IDPList_set(self,value) set_node((gpointer*)&(self)->IDPList, (value))
                    


/* Constructors, destructors & static methods implementations */

#define new_LassoSamlp2Scoping lasso_samlp2_scoping_new
#define delete_LassoSamlp2Scoping(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSamlp2Scoping_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

