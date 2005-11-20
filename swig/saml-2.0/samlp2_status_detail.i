
#ifndef SWIGPHP4
%rename(Samlp2StatusDetail) LassoSamlp2StatusDetail;
#endif
typedef struct {
} LassoSamlp2StatusDetail;
%extend LassoSamlp2StatusDetail {


	/* Constructor, Destructor & Static Methods */
	LassoSamlp2StatusDetail();
	~LassoSamlp2StatusDetail();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{


/* Constructors, destructors & static methods implementations */

#define new_LassoSamlp2StatusDetail lasso_samlp2_status_detail_new
#define delete_LassoSamlp2StatusDetail(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSamlp2StatusDetail_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

