
#ifndef SWIGPHP4
%rename(Samlp2Status) LassoSamlp2Status;
#endif
typedef struct {
	char *StatusMessage;
} LassoSamlp2Status;
%extend LassoSamlp2Status {

#ifndef SWIGPHP4
	%rename(statusCode) StatusCode;
#endif
	%newobject *StatusCode_get;
	LassoSamlp2StatusCode *StatusCode;

#ifndef SWIGPHP4
	%rename(statusDetail) StatusDetail;
#endif
	%newobject *StatusDetail_get;
	LassoSamlp2StatusDetail *StatusDetail;


	/* Constructor, Destructor & Static Methods */
	LassoSamlp2Status();
	~LassoSamlp2Status();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{

/* StatusCode */

#define LassoSamlp2Status_get_StatusCode(self) get_node((self)->StatusCode)
#define LassoSamlp2Status_StatusCode_get(self) get_node((self)->StatusCode)
#define LassoSamlp2Status_set_StatusCode(self,value) set_node((gpointer*)&(self)->StatusCode, (value))
#define LassoSamlp2Status_StatusCode_set(self,value) set_node((gpointer*)&(self)->StatusCode, (value))
                    

/* StatusDetail */

#define LassoSamlp2Status_get_StatusDetail(self) get_node((self)->StatusDetail)
#define LassoSamlp2Status_StatusDetail_get(self) get_node((self)->StatusDetail)
#define LassoSamlp2Status_set_StatusDetail(self,value) set_node((gpointer*)&(self)->StatusDetail, (value))
#define LassoSamlp2Status_StatusDetail_set(self,value) set_node((gpointer*)&(self)->StatusDetail, (value))
                    


/* Constructors, destructors & static methods implementations */

#define new_LassoSamlp2Status lasso_samlp2_status_new
#define delete_LassoSamlp2Status(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSamlp2Status_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

