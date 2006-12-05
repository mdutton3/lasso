
#ifndef SWIGPHP4
%rename(Samlp2StatusCode) LassoSamlp2StatusCode;
#endif
typedef struct {
#ifndef SWIGPHP4
	%rename(value) Value;
#endif
	char *Value;
} LassoSamlp2StatusCode;
%extend LassoSamlp2StatusCode {

#ifndef SWIGPHP4
	%rename(statusCode) StatusCode;
#endif
	%newobject *StatusCode_get;
	LassoSamlp2StatusCode *StatusCode;


	/* Constructor, Destructor & Static Methods */
	LassoSamlp2StatusCode();
	~LassoSamlp2StatusCode();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{

/* StatusCode */

#define LassoSamlp2StatusCode_get_StatusCode(self) get_node((self)->StatusCode)
#define LassoSamlp2StatusCode_StatusCode_get(self) get_node((self)->StatusCode)
#define LassoSamlp2StatusCode_set_StatusCode(self,value) set_node((gpointer*)&(self)->StatusCode, (value))
#define LassoSamlp2StatusCode_StatusCode_set(self,value) set_node((gpointer*)&(self)->StatusCode, (value))
                    


/* Constructors, destructors & static methods implementations */

#define new_LassoSamlp2StatusCode lasso_samlp2_status_code_new
#define delete_LassoSamlp2StatusCode(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoSamlp2StatusCode_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

