
#ifndef SWIGPHP4
%rename(IdWsf2DiscoSvcMetadata) LassoIdWsf2DiscoSvcMetadata;
#endif
typedef struct {
	char *Abstract;
	char *ProviderID;
	/* XXX : Change this "void" if we happen to add ServiceContext in swig as well */
	void *ServiceContext;
	char *svcMDID;
} LassoIdWsf2DiscoSvcMetadata;
%extend LassoIdWsf2DiscoSvcMetadata {

	/* Constructor, Destructor & Static Methods */
	LassoIdWsf2DiscoSvcMetadata(gchar *service_type, gchar *abstract, gchar *provider_id);
	~LassoIdWsf2DiscoSvcMetadata();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{


/* Constructors, destructors & static methods implementations */

#define new_LassoIdWsf2DiscoSvcMetadata lasso_idwsf2_disco_svc_metadata_new
#define delete_LassoIdWsf2DiscoSvcMetadata(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoIdWsf2DiscoSvcMetadata_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

