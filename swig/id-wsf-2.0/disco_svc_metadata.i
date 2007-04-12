
#ifndef SWIGPHP4
%rename(Idwsf2DiscoSvcMetadata) LassoIdwsf2DiscoSvcMetadata;
#endif
typedef struct {
	char *Abstract;
	char *ProviderID;
	/* XXX : Change this "void" if we happen to add ServiceContext in swig as well */
	void *ServiceContext;
	char *svcMDID;
} LassoIdwsf2DiscoSvcMetadata;
%extend LassoIdwsf2DiscoSvcMetadata {

	/* Constructor, Destructor & Static Methods */
	LassoIdwsf2DiscoSvcMetadata(gchar *service_type, gchar *abstract, gchar *provider_id);
	~LassoIdwsf2DiscoSvcMetadata();

	/* Method inherited from LassoNode */
	%newobject dump;
	char* dump();
}

%{


/* Constructors, destructors & static methods implementations */

#define new_LassoIdwsf2DiscoSvcMetadata lasso_idwsf2_disco_svc_metadata_new
#define delete_LassoIdwsf2DiscoSvcMetadata(self) lasso_node_destroy(LASSO_NODE(self))

/* Implementations of methods inherited from LassoNode */

#define LassoIdwsf2DiscoSvcMetadata_dump(self) lasso_node_dump(LASSO_NODE(self))

%}

