#include <lasso/protocols/name_identifier.h>

LassoNode *lasso_build_nameIdentifier(const xmlChar *nameIdentifier,
				      const xmlChar *nameQualifier,
				      const xmlChar *format)
{
     LassoNode *identifier;

     identifier = lasso_saml_name_identifier_new(nameIdentifier);
     lasso_saml_name_identifier_set_nameQualifier(identifier, nameQualifier);
     lasso_saml_name_identifier_set_format(identifier, format);

     return(identifier);
}

LassoNode *lasso_build_idpProvidedNameIdentifier(const xmlChar *nameIdentifier,
						 const xmlChar *nameQualifier,
						 const xmlChar *format)
{
     LassoNode *identifier;

     identifier = lasso_lib_idp_provided_name_identifier_new();
     lasso_saml_name_identifier_set_nameQualifier(identifier, nameQualifier);
     lasso_saml_name_identifier_set_format(identifier, format);

     return(identifier);
}

LassoNode *lasso_build_spProvidedNameIdentifier(const xmlChar *nameIdentifier,
						const xmlChar *nameQualifier,
						const xmlChar *format)
{
     LassoNode *identifier;

     identifier = lasso_lib_sp_provided_name_identifier_new();
     lasso_saml_name_identifier_set_nameQualifier(identifier, nameQualifier);
     lasso_saml_name_identifier_set_format(identifier, format);

     return(identifier);
}

LassoNode *lasso_build_oldProvidedNameIdentifier(const xmlChar *nameIdentifier,
						 const xmlChar *nameQualifier,
						 const xmlChar *format)
{
     LassoNode *identifier;

     identifier = lasso_lib_old_provided_name_identifier_new();
     lasso_saml_name_identifier_set_nameQualifier(identifier, nameQualifier);
     lasso_saml_name_identifier_set_format(identifier, format);

     return(identifier);
}
