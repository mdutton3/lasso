#include <lasso/protocols/protocols.h>

GString *lasso_build_encoded_message_url(const char *authority, LassoNode *request)
{
	 GString *url;
	 xmlChar *query;

	 url = g_string_new(authority);
	 g_string_append_c(url, '?');
	 g_string_append(url, lasso_node_url_encode(request));

	 return(url);
}

void lasso_sign_encoded_message(GString *message, const char *private_key_filename)
{
     lasso_str_sign(message->str, xmlSecTransformRsaSha1Id, private_key_filename);
}
