#ifndef SINGLE_SIGN_ON_AND_FEDERATION_H
#define SINGLE_SIGN_ON_AND_FEDERATION_H

#include <lasso/lasso.h>

xmlChar *lasso_build_url_encoded_message_authnRequest(const char *,
													  const char *,
													  const char *,
													  const char *,
													  const char *,
													  const char *,
													  const char **,
													  const char **,
													  const char *,
													  const char *,
													  const char *,
													  const char **,
													  const char *);

#endif
