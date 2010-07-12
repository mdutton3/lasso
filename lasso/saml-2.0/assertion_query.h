/* $Id: assertion_query.h 3237 2007-05-30 17:17:45Z dlaniel $
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004-2007 Entr'ouvert
 * http://lasso.entrouvert.org
 *
 * Authors: See AUTHORS file in top-level directory.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#ifndef __LASSO_ASSERTION_QUERY_H__
#define __LASSO_ASSERTION_QUERY_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../id-ff/profile.h"
#include "../xml/saml-2.0/samlp2_manage_name_id_request.h"
#include "../xml/saml-2.0/samlp2_manage_name_id_response.h"

#define LASSO_TYPE_ASSERTION_QUERY (lasso_assertion_query_get_type())
#define LASSO_ASSERTION_QUERY(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_ASSERTION_QUERY, LassoAssertionQuery))
#define LASSO_ASSERTION_QUERY_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_ASSERTION_QUERY, \
				 LassoAssertionQueryClass))
#define LASSO_IS_ASSERTION_QUERY(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_ASSERTION_QUERY))
#define LASSO_IS_ASSERTION_QUERY_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_ASSERTION_QUERY))
#define LASSO_ASSERTION_QUERY_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_ASSERTION_QUERY, \
				    LassoAssertionQueryClass))

typedef struct _LassoAssertionQuery LassoAssertionQuery;
typedef struct _LassoAssertionQueryClass LassoAssertionQueryClass;
typedef struct _LassoAssertionQueryPrivate LassoAssertionQueryPrivate;

/**
 * LassoAssertionQueryRequestType:
 * @LASSO_ASSERTION_QUERY_REQUEST_TYPE_UNSET: the unknown value
 * @LASSO_ASSERTION_QUERY_REQUEST_TYPE_ASSERTION_ID: an AssertionID request, to retrieve an
 * assertion by its ID.
 * @LASSO_ASSERTION_QUERY_REQUEST_TYPE_AUTHN: an AuthnQuery request, which is used to request existing authentication assertions about a given subject from an Authentication Authority
 * @LASSO_ASSERTION_QUERY_REQUEST_TYPE_ATTRIBUTE: an AttributeQuery, which is used to retrieve
 * attribute an a principal.
 * @LASSO_ASSERTION_QUERY_REQUEST_TYPE_AUTHZ_DECISION: an AuthzDecisionQuery, which is used to
 * request authorisation to let a principal access a certain resource.
 *
 * Enumerate the existing kind of AssertionQuery requests.
 **/
typedef enum {
	LASSO_ASSERTION_QUERY_REQUEST_TYPE_UNSET = 0,
	LASSO_ASSERTION_QUERY_REQUEST_TYPE_ASSERTION_ID,
	LASSO_ASSERTION_QUERY_REQUEST_TYPE_AUTHN,
	LASSO_ASSERTION_QUERY_REQUEST_TYPE_ATTRIBUTE,
	LASSO_ASSERTION_QUERY_REQUEST_TYPE_AUTHZ_DECISION,
	LASSO_ASSERTION_QUERY_REQUEST_TYPE_LAST
} LassoAssertionQueryRequestType;

struct _LassoAssertionQuery {
	LassoProfile parent;
	/*< private >*/
	LassoAssertionQueryPrivate *private_data;
};

struct _LassoAssertionQueryClass {
	LassoProfileClass parent;
};

LASSO_EXPORT GType lasso_assertion_query_get_type(void);

LASSO_EXPORT LassoAssertionQuery *lasso_assertion_query_new(LassoServer *server);

LASSO_EXPORT void lasso_assertion_query_destroy(LassoAssertionQuery *assertion_query);

LASSO_EXPORT lasso_error_t lasso_assertion_query_init_request(
		LassoAssertionQuery *assertion_query,
		char *remote_provider_id,
		LassoHttpMethod http_method,
		LassoAssertionQueryRequestType query_request_type);

LASSO_EXPORT lasso_error_t lasso_assertion_query_validate_request(
		LassoAssertionQuery *assertion_query);

LASSO_EXPORT lasso_error_t lasso_assertion_query_build_request_msg(
		LassoAssertionQuery *assertion_query);

LASSO_EXPORT lasso_error_t lasso_assertion_query_process_request_msg(
		LassoAssertionQuery *assertion_query,
		gchar *request_msg);

LASSO_EXPORT lasso_error_t lasso_assertion_query_build_response_msg(
		LassoAssertionQuery *assertion_query);

LASSO_EXPORT lasso_error_t lasso_assertion_query_process_response_msg(
		LassoAssertionQuery *assertion_query,
		gchar *response_msg);

LASSO_EXPORT lasso_error_t lasso_assertion_query_add_attribute_request(LassoAssertionQuery *assertion_query,
		char *format, char *name);

LASSO_EXPORT LassoAssertionQueryRequestType lasso_assertion_query_get_request_type(
		LassoAssertionQuery *assertion_query);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_ASSERTION_QUERY_H__ */
