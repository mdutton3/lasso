/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Authors: Nicolas Clapies <nclapies@entrouvert.com>
 *          Valery Febvre <vfebvre@easter-eggs.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef __LASSO_DISCO_MODIFY_RESPONSE_H__
#define __LASSO_DISCO_MODIFY_RESPONSE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/xml/xml.h>

#define LASSO_TYPE_DISCO_MODIFY_RESPONSE (lasso_disco_modify_response_get_type())
#define LASSO_DISCO_MODIFY_RESPONSE(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_DISCO_MODIFY_RESPONSE, \
				    LassoDiscoModifyResponse))
#define LASSO_DISCO_MODIFY_RESPONSE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_DISCO_MODIFY_RESPONSE, \
				 LassoDiscoModifyResponseClass))
#define LASSO_IS_DISCO_MODIFY_RESPONSE(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_DISCO_MODIFY_RESPONSE))
#define LASSO_IS_DISCO_MODIFY_RESPONSE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_DISCO_MODIFY_RESPONSE))
#define LASSO_DISCO_MODIFY_RESPONSE_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_DISCO_MODIFY_RESPONSE, \
				    LassoDiscoModifyResponseClass)) 

typedef struct _LassoDiscoModifyResponse LassoDiscoModifyResponse;
typedef struct _LassoDiscoModifyResponseClass LassoDiscoModifyResponseClass;

struct _LassoDiscoModifyResponse {
	LassoNode parent;

	char *Status; /* FIXME valos */

	char *id;
	char *newEntryIDs;
};

struct _LassoDiscoModifyResponseClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_disco_modify_response_get_type            (void);

LASSO_EXPORT LassoDiscoModifyResponse* lasso_disco_modify_response_new  ();

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_DISCO_MODIFY_RESPONSE_H__ */
