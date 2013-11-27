/* $Id: wsa_problem_action.h,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __LASSO_WSA_PROBLEM_ACTION_H__
#define __LASSO_WSA_PROBLEM_ACTION_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml.h"
#include "wsa_attributed_uri.h"

#define LASSO_TYPE_WSA_PROBLEM_ACTION (lasso_wsa_problem_action_get_type())
#define LASSO_WSA_PROBLEM_ACTION(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), \
		LASSO_TYPE_WSA_PROBLEM_ACTION, \
		LassoWsAddrProblemAction))
#define LASSO_WSA_PROBLEM_ACTION_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), \
		LASSO_TYPE_WSA_PROBLEM_ACTION, \
		LassoWsAddrProblemActionClass))
#define LASSO_IS_WSA_PROBLEM_ACTION(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), \
		LASSO_TYPE_WSA_PROBLEM_ACTION))
#define LASSO_IS_WSA_PROBLEM_ACTION_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), \
		LASSO_TYPE_WSA_PROBLEM_ACTION))
#define LASSO_WSA_PROBLEM_ACTION_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), \
		LASSO_TYPE_WSA_PROBLEM_ACTION, \
		LassoWsAddrProblemActionClass))


typedef struct _LassoWsAddrProblemAction LassoWsAddrProblemAction;
typedef struct _LassoWsAddrProblemActionClass LassoWsAddrProblemActionClass;


struct _LassoWsAddrProblemAction {
	LassoNode parent;

	/*< public >*/
	/* elements */
	LassoWsAddrAttributedURI *Action;
	char *SoapAction;
	/* attributes */
	GHashTable *attributes;
};


struct _LassoWsAddrProblemActionClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_wsa_problem_action_get_type(void);
LASSO_EXPORT LassoWsAddrProblemAction* lasso_wsa_problem_action_new(void);



#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_WSA_PROBLEM_ACTION_H__ */
