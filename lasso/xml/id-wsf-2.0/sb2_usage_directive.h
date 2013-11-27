/* $Id: sb2_usage_directive.h,v 1.0 2005/10/14 15:17:55 fpeters Exp $
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

#ifndef __LASSO_IDWSF2_SB2_USAGE_DIRECTIVE_H__
#define __LASSO_IDWSF2_SB2_USAGE_DIRECTIVE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml.h"

#define LASSO_TYPE_IDWSF2_SB2_USAGE_DIRECTIVE (lasso_idwsf2_sb2_usage_directive_get_type())
#define LASSO_IDWSF2_SB2_USAGE_DIRECTIVE(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), \
		LASSO_TYPE_IDWSF2_SB2_USAGE_DIRECTIVE, \
		LassoIdWsf2Sb2UsageDirective))
#define LASSO_IDWSF2_SB2_USAGE_DIRECTIVE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), \
		LASSO_TYPE_IDWSF2_SB2_USAGE_DIRECTIVE, \
		LassoIdWsf2Sb2UsageDirectiveClass))
#define LASSO_IS_IDWSF2_SB2_USAGE_DIRECTIVE(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), \
		LASSO_TYPE_IDWSF2_SB2_USAGE_DIRECTIVE))
#define LASSO_IS_IDWSF2_SB2_USAGE_DIRECTIVE_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), \
		LASSO_TYPE_IDWSF2_SB2_USAGE_DIRECTIVE))
#define LASSO_IDWSF2_SB2_USAGE_DIRECTIVE_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), \
		LASSO_TYPE_IDWSF2_SB2_USAGE_DIRECTIVE, \
		LassoIdWsf2Sb2UsageDirectiveClass))


typedef struct _LassoIdWsf2Sb2UsageDirective LassoIdWsf2Sb2UsageDirective;
typedef struct _LassoIdWsf2Sb2UsageDirectiveClass LassoIdWsf2Sb2UsageDirectiveClass;


struct _LassoIdWsf2Sb2UsageDirective {
	LassoNode parent;

	/*< public >*/
	/* attributes */
	char *ref;
	GHashTable *attributes;
};


struct _LassoIdWsf2Sb2UsageDirectiveClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_idwsf2_sb2_usage_directive_get_type(void);
LASSO_EXPORT LassoIdWsf2Sb2UsageDirective* lasso_idwsf2_sb2_usage_directive_new(void);



#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_IDWSF2_SB2_USAGE_DIRECTIVE_H__ */
