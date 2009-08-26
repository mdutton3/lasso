/* $Id$
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef __LASSO_SAMLP2_IDP_ENTRY_H__
#define __LASSO_SAMLP2_IDP_ENTRY_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "../xml.h"

#define LASSO_TYPE_SAMLP2_IDP_ENTRY (lasso_samlp2_idp_entry_get_type())
#define LASSO_SAMLP2_IDP_ENTRY(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SAMLP2_IDP_ENTRY, \
				LassoSamlp2IDPEntry))
#define LASSO_SAMLP2_IDP_ENTRY_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_SAMLP2_IDP_ENTRY, \
				LassoSamlp2IDPEntryClass))
#define LASSO_IS_SAMLP2_IDP_ENTRY(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SAMLP2_IDP_ENTRY))
#define LASSO_IS_SAMLP2_IDP_ENTRY_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SAMLP2_IDP_ENTRY))
#define LASSO_SAMLP2_IDP_ENTRY_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_SAMLP2_IDP_ENTRY, \
				LassoSamlp2IDPEntryClass))

typedef struct _LassoSamlp2IDPEntry LassoSamlp2IDPEntry;
typedef struct _LassoSamlp2IDPEntryClass LassoSamlp2IDPEntryClass;


struct _LassoSamlp2IDPEntry {
	LassoNode parent;

	/*< public >*/
	/* attributes */
	char *ProviderID;
	char *Name;
	char *Loc;
};


struct _LassoSamlp2IDPEntryClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_samlp2_idp_entry_get_type(void);
LASSO_EXPORT LassoNode* lasso_samlp2_idp_entry_new(void);



#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SAMLP2_IDP_ENTRY_H__ */
