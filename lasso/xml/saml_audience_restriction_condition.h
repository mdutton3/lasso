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

#ifndef __LASSO_SAML_AUDIENCE_RESTRICTION_CONDITION_H__
#define __LASSO_SAML_AUDIENCE_RESTRICTION_CONDITION_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/xml/saml_condition_abstract.h>

#define LASSO_TYPE_SAML_AUDIENCE_RESTRICTION_CONDITION \
	(lasso_saml_audience_restriction_condition_get_type())
#define LASSO_SAML_AUDIENCE_RESTRICTION_CONDITION(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SAML_AUDIENCE_RESTRICTION_CONDITION,\
				    LassoSamlAudienceRestrictionCondition))
#define LASSO_SAML_AUDIENCE_RESTRICTION_CONDITION_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_SAML_AUDIENCE_RESTRICTION_CONDITION, \
				 LassoSamlAudienceRestrictionConditionClass))
#define LASSO_IS_SAML_AUDIENCE_RESTRICTION_CONDITION(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SAML_AUDIENCE_RESTRICTION_CONDITION))
#define LASSO_IS_SAML_AUDIENCE_RESTRICTION_CONDITION_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SAML_AUDIENCE_RESTRICTION_CONDITION))
#define LASSO_SAML_AUDIENCE_RESTRICTION_CONDITION_GET_CLASS(o) \
	(G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_SAML_AUDIENCE_RESTRICTION_CONDITION, \
				    LassoSamlAudienceRestrictionConditionClass)) 

typedef struct _LassoSamlAudienceRestrictionCondition LassoSamlAudienceRestrictionCondition;
typedef struct _LassoSamlAudienceRestrictionConditionClass \
	LassoSamlAudienceRestrictionConditionClass;

struct _LassoSamlAudienceRestrictionCondition {
	LassoSamlConditionAbstract parent;

	/*< public >*/
	/* <element ref="saml:Audience" maxOccurs="unbounded"/> */
	char *Audience;	/* XXX: unbounded -> GList */
};

struct _LassoSamlAudienceRestrictionConditionClass {
	LassoSamlConditionAbstractClass parent;
};

LASSO_EXPORT GType lasso_saml_audience_restriction_condition_get_type(void);
LASSO_EXPORT LassoSamlAudienceRestrictionCondition*
		lasso_saml_audience_restriction_condition_new(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SAML_AUDIENCE_RESTRICTION_CONDITION_H__ */
