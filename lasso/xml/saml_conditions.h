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

#ifndef __LASSO_SAML_CONDITIONS_H__
#define __LASSO_SAML_CONDITIONS_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/xml/xml.h>
#include <lasso/xml/saml_audience_restriction_condition.h>
#include <lasso/xml/saml_condition_abstract.h>

#define LASSO_TYPE_SAML_CONDITIONS (lasso_saml_conditions_get_type())
#define LASSO_SAML_CONDITIONS(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_SAML_CONDITIONS, LassoSamlConditions))
#define LASSO_SAML_CONDITIONS_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_SAML_CONDITIONS, LassoSamlConditionsClass))
#define LASSO_IS_SAML_CONDITIONS(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_SAML_CONDITIONS))
#define LASSO_IS_SAML_CONDITIONS_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_SAML_CONDITIONS))
#define LASSO_SAML_CONDITIONS_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_SAML_CONDITIONS, LassoSamlConditionsClass)) 

typedef struct _LassoSamlConditions LassoSamlConditions;
typedef struct _LassoSamlConditionsClass LassoSamlConditionsClass;

struct _LassoSamlConditions {
	LassoNode parent;

	/* <element ref="saml:Condition"/> XXX: unbounded */
	/* LassoSamlCondition *Condition;  XXX missing from lasso */ 
	/* <element ref="saml:AudienceRestrictionCondition"/> XXX: unbounded */
	LassoSamlAudienceRestrictionCondition *AudienceRestrictionCondition;
	/* <attribute name="NotBefore" type="dateTime" use="optional"/> */
	char *NotBefore;
	/* <attribute name="NotOnOrAfter" type="dateTime" use="optional"/> */
	char *NotOnOrAfter;
};

struct _LassoSamlConditionsClass {
	LassoNodeClass parent;
};

LASSO_EXPORT GType lasso_saml_conditions_get_type(void);
LASSO_EXPORT LassoSamlConditions* lasso_saml_conditions_new(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_SAML_CONDITIONS_H__ */
