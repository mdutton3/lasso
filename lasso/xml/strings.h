/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Author: Valery Febvre <vfebvre@easter-eggs.com>
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

#ifndef __LASSO_STRINGS_H__
#define __LASSO_STRINGS_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <lasso/export.h>
#include <glib-object.h>

/* NameIDPolicyType */
LASSO_EXPORT_VAR const gchar lassoLibNameIDPolicyTypeNone[];
LASSO_EXPORT_VAR const gchar lassoLibNameIDPolicyTypeOneTime[];
LASSO_EXPORT_VAR const gchar lassoLibNameIDPolicyTypeFederated[];
LASSO_EXPORT_VAR const gchar lassoLibNameIDPolicyTypeAny[];

/* AuthnContextComparison */
LASSO_EXPORT_VAR const gchar lassoLibAuthnContextComparisonExact[];
LASSO_EXPORT_VAR const gchar lassoLibAuthnContextComparisonMinimum[];
LASSO_EXPORT_VAR const gchar lassLibAuthnContextComparisonBetter[];

/* Lib versioning */
LASSO_EXPORT_VAR const gchar lassoLibMajorVersion[];
LASSO_EXPORT_VAR const gchar lassoLibMinorVersion[];

/* Saml versioning */
LASSO_EXPORT_VAR const gchar lassoSamlMajorVersion[];
LASSO_EXPORT_VAR const gchar lassoSamlMinorVersion[];

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_STRINGS_H__ */
