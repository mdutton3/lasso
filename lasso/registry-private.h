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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */


#ifndef __REGISTRY_PRIVATE_H__
#define __REGISTRY_PRIVATE_H__

#include "registry.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct _LassoRegistry LassoRegistry;

struct _LassoRegistry {
		GHashTable *functional_mapping;
		GHashTable *direct_mapping;
};

LassoRegistry *lasso_registry_new();
void lasso_registry_destroy();
void lasso_registry_default_shutdown();
gint lasso_registry_add_direct_mapping(LassoRegistry *registry, const char *from_namespace,
		const char *from_name, const char *to_namespace, const char *to_name);
gint lasso_registry_add_functional_mapping(LassoRegistry *registry, const char *from_namespace,
		const char *to_namespace, LassoRegistryTranslationFunction translation_function);
const char* lasso_registry_get_mapping(LassoRegistry *registry, const char *from_namespace,
		const char *from_name, const char *to_namespace);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __REGISTRY_PRIVATE_H__ */
