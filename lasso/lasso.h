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

#ifndef __LASSO_H__
#define __LASSO_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/version.h>
#include <lasso/export.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/crypto.h>

#include <lasso/schema/strings.h>
#include <lasso/schema/saml.h>
#include <lasso/schema/lib.h>
#include <lasso/protocols/protocols.h>

LASSO_EXPORT int lasso_init(void);
LASSO_EXPORT int lasso_shutdown(void);

/**
 * lassoCheckVersionMode:
 * @lassoCheckVersionExact:		the version should match exactly.
 * @lassoCheckVersionABICompatible:	the version should be ABI compatible.
 *
 * The lasso library version mode.
 */
typedef enum {
  lassoCheckVersionExact = 0,
  lassoCheckVersionABICompatible
} lassoCheckVersionMode;

/**
 * lasso_check_version_exact:
 *
 * Macro. Returns 1 if the loaded lasso library version exactly matches 
 * the one used to compile the caller, 0 if it does not or a negative
 * value if an error occurs.
 */
#define lasso_check_version_exact()	\
    lasso_check_version_ext(LASSO_VERSION_MAJOR, LASSO_VERSION_MINOR, \
                            LASSO_VERSION_SUBMINOR, lassoCheckVersionExact)

/**
 * lasso_check_version:
 *
 * Macro. Returns 1 if the loaded lasso library version ABI compatible with
 * the one used to compile the caller, 0 if it does not or a negative
 * value if an error occurs.
 */
#define lasso_check_version()	\
    lasso_check_version_ext(LASSO_VERSION_MAJOR, LASSO_VERSION_MINOR, \
			    LASSO_VERSION_SUBMINOR, \
			    lassoCheckVersionABICompatible)

LASSO_EXPORT int lasso_check_version_ext(int major,
					 int minor,
					 int subminor,
					 lassoCheckVersionMode mode);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_H__ */
