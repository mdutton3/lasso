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

#ifndef __LASSO_PROTOCOLS_H__
#define __LASSO_PROTOCOLS_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <lasso/lasso.h>
#include <lasso/protocols/federation_termination_notification.h>
#include <lasso/protocols/logout.h>
#include <lasso/protocols/register_name_identifier.h>
#include <lasso/protocols/single_sign_on_and_federation.h>

GString *lasso_build_encoded_message_url(const char *authority,
					 LassoNode *request);
void lasso_sign_encoded_message(GString *message,
				const char *private_key_filename);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif  /* __LASSO_PROTOCOLS_H__ */
