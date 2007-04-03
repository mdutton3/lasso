/* $Id: wsf_profile_private.h,v 1.4 2005/10/06 15:03:56 nclapies Exp $ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004, 2005 Entr'ouvert
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

#ifndef __LASSO_WSF2_PROFILE_PRIVATE_H__
#define __LASSO_WSF2_PROFILE_PRIVATE_H__

#ifdef __cplusplus
extern "C" {

#endif /* __cplusplus */ 

#include <lasso/xml/soap_fault.h>

//void lasso_wsf_profile_set_description(LassoWsfProfile *profile,
//				       LassoDiscoDescription *description);
//void lasso_wsf_profile_set_security_mech_id(LassoWsfProfile *profile,
//					    const gchar *security_mech_id);
LassoSoapFault* lasso_wsf2_profile_get_fault(LassoWsf2Profile *profile);

void lasso_wsf2_profile_set_public_key(LassoWsf2Profile *profile, const char *public_key); 

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_WSF2_PROFILE_PRIVATE_H__ */
