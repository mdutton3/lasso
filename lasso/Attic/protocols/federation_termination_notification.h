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
 * Foundation, Inc., 59 Templ
e Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef __FEDERATION_TERMINATION_NOTIFICATION_H__
#define __FEDERATION_TERMINATION_NOTIFICATION_H__

#include <lasso/protocols/protocols.h>

LassoNode *lasso_build_full_federationTerminationNotification(const xmlChar *requestID,
							      const xmlChar *majorVersion,
							      const xmlChar *minorVersion,
							      const xmlChar *issueInstant,
							      const xmlChar *providerID,
							      LassoNode     *nameIdentifier,
							      const xmlChar *consent);

LassoNode *lasso_build_federationTerminationNotification(const xmlChar *providerID,
							 LassoNode     *nameIdentifier,
							 const xmlChar *consent);

#endif /* __FEDERATION_TERMINATION_NOTIFICATION_H__ */
