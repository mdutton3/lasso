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

#ifndef __LASSO_PROVIDER_H__
#define __LASSO_PROVIDER_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */ 

#include <lasso/xml/xml.h>

#define LASSO_TYPE_PROVIDER (lasso_provider_get_type())
#define LASSO_PROVIDER(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), LASSO_TYPE_PROVIDER, LassoProvider))
#define LASSO_PROVIDER_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), LASSO_TYPE_PROVIDER, LassoProviderClass))
#define LASSO_IS_PROVIDER(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), LASSO_TYPE_PROVIDER))
#define LASSP_IS_PROVIDER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), LASSO_TYPE_PROVIDER))
#define LASSO_PROVIDER_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), LASSO_TYPE_PROVIDER, LassoProviderClass)) 

#define LASSO_PROVIDER_NODE             "LassoProvider"
#define LASSO_PROVIDER_PUBLIC_KEY_NODE  "PublicKey"
#define LASSO_PROVIDER_CERTIFICATE_NODE "Certificate"

typedef struct _LassoProvider LassoProvider;
typedef struct _LassoProviderClass LassoProviderClass;

struct _LassoProvider {
  GObject parent;

  LassoNode *metadata;

  gchar *public_key;
  gchar *certificate;

  /*< private >*/
};

struct _LassoProviderClass {
  GObjectClass parent;
};

LASSO_EXPORT GType          lasso_provider_get_type                                             (void);

LASSO_EXPORT LassoProvider *lasso_provider_new                                                  (gchar *metadata_filename,
												 gchar *public_key_filename,
												 gchar *certificate_filename);

LASSO_EXPORT LassoProvider *lasso_provider_new_metadata_xmlNode                                 (xmlNodePtr metadata_xmlNode);

LASSO_EXPORT LassoProvider *lasso_provider_new_metadata_filename                                (gchar *metadata_filename);

LASSO_EXPORT gchar         *lasso_provider_get_assertionConsumerServiceURL                      (LassoProvider *provider);

LASSO_EXPORT gchar         *lasso_provider_get_federationTerminationNotificationProtocolProfile (LassoProvider *provider);

LASSO_EXPORT gchar         *lasso_provider_get_federationTerminationNotificationServiceURL      (LassoProvider *provider);

LASSO_EXPORT gchar         *lasso_provider_dump                                                 (LassoProvider *provider);

LASSO_EXPORT gchar         *lasso_provider_get_providerID                                       (LassoProvider *provider);

LASSO_EXPORT gchar         *lasso_provider_get_registerNameIdentifierProtocolProfile            (LassoProvider *provider);

LASSO_EXPORT gchar         *lasso_provider_get_registerNameIdentifierServiceURL                 (LassoProvider *provider);

LASSO_EXPORT gchar         *lasso_provider_get_singleSignOnProtocolProfile                      (LassoProvider *provider);

LASSO_EXPORT gchar         *lasso_provider_get_singleSignOnServiceURL                           (LassoProvider *provider);

LASSO_EXPORT gchar         *lasso_provider_get_singleLogoutProtocolProfile                      (LassoProvider *provider);

LASSO_EXPORT gchar         *lasso_provider_get_singleLogoutServiceURL                           (LassoProvider *provider);

LASSO_EXPORT gchar         *lasso_provider_get_singleLogoutServiceReturnURL                     (LassoProvider *provider);

LASSO_EXPORT gchar*         lasso_provider_get_soapEndpoint                                     (LassoProvider *provider);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __LASSO_PROVIDER_H__ */
