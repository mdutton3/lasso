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

#include <xmlsec/xmlsec.h>
#include <xmlsec/crypto.h>
#include <libxslt/xslt.h>

#include "lasso.h"

#if defined _MSC_VER
HINSTANCE g_hModule = NULL; /**< DLL Instance. */
/** \brief Microsoft® Windows® DLL main function.
 *
 *  This function is called when the DLL is attached, detached from a program.
 *  
 *  \param  hinstDLL    Handle to the DLL module.
 *  \param  fdwReason   Reason value of the DLL call.
 *  \param  lpvReserved RFU.
 *
 *  \return TRUE is everything is ok.
 *  
 */
BOOL WINAPI
DllMain(
  HINSTANCE hinstDLL,  /* handle to the DLL module */
  DWORD fdwReason,     /* reason for calling function */
  LPVOID lpvReserved)  /* reserved */
{
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hinstDLL);
        g_hModule = hinstDLL;
    }
    return TRUE;
}
#endif

/**
 * lasso_init:
 *
 * Initializes Lasso library
 *
 * Return value: 0 on success or a negative value otherwise.
 */
int lasso_init()
{
  g_type_init();

  /* Init libxml and libxslt libraries */
  xmlInitParser();
  /*LIBXML_TEST_VERSION*/
  /* xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS; */
  /* xmlSubstituteEntitiesDefault(1); */

  /* Init xmlsec library */
  if(xmlSecInit() < 0) {
    message(G_LOG_LEVEL_ERROR, "XMLSec initialization failed.\n");
    return(-1);
  }
  
  /* Check loaded library version */
  if(xmlSecCheckVersion() != 1) {
    message(G_LOG_LEVEL_ERROR, "Loaded xmlsec library version is not compatible.\n");
    return(-1);
  }

  /* Load default crypto engine if we are supporting dynamic
   * loading for xmlsec-crypto libraries. Use the crypto library
   * name ("openssl", "nss", etc.) to load corresponding 
   * xmlsec-crypto library.
   */
#ifdef XMLSEC_CRYPTO_DYNAMIC_LOADING
  if(xmlSecCryptoDLLoadLibrary(BAD_CAST XMLSEC_CRYPTO) < 0) {
    message(G_LOG_LEVEL_ERROR, "Unable to load default xmlsec-crypto library. Make sure\n"
	    "that you have it installed and check shared libraries path\n"
	    "(LD_LIBRARY_PATH) envornment variable.\n");
    return(-1);	
  }
#endif /* XMLSEC_CRYPTO_DYNAMIC_LOADING */

  /* Init crypto library */
  if(xmlSecCryptoAppInit(NULL) < 0) {
    message(G_LOG_LEVEL_ERROR, "Crypto initialization failed.\n");
    return(-1);
  }
  
  /* Init xmlsec-crypto library */
  if(xmlSecCryptoInit() < 0) {
    message(G_LOG_LEVEL_ERROR, "xmlsec-crypto initialization failed.\n");
    return(-1);
  }
  return 0;
}

/**
 * lasso_shutdown:
 * 
 * Clean ups the Lasso Library.
 * 
 * Return value: 0 on success or a negative value otherwise.
 **/
int lasso_shutdown()
{
  /* Shutdown xmlsec-crypto library */
  xmlSecCryptoShutdown();
  
  /* Shutdown crypto library */
  xmlSecCryptoAppShutdown();
  
  /* Shutdown xmlsec library */
  xmlSecShutdown();
  
  /* Shutdown libxslt/libxml */
#ifndef XMLSEC_NO_XSLT
  xsltCleanupGlobals();            
#endif /* XMLSEC_NO_XSLT */
  /* Cleanup function for the XML library */
  xmlCleanupParser();
  /* this is to debug memory for regression tests */
  xmlMemoryDump();
  return (0);
}

/** 
 * lasso_check_version_ext:
 * @major:	the major version number.
 * @minor:	the minor version number.
 * @subminor:	the subminor version number.
 * @mode:	the version check mode.
 *
 * Checks if the loaded version of Lasso library could be used.
 *
 * Returns 1 if the loaded lasso library version is OK to use
 * 0 if it is not or a negative value if an error occurs.
 */
int 
lasso_check_version_ext(int major, int minor, int subminor, lassoCheckVersionMode mode)
{
  /* we always want to have a match for major version number */
  if (major != LASSO_VERSION_MAJOR) {
    g_message("expected major version=%d;real major version=%d",
	      LASSO_VERSION_MAJOR, major);
    return (0);
  }
  
  switch (mode) {
  case lassoCheckVersionExact:
    if ((minor != LASSO_VERSION_MINOR) || (subminor != LASSO_VERSION_SUBMINOR)) {
      g_message("mode=exact;expected minor version=%d;real minor version=%d;expected subminor version=%d;real subminor version=%d",
		LASSO_VERSION_MINOR, minor,
		LASSO_VERSION_SUBMINOR, subminor);
      return (0);
    }
    break;
  case lassoCheckVersionABICompatible:
    if ((minor < LASSO_VERSION_MINOR) ||
	((minor == LASSO_VERSION_MINOR) && (subminor < LASSO_VERSION_SUBMINOR))) {
      g_message("mode=abi compatible;expected minor version=%d;real minor version=%d;expected subminor version=%d;real subminor version=%d",
		LASSO_VERSION_MINOR, minor,
		LASSO_VERSION_SUBMINOR, subminor);
      return (0);
    }
    break;
  }
  
  return (1);
}
