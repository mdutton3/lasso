/* $Id$
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

#include <xmlsec/xmlsec.h>
#include <xmlsec/crypto.h>
#include <libxslt/xslt.h>

#include "lasso_config.h"
#include "lasso.h"

#if defined _MSC_VER
HINSTANCE g_hModule = NULL;

/**
 * DllMain:
 * @hinstDLL: hnadle to the DLL module
 * @fdwReason: reason value of the DLL call
 * @lpvReserved:
 *
 * Called when the DLL is attached or detached by a program.
 *
 * Return value: %TRUE if everything is OK
 **/
BOOL WINAPI
DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(hinstDLL);
		g_hModule = hinstDLL;
	}
	return TRUE;
}
#endif

#include "types.c"

/**
 * lasso_init:
 *
 * Initializes Lasso library.
 *
 * Return value: 0 on success; or a negative value otherwise.
 **/
int lasso_init()
{
	int i;

	g_type_init();

	/* Init Lasso classes */
	for (i=0; functions[i]; i++)
		functions[i]();

	/* Init libxml and libxslt libraries */
	xmlInitParser();
	/*LIBXML_TEST_VERSION*/
	/* xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS; */
	/* xmlSubstituteEntitiesDefault(1); */

	/* Init xmlsec library */
	if (xmlSecInit() < 0) {
		message(G_LOG_LEVEL_CRITICAL, "XMLSec initialization failed.");
		return -1;
	}

	/* Load default crypto engine if we are supporting dynamic
	 * loading for xmlsec-crypto libraries. Use the crypto library
	 * name ("openssl", "nss", etc.) to load corresponding 
	 * xmlsec-crypto library.
	 */
#ifdef XMLSEC_CRYPTO_DYNAMIC_LOADING
	if (xmlSecCryptoDLLoadLibrary(BAD_CAST XMLSEC_CRYPTO) < 0) {
		message(G_LOG_LEVEL_CRITICAL,
				"Unable to load default xmlsec-crypto library. Make sure"
				"that you have it installed and check shared libraries path"
				"(LD_LIBRARY_PATH) environment variable.");
		return -1;	
	}
#endif /* XMLSEC_CRYPTO_DYNAMIC_LOADING */

	/* Init crypto library */
	if (xmlSecCryptoAppInit(NULL) < 0) {
		message(G_LOG_LEVEL_CRITICAL, "Crypto initialization failed.");
		return -1;
	}

	/* Init xmlsec-crypto library */
	if (xmlSecCryptoInit() < 0) {
		message(G_LOG_LEVEL_CRITICAL, "xmlsec-crypto initialization failed.");
		return -1;
	}
	return 0;
}

/**
 * lasso_shutdown:
 * 
 * Clean ups Lasso library.
 * 
 * Return value: 0 on success; or a negative value otherwise.
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
#ifdef LASSO_DEBUG
	/* this is to debug memory for regression tests */
	xmlMemoryDump();
#endif
	return 0;
}

/** 
 * lasso_check_version:
 * @major: major version numbe
 * @minor: minor version number
 * @subminor: subminor version number
 * @mode: version check mode
 *
 * Checks if the loaded version of Lasso library could be used.
 *
 * Returns 1 if the loaded lasso library version is OK to use
 *     0 if it is not; or a negative value if an error occurs.
 **/
int 
lasso_check_version(int major, int minor, int subminor, LassoCheckVersionMode mode)
{
	if (mode == LASSO_CHECK_VERSION_NUMERIC) {
		if (LASSO_VERSION_MAJOR*10000 + LASSO_VERSION_MINOR*100 + LASSO_VERSION_SUBMINOR <
				major*10000 + minor*100 + subminor)
			return 0;
		return 1;
	}
	/* we always want to have a match for major version number */
	if (major != LASSO_VERSION_MAJOR) {
		g_message("expected major version=%d;real major version=%d",
				LASSO_VERSION_MAJOR, major);
		return 0;
	}

	if (mode == LASSO_CHECK_VERSION_EXACT) {
		if (minor != LASSO_VERSION_MINOR || subminor != LASSO_VERSION_SUBMINOR) {
			g_message("mode=exact;expected minor version=%d;"
					"real minor version=%d;expected subminor version=%d;"
					"real subminor version=%d",
					LASSO_VERSION_MINOR, minor,
					LASSO_VERSION_SUBMINOR, subminor);
			return 0;
		}
	}

	if (mode == LASSO_CHECK_VERSIONABI_COMPATIBLE) {
		if (minor < LASSO_VERSION_MINOR || (minor == LASSO_VERSION_MINOR && 
					subminor < LASSO_VERSION_SUBMINOR)) {
			g_message("mode=abi compatible;expected minor version=%d;"
					"real minor version=%d;expected subminor version=%d;"
					"real subminor version=%d",
					LASSO_VERSION_MINOR, minor,
					LASSO_VERSION_SUBMINOR, subminor);
			return 0;
		}
	}

	if (mode > LASSO_CHECK_VERSION_NUMERIC)
		return -1;

	return 1;
}
