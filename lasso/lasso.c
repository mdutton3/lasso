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

/**
 * SECTION:lasso
 * @short_description: Initialization functions
 *
 * <sec2>
 * <title>Environment variables</title>
 * <para>
 * <literal>LASSO_FLAG</literal> is an environment variable containing white-space separated values
 * which allows to modify the behaviour of lasso. To negate the effect of one of
 * the value, just add <literal>no-</literal> in front of its name. The flag are also modifiable
 * using the lasso_set_flag() function. Those values are:
 *
 * <informaltable frame="non">
 * <tgroup cols="2">
 * <tbody>
 * <rows>
 * <entry><literal>no-verify-signature</literal></entry>
 * <entry><para>Disable the validation of signatures on all message, usually for
 * debugging pupose</para></entry>
 * </rows>
 * <rows>
 * <entry><literal>memory-debug</literal></entry>
 * <entry><para>Enable the tracing of nodes allocation, deallocation and initialization.</para></entry>
 * </rows>
 * <rows id="strict-checking">
 * <entry><literal>strict-checking</literal></entry>
 * <entry><para>Enable checking which were not done in previous version of Lasso, like matching <literal>ResponseTo</literal> attributes of response messages to the identifier of the request.</para></entry>
 * </rows>
 * <rows>
 * <entry><literal>no-add-signature</literal></entry>
 * <entry><para>Disable all signatures</para></entry>
 * </rows>
 * <rows>
 * <entry><literal>no-sign-messages</literal></entry>
 * <entry><para>Disable signatures on messages.</para></entry>
 * </rows>
 * <rows>
 * <entry><literal>no-sign-messages</literal></entry>
 * <entry><para>Disable signatures on messages.</para></entry>
 * </rows>
 * </tbody>
 * </tgroup>
 * </informaltable>
 * </para>
 * </sec2>
 **/

#include <stdlib.h> /* getenv */
#include <string.h> /* strcmp */
#include <xmlsec/xmlsec.h>
#include <xmlsec/crypto.h>
#include <libxslt/xslt.h>
#include <config.h>
#include "lasso.h"
#include "lasso_config.h"
#include "debug.h"
#include "backward_comp.h"
#include "registry-private.h"
#include "xml/private.h"
#include "utils.h"

/* Set to true, it forces lasso_provider_verify_signature and lasso_query_verify_signature to always
 * return TRUE. */
gboolean lasso_flag_verify_signature = TRUE;
/* Set to true, it activates debugging code for LassoNode freeing */
gboolean lasso_flag_memory_debug = FALSE;
/* set to true, it activates more strict validation of messages */
gboolean lasso_flag_strict_checking = FALSE;
/* set to false, it does not sign messages */
gboolean lasso_flag_add_signature = TRUE;
static void lasso_flag_parse_environment_variable();
/* do not sign messages */
gboolean lasso_flag_sign_messages = TRUE;
/* thin sessions */
gboolean lasso_flag_thin_sessions = FALSE;

#ifndef LASSO_FLAG_ENV_VAR
#define LASSO_FLAG_ENV_VAR "LASSO_FLAG"
#endif

#if defined _MSC_VER
HINSTANCE g_hModule = NULL;

/**
 * DllMain:
 * @hinstDLL: hnadle to the DLL module
 * @fdwReason: reason value of the DLL call
 * @lpvReserved: use is unknown.
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

static void
lasso_xml_generic_error_func(G_GNUC_UNUSED void *ctx, const char *msg, ...)
{
	va_list args;

	va_start(args, msg);
	g_logv(LASSO_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, msg, args);
	va_end(args);
}

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
		return LASSO_ERROR_UNDEFINED;
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
		return LASSO_ERROR_UNDEFINED;
	}
#endif /* XMLSEC_CRYPTO_DYNAMIC_LOADING */

	/* Init crypto library */
	if (xmlSecCryptoAppInit(NULL) < 0) {
		message(G_LOG_LEVEL_CRITICAL, "Crypto initialization failed.");
		return LASSO_ERROR_UNDEFINED;
	}

	/* Init xmlsec-crypto library */
	if (xmlSecCryptoInit() < 0) {
		message(G_LOG_LEVEL_CRITICAL, "xmlsec-crypto initialization failed.");
		return LASSO_ERROR_UNDEFINED;
	}
	lasso_flag_parse_environment_variable();
	xmlSetGenericErrorFunc(NULL, lasso_xml_generic_error_func);
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

	/* Disallocate default registry */
	lasso_registry_default_shutdown();

	if (lasso_flag_memory_debug == TRUE) {
	/* this is to debug memory for regression tests */
		xmlMemoryDump();
	}
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
 * Return value: 1 if the loaded lasso library version is OK to use
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
		return 0;
	}

	if (mode == LASSO_CHECK_VERSION_EXACT) {
		if (minor != LASSO_VERSION_MINOR || subminor != LASSO_VERSION_SUBMINOR) {
			return 0;
		}
	}

	if (mode == LASSO_CHECK_VERSIONABI_COMPATIBLE) {
		if (minor < LASSO_VERSION_MINOR || (minor == LASSO_VERSION_MINOR &&
					subminor < LASSO_VERSION_SUBMINOR)) {
			return 0;
		}
	}

	if (mode > LASSO_CHECK_VERSION_NUMERIC)
		return LASSO_ERROR_UNDEFINED;

	return 1;
}

/**
 * lasso_set_flag:
 * @flag: a string representing a flag name, prefix with 'no-' to disable it.
 *
 * Set a debugging flag. You can also use the environment variable LASSO_FLAG
 * to get the same effect. LASSO_FLAG must contain flag name separated by spaces, commas,
 * tabulations or colons.
 */
void lasso_set_flag(char *flag) {
	gboolean value = TRUE;

	g_return_if_fail(flag);

	/* Handle negative flags */
	if (flag && strncmp(flag, "no-", 3) == 0) {
		value = FALSE;
		flag += 3;
	}

	do {
		if (lasso_strisequal(flag,"verify-signature")) {
			lasso_flag_verify_signature = value;
			continue;
		}
		if (lasso_strisequal(flag,"memory-debug")) {
			lasso_flag_memory_debug = value;
			continue;
		}
		if (lasso_strisequal(flag,"strict-checking")) {
			lasso_flag_strict_checking = value;
			continue;
		}
		if (lasso_strisequal(flag,"add-signature")) {
			lasso_flag_add_signature = value;
			continue;
		}
		if (lasso_strisequal(flag,"sign-messages")) {
			lasso_flag_sign_messages = value;
			continue;
		}
		if (lasso_strisequal(flag,"thin-sessions")) {
			lasso_flag_thin_sessions = value;
		}
	} while (FALSE);
}

static void lasso_flag_parse_environment_variable() {
	char *lasso_flag = getenv(LASSO_FLAG_ENV_VAR);
	char *save_ptr;
	char *token;
	const char delim[] = ", \t:";

	if (lasso_flag) {
		token = strtok_r(lasso_flag, delim, &save_ptr);
		do {
			lasso_set_flag(token);
		} while ((token = strtok_r(NULL, delim, &save_ptr)) != NULL);
	}
}
