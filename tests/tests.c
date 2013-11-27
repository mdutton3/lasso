/*
 * Lasso library C unit tests
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

#include <stdlib.h>
#include <string.h>
#include <config.h>

#include <check.h>
#include <glib.h>
#include "../lasso/lasso.h"
#include "../lasso/lasso_config.h"

extern Suite* basic_suite();
extern Suite* login_suite();
extern Suite* login_saml2_suite();
extern Suite* random_suite();
extern Suite* metadata_suite();
extern Suite* assertion_query_suite();
extern Suite* non_regression_suite();
#ifdef LASSO_WSF_ENABLED
extern Suite* idwsf2_suite();
#endif

typedef Suite* (*SuiteFunction) ();

SuiteFunction suites[] = {
	basic_suite,
	login_suite,
	login_saml2_suite,
	random_suite,
	metadata_suite,
	assertion_query_suite,
	non_regression_suite,
#ifdef LASSO_WSF_ENABLED
	idwsf2_suite,
#endif
	NULL
};
void error_logger(const gchar *log_domain, GLogLevelFlags log_level,
		const gchar *message, G_GNUC_UNUSED gpointer user_data)
{
	fail("No logging output expected: message «%s» was emitted for domain «%s» at the level"
			" «%d»", message, log_domain, log_level);
}

int
main(int argc, char *argv[])
{
	int rc = 0;
	SRunner *sr;
	int i;
	int dont_fork = 0;

	for (i=1; i<argc; i++) {
		if (strcmp(argv[i], "--dontfork") == 0) {
			dont_fork = 1;
		}
	}

	lasso_init();
	g_log_set_default_handler(error_logger, NULL);

	sr = srunner_create(suites[0]());

	i = 1;
	while (suites[i]) {
		srunner_add_suite(sr, suites[i]());
		i++;
	}

	if (dont_fork) {
		srunner_set_fork_status(sr, CK_NOFORK);
	}
#ifdef CHECK_IS_XML
	srunner_set_xml(sr, "result.xml");
#endif
	srunner_run_all (sr, CK_VERBOSE);
	rc = srunner_ntests_failed(sr);

	srunner_free(sr);
	/*suite_free(s);  */
	/* no longer available in check 0.9.0; it will leak a
	 * bit with previous versions */
	lasso_shutdown();

	return (rc == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

