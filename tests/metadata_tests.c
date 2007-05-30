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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdlib.h>
#include <string.h>

#include <check.h>

#include <lasso/lasso.h>
#include <lasso/id-ff/provider.h>

START_TEST(test01_metadata_load_der_certificate_from_x509_cert)
{
	LassoProvider *provider = lasso_provider_new(LASSO_PROVIDER_ROLE_SP,
			TESTSMETADATADIR "/metadata_01.xml", NULL, NULL);
	fail_unless(provider != NULL, "Can't load DER certificate from <ds:X509Certificate>");
}
END_TEST

START_TEST(test02_metadata_load_pem_certificate_from_x509_cert)
{
	LassoProvider *provider = lasso_provider_new(LASSO_PROVIDER_ROLE_SP,
			TESTSMETADATADIR "/metadata_02.xml", NULL, NULL);
	fail_unless(provider != NULL, "Can't load PEM certificate from <ds:X509Certificate>");
}
END_TEST

START_TEST(test03_metadata_load_der_public_key_from_keyvalue)
{
	LassoProvider *provider = lasso_provider_new(LASSO_PROVIDER_ROLE_SP,
			TESTSMETADATADIR "/metadata_03.xml", NULL, NULL);
	fail_unless(provider != NULL, "Can't load DER public key from <ds:KeyValue>");
}
END_TEST

START_TEST(test04_metadata_load_pem_public_key_from_keyvalue)
{
	LassoProvider *provider = lasso_provider_new(LASSO_PROVIDER_ROLE_SP,
			TESTSMETADATADIR "/metadata_04.xml", NULL, NULL);
	fail_unless(provider != NULL, "Can't load PEM public key from <ds:KeyValue>");
}
END_TEST

START_TEST(test05_metadata_load_public_key_from_x509_cert)
{
	LassoProvider *provider = lasso_provider_new(LASSO_PROVIDER_ROLE_SP,
			TESTSMETADATADIR "/metadata_05.xml", NULL, NULL);
	fail_unless(provider != NULL, "Can't load DER public key from <ds:X509Certificate>");
}
END_TEST


Suite*
metadata_suite()
{
	Suite *s = suite_create("Metadata");
	TCase *tc_metadata_load_der_certificate_from_x509_cert =
		tcase_create("Load DER certificate from metadata");
	TCase *tc_metadata_load_pem_certificate_from_x509_cert =
		tcase_create("Load PEM certificate from metadata");
	TCase *tc_metadata_load_der_public_key_from_keyvalue =
		tcase_create("Load DER public key from <ds:KeyValue>");
	TCase *tc_metadata_load_pem_public_key_from_keyvalue =
		tcase_create("Load PEM public key from <ds:KeyValue>");
	TCase *tc_metadata_load_public_key_from_x509_cert =
		tcase_create("Load DER public key from <ds:X509Certificate>");
	suite_add_tcase(s, tc_metadata_load_der_certificate_from_x509_cert);
	suite_add_tcase(s, tc_metadata_load_pem_certificate_from_x509_cert);
	suite_add_tcase(s, tc_metadata_load_der_public_key_from_keyvalue);
	suite_add_tcase(s, tc_metadata_load_pem_public_key_from_keyvalue);
	suite_add_tcase(s, tc_metadata_load_public_key_from_x509_cert);
	tcase_add_test(tc_metadata_load_der_certificate_from_x509_cert,
		test01_metadata_load_der_certificate_from_x509_cert);
	tcase_add_test(tc_metadata_load_pem_certificate_from_x509_cert,
		test02_metadata_load_pem_certificate_from_x509_cert);
	tcase_add_test(tc_metadata_load_der_public_key_from_keyvalue,
		test03_metadata_load_der_public_key_from_keyvalue);
	tcase_add_test(tc_metadata_load_pem_public_key_from_keyvalue,
		test04_metadata_load_pem_public_key_from_keyvalue);
	tcase_add_test(tc_metadata_load_public_key_from_x509_cert,
		test05_metadata_load_public_key_from_x509_cert);
	return s;
}
