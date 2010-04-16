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

#include <../lasso/lasso.h>
#include <../lasso/id-ff/provider.h>
#include "../lasso/utils.h"
#include "./tests.h"
#include "../lasso/xml/saml-2.0/saml2_xsd.h"

START_TEST(test01_metadata_load_der_certificate_from_x509_cert)
{
	LassoProvider *provider = lasso_provider_new(LASSO_PROVIDER_ROLE_SP,
			TESTSMETADATADIR "/metadata_01.xml", NULL, NULL);
	fail_unless(provider != NULL, "Can't load DER certificate from <ds:X509Certificate>");
	g_object_unref(provider);
}
END_TEST

START_TEST(test02_metadata_load_pem_certificate_from_x509_cert)
{
	LassoProvider *provider = lasso_provider_new(LASSO_PROVIDER_ROLE_SP,
			TESTSMETADATADIR "/metadata_02.xml", NULL, NULL);
	fail_unless(provider != NULL, "Can't load PEM certificate from <ds:X509Certificate>");
	g_object_unref(provider);
}
END_TEST

START_TEST(test03_metadata_load_der_public_key_from_keyvalue)
{
	LassoProvider *provider = lasso_provider_new(LASSO_PROVIDER_ROLE_SP,
			TESTSMETADATADIR "/metadata_03.xml", NULL, NULL);
	fail_unless(provider != NULL, "Can't load DER public key from <ds:KeyValue>");
	g_object_unref(provider);
}
END_TEST

START_TEST(test04_metadata_load_pem_public_key_from_keyvalue)
{
	LassoProvider *provider = lasso_provider_new(LASSO_PROVIDER_ROLE_SP,
			TESTSMETADATADIR "/metadata_04.xml", NULL, NULL);
	fail_unless(provider != NULL, "Can't load PEM public key from <ds:KeyValue>");
	g_object_unref(provider);
}
END_TEST

START_TEST(test05_metadata_load_public_key_from_x509_cert)
{
	LassoProvider *provider = lasso_provider_new(LASSO_PROVIDER_ROLE_SP,
			TESTSMETADATADIR "/metadata_05.xml", NULL, NULL);
	fail_unless(provider != NULL, "Can't load DER public key from <ds:X509Certificate>");
	g_object_unref(provider);
}
END_TEST

START_TEST(test06_metadata_load_public_key_from_rsa_keyvalue)
{
	LassoProvider *provider = lasso_provider_new(LASSO_PROVIDER_ROLE_SP,
			TESTSMETADATADIR "/metadata_06.xml", NULL, NULL);
	fail_unless(provider != NULL, "Can't load RSAKeyValue node");
	g_object_unref(provider);
}
END_TEST

START_TEST(test07_metadata_role_descriptors)
{
	LassoProvider *provider = (LassoProvider*)lasso_provider_new(LASSO_PROVIDER_ROLE_IDP, TESTSDATADIR "/idp6-saml2/metadata.xml",
			NULL, NULL);
	GList *l;
	int i = 0;

	check_not_null(provider);
	for (i = 1; i < LASSO_PROVIDER_ROLE_LAST; i *= 2) {
		l = lasso_provider_get_metadata_keys_for_role(provider, i);
		if (i == LASSO_PROVIDER_ROLE_IDP) {
			check_equals(g_list_length(l), 10);
		} else if (i == LASSO_PROVIDER_ROLE_AUTHN_AUTHORITY ||
				i == LASSO_PROVIDER_ROLE_AUTHZ_AUTHORITY ||
				i == LASSO_PROVIDER_ROLE_ATTRIBUTE_AUTHORITY) {
			check_equals(g_list_length(l), 3);
		}
		lasso_release_list_of_strings(l);
	}
	l = lasso_provider_get_metadata_list_for_role(provider, LASSO_PROVIDER_ROLE_IDP,
			LASSO_SAML2_METADATA_ATTRIBUTE_WANT_AUTHN_REQUEST_SIGNED);
	check_not_null(l);
	check_null(l->next);
	check_str_equals(l->data, "true");
	lasso_release_gobject(provider);
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
	TCase *tc_metadata_load_public_key_from_rsa_keyvalue =
		tcase_create("Load RSAKeyValue public key");
	TCase *tc_metadata_role_descriptors =
		tcase_create("Lookup different role descriptors datas");

	suite_add_tcase(s, tc_metadata_load_der_certificate_from_x509_cert);
	suite_add_tcase(s, tc_metadata_load_pem_certificate_from_x509_cert);
	suite_add_tcase(s, tc_metadata_load_der_public_key_from_keyvalue);
	suite_add_tcase(s, tc_metadata_load_pem_public_key_from_keyvalue);
	suite_add_tcase(s, tc_metadata_load_public_key_from_x509_cert);
	suite_add_tcase(s, tc_metadata_load_public_key_from_rsa_keyvalue);
	suite_add_tcase(s, tc_metadata_role_descriptors);
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
	tcase_add_test(tc_metadata_load_public_key_from_rsa_keyvalue,
		test06_metadata_load_public_key_from_rsa_keyvalue);
	tcase_add_test(tc_metadata_role_descriptors,
			test07_metadata_role_descriptors);
	return s;
}
