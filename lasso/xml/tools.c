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

/* permit importation of strptime for glibc2 */
#define _XOPEN_SOURCE
/* permit importation of timegm for glibc2, wait for people to complain it does not work on their
 * system. */
#define _BSD_SOURCE
#include "private.h"
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <stdarg.h>

#include <libxml/uri.h>
#include <libxml/parser.h>
#include <libxml/parserInternals.h>
#include <libxml/xmlIO.h>

#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/engine.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include <xmlsec/base64.h>
#include <xmlsec/crypto.h>
#include <xmlsec/templates.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/errors.h>
#include <xmlsec/openssl/x509.h>
#include <xmlsec/openssl/crypto.h>
#include <xmlsec/soap.h>

#include <zlib.h>

#include <glib.h>
#include "xml.h"
#include "xml_enc.h"
#include "saml-2.0/saml2_assertion.h"
#include <unistd.h>
#include "../debug.h"
#include "../utils.h"
#include <stdarg.h>
#include <ctype.h>
#include "../lasso_config.h"

/**
 * SECTION:tools
 * @short_description: Misc functions used inside Lasso
 * @stability: Internal
 */

/* A query string can be 3 times larger than the byte string value, because of the octet encoding
 * %xx */
const int query_string_attribute_length_limit = 8192 * 3;
static xmlSecKeyPtr lasso_get_public_key_from_private_key_file(const char *private_key_file);
static gboolean is_base64(const char *message);
static void xmlDetectSAX2(xmlParserCtxtPtr ctxt);

/**
 * lasso_build_random_sequence:
 * @buffer: buffer to fill with random sequence
 * @size: the sequence size in byte (character)
 *
 * Builds a random sequence of [0-9A-F] characters of size @size.
 *
 * Return value: None
 **/
void
lasso_build_random_sequence(char *buffer, unsigned int size)
{
	char *t;
	unsigned int rnd, i;

	t = buffer;
	while (t-buffer < (int)size) {
		rnd = g_random_int();
		for (i=0; i<sizeof(int); i++) {
			*(t++) = '0' + ((rnd>>i*4)&0xf);
			if (*(t-1) > '9') *(t-1) += 7;
		}
	}
}

/**
 * lasso_build_unique_id:
 * @size: the ID's length (between 32 and 40)
 *
 * Builds an ID which has an unicity probability of 2^(-size*4).
 *
 * Return value:(transfer full): a "unique" ID (begin always with _ character)
 **/
char*
lasso_build_unique_id(unsigned int size)
{
	/*
	 * When generating one-time-use identifiers for Principals, in the
	 * case that a pseudorandom technique is employed, the probability
	 * of two randomly chosen identifiers being identical MUST be less
	 * than or equal to 2-128 and SHOULD be less than or equal to 2-160.
	 * These levels correspond, respectively, to use of strong 128-bit
	 * and 160-bit hash functions, in conjunction with sufficient input
	 * entropy.
	 *   -- 3.1.4 Name Identifier Construction
	 *      in « Liberty ID-FF Protocols and Schema Specification »
	 */
	char *result;

	g_assert(size >= 32);

	result = g_malloc(size+2); /* trailing \0 and leading _ */
	result[0] = '_';
	lasso_build_random_sequence(result+1, size);
	result[size+1] = 0;
	return result;
}

/**
 * lasso_time_to_iso_8601_gmt:
 * @now: a #time_t value
 *
 * Format the given time as an ISO 8601 date-time value in UTC.
 *
 * Return value:(transfer full): an ISO 9601 formatted string.
 */
char*
lasso_time_to_iso_8601_gmt(time_t now)
{
	struct tm *tm;
	char *ret;

	ret = g_malloc(21);
	tm = gmtime(&now);
	strftime(ret, 21, "%Y-%m-%dT%H:%M:%SZ", tm);

	return ret;
}

/**
 * lasso_get_current_time:
 *
 * Returns the current time, format is "yyyy-mm-ddThh:mm:ssZ".
 *
 * Return value: a string
 **/
char*
lasso_get_current_time()
{
	return lasso_time_to_iso_8601_gmt(time(NULL));
}

static const char xsdtime_format1[] = "dddd-dd-ddTdd:dd:ddZ";
static const char xsdtime_format2[] = "dddd-dd-ddTdd:dd:dd.?Z";

static gboolean
xsdtime_match_format(const char *xsdtime, const char *format)
{
	while (*format && *xsdtime) {
		if (*format == 'd' && isdigit(*xsdtime)) {
			++format;
			++xsdtime;
		} else if (*format == '?') {
			while (isdigit(*xsdtime))
				++xsdtime;
			++format;
		} else if (*format == *xsdtime) {
			++format;
			++xsdtime;
		} else {
			break;
		}
	}
	if (*format == '\0' && *xsdtime == '\0') {
		return TRUE;
	} else {
		return FALSE;
	}
}

/**
 * lasso_iso_8601_gmt_to_time_t:
 * @xsdtime: an xsd time value
 *
 * Return value: a corresponding time_t value if possible.
 */
time_t
lasso_iso_8601_gmt_to_time_t(const char *xsdtime)
{
	struct tm tm;
	char *strptime_ret;

	if (xsdtime == NULL) {
		return -1;
	}

	if (xsdtime_match_format(xsdtime, xsdtime_format1)) {
		strptime_ret = strptime (xsdtime, "%Y-%m-%dT%H:%M:%SZ", &tm);
		if (strptime_ret == NULL) {
			return -1;
		}
	} else if (xsdtime_match_format(xsdtime, xsdtime_format2)) {
		strptime_ret = strptime (xsdtime, "%Y-%m-%dT%H:%M:%S.", &tm);
		if (strptime_ret == NULL) {
			return -1;
		}
	}
	return timegm(&tm);
}

/**
 * lasso_get_pem_file_type:
 * @pem_file: a pem file
 *
 * Gets the type of a pem file.
 *
 * Return value: the pem file type
 **/
LassoPemFileType
lasso_get_pem_file_type(const char *pem_file)
{
	BIO* bio;
	EVP_PKEY *pkey;
	X509 *cert;
	LassoPemFileType type = LASSO_PEM_FILE_TYPE_UNKNOWN;

	g_return_val_if_fail(pem_file != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	bio = BIO_new_file(pem_file, "rb");
	if (bio == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "Failed to open %s pem file", pem_file);
		return LASSO_PEM_FILE_TYPE_UNKNOWN;
	}

	pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
	if (pkey != NULL) {
		type = LASSO_PEM_FILE_TYPE_PUB_KEY;
		EVP_PKEY_free(pkey);
	} else {
		if (BIO_reset(bio) == 0) {
			pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
			if (pkey != NULL) {
				type = LASSO_PEM_FILE_TYPE_PRIVATE_KEY;
				EVP_PKEY_free(pkey);
			} else {
				if (BIO_reset(bio) == 0) {
					cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
					if (cert != NULL) {
						type = LASSO_PEM_FILE_TYPE_CERT;
						X509_free(cert);
					}
				}
			}
		}
	}
	BIO_free(bio);

	return type;
}

/**
 * lasso_get_public_key_from_pem_file:
 * @file: the name of a file containing a public key
 *
 * Load a public key from a file in the PEM format.
 *
 * Returns: a #xmlSecKey if one is found, NULL otherwise.
 */
xmlSecKeyPtr lasso_get_public_key_from_pem_file(const char *file) {
	LassoPemFileType file_type;
	xmlSecKeyPtr pub_key = NULL;

	file_type = lasso_get_pem_file_type(file);
	switch (file_type) {
		case LASSO_PEM_FILE_TYPE_UNKNOWN:
			message(G_LOG_LEVEL_CRITICAL, "PEM file type unknown: %s", file);
			break; /* with a warning ? */
		case LASSO_PEM_FILE_TYPE_CERT:
			pub_key = lasso_get_public_key_from_pem_cert_file(file);
			break;
		case LASSO_PEM_FILE_TYPE_PUB_KEY:
			pub_key = xmlSecCryptoAppKeyLoad(file,
					xmlSecKeyDataFormatPem, NULL, NULL, NULL);
			break;
		case LASSO_PEM_FILE_TYPE_PRIVATE_KEY:
			pub_key = lasso_get_public_key_from_private_key_file(file);

			break; /* with a warning ? */
	}
	return pub_key;
}
/**
 * lasso_get_public_key_from_pem_cert_file:
 * @pem_cert_file: an X509 pem certificate file
 *
 * Gets the public key in an X509 pem certificate file.
 *
 * Return value: a public key or NULL if an error occurs.
 **/
xmlSecKeyPtr
lasso_get_public_key_from_pem_cert_file(const char *pem_cert_file)
{
	FILE *fd;
	X509 *pem_cert;
	xmlSecKeyDataPtr data;
	xmlSecKeyPtr key = NULL;

	g_return_val_if_fail(pem_cert_file != NULL, NULL);

	/* load pem certificate from file */
	fd = fopen(pem_cert_file, "r");
	if (fd == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "Failed to open %s pem certificate file",
				pem_cert_file);
		return NULL;
	}
	/* read the pem X509 certificate */
	pem_cert = PEM_read_X509(fd, NULL, NULL, NULL);
	fclose(fd);
	if (pem_cert == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "Failed to read X509 certificate");
		return NULL;
	}

	/* get public key value in certificate */
	data = xmlSecOpenSSLX509CertGetKey(pem_cert);
	if (data != NULL) {
		/* create key and set key value */
		key = xmlSecKeyCreate();
		xmlSecKeySetValue(key, data);
	} else {
		message(G_LOG_LEVEL_CRITICAL,
				"Failed to get the public key in the X509 certificate");
	}
	X509_free(pem_cert);

	return key;
}

/**
 * lasso_get_public_key_from_private_key_file:
 * @private_key_file: the name of a file containing a private key in PEM format
 *
 * Load a public key from a private key.
 *
 * Returns: a new $xmlSecKey containing the private key
 */
static xmlSecKeyPtr
lasso_get_public_key_from_private_key_file(const char *private_key_file)
{
	return xmlSecCryptoAppKeyLoad(private_key_file,
			xmlSecKeyDataFormatPem, NULL, NULL, NULL);
}

/**
 * lasso_load_certs_from_pem_certs_chain_file:
 * @pem_certs_chain_file: a CA certificate chain file
 *
 * Creates a keys manager and loads inside all the CA certificates of
 * @pem_certs_chain_file. Caller is responsible for freeing it with
 * xmlSecKeysMngrDestroy() function.
 *
 * Return value: a newly allocated keys manager or NULL if an error occurs.
 **/
xmlSecKeysMngrPtr
lasso_load_certs_from_pem_certs_chain_file(const char* pem_certs_chain_file)
{
	xmlSecKeysMngrPtr keys_mngr = NULL;
	GIOChannel *gioc = NULL;
	gchar *line = NULL;
	gsize len, pos;
	GString *cert = NULL;
	gint ret;
	gint certificates = 0;

	/* No file just return NULL */
	goto_cleanup_if_fail (pem_certs_chain_file && strlen(pem_certs_chain_file) != 0);
	gioc = g_io_channel_new_file(pem_certs_chain_file, "r", NULL);
	if (! gioc) {
		message(G_LOG_LEVEL_CRITICAL, "Cannot open chain file %s", pem_certs_chain_file);
		goto cleanup;
	}

	keys_mngr = xmlSecKeysMngrCreate();
	if (keys_mngr == NULL) {
		message(G_LOG_LEVEL_CRITICAL,
				lasso_strerror(LASSO_DS_ERROR_KEYS_MNGR_CREATION_FAILED));
		goto cleanup;
	}

	/* initialize keys manager */
	if (xmlSecCryptoAppDefaultKeysMngrInit(keys_mngr) < 0) {
		message(G_LOG_LEVEL_CRITICAL,
				lasso_strerror(LASSO_DS_ERROR_KEYS_MNGR_INIT_FAILED));
		xmlSecKeysMngrDestroy(keys_mngr);
		goto cleanup;
	}

	while (g_io_channel_read_line(gioc, &line, &len, &pos, NULL) == G_IO_STATUS_NORMAL) {
		if (line != NULL && g_strstr_len(line, 64, "BEGIN CERTIFICATE") != NULL) {
			cert = g_string_new(line);
		} else if (cert != NULL && line != NULL && g_strstr_len(line, 64, "END CERTIFICATE") != NULL) {
			g_string_append(cert, line);
			/* load the new certificate found in the keys manager */
			/* create keys manager */
			ret = xmlSecCryptoAppKeysMngrCertLoadMemory(keys_mngr,
					(const xmlSecByte*) cert->str,
					(xmlSecSize) cert->len,
					xmlSecKeyDataFormatPem,
					xmlSecKeyDataTypeTrusted);
			if (ret < 0) {
				goto cleanup;
			}
			certificates++;
			lasso_release_gstring(cert, TRUE);
			cert = NULL;
		} else if (cert != NULL && line != NULL && line[0] != '\0') {
			g_string_append(cert, line);
		}
		/* free last line read */
		lasso_release_string(line);
	}

cleanup:
	if (gioc) {
		g_io_channel_shutdown(gioc, TRUE, NULL);
		g_io_channel_unref(gioc);
	}
	if (cert)
		lasso_release_gstring(cert, TRUE);
	if (certificates == 0)
		lasso_release_key_manager(keys_mngr);
	lasso_release_string(line);

	return keys_mngr;
}

/*
 * lasso_query_sign:
 * @query: a query (an url-encoded node)
 * @sign_method: the Signature transform method
 * @private_key_file: the private key
 * @private_key_file_password: the private key password
 *
 * Signs a query (url-encoded message).
 *
 * Return value: a newly allocated query signed or NULL if an error occurs.
 **/
char*
lasso_query_sign(char *query, LassoSignatureContext context)
{
	char *digest = NULL; /* 160 bit buffer */
	RSA *rsa = NULL;
	DSA *dsa = NULL;
	unsigned char *sigret = NULL;
	unsigned int siglen = 0;
	xmlChar *b64_sigret = NULL, *e_b64_sigret = NULL;
	char *new_query = NULL, *s_new_query = NULL;
	int status = 0;
	const xmlChar *algo_href = NULL;
	char *hmac_key;
	size_t hmac_key_length;
	const EVP_MD *md;
	xmlSecKey *key;
	xmlSecKeyData *key_data;
	unsigned int sigret_size = 0;
	LassoSignatureMethod sign_method;

	g_return_val_if_fail(query != NULL, NULL);
	g_return_val_if_fail(lasso_validate_signature_method(context.signature_method), NULL);

	key = context.signature_key;
	sign_method = context.signature_method;
	key_data = xmlSecKeyGetValue(key);


	/* add SigAlg */
	switch (sign_method) {
		case LASSO_SIGNATURE_METHOD_RSA_SHA1:
			algo_href = xmlSecHrefRsaSha1;
			break;
		case LASSO_SIGNATURE_METHOD_DSA_SHA1:
			algo_href = xmlSecHrefDsaSha1;
			break;
		case LASSO_SIGNATURE_METHOD_HMAC_SHA1:
			algo_href = xmlSecHrefHmacSha1;
			break;
		case LASSO_SIGNATURE_METHOD_NONE:
		case LASSO_SIGNATURE_METHOD_LAST:
			g_assert_not_reached();
	}

	{
		const char *t = (char*)xmlURIEscapeStr(algo_href, NULL);
		new_query = g_strdup_printf("%s&SigAlg=%s", query, t);
		xmlFree(BAD_CAST t);
	}

	/* build buffer digest */
	digest = lasso_sha1(new_query);
	if (digest == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "Failed to build the buffer digest");
		goto done;
	}
	/* extract the OpenSSL key */
	switch (sign_method) {
		case LASSO_SIGNATURE_METHOD_RSA_SHA1:
			rsa = xmlSecOpenSSLKeyDataRsaGetRsa(key_data);
			g_assert(rsa);
			/* alloc memory for sigret */
			sigret_size = RSA_size(rsa);
			break;
		case LASSO_SIGNATURE_METHOD_DSA_SHA1:
			dsa = xmlSecOpenSSLKeyDataDsaGetDsa(key_data);
			g_assert(dsa);
			/* alloc memory for sigret */
			sigret_size = DSA_size(dsa);
			break;
		case LASSO_SIGNATURE_METHOD_HMAC_SHA1:
			lasso_get_hmac_key(key, (void**)&hmac_key,
					&hmac_key_length);
			g_assert(hmac_key);
			md = EVP_sha1();
			sigret_size = EVP_MD_size(md);
			/* key should be at least 128 bits long */
			if (hmac_key_length < 16) {
				critical("HMAC key should be at least 128 bits long");
				goto done;
			}
			break;
		default:
			g_assert_not_reached();
	}
	sigret = (unsigned char *)g_malloc (sigret_size);

	switch (sign_method) {
		case LASSO_SIGNATURE_METHOD_RSA_SHA1:
			/* sign digest message */
			status = RSA_sign(NID_sha1, (unsigned char*)digest, 20, sigret,
					&siglen, rsa);
			break;
		case LASSO_SIGNATURE_METHOD_DSA_SHA1:
			status = DSA_sign(NID_sha1, (unsigned char*)digest, 20, sigret,
					&siglen, dsa);
			break;
		case LASSO_SIGNATURE_METHOD_HMAC_SHA1:
			HMAC(md, hmac_key, hmac_key_length, (unsigned char *)new_query,
					strlen(new_query), sigret, &siglen);
			status = 1;
			break;
		case LASSO_SIGNATURE_METHOD_LAST:
		case LASSO_SIGNATURE_METHOD_NONE:
			g_assert_not_reached();
	}

	g_assert(siglen == sigret_size);

	if (status == 0) {
		goto done;
	}

	/* Base64 encode the signature value */
	b64_sigret = xmlSecBase64Encode(sigret, sigret_size, 0);
	/* escape b64_sigret */
	e_b64_sigret = xmlURIEscapeStr((xmlChar*)b64_sigret, NULL);

	/* add signature */
	switch (sign_method) {
		case LASSO_SIGNATURE_METHOD_RSA_SHA1:
		case LASSO_SIGNATURE_METHOD_DSA_SHA1:
		case LASSO_SIGNATURE_METHOD_HMAC_SHA1:
			s_new_query = g_strdup_printf("%s&Signature=%s", new_query, (char*)
					e_b64_sigret);
			break;
		case LASSO_SIGNATURE_METHOD_NONE:
		case LASSO_SIGNATURE_METHOD_LAST:
			g_assert_not_reached();
	}

done:
	lasso_release(new_query);
	lasso_release_string(digest);
	lasso_release(sigret);
	lasso_release_xml_string(b64_sigret);
	lasso_release_xml_string(e_b64_sigret);

	return s_new_query;
}

LassoNode*
lasso_assertion_encrypt(LassoSaml2Assertion *assertion, char *recipient)
{
	xmlSecKey *encryption_public_key = NULL;
	LassoEncryptionSymKeyType encryption_sym_key_type = 0;
	LassoNode *ret = NULL;

	lasso_node_get_encryption((LassoNode*)assertion, &encryption_public_key,
			&encryption_sym_key_type);
	if (! encryption_public_key) {
		return NULL;
	}

	ret = LASSO_NODE(lasso_node_encrypt(LASSO_NODE(assertion),
		encryption_public_key, encryption_sym_key_type, recipient));
	lasso_release_sec_key(encryption_public_key);
	return ret;

}

static lasso_error_t
lasso_query_verify_helper(const char *signed_content, const char *b64_signature, const char *algorithm,
		const xmlSecKey *key)
{
	RSA *rsa = NULL;
	DSA *dsa = NULL;
	char *digest = NULL;
	xmlSecByte *signature = NULL;
	int key_size = 0;
	unsigned char *hmac_key = NULL;
	size_t hmac_key_length = 0;
	const EVP_MD *md = NULL;
	lasso_error_t rc = 0;
	LassoSignatureMethod method = LASSO_SIGNATURE_METHOD_NONE;

	if (lasso_strisequal(algorithm, (char*)xmlSecHrefRsaSha1)) {
		goto_cleanup_if_fail_with_rc(key->value->id == xmlSecOpenSSLKeyDataRsaId,
				LASSO_DS_ERROR_INVALID_SIGALG)
		rsa = xmlSecOpenSSLKeyDataRsaGetRsa(key->value);
		key_size = RSA_size(rsa);
		method = LASSO_SIGNATURE_METHOD_RSA_SHA1;
	} else if (lasso_strisequal(algorithm, (char*)xmlSecHrefDsaSha1)) {
		goto_cleanup_if_fail_with_rc(key->value->id == xmlSecOpenSSLKeyDataDsaId, LASSO_DS_ERROR_INVALID_SIGALG);
		dsa = xmlSecOpenSSLKeyDataDsaGetDsa(key->value);
		key_size = DSA_size(dsa);
		method = LASSO_SIGNATURE_METHOD_DSA_SHA1;
	} else if (lasso_strisequal(algorithm, (char*)xmlSecHrefHmacSha1)) {
		lasso_check_good_rc(lasso_get_hmac_key(key, (void**)&hmac_key, &hmac_key_length));
		md = EVP_sha1();
		key_size = EVP_MD_size(md);
		method = LASSO_SIGNATURE_METHOD_HMAC_SHA1;
	} else {
		goto_cleanup_with_rc(LASSO_DS_ERROR_INVALID_SIGALG);
	}
	/* decode signature */
	signature = g_malloc(key_size+1);
	goto_cleanup_if_fail_with_rc(
			xmlSecBase64Decode((xmlChar*)b64_signature, signature, key_size+1) != 0,
			LASSO_DS_ERROR_INVALID_SIGNATURE);
	/* digest */
	switch (method) {
		case LASSO_SIGNATURE_METHOD_RSA_SHA1:
		case LASSO_SIGNATURE_METHOD_DSA_SHA1:
			digest = lasso_sha1(signed_content);
			break;
		default:
			break;
	}
	/* verify signature */
	switch (method) {
		case LASSO_SIGNATURE_METHOD_RSA_SHA1:
			goto_cleanup_if_fail_with_rc(
					RSA_verify(
						NID_sha1,
						(unsigned char*)digest,
						20,
						signature,
						key_size, rsa) == 1,
					LASSO_DS_ERROR_INVALID_SIGNATURE);
			break;
		case LASSO_SIGNATURE_METHOD_DSA_SHA1:
			goto_cleanup_if_fail_with_rc(
					DSA_verify(NID_sha1,
						(unsigned char*)digest,
						20,
						signature,
						key_size, dsa) == 1,
					LASSO_DS_ERROR_INVALID_SIGNATURE);
			break;
		case LASSO_SIGNATURE_METHOD_HMAC_SHA1:
			digest = g_malloc(key_size);
			HMAC(md, hmac_key, hmac_key_length, (unsigned char*)signed_content,
				strlen(signed_content), (unsigned char*)digest, NULL);

			goto_cleanup_if_fail_with_rc(lasso_crypto_memequal(digest, signature,
						key_size),
					LASSO_DS_ERROR_INVALID_SIGNATURE);
			break;
		case LASSO_SIGNATURE_METHOD_NONE:
		case LASSO_SIGNATURE_METHOD_LAST:
			g_assert_not_reached();
	}
cleanup:
	lasso_release_string(digest);
	lasso_release_string(signature);
	return rc;

}

/**
 * lasso_query_verify_signature:
 * @query: a query (an url-encoded message)
 * @sender_public_key: the query sender public key
 *
 * Verifies the query signature.
 *
 * Return value: 0 if signature is valid
 * a positive value if signature was not found or is invalid
 * a negative value if an error occurs during verification
 **/
lasso_error_t
lasso_query_verify_signature(const char *query, const xmlSecKey *sender_public_key)
{
	gchar **str_split = NULL;
	char *b64_signature = NULL;
	char *sig_alg = NULL;
	char *usig_alg = NULL;
	lasso_error_t rc = 0;

	g_return_val_if_fail(query != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	if (lasso_flag_verify_signature == FALSE) {
		return 0;
	}

	g_return_val_if_fail(sender_public_key != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);
	g_return_val_if_fail(sender_public_key->value != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	/* split query, the signature MUST be the last param of the query
	 * actually there could be more params in the URL; but they wouldn't be
	 * covered by the signature */

	str_split = g_strsplit(query, "&Signature=", 0);
	if (str_split[0] == NULL || str_split[1] == NULL)
		goto_cleanup_with_rc(LASSO_DS_ERROR_SIGNATURE_NOT_FOUND);
	sig_alg = strstr(str_split[0], "&SigAlg=");
	if (sig_alg == NULL)
		goto_cleanup_with_rc(LASSO_DS_ERROR_INVALID_SIGALG);
	sig_alg = strchr(sig_alg, '=')+1;
	usig_alg = xmlURIUnescapeString(sig_alg, 0, NULL);
	/* insure there is only the signature in str_split[1] */
	if (strchr(str_split[1], '&')) {
		strchr(str_split[1], '&')[0] = 0;
	}

	/* get signature (unescape + base64 decode) */
	b64_signature = (char*)xmlURIUnescapeString(str_split[1], 0, NULL);
	lasso_check_good_rc(lasso_query_verify_helper(str_split[0],
				b64_signature, usig_alg, sender_public_key));


cleanup:
	if (b64_signature)
		xmlFree(b64_signature);
	if (usig_alg)
		xmlFree(usig_alg);
	g_strfreev(str_split);
	return rc;
}

/**
 * lasso_saml2_query_verify_signature:
 * @query: a query string
 * @sender_public_key: the #xmlSecKey for the sender
 *
 * Verify a query signature following SAML 2.0 semantic.
 *
 * Return value: 0 if signature is validated, an error code otherwise.
 */
int
lasso_saml2_query_verify_signature(const char *query, const xmlSecKey *sender_public_key)
{
	char *b64_signature = NULL;
	char *query_copy = NULL;
	char *signed_query = NULL;
	char *i = NULL;
	char **components = NULL, **j = NULL;
	int n = 0;
	char *saml_request_response = NULL;
	char *relaystate = NULL;
	char *sig_alg, *usig_alg = NULL;
	lasso_error_t rc = 0;

	lasso_return_val_if_fail(query != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);
	lasso_return_val_if_fail(lasso_flag_verify_signature, 0);
	lasso_return_val_if_fail(sender_public_key != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);
	lasso_return_val_if_fail(sender_public_key->value != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

	/* extract fields */
	i = query_copy = g_strdup(query);
	n = 1;
	while (*i) {
		if (*i == '&' || *i == ';')
			n++;
		i++;
	}
	components = g_new0(char*, n+1);
	components[n] = NULL;
	n = 0;
	i = query_copy;
	components[n] = query_copy;
	n += 1;
	while (*i) {
		if (*i == '&' || *i == ';') {
			*i = '\0';
			components[n] = i + 1;
			n++;
		}
		i++;
	}
	/* extract specific fields */
	j = components;
#define match_field(x) \
	(strncmp(x "=", *j, sizeof(x)) == 0)
#define value strchr(*j, '=') + 1
	while (*j) {
		if (match_field(LASSO_SAML2_FIELD_RESPONSE)
				|| match_field(LASSO_SAML2_FIELD_REQUEST)) {
			saml_request_response = *j;
		} else if (match_field(LASSO_SAML2_FIELD_RELAYSTATE)) {
			relaystate = *j;
		} else if (match_field(LASSO_SAML2_FIELD_SIGALG)) {
			sig_alg = *j;
		} else if (match_field(LASSO_SAML2_FIELD_SIGNATURE)) {
			b64_signature = value;
			b64_signature = xmlURIUnescapeString(b64_signature, 0, NULL);
		}
		++j;
	}
#undef match_field
#undef value

	if (! saml_request_response) {
		message(G_LOG_LEVEL_CRITICAL, "SAMLRequest or SAMLResponse missing in query");
		goto_cleanup_with_rc(LASSO_PROFILE_ERROR_INVALID_QUERY);
	}

	if (! b64_signature) {
		goto_cleanup_with_rc(LASSO_DS_ERROR_SIGNATURE_NOT_FOUND);
	}
	/* build the signed query */
	if (relaystate) {
		signed_query = g_strconcat(saml_request_response, "&", relaystate, "&", sig_alg, NULL);
	} else {
		signed_query = g_strconcat(saml_request_response, "&", sig_alg, NULL);
	}

	sig_alg = strchr(sig_alg, '=')+1;
	if (! sig_alg) {
		goto_cleanup_with_rc(LASSO_DS_ERROR_INVALID_SIGALG);
	}
	usig_alg = xmlURIUnescapeString(sig_alg, 0, NULL);
	lasso_check_good_rc(lasso_query_verify_helper(signed_query, b64_signature, usig_alg,
				sender_public_key));


cleanup:
	if (b64_signature)
		xmlFree(b64_signature);
	if (usig_alg)
		xmlFree(usig_alg);
	lasso_release(components);
	lasso_release(query_copy);
	lasso_release(signed_query);

	return rc;
}

/**
 * lasso_sha1:
 * @str: a string
 *
 * Builds the SHA-1 message digest (cryptographic hash) of @str
 *
 * Return value: 20-bytes buffer allocated with xmlMalloc
 **/
char*
lasso_sha1(const char *str)
{
	xmlChar *md;

	if (str == NULL)
		return NULL;

	md = g_malloc(20);
	return (char*)SHA1((unsigned char*)str, strlen(str), md);
}

char**
urlencoded_to_strings(const char *str)
{
	int i, n=1;
	char *st, *st2;
	char **result;

	/* count components */
	st = (char*)str;
	while (*st) {
		if (*st == '&' || *st == ';')
			n++;
		n++;
		st++;
	}

	/* allocate result array */
	result = g_new0(char*, n+1);
	result[n] = NULL;

	/* tokenize */
	st = st2 = (char*)str;
	i = 0;
	while(1) {
		if (*st == '&' || *st == ';' || *st == '\0') {
			ptrdiff_t len = st - st2;
			if (len) {
				result[i] = xmlURIUnescapeString(st2, len, NULL);
			} else {
				result[i] = g_malloc0(1);
			}
			i++;
			st2 = st + 1;
			if (*st == '\0')
				break;
		}
		st++;
	}

	return result;
}

void _lasso_xmlsec_password_callback() {
}

/**
 * lasso_sign_node:
 * @xmlnode: the xmlnode to sign
 * @id_attr_name: (allow-none): an ID attribute to reference the xmlnode in the signature
 * @id_value: (allow-none): value of the ID attribute
 * @private_key_file: the path to a key file, or the key itself PEM encoded.
 * @certificate_file: (allow-none): the path to a certificate file to place in the KeyInfo, or the certificate
 * itself PEM encoded.
 *
 * Sign an xmlnode, use the given attribute to reference or create an envelopped signature,
 * eventually place a certificate in the KeyInfo node. The signature template must already be
 * present on the xmlnode.
 *
 * Return value: 0 if successful, an error code otherwise.
 */
int
lasso_sign_node(xmlNode *xmlnode, LassoSignatureContext context, const char *id_attr_name,
		const char *id_value)
{
	xmlDoc *doc = NULL;
	xmlNode *sign_tmpl = NULL, *old_parent = NULL;
	xmlSecDSigCtx *dsig_ctx = NULL;
	xmlAttr *id_attr = NULL;
	lasso_error_t rc = 0;

	g_return_val_if_fail(context.signature_method, LASSO_DS_ERROR_INVALID_SIGALG);
	g_return_val_if_fail(context.signature_key, LASSO_DS_ERROR_PRIVATE_KEY_LOAD_FAILED);

	sign_tmpl = xmlSecFindNode(xmlnode, xmlSecNodeSignature, xmlSecDSigNs);
	goto_cleanup_if_fail_with_rc(sign_tmpl != NULL,
			LASSO_DS_ERROR_SIGNATURE_TEMPLATE_NOT_FOUND);

	doc = xmlNewDoc((xmlChar*)"1.0");
	old_parent = xmlnode->parent;
	xmlnode->parent = NULL;
	xmlDocSetRootElement(doc, xmlnode);
	xmlSetTreeDoc(sign_tmpl, doc);
	if (id_attr_name && id_value) {
		id_attr = xmlHasProp(xmlnode, (xmlChar*)id_attr_name);
		xmlAddID(NULL, doc, (xmlChar*)id_value, id_attr);
	}

	dsig_ctx = xmlSecDSigCtxCreate(NULL);
	lasso_assign_sec_key(dsig_ctx->signKey, context.signature_key);
	if (xmlSecDSigCtxSign(dsig_ctx, sign_tmpl) < 0) {
		goto_cleanup_with_rc(LASSO_DS_ERROR_SIGNATURE_FAILED);
	}

cleanup:
	if (doc) {
		xmlRemoveID(doc, id_attr);
		xmlUnlinkNode(xmlnode);
		lasso_release_doc(doc);
		xmlnode->parent = old_parent;
		xmlSetTreeDoc(xmlnode, NULL);
	}
	lasso_release_signature_context(dsig_ctx);
	return rc;
}

gchar*
lasso_node_build_deflated_query(LassoNode *node)
{
	/* actually deflated and b64'ed and url-escaped */
	xmlNode *xmlnode;
	gchar *result;

	xmlnode = lasso_node_get_xmlNode(node, FALSE);
	result = lasso_xmlnode_build_deflated_query(xmlnode);
	xmlFreeNode(xmlnode);
	return result;
}

gchar*
lasso_xmlnode_build_deflated_query(xmlNode *xmlnode)
{
	xmlOutputBuffer *output_buffer;
	xmlBuffer *buffer;
	xmlCharEncodingHandlerPtr handler = NULL;
	xmlChar *ret, *b64_ret;
	char *rret;
	unsigned long in_len;
	int rc = 0;
	z_stream stream;

	handler = xmlFindCharEncodingHandler("utf-8");
	buffer = xmlBufferCreate();
	output_buffer = xmlOutputBufferCreateBuffer(buffer, handler);
	xmlNodeDumpOutput(output_buffer, NULL, xmlnode, 0, 0, NULL);
	xmlOutputBufferClose(output_buffer);
	xmlBufferAdd(buffer, BAD_CAST "", 1);

	in_len = strlen((char*)xmlBufferContent(buffer));
	ret = g_malloc(in_len * 2);
		/* deflating should never increase the required size but we are
		 * more conservative than that.  Twice the size should be
		 * enough. */

	stream.next_in = (xmlChar*)xmlBufferContent(buffer);
	stream.avail_in = in_len;
	stream.next_out = ret;
	stream.avail_out = in_len * 2;

	stream.zalloc = NULL;
	stream.zfree = NULL;
	stream.opaque = NULL;

	/* -MAX_WBITS to disable zib headers */
	rc = deflateInit2(&stream, Z_DEFAULT_COMPRESSION,
		Z_DEFLATED, -MAX_WBITS, 5, 0);
	if (rc == Z_OK) {
		rc = deflate(&stream, Z_FINISH);
		if (rc != Z_STREAM_END) {
			deflateEnd(&stream);
			if (rc == Z_OK) {
				rc = Z_BUF_ERROR;
			}
		} else {
			rc = deflateEnd(&stream);
		}
	}
	xmlBufferFree(buffer);
	if (rc != Z_OK) {
		lasso_release(ret);
		message(G_LOG_LEVEL_CRITICAL, "Failed to deflate");
		return NULL;
	}

	b64_ret = xmlSecBase64Encode(ret, stream.total_out, 0);
	lasso_release(ret);

	ret = xmlURIEscapeStr(b64_ret, NULL);
	rret = g_strdup((char*)ret);
	xmlFree(b64_ret);
	xmlFree(ret);

	return rret;
}

void
lasso_get_query_string_param_value(const char *qs, const char *param_key, const char **value,
		size_t *length)
{
	size_t key_size = strlen(param_key);

	*value = NULL;
	*length = 0;
	while (qs) {
		if (strncmp(qs, param_key, key_size) == 0 &&
				qs[key_size] == '=')
		{
			char *end;
			*value = &qs[key_size+1];
			end = strchr(*value, '&');
			if (! end) {
				end = strchr(*value, ';');
			}
			if (end) {
				*length = (ptrdiff_t)(end - *value);
			} else {
				*length = strlen(*value);
			}
			return;
		}
		qs = strchr(qs, '&');
	}
}

gboolean
lasso_node_init_from_deflated_query_part(LassoNode *node, char *deflate_string)
{
	int len;
	xmlChar *b64_zre, *zre, *re;
	z_stream zstr;
	int z_err;
	xmlDoc *doc;
	xmlNode *root;

	b64_zre = (xmlChar*)xmlURIUnescapeString(deflate_string, 0, NULL);
	len = strlen((char*)b64_zre);
	zre = xmlMalloc(len*4);
	len = xmlSecBase64Decode(b64_zre, zre, len*4);
	xmlFree(b64_zre);

	zstr.zalloc = NULL;
	zstr.zfree = NULL;
	zstr.opaque = NULL;

	zstr.avail_in = len;
	re = xmlMalloc(len*10);
	zstr.next_in = (xmlChar*)zre;
	zstr.total_in = 0;
	zstr.avail_out = len*10;
	zstr.total_out = 0;
	zstr.next_out = re;

	z_err = inflateInit2(&zstr, -MAX_WBITS);
	if (z_err != Z_OK) {
		message(G_LOG_LEVEL_CRITICAL, "Failed to inflateInit");
		xmlFree(zre);
		xmlFree(re);
		return FALSE;
	}

	z_err = inflate(&zstr, Z_FINISH);
	if (z_err != Z_STREAM_END) {
		message(G_LOG_LEVEL_CRITICAL, "Failed to inflate");
		inflateEnd(&zstr);
		xmlFree(zre);
		xmlFree(re);
		return FALSE;
	}
	re[zstr.total_out] = 0;
	inflateEnd(&zstr);
	xmlFree(zre);

	doc = lasso_xml_parse_memory((char*)re, strlen((char*)re));
	xmlFree(re);
	root = xmlDocGetRootElement(doc);
	lasso_node_init_from_xml(node, root);
	lasso_release_doc(doc);

	return TRUE;
}

char*
lasso_concat_url_query(const char *url, const char *query)
{
	if (strchr(url, '?')) {
		return g_strdup_printf("%s&%s", url, query);
	} else {
		return g_strdup_printf("%s?%s", url, query);
	}
}

static void structuredErrorFunc (void *userData, xmlErrorPtr error) {
		*(int*)userData = error->code;
}

/**
 * lasso_eval_xpath_expression:
 * @xpath_ctx: the XPath context object
 * @expression: a string containg the XPath expression to evaluate
 * @xpath_object_ptr: pointer to an output variable to store the resulting XPath object, can be
 * NULL.
 * @xpath_error_code: pointer to an output variable to store an eventual XPath error code, can be
 * NULL.
 *
 * Evaluates a given XPath expression in the given XPath context. Eventually return an XPath object
 * and/or an error code.
 *
 * Return value: TRUE if no error occurred during evaluation, FALSE otherwise.
 */
gboolean
lasso_eval_xpath_expression(xmlXPathContextPtr xpath_ctx, const char *expression,
		xmlXPathObjectPtr *xpath_object_ptr, int *xpath_error_code)
{
	xmlXPathObject *xpath_object = NULL;
	int errorCode = 0;
	xmlStructuredErrorFunc oldStructuredErrorFunc;
	gboolean rc = TRUE;

	g_return_val_if_fail(xpath_ctx != NULL && expression != NULL, FALSE);

	if (xpath_error_code) { /* reset */
		*xpath_error_code = 0;
	}
	oldStructuredErrorFunc = xpath_ctx->error;
	xpath_ctx->error = structuredErrorFunc;
	xpath_ctx->userData = &errorCode;
	xpath_object = xmlXPathEvalExpression((xmlChar*)expression, xpath_ctx);
	xpath_ctx->error = oldStructuredErrorFunc;
	xpath_ctx->userData = NULL;

	if (xpath_object) {
		if (xpath_object_ptr) {
			lasso_transfer_xpath_object(*xpath_object_ptr, xpath_object);
		}
	} else {
		rc = FALSE;
	}

	if (xpath_error_code && errorCode) {
		*xpath_error_code = errorCode;
	}
	lasso_release_xpath_object(xpath_object);

	return rc;
}

static gboolean
lasso_saml_constrain_dsigctxt(xmlSecDSigCtxPtr dsigCtx) {
	/* Limit allowed transforms for signature and reference processing */
	if((xmlSecDSigCtxEnableSignatureTransform(dsigCtx, xmlSecTransformInclC14NId) < 0) ||
			(xmlSecDSigCtxEnableSignatureTransform(dsigCtx, xmlSecTransformExclC14NId) < 0) ||
			(xmlSecDSigCtxEnableSignatureTransform(dsigCtx, xmlSecTransformSha1Id) < 0) ||
			(xmlSecDSigCtxEnableSignatureTransform(dsigCtx, xmlSecTransformHmacSha1Id) < 0) ||
			(xmlSecDSigCtxEnableSignatureTransform(dsigCtx, xmlSecTransformDsaSha1Id) < 0) ||
			(xmlSecDSigCtxEnableSignatureTransform(dsigCtx, xmlSecTransformRsaSha1Id) < 0)) {

		message(G_LOG_LEVEL_CRITICAL, "Error: failed to limit allowed signature transforms");
		return FALSE;
	}
	if((xmlSecDSigCtxEnableReferenceTransform(dsigCtx, xmlSecTransformInclC14NId) < 0) ||
			(xmlSecDSigCtxEnableReferenceTransform(dsigCtx, xmlSecTransformExclC14NId) < 0) ||
			(xmlSecDSigCtxEnableReferenceTransform(dsigCtx, xmlSecTransformSha1Id) < 0) ||
			(xmlSecDSigCtxEnableReferenceTransform(dsigCtx, xmlSecTransformEnvelopedId) < 0)) {

		message(G_LOG_LEVEL_CRITICAL, "Error: failed to limit allowed reference transforms");
		return FALSE;
	}

	/* Limit possible key info to X509, RSA and DSA */
	if((xmlSecPtrListAdd(&(dsigCtx->keyInfoReadCtx.enabledKeyData), BAD_CAST xmlSecKeyDataX509Id) < 0) ||
			(xmlSecPtrListAdd(&(dsigCtx->keyInfoReadCtx.enabledKeyData), BAD_CAST xmlSecKeyDataHmacId) < 0) ||
			(xmlSecPtrListAdd(&(dsigCtx->keyInfoReadCtx.enabledKeyData), BAD_CAST xmlSecKeyDataRsaId) < 0) ||
			(xmlSecPtrListAdd(&(dsigCtx->keyInfoReadCtx.enabledKeyData), BAD_CAST xmlSecKeyDataDsaId) < 0)) {
		message(G_LOG_LEVEL_CRITICAL, "Error: failed to limit allowed key data");
		return FALSE;
	}
	return TRUE;
}

/**
 * lasso_verify_signature:
 * @signed_node: an #xmlNode containing an enveloped xmlDSig signature
 * @doc: (allow-none): the eventual #xmlDoc from which the node is extracted, if none is given then it will be
 * created
 * @id_attr_name: the id attribune name for this node
 * @keys_manager: (allow-none): an #xmlSecKeysMnr containing the CA cert chain, to validate the key in the
 * signature if there is one.
 * @public_key: (allow-none): a public key to validate the signature, if present the function ignore the key
 * contained in the signature.
 * @signature_verification_option: flag to specify option about signature validation, see
 * #SignatureVerificationOption.
 * @uri_references: if the signature references multiple nodes, return them as a list of node IDs.
 *
 * This function validate a signature on an xmlNode following the instructions given in the document
 * Assertions and Protocol or the OASIS Security Markup Language (SAML) V1.1.
 *
 * The only kind of references that are accepted in thoses signatures are node ID references,
 * looking like &#35;xxx;.
 *
 * Beware that it does not validate every needed properties for a SAML assertion, request or
 * response to be acceptable.
 *
 * Return: 0 if signature was validated, and error code otherwise.
 */

int
lasso_verify_signature(xmlNode *signed_node, xmlDoc *doc, const char *id_attr_name,
		xmlSecKeysMngr *keys_manager, xmlSecKey *public_key,
		SignatureVerificationOption signature_verification_option,
		GList **uri_references)
{
	int rc = LASSO_DS_ERROR_SIGNATURE_VERIFICATION_FAILED;
	xmlNodePtr signature = NULL;
	xmlSecDSigCtx *dsigCtx = NULL;
	xmlChar *id = NULL;
	char *reference_uri = NULL;
	xmlSecDSigReferenceCtx *dsig_reference_ctx = NULL;
	gboolean free_the_doc = FALSE;

	g_return_val_if_fail(signed_node && (keys_manager || public_key),
			LASSO_PARAM_ERROR_INVALID_VALUE);

	if (lasso_flag_verify_signature == FALSE) {
		return 0;
	}
	/* Find signature as direct child. */
	signature = xmlSecFindChild(signed_node, xmlSecNodeSignature, xmlSecDSigNs);
	goto_cleanup_if_fail_with_rc (signature, LASSO_DS_ERROR_SIGNATURE_NOT_FOUND);

	/* Create a temporary doc, if needed */
	if (doc == NULL) {
		doc = xmlNewDoc((xmlChar*)XML_DEFAULT_VERSION);
		goto_cleanup_if_fail_with_rc(doc, LASSO_ERROR_OUT_OF_MEMORY);
		xmlDocSetRootElement(doc, signed_node);
		free_the_doc = TRUE;
	}

	/* Find ID */
	if (id_attr_name) {
		id = xmlGetProp(signed_node, (xmlChar*)id_attr_name);
		if (id) {
			xmlAddID(NULL, doc, id, xmlHasProp(signed_node, (xmlChar*)id_attr_name));
		}
	}

	/* Create DSig context */
	dsigCtx = xmlSecDSigCtxCreate(keys_manager);
	goto_cleanup_if_fail_with_rc(doc, LASSO_DS_ERROR_CONTEXT_CREATION_FAILED);
	/* XXX: Is xmlSecTransformUriTypeSameEmpty permitted ?
	 * I would say yes only if signed_node == signature->parent. */
	dsigCtx->enabledReferenceUris = 0;
	dsigCtx->enabledReferenceUris |= xmlSecTransformUriTypeSameDocument;
	if (signature_verification_option & EMPTY_URI) {
		dsigCtx->enabledReferenceUris |= xmlSecTransformUriTypeEmpty;
	}

	goto_cleanup_if_fail_with_rc(lasso_saml_constrain_dsigctxt(dsigCtx),
			LASSO_DS_ERROR_SIGNATURE_VERIFICATION_FAILED);
	/* Given a public key use it to validate the signature ! */
	if (public_key) {
		dsigCtx->signKey = xmlSecKeyDuplicate(public_key);
	}

	/* Verify signature */
	goto_cleanup_if_fail_with_rc(xmlSecDSigCtxVerify(dsigCtx, signature) >= 0,
			LASSO_DS_ERROR_SIGNATURE_VERIFICATION_FAILED);
	goto_cleanup_if_fail_with_rc(dsigCtx->status == xmlSecDSigStatusSucceeded,
			LASSO_DS_ERROR_SIGNATURE_VERIFICATION_FAILED);

	/* There should be only one reference */
	goto_cleanup_if_fail_with_rc(((signature_verification_option & NO_SINGLE_REFERENCE) == 0) ||
			xmlSecPtrListGetSize(&(dsigCtx->signedInfoReferences)) == 1, LASSO_DS_ERROR_TOO_MUCH_REFERENCES);
	/* The reference should be to the signed node */
	{
		gboolean ok = FALSE;
		reference_uri = g_strdup_printf("#%s", id);
		dsig_reference_ctx = (xmlSecDSigReferenceCtx*)
			xmlSecPtrListGetItem(&(dsigCtx->signedInfoReferences), 0);
		ok |= dsig_reference_ctx != 0 &&
			lasso_strisequal((char*)dsig_reference_ctx->uri, reference_uri);
		ok |= (signature_verification_option & EMPTY_URI)
			&& xmlDocGetRootElement(doc) == signed_node
			&& lasso_strisequal((char*)dsig_reference_ctx->uri, "");
		goto_cleanup_if_fail_with_rc(ok,
				LASSO_DS_ERROR_INVALID_REFERENCE_FOR_SAML);
	}
	/* Keep URI of all nodes signed if asked */
	if (uri_references) {
		gint size = xmlSecPtrListGetSize(&(dsigCtx->signedInfoReferences));
		int i;
		for (i = 0; i < size; ++i) {

			dsig_reference_ctx = (xmlSecDSigReferenceCtx*)xmlSecPtrListGetItem(&(dsigCtx->signedInfoReferences), i);
			if (dsig_reference_ctx->uri == NULL) {
				message(G_LOG_LEVEL_CRITICAL, "dsig_reference_ctx->uri cannot be null");
				continue;
			}
			lasso_list_add_xml_string(*uri_references, dsig_reference_ctx->uri);
		}
	}

	if (dsigCtx->status == xmlSecDSigStatusSucceeded) {
		rc = 0;
	}

cleanup:
	lasso_release_string(reference_uri);
	lasso_release_signature_context(dsigCtx);
	if (free_the_doc) {
		xmlUnlinkNode(signed_node);
		xmlSetTreeDoc(signed_node, NULL);
		lasso_release_doc(doc);
	}
	lasso_release_string(id);
	return rc;
}

gboolean
lasso_xml_is_soap(xmlNode *root)
{
	return xmlSecCheckNodeName(root, xmlSecNodeEnvelope, xmlSecSoap11Ns) ||
		xmlSecCheckNodeName(root, xmlSecNodeEnvelope, xmlSecSoap12Ns);
}

xmlNode*
lasso_xml_get_soap_content(xmlNode *root)
{
	gboolean is_soap11 = FALSE;
	gboolean is_soap12 = FALSE;
	xmlNode *content = NULL;

	is_soap11 = xmlSecCheckNodeName(root, xmlSecNodeEnvelope, xmlSecSoap11Ns);
	is_soap12 = xmlSecCheckNodeName(root, xmlSecNodeEnvelope, xmlSecSoap12Ns);

	if (is_soap11 || is_soap12) {
		xmlNode *body;

		if (is_soap11) {
			body = xmlSecSoap11GetBody(root);
		} else {
			body = xmlSecSoap12GetBody(root);
		}
		if (body) {
			content = xmlSecGetNextElementNode(body->children);
		}
	}

	return content;
}

LassoMessageFormat
lasso_xml_parse_message(const char *message, LassoMessageFormat constraint, xmlDoc **doc_out, xmlNode **root_out)
{
	char *msg = NULL;
	gboolean b64 = FALSE;
	LassoMessageFormat rc = LASSO_MESSAGE_FORMAT_UNKNOWN;
	xmlDoc *doc = NULL;
	xmlNode *root = NULL;
	gboolean any = constraint == LASSO_MESSAGE_FORMAT_UNKNOWN;

	msg = (char*)message;

	/* BASE64 case */
	if (any || constraint == LASSO_MESSAGE_FORMAT_BASE64) {
		if (message[0] != 0 && is_base64(message)) {
			msg = g_malloc(strlen(message));
			rc = xmlSecBase64Decode((xmlChar*)message, (xmlChar*)msg, strlen(message));
			if (rc >= 0) {
				b64 = TRUE;
			} else {
				lasso_release(msg);
				msg = (char*)message;
			}
		}
	}

	/* XML case */
	if (any || constraint == LASSO_MESSAGE_FORMAT_BASE64 ||
		constraint == LASSO_MESSAGE_FORMAT_XML ||
		constraint == LASSO_MESSAGE_FORMAT_SOAP) {
		if (strchr(msg, '<')) {
			doc = lasso_xml_parse_memory(msg, strlen(msg));
			if (doc == NULL) {
				rc = LASSO_MESSAGE_FORMAT_UNKNOWN;
				goto cleanup;
			}
			root = xmlDocGetRootElement(doc);

			if (any || constraint == LASSO_MESSAGE_FORMAT_SOAP) {
				gboolean is_soap = FALSE;

				is_soap = lasso_xml_is_soap(root);
				if (is_soap) {
					root = lasso_xml_get_soap_content(root);
				}
				if (! root) {
					rc = LASSO_MESSAGE_FORMAT_ERROR;
					goto cleanup;
				}
				if (is_soap) {
					rc = LASSO_MESSAGE_FORMAT_SOAP;
					goto cleanup;
				}
				if (b64) {
					lasso_release(msg);
					rc = LASSO_MESSAGE_FORMAT_BASE64;
					goto cleanup;
				}
				rc = LASSO_MESSAGE_FORMAT_XML;
				goto cleanup;
			}
		}
	}

cleanup:
	if (doc_out) {
		*doc_out = doc;
		if (root_out) {
			*root_out = root;
		}
	} else {
		lasso_release_doc(doc);
		lasso_release_xml_node(root);
	}
	return rc;
}

static gboolean
is_base64(const char *message)
{
	const char *c;

	c = message;
	while (*c != 0 && (isalnum((int)*c) || *c == '+' || *c == '/' || *c == '\n' || *c == '\r')) c++;
	while (*c == '=' || *c == '\n' || *c == '\r') c++; /* trailing = */

	if (*c == 0)
		return TRUE;

	return FALSE;
}

/**
 * lasso_node_decrypt_xmlnode
 * @encrypted_element: an EncrytpedData #xmlNode
 * @encrypted_keys: a #GList of EncrytpedKey #xmlNode
 * @encryption_private_key : a private key to decrypt the node
 * @output: a pointer a #LassoNode variable to store the decrypted element
 *
 * Try to decrypt an encrypted element.
 *
 * Return value: 0 if successful,
 * LASSO_DS_ERROR_DECRYPTION_FAILED if decrypted failed,
 * LASSO_XML_ERROR_OBJECT_CONSTRUCTION_FAILED if construction of a #LassoNode from the decrypted
 * content failed,
 * LASSO_DS_ERROR_CONTEXT_CREATION_FAILED if some context initialization failed.
 **/
int
lasso_node_decrypt_xmlnode(xmlNode* encrypted_element,
		GList *encrypted_keys,
		xmlSecKey *encryption_private_key,
		LassoNode **output)
{
	xmlDocPtr doc = NULL;
	xmlDocPtr doc2 = NULL;
	xmlSecEncCtxPtr encCtx = NULL;
	xmlSecKeyPtr sym_key = NULL;
	xmlSecBufferPtr key_buffer = NULL;
	LassoNode *decrypted_node = NULL;
	xmlNodePtr encrypted_data_node = NULL;
	xmlNodePtr encrypted_key_node = NULL;
	xmlNodePtr encryption_method_node = NULL;
	xmlChar *algorithm = NULL;
	xmlSecKeyDataId key_type;
	GList *i = NULL;
	int rc = LASSO_XMLENC_ERROR_INVALID_ENCRYPTED_DATA;

	if (encryption_private_key == NULL || !xmlSecKeyIsValid(encryption_private_key)) {
		message(G_LOG_LEVEL_WARNING, "Invalid decryption key");
		rc = LASSO_PROFILE_ERROR_MISSING_ENCRYPTION_PRIVATE_KEY;
		goto cleanup;
	}

	/* Need to duplicate it because xmlSecEncCtxDestroy(encCtx); will destroy it */
	encryption_private_key = xmlSecKeyDuplicate(encryption_private_key);

	encrypted_data_node = xmlCopyNode(encrypted_element, 1);

	/* Get the encryption algorithm for EncryptedData in its EncryptionMethod node */
	encryption_method_node = xmlSecTmplEncDataGetEncMethodNode(encrypted_data_node);
	if (encryption_method_node == NULL) {
		message(G_LOG_LEVEL_WARNING, "No EncryptionMethod node in EncryptedData");
		goto cleanup;
	}
	algorithm = xmlGetProp(encryption_method_node, (xmlChar *)"Algorithm");
	if (algorithm == NULL) {
		message(G_LOG_LEVEL_WARNING, "No EncryptionMethod");
		goto cleanup;
	}
	if (strstr((char*)algorithm , "#aes")) {
		key_type = xmlSecKeyDataAesId;
	} else if (strstr((char*)algorithm , "des")) {
		key_type = xmlSecKeyDataDesId;
	} else {
		message(G_LOG_LEVEL_WARNING, "Unknown EncryptionMethod");
		goto cleanup;
	}

	/* Get the EncryptedKey */
	if (encrypted_keys != NULL) {
		for (i = encrypted_keys; i; i = g_list_next(i)) {
			if (i->data == NULL)
				continue;
			if (strcmp((char*)((xmlNode*)i->data)->name, "EncryptedKey") == 0) {
				encrypted_key_node = xmlCopyNode((xmlNode*)(i->data), 1);
				break;
			}
		}
	} else {
		/* Look an EncryptedKey inside the EncryptedData */
		xmlNodePtr key_info;
		do {
			key_info = xmlSecFindChild(encrypted_data_node, xmlSecNodeKeyInfo, xmlSecDSigNs);
			if (! key_info)
				break;
			encrypted_key_node = xmlSecFindChild(key_info, xmlSecNodeEncryptedKey, xmlSecEncNs);
		} while (0);
	}

	if (encrypted_key_node == NULL) {
		message(G_LOG_LEVEL_WARNING, "No EncryptedKey node");
		goto cleanup;
	}

	/* Create a document to contain the node to decrypt */
	doc = xmlNewDoc((xmlChar*)"1.0");
	xmlDocSetRootElement(doc, encrypted_data_node);

	doc2 = xmlNewDoc((xmlChar*)"1.0");
	xmlDocSetRootElement(doc2, encrypted_key_node);

	/* create encryption context to decrypt EncryptedKey */
	encCtx = xmlSecEncCtxCreate(NULL);
	if (encCtx == NULL) {
		message(G_LOG_LEVEL_WARNING, "Failed to create encryption context");
		rc = LASSO_DS_ERROR_CONTEXT_CREATION_FAILED;
		goto cleanup;
	}
	encCtx->encKey = encryption_private_key;
	encCtx->mode = xmlEncCtxModeEncryptedKey;

	/* decrypt the EncryptedKey */
	key_buffer = xmlSecEncCtxDecryptToBuffer(encCtx, encrypted_key_node);
	if (key_buffer != NULL) {
		sym_key = xmlSecKeyReadBuffer(key_type, key_buffer);
	}
	rc = LASSO_DS_ERROR_ENCRYPTION_FAILED;
	if (sym_key == NULL) {
		goto cleanup;
	}

	/* create encryption context to decrypt EncryptedData */
	xmlSecEncCtxDestroy(encCtx);
	encCtx = xmlSecEncCtxCreate(NULL);
	if (encCtx == NULL) {
		message(G_LOG_LEVEL_WARNING, "Failed to create encryption context");
		rc = LASSO_DS_ERROR_CONTEXT_CREATION_FAILED;
		goto cleanup;
	}
	encCtx->encKey = sym_key;
	encCtx->mode = xmlEncCtxModeEncryptedData;

	/* decrypt the EncryptedData */
	if ((xmlSecEncCtxDecrypt(encCtx, encrypted_data_node) < 0) || (encCtx->result == NULL)) {
		rc = LASSO_XMLENC_ERROR_INVALID_ENCRYPTED_DATA;
		message(G_LOG_LEVEL_WARNING, "EncryptedData decryption failed");
		goto cleanup;
	}

	decrypted_node = lasso_node_new_from_xmlNode(doc->children);
	if (decrypted_node) {
		rc = 0;
	} else {
		rc = LASSO_XML_ERROR_OBJECT_CONSTRUCTION_FAILED;
	}
	if (output) {
		lasso_assign_gobject(*output, decrypted_node);
	}

cleanup:
	if (doc == NULL && encrypted_data_node) {
		xmlFreeNode(encrypted_data_node);
	}
	if (doc2 == NULL && encrypted_key_node) {
		xmlFreeNode(encrypted_key_node);
	}
	if (encCtx) {
		xmlSecEncCtxDestroy(encCtx);
	}
	lasso_release_doc(doc);
	lasso_release_doc(doc2);
	lasso_release_gobject(decrypted_node);
	lasso_release_xml_string(algorithm);

	return rc;
}

static void xml_logv(int log_level, const char *msg, va_list arg_ptr) {
	char buffer[512], *escaped;

	vsnprintf(buffer, 512, msg, arg_ptr);
	escaped = g_strescape(buffer, NULL);
	g_log(LASSO_LOG_DOMAIN, log_level, "libxml2: %s", escaped);
	lasso_release_string(escaped);
}

static void __xmlWarningFunc(G_GNUC_UNUSED void *userData, const char *msg, ...) {
	va_list arg_ptr;

	va_start(arg_ptr, msg);
	xml_logv(G_LOG_LEVEL_WARNING, msg, arg_ptr);
}

static void __xmlErrorFunc(G_GNUC_UNUSED void *userData, const char *msg, ...) {
	va_list arg_ptr;

	va_start(arg_ptr, msg);
	xml_logv(G_LOG_LEVEL_CRITICAL, msg, arg_ptr);
}

/**
 * lasso_xml_parse_memory:
 * @buffer:  an pointer to a char array
 * @size:  the size of the array
 *
 * Parse an XML in-memory block and build a tree; exactly like xmlParseMemory
 * safe two exceptions:
 * <itemizedlist>
 * <listitem><para>
 *  it won't download anything from the network (XML_PARSE_NONET)
 * </listitem></para>
 * <listitem><para>
 *  it will refuse documents with a DTD (for security reason)
 * </para></listitem>
 * </itemizedlist>
 *
 * Return value: the resulting document tree
 **/
xmlDocPtr
lasso_xml_parse_memory(const char *buffer, int size) {
	return lasso_xml_parse_memory_with_error(buffer, size, NULL);
}

xmlDocPtr
lasso_xml_parse_memory_with_error(const char *buffer, int size, xmlError *error) {
	xmlDocPtr ret;
	xmlParserCtxtPtr ctxt;

	ctxt = xmlCreateMemoryParserCtxt(buffer, size);
	if (ctxt == NULL) {
		return NULL;
	}
	xmlDetectSAX2(ctxt);
	if (ctxt->errNo == XML_ERR_NO_MEMORY) {
		return NULL;
	}
	ctxt->recovery = 0;
	xmlCtxtUseOptions(ctxt, XML_PARSE_NONET);
	if (error) {
		ctxt->sax->warning = NULL;
		ctxt->sax->error = NULL;
		ctxt->sax->fatalError = NULL;
	} else {
		/* reroute errors through GLib logger */
		ctxt->sax->warning = __xmlWarningFunc;
		ctxt->sax->error = __xmlErrorFunc;
	}

	xmlParseDocument(ctxt);

	if (error) {
		xmlCopyError(&ctxt->lastError, error);
	}

	if (ctxt->wellFormed && ctxt->myDoc->intSubset != NULL) {
		message(G_LOG_LEVEL_WARNING, "Denied message with DTD content");
		ctxt->wellFormed = 0;
	}

	if (ctxt->wellFormed) {
		ret = ctxt->myDoc;
	} else {
		ret = NULL;
		lasso_release_doc(ctxt->myDoc);
		ctxt->myDoc = NULL;
	}
	xmlFreeParserCtxt(ctxt);

	return ret;
}

/**
 * lasso_xml_parse_file:
 * @filepath: the file path
 *
 * Parse an XML file, report errors through GLib logger with the Lasso domain
 *
 * Return value: a newly create #xmlDoc object if successful, NULL otherwise.
 */
xmlDocPtr
lasso_xml_parse_file(const char *filepath)
{
	char *file_content;
	size_t file_length;
	GError *error = NULL;

	if (g_file_get_contents(filepath, &file_content, &file_length, &error)) {
		xmlDocPtr ret;

		ret = lasso_xml_parse_memory(file_content, file_length);
		lasso_release(file_content);
		return ret;
	} else {
		message(G_LOG_LEVEL_CRITICAL, "Cannot read XML file %s: %s", filepath, error->message);
		g_error_free(error);
		return NULL;
	}
}

/* (almost) straight from libxml2 internal API */
static void
xmlDetectSAX2(xmlParserCtxtPtr ctxt) {
	if (ctxt == NULL) return;
#ifdef LIBXML_SAX1_ENABLED
	if ((ctxt->sax != NULL) && (ctxt->sax->initialized == XML_SAX2_MAGIC) &&
			((ctxt->sax->startElementNs != NULL) ||
			 (ctxt->sax->endElementNs != NULL)))
		ctxt->sax2 = 1;
#else
	ctxt->sax2 = 1;
#endif /* LIBXML_SAX1_ENABLED */

	ctxt->str_xml = xmlDictLookup(ctxt->dict, BAD_CAST "xml", 3);
	ctxt->str_xmlns = xmlDictLookup(ctxt->dict, BAD_CAST "xmlns", 5);
	ctxt->str_xml_ns = xmlDictLookup(ctxt->dict, XML_XML_NAMESPACE, 36);
	if ((ctxt->str_xml==NULL) || (ctxt->str_xmlns==NULL) ||
			(ctxt->str_xml_ns == NULL)) {
		ctxt->errNo = XML_ERR_NO_MEMORY;
	}
}

/**
 * lasso_get_relaystate_from_query:
 * @query: a C-string containing the query part of an URL
 *
 * Extracts the relaystate argument contained in an URL query string.
 *
 * Return value: NULL if not relaystate is present in the URL, the RelayState decoded value
 * otherwise.
 */
char *
lasso_get_relaystate_from_query(const char *query) {
	const char *start = NULL, *end = NULL;
	char *result = NULL;

	if (query == NULL)
		return NULL;
	if (strncmp(query, LASSO_SAML2_FIELD_RELAYSTATE "=", sizeof(LASSO_SAML2_FIELD_RELAYSTATE
				"=") - 1) == 0) {
		start = query + sizeof(LASSO_SAML2_FIELD_RELAYSTATE);
	}
	if (! start) {
		if (! start) {
			start = strstr(query, "&RelayState=");
		}
		if (! start) {
			start = strstr(query, ";RelayState=");
		}
		if (start) {
			start += sizeof(LASSO_SAML2_FIELD_RELAYSTATE "=");
		}
	}
	if (start) {
		ptrdiff_t length;
		const char *end2;

		end = strchr(start, '&');
		end2 = strchr(start, ';');
		if ((end2 != NULL) && ((end == NULL) || (end2 < end))) {
			end = end2;
		}
		if (end) {
			length = end-start;
		} else {
			length = strlen(start);
		}
		if (length > query_string_attribute_length_limit) {
			message(G_LOG_LEVEL_WARNING, "Received a RelayState of size %ti > %u",
					length, query_string_attribute_length_limit);
		}
		if (length) {
			result = xmlURIUnescapeString(start, length, NULL);
		} else {
			result = g_malloc0(1);
		}
	}
	return result;
}

/**
 * lasso_url_add_parameters:
 * @url: the original URL
 * @free: whether to free the URL parameter
 * @...: pairs of strings, key, value, followed by NULL
 *
 * Iterate over all pairs of key,value, and concatenate them to @url encoded as "&key=value", where
 * key and value are url-encoded.
 * If free is true and at least one pair was given, url is freed. If url is NULL, the first
 * ampersand is omitted.
 *
 * Return value: a newly allocated string, or url.
 */
char*
lasso_url_add_parameters(char *url,
		gboolean free, ...)
{
	char *old_url = url, *new_url;
	xmlChar *encoded_key, *encoded_value;
	va_list ap;

	va_start(ap, free);

	while (1) {
		char *key;
		char *value;

		key = va_arg(ap, char*);
		if (! key) {
			break;
		}
		encoded_key = xmlURIEscapeStr((xmlChar*)key, NULL);
		goto_cleanup_if_fail(encoded_key);

		value = va_arg(ap, char*);
		if (! value) {
			message(G_LOG_LEVEL_CRITICAL, "lasso_url_add_parameter: key without a value !!");
			break;
		}
		encoded_value = xmlURIEscapeStr((xmlChar*)value, NULL);
		goto_cleanup_if_fail(encoded_value);

		if (old_url) {
			new_url = g_strdup_printf("%s&%s=%s", old_url, (char*)encoded_key, (char*)encoded_value);
		} else {
			new_url = g_strdup_printf("%s=%s", (char*)encoded_key, (char*)encoded_value);
		}
		if (old_url != url) {
			lasso_release_string(old_url);
		}
		old_url = new_url;

		lasso_release_xml_string(encoded_key);
		lasso_release_xml_string(encoded_value);
	}
cleanup:
	va_end(ap);
	if (free && new_url != url) {
		lasso_release(url);
	}
	lasso_release_xml_string(encoded_key);

	return new_url;
}

xmlSecKey*
_lasso_xmlsec_load_key_from_buffer(const char *buffer, size_t length, const char *password,
		LassoSignatureMethod signature_method, const char *certificate)
{
	int i = 0;
	xmlSecKeyDataFormat key_formats[] = {
		xmlSecKeyDataFormatPem,
		xmlSecKeyDataFormatCertPem,
		xmlSecKeyDataFormatDer,
		xmlSecKeyDataFormatBinary,
		xmlSecKeyDataFormatCertDer,
		xmlSecKeyDataFormatPkcs8Der,
		xmlSecKeyDataFormatPkcs8Pem,
		0
	};
	xmlSecKeyDataFormat cert_formats[] = {
		xmlSecKeyDataFormatCertPem,
		xmlSecKeyDataFormatCertDer,
		0
	};
	xmlSecKey *private_key = NULL;

	xmlSecErrorsDefaultCallbackEnableOutput(FALSE);
	switch (signature_method) {
		case LASSO_SIGNATURE_METHOD_RSA_SHA1:
		case LASSO_SIGNATURE_METHOD_DSA_SHA1:
			for (i = 0; key_formats[i] && private_key == NULL; i++) {
				private_key = xmlSecCryptoAppKeyLoadMemory((xmlSecByte*)buffer, length,
						key_formats[i], password, NULL, NULL);
			}
			break;
		case LASSO_SIGNATURE_METHOD_HMAC_SHA1:
			private_key = xmlSecKeyReadMemory(xmlSecKeyDataHmacId, (xmlSecByte*)buffer, length);
			if (private_key) {
				xmlSecKeySetName(private_key, BAD_CAST "shared");
			}
			break;
		case LASSO_SIGNATURE_METHOD_LAST:
		case LASSO_SIGNATURE_METHOD_NONE:
			g_assert_not_reached();
	}
	goto_cleanup_if_fail(private_key != NULL);
	if (certificate) {
		if (signature_method == LASSO_SIGNATURE_METHOD_RSA_SHA1 || signature_method == LASSO_SIGNATURE_METHOD_DSA_SHA1) {
			int done = 0;

			for (i=0; cert_formats[i]; i++) {
				if (xmlSecCryptoAppKeyCertLoad(private_key, certificate, cert_formats[i])
						== 0) {
					done = 1;
					break;
				}
				if (xmlSecCryptoAppKeyCertLoadMemory(private_key, BAD_CAST certificate,
							strlen(certificate), cert_formats[i]) == 0) {
					done = 1;
					break;
				}
			}
			if (done == 0) {
				warning("Unable to load certificate: %s", certificate);
			}
		} else {
			warning("Attaching a certificate for signature only "
					"works with DSA and RSA algorithms.");
		}
	}
cleanup:
	xmlSecErrorsDefaultCallbackEnableOutput(TRUE);
	return private_key;
}
/**
 * lasso_base64_decode:
 * @from: the source base64 encoded string
 * @buffer: an output argument to place the resulting buffer pointer
 * @buffer_len: an output argument to place the resulting buffer length
 *
 * Decode the given string as Base64 and allocate a buffer for the decoded content, place the
 * pointer to the buffer in @buffer and the length in @buffer_len
 *
 * Return value: TRUE if successful, FALSE otherwise.
 */
gboolean
lasso_base64_decode(const char *from, char **buffer, int *buffer_len)
{
	size_t len = strlen(from);
	int ret;

	/* base64 map 4 bytes to 3 */
	len = len / 4 + (len % 4 ? 1 : 0);
	len *= 3;
	len += 1; /* zero byte */
	*buffer = g_malloc0(len);

	xmlSecErrorsDefaultCallbackEnableOutput(FALSE);
	ret = xmlSecBase64Decode(BAD_CAST from, BAD_CAST *buffer, len);
	xmlSecErrorsDefaultCallbackEnableOutput(TRUE);
	if (ret <= 0) {
		lasso_release_string(*buffer);
		return FALSE;
	}
	*buffer_len = ret;
	return TRUE;
}

/**
 * lasso_xmlsec_load_private_key_from_buffer:
 * @buffer: a buffer containing a key in any format
 * @length: length of the buffer
 * @password: eventually a password
 */
xmlSecKey*
lasso_xmlsec_load_private_key_from_buffer(const char *buffer, size_t length, const char *password,
		LassoSignatureMethod signature_method, const char *certificate) {
	xmlSecKey *private_key = NULL;

	private_key = _lasso_xmlsec_load_key_from_buffer(buffer, length, password, signature_method, certificate);

	/* special lasso metadata hack */
	if (! private_key) {
		char *out = NULL;
		int len;

		if (lasso_base64_decode(buffer, &out, &len)) {
			private_key = _lasso_xmlsec_load_key_from_buffer((char*)out, len, password,
					signature_method, certificate);
		}
		lasso_release_string(out);
	}

	return private_key;
}

xmlSecKey*
lasso_xmlsec_load_private_key(const char *filename_or_buffer, const char *password, LassoSignatureMethod signature_method, const char *certificate) {
	char *buffer = NULL;
	size_t length;
	xmlSecKey *ret;

	if (! filename_or_buffer)
		return NULL;

	if (g_file_get_contents(filename_or_buffer, &buffer, &length, NULL)) {
		ret = lasso_xmlsec_load_private_key_from_buffer(buffer, length, password, signature_method, certificate);
	} else {
		ret = lasso_xmlsec_load_private_key_from_buffer(filename_or_buffer,
				strlen(filename_or_buffer), password, signature_method,
				certificate);
	}
	lasso_release_string(buffer);
	return ret;

}

gboolean
lasso_get_base64_content(xmlNode *node, char **content, size_t *length) {
	xmlChar *base64, *stripped_base64;
	xmlChar *result;
	int base64_length;
	int rc = 0;

	if (! node || ! content || ! length)
		return FALSE;

	base64 = xmlNodeGetContent(node);
	if (! base64)
		return FALSE;
	stripped_base64 = base64;
	/* skip spaces */
	while (*stripped_base64 && isspace(*stripped_base64))
		stripped_base64++;

	base64_length = strlen((char*)stripped_base64);
	result = g_new(xmlChar, base64_length);
	xmlSecErrorsDefaultCallbackEnableOutput(FALSE);
	rc = xmlSecBase64Decode(stripped_base64, result, base64_length);
	xmlSecErrorsDefaultCallbackEnableOutput(TRUE);
	xmlFree(base64);
	if (rc < 0) {
		return FALSE;
	} else {
		*content = (char*)g_memdup(result, rc);
		xmlFree(result);
		*length = rc;
		return TRUE;
	}
}

xmlSecKeyPtr
lasso_xmlsec_load_key_info(xmlNode *key_descriptor)
{
	xmlSecKeyPtr key, result = NULL;
	xmlNodePtr key_info = NULL;
	xmlSecKeyInfoCtx ctx;
	xmlSecKeysMngr *keys_mngr;
	xmlNodePtr key_value = NULL;
	int rc = 0;
	xmlChar *content = NULL;
	X509 *cert;

	if (! key_descriptor)
		return NULL;

	key_info = xmlSecFindChild(key_descriptor, xmlSecNodeKeyInfo, xmlSecDSigNs);
	if (! key_info)
		return NULL;
	keys_mngr = xmlSecKeysMngrCreate();
	rc = xmlSecCryptoAppDefaultKeysMngrInit(keys_mngr);
	if (rc < 0) {
		goto next;
	}
	rc = xmlSecKeyInfoCtxInitialize(&ctx, keys_mngr);
	if (rc < 0) {
		goto next;
	}
	ctx.flags = XMLSEC_KEYINFO_FLAGS_DONT_STOP_ON_KEY_FOUND
		| XMLSEC_KEYINFO_FLAGS_X509DATA_DONT_VERIFY_CERTS;
	ctx.mode = xmlSecKeyInfoModeRead;
	ctx.keyReq.keyId = xmlSecKeyDataIdUnknown;
	ctx.keyReq.keyType = xmlSecKeyDataTypePublic;
	ctx.keyReq.keyUsage = xmlSecKeyDataUsageAny;
	ctx.certsVerificationDepth = 0;

	key = xmlSecKeyCreate();
	/* anyway to make this reentrant and thread safe ? */
	xmlSecErrorsDefaultCallbackEnableOutput(FALSE);
	rc = xmlSecKeyInfoNodeRead(key_info, key, &ctx);
	xmlSecErrorsDefaultCallbackEnableOutput(TRUE);
	xmlSecKeyInfoCtxFinalize(&ctx);

	if (rc == 0) {
		xmlSecKeyDataPtr cert_data;

		cert_data = xmlSecKeyGetData(key, xmlSecOpenSSLKeyDataX509Id);

		if (cert_data) {
			cert = xmlSecOpenSSLKeyDataX509GetCert(cert_data, 0);
			if (cert) {
				xmlSecKeyDataPtr cert_key;

				cert_key = xmlSecOpenSSLX509CertGetKey(cert);
				rc = xmlSecKeySetValue(key, cert_key);
				if (rc < 0) {
					xmlSecKeyDataDestroy(cert_key);
					goto next;
				}
			}
		}
	}

	if (rc == 0 && xmlSecKeyIsValid(key)) {
		result = key;
		key = NULL;
		goto cleanup;
	}
	xmlSecKeyDestroy(key);
next:
	if (! (key_value = xmlSecFindChild(key_info, xmlSecNodeKeyValue, xmlSecDSigNs)) &&
		 ! (key_value = xmlSecFindNode(key_info, xmlSecNodeX509Certificate, xmlSecDSigNs)))  {
		goto cleanup;
	}

	content = xmlNodeGetContent(key_value);
	if (content) {
		result = lasso_xmlsec_load_private_key_from_buffer((char*)content,
				strlen((char*)content), NULL, LASSO_SIGNATURE_METHOD_RSA_SHA1, NULL);
		xmlFree(content);
	}

cleanup:
	lasso_release_key_manager(keys_mngr);
	return result;
}

/**
 * lasso_xmlnode_to_string:
 * @xmlnode: an #xmlNode structure
 * @format: whether to allow formatting (it break XML signatures)
 *
 * Transform an XML node to a C string
 *
 * Return value: a newly allocated C string
 */
char*
lasso_xmlnode_to_string(xmlNode *node, gboolean format, int level)
{
	xmlOutputBufferPtr output_buffer;
	xmlBuffer *buffer;
	char *str;

	if (! node)
		return NULL;

	buffer = xmlBufferCreate();
	output_buffer = xmlOutputBufferCreateBuffer(buffer, NULL);
	xmlNodeDumpOutput(output_buffer, NULL, node, level, format ? 1 : 0, NULL);
	xmlOutputBufferClose(output_buffer);
	xmlBufferAdd(buffer, BAD_CAST "", 1);
	/* do not mix XML and GLib strings, so we must copy */
	str = g_strdup((char*)xmlBufferContent(buffer));
	xmlBufferFree(buffer);

	return str;
}

/**
 * lasso_string_to_xsd_integer:
 * @saml2_assertion: a #LassoSaml2Assertion object
 * @integer: a long int variable to store the result
 *
 * Parse a string using the xsd:integer schema.
 *
 * Return value: TRUE if successful, FALSE otherwise.
 */
gboolean
lasso_string_to_xsd_integer(const char *str, long int *integer)
{
	const char *save = str;

	if (! str)
		return FALSE;
	while (isspace(*str))
		str++;
	if (*str == '+' || *str == '-')
		str++;
	while (isdigit(*str))
		str++;
	while (isspace(*str))
		str++;
	if (*str)
		return FALSE;
	*integer = strtol(save, NULL, 10);
	if ((*integer == LONG_MAX || *integer == LONG_MIN) && errno == ERANGE)
		return FALSE;
	return TRUE;
}

void
lasso_set_string_from_prop(char **str, xmlNode *node, xmlChar *name, xmlChar *ns)
{
	xmlChar *value;

	g_assert(str);
	g_assert(node);
	value = xmlGetNsProp(node, name, ns);
	if (value) {
		lasso_assign_string(*str, (char*)value);
	}
	lasso_release_xml_string(value);
}


/**
 * lasso_log_set_handler:
 * @log_levels: the log levels to apply the log handler for. To handle fatal
 *   and recursive messages as well, combine the log levels with the
 *   #G_LOG_FLAG_FATAL and #G_LOG_FLAG_RECURSION bit flags.
 * @log_func: the log handler function.
 * @user_data: data passed to the log handler.
 *
 * Sets the log handler for a domain and a set of log levels.  To handle fatal
 * and recursive messages the @log_levels parameter must be combined with the
 * #G_LOG_FLAG_FATAL and #G_LOG_FLAG_RECURSION bit flags.
 *
 * Note that since the #G_LOG_LEVEL_ERROR log level is always fatal, if you
 * want to set a handler for this log level you must combine it with
 * #G_LOG_FLAG_FATAL.
 *
 * Returns: the id of the new handler.
 **/
guint
lasso_log_set_handler(GLogLevelFlags log_levels, GLogFunc log_func, gpointer user_data)
{
	return g_log_set_handler(LASSO_LOG_DOMAIN, log_levels, log_func, user_data);
}

/**
 * lasso_log_remove_handler:
 * @handler_id: the id of the handler, which was returned in
 *   lasso_log_set_handler().
 *
 * Removes the log handler.
 **/
void
lasso_log_remove_handler(guint handler_id)
{
	g_log_remove_handler(LASSO_LOG_DOMAIN, handler_id);
}

/**
 * lasso_get_hmac_key:
 * @key: an #xmlSecKey object
 * @buffer: a byte buffer of size @size
 * @size: the size of @buffer as bytes
 *
 * Extract the symetric HMAC key from the #xmlSecKey structure and place a pointer to i into the
 * buffer variable.
 *
 * Return value: 0 if successful, an error code otherwise.
 */
lasso_error_t
lasso_get_hmac_key(const xmlSecKey *key, void **buffer, size_t *size)
{
	xmlSecKeyDataPtr key_data;
	xmlSecBufferPtr key_data_buffer;

	lasso_null_param(key);
	lasso_null_param(buffer);
	lasso_null_param(size);

	if (key->value->id != xmlSecKeyDataHmacId) {
		return LASSO_PARAM_ERROR_INVALID_VALUE;
	}
	key_data = xmlSecKeyGetValue((xmlSecKeyPtr)key);
	g_return_val_if_fail(key_data, LASSO_PARAM_ERROR_INVALID_VALUE);
	key_data_buffer = xmlSecKeyDataBinaryValueGetBuffer(key_data);
	g_return_val_if_fail(key_data_buffer, LASSO_PARAM_ERROR_INVALID_VALUE);
	*buffer = xmlSecBufferGetData(key_data_buffer);
	*size = xmlSecBufferGetSize(key_data_buffer);
	g_return_val_if_fail(*buffer && *size, LASSO_PARAM_ERROR_INVALID_VALUE);
	return 0;
}

/**
 * lasso_make_signature_context_from_buffer:
 * @buffer: a byte buffer of size @length
 * @length: the size of @buffer as bytes
 * @password: an eventual password to decoded the private key contained in @buffer
 * @signature_method: the signature method to associate to this key
 * @certificate: a certificate as a file path or PEM encoded in a NULL-terminated string, to
 * associate with the key, it will be used to fill the KeyInfo node in an eventual signature.
 *
 * Load a signature key and return an initialized #LassoSignatureContext structure. If the structure
 * contains a new #xmlSecKey it must be freed by the caller. If your must store it. use
 * lasso_assign_new_signature_context and not lasso_assign_signature_context which is gonna
 * duplicate the key and so make a leak.
 *
 * Return value: an initialized LassoSignatureContext containing a freshly created @xmlSecKey object
 * successful, LASSO_SIGNATURE_CONTEXT_NONE otherwise. The caller must free the #xmlSecKey.
 */
LassoSignatureContext
lasso_make_signature_context_from_buffer(const void *buffer, size_t length, const char *password,
		LassoSignatureMethod signature_method, const char *certificate) {
	LassoSignatureContext context = LASSO_SIGNATURE_CONTEXT_NONE;

	context.signature_key = lasso_xmlsec_load_private_key_from_buffer(buffer, length, password,
			signature_method, certificate);
	if (context.signature_key) {
		context.signature_method = signature_method;
	}
	return context;
}

/**
 * lasso_make_signature_context_from_path_or_string:
 * @filename_or_buffer: a file path of a string containing the key PEM or Base64 encoded
 * @password: an eventual password to decoded the private key contained in @buffer
 * @signature_method: the signature method to associate to this key
 * @certificate: a certificate as a file path or PEM encoded in a NULL-terminated string, to
 * associate with the key, it will be used to fill the KeyInfo node in an eventual signature.
 *
 * Load a signature key and return an initialized #LassoSignatureContext structure. If the structure
 * contains a new #xmlSecKey it must be freed by the caller. If your must store it. use
 * lasso_assign_new_signature_context and not lasso_assign_signature_context which is gonna
 * duplicate the key and so make a leak.
 *
 * Return value: an initialized LassoSignatureContext containing a freshly created @xmlSecKey object
 * successful, LASSO_SIGNATURE_CONTEXT_NONE otherwise.
 */
LassoSignatureContext
lasso_make_signature_context_from_path_or_string(char *filename_or_buffer, const char *password,
		LassoSignatureMethod signature_method, const char *certificate) {
	LassoSignatureContext context = LASSO_SIGNATURE_CONTEXT_NONE;

	context.signature_key = lasso_xmlsec_load_private_key(filename_or_buffer, password,
			signature_method, certificate);
	if (context.signature_key) {
		context.signature_method = signature_method;
	}
	return context;
}

xmlNs *
get_or_define_ns(xmlNode *xmlnode, const xmlChar *ns_uri, const xmlChar *advised_prefix) {
	xmlNs *ns;
	char prefix[20];
	int i = 1;

	ns = xmlSearchNsByHref(NULL, xmlnode, ns_uri);
	if (ns)
		return ns;
	/* Try with the advised prefix */
	if (advised_prefix) {
		ns = xmlSearchNs(NULL, xmlnode, BAD_CAST prefix);
		if (! ns) { /* If not taken, use it */
			return xmlNewNs(xmlnode, ns_uri, BAD_CAST advised_prefix);
		}
	}
	/* Create a prefix from scratch */
	do {
		sprintf(prefix, "ns%u", i);
		i++;
		ns = xmlSearchNs(NULL, xmlnode, BAD_CAST prefix);
	} while (ns);
	return xmlNewNs(xmlnode, ns_uri, BAD_CAST prefix);
}


void
set_qname_attribute(xmlNode *node,
		const xmlChar *attribute_ns_prefix,
		const xmlChar *attribute_ns_href,
		const xmlChar *attribute_name,
		const xmlChar *prefix,
		const xmlChar *href,
		const xmlChar *name) {
	xmlNs *type_ns;
	xmlNs *xsi_ns;
	xmlChar *value;

	xsi_ns = get_or_define_ns(node, attribute_ns_href, attribute_ns_prefix);
	type_ns = get_or_define_ns(node, href, prefix);
	value = BAD_CAST g_strdup_printf("%s:%s", type_ns->prefix, name);
	xmlSetNsProp(node, xsi_ns, attribute_name, value);
	lasso_release_string(value);
}

void
set_xsi_type(xmlNode *node,
		const xmlChar *type_ns_prefix,
		const xmlChar *type_ns_href,
		const xmlChar *type_name) {
	set_qname_attribute(node,
			BAD_CAST LASSO_XSI_PREFIX,
			BAD_CAST LASSO_XSI_HREF,
			BAD_CAST "type",
			type_ns_prefix,
			type_ns_href,
			type_name);
}

void
lasso_xmlnode_add_saml2_signature_template(xmlNode *node, LassoSignatureContext context,
		const char *id) {
	xmlSecTransformId transform_id;
	xmlNode *existing_signature = NULL, *signature = NULL, *reference, *key_info;
	char *uri;

	if (! lasso_validate_signature_context(context) || ! node)
		return;

	switch (context.signature_method) {
		case LASSO_SIGNATURE_METHOD_RSA_SHA1:
			transform_id = xmlSecTransformRsaSha1Id;
			break;
		case LASSO_SIGNATURE_METHOD_DSA_SHA1:
			transform_id = xmlSecTransformDsaSha1Id;
			break;
		case LASSO_SIGNATURE_METHOD_HMAC_SHA1:
			transform_id = xmlSecTransformHmacSha1Id;
			break;
		default:
			g_assert_not_reached();
	}
	existing_signature = xmlSecFindChild(node, xmlSecNodeSignature, xmlSecDSigNs);
	signature = xmlSecTmplSignatureCreate(NULL,
			xmlSecTransformExclC14NId,
			transform_id, NULL);
	if (existing_signature) {
		xmlSecReplaceNode(existing_signature, signature);
	} else {
		xmlAddChild(node, signature);
	}

	/* Normally the signature is son of the signed node, which holds an Id attribute, but in
	 * other cases, set snippet->offset to 0 and use xmlSecTmpSignatureAddReference from another
	 * node get_xmlNode virtual method to add the needed reference.
	 */
	if (id) {
		uri = g_strdup_printf("#%s", id);
		reference = xmlSecTmplSignatureAddReference(signature,
				xmlSecTransformSha1Id, NULL, (xmlChar*)uri, NULL);
		lasso_release(uri);
	}

	/* add enveloped transform */
	xmlSecTmplReferenceAddTransform(reference, xmlSecTransformEnvelopedId);
	/* add exclusive C14N transform */
	xmlSecTmplReferenceAddTransform(reference, xmlSecTransformExclC14NId);
	/* if the key is the public part of an asymetric key, add its certificate or the key itself */
	switch (context.signature_method) {
		case LASSO_SIGNATURE_METHOD_RSA_SHA1:
		case LASSO_SIGNATURE_METHOD_DSA_SHA1:
			/* asymetric cryptography methods */
			key_info = xmlSecTmplSignatureEnsureKeyInfo(signature, NULL);
			if (xmlSecKeyGetData(context.signature_key, xmlSecOpenSSLKeyDataX509Id)) {
				/* add <dsig:KeyInfo/> */
				xmlSecTmplKeyInfoAddX509Data(key_info);
			} else {
				xmlSecTmplKeyInfoAddKeyValue(key_info);
			}
			break;
		case LASSO_SIGNATURE_METHOD_HMAC_SHA1:
			if (context.signature_key->name) {
				key_info = xmlSecTmplSignatureEnsureKeyInfo(signature, NULL);
				xmlSecTmplKeyInfoAddKeyName(key_info, NULL);

			}
			break;
		default:
			g_assert_not_reached();
	}
}
