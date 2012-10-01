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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

static int
_lasso_openssl_pwd_callback(char *buf, int size, G_GNUC_UNUSED int rwflag, void *u)
{
	if (u) {
		strncpy(buf, u, size);
		return strlen(u);
	}
	return 0;
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
lasso_query_sign(char *query, LassoSignatureMethod sign_method, const char *private_key_file,
		const char *private_key_file_password)
{
	BIO *bio = NULL;
	char *digest = NULL; /* 160 bit buffer */
	RSA *rsa = NULL;
	DSA *dsa = NULL;
	unsigned char *sigret = NULL;
	unsigned int siglen;
	char *b64_sigret = NULL, *e_b64_sigret = NULL;
	char *new_query = NULL, *s_new_query = NULL;
	int status = 0;
	char *t;

	g_return_val_if_fail(query != NULL, NULL);
	g_return_val_if_fail(sign_method == LASSO_SIGNATURE_METHOD_RSA_SHA1 ||
			sign_method == LASSO_SIGNATURE_METHOD_DSA_SHA1, NULL);
	g_return_val_if_fail(private_key_file != NULL, NULL);

	if (access(private_key_file, R_OK) == 0) {
		bio = BIO_new_file(private_key_file, "rb");
	} else {
		// Safe deconst cast, the BIO is read-only
		bio = BIO_new_mem_buf((char*)private_key_file, -1);
	}
	if (bio == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "Failed to open %s private key file",
				private_key_file);
		return NULL;
	}

	/* add SigAlg */
	switch (sign_method) {
		case LASSO_SIGNATURE_METHOD_RSA_SHA1:
			t = (char*)xmlURIEscapeStr(xmlSecHrefRsaSha1, NULL);
			new_query = g_strdup_printf("%s&SigAlg=%s", query, t);
			xmlFree(t);
			break;
		case LASSO_SIGNATURE_METHOD_DSA_SHA1:
			t = (char*)xmlURIEscapeStr(xmlSecHrefDsaSha1, NULL);
			new_query = g_strdup_printf("%s&SigAlg=%s", query, t);
			xmlFree(t);
			break;
		case LASSO_SIGNATURE_METHOD_LAST:
			g_assert_not_reached();
	}

	/* build buffer digest */
	digest = lasso_sha1(new_query);
	if (digest == NULL) {
		message(G_LOG_LEVEL_CRITICAL, "Failed to build the buffer digest");
		goto done;
	}

	/* calculate signature value */
	if (sign_method == LASSO_SIGNATURE_METHOD_RSA_SHA1) {
		/* load private key */
		rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, _lasso_openssl_pwd_callback,
				(void*)private_key_file_password);
		if (rsa == NULL) {
			goto done;
		}
		/* alloc memory for sigret */
		sigret = (unsigned char *)g_malloc (RSA_size(rsa));
		/* sign digest message */
		status = RSA_sign(NID_sha1, (unsigned char*)digest, 20, sigret, &siglen, rsa);
		RSA_free(rsa);
	} else if (sign_method == LASSO_SIGNATURE_METHOD_DSA_SHA1) {
		dsa = PEM_read_bio_DSAPrivateKey(bio, NULL, _lasso_openssl_pwd_callback,
				(void*)private_key_file_password);
		if (dsa == NULL) {
			goto done;
		}
		sigret = (unsigned char *)g_malloc (DSA_size(dsa));
		status = DSA_sign(NID_sha1, (unsigned char*)digest, 20, sigret, &siglen, dsa);
		DSA_free(dsa);
	}

	if (status == 0) {
		goto done;
	}

	/* Base64 encode the signature value */
	b64_sigret = (char*)xmlSecBase64Encode(sigret, siglen, 0);
	/* escape b64_sigret */
	e_b64_sigret = (char*)xmlURIEscapeStr((xmlChar*)b64_sigret, NULL);

	/* add signature */
	switch (sign_method) {
		case LASSO_SIGNATURE_METHOD_RSA_SHA1:
			s_new_query = g_strdup_printf("%s&Signature=%s", new_query, e_b64_sigret);
			break;
		case LASSO_SIGNATURE_METHOD_DSA_SHA1:
			s_new_query = g_strdup_printf("%s&Signature=%s", new_query, e_b64_sigret);
			break;
		case LASSO_SIGNATURE_METHOD_LAST:
			g_assert_not_reached();
	}

done:
	lasso_release(new_query);
	xmlFree(digest);
	BIO_free(bio);
	lasso_release(sigret);
	xmlFree(b64_sigret);
	xmlFree(e_b64_sigret);

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
int
lasso_query_verify_signature(const char *query, const xmlSecKey *sender_public_key)
{
	RSA *rsa = NULL;
	DSA *dsa = NULL;
	gchar **str_split = NULL;
	char *digest = NULL, *b64_signature = NULL;
	xmlSecByte *signature = NULL;
	int key_size, status = 0, ret = 0;
	char *sig_alg, *usig_alg = NULL;

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
	if (str_split[0] == NULL || str_split[1] == NULL) {
		g_strfreev(str_split);
		return LASSO_DS_ERROR_SIGNATURE_NOT_FOUND;
	}

	if (sender_public_key->value->id == xmlSecOpenSSLKeyDataRsaId) {
	} else {
		/* no key; it will fail later */
	}

	sig_alg = strstr(str_split[0], "&SigAlg=");
	if (sig_alg == NULL) {
		ret = critical_error(LASSO_DS_ERROR_INVALID_SIGALG);
		goto done;
	}
	sig_alg = strchr(sig_alg, '=')+1;

	usig_alg = xmlURIUnescapeString(sig_alg, 0, NULL);
	if (strcmp(usig_alg, (char*)xmlSecHrefRsaSha1) == 0) {
		if (sender_public_key->value->id != xmlSecOpenSSLKeyDataRsaId) {
			ret = critical_error(LASSO_DS_ERROR_PUBLIC_KEY_LOAD_FAILED);
			goto done;
		}
		rsa = xmlSecOpenSSLKeyDataRsaGetRsa(sender_public_key->value);
		if (rsa == NULL) {
			ret = critical_error(LASSO_DS_ERROR_PUBLIC_KEY_LOAD_FAILED);
			goto done;
		}
		key_size = RSA_size(rsa);
	} else if (strcmp(usig_alg, (char*)xmlSecHrefDsaSha1) == 0) {
		if (sender_public_key->value->id != xmlSecOpenSSLKeyDataDsaId) {
			ret = critical_error(LASSO_DS_ERROR_PUBLIC_KEY_LOAD_FAILED);
			goto done;
		}
		dsa = xmlSecOpenSSLKeyDataDsaGetDsa(sender_public_key->value);
		if (dsa == NULL) {
			ret = critical_error(LASSO_DS_ERROR_PUBLIC_KEY_LOAD_FAILED);
			goto done;
		}
		key_size = DSA_size(dsa);
	} else {
		ret = critical_error(LASSO_DS_ERROR_INVALID_SIGALG);
		goto done;
	}

	/* insure there is only the signature in str_split[1] */
	if (strchr(str_split[1], '&')) {
		strchr(str_split[1], '&')[0] = 0;
	}

	/* get signature (unescape + base64 decode) */
	signature = xmlMalloc(key_size+1);
	b64_signature = (char*)xmlURIUnescapeString(str_split[1], 0, NULL);
	if (b64_signature == NULL || xmlSecBase64Decode((xmlChar*)b64_signature, signature, key_size+1) < 0) {
		ret = LASSO_DS_ERROR_INVALID_SIGNATURE;
		goto done;
	}

	/* compute signature digest */
	digest = lasso_sha1(str_split[0]);
	if (digest == NULL) {
		ret = critical_error(LASSO_DS_ERROR_DIGEST_COMPUTE_FAILED);
		goto done;
	}

	if (rsa) {
		status = RSA_verify(NID_sha1, (unsigned char*)digest, 20, signature, key_size, rsa);
	} else if (dsa) {
		status = DSA_verify(NID_sha1, (unsigned char*)digest, 20, signature, key_size, dsa);
	}

	if (status != 1) {
		ret = LASSO_DS_ERROR_INVALID_SIGNATURE;
	}

done:
	xmlFree(b64_signature);
	xmlFree(signature);
	xmlFree(digest);
	xmlFree(usig_alg);
	g_strfreev(str_split);

	return ret;
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
	RSA *rsa = NULL;
	DSA *dsa = NULL;
	char *digest = NULL, *b64_signature = NULL;
	xmlSecByte *signature = NULL;
	int key_size, status = 0, ret = 0;
	char *query_copy = NULL;
	char *signed_query = NULL;
	char *i = NULL;
	char **components = NULL, **j = NULL;
	int n = 0;
	char *saml_request_response = NULL;
	char *relaystate = NULL;
	char *sig_alg, *usig_alg = NULL;

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
		ret = LASSO_PROFILE_ERROR_INVALID_QUERY;
		goto done;
	}

	if (! b64_signature) {
		ret = LASSO_DS_ERROR_SIGNATURE_NOT_FOUND;
		goto done;
	}
	/* build the signed query */
	if (relaystate) {
		signed_query = g_strconcat(saml_request_response, "&", relaystate, "&", sig_alg, NULL);
	} else {
		signed_query = g_strconcat(saml_request_response, "&", sig_alg, NULL);
	}

	sig_alg = strchr(sig_alg, '=')+1;
	if (! sig_alg) {
		ret = LASSO_DS_ERROR_INVALID_SIGALG;
		goto done;
	}
	usig_alg = xmlURIUnescapeString(sig_alg, 0, NULL);
	if (lasso_strisequal(usig_alg,(char *)xmlSecHrefRsaSha1)) {
		if (sender_public_key->value->id != xmlSecOpenSSLKeyDataRsaId) {
			ret = critical_error(LASSO_DS_ERROR_PUBLIC_KEY_LOAD_FAILED);
			goto done;
		}
		rsa = xmlSecOpenSSLKeyDataRsaGetRsa(sender_public_key->value);
		if (rsa == NULL) {
			ret = critical_error(LASSO_DS_ERROR_PUBLIC_KEY_LOAD_FAILED);
			goto done;
		}
		key_size = RSA_size(rsa);
	} else if (lasso_strisequal(usig_alg,(char *)xmlSecHrefDsaSha1)) {
		if (sender_public_key->value->id != xmlSecOpenSSLKeyDataDsaId) {
			ret = critical_error(LASSO_DS_ERROR_PUBLIC_KEY_LOAD_FAILED);
			goto done;
		}
		dsa = xmlSecOpenSSLKeyDataDsaGetDsa(sender_public_key->value);
		if (dsa == NULL) {
			ret = critical_error(LASSO_DS_ERROR_PUBLIC_KEY_LOAD_FAILED);
			goto done;
		}
		key_size = DSA_size(dsa);
	} else {
		ret = critical_error(LASSO_DS_ERROR_INVALID_SIGALG);
		goto done;
	}

	/* get signature (unescape + base64 decode) */
	signature = xmlMalloc(key_size+1);
	xmlSecErrorsDefaultCallbackEnableOutput(FALSE);
	if (b64_signature == NULL || xmlSecBase64Decode((xmlChar*)b64_signature, signature, key_size+1) < 0) {
		xmlSecErrorsDefaultCallbackEnableOutput(TRUE);
		ret = LASSO_DS_ERROR_INVALID_SIGNATURE;
		goto done;
	}
	xmlSecErrorsDefaultCallbackEnableOutput(TRUE);

	/* compute signature digest */
	digest = lasso_sha1(signed_query);
	if (digest == NULL) {
		ret = critical_error(LASSO_DS_ERROR_DIGEST_COMPUTE_FAILED);
		goto done;
	}

	if (rsa) {
		status = RSA_verify(NID_sha1, (unsigned char*)digest, 20, signature, key_size, rsa);
	} else if (dsa) {
		status = DSA_verify(NID_sha1, (unsigned char*)digest, 20, signature, key_size, dsa);
	}

	if (status != 1) {
		ret = LASSO_DS_ERROR_INVALID_SIGNATURE;
	}

done:
	xmlFree(b64_signature);
	xmlFree(signature);
	xmlFree(digest);
	xmlFree(usig_alg);
	lasso_release(components);
	lasso_release(query_copy);
	lasso_release(signed_query);

	return ret;
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

	md = xmlMalloc(20);
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
			result[i] = xmlURIUnescapeString(st2, len, NULL);
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
lasso_sign_node(xmlNode *xmlnode, const char *id_attr_name, const char *id_value,
		const char *private_key_file, const char *private_key_password,
		const char *certificate_file)
{
	xmlDoc *doc;
	xmlNode *sign_tmpl, *old_parent;
	xmlSecDSigCtx *dsig_ctx;
	xmlAttr *id_attr = NULL;
	void *password_callback = NULL;

	if (private_key_file == NULL || xmlnode == NULL)
		return LASSO_PARAM_ERROR_BAD_TYPE_OR_NULL_OBJ;

	sign_tmpl = xmlSecFindNode(xmlnode, xmlSecNodeSignature, xmlSecDSigNs);
	if (sign_tmpl == NULL)
		return LASSO_DS_ERROR_SIGNATURE_TEMPLATE_NOT_FOUND;

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
	if (! private_key_password) {
		password_callback = _lasso_openssl_pwd_callback;
	}
	if (access(private_key_file, R_OK) == 0) {
		dsig_ctx->signKey = xmlSecCryptoAppKeyLoad(private_key_file,
				xmlSecKeyDataFormatPem, private_key_password,
				password_callback, NULL /* password_callback_ctx */);
	} else {
		int len = private_key_file ? strlen(private_key_file) : 0;
		dsig_ctx->signKey = xmlSecCryptoAppKeyLoadMemory((xmlSecByte*)private_key_file, len,
				xmlSecKeyDataFormatPem, private_key_password,
				password_callback, NULL /* password_callback_ctx */);
	}
	if (dsig_ctx->signKey == NULL) {
		xmlSecDSigCtxDestroy(dsig_ctx);
		return critical_error(LASSO_DS_ERROR_PRIVATE_KEY_LOAD_FAILED);
	}
	if (certificate_file != NULL && certificate_file[0] != 0) {
		int rc = -1;

		if (access(certificate_file, R_OK) == 0) {
			rc = xmlSecCryptoAppKeyCertLoad(dsig_ctx->signKey, certificate_file,
						xmlSecKeyDataFormatPem);
		} else {
			int len = certificate_file ? strlen(certificate_file) : 0;

			rc = xmlSecCryptoAppKeyCertLoadMemory(dsig_ctx->signKey, (xmlSecByte*)certificate_file,
						len, xmlSecKeyDataFormatPem);
		}
		if (rc < 0) {
			xmlSecDSigCtxDestroy(dsig_ctx);
			return critical_error(LASSO_DS_ERROR_CERTIFICATE_LOAD_FAILED);
		}
	}
	if (xmlSecDSigCtxSign(dsig_ctx, sign_tmpl) < 0) {
		xmlSecDSigCtxDestroy(dsig_ctx);
		return critical_error(LASSO_DS_ERROR_SIGNATURE_FAILED);
	}
	xmlSecDSigCtxDestroy(dsig_ctx);
	xmlRemoveID(doc, id_attr);
	xmlUnlinkNode(xmlnode);
	lasso_release_doc(doc);
	xmlnode->parent = old_parent;
	xmlSetTreeDoc(xmlnode, NULL);

	return 0;
}

static gchar*
lasso_xmlnode_build_deflated_query(xmlNode *xmlnode)
{
	xmlOutputBuffer *output_buffer;
	xmlBuffer *buffer;
	xmlChar *ret, *b64_ret;
	char *rret;
	unsigned long in_len;
	int rc = 0;
	z_stream stream;

	buffer = xmlBufferCreate();
	output_buffer = xmlOutputBufferCreateBuffer(buffer, NULL);
	xmlNodeDumpOutput(output_buffer, NULL, xmlnode, 0, 0, NULL);
	xmlOutputBufferClose(output_buffer);
	xmlBufferAdd(buffer, BAD_CAST "", 1);
	lasso_release_xml_node(xmlnode);
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

	void structuredErrorFunc (G_GNUC_UNUSED void *userData, xmlErrorPtr error) {
		errorCode = error->code;
	}

	g_return_val_if_fail(xpath_ctx != NULL && expression != NULL, FALSE);

	if (xpath_error_code) { /* reset */
		*xpath_error_code = 0;
	}
	oldStructuredErrorFunc = xpath_ctx->error;
	xpath_ctx->error = structuredErrorFunc;
	xpath_object = xmlXPathEvalExpression((xmlChar*)expression, xpath_ctx);
	xpath_ctx->error = oldStructuredErrorFunc;

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

	g_return_val_if_fail(signed_node && id_attr_name && (keys_manager || public_key),
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
	id = xmlGetProp(signed_node, (xmlChar*)id_attr_name);
	if (id) {
		xmlAddID(NULL, doc, id, xmlHasProp(signed_node, (xmlChar*)id_attr_name));
	}

	/* Create DSig context */
	dsigCtx = xmlSecDSigCtxCreate(keys_manager);
	goto_cleanup_if_fail_with_rc(doc, LASSO_DS_ERROR_CONTEXT_CREATION_FAILED);
	/* XXX: Is xmlSecTransformUriTypeSameEmpty permitted ?
	 * I would say yes only if signed_node == signature->parent. */
	dsigCtx->enabledReferenceUris = xmlSecTransformUriTypeSameDocument;
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
	reference_uri = g_strdup_printf("#%s", id);
	dsig_reference_ctx = (xmlSecDSigReferenceCtx*)xmlSecPtrListGetItem(&(dsigCtx->signedInfoReferences), 0);
	goto_cleanup_if_fail_with_rc(dsig_reference_ctx != 0 &&
			strcmp((char*)dsig_reference_ctx->uri, reference_uri) == 0,
			LASSO_DS_ERROR_INVALID_REFERENCE_FOR_SAML);
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
	int rc = LASSO_DS_ERROR_DECRYPTION_FAILED;

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
	if (sym_key == NULL) {
		message(G_LOG_LEVEL_WARNING, "EncryptedKey decryption failed");
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
	g_log("Lasso", log_level, "libxml2: %s", escaped);
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
	GError *error;

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
		result = xmlURIUnescapeString(start, length, NULL);
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
	int rc = 0;
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
		goto_cleanup_if_fail_with_rc(encoded_key, 0);

		value = va_arg(ap, char*);
		if (! value) {
			message(G_LOG_LEVEL_CRITICAL, "lasso_url_add_parameter: key without a value !!");
			break;
		}
		encoded_value = xmlURIEscapeStr((xmlChar*)value, NULL);
		goto_cleanup_if_fail_with_rc(encoded_value, 0);

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
_lasso_xmlsec_load_key_from_buffer(const char *buffer, size_t length, const char *password)
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
	xmlSecKey *private_key = NULL;

	xmlSecErrorsDefaultCallbackEnableOutput(FALSE);
	for (i = 0; key_formats[i] && private_key == NULL; i++) {
		private_key = xmlSecCryptoAppKeyLoadMemory((xmlSecByte*)buffer, length,
				key_formats[i], password, NULL, NULL);
	}
	xmlSecErrorsDefaultCallbackEnableOutput(TRUE);

	return private_key;
}

/**
 * lasso_xmlsec_load_private_key_from_buffer:
 * @buffer: a buffer containing a key in any format
 * @length: length of the buffer
 * @password: eventually a password
 */
xmlSecKey*
lasso_xmlsec_load_private_key_from_buffer(const char *buffer, size_t length, const char *password) {
	xmlSecKey *private_key = NULL;

	private_key = _lasso_xmlsec_load_key_from_buffer(buffer, length, password);

	/* special lasso metadata hack */
	if (! private_key) {
		xmlChar *out;
		int len;
		out = xmlMalloc(length*4);
		xmlSecErrorsDefaultCallbackEnableOutput(FALSE);
		len = xmlSecBase64Decode(BAD_CAST buffer, out, length*4);
		xmlSecErrorsDefaultCallbackEnableOutput(TRUE);
		private_key = _lasso_xmlsec_load_key_from_buffer((char*)out, len, password);
		xmlFree(out);
	}

	return private_key;
}

xmlSecKey*
lasso_xmlsec_load_private_key(const char *filename_or_buffer, const char *password) {
	char *buffer = NULL;
	size_t length;
	xmlSecKey *ret;

	if (! filename_or_buffer)
		return NULL;

	if (g_file_get_contents(filename_or_buffer, &buffer, &length, NULL)) {
		ret = lasso_xmlsec_load_private_key_from_buffer(buffer, length, password);
	} else {
		ret = lasso_xmlsec_load_private_key_from_buffer(filename_or_buffer, strlen(filename_or_buffer), password);
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
		result = lasso_xmlsec_load_private_key_from_buffer((char*)content, strlen((char*)content), NULL);
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
	return g_log_set_handler("Lasso", log_levels, log_func, user_data);
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
	g_log_remove_handler("Lasso", handler_id);
}

void
lasso_apply_signature(LassoNode *node, gboolean lasso_dump,
		xmlNode **xmlnode, char *id_attribute, char *id_value, LassoSignatureType old_sign_type, char *old_private_key_file, char *old_certificate_file)
{
	int rc = 0;
	LassoSignatureType sign_type = LASSO_SIGNATURE_TYPE_NONE;
	LassoSignatureMethod sign_method = LASSO_SIGNATURE_METHOD_RSA_SHA1;
	char *private_key_file = NULL;
	char *private_key_password = NULL;
	char *certificate_file = NULL;

	lasso_node_get_signature(node, &sign_type, &sign_method, &private_key_file, &private_key_password,
			&certificate_file);

	if (!sign_type) {
		sign_type = old_sign_type;
		private_key_password = NULL;
		private_key_file = old_private_key_file;
		certificate_file = old_certificate_file;
	}

	if (lasso_dump == FALSE && sign_type) {
		char *node_name;
		char *prefix;

		node_name = LASSO_NODE_GET_CLASS(node)->node_data->node_name;
		prefix = (char*)LASSO_NODE_GET_CLASS(node)->node_data->ns->prefix;

		if (private_key_file == NULL) {
			message(G_LOG_LEVEL_WARNING,
					"No Private Key set for signing %s:%s", prefix, node_name);
		} else {
			rc = lasso_sign_node(*xmlnode, id_attribute, id_value, private_key_file,
					private_key_password, certificate_file);
			if (rc != 0) {
				message(G_LOG_LEVEL_WARNING, "Signing of %s:%s: %s", prefix, node_name, lasso_strerror(rc));
			}
		}
		if (rc != 0) {
			lasso_release_xml_node(*xmlnode);
		}
	}
}
