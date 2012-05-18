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

#include "private.h"
#include <string.h>
#include <time.h>
#include <ctype.h>

#include <libxml/uri.h>
#include <libxml/parser.h>
#include <libxml/parserInternals.h>

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
#include <lasso/xml/xml.h>
#include <lasso/xml/xml_enc.h>
#include <lasso/xml/saml-2.0/saml2_assertion.h>
#include <unistd.h>
#include "../debug.h"
#include "../utils.h"

LassoNode* lasso_assertion_encrypt(LassoSaml2Assertion *assertion);
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
 * Return value: a "unique" ID (begin always with _ character)
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
 * lasso_get_current_time:
 *
 * Returns the current time, format is "yyyy-mm-ddThh:mm:ssZ".
 *
 * Return value: a string
 **/
char*
lasso_get_current_time()
{
	time_t now;
	struct tm *tm;
	char *ret;

	ret = g_malloc(21);
	now = time(NULL);
	tm = gmtime(&now);
	strftime(ret, 21, "%Y-%m-%dT%H:%M:%SZ", tm);

	return ret;
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
			message(G_LOG_LEVEL_WARNING, "PEM file type unknown: %s", file);
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
	xmlSecKeysMngrPtr keys_mngr;
	GIOChannel *gioc;
	gchar *line;
	gsize len, pos;
	GString *cert = NULL;
	gint ret;

	/* No file just return NULL */
	if (! pem_certs_chain_file || strlen(pem_certs_chain_file) == 0) {
		return NULL;
	}
	gioc = g_io_channel_new_file(pem_certs_chain_file, "r", NULL);
	if (! gioc) {
		message(G_LOG_LEVEL_WARNING, "Cannot open chain file %s", pem_certs_chain_file);
		return NULL;
	}

	/* create keys manager */
	keys_mngr = xmlSecKeysMngrCreate();
	if (keys_mngr == NULL) {
		message(G_LOG_LEVEL_CRITICAL,
				lasso_strerror(LASSO_DS_ERROR_KEYS_MNGR_CREATION_FAILED));
		return NULL;
	}
	/* initialize keys manager */
	if (xmlSecCryptoAppDefaultKeysMngrInit(keys_mngr) < 0) {
		message(G_LOG_LEVEL_CRITICAL,
				lasso_strerror(LASSO_DS_ERROR_KEYS_MNGR_INIT_FAILED));
		xmlSecKeysMngrDestroy(keys_mngr);
		return NULL;
	}

	while (g_io_channel_read_line(gioc, &line, &len, &pos, NULL) == G_IO_STATUS_NORMAL) {
		if (g_strstr_len(line, 64, "BEGIN CERTIFICATE") != NULL) {
			cert = g_string_new(line);
		} else if (g_strstr_len(line, 64, "END CERTIFICATE") != NULL) {
			g_string_append(cert, line);
			/* load the new certificate found in the keys manager */
			ret = xmlSecCryptoAppKeysMngrCertLoadMemory(keys_mngr,
					(const xmlSecByte*) cert->str,
					(xmlSecSize) cert->len,
					xmlSecKeyDataFormatPem,
					xmlSecKeyDataTypeTrusted);
			g_string_free(cert, TRUE);
			cert = NULL;
			if (ret < 0) {
				if (line) {
					g_free(line);
					xmlSecKeysMngrDestroy(keys_mngr);
				}
				g_io_channel_shutdown(gioc, TRUE, NULL);
				return NULL;
			}
		} else if (cert != NULL && line != NULL && line[0] != '\0') {
			g_string_append(cert, line);
		} else {
			debug("Empty line found in the CA certificate chain file");
		}
		/* free last line read */
		if (line != NULL) {
			g_free(line);
			line = NULL;
		}
	}

	g_io_channel_shutdown(gioc, TRUE, NULL);
	g_io_channel_unref(gioc);

	return keys_mngr;
}

/*
 * lasso_query_sign:
 * @query: a query (an url-encoded node)
 * @sign_method: the Signature transform method
 * @private_key_file: the private key
 *
 * Signs a query (url-encoded message).
 *
 * Return value: a newly allocated query signed or NULL if an error occurs.
 **/
char*
lasso_query_sign(char *query, LassoSignatureMethod sign_method, const char *private_key_file)
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
		rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
		if (rsa == NULL) {
			goto done;
		}
		/* alloc memory for sigret */
		sigret = (unsigned char *)g_malloc (RSA_size(rsa));
		/* sign digest message */
		status = RSA_sign(NID_sha1, (unsigned char*)digest, 20, sigret, &siglen, rsa);
		RSA_free(rsa);
	} else if (sign_method == LASSO_SIGNATURE_METHOD_DSA_SHA1) {
		dsa = PEM_read_bio_DSAPrivateKey(bio, NULL, NULL, NULL);
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
	}

done:
	g_free(new_query);
	xmlFree(digest);
	BIO_free(bio);
	g_free(sigret);
	xmlFree(b64_sigret);
	xmlFree(e_b64_sigret);

	return s_new_query;
}

LassoNode*
lasso_assertion_encrypt(LassoSaml2Assertion *assertion)
{
	LassoNode *encrypted_element = NULL;
	gchar *b64_value;
	xmlSecByte *value;
	int length;
	int rc;
	xmlSecKey *encryption_public_key = NULL;
	int i;
	xmlSecKeyDataFormat key_formats[] = {
		xmlSecKeyDataFormatDer,
		xmlSecKeyDataFormatCertDer,
		xmlSecKeyDataFormatPkcs8Der,
		xmlSecKeyDataFormatCertPem,
		xmlSecKeyDataFormatPkcs8Pem,
		xmlSecKeyDataFormatPem,
		xmlSecKeyDataFormatBinary,
		0
	};

	if (assertion->encryption_activated == FALSE ||
			assertion->encryption_public_key_str == NULL) {
		return NULL;
	}

	b64_value = g_strdup(assertion->encryption_public_key_str);
	length = strlen(b64_value);
	value = g_malloc(length*4); /* enough place for decoding */
	rc = xmlSecBase64Decode((xmlChar*)b64_value, value, length);
	if (rc < 0) {
		/* bad base-64 */
		g_free(value);
		g_free(b64_value);
		return NULL;
	}

	xmlSecErrorsDefaultCallbackEnableOutput(FALSE);
	for (i = 0; key_formats[i] && encryption_public_key == NULL; i++) {
		encryption_public_key = xmlSecCryptoAppKeyLoadMemory(value, rc,
				key_formats[i], NULL, NULL, NULL);
	}
	xmlSecErrorsDefaultCallbackEnableOutput(TRUE);

	/* Finally encrypt the assertion */
	encrypted_element = LASSO_NODE(lasso_node_encrypt(LASSO_NODE(assertion),
		encryption_public_key, assertion->encryption_sym_key_type));

	g_free(b64_value);
	g_free(value);

	return encrypted_element;
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
	if (str_split[1] == NULL) {
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
	xmlSecBase64Decode((xmlChar*)b64_signature, signature, key_size+1);

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

	st = (char*)str;
	while (strchr(st, '&')) {
		st = strchr(st, '&')+1;
		n++;
	}

	result = g_malloc(sizeof(char*)*(n+1));
	result[n] = NULL;

	st = (char*)str;
	for (i=0; i<n; i++) {
		st2 = strchr(st, '&');
		st2 = st2 ? st2 : st+strlen(st);
		result[i] = xmlURIUnescapeString(st, st2-st, NULL);
		st = st2 + 1;
	}
	return result;
}

void
_debug(GLogLevelFlags level, const char *filename, int line,
		const char *function, const char *format, ...)
{
	char debug_string[1024];
	time_t ts;
	char date[20];
	va_list args;

	va_start(args, format);
	g_vsnprintf(debug_string, 1024, format, args);
	va_end(args);

	time(&ts);
	strftime(date, 20, "%Y-%m-%d %H:%M:%S", localtime(&ts));

	if (level == G_LOG_LEVEL_DEBUG || level == G_LOG_LEVEL_CRITICAL) {
		g_log("Lasso", level, "%s (%s/%s:%d)\n======> %s",
				date, filename, function, line, debug_string);
	} else {
		g_log("Lasso", level, "%s\t%s", date, debug_string);
	}
}

int
error_code(G_GNUC_UNUSED GLogLevelFlags level, int error, ...)
{
	const char *format;
	char message[1024];
	va_list args;

	format = lasso_strerror(error);

	va_start(args, error);
	g_vsnprintf(message, 1024, format, args);
	va_end(args);

	return error;
}


int
lasso_sign_node(xmlNode *xmlnode, const char *id_attr_name, const char *id_value,
		const char *private_key_file, G_GNUC_UNUSED const char* private_key_password, const char *certificate_file)
{
	xmlDoc *doc;
	xmlNode *sign_tmpl, *old_parent;
	xmlSecDSigCtx *dsig_ctx;
	xmlAttr *id_attr = NULL;

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
	if (access(private_key_file, R_OK) == 0) {
		dsig_ctx->signKey = xmlSecCryptoAppKeyLoad(private_key_file,
				xmlSecKeyDataFormatPem,
				NULL, NULL, NULL);
	} else {
		int len = private_key_file ? strlen(private_key_file) : 0;
		dsig_ctx->signKey = xmlSecCryptoAppKeyLoadMemory((xmlSecByte*)private_key_file, len,
				xmlSecKeyDataFormatPem, NULL, NULL, NULL);
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

gchar*
lasso_node_build_deflated_query(LassoNode *node)
{
	/* actually deflated and b64'ed and url-escaped */
	xmlNode *xmlnode;
	xmlOutputBufferPtr buf;
	xmlCharEncodingHandlerPtr handler = NULL;
	xmlChar *buffer;
	xmlChar *ret, *b64_ret;
	char *rret;
	unsigned long in_len;
	int rc;
	z_stream stream;

	xmlnode = lasso_node_get_xmlNode(node, FALSE);

	handler = xmlFindCharEncodingHandler("utf-8");
	buf = xmlAllocOutputBuffer(handler);
	xmlNodeDumpOutput(buf, NULL, xmlnode, 0, 0, "utf-8");
	xmlOutputBufferFlush(buf);
	buffer = buf->conv ? buf->conv->content : buf->buffer->content;

	xmlFreeNode(xmlnode);
	xmlnode = NULL;

	in_len = strlen((char*)buffer);
	ret = g_malloc(in_len * 2);
		/* deflating should never increase the required size but we are
		 * more conservative than that.  Twice the size should be
		 * enough. */

	stream.next_in = buffer;
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
	if (rc != Z_OK) {
		g_free(ret);
		message(G_LOG_LEVEL_CRITICAL, "Failed to deflate");
		return NULL;
	}

	b64_ret = xmlSecBase64Encode(ret, stream.total_out, 0);
	xmlOutputBufferClose(buf);
	g_free(ret);

	ret = xmlURIEscapeStr(b64_ret, NULL);
	rret = g_strdup((char*)ret);
	xmlFree(b64_ret);
	xmlFree(ret);

	return rret;
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

static gboolean
lasso_saml_constrain_dsigctxt(xmlSecDSigCtxPtr dsigCtx) {
	/* Limit allowed transforms for signature and reference processing */
	if((xmlSecDSigCtxEnableSignatureTransform(dsigCtx, xmlSecTransformInclC14NId) < 0) ||
			(xmlSecDSigCtxEnableSignatureTransform(dsigCtx, xmlSecTransformExclC14NId) < 0) ||
			(xmlSecDSigCtxEnableSignatureTransform(dsigCtx, xmlSecTransformSha1Id) < 0) ||
			(xmlSecDSigCtxEnableSignatureTransform(dsigCtx, xmlSecTransformRsaSha1Id) < 0)) {

		g_warning("Error: failed to limit allowed signature transforms");
		return FALSE;
	}
	if((xmlSecDSigCtxEnableReferenceTransform(dsigCtx, xmlSecTransformInclC14NId) < 0) ||
			(xmlSecDSigCtxEnableReferenceTransform(dsigCtx, xmlSecTransformExclC14NId) < 0) ||
			(xmlSecDSigCtxEnableReferenceTransform(dsigCtx, xmlSecTransformSha1Id) < 0) ||
			(xmlSecDSigCtxEnableReferenceTransform(dsigCtx, xmlSecTransformEnvelopedId) < 0)) {

		g_warning("Error: failed to limit allowed reference transforms");
		return FALSE;
	}

	/* Limit possible key info to X509, RSA and DSA */
	if((xmlSecPtrListAdd(&(dsigCtx->keyInfoReadCtx.enabledKeyData), BAD_CAST xmlSecKeyDataX509Id) < 0) ||
			(xmlSecPtrListAdd(&(dsigCtx->keyInfoReadCtx.enabledKeyData), BAD_CAST xmlSecKeyDataRsaId) < 0) ||
			(xmlSecPtrListAdd(&(dsigCtx->keyInfoReadCtx.enabledKeyData), BAD_CAST xmlSecKeyDataDsaId) < 0)) {
		g_warning("Error: failed to limit allowed key data");
		return FALSE;
	}
	return TRUE;
}

/**
 * lasso_verify_signature:
 * @signed_node: an #xmlNode containing an enveloped xmlDSig signature
 * @id_attr_name: the id attribune name for this node
 * @keys_manager: an #xmlSecKeysMnr containing the CA cert chain, to validate the key in the
 * signature if there is one.
 * @public_key: a public key to validate the signature, if present the function ignore the key
 * contained in the signature.
 *
 * This function validate a signature on an xmlNode following the instructions given in the document
 * Assertions and Protocol or the OASIS Security Markup Language (SAML) V1.1.
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
	/* Find signature */
	signature = xmlSecFindNode(signed_node, xmlSecNodeSignature, xmlSecDSigNs);
	goto_exit_if_fail (signature, LASSO_DS_ERROR_SIGNATURE_NOT_FOUND);

	/* Create a temporary doc, if needed */
	if (doc == NULL) {
		doc = xmlNewDoc((xmlChar*)XML_DEFAULT_VERSION);
		goto_exit_if_fail(doc, LASSO_ERROR_OUT_OF_MEMORY);
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
	goto_exit_if_fail(doc, LASSO_DS_ERROR_CONTEXT_CREATION_FAILED);
	/* XXX: Is xmlSecTransformUriTypeSameEmpty permitted ?
	 * I would say yes only if signed_node == signature->parent. */
	dsigCtx->enabledReferenceUris = xmlSecTransformUriTypeSameDocument;
	goto_exit_if_fail(lasso_saml_constrain_dsigctxt(dsigCtx),
			LASSO_DS_ERROR_SIGNATURE_VERIFICATION_FAILED);
	/* Given a public key use it to validate the signature ! */
	if (public_key) {
		dsigCtx->signKey = xmlSecKeyDuplicate(public_key);
	}

	/* Verify signature */
	goto_exit_if_fail(xmlSecDSigCtxVerify(dsigCtx, signature) >= 0,
			LASSO_DS_ERROR_SIGNATURE_VERIFICATION_FAILED);
	goto_exit_if_fail(dsigCtx->status == xmlSecDSigStatusSucceeded,
			LASSO_DS_ERROR_SIGNATURE_VERIFICATION_FAILED);

	/* There should be only one reference */
	goto_exit_if_fail(((signature_verification_option & NO_SINGLE_REFERENCE) == 0) &&
			xmlSecPtrListGetSize(&(dsigCtx->signedInfoReferences)) == 1, LASSO_DS_ERROR_TOO_MUCH_REFERENCES);
	/* The reference should be to the signed node */
	reference_uri = g_strdup_printf("#%s", id);
	dsig_reference_ctx = (xmlSecDSigReferenceCtx*)xmlSecPtrListGetItem(&(dsigCtx->signedInfoReferences), 0);
	goto_exit_if_fail(dsig_reference_ctx != 0 &&
			strcmp((char*)dsig_reference_ctx->uri, reference_uri) == 0,
			LASSO_DS_ERROR_INVALID_REFERENCE_FOR_SAML);
	/* Keep URI of all nodes signed if asked */
	if (uri_references) {
		gint size = xmlSecPtrListGetSize(&(dsigCtx->signedInfoReferences));
		int i;
		for (i = 0; i < size; ++i) {

			dsig_reference_ctx = (xmlSecDSigReferenceCtx*)xmlSecPtrListGetItem(&(dsigCtx->signedInfoReferences), i);
			if (dsig_reference_ctx->uri == NULL) {
				g_warning("dsig_reference_ctx->uri cannot be null");
				continue;
			}
			lasso_list_add_xml_string(*uri_references, dsig_reference_ctx->uri);
		}
	}

	if (dsigCtx->status == xmlSecDSigStatusSucceeded) {
		rc = 0;
	}

exit:
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
				g_free(msg);
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
					g_free(msg);
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
	while (*c != 0 && (isalnum(*c) || *c == '+' || *c == '/' || *c == '\n' || *c == '\r')) c++;
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
	char *algorithm = NULL;
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
	algorithm = (char*)xmlGetProp(encryption_method_node, (xmlChar *)"Algorithm");
	if (algorithm == NULL) {
		message(G_LOG_LEVEL_WARNING, "No EncryptionMethod");
		goto cleanup;
	}
	if (strstr(algorithm , "#aes")) {
		key_type = xmlSecKeyDataAesId;
	} else if (strstr(algorithm , "des")) {
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
		encrypted_key_node = encrypted_data_node;
		while (encrypted_key_node &&
				strcmp((char*)encrypted_key_node->name, "EncryptedKey") != 0 ) {
			if (strcmp((char*)encrypted_key_node->name, "EncryptedData") == 0 ||
					strcmp((char*)encrypted_key_node->name, "KeyInfo") == 0) {
				encrypted_key_node = xmlCopyNode(encrypted_key_node->children, 1);
				break;
			}
			encrypted_key_node = encrypted_key_node->next;
		}
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
	if (doc == NULL) {
		if (encrypted_data_node) {
			xmlFreeNode(encrypted_data_node);
		}
		if (encrypted_key_node) {
			xmlFreeNode(encrypted_key_node);
		}
	}
	if (encCtx) {
		xmlSecEncCtxDestroy(encCtx);
	}
	lasso_release_doc(doc);
	lasso_release_gobject(decrypted_node);

	return rc;
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
lasso_xml_parse_memory(const char *buffer, int size)
{
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

	xmlParseDocument(ctxt);

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

char *
lasso_get_relaystate_from_query(const char *query) {
	char *start, *end;
	char *result = NULL;

	if (query == NULL)
		return NULL;
	start = strstr(query, "?RelayState=");
	if (! start) {
		start = strstr(query, "&RelayState=");
	}
	if (start) {
		ptrdiff_t length;

		start += sizeof("&RelayState=") - 1;
		end = strchr(start, '&');
		if (end) {
			length = end-start;
		} else {
			length = strlen(start);
		}
		if (length > 240) {
			g_warning("Refused to parse a RelayState of size %ti > 240", length);
		} else {
			result = xmlURIUnescapeString(start, length, NULL);
		}
	}
	return result;
}
