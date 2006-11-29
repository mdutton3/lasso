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

#include <string.h>
#include <time.h>

#include <libxml/uri.h>

#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/engine.h>

#include <xmlsec/base64.h>
#include <xmlsec/crypto.h>
#include <xmlsec/templates.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/xmltree.h>

#include <zlib.h>

#include <lasso/xml/xml.h>
#include <lasso/xml/saml-2.0/saml2_assertion.h>

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

	g_return_val_if_fail(pem_certs_chain_file != NULL, NULL);

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

	gioc = g_io_channel_new_file(pem_certs_chain_file, "r", NULL);
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

	bio = BIO_new_file(private_key_file, "rb");
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
	}
	else if (sign_method == LASSO_SIGNATURE_METHOD_DSA_SHA1) {
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

LassoNode *
lasso_assertion_encrypt(LassoSaml2Assertion *assertion)
{
	LassoNode *encrypted_element = NULL;
	xmlChar *b64_value;
	xmlSecByte *value;
	int length;
	int rc;
	xmlSecKeyInfoCtxPtr ctx;
	xmlSecKey *encryption_public_key = NULL;
	int i;

	if (! assertion->encryption_activated ||
			assertion->encryption_public_key_str == NULL) {
		return NULL;
	}

	/* Load the encryption key*/
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

	b64_value = (xmlChar*)g_strdup(assertion->encryption_public_key_str);
	length = strlen((char*)b64_value);
	value = g_malloc(length);
	xmlSecErrorsDefaultCallbackEnableOutput(FALSE);
	rc = xmlSecBase64Decode(b64_value, value, length);
	if (rc < 0) {
		/* bad base-64 */
		g_free(value);
		value = (xmlSecByte*)g_strdup((char*)b64_value);
		rc = strlen((char*)value);
	}

	for (i = 0; key_formats[i] && encryption_public_key == NULL; i++) {
		encryption_public_key = xmlSecCryptoAppKeyLoadMemory(value, rc,
				key_formats[i], NULL, NULL, NULL);
	}

	/* Finally encrypt the assertion */
	encrypted_element = LASSO_NODE(lasso_node_encrypt(assertion, encryption_public_key));

	xmlSecErrorsDefaultCallbackEnableOutput(TRUE);
	xmlFree(b64_value);
	g_free(value);	
/* 	g_free(assertion->encryption_public_key_str); */

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

	if (status == 0) {
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
error_code(GLogLevelFlags level, int error, ...)
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
		const char *private_key_file, const char *certificate_file)
{
	xmlDoc *doc;
	xmlNode *sign_tmpl, *old_parent;
	xmlSecDSigCtx *dsig_ctx;

	sign_tmpl = NULL;
	for (sign_tmpl = xmlnode->children; sign_tmpl; sign_tmpl = sign_tmpl->next) {
		if (strcmp((char*)sign_tmpl->name, "Signature") == 0)
			break;
	}
	sign_tmpl = xmlSecFindNode(xmlnode, xmlSecNodeSignature, xmlSecDSigNs);

	if (sign_tmpl == NULL)
		return LASSO_DS_ERROR_SIGNATURE_TEMPLATE_NOT_FOUND;

	doc = xmlNewDoc((xmlChar*)"1.0");
	old_parent = xmlnode->parent;
	xmlnode->parent = NULL;
	xmlDocSetRootElement(doc, xmlnode);
	xmlSetTreeDoc(sign_tmpl, doc);
	if (id_attr_name) {
		xmlAttr *id_attr = xmlHasProp(xmlnode, (xmlChar*)id_attr_name);
		if (id_value) {
			xmlAddID(NULL, doc, (xmlChar*)id_value, id_attr);
		}
	}

	dsig_ctx = xmlSecDSigCtxCreate(NULL);
	dsig_ctx->signKey = xmlSecCryptoAppKeyLoad(private_key_file,
			xmlSecKeyDataFormatPem,
			NULL, NULL, NULL);
	if (dsig_ctx->signKey == NULL) {
		xmlSecDSigCtxDestroy(dsig_ctx);
		return critical_error(LASSO_DS_ERROR_PRIVATE_KEY_LOAD_FAILED);
	}
	if (certificate_file != NULL && certificate_file[0] != 0) {
		if (xmlSecCryptoAppKeyCertLoad(dsig_ctx->signKey, certificate_file,
					xmlSecKeyDataFormatPem) < 0) {
			xmlSecDSigCtxDestroy(dsig_ctx);
			return critical_error(LASSO_DS_ERROR_CERTIFICATE_LOAD_FAILED);
		}
	}
	if (xmlSecDSigCtxSign(dsig_ctx, sign_tmpl) < 0) {
		xmlSecDSigCtxDestroy(dsig_ctx);
		return critical_error(LASSO_DS_ERROR_SIGNATURE_FAILED);
	}
	xmlSecDSigCtxDestroy(dsig_ctx);
	xmlUnlinkNode(xmlnode);
	xmlnode->parent = old_parent;
	xmlFreeDoc(doc);

	return 0;
}

gchar*
lasso_node_build_deflated_query(LassoNode *node)
{
	/* actually deflated and b64'ed and url-escaped */
	xmlNode *message;
	xmlOutputBufferPtr buf;
	xmlCharEncodingHandlerPtr handler = NULL;
	xmlChar *buffer;
	xmlChar *ret, *b64_ret;
	char *rret;
	unsigned long in_len;
	int rc;
	z_stream stream;

	message = lasso_node_get_xmlNode(node, FALSE);
	
	handler = xmlFindCharEncodingHandler("utf-8");
	buf = xmlAllocOutputBuffer(handler);
	xmlNodeDumpOutput(buf, NULL, message, 0, 0, "utf-8");
	xmlOutputBufferFlush(buf);
	buffer = buf->conv ? buf->conv->content : buf->buffer->content;

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

	doc = xmlParseMemory((char*)re, strlen((char*)re));
	xmlFree(re);
	root = xmlDocGetRootElement(doc);
	lasso_node_init_from_xml(node, root);
	xmlFreeDoc(doc);

	return TRUE;
}

char*
lasso_concat_url_query(char *url, char *query)
{
	if (strchr(url, '?')) {
		return g_strdup_printf("%s&%s", url, query);
	} else {
		return g_strdup_printf("%s?%s", url, query);
	}
}

