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

#include <string.h>

#include <libxml/uri.h>

#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/engine.h>

#include <xmlsec/xmltree.h>
#include <xmlsec/base64.h>

#include <lasso/xml/tools.h>
#include <lasso/xml/errors.h>
#include <lasso/xml/strings.h>

/**
 * lasso_build_random_sequence:
 * @size: the sequence size in byte (character)
 * 
 * Builds a random sequence of [0-9A-F] characters of size @size.
 * 
 * Return value: a newly allocated string or NULL if an error occurs.
 **/
xmlChar *
lasso_build_random_sequence(guint8 size)
{
  int i, val;
  xmlChar *seq;

  g_return_val_if_fail(size > 0, NULL);

  seq = xmlMalloc(size+1);

  for (i=0; i<size; i++) {
    val = g_random_int_range(0, 16);
    if (val < 10)
      seq[i] = 48 + val;
    else
      seq[i] = 65 + val-10;
  }
  seq[size] = '\0';

  return seq;
}

/**
 * lasso_build_unique_id:
 * @size: the ID's length (between 32 and 40)
 * 
 * Builds an ID which has an unicity probability of 2^(-size*4).
 * 
 * Return value: a "unique" ID (begin always with _ character)
 **/
xmlChar *
lasso_build_unique_id(guint8 size)
{
  /*
    The probability of 2 randomly chosen identifiers being identical MUST be
    less than 2^-128 and SHOULD be less than 2^-160.
    so we must have 128 <= exp <= 160
    we could build a 128-bit binary number but hexa system is shorter
    32 <= hexa number size <= 40
  */
  int i, val;
  xmlChar *id;

  g_return_val_if_fail((size >= 32 && size <= 40) || size == 0, NULL);

  if (size == 0) size = 32;
  id = xmlMalloc(size+1+1); /* one for _ and one for \0 */

  /* build hex number (<= 2^exp-1) */
  id[0] = '_';
  for (i=1; i<size+1; i++) {
    val = g_random_int_range(0, 16);
    if (val < 10)
      id[i] = 48 + val;
    else
      id[i] = 65 + val-10;
  }
  id[size+1] = '\0';

  return id;
}

/**
 * lasso_g_ptr_array_index:
 * @a: a GPtrArray
 * @i: the index
 * 
 * Gets the pointer at the given index @i of the pointer array.
 * 
 * Return value: the pointer at the given index.
 **/
xmlChar*
lasso_g_ptr_array_index(GPtrArray *a, guint i)
{
  if (a != NULL) {
    return g_ptr_array_index(a, i);
  }
  else {
    return NULL;
  }
}

/**
 * lasso_get_current_time:
 * 
 * Returns the current time, format is "yyyy-mm-ddThh:mm:ssZ".
 * 
 * Return value: a string
 **/
gchar *
lasso_get_current_time()
{
  struct tm *tm;
  GTimeVal time_val;
  gchar *ret = g_new0(gchar, 21);

  g_get_current_time(&time_val);
  tm = localtime(&(time_val.tv_sec));
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
lassoPemFileType
lasso_get_pem_file_type(const gchar *pem_file)
{
  BIO* bio;
  EVP_PKEY *pkey;
  X509 *cert;
  guint type = LASSO_PEM_FILE_TYPE_UNKNOWN;

  g_return_val_if_fail(pem_file != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

  bio = BIO_new_file(pem_file, "rb");
  if (bio == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Failed to open %s pem file",
	    pem_file);
    return -1;
  }

  pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
  if (pkey != NULL) {
    type = LASSO_PEM_FILE_TYPE_PUB_KEY;
    EVP_PKEY_free(pkey);
  }
  else {
    BIO_reset(bio);
    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (pkey != NULL) {
      type = LASSO_PEM_FILE_TYPE_PRIVATE_KEY;
      EVP_PKEY_free(pkey);
    }
    else {
      BIO_reset(bio);
      cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
      if (cert != NULL) {
	type = LASSO_PEM_FILE_TYPE_CERT;
	X509_free(cert);
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
lasso_get_public_key_from_pem_cert_file(const gchar *pem_cert_file)
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
  }
  else {
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
lasso_load_certs_from_pem_certs_chain_file(const gchar* pem_certs_chain_file)
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
    }
    else if (g_strstr_len(line, 64, "END CERTIFICATE") != NULL) {
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
	goto error;
      }
    }
    else if (cert != NULL && line != NULL && line[0] != '\0') {
      g_string_append(cert, line);
    }
    else {
      debug("Empty line found in the CA certificate chain file")
    }
    /* free last line read */
    if (line != NULL) {
      g_free(line);
      line = NULL;
    }
  }
  goto done;

 error:
  if (line != NULL) {
    g_free(line);
    line = NULL;
  }
  xmlSecKeysMngrDestroy(keys_mngr);
  keys_mngr = NULL;

 done:
  g_io_channel_shutdown(gioc, TRUE, NULL);

  return keys_mngr;
}

/**
 * lasso_query_sign:
 * @query: a query (an url-encoded node)
 * @sign_method: the Signature transform method
 * @private_key_file: the private key
 * 
 * Signs a query (url-encoded message).
 * 
 * Return value: a newly allocated query signed or NULL if an error occurs.
 **/
xmlChar*
lasso_query_sign(xmlChar              *query,
		 lassoSignatureMethod  sign_method,
		 const char           *private_key_file)
{
  BIO *bio = NULL;
  xmlChar *digest = NULL; /* 160 bit buffer */
  RSA *rsa = NULL;
  DSA *dsa = NULL;
  unsigned char *sigret = NULL;
  unsigned int siglen;
  xmlChar *b64_sigret = NULL, *e_b64_sigret = NULL;
  xmlChar *new_query = NULL, *s_new_query = NULL;
  int status = 0;
  char *t;

  g_return_val_if_fail(query != NULL, NULL);
  g_return_val_if_fail(sign_method == LASSO_SIGNATURE_METHOD_RSA_SHA1 || \
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
    t = xmlURIEscapeStr(xmlSecHrefRsaSha1, NULL);
    new_query = g_strdup_printf("%s&SigAlg=%s", query, t);
    xmlFree(t);
    break;
  case LASSO_SIGNATURE_METHOD_DSA_SHA1:
    t = xmlURIEscapeStr(xmlSecHrefDsaSha1, NULL);
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
    status = RSA_sign(NID_sha1, digest, 20, sigret, &siglen, rsa);
    RSA_free(rsa);
  }
  else if (sign_method == LASSO_SIGNATURE_METHOD_DSA_SHA1) {
    dsa = PEM_read_bio_DSAPrivateKey(bio, NULL, NULL, NULL);
    if (dsa == NULL) {
      goto done;
    }
    sigret = (unsigned char *)g_malloc (DSA_size(dsa));
    status = DSA_sign(NID_sha1, digest, 20, sigret, &siglen, dsa);
    DSA_free(dsa);
  }
  if (status == 0) {
    goto done;
  }

  /* Base64 encode the signature value */
  b64_sigret = xmlSecBase64Encode(sigret, siglen, 0);
  /* escape b64_sigret */
  e_b64_sigret = xmlURIEscapeStr(b64_sigret, NULL);

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
  free(sigret);
  xmlFree(b64_sigret);
  free(e_b64_sigret);

  return s_new_query;
}

/**
 * lasso_query_verify_signature:
 * @query: a query (an url-encoded message)
 * @sender_public_key_file: the query sender public key
 * 
 * Verifies the query signature.
 * 
 * Return value: 0 if signature is valid
 * a positive value if signature was not found or is invalid
 * a negative value if an error occurs during verification
 **/
int
lasso_query_verify_signature(const gchar   *query,
			     const xmlChar *sender_public_key_file)
{
  BIO *bio = NULL;
  RSA *rsa = NULL;
  DSA *dsa = NULL;
  gchar **str_split = NULL;
  lassoSignatureMethod  sign_method;
  xmlChar *digest = NULL, *b64_signature = NULL;
  xmlChar *e_rsa_alg = NULL, *e_dsa_alg = NULL;
  xmlSecByte *signature;
  int key_size, status = 0, ret = 0;

  g_return_val_if_fail(query != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);
  g_return_val_if_fail(sender_public_key_file != NULL, LASSO_PARAM_ERROR_INVALID_VALUE);

  /* split query, the signature MUST be the last param of the query */
  str_split = g_strsplit(query, "&Signature=", 0);
  if (str_split[1] == NULL) {
    ret = LASSO_DS_ERROR_SIGNATURE_NOT_FOUND;
    goto done;
  }

  /* create bio to read public key */
  bio = BIO_new_file(sender_public_key_file, "rb");
  if (bio == NULL) {
    message(G_LOG_LEVEL_CRITICAL, lasso_strerror(LASSO_DS_ERROR_PUBLIC_KEY_LOAD_FAILED),
	    sender_public_key_file);
    ret = LASSO_DS_ERROR_PUBLIC_KEY_LOAD_FAILED;
    goto done;
  }  

  /* get signature method (algorithm) and read public key */
  e_rsa_alg = xmlURIEscapeStr(xmlSecHrefRsaSha1, NULL);
  e_dsa_alg = xmlURIEscapeStr(xmlSecHrefDsaSha1, NULL);
  if (g_strrstr(str_split[0], e_rsa_alg) != NULL) {
    sign_method = LASSO_SIGNATURE_METHOD_RSA_SHA1;
    rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    /* rsa = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL); */
    if (rsa == NULL) {
      ret = LASSO_DS_ERROR_PUBLIC_KEY_LOAD_FAILED;
      goto done;
    }
    key_size = RSA_size(rsa);
  }
  else if (g_strrstr(str_split[0], e_dsa_alg) != NULL) {
    sign_method = LASSO_SIGNATURE_METHOD_DSA_SHA1;
    dsa = PEM_read_bio_DSA_PUBKEY(bio, NULL, NULL, NULL);
    if (dsa == NULL) {
      ret = LASSO_DS_ERROR_PUBLIC_KEY_LOAD_FAILED;
      goto done;
    }
    key_size = DSA_size(dsa);
  }
  else {
    message(G_LOG_LEVEL_CRITICAL, lasso_strerror(LASSO_DS_ERROR_INVALID_SIGALG));
    ret = LASSO_DS_ERROR_INVALID_SIGALG;
    goto done;
  }

  /* get signature (unescape + base64 decode) */
  signature = (xmlSecByte *)xmlMalloc(key_size+1);
  b64_signature = xmlURIUnescapeString(str_split[1], 0, NULL);
  xmlSecBase64Decode(b64_signature, signature, key_size+1);

  /* calculate signature digest */
  digest = lasso_sha1(str_split[0]);
  if (digest == NULL) {
    message(G_LOG_LEVEL_CRITICAL, lasso_strerror(LASSO_DS_ERROR_DIGEST_COMPUTE_FAILED));
    ret = LASSO_DS_ERROR_DIGEST_COMPUTE_FAILED;
    goto done;
  }

  if (sign_method == LASSO_SIGNATURE_METHOD_RSA_SHA1) {
    status = RSA_verify(NID_sha1, digest, 20, signature, RSA_size(rsa), rsa);
    /* printf("OpenSSL %s\n", ERR_error_string(ERR_get_error(), NULL)); */
    /* printf("OpenSSL %s\n", ERR_error_string(ERR_peek_last_error(), NULL)); */
  }
  else if (sign_method == LASSO_SIGNATURE_METHOD_DSA_SHA1) {
    status = DSA_verify(NID_sha1, digest, 20, signature, DSA_size(dsa), dsa);
  }
  if (status == 0) {
    ret = LASSO_DS_ERROR_INVALID_SIGNATURE;
  }

 done:
  xmlFree(b64_signature);
  xmlFree(signature);
  xmlFree(digest);
  xmlFree(e_rsa_alg);
  xmlFree(e_dsa_alg);
  g_strfreev(str_split);
  BIO_free(bio);
  RSA_free(rsa);
  DSA_free(dsa);

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
xmlChar*
lasso_sha1(xmlChar *str)
{
  xmlChar *md;

  if (str != NULL) {
    md = xmlMalloc(20);
    return SHA1(str, strlen(str), md);
  }
  
  return NULL;
}

char** urlencoded_to_strings(const char *str)
{
	int i, n=1;
	char *st, *st2;
	char **result;

	st = (char*)str;
	while (strchr(st, '&')) {
		st = strchr(st, '&')+1;
		n++;
	}

	result = malloc(sizeof(char*)*n+2);
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


