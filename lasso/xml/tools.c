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

#include <openssl/sha.h>

#include <xmlsec/xmltree.h>
#include <xmlsec/base64.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/templates.h>

#include <lasso/xml/tools.h>

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
 * lasso_doc_get_node_content:
 * @doc: a doc
 * @name: the name
 * 
 * Gets the value of the first node having given @name.
 * 
 * Return value: a node value or NULL if no node found or if no content is
 * available
 **/
xmlChar *
lasso_doc_get_node_content(xmlDocPtr doc, const xmlChar *name)
{
  xmlNodePtr node;

  /* FIXME: bad namespace used */
  node = xmlSecFindNode(xmlDocGetRootElement(doc), name, xmlSecDSigNs);
  if (node != NULL)
    /* val returned must be xmlFree() */
    return xmlNodeGetContent(node);
  else
    return NULL;
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
  strftime((char *)ret, 21, "%Y-%m-%dT%H:%M:%SZ", tm);

  return ret;
}

/**
 * lasso_get_pubkey_from_pem_certificate:
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

  /* load pem certificate from file */
  fd = fopen(pem_cert_file, "r");
  if (fd == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Failed to open %s pem certificate file\n",
	    pem_cert_file);
    return NULL;
  }
  /* read the pem X509 certificate */
  pem_cert = PEM_read_X509(fd, NULL, NULL, NULL);
  fclose(fd);
  if (pem_cert == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Failed to read X509 certificate\n");
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
	    "Failed to get the public key in the X509 certificate\n");
  }
  X509_free(pem_cert);

  return key;
}

/**
 * lasso_get_pem_file_type:
 * @pem_file: a pem file
 * 
 * Gets the type of the pem file.
 * 
 * Return value: the pem file type
 **/
lassoPemFileType
lasso_get_pem_file_type(const gchar *pem_file)
{
  BIO* bio;
  EVP_PKEY *pkey;
  X509 *cert;
  guint type = lassoPemFileTypeUnknown;

  bio = BIO_new_file(pem_file, "rb");
  if (bio == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Failed to open %s pem file\n",
	    pem_file);
    return -1;
  }

  pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
  if (pkey != NULL) {
    type = lassoPemFileTypePubKey;
    EVP_PKEY_free(pkey);
  }
  else {
    BIO_reset(bio);
    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (pkey != NULL) {
      type = lassoPemFileTypePrivateKey;
      EVP_PKEY_free(pkey);
    }
    else {
      BIO_reset(bio);
      cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
      if (cert != NULL) {
	type = lassoPemFileTypeCert;
	X509_free(cert);
      }
    }
  }
  BIO_free(bio);

  return type;
}

/**
 * lasso_query_get_value:
 * @query: a query (an url-encoded node)
 * @param: the parameter
 * 
 * Returns the value of the given @param
 * 
 * Return value: a string or NULL if no parameter found
 **/
GPtrArray *
lasso_query_get_value(const gchar   *query,
		      const xmlChar *param)
{
  guint i;
  GData *gd;
  GPtrArray *tmp_array, *array = NULL;

  gd = lasso_query_to_dict(query);
  tmp_array = (GPtrArray *)g_datalist_get_data(&gd, (gchar *)param);
  /* create a copy of tmp_array */
  if (tmp_array != NULL) {
    array = g_ptr_array_new();
    for(i=0; i<tmp_array->len; i++)
      g_ptr_array_add(array, g_strdup(g_ptr_array_index(tmp_array, i)));
  }
  g_datalist_clear(&gd);
  return array;
}

static void
gdata_query_to_dict_destroy_notify(gpointer data)
{
  guint i;
  GPtrArray *array = data;

  for (i=0; i<array->len; i++) {
    g_free(array->pdata[i]);
  }
  g_ptr_array_free(array, TRUE);
}

/**
 * lasso_query_to_dict:
 * @query: the query (an url-encoded node)
 * 
 * Explodes query to build a dictonary.
 * Dictionary values are stored in GPtrArray.
 * The caller is responsible for freeing returned object by calling
 * g_datalist_clear() function.
 *
 * Return value: a dictonary
 **/
GData *
lasso_query_to_dict(const gchar *query)
{
  GData *gd = NULL;
  gchar **sa1, **sa2, **sa3;
  xmlChar *str_unescaped;
  GPtrArray *gpa;
  guint i, j;
  
  g_datalist_init(&gd);
  
  i = 0;
  sa1 = g_strsplit(query, "&", 0);

  while (sa1[i++] != NULL) {
    /* split of key=value to get (key, value) sub-strings */
    sa2 = g_strsplit(sa1[i-1], "=", 0);
    /* if no key / value found, then continue */
    if (sa2 == NULL) {
      continue;
    }
    /* if only a key but no value, then continue */
    if (sa2[1] == NULL) {
      continue;
    }

    /* split of value to get mutli values sub-strings separated by SPACE char */
    str_unescaped = lasso_str_unescape(sa2[1]);
    sa3 = g_strsplit(str_unescaped, " ", 0);
    if (sa3 == NULL) {
      g_strfreev(sa2);
      continue;
    }

    xmlFree(str_unescaped);
    gpa = g_ptr_array_new();
    j = 0;
    while (sa3[j++] != NULL) {
      g_ptr_array_add(gpa, g_strdup(sa3[j-1]));
    }
    /* add key => values in dict */
    g_datalist_set_data_full(&gd, sa2[0], gpa,
			     gdata_query_to_dict_destroy_notify);
    g_strfreev(sa3);
    g_strfreev(sa2);
  }  
  g_strfreev(sa1);

  return gd;
}

/**
 * lasso_query_verify_signature:
 * @query: a query  (an url-encoded and signed node)
 * @sender_public_key_file: the sender public key
 * @recipient_private_key_file: the recipient private key
 * 
 * Verifys the query's signature.
 * 
 * Return value: 1 if signature is valid, 0 if invalid, 2 if no signature found
 * and -1 if an error occurs.
 **/
int
lasso_query_verify_signature(const gchar   *query,
			     const xmlChar *sender_public_key_file,
			     const xmlChar *recipient_private_key_file)
{
  xmlDocPtr doc;
  xmlNodePtr sigNode, sigValNode;
  xmlSecDSigCtxPtr dsigCtx;
  xmlChar *str_unescaped;
  gchar **str_split;
  /*
     0: signature invalid
     1: signature ok
     2: signature not found
    -1: error during verification
  */
  gint ret = -1;

  /* split query, signature (must be last param) */
  str_split = g_strsplit(query, "&Signature=", 0);
  if (str_split[1] == NULL)
    return 2;
  /* re-create doc to verify (signed + enrypted) */
  doc = lasso_str_sign(str_split[0],
		       lassoSignatureMethodRsaSha1,
		       recipient_private_key_file);
  sigValNode = xmlSecFindNode(xmlDocGetRootElement(doc),
			      xmlSecNodeSignatureValue,
			      xmlSecDSigNs);
  /* set SignatureValue content */
  str_unescaped = lasso_str_unescape(str_split[1]);
  xmlNodeSetContent(sigValNode, str_unescaped);
  g_free(str_unescaped);

  g_strfreev(str_split);
  /*xmlDocDump(stdout, doc);*/

  /* find start node */
  sigNode = xmlSecFindNode(xmlDocGetRootElement(doc),
			   xmlSecNodeSignature, xmlSecDSigNs);
  
  /* create signature context */
  dsigCtx = xmlSecDSigCtxCreate(NULL);
  if(dsigCtx == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Failed to create signature context\n");
    goto done;
  }
  
  /* load public key */
  dsigCtx->signKey = xmlSecCryptoAppKeyLoad(sender_public_key_file,
					    xmlSecKeyDataFormatPem,
					    NULL, NULL, NULL);
  if(dsigCtx->signKey == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Failed to load public pem key from \"%s\"\n",
	    sender_public_key_file);
    goto done;
  }
  
  /* verify signature */
  if(xmlSecDSigCtxVerify(dsigCtx, sigNode) < 0) {
    message(G_LOG_LEVEL_CRITICAL, "Failed to verify signature\n");
    ret = 0;
    goto done;
  }
  
  /* print verification result to stdout and return */
  if(dsigCtx->status == xmlSecDSigStatusSucceeded) {
    ret = 1;
  }
  else {
    ret = 0;
  }
  
 done:
  /* cleanup */
  if(dsigCtx != NULL) {
    xmlSecDSigCtxDestroy(dsigCtx);
  }
  
  if(doc != NULL) {
    xmlFreeDoc(doc);
  }
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

/**
 * lasso_str_escape:
 * @str: a string
 * 
 * Escapes the given string @str.
 * 
 * Return value: a new escaped string or NULL in case of error.
 **/
xmlChar *
lasso_str_escape(xmlChar *str)
{
  /* value returned must be xmlFree() */
  return xmlURIEscapeStr((const xmlChar *)str, NULL);
}

xmlChar *
lasso_str_hash(xmlChar    *str,
	       const char *private_key_file)
{
  xmlDocPtr doc;
  xmlChar *b64_digest, *digest = g_new0(xmlChar, 21);
  gint i;

  doc = lasso_str_sign(str,
		       lassoSignatureMethodRsaSha1,
		       private_key_file);
  b64_digest = xmlNodeGetContent(xmlSecFindNode(
			  	 	xmlDocGetRootElement(doc),
					xmlSecNodeDigestValue,
					xmlSecDSigNs));
  i = xmlSecBase64Decode(b64_digest, digest, 21);
  xmlFree(b64_digest);
  xmlFreeDoc(doc);
  /* value returned must be xmlFree() */
  return digest;
}

/**
 * lasso_str_sign:
 * @str: 
 * @sign_method: 
 * @private_key_file: 
 * 
 * 
 * 
 * Return value: 
 **/
xmlDocPtr
lasso_str_sign(xmlChar              *str,
	       lassoSignatureMethod  sign_method,
	       const char           *private_key_file)
{
  /* FIXME : renamed fct into lasso_query_add_signature
     SHOULD returned a query (xmlChar) instead of xmlDoc */
  xmlDocPtr  doc = xmlNewDoc("1.0");
  xmlNodePtr envelope = xmlNewNode(NULL, "Envelope");
  xmlNodePtr cdata, data = xmlNewNode(NULL, "Data");
  xmlNodePtr signNode = NULL;
  xmlNodePtr refNode = NULL;
  xmlNodePtr keyInfoNode = NULL;
  xmlSecDSigCtxPtr dsigCtx = NULL;

  /* create doc */
  xmlNewNs(envelope, "urn:envelope", NULL);
  cdata = xmlNewCDataBlock(doc, str, strlen(str));
  xmlAddChild(envelope, data);
  xmlAddChild(data, cdata);
  xmlAddChild((xmlNodePtr)doc, envelope);

  /* create signature template for enveloped signature */
  switch (sign_method) {
  case lassoSignatureMethodRsaSha1:
    signNode = xmlSecTmplSignatureCreate(doc, xmlSecTransformExclC14NId,
					 xmlSecTransformRsaSha1Id, NULL);
    break;
  case lassoSignatureMethodDsaSha1:
    signNode = xmlSecTmplSignatureCreate(doc, xmlSecTransformExclC14NId,
					 xmlSecTransformDsaSha1Id, NULL);
    break;
  }

  if (signNode == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Failed to create signature template\n");
    goto done;		
  }
  
  /* add <dsig:Signature/> node to the doc */
  xmlAddChild(xmlDocGetRootElement(doc), signNode);
  
  /* add reference */
  refNode = xmlSecTmplSignatureAddReference(signNode, xmlSecTransformSha1Id,
					    NULL, NULL, NULL);
  if (refNode == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Failed to add reference to signature template\n");
    goto done;		
  }
  
  /* add enveloped transform */
  if (xmlSecTmplReferenceAddTransform(refNode,
				      xmlSecTransformEnvelopedId) == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Failed to add enveloped transform to reference\n");
    goto done;		
  }
  
  /* add <dsig:KeyInfo/> and <dsig:KeyName/> nodes to put key name in the
     signed document */
  keyInfoNode = xmlSecTmplSignatureEnsureKeyInfo(signNode, NULL);
  if (keyInfoNode == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Failed to add key info\n");
    goto done;		
  }
  
  if (xmlSecTmplKeyInfoAddKeyName(keyInfoNode, NULL) == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Failed to add key name\n");
    goto done;		
  }
  
  /* create signature context */
  dsigCtx = xmlSecDSigCtxCreate(NULL);
  if (dsigCtx == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Failed to create signature context\n");
    goto done;
  }

  /* load private key */
  dsigCtx->signKey = xmlSecCryptoAppKeyLoad(private_key_file,
					    xmlSecKeyDataFormatPem,
					    NULL, NULL, NULL);
  if (dsigCtx->signKey == NULL) {
    message(G_LOG_LEVEL_CRITICAL, "Failed to load private pem key from \"%s\"\n",
	    private_key_file);
    goto done;
  }

  /* sign the template */
  if (xmlSecDSigCtxSign(dsigCtx, signNode) < 0) {
    message(G_LOG_LEVEL_CRITICAL, "Signature failed\n");
    goto done;
  }
  
  /* xmlDocDump(stdout, doc); */
  xmlSecDSigCtxDestroy(dsigCtx);
  /* doc must be freed be caller */
  return doc;

 done:    
  /* cleanup */
  if (dsigCtx != NULL) {
    xmlSecDSigCtxDestroy(dsigCtx);
  }
  
  if (doc != NULL) {
    xmlFreeDoc(doc); 
  }
  return NULL;
}

/**
 * lasso_str_unescape:
 * @str: an escaped string
 * 
 * Unescapes the given string @str.
 * 
 * Return value: a new unescaped string or NULL in case of error.
 **/
xmlChar *
lasso_str_unescape(xmlChar *str)
{
  xmlChar *ret;

  ret = g_malloc(strlen(str) * 2); /* XXX why *2?  strlen(str) should be enough */
  xmlURIUnescapeString((const char *)str, 0, ret);
  return ret;
}
