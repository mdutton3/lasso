/* $Id$ 
 *
 * Lasso - A free implementation of the Liberty Alliance specifications.
 *
 * Copyright (C) 2004 Entr'ouvert
 * http://lasso.entrouvert.org
 * 
 * Author: Valery Febvre <vfebvre@easter-eggs.com>
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

#include <lasso/xml/tools.h>

xmlChar *
lasso_build_unique_id(guint8 size)
{
  /*
    The probability of 2 randomly chosen identifiers being identical MUST be
    less than 2^-128 and SHOULD be less than 2^-160.
    so we must have 128 <= exp <= 160
    we could build a 128-bit binary number but hexa system is shorter
    32 <= hexa number size <= 48
  */
  int i, val;
  xmlChar *id, *enc_id;

  if (size == 0) size = 32;
  id = g_malloc(size+1);

  /* build hex number (<= 2^exp-1) */
  for (i=0; i<size; i++) {
    val = g_random_int_range(0, 16);
    if (val < 10)
      id[i] = 48 + val;
    else
      id[i] = 65 + val-10;
  }
  id[size] = '\0';

  /* base64 encoding of build string */
  enc_id = xmlSecBase64Encode((const xmlChar *)id, size, 0);

  g_free(id);
  return (enc_id);
}

xmlChar *
lasso_doc_get_node_content(xmlDocPtr doc, const xmlChar *name)
{
  xmlNodePtr node;

  /* FIXME : bad namespace used */
  node = xmlSecFindNode(xmlDocGetRootElement(doc), name, xmlSecDSigNs);
  if (node != NULL)
    /* val returned must be xmlFree() */
    return (xmlNodeGetContent(node));
  else
    return (NULL);
}

xmlChar*
lasso_g_ptr_array_index(GPtrArray *a, guint i)
{
  if (a != NULL) {
    return (g_ptr_array_index(a, i));
  }
  else {
    return (NULL);
  }
}

xmlChar *
lasso_get_current_time()
{
  struct tm *tm;
  GTimeVal time_val;
  xmlChar *ret = g_malloc(21);

  g_get_current_time(&time_val);
  tm = localtime(&(time_val.tv_sec));
  strftime(ret, 21, "%FT%TZ", tm);

  return (ret);
}

static void gdata_query_to_dict_destroy_notify(gpointer data) {
  gint i;
  GPtrArray *array = data;

  for (i=0; i<array->len; i++) {
    g_free(array->pdata[i]);
  }
  g_ptr_array_free(array, TRUE);
}

/**
 * lasso_query_to_dict:
 * @query: the query part of the 'url-encoded + signed' message
 * 
 * Split query (& char) and build a dictonary with key=value
 * value is a GPtrArray.
 * The caller is responsible for freeing returned object by calling
 * g_datalist_clear() function.
 *
 * Return value: a dictonary
 **/
GData *
lasso_query_to_dict(const xmlChar *query)
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
    str_unescaped = lasso_str_unescape(sa1[i-1]);
    sa2 = g_strsplit(str_unescaped, "=", 0);
    xmlFree(str_unescaped);
    //printf("%s => ", sa2[0]);
    /* split of value to get mutli values sub-strings separated by SPACE char */
    str_unescaped = lasso_str_unescape(sa2[1]);
    sa3 = g_strsplit(str_unescaped, " ", 0);
    xmlFree(str_unescaped);
    gpa = g_ptr_array_new();
    j = 0;
    while (sa3[j++] != NULL) {
      g_ptr_array_add(gpa, g_strdup(sa3[j-1]));
      //printf("%s, ", sa3[j-1]);
    }
    //printf("\n");
    /* add key => values in dict */
    g_datalist_set_data_full(&gd, sa2[0], gpa,
			     gdata_query_to_dict_destroy_notify);
    g_strfreev(sa3);
    g_strfreev(sa2);
  }
  
  g_strfreev(sa1);
  return (gd);
}

xmlChar *
lasso_str_escape(xmlChar *str)
{
  /* value returned must be xmlFree() */
  return (xmlURIEscapeStr((const xmlChar *)str, NULL));
}

xmlDocPtr
lasso_str_sign(xmlChar *str,
	       xmlSecTransformId signMethodId,
	       const char* key_file)
{
  xmlDocPtr  doc = xmlNewDoc("1.0");
  xmlNodePtr envelope = xmlNewNode(NULL, "Envelope");
  xmlNodePtr cdata, data = xmlNewNode(NULL, "Data");
  xmlNodePtr signNode;
  xmlNodePtr refNode;
  xmlNodePtr keyInfoNode;
  xmlSecDSigCtxPtr dsigCtx;

  /* create doc */
  xmlNewNs(envelope, "urn:envelope", NULL);
  cdata = xmlNewCDataBlock(doc, str, strlen(str));
  xmlAddChild(envelope, data);
  xmlAddChild(data, cdata);
  xmlAddChild((xmlNodePtr)doc, envelope);

  /* create signature template for enveloped signature */
  signNode = xmlSecTmplSignatureCreate(doc, xmlSecTransformExclC14NId,
				       signMethodId, NULL);
  if (signNode == NULL) {
    fprintf(stderr, "Error: failed to create signature template\n");
    goto done;		
  }
  
  /* add <dsig:Signature/> node to the doc */
  xmlAddChild(xmlDocGetRootElement(doc), signNode);
  
  /* add reference */
  refNode = xmlSecTmplSignatureAddReference(signNode, xmlSecTransformSha1Id,
					    NULL, NULL, NULL);
  if (refNode == NULL) {
    fprintf(stderr, "Error: failed to add reference to signature template\n");
    goto done;		
  }
  
  /* add enveloped transform */
  if (xmlSecTmplReferenceAddTransform(refNode, xmlSecTransformEnvelopedId) == NULL) {
    fprintf(stderr, "Error: failed to add enveloped transform to reference\n");
    goto done;		
  }
  
  /* add <dsig:KeyInfo/> and <dsig:KeyName/> nodes to put key name in the
     signed document */
  keyInfoNode = xmlSecTmplSignatureEnsureKeyInfo(signNode, NULL);
  if (keyInfoNode == NULL) {
    fprintf(stderr, "Error: failed to add key info\n");
    goto done;		
  }
  
  if (xmlSecTmplKeyInfoAddKeyName(keyInfoNode, NULL) == NULL) {
    fprintf(stderr, "Error: failed to add key name\n");
    goto done;		
  }
  
  /* create signature context */
  dsigCtx = xmlSecDSigCtxCreate(NULL);
  if (dsigCtx == NULL) {
    fprintf(stderr,"Error: failed to create signature context\n");
    goto done;
  }

  /* load private key */
  dsigCtx->signKey = xmlSecCryptoAppKeyLoad(key_file, xmlSecKeyDataFormatPem,
					    NULL, NULL, NULL);
  if (dsigCtx->signKey == NULL) {
    fprintf(stderr,"Error: failed to load private pem key from \"%s\"\n", key_file);
    goto done;
  }

  /* sign the template */
  if (xmlSecDSigCtxSign(dsigCtx, signNode) < 0) {
    fprintf(stderr,"Error: signature failed\n");
    goto done;
  }
  
  //xmlDocDump(stdout, doc);
  xmlSecDSigCtxDestroy(dsigCtx);
  /* doc must be freed be caller */
  return (doc);

 done:    
  /* cleanup */
  if (dsigCtx != NULL) {
    xmlSecDSigCtxDestroy(dsigCtx);
  }
  
  if (doc != NULL) {
    xmlFreeDoc(doc); 
  }
  return (NULL);
}

xmlChar *
lasso_str_unescape(xmlChar *str)
{
  xmlChar *ret;

  ret = g_malloc(strlen(str) * 2);
  xmlURIUnescapeString((const char *)str, 0, ret);
  return (ret);
}

int
lasso_str_verify(xmlChar *str,
		 const xmlChar *sender_public_key_file,
		 const xmlChar *recipient_private_key_file)
{
  xmlDocPtr doc;
  xmlNodePtr sigNode, sigValNode;
  xmlSecDSigCtxPtr dsigCtx;
  gchar **str_split;
  gint ret = -1;

  /* split query, signatureValue */
  str_split = g_strsplit((const gchar *)str, "&Signature=", 0);
  /* re-create doc to verify (signed + enrypted) */
  doc = lasso_str_sign(str_split[0],
		       xmlSecTransformRsaSha1Id,
		       recipient_private_key_file);
  sigValNode = xmlSecFindNode(xmlDocGetRootElement(doc),
			      xmlSecNodeSignatureValue,
			      xmlSecDSigNs);
  /* set SignatureValue content */
  xmlNodeSetContent(sigValNode, lasso_str_unescape(str_split[1]));

  g_strfreev(str_split);
  //xmlDocDump(stdout, doc);

  /* find start node */
  sigNode = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeSignature, xmlSecDSigNs);
  
  /* create signature context */
  dsigCtx = xmlSecDSigCtxCreate(NULL);
  if(dsigCtx == NULL) {
    fprintf(stderr,"Error: failed to create signature context\n");
    goto done;
  }
  
  /* load public key */
  dsigCtx->signKey = xmlSecCryptoAppKeyLoad(sender_public_key_file, xmlSecKeyDataFormatPem, NULL, NULL, NULL);
  if(dsigCtx->signKey == NULL) {
    fprintf(stderr,"Error: failed to load public pem key from \"%s\"\n", sender_public_key_file);
    goto done;
  }
  
  /* Verify signature */
  if(xmlSecDSigCtxVerify(dsigCtx, sigNode) < 0) {
    fprintf(stderr,"Error: signature verify\n");
    goto done;
  }
  
  /* print verification result to stdout and return */
  if(dsigCtx->status == xmlSecDSigStatusSucceeded) {
    fprintf(stdout, "Signature is OK\n");
    ret = 1;
  }
  else {
    fprintf(stdout, "Signature is INVALID\n");
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
  return (ret);
}
