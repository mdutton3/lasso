/* $Id$
 *
 * Lasso - A free implementation of the Samlerty Alliance specifications.
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

#include <lasso/xml/ds_signature.h>

/*
The schema fragment ():

*/

void lasso_ds_signature_sign(LassoDsSignature *node,
			     const xmlChar    *private_key_file,
			     const xmlChar    *certificate_file)
{
  xmlNodePtr signature = LASSO_NODE_GET_CLASS(node)->get_xmlNode(LASSO_NODE(node));
  xmlSecDSigCtxPtr dsig_ctx;

  /* create signature context */
  dsig_ctx = xmlSecDSigCtxCreate(NULL);
  if(dsig_ctx == NULL) {
    printf("Error: failed to create signature context\n");
  }
  
  /* load private key, assuming that there is not password */
  dsig_ctx->signKey = xmlSecCryptoAppKeyLoad(private_key_file,
					     xmlSecKeyDataFormatPem,
					     NULL, NULL, NULL);
  if(dsig_ctx->signKey == NULL) {
    printf("Error: failed to load private pem key from \"%s\"\n",
	   private_key_file);
  }
  
  /* load certificate and add to the key */
  if(xmlSecCryptoAppKeyCertLoad(dsig_ctx->signKey, certificate_file,
				xmlSecKeyDataFormatPem) < 0) {
    printf("Error: failed to load pem certificate \"%s\"\n", certificate_file);
  }

  /* sign the template */
  if(xmlSecDSigCtxSign(dsig_ctx, signature) < 0) {
    printf("Error: signature failed\n");
  }
}

/*****************************************************************************/
/* instance and class init functions                                         */
/*****************************************************************************/

static void
lasso_ds_signature_instance_init(LassoDsSignature *instance)
{
}

static void
lasso_ds_signature_class_init(LassoDsSignatureClass *klass)
{
}

GType lasso_ds_signature_get_type() {
  static GType this_type = 0;

  if (!this_type) {
    static const GTypeInfo this_info = {
      sizeof (LassoDsSignatureClass),
      NULL,
      NULL,
      (GClassInitFunc) lasso_ds_signature_class_init,
      NULL,
      NULL,
      sizeof(LassoDsSignature),
      0,
      (GInstanceInitFunc) lasso_ds_signature_instance_init,
    };
    
    this_type = g_type_register_static(LASSO_TYPE_NODE,
				       "LassoDsSignature",
				       &this_info, 0);
  }
  return this_type;
}

/**
 * lasso_ds_signature_new:
 * @doc: the doc
 * @signMethodId: the signature method (RsaSha1 or DsaSha1)
 *
 * Creates a new <ds:Signature> node object.
 * 
 * Return value: the new @LassoDsDignature
 **/
LassoNode* lasso_ds_signature_new(xmlDocPtr         doc,
				  xmlSecTransformId signMethodId)
{
  LassoNode *node;
  xmlNodePtr signature;
  xmlNodePtr reference;
  xmlNodePtr key_info;

  node = LASSO_NODE(g_object_new(LASSO_TYPE_DS_SIGNATURE, NULL));

  //signature = xmlSecTmplSignatureCreate(NULL, xmlSecTransformExclC14NId,
  signature = xmlSecTmplSignatureCreate(doc, xmlSecTransformExclC14NId,
					signMethodId, NULL);
  if (signature == NULL) {
    printf("Error: failed to create signature template\n");
  }
  reference = xmlSecTmplSignatureAddReference(signature,
					      xmlSecTransformSha1Id,
					      NULL, NULL, NULL);
  if (reference == NULL) {
    printf("Error: failed to add reference to signature template\n");
  }

  // add enveloped transform
  if (xmlSecTmplReferenceAddTransform(reference, xmlSecTransformEnvelopedId) == NULL) {
    printf("Error: failed to add enveloped transform to reference\n");
  }

  /* add <dsig:KeyInfo/> and <dsig:X509Data/> */
  key_info = xmlSecTmplSignatureEnsureKeyInfo(signature, NULL);
  if(key_info == NULL) {
    printf("Error: failed to add key info\n");
  }
  
  if(xmlSecTmplKeyInfoAddX509Data(key_info) == NULL) {
    printf("Error: failed to add X509Data node\n");
  }

  LASSO_NODE_GET_CLASS(node)->set_xmlNode(node, signature);

  return (node);
}
