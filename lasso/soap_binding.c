
#include <lasso/soap_binding.h>


static LassoSoapHeader *
lasso_soap_binding_get_header(

#define find_node_type_in_list(iter, check) \
 { while (iter && ! check(iter->data)) \
     iter = iter->next; }

/** Look up the sb:Provider header in the SOAP message envelope.
 *
 *  @envelope a LassoSoapEnvelope
 *  @return NULL if no Provider element is present in the header of the SOAP envelope. If found it returns a reference you do not own. */
LassoSoapBindingProvider*
lasso_soap_binding_get_provider(LassoSoapEnvelope *envelope) {
	g_return_val_if_fail(envelope, NULL);

	if (envelope->Header) {
		GList *iter = envelop->Header->Other;
		find_node_type_in_list(iter, LASSO_IS_SOAP_BINDING_PROVIDER);
		if (iter) {
			return LASSO_SOAP_BINDING_PROVIDER(iter->data);
		}
	}	
	return NULL;
}

/** Look up the sb:Correlation header in the SOAP message envelope.
 *
 *  @envelope a LassoSoapEnvelope
 *  @return NULL if no Correlation element is present in the header of the SOAP envelope. If found it returns a reference you do not own. */
LassoSoapBindingCorrelation*
lasso_soap_binding_get_correlation(LassoSoapEnvelope *evelope) {
	g_return_val_if_fail(envelope, NULL);

	if (envelope->Header) {
		GList *iter = envelop->Header->Other;
		find_node_type_in_list(iter, LASSO_IS_SOAP_BINDING_CORRELATION);
		if (iter) {
			return LASSO_SOAP_BINDING_CORRELATION(iter->data);
		}
	}	
	return NULL;
}
