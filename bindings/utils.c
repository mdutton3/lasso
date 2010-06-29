/*
 * In this file we put utility functions shared by all bindings.
 *
 * They usually are data structure manipulation or conversion functions.
 */
#include <libxml/tree.h>
#include "../lasso/utils.h"

/**
 * lasso_string_fragment_to_xmlnode:
 * @fragment: a fragment of an XML document
 * @size: 
 *
 * Try to get one and only one node from a string, the node can be a simple string or a single node.
 *
 * Return value: a newly allocated xmlNode* or NULL if parsing fails.
 */
static xmlNode*
lasso_string_fragment_to_xmlnode(const char *fragment, int size) {
	xmlDoc *doc = NULL;
	xmlNode *node = NULL;
	xmlNode *list = NULL, *ref = NULL;
	xmlParserErrors errors;

	if (size == 0) {
		size = strlen(fragment);
	}

	/* single node case, with preceding or following spaces */
	doc = xmlReadMemory(fragment, size, NULL, NULL, XML_PARSE_NONET);
	if (doc) {
		node = xmlDocGetRootElement(doc);
		if (node != NULL) {
			node = xmlCopyNode(node, 1);
			goto cleanup;
		}
		lasso_release_doc(doc);
	}
	/* simple string */
	doc = xmlNewDoc(BAD_CAST "1.0");
	ref = xmlNewNode(NULL, BAD_CAST "root");

	xmlDocSetRootElement(doc, ref);
	errors  = xmlParseInNodeContext(ref, fragment, size,
		XML_PARSE_NONET, &list);
	if (errors == XML_ERR_OK && list != NULL && list->next == NULL) {
		node = xmlCopyNode(list, 1);
	}
cleanup:
	lasso_release_doc(doc);
	lasso_release_xml_node_list(list);
	return node;
}
