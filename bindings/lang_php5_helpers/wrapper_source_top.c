#include <php.h>
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION
#include <lasso/lasso.h>
#include "php_lasso.h"

int le_lasso_server;

ZEND_GET_MODULE(lasso)

typedef struct {
	GObject *obj;
	char *typename;
} PhpGObjectPtr;

PHP_FUNCTION(lasso_get_object_typename)
{
	PhpGObjectPtr *self;
	zval *zval_self;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "r", &zval_self) == FAILURE) {
		RETURN_FALSE;
	}

	ZEND_FETCH_RESOURCE(self, PhpGObjectPtr *, &zval_self, -1, PHP_LASSO_SERVER_RES_NAME, le_lasso_server);
	RETURN_STRING(self->typename, 1);
}

static char*
get_string_from_xml_node(xmlNode *xmlnode)
{
	xmlOutputBufferPtr buf;
	char *xmlString;

	if (xmlnode == NULL) {
		return NULL;
	}

	buf = xmlAllocOutputBuffer(NULL);
	if (buf == NULL) {
		xmlString = NULL;
	} else {
		xmlNodeDumpOutput(buf, NULL, xmlnode, 0, 1, NULL);
		xmlOutputBufferFlush(buf);
		if (buf->conv == NULL) {
			xmlString = estrdup((char*)buf->buffer->content);
		} else {
			xmlString = estrdup((char*)buf->conv->content);
		}
		xmlOutputBufferClose(buf);
	}

	return xmlString;
}

static xmlNode*
get_xml_node_from_string(char *string) {
	xmlDoc *doc;
	xmlNode *node;

	doc = xmlReadDoc((xmlChar*)string, NULL, NULL, XML_PARSE_NONET);
	node = xmlDocGetRootElement(doc);
	if (node != NULL) {
		node = xmlCopyNode(node, 1);
	}
	xmlFreeDoc(doc);

	return node;
}

