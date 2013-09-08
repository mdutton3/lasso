#include "../lasso/lasso.h"
#include "../lasso/xml/xml.h"
#include <glib.h>
#include <libxml/tree.h>

void load(char *file) {
	LassoNode *node = NULL;
	char *content;
	size_t len;
	xmlNode *xmlnode;

	g_file_get_contents(file, &content, &len, NULL);
	node = lasso_node_new_from_dump(content);
	g_free(content);
	xmlnode = lasso_node_get_xmlNode(node, TRUE);
	content = lasso_node_dump(node);
	g_free(content);
	content = lasso_node_export_to_soap(node);
	g_free(content);

	g_object_unref(node);
	xmlFreeNode(xmlnode);
}

int main(G_GNUC_UNUSED int argc, G_GNUC_UNUSED char **argv) {
	lasso_init();
	load(SRCDIR "/data/response-1");
	load(SRCDIR "/data/response-2");
	load(SRCDIR "/data/response-3");
	load(SRCDIR "/data/response-4");
	lasso_shutdown();

	return 0;
}
