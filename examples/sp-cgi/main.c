/**
 * Simple Lasso CGI
 *
 * Usage:
 *
 * ./main <private-key.pem> <certificate.pem> [<idp-metadata.xml>...]
 *
 * The assertion consumer only support the POST binding, single logout is not supported.
 *
 * Entr'ouvert © 2014
 */

#include <time.h>
#include <alloca.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <lasso/lasso.h>
#include <lasso/xml/saml-2.0/samlp2_authn_request.h>
#include <lasso/xml/saml-2.0/samlp2_response.h>
#include <lasso/xml/saml-2.0/saml2_attribute_statement.h>
#include <lasso/xml/saml-2.0/saml2_attribute.h>
#include <lasso/xml/saml-2.0/saml2_attribute_value.h>
#include <lasso/xml/misc_text_node.h>


LassoServer *server = NULL;

/* CGI Env */
static char *query_string = NULL;
static char *path_info = NULL;
static char *host = NULL;
static char *script_name = NULL;
static char *scheme = NULL;
static char *content_type = NULL;
static char* content_length = NULL;

/* SP metadatas and keys */
static char *private_key = NULL;
static size_t private_key_length = 0;
static char *certificate = NULL;
static size_t certificate_length = 0;
static char *metadata = NULL;
static size_t metadata_length = 0;

char*
get_cookie(const char *cookie_name)
{
	char *cookies = getenv("HTTP_COOKIE");
	size_t l = strlen(cookie_name);
	char *value = NULL;

	if (! cookies) {
		return NULL;
	}
	while (*cookies) {
		if (*cookies == ' ') {
			cookies++;
		} else {
			char *next_semicolon = strchr(cookies, ';');

			if (startswith(cookies, cookie_name) && cookies[l] == '=') {
				size_t size = 0;
				
				cookies += l + 1;
				if (next_semicolon) {
					size = cookies - next_semicolon;
				} else {
					size = strlen(cookies);
				}
				value = malloc(size+1);
				value[size] = '\0';
				strncpy(value, cookies, size);
				break;
			}
			if (next_semicolon) {
				cookies = next_semicolon + 1;
			} else {
				break;
			}
		}
	}
	return value;
}

char*
get_parameter2(const char *name, const char *qs) {
	const size_t l = strlen(name);
	char *value = NULL;

	if (! qs) {
		return NULL;
	}

	while (qs) {
		const char *next_amp = strchr(qs, '&');

		if (startswith(qs, name) && (qs[l] == '=' || qs[l] == '&' || qs[l] == '\0')) {
			char *copy = NULL;
			size_t size = 0;

			qs += l;
			if (*qs) {
				qs++;
			}
			if (next_amp) {
				size = next_amp - qs;
			} else {
				size = strlen(qs);
			}
			copy = alloca(size+1);
			copy[size] = '\0';
			strncpy(copy, qs, size);
			value = g_uri_unescape_string(copy, NULL);
			break;
		}
		if (next_amp) {
			qs = next_amp + 1;
		} else {
			break;
		}
	}
	return value;
}

char*
get_parameter(const char *name) {
	const char *qs = getenv("QUERY_STRING");

	return get_parameter2(name, qs);
}

gboolean
startswith(const char *s, const char *needle) {
	if (! needle) {
		return TRUE;
	}
	if (! s) {
		return FALSE;
	}
	return strncmp(s, needle, strlen(needle)) == 0;
}

#define OR(a,b) ((a) ? (a) : (b))

int
main(int argc, char **argv) {
	int i = 0;
	char *pair = NULL;
	struct stat buf;
	char *end;
	int ret, fd;
	GError *err;

	if (argc < 2) {
		g_error("You must give your private key file as first argument");
	}

	if (argc < 3) {
		g_error("You must give your certificate file as second argument");
	}

	if (! g_file_get_contents(argv[1], &private_key, &private_key_length, &err)) {
		g_error("Failed to read %s: %s", argv[1], err->message);
	}
	if (! g_file_get_contents(argv[1], &certificate, &certificate_length, &err)) {
		g_error("Failed to read %s: %s", argv[2], err->message);
	}

	/* remove PEM prefix and suffix */
	while (*certificate != '\n' && *certificate != '\0') {
		certificate++;
	}
	certificate++;
	end = certificate;
	while (*end != '-' && *end != '\0') {
		end++;
	}
	end--;
	*end = '\0';

	/* read CGI env */
	path_info = OR(getenv("PATH_INFO"), "");
	query_string = OR(getenv("QUERY_STRING"), "");
	host = OR(getenv("HTTP_HOST"), "");
	script_name = OR(getenv("SCRIPT_NAME"), "");
	content_type = OR(getenv("CONTENT_TYPE"), "");
	content_length = OR(getenv("CONTENT_LENGTH"), "");
	if (getenv("HTTPS")) {
		scheme = "https";
	} else {
		scheme = "http";
	}

	/* generate metadata */
	metadata_length = snprintf_metadata(NULL, 0);
	metadata = g_malloc(metadata_length+1);
	snprintf_metadata(metadata, metadata_length+1);
	metadata[metadata_length] = '\0';

	
	/* create Lasso objects */
	lasso_init();
	server = lasso_server_new_from_buffers(metadata, private_key, NULL, NULL);
	g_message("Server created with private key %s and certificate %s", argv[1], argv[2]);
	for (i = 3; i < argc; i++) {
		lasso_error_t rc = 0;
		g_message("Loading idp metadata %s", argv[i]);
		rc = lasso_server_add_provider(server, LASSO_PROVIDER_ROLE_IDP, argv[i], NULL, NULL);
		if (rc != 0) {
			g_error("Failed to load IdP metadata %s: %s", argv[i], lasso_strerror(rc));
		}
	}

	if (strcmp(path_info, "/metadata") == 0) {
		return show_metadata();
	} else if (strcmp(path_info, "/login") == 0) {
		return emit_authn_request();
	} else if (strcmp(path_info, "/assertionConsumerPost") == 0) {
		return assertion_consumer();
	} else if (strcmp(path_info, "/logout") == 0) {
		return logout();
	} else if (strcmp(path_info, "/") == 0) {
		return homepage();
	} else {
		printf("Location: %s/\n\n", script_name);
	}
}

int
homepage()
{
	char *session_id = get_cookie("session_id");

	printf("Content-type: text/html\n\n");
	printf("<html><body><ul>\n");
	printf("<li><a href=\"%s/metadata\">/metadata</a> - retrieve metadatas</li>\n", script_name);
	printf("<li><a href=\"%s/login\">/login?entityID=...&ReturnURL=...</a> - launch AuthnRequest</li>\n", script_name);
	printf("<li><a href=\"%s/assertionConsumerPost\">/assertionConsumerPost</a> - consumer assertion sent using POST binding</li>\n", script_name);
	printf("<li><a href=\"%s/logout\">/logout</a> - delete local session\n", script_name);
	printf("</ul>\n");
	printf("\n");
	if (session_id) {
		char *session_path = g_strdup_printf("session_%s", session_id);
		char *content;
		size_t length;
		GError *error;

		if (g_file_get_contents(session_path, &content, &length, &error)) {
			g_message("session_path %sx", session_path);
			printf("<p>Session ID: %s</p>", g_markup_escape_text(session_id, strlen(session_id)));
			printf("<pre>\n");
			fwrite(content, length, 1, stdout);
			printf("</pre></body></html>\n");
			g_free(content);
		} else {
			g_error("Unable to read %s %s", session_path, error->message);
		}
	}

	return 0;
}

int
show_metadata()
{
	printf("Content-Type: text/xml\n\n%s", metadata);
	return 0;
}

int
snprintf_metadata(char *output, size_t length) {
	size_t l = 0;

	l += snprintf(output+l, length, "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n");
	l += snprintf(output+l, length, "<EntityDescriptor entityID=\"%s://%s%s/metadata\" xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\">\n", scheme, host, script_name);
	l += snprintf(output+l, length, "<SPSSODescriptor AuthnRequestsSigned=\"true\" WantAssertionsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n");
	l += snprintf(output+l, length, "<KeyDescriptor use=\"signing\">\n\
<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n\
<ds:X509Data>\n\
<ds:X509Certificate>%s</ds:X509Certificate>\n\
</ds:X509Data>\n\
</ds:KeyInfo>\n\
</KeyDescriptor>\n", certificate);
	l += snprintf(output+l, length, "<AssertionConsumerService index=\"0\" isDefault=\"true\" Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"%s://%s%s/assertionConsumerPost\" />\n", scheme, host, script_name);
	l += snprintf(output+l, length, "</SPSSODescriptor>\n</EntityDescriptor>");
	return l;
}

int
emit_authn_request() {
	gboolean is_passive = FALSE;
	char *entity_id = NULL;
	char *relay_state = NULL;
	LassoLogin *login = NULL;
	LassoHttpMethod http_method = LASSO_HTTP_METHOD_ANY;

	is_passive = get_parameter("isPassive") != NULL;
	entity_id = get_parameter("entityID");
	relay_state = get_parameter("ReturnURL");

	login = lasso_login_new(server);
	if (! login) {
		g_error("Unable to create a login object");
	}
	{
		lasso_error_t rc = lasso_login_init_authn_request(login, entity_id, http_method);
		if (rc != 0) {
			g_error("lasso_login_init_authn_request returned an error: %s", lasso_strerror(rc));
		}
	}
	((LassoSamlp2AuthnRequest*)login->parent.request)->IsPassive = is_passive;
	login->parent.msg_relayState = relay_state;
	{
		lasso_error_t rc = lasso_login_build_authn_request_msg(login);
		if (rc != 0) {
			g_error("lasso_login_build_authn_reques_msg returned an error: %s", lasso_strerror(rc));
		}
	}
	if (login->parent.msg_body) { // POST binding case
		printf("Content-type: text/html\n\n");
		printf("<html>\n\
<body onload=\"document.forms['saml'].submit()\">\n\
<form action=\"%s\" method=\"post\" name=\"saml\">\n\
<input type=\"hidden\" name=\"SAMLRequest\" value=\"%s\">\n", login->parent.msg_url, login->parent.msg_body);
		if (relay_state) {
			printf("<input type=\"hidden\" name=\"RelayState\" value=\"%s\">\n",
					g_markup_escape_text(relay_state, -1));
		}
		printf("</form>\n\
</body>\n\
</html>");
	} else { // redirect binding case
		printf("Status: 303 See other\n");
		printf("Location: %s\n", login->parent.msg_url);
		printf("\n");
	}
}

void
write_rfc822_field_value(FILE *file, char *value)
{
	char *p = NULL;

	p = strchr(value, '\n');
	while (p) {
		p += 1;
		fwrite(value, p-value, 1, file);
		value = p;
		// add continuation whitespace
		fprintf(file, " ");
		p = strchr(value, '\n');
	}
	fprintf(file, "%s\n", value);

}

void
write_attributes(LassoLogin *login, FILE *session_file)
{
	LassoSamlp2Response *response = (LassoSamlp2Response*)login->parent.response;
	LassoSaml2Assertion *assertion = (LassoSaml2Assertion*)response->Assertion->data;
	LassoSaml2NameID *issuer = response->parent.Issuer;
	LassoSaml2Subject *subject = assertion->Subject;
	LassoSaml2NameID *name_id= subject->NameID;
	GList *ats_list, *at_list, *atv_list;

	fprintf(session_file, "Issuer: ");
	write_rfc822_field_value(session_file, issuer->content);
	fprintf(session_file, "NameID: ");
	write_rfc822_field_value(session_file, name_id->content);
	fprintf(session_file, "NameIDFormat: ");
	write_rfc822_field_value(session_file, name_id->Format);
	ats_list = assertion->AttributeStatement;
	while (ats_list) {
		LassoSaml2AttributeStatement *ats = ats_list->data;
		at_list = ats->Attribute;
		while(at_list) {
			LassoSaml2Attribute *at = at_list->data;
			atv_list = at->AttributeValue;
			while (atv_list) {
				LassoSaml2AttributeValue *atv = atv_list->data;
				if (atv->any && atv->any->data && LASSO_IS_MISC_TEXT_NODE(atv->any->data)) {
					LassoMiscTextNode *mtn = atv->any->data;
					fprintf(session_file, "%s: ", at->Name);
					write_rfc822_field_value(session_file, mtn->content);
				}
				atv_list = atv_list->next;
			}
			at_list = at_list->next;
		}
		ats_list = ats_list->next;
	}

}

int
assertion_consumer() {
	size_t content_length_s = 0;
	char *buffer = NULL;
	int l = 0;
	int ret = 0;
	char *saml_response = NULL;
	char *relay_state = NULL;
	LassoLogin *login = NULL;

	if (! content_type || strcmp(content_type, "application/x-www-form-urlencoded") != 0) {
		g_error("Content-type is not application/x-www-form-urlencoded");
	}
	if (! content_length) {
		g_error("Missing CONTENT_LENGTH environment variable");
	}
	content_length_s = atoi(content_length);
	if (content_length_s > 100000 || content_length_s < 0) {
		g_error("Invalid CONTENT_LENGTH");
	}
	buffer = malloc(content_length_s+1);
	buffer[content_length_s] = '\0';
	while (ret = read(0, buffer+l, content_length_s-l)) {
		if (ret == -1) {
			if (errno == EINTR) {
				continue;
			}
			g_error("Error while reading POST data %s", strerror(errno));
		}
		l += ret;
	}

	saml_response = get_parameter2("SAMLResponse", buffer);
	relay_state = get_parameter2("RelayState", buffer);

	if (! saml_response) {
		printf("Status: 401 Invalid request\n");
		printf("Content-type: text/lain\n\n");
		printf("Missing SAMLResponse");
	}

	login = lasso_login_new(server);
	if (! login) {
		g_error("Unable to create a login object");
	}
	g_message("SAMLRequest %s", saml_response);
	{
		lasso_error_t rc = 0;
		rc = lasso_login_process_authn_response_msg(login, saml_response);
		if (rc == LASSO_PROFILE_ERROR_STATUS_NOT_SUCCESS) {
			LassoSamlp2Response *response = (LassoSamlp2Response*)login->parent.response;
			printf("Content-type: text/html\n\n");
			printf("<h1>Authentication request was denied</h1>");
			printf("<pre>");
			printf("<b>Status message:</b> %s\n", response->parent.Status->StatusMessage);
			if (response->parent.Status->StatusCode->Value)
				printf("<b>First level status code:</b> %s\n", response->parent.Status->StatusCode->Value);
			if (response->parent.Status->StatusCode->StatusCode->Value)
				printf("<b>Second level status code:</b> %s\n", response->parent.Status->StatusCode->StatusCode->Value);
			printf("</pre>");
			printf("<a href=\"%s/\">Back</a>", script_name);
			return 0;
		} else if (rc != 0) {
			g_error("lasso_login_process_authn_response_msg returned an error: %s", lasso_strerror(rc));
		}
	}
	// Allocate new session
	{
		long unsigned int session_id = (long unsigned int)random();
		char *session_file_path = NULL;
		FILE *session_file = NULL;
		int l = snprintf(NULL, 0, "session_%lu", session_id);
		session_file_path = malloc(l+1);
		session_file_path[l] = '\0';
		sprintf(session_file_path, "session_%lu", session_id);

		session_file = fopen(session_file_path, "w+");
		if (! session_file) {
			g_error("Cannot open session_file %s: %s", session_file_path, strerror(errno));
		}
		write_attributes(login, session_file);
		fclose(session_file);

		printf("Status: 303 See other\n");
		printf("Set-Cookie: session_id=%lu;path=/\n", session_id);
		if (relay_state) {
			printf("Location: %s\n", relay_state);
		} else {
			printf("Location: %s/\n", script_name);
		}
		printf("\n");
	}
	return 0;
}

int
logout()
{
	char *session_id = get_cookie("session_id");
	char *return_url = NULL;

	return_url = get_parameter("ReturnURL");
	if (session_id) {
		char *path = NULL;
		size_t size = snprintf(NULL, 0, "session_%s", session_id);
		int rc;
		path = malloc(size+1);
		sprintf(path, "session_%s", session_id);
		rc = unlink(path);
		if (rc == -1 && errno != ENOENT) {
			g_error("logout: unlink of %s failed", path);
		}
		free(path);
	}
	printf("Status: 303 See other\n");
	if (return_url) {
		printf("Location: %s\n", return_url);
	} else {
		printf("Location: %s/\n", script_name);
	}
	// Delete the session cookie
	printf("Set-Cookie: session_id=;path=/;Expires=Thu, 01-Jan-1970 00:00:01 GMT\n");
	printf("\n");
	return 0;
}
