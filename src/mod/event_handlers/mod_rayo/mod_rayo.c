/* 
 * FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 * Copyright (C) 2005-2013, Anthony Minessale II <anthm@freeswitch.org>
 *
 * Version: MPL 1.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is FreeSWITCH Modular Media Switching Software Library / Soft-Switch Application
 *
 * The Initial Developer of the Original Code is
 * Anthony Minessale II <anthm@freeswitch.org>
 * Portions created by the Initial Developer are Copyright (C)
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 * Chris Rienzo <chris.rienzo@grasshopper.com>
 *
 * mod_rayo.c -- Rayo server / node implementation.  Allows MxN clustering of FreeSWITCH and Rayo Clients (like Adhearsion)
 *
 */
#include <switch.h>
#include <iksemel.h>


SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_rayo_shutdown);
SWITCH_MODULE_LOAD_FUNCTION(mod_rayo_load);
SWITCH_MODULE_DEFINITION(mod_rayo, mod_rayo_load, mod_rayo_shutdown, NULL);

struct rayo_session;

typedef void (*iq_set_command_handler_fn)(struct rayo_session *, iks *);
struct iq_set_command_handler {
	iq_set_command_handler_fn fn;
};

/**
 * Module state
 */
static struct {
	switch_memory_pool_t *pool;
	int shutdown;
	switch_hash_t *users;
	switch_hash_t *iq_set_command_handlers;
} globals;

/**
 * A server listening for clients
 */
struct rayo_server {
	switch_memory_pool_t *pool;
	char *addr;
	switch_port_t port;
	switch_socket_t *socket;
};

enum rayo_session_state {
	SS_NEW,
	SS_AUTHENTICATED,
	SS_RESOURCE_BOUND,
	SS_SESSION_ESTABLISHED,
	SS_ONLINE,
	SS_ERROR,
	SS_DESTROY
};

/**
 * A Rayo XML stream
 */
struct rayo_session {
	switch_memory_pool_t *pool;
	switch_socket_t *socket;
	char *server_jid;
	char *client_jid;
	char *client_resource_id;
	char *client_jid_full;
	int incoming;
	iksparser *parser;
	iksfilter *filter;
	char id[SWITCH_UUID_FORMATTED_LENGTH + 1];
	enum rayo_session_state state;
};

/**
 * Convert Rayo state to string
 * @param state the Rayo state
 * @return the string value of type or "UNKNOWN"
 */
static const char *rayo_session_state_to_string(enum rayo_session_state state)
{
	switch(state) {
		case SS_NEW: return "NEW";
		case SS_AUTHENTICATED: return "AUTHENTICATED";
		case SS_RESOURCE_BOUND: return "RESOURCE_BOUND";
		case SS_SESSION_ESTABLISHED: return "SESSION_ESTABLISHED";
		case SS_ONLINE: return "SESSION_ESTABLISHED";
		case SS_ERROR: return "ERROR";
		case SS_DESTROY: return "DESTROY";
		default: return "UNKNOWN";
	}
}

/**
 * Convert iksemel XML node type to string
 * @param type the XML node type
 * @return the string value of type or "UNKNOWN"
 */
static const char *node_type_to_string(int type)
{
	switch(type) {
		case IKS_NODE_START: return "NODE_START";
		case IKS_NODE_NORMAL: return "NODE_NORMAL";
		case IKS_NODE_ERROR: return "NODE_ERROR";
		case IKS_NODE_STOP: return "NODE_START";
		default: return "NODE_UNKNOWN";
	}
}

/**
 * Convert iksemel error code to string
 * @param err the iksemel error code
 * @return the string value of error or "UNKNOWN"
 */
static const char *net_error_to_string(int err)
{
	switch (err) {
		case IKS_OK: return "OK";
		case IKS_NOMEM: return "NOMEM";
		case IKS_BADXML: return "BADXML";
		case IKS_HOOK: return "HOOK";
		case IKS_NET_NODNS: return "NET_NODNS";
        case IKS_NET_NOSOCK: return "NET_NOSOCK";
		case IKS_NET_NOCONN: return "NET_NOCONN";
		case IKS_NET_RWERR: return "NET_RWERR";
		case IKS_NET_NOTSUPP: return "NET_NOTSUPP";
		case IKS_NET_TLSFAIL: return "NET_TLSFAIL";
		case IKS_NET_DROPPED: return "NET_DROPPED";
		case IKS_NET_UNKNOWN: return "NET_UNKNOWN";
		default: return "UNKNOWN";
	}
}

/**
 * Handle stream logging callback
 */
void on_log(void *user_data, const char *data, size_t size, int is_incoming) 
{
	if (size > 0) {
		struct rayo_session *rsession = (struct rayo_session *)user_data;
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s %s %s\n", rsession->id, is_incoming ? "RECV" : "SEND", data);
	}
}


/**
 * Add command handler function to hash
 * @param name the command name
 * @param fn the command callback function
 */
static void add_iq_set_command_handler(const char *name, iq_set_command_handler_fn fn)
{
	/* have to wrap function pointer since conversion to void * is not allowed */
	struct iq_set_command_handler *handler = switch_core_alloc(globals.pool, sizeof (*handler));
	handler->fn = fn;
	switch_core_hash_insert(globals.iq_set_command_handlers, name, handler);
}

/**
 * Get command handler function from hash
 * @param name the command name
 * @param namespace the command namespace
 * @return the command handler function or NULL
 */
static iq_set_command_handler_fn get_iq_set_command_handler(const char *name, const char *namespace)
{
	struct iq_set_command_handler *handler = NULL;
	if (zstr(name)) {
		return NULL;
	}
	if (zstr(namespace)) {
		handler = (struct iq_set_command_handler *)switch_core_hash_find(globals.iq_set_command_handlers, name);
	} else {
		char full_name[1024];
		full_name[1023] = '\0';
		snprintf(full_name, sizeof(full_name) - 1, "%s:%s", namespace, name);
		handler = (struct iq_set_command_handler *)switch_core_hash_find(globals.iq_set_command_handlers, full_name);
	}
	if (handler) {
		return handler->fn;
	}
	return NULL;
}

/**
 * Get attribute value of node, returning empty string if non-existent or not set.
 * @param xml the XML node to search
 * @param attrib the Attribute name
 * @return the attribute value
 */
static char *soft_find_attrib(iks *xml, const char *attrib)
{
	char *value = iks_find_attrib(xml, attrib);
	return zstr(value) ? "" : value;
}

/**
 * Send bind + session reply to Rayo client <session>
 * @param rsession the Rayo session to use
 * @return the error code
 */
static int rayo_send_header_bind(struct rayo_session *rsession)
{
	char *header = switch_mprintf(
		"<stream:stream xmlns=\""IKS_NS_CLIENT"\" xmlns:db=\"jabber:server:dialback\""
		" from=\"%s\" id=\"%s\" xml:lang=\"en\" version=\"1.0\""
		" xmlns:stream=\"http://etherx.jabber.org/streams\"><stream:features>"
		"<bind xmlns=\""IKS_NS_XMPP_BIND"\"/>"
		"<session xmlns=\""IKS_NS_XMPP_SESSION"\"/>"
		"</stream:features>", rsession->server_jid, rsession->id);
	int result = iks_send_raw(rsession->parser, header);
	switch_safe_free(header);
	return result;
}

/**
 * Handle <presence> message callback
 * @param user_data the Rayo session
 * @param pak the <presence> packet
 * @return IKS_FILTER_EAT
 */
static int on_presence(void *user_data, ikspak *pak)
{
	struct rayo_session *rsession = (struct rayo_session *)user_data;
	iks *node = pak->x;
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s, presence, state = %s\n", rsession->id, rayo_session_state_to_string(rsession->state));
	if (rsession->state == SS_SESSION_ESTABLISHED) {
		iks *show = iks_find(node, "show");
		if (show) {
			char *status = iks_cdata(iks_child(show));
			if (!zstr(status) && !strcmp("chat", status)) {
				rsession->state = SS_ONLINE;
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s, %s is ONLINE\n", rsession->id, rsession->client_jid_full);
			}
		} else {
			/* TODO error */
		}
	} else {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "%s, presence UNEXPECTED, state = %s\n", rsession->id, rayo_session_state_to_string(rsession->state));
		/* TODO error */
	}
	return IKS_FILTER_EAT;
}

/**
 * Handle <iq><ping> request
 * @param node the <iq> node
 */
static void on_iq_set_xmpp_ping(struct rayo_session *rsession, iks *node)
{
	iks *pong = iks_new("iq");
	char *from = iks_find_attrib(node, "from");
	char *to = iks_find_attrib(node, "to");
	
	if (zstr(from)) {
		from = rsession->client_jid_full;
	}
	if (zstr(to)) {
		to = rsession->server_jid;
	}

	iks_insert_attrib(pong, "type", "result");
	iks_insert_attrib(pong, "from", to);
	iks_insert_attrib(pong, "to", from);
	iks_insert_attrib(pong, "id", iks_find_attrib(node, "id"));
	iks_send(rsession->parser, pong);
	iks_delete(pong);	
}

/**
 * Handle <iq><session> request
 * @param node the <iq> node
 */
static void on_iq_set_xmpp_session(struct rayo_session *rsession, iks *node)
{
	if (rsession->state == SS_RESOURCE_BOUND) {
		iks *reply = iks_new("iq");
		iks_insert_attrib(reply, "type", "result");
		iks_insert_attrib(reply, "from", rsession->server_jid);
		iks_insert_attrib(reply, "to", rsession->client_jid_full);
		iks_insert_attrib(reply, "id", iks_find_attrib(node, "id"));
		iks_send(rsession->parser, reply);
		iks_delete(reply);
		rsession->state = SS_SESSION_ESTABLISHED;
	} else {
		/* TODO error */
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "%s, iq UNEXPECTED <session>, state = %s\n", rsession->id, rayo_session_state_to_string(rsession->state));
	}
}

/**
 * Handle <iq><bind> request
 * @param node the <iq> node
 */
static void on_iq_set_xmpp_bind(struct rayo_session *rsession, iks *node)
{
	if (rsession->state == SS_AUTHENTICATED) {
		iks *bind = iks_find(node, "bind");
		iks *resource = iks_find(bind, "resource");
		iks *reply, *x;
		char *resource_id = NULL;

		/* get optional client resource ID */
		if (resource) {
			resource_id = iks_cdata(iks_child(resource));
 		}
 		
 		/* generate resource ID for client if not already set */
 		if (zstr(resource_id)) {
			char resource_id_buf[SWITCH_UUID_FORMATTED_LENGTH + 1];
			switch_uuid_str(resource_id_buf, sizeof(resource_id_buf));
			resource_id = switch_core_strdup(rsession->pool, resource_id_buf);
		}

		/* create full JID */
		rsession->client_resource_id = resource_id;
		rsession->client_jid_full = switch_core_sprintf(rsession->pool, "%s/%s", rsession->client_jid, rsession->client_resource_id);

		/* create reply */
		reply = iks_new("iq");	
		iks_insert_attrib(reply, "type", "result");
		iks_insert_attrib(reply, "id", iks_find_attrib(node, "id"));

		x = iks_insert(reply, "bind");
		iks_insert_attrib(x, "xmlns", IKS_NS_XMPP_BIND);
		iks_insert_cdata(iks_insert(x, "jid"), rsession->client_jid_full, strlen(rsession->client_jid_full));

		/* send reply to client */
		iks_send(rsession->parser, reply);
		iks_delete(reply);

		rsession->state = SS_RESOURCE_BOUND;
	} else {
		/* TODO error */
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "%s, iq UNEXPECTED <bind>, state = %s\n", rsession->id, rayo_session_state_to_string(rsession->state));
	}
}

/**
 * Handle <iq> get requests
 * @param node the <iq> node
 * @return IKS_FILTER_EAT
 */
static int on_iq_get(void *user_data, ikspak *pak)
{
	struct rayo_session *rsession = (struct rayo_session *)user_data;
	iks *node = pak->x;
	iks *response = iks_copy(node);
	iks *x;
	
	/* <iq> */
	iks_insert_attrib(response, "from", rsession->server_jid);
	iks_insert_attrib(response, "to", rsession->client_jid_full);
	iks_insert_attrib(response, "type", "error");
	
	/* <error> */
	x = iks_insert(response, "error");
	iks_insert_attrib(x, "type", "cancel");
	
	/* <feature-not-implemented> */
	x = iks_insert(x, "feature-not-implemented");
	iks_insert_attrib(x, "xmlns", "urn:ietf:params:xml:ns:xmpp-stanzas");
	
	/* <text> */
	x = iks_insert(x, "text");
	iks_insert_cdata(x, "Feature not supported", strlen("Feature not supported"));
	
	iks_send(rsession->parser, response);
	iks_delete(response);
	
	return IKS_FILTER_EAT;
}

/**
 * Send <success> reply to Rayo client <auth>
 * @param rsession the Rayo session to use.
 */
static int rayo_send_auth_success(struct rayo_session *rsession)
{
	return iks_send_raw(rsession->parser, "<success xmlns=\""IKS_NS_XMPP_SASL"\"/>");
}

/**
 * Send <failure> reply to Rayo client <auth>
 * @param rsession the Rayo session to use.
 * @param reason the reason for failure
 */
static int rayo_send_auth_failure(struct rayo_session *rsession, const char *reason)
{
	int result;
	char *reply = switch_mprintf("<failure xmlns=\""IKS_NS_XMPP_SASL"\">"
		"<%s/></failure></session:session>", reason);
	result = iks_send_raw(rsession->parser, reply);
	return result;
}

/**
 * Parse authzid, authcid, and password tokens from base64 PLAIN auth message.
 * @param message the base-64 encoded authentication message
 * @param authzid the authorization id in the message
 * @param authcid the authentication id in the message
 * @param password the password in the message
 */
static void parse_plain_auth_message(char *message, char **authzid, char **authcid, char **password)
{
	char *decoded = iks_base64_decode(message);
	int maxlen = strlen(message) * 6 / 8 + 1;
	int pos = 0;
	*authzid = NULL;
	*authcid = NULL;
	*password = NULL;
	if (decoded == NULL) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Missing auth message\n");
		return;
	}
	*authzid = decoded;
	pos = strlen(*authzid) + 1;
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "authcid = %s\n", *authzid);
	if (pos >= maxlen) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Stopped at authzid\n");
		return;
	}
	*authcid = decoded + pos;
	pos += strlen(*authcid) + 1;
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "authcid = %s\n", *authcid);
	if (pos >= maxlen) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Stopped at authcid\n");
		return;
	}
	*password = decoded + pos;
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "password = %s\n", zstr(*password) ? "(null)" : "xxxxxx");
}

/**
 * Validate username and password
 * @param authzid authorization id
 * @param authcid authentication id
 * @param password
 */
static int verify_plain_auth(char *authzid, char *authcid, char *password)
{
	char *correct_password;
	if (zstr(authzid) || zstr(authcid) || zstr(password)) {
		return 0;
	}
	correct_password = switch_core_hash_find(globals.users, authcid);
	return !zstr(correct_password) && !strcmp(correct_password, password);
}

/**
 * Send sasl reply to Rayo client <session>
 * @param rsession the Rayo session to use.
 * @return the error code
 */
static int rayo_send_header_auth(struct rayo_session *rsession)
{
	char *header = switch_mprintf(
		"<stream:stream xmlns=\""IKS_NS_CLIENT"\" xmlns:db=\"jabber:server:dialback\""
		" from=\"%s\" id=\"%s\" xml:lang=\"en\" version=\"1.0\""
		" xmlns:stream=\"http://etherx.jabber.org/streams\"><stream:features>"
		"<mechanisms xmlns=\""IKS_NS_XMPP_SASL"\"><mechanism>"
		"PLAIN</mechanism></mechanisms></stream:features>", rsession->server_jid, rsession->id);
	int result = iks_send_raw(rsession->parser, header);
	switch_safe_free(header);
	return result;
}

/**
 * Handle <auth> message.  Only PLAIN supported.
 * @param user_data the Rayo session
 * @param pak the <auth> packet
 */
static void on_auth(struct rayo_session *rsession, iks *node)
{
	char *xmlns, *mechanism;

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s, auth, state = %s\n", rsession->id, rayo_session_state_to_string(rsession->state));

	/* wrong state for authentication */
	if (rsession->state != SS_NEW) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "%s, auth UNEXPECTED, state = %s\n", rsession->id, rayo_session_state_to_string(rsession->state));
		/* TODO error */
		rsession->state = SS_ERROR;
		return;
	}

	/* unsupported authentication type */
	xmlns = soft_find_attrib(node, "xmlns");
	if (strcmp(IKS_NS_XMPP_SASL, xmlns)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "%s, auth, state = %s, unsupported namespace: %s!\n", rsession->id, rayo_session_state_to_string(rsession->state), xmlns);
		/* TODO error */
		rsession->state = SS_ERROR;
		return;
	}

	/* unsupported SASL authentication mechanism */
	mechanism = soft_find_attrib(node, "mechanism");
	if (strcmp("PLAIN", mechanism)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "%s, auth, state = %s, unsupported SASL mechanism: %s!\n", rsession->id, rayo_session_state_to_string(rsession->state), mechanism);
		rayo_send_auth_failure(rsession, "invalid-mechanism");
		rsession->state = SS_ERROR;
		return;
	}

	{
		/* get user and password from auth */
		char *message = iks_cdata(iks_child(node));
		char *authzid = NULL, *authcid, *password;
		/* TODO use library for this! */
		parse_plain_auth_message(message, &authzid, &authcid, &password);
		if (verify_plain_auth(authzid, authcid, password)) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s, auth, state = %s, SASL/PLAIN decoded = %s %s\n", rsession->id, rayo_session_state_to_string(rsession->state), authzid, authcid);
			rayo_send_auth_success(rsession);
			rsession->client_jid = switch_core_strdup(rsession->pool, authzid);
			rsession->client_jid_full = rsession->client_jid;
			rsession->state = SS_AUTHENTICATED;
		} else {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "%s, auth, state = %s, invalid user or password!\n", rsession->id, rayo_session_state_to_string(rsession->state));
			rayo_send_auth_failure(rsession, "not-authorized");
			rsession->state = SS_ERROR;
		}
		switch_safe_free(authzid);
	}
}

/**
 * Handle <iq> set message callback
 * @param user_data the Rayo session 
 * @param pak the <iq> packet
 * @return IKS_FILTER_EAT
 */
static int on_iq_set(void *user_data, ikspak *pak)
{
	struct rayo_session *rsession = (struct rayo_session *)user_data;
	iks *iq = pak->x;
	iks *command = iks_child(iq);
	iq_set_command_handler_fn fn = NULL;
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s, iq, state = %s\n", rsession->id, rayo_session_state_to_string(rsession->state));
	if (command) {
		fn = get_iq_set_command_handler(iks_name(command), iks_find_attrib(command, "xmlns"));
	}
	if (fn) {
		fn(rsession, iq);
	} else {
		/* TODO error */
		rsession->state = SS_ERROR;
	}
	return IKS_FILTER_EAT;
}

/**
 * Handle XML stream callback
 */
static int on_stream(void *user_data, int type, iks *node)
{
	struct rayo_session *rsession = (struct rayo_session *)user_data;
	ikspak *pak = NULL;

	if (node) {
		pak = iks_packet(node);
	}
	
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s, node, state = %s, type = %s\n", rsession->id, rayo_session_state_to_string(rsession->state), node_type_to_string(type));

	switch(type) {
		case IKS_NODE_START:
			if (rsession->state == SS_NEW) {
				rsession->server_jid = switch_core_strdup(rsession->pool, soft_find_attrib(node, "to"));
				rayo_send_header_auth(rsession);
			} else if (rsession->state == SS_AUTHENTICATED) {
				rayo_send_header_bind(rsession);
			}
			break;
		case IKS_NODE_NORMAL:
			if (!strcmp("auth", iks_name(node))) {
				on_auth(rsession, node);
			}
			break;
		case IKS_NODE_ERROR:
			break;
		case IKS_NODE_STOP:
			break;
	}
	
	if (pak) {
		iks_filter_packet(rsession->filter, pak);
	}
	
	/* TODO */
	if (node) {
		iks_delete(node);
	}
	return IKS_OK;
}

/**
 * @param rsession the Rayo session to check
 * @return 0 if session is dead
 */
static int rayo_session_ready(struct rayo_session *rsession)
{
	return rsession->state != SS_ERROR && rsession->state != SS_DESTROY;
}

/**
 * Handles Rayo XML stream
 */
static void *SWITCH_THREAD_FUNC rayo_session_thread(switch_thread_t *thread, void *obj)
{
	iksparser *parser;
	struct rayo_session *rsession = (struct rayo_session *)obj;
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s New connection\n", rsession->id);	
	
	/* set up XMPP stream parser */
	parser = iks_stream_new(IKS_NS_SERVER, rsession, on_stream);
	if (!parser) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s Failed to create XMPP stream parser!\n", rsession->id);
		goto done;
	}
	rsession->parser = parser;

	/* set up additional message callbacks */
	rsession->filter = iks_filter_new();
	iks_filter_add_rule(rsession->filter, on_presence, rsession,
		IKS_RULE_TYPE, IKS_PAK_PRESENCE,
		IKS_RULE_DONE);
	iks_filter_add_rule(rsession->filter, on_iq_set, rsession,
		IKS_RULE_TYPE, IKS_PAK_IQ,
		IKS_RULE_SUBTYPE, IKS_TYPE_SET,
		IKS_RULE_DONE);
	iks_filter_add_rule(rsession->filter, on_iq_get, rsession,
		IKS_RULE_TYPE, IKS_PAK_IQ,
		IKS_RULE_SUBTYPE, IKS_TYPE_GET,
		IKS_RULE_DONE);

	/* enable logging of XMPP stream */
	iks_set_log_hook(parser, on_log); 
	
	if (rsession->incoming) {
		/* connect XMPP stream parser to socket */
		switch_os_socket_t socket;
		switch_os_sock_get(&socket, rsession->socket);
		iks_connect_fd(parser, socket);
		/* TODO error checking */
	} else {
		/* make client connection */
		/* TODO */
	}
	
	while (!globals.shutdown && rayo_session_ready(rsession)) {
		/* TODO keep alive, figure out how to get events */
		int result = iks_recv(parser, 1);
		switch (result) {
			case IKS_OK:
				break;
			case IKS_NET_RWERR:
			case IKS_NET_NOCONN:
			case IKS_NET_NOSOCK:
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "%s iks_recv() error = %s, ending session\n", rsession->id, net_error_to_string(result));
				rsession->state = SS_ERROR;
				break;
			default:
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "%s iks_recv() error = %s\n", rsession->id, net_error_to_string(result));
				switch_yield(100 * 1000);
				break;
		}
	}

  done:
  
	if (rsession->parser) {
		iks_disconnect(rsession->parser);
	}
	
	if (rsession->incoming) {
		switch_socket_shutdown(rsession->socket, SWITCH_SHUTDOWN_READWRITE);
		switch_socket_close(rsession->socket);
	}
	
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s Connection closed\n", rsession->id);
	
	switch_core_destroy_memory_pool(&rsession->pool);

	return NULL;
}

/**
 * Create a new Rayo session
 */
static struct rayo_session *rayo_session_create(switch_memory_pool_t *pool, switch_socket_t *socket, int incoming)
{
	struct rayo_session *rsession = NULL;
	if (!(rsession = switch_core_alloc(pool, sizeof(*rsession)))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Memory Error\n");
		return NULL;
	}
	rsession->pool = pool;
	rsession->socket = socket;
	rsession->incoming = incoming;
	rsession->state = SS_NEW;
	switch_uuid_str(rsession->id, sizeof(rsession->id));
	rsession->server_jid = "";
	rsession->client_jid = "";
	rsession->client_jid_full = "";
	rsession->client_resource_id = "";
	return rsession;
}

/**
 * Listens for new Rayo client connections
 */
static void *SWITCH_THREAD_FUNC rayo_server_thread(switch_thread_t *thread, void *obj)
{
	struct rayo_server *server = (struct rayo_server *)obj;
	uint32_t errs = 0;

	/* bind to XMPP port */
	while (!globals.shutdown) {
		switch_status_t rv;
		switch_sockaddr_t *sa;
		rv = switch_sockaddr_info_get(&sa, server->addr, SWITCH_UNSPEC, server->port, 0, server->pool);
		if (rv)
			goto fail;
		rv = switch_socket_create(&server->socket, switch_sockaddr_get_family(sa), SOCK_STREAM, SWITCH_PROTO_TCP, server->pool);
		if (rv)
			goto sock_fail;
		rv = switch_socket_opt_set(server->socket, SWITCH_SO_REUSEADDR, 1);
		if (rv)
			goto sock_fail;
#ifdef WIN32
		/* Enable dual-stack listening on Windows (if the listening address is IPv6), it's default on Linux */
		if (switch_sockaddr_get_family(sa) == AF_INET6) {
			rv = switch_socket_opt_set(server->socket, 16384, 0);
			if (rv) goto sock_fail;
		}
#endif
		rv = switch_socket_bind(server->socket, sa);
		if (rv)
			goto sock_fail;
		rv = switch_socket_listen(server->socket, 5);
		if (rv)
			goto sock_fail;
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Rayo server listening on %s:%u\n", server->addr, server->port);

		break;
   sock_fail:
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Socket Error! Rayo server could not listen on %s:%u\n", server->addr, server->port);
		switch_yield(100000);
	}

	/* Listen for XMPP client connections */
	while (!globals.shutdown) {
		switch_socket_t *socket = NULL;
		switch_memory_pool_t *pool = NULL;
		switch_status_t rv;

		if (switch_core_new_memory_pool(&pool) != SWITCH_STATUS_SUCCESS) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to create memory pool for new client connection!\n");
			goto fail;
		}

		if ((rv = switch_socket_accept(&socket, server->socket, pool))) {
			switch_core_destroy_memory_pool(&pool);
			if (globals.shutdown) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "Shutting Down\n");
				goto end;
			} else {
				/* I wish we could use strerror_r here but its not defined everywhere =/ */
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Socket Error [%s]\n", strerror(errno));
				if (++errs > 100) {
					goto end;
				}
			}
		} else { /* got a new connection */
			switch_thread_t *thread;
			switch_threadattr_t *thd_attr = NULL;
			struct rayo_session *rsession;
			
			errs = 0;
			
			/* start session thread */
			if (!(rsession = rayo_session_create(pool, socket, 1))) {
				switch_socket_shutdown(socket, SWITCH_SHUTDOWN_READWRITE);
				switch_socket_close(socket);
				switch_core_destroy_memory_pool(&pool);
				break;
			}
			switch_threadattr_create(&thd_attr, rsession->pool);
			switch_threadattr_detach_set(thd_attr, 1);
			switch_threadattr_stacksize_set(thd_attr, SWITCH_THREAD_STACKSIZE);
			switch_thread_create(&thread, thd_attr, rayo_session_thread, rsession, rsession->pool);
		}
	}

  end:

	/* shutdown server */
	switch_socket_shutdown(server->socket, SWITCH_SHUTDOWN_READWRITE);
	switch_socket_close(server->socket);

	if (server->pool) {
		switch_core_destroy_memory_pool(&server->pool);
	}

fail:
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Rayo server %s:%u thread done\n", server->addr, server->port);
	return NULL;
}

/**
 * Add a new server for Rayo client connections.
 * @param addr the IP address
 * @param port the port
 */
static switch_status_t add_rayo_server(char *addr, char *port)
{
	switch_memory_pool_t *pool;
	struct rayo_server *new_server = NULL;
	switch_thread_t *thread;
	switch_threadattr_t *thd_attr = NULL;

	if (zstr(addr)) {
		return SWITCH_STATUS_FALSE;
	}

	if (switch_core_new_memory_pool(&pool) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to create memory pool!\n");
		return SWITCH_STATUS_FALSE;
	}

	new_server = switch_core_alloc(pool, sizeof(*new_server));
	new_server->pool = pool;
	new_server->addr = switch_core_strdup(new_server->pool, addr);
	new_server->port = zstr(port) ? IKS_JABBER_PORT : atoi(port);

	/* start the server thread */
	switch_threadattr_create(&thd_attr, new_server->pool);
	switch_threadattr_detach_set(thd_attr, 1);
	switch_threadattr_stacksize_set(thd_attr, SWITCH_THREAD_STACKSIZE);
	switch_thread_create(&thread, thd_attr, rayo_server_thread, new_server, new_server->pool);
	
	return SWITCH_STATUS_SUCCESS;
}

/**
 * Process module XML configuration
 * @param pool memory pool to allocate from
 * @return SWITCH_STATUS_SUCCESS on successful (re)configuration
 */
static switch_status_t do_config(switch_memory_pool_t *pool)
{
	char *cf = "rayo.conf";
	switch_xml_t cfg, xml;
	switch_status_t status = SWITCH_STATUS_SUCCESS;

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Configuring module\n");
	if (!(xml = switch_xml_open_cfg(cf, &cfg, NULL))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "open of %s failed\n", cf);
		return SWITCH_STATUS_TERM;
	}

	/* get params */
	{
		switch_xml_t settings = switch_xml_child(cfg, "settings");
		if (settings) {
			switch_xml_t param;
			for (param = switch_xml_child(settings, "param"); param; param = param->next) {
				char *var = (char *) switch_xml_attr_soft(param, "name");
				char *val = (char *) switch_xml_attr_soft(param, "value");
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "param: %s = %s\n", var, val);
				if (!strcasecmp(var, "foo")) {
					/* TODO remove */
				} else {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "Unsupported param: %s\n", var);
				}
			}
		}
	}

	/* configure listen addresses */
	{
		switch_xml_t listeners = switch_xml_child(cfg, "listeners");
		if (listeners) {
			switch_xml_t l;
			for (l = switch_xml_child(listeners, "listener"); l; l = l->next) {
				char *val = switch_xml_txt(l);
				char *port = "";
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Listener: %s\n", val);
				if (add_rayo_server(val, port) != SWITCH_STATUS_SUCCESS) {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "Failed to create listener: %s\n", val);
				}
			}
		}
	}
	
	/* configure authorized users */
	{
		switch_xml_t users = switch_xml_child(cfg, "users");
		if (users) {
			switch_xml_t u;
			for (u = switch_xml_child(users, "user"); u; u = u->next) {
				const char *user = switch_xml_attr_soft(u, "name");
				const char *password = switch_xml_attr_soft(u, "password");
				switch_core_hash_insert(globals.users, switch_core_strdup(pool, user), switch_core_strdup(pool, password));
			}
		}
	}

	switch_xml_free(xml);

	return status;
}

/**
 * Offer a call for Rayo 3PCC
 * @param session_uuid
 * @return SWITCH_STATUS_SUCCESS on success
 */
static switch_status_t offer_call(char *session_uuid)
{
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Offering call %s for Rayo 3PCC\n", session_uuid);
	/* TODO */
	return SWITCH_STATUS_FALSE;
}

#define RAYO_USAGE ""
/**
 * Notify of new call and park channel
 */
SWITCH_STANDARD_APP(rayo_app)
{
	if (offer_call(switch_core_session_get_uuid(session)) == SWITCH_STATUS_SUCCESS) {
		switch_ivr_park(session, NULL);
	}
}

/**
 * Load module
 */
SWITCH_MODULE_LOAD_FUNCTION(mod_rayo_load)
{
	switch_application_interface_t *app_interface;

	*module_interface = switch_loadable_module_create_module_interface(pool, modname);

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Loading module\n");
	memset(&globals, 0, sizeof(globals));
	globals.pool = pool;
	switch_core_hash_init(&globals.users, pool);
	
	switch_core_hash_init(&globals.iq_set_command_handlers, pool);
	add_iq_set_command_handler(IKS_NS_XMPP_BIND":bind", on_iq_set_xmpp_bind);
	add_iq_set_command_handler(IKS_NS_XMPP_SESSION":session", on_iq_set_xmpp_session);
	add_iq_set_command_handler("urn:xmpp:ping:ping", on_iq_set_xmpp_ping);

	if(do_config(globals.pool) != SWITCH_STATUS_SUCCESS) {
		return SWITCH_STATUS_TERM;
	}

	SWITCH_ADD_APP(app_interface, "rayo", "Offer call control to Rayo client(s)", "", rayo_app, RAYO_USAGE, SAF_SUPPORT_NOMEDIA);

	return SWITCH_STATUS_SUCCESS;
}

/**
 * Shutdown module.  Notifies threads to stop.
 */
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_rayo_shutdown)
{
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Shutdown module\n");
	globals.shutdown = 1;
	/* TODO wait for shutdown */
	/* TODO cleanup hash, etc */
	return SWITCH_STATUS_SUCCESS;
}

/* For Emacs:
 * Local Variables:
 * mode:c
 * indent-tabs-mode:t
 * tab-width:4
 * c-basic-offset:4
 * End:
 * For VIM:
 * vim:set softtabstop=4 shiftwidth=4 tabstop=4
 */
