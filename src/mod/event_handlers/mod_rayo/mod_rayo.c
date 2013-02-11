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
 * Module state
 */
static struct {
	switch_memory_pool_t *pool;
	int shutdown;
	switch_hash_t *users;
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
	SS_ERROR,
	SS_DESTROY
};

/**
 * A Rayo XML stream
 */
struct rayo_session {
	switch_memory_pool_t *pool;
	switch_socket_t *socket;
	char *to;
	char *from;
	char *client_jid;
	char *client_resource;
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
		case SS_ERROR: return "ERROR";
		case SS_DESTROY: return "DESTROY";
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
		"<stream:stream xmlns=\"jabber:server\" xmlns:db=\"jabber:server:dialback\""
		" from=\"%s\" id=\"%s\" xml:lang=\"en\" version=\"1.0\""
		" xmlns:stream=\"http://etherx.jabber.org/streams\"><stream:features>"
		"<bind xmlns=\"urn:ietf:params:xml:ns:xmpp-bind\"/>"
		"<session xmlns=\"urn:ietf:params:xml:ns:xmpp-session\"/>"
		"</stream:features>", rsession->from, rsession->id);
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
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s, presence, state = %s\n", rsession->id, rayo_session_state_to_string(rsession->state));
	if (rsession->state == SS_SESSION_ESTABLISHED) {
	} else {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "%s, presence UNEXPECTED, state = %s\n", rsession->id, rayo_session_state_to_string(rsession->state));
		/* TODO error */
	}
	return IKS_FILTER_EAT;
}

/**
 * Send <success> reply to Rayo client <auth>
 * @param rsession the Rayo session to use.
 */
static int rayo_send_auth_success(struct rayo_session *rsession)
{
	return iks_send_raw(rsession->parser, "<success xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\"/>");
}

/**
 * Send <failure> reply to Rayo client <auth>
 * @param rsession the Rayo session to use.
 * @param reason the reason for failure
 */
static int rayo_send_auth_failure(struct rayo_session *rsession, const char *reason)
{
	int result;
	char *reply = switch_mprintf("<failure xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\">"
		"<%s/></failure></session:session>", reason);
	result = iks_send_raw(rsession->parser, reply);
	return result;
}

/**
 * Parse jid, user, and password tokens from base64 PLAIN auth body.
 */
static void parse_plain_auth_body(char *body, char **jid, char **user, char **password)
{
	char *body_decoded = iks_base64_decode(body);
	int len = 0;
	int maxlen = strlen(body) * 6 / 8 + 1;
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "maxlen = %i\n", maxlen);
	*jid = "";
	*user = "";
	*password = "";
	if (body_decoded == NULL) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Missing auth body\n");
		return;
	}
	*jid = body_decoded;
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "jid = %s\n", *jid);
	len = strlen(*jid) + 1;
	if (len >= maxlen) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Stopped at JID\n");
		return;
	}
	*user = body_decoded + len;
	len += strlen(*user) + 1;
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "user = %s\n", *user);
	if (len >= maxlen) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Stopped at user\n");
		return;
	}
	*password = body_decoded + len;
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "password = %s\n", *password);
	return;
}

/**
 * Validate username and password
 * @param username
 * @param password
 */
static int is_correct_user_password(char *username, char *password)
{
	char *correct_password;
	if (zstr(username) || zstr(password)) {
		return 0;
	}
	correct_password = switch_core_hash_find(globals.users, username);
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "is_authenticated? username = %s, password = %s, expected = %s\n", username, password, correct_password);
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
		"<stream:stream xmlns=\"jabber:client\" xmlns:db=\"jabber:server:dialback\""
		" from=\"%s\" id=\"%s\" xml:lang=\"en\" version=\"1.0\""
		" xmlns:stream=\"http://etherx.jabber.org/streams\"><stream:features>"
		"<mechanisms xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\"><mechanism>"
		"PLAIN</mechanism></mechanisms></stream:features>", rsession->from, rsession->id);
	int result = iks_send_raw(rsession->parser, header);
	switch_safe_free(header);
	return result;
}

/**
 * Handle <auth> message callback.  Only PLAIN supported.
 * @param user_data the Rayo session
 * @param pak the <auth> packet
 * @return IKS_FILTER_EAT
 */
static int on_auth(void *user_data, iks *node)
{
	struct rayo_session *rsession = (struct rayo_session *)user_data;
	char *xmlns, *mechanism;

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s, auth, state = %s\n", rsession->id, rayo_session_state_to_string(rsession->state));

	/* wrong state for authentication */
	if (rsession->state != SS_NEW) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "%s, auth UNEXPECTED, state = %s\n", rsession->id, rayo_session_state_to_string(rsession->state));
		/* TODO error */
		rsession->state = SS_ERROR;
		goto done;
	}

	/* unsupported authentication type */
	xmlns = soft_find_attrib(node, "xmlns");
	if (strcmp(IKS_NS_XMPP_SASL, xmlns)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "%s, auth, state = %s, unsupported namespace: %s!\n", rsession->id, rayo_session_state_to_string(rsession->state), xmlns);
		/* TODO error */
		rsession->state = SS_ERROR;
		goto done;
	}

	/* unsupported SASL authentication mechanism */
	mechanism = soft_find_attrib(node, "mechanism");
	if (strcmp("PLAIN", mechanism)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "%s, auth, state = %s, unsupported SASL mechanism: %s!\n", rsession->id, rayo_session_state_to_string(rsession->state), mechanism);
		rayo_send_auth_failure(rsession, "invalid-mechanism");
		rsession->state = SS_ERROR;
		goto done;
	}

	{
		/* get user and password from auth */
		char *body = iks_cdata(iks_child(node));
		char *jid = NULL, *user, *password;
		parse_plain_auth_body(body, &jid, &user, &password);
		if (is_correct_user_password(jid, password)) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s, auth, state = %s, SASL/PLAIN decoded = %s %s\n", rsession->id, rayo_session_state_to_string(rsession->state), jid, user);
			rayo_send_auth_success(rsession);
			rsession->state = SS_AUTHENTICATED;
		} else {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "%s, auth, state = %s, invalid user or password!\n", rsession->id, rayo_session_state_to_string(rsession->state));
			rayo_send_auth_failure(rsession, "not-authorized");
			rsession->state = SS_ERROR;
		}
		switch_safe_free(jid);
	}

  done:
	return IKS_FILTER_EAT;
}

#if 0
/**
 * Send <iq> result feature-not-implemented
 */
static int send_feature_not_implemented(struct rayo_session *rsession, char *from, char *to, char *id)
{
	char *reply = switch_mprintf(
		"<iq from=\"%s\" id=\"%s\" to=\"%s\" type=\"error\">"
		"%s<error type=\"cancel\"><feature-not-implemented "
		"xmlns=\"urn:ietf:params:xml:ns:xmpp-stanzas\"/>"
		"<text xml:lang=\"en\" xmlns=\"urn:ietf:params:xml:ns:xmpp-stanzas\">"
		"Feature not supported</text></error></iq>",
		rsession->from, rsession->to, command, id);
	iks_send_raw(rsession->parser, reply);
	switch_safe_free(reply);
	return result;
}
#endif

/**
 * Handle <iq> message callback
 * @param user_data the Rayo session 
 * @param pak the <iq> packet
 * @return IKS_FILTER_EAT
 */
static int on_command(void *user_data, ikspak *pak)
{
	struct rayo_session *rsession = (struct rayo_session *)user_data;
	iks *iq = pak->x;
	iks *command = iks_child(iq);
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s, iq, state = %s\n", rsession->id, rayo_session_state_to_string(rsession->state));
	if (!command) {
		/* TODO error */
		rsession->state = SS_ERROR;
	} else if (rsession->state == SS_AUTHENTICATED) {
		char *command_name = iks_name(command);
		/* looking for bind */
		if (!strcmp("bind", command_name)) {
			rsession->state = SS_RESOURCE_BOUND;
			/* TODO reply with JID */
		} else {
			/* TODO error */
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "%s, iq UNEXPECTED: %s, state = %s\n", rsession->id, command_name, rayo_session_state_to_string(rsession->state));
		}
	} else if (rsession->state == SS_RESOURCE_BOUND) {
		iks *command = iks_child(iq);
		char *command_name = iks_name(command);
		/* looking for session */
		if (!strcmp("session", command_name)) {
			rsession->state = SS_SESSION_ESTABLISHED;
			/* TODO reply */
		} else {
			/* TODO error */
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "%s, iq UNEXPECTED: %s, state = %s\n", rsession->id, command_name, rayo_session_state_to_string(rsession->state));
		}
	} else if (rsession->state == SS_SESSION_ESTABLISHED) {
		iks *command = iks_child(iq);
		char *command_name = iks_name(command);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "%s, iq UNSUPPORTED: %s, state = %s\n", rsession->id, command_name, rayo_session_state_to_string(rsession->state));
		/* TODO handle command */
	} else {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "%s, iq UNEXPECTED, state = %s\n", rsession->id, rayo_session_state_to_string(rsession->state));
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
				/* assign ID to this session and send reply */
				switch_uuid_str(rsession->id, sizeof(rsession->id));
				rsession->from = switch_core_strdup(rsession->pool, soft_find_attrib(node, "to"));
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
 * Handles Rayo XML stream
 */
static void *SWITCH_THREAD_FUNC rayo_session_thread(switch_thread_t *thread, void *obj)
{
	iksparser *parser;
	struct rayo_session *rsession = (struct rayo_session *)obj;
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "New connection\n");	
	
	/* set up XMPP stream parser */
	parser = iks_stream_new(IKS_NS_SERVER, rsession, on_stream);
	if (!parser) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to create XMPP stream parser!\n");
		goto done;
	}
	rsession->parser = parser;

	/* set up additional message callbacks */
	rsession->filter = iks_filter_new();
	iks_filter_add_rule(rsession->filter, on_presence, rsession,
		IKS_RULE_TYPE, IKS_PAK_PRESENCE,
		IKS_RULE_DONE);
	iks_filter_add_rule(rsession->filter, on_command, rsession,
		IKS_RULE_TYPE, IKS_PAK_IQ,
		IKS_RULE_SUBTYPE, IKS_TYPE_SET,
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
	
	while (!globals.shutdown && rsession->state != SS_ERROR) {
		iks_recv(parser, 1);
		/* TODO check errors, keep alive, figure out how to get events */
	}
	
  done:
  
	if (rsession->parser) {
		iks_disconnect(rsession->parser);
	}
	
	if (rsession->incoming) {
		switch_socket_shutdown(rsession->socket, SWITCH_SHUTDOWN_READWRITE);
		switch_socket_close(rsession->socket);
	}
	switch_core_destroy_memory_pool(&rsession->pool);
	
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Connection closed\n");
	return NULL;
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
			if (!(rsession = switch_core_alloc(pool, sizeof(*rsession)))) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Memory Error\n");
				switch_socket_shutdown(socket, SWITCH_SHUTDOWN_READWRITE);
				switch_socket_close(socket);
				switch_core_destroy_memory_pool(&pool);
				break;
			}
			strcpy(rsession->id, "(new)");
			rsession->pool = pool;
			rsession->socket = socket;
			rsession->incoming = 1;
			rsession->state = SS_NEW;
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

#define RAYO_USAGE ""
/**
 * Notify of new call and park channel
 */
SWITCH_STANDARD_APP(rayo_app)
{
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Offering call for Rayo control\n");
	/* TODO send offer */
	switch_ivr_park(session, NULL);
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
