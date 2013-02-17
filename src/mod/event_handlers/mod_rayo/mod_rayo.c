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

#define MAX_QUEUE_LEN 25000

#define RAYO_EVENT_XMPP_SEND "rayo::xmpp_send"
#define RAYO_EVENT_OFFER "rayo::offer"

#define RAYO_CAUSE_HANGUP "NORMAL_CLEARING"
#define RAYO_CAUSE_DECLINE "CALL_REJECTED"
#define RAYO_CAUSE_BUSY "USER_BUSY"
#define RAYO_CAUSE_ERROR "TEMPORARY_FAILURE"

#define RAYO_PRIVATE_VAR "_rayo_private"

typedef char * app_iks;

struct rayo_session;
struct rayo_call;

/** command handler function */
typedef void (*command_handler)(struct rayo_session *, struct rayo_call *, iks *);

/**
 * Function pointer wrapper for the handlers hash
 */
struct command_handler_wrapper {
	command_handler fn;
};

/**
 * Module state
 */
static struct {
	/** module memory pool */
	switch_memory_pool_t *pool;
	/** module shutdown flag */
	int shutdown;
	/** prevents module shutdown until all session/server threads are finished */
	switch_thread_rwlock_t *shutdown_rwlock;
	/** users mapped to passwords */
	switch_hash_t *users;
	/** XMPP <iq> set commands mapped to functions */
	switch_hash_t *command_handlers;
	/** XMPP <iq> set commands mapped to functions */
	switch_hash_t *rayo_command_handlers;
	/** map of DCP JID to session */
	switch_hash_t *client_routes;
	/** synchronizes access to routes */
	switch_mutex_t *client_routes_mutex;
	/** domain for calls/mixers/server/etc */
	char *domain;
} globals;

/**
 * A server listening for clients
 */
struct rayo_server {
	/** server socket memory pool */
	switch_memory_pool_t *pool;
	/** listen address */
	char *addr;
	/** listen port */
	switch_port_t port;
	/** listen socket */
	switch_socket_t *socket;
	/** pollset for listen socket */
	switch_pollfd_t *read_pollfd;
};

enum rayo_session_state {
	SS_NEW,
	SS_AUTHENTICATED,
	SS_RESOURCE_BOUND,
	SS_SESSION_ESTABLISHED,
	SS_ONLINE,
	SS_SHUTDOWN,
	SS_ERROR,
	SS_DESTROY
};

enum presence_status {
	PS_UNKNOWN = -1,
	PS_OFFLINE = 0,
	PS_ONLINE = 1
};

/**
 * A Rayo XML stream
 */
struct rayo_session {
	/** session pool */
	switch_memory_pool_t *pool;
	/** socket to client */
	switch_socket_t *socket;
	/** (this) server Jabber ID */
	char *server_jid;
	/** client Jabber ID */
	char *client_jid;
	/** client full Jabber ID */
	char *client_jid_full;
	/** 1 if this session started from direct client connection */
	int incoming;
	/** XML stream parser */
	iksparser *parser;
	/** XML stream filter (sets callbacks to <iq>, <presence>, etc). */
	iksfilter *filter;
	/** session ID */
	char id[SWITCH_UUID_FORMATTED_LENGTH + 1];
	/** session state */
	enum rayo_session_state state;
	/** event queue */
	switch_queue_t *event_queue;
};

/**
 * A call controlled by Rayo
 */
struct rayo_call {
	/** The session this call belongs to */
	switch_core_session_t *session;
	/** The call JID */
	char *jid;
	/** Definitive controlling party JID */
	char *dcp_jid;
	/** Potential controlling parties */
	switch_hash_t *pcps;
	/** synchronizes access to this call */
	switch_mutex_t *mutex;
	/** Active play ID */
	char *play_component_id;
};

/* See RFC-3920 XMPP core for error definitions */
typedef struct {
	const char *name;
	const char *type;
} stanza_error;
static const stanza_error STANZA_ERROR_BAD_REQUEST = { "bad-request", "modify" };
static const stanza_error STANZA_ERROR_CONFLICT = { "conflict", "cancel" };
static const stanza_error STANZA_ERROR_FEATURE_NOT_IMPLEMENTED = { "feature-not-implemented", "modify" };
static const stanza_error STANZA_ERROR_FORBIDDEN = { "forbidden", "auth" };
static const stanza_error STANZA_ERROR_GONE = { "gone", "modify" };
static const stanza_error STANZA_ERROR_INTERNAL_SERVER_ERROR = { "internal-server-error", "wait" };
static const stanza_error STANZA_ERROR_ITEM_NOT_FOUND = { "item-not-found", "cancel" };
static const stanza_error STANZA_ERROR_JID_MALFORMED = { "jid-malformed", "modify" };
static const stanza_error STANZA_ERROR_NOT_ACCEPTABLE = { "not-acceptable", "modify" };
static const stanza_error STANZA_ERROR_NOT_ALLOWED = { "not-allowed", "cancel" };
static const stanza_error STANZA_ERROR_NOT_AUTHORIZED = { "not-authorized", "auth" };
static const stanza_error STANZA_ERROR_RECIPIENT_UNAVAILABLE = { "recipient-unavailable", "wait" };
static const stanza_error STANZA_ERROR_REDIRECT = { "redirect", "modify" };
static const stanza_error STANZA_ERROR_REGISTRATION_REQUIRED = { "registration-required", "auth" };
static const stanza_error STANZA_ERROR_REMOTE_SERVER_NOT_FOUND = { "remote-server-not-found", "cancel" };
static const stanza_error STANZA_ERROR_REMOTE_SERVER_TIMEOUT = { "remote-server-timeout", "wait" };
static const stanza_error STANZA_ERROR_RESOURCE_CONSTRAINT = { "resource-constraint", "wait" };
static const stanza_error STANZA_ERROR_SERVICE_UNAVAILABLE = { "service-unavailable", "cancel" };
static const stanza_error STANZA_ERROR_UNDEFINED_CONDITION = { "undefined-condition", "wait" };
static const stanza_error STANZA_ERROR_UNEXPECTED_REQUEST = { "unexpected-request", "wait" };

#define create_iq_error(iq, from, to, error) _create_iq_error(iq, from, to, &error)

/**
 * Create <iq> error response from <iq> request
 * @param iq the <iq> get/set request
 * @param from
 * @param to
 * @param error the XMPP stanza error
 * @return the <iq> error response
 */
static iks *_create_iq_error(iks *iq, const char *from, const char *to, const stanza_error *error)
{
	iks *response = iks_copy(iq);
	iks *x;

	/* <iq> */
	iks_insert_attrib(response, "from", from);
	iks_insert_attrib(response, "to", to);
	iks_insert_attrib(response, "type", "error");

	/* <error> */
	x = iks_insert(response, "error");
	iks_insert_attrib(x, "type", error->type);

	/* e.g. <feature-not-implemented> */
	x = iks_insert(x, error->name);
	iks_insert_attrib(x, "xmlns", "urn:ietf:params:xml:ns:xmpp-stanzas");

	return response;
}

#define app_create_iq_error(iq, from, to, error) _app_create_iq_error(iq, from, to, &error)

/**
 * Create <iq> error response from <iq> request
 * @param iq the <iq> get/set request
 * @param from
 * @param to
 * @param error the XMPP stanza error
 * @return the <iq> error response
 */
static app_iks *_app_create_iq_error(switch_xml_t iq, const char *from, const char *to, const stanza_error *error)
{
	char *command = switch_xml_toxml(iq->child, SWITCH_FALSE);
	char *response = switch_mprintf(
		"<iq id='%s' from='%s' to='%s' type='error'>"
		"%s<error type='%s'>"
		"<%s xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>",
		switch_xml_attr_soft(iq, "id"),
		from,
		to,
		command,
		error->type,
		error->name);
	switch_safe_free(command);
	return (app_iks *)response;
}

/**
 * Send an XMPP message from a FreeSWITCH application thread
 * @param session the session
 * @param msg the message to send
 */
static void app_iks_send(switch_core_session_t *session, app_iks *msg)
{
	/* sends message to Rayo session via event */
	switch_event_t *event;
	if (switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, RAYO_EVENT_XMPP_SEND) == SWITCH_STATUS_SUCCESS) {
		switch_channel_event_set_data(switch_core_session_get_channel(session), event);
		switch_event_add_body(event, "%s", (char *)msg);
		switch_event_fire(&event);
	}
}

/**
 * Destroy the XMPP message
 * @param msg the message
 */
static void app_iks_delete(app_iks *msg)
{
	switch_safe_free(msg);
}

/**
 * Create <iq> result response
 * @param from
 * @param to
 * @param id
 * @return the result response
 */
static iks *create_iq_result(const char *from, const char *to, const char *id)
{
	iks *response = iks_new("iq");
	iks_insert_attrib(response, "from", from);
	iks_insert_attrib(response, "to", to);
	iks_insert_attrib(response, "type", "result");
	iks_insert_attrib(response, "id", id);
	return response;
}

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
		case SS_ONLINE: return "ONLINE";
		case SS_SHUTDOWN: return "SHUTDOWN";
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
 * Handle XMPP stream logging callback
 * @param user_data the Rayo session
 * @param data the log message
 * @param size of the log message
 * @param is_incoming true if this is a log for a received message
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
 * @param hash the hash to add to
 * @param name the command name
 * @param fn the command callback function
 */
static void add_command_handler(switch_hash_t *hash, const char *name, command_handler fn, switch_memory_pool_t *pool)
{
	/* have to wrap function pointer since conversion to void * is not allowed */
	struct command_handler_wrapper *wrapper = switch_core_alloc(pool, sizeof (*wrapper));
	wrapper->fn = fn;
	switch_core_hash_insert(hash, name, wrapper);
}

/**
 * Get command handler function from hash
 * @param hash the hash to search
 * @param name the command name
 * @param namespace the command namespace
 * @return the command handler function or NULL
 */
static command_handler get_command_handler(switch_hash_t *hash, const char *name, const char *namespace)
{
	struct command_handler_wrapper *wrapper = NULL;
	if (zstr(name)) {
		return NULL;
	}
	if (zstr(namespace)) {
		wrapper = (struct command_handler_wrapper *)switch_core_hash_find(hash, name);
	} else {
		char full_name[1024];
		full_name[1023] = '\0';
		snprintf(full_name, sizeof(full_name) - 1, "%s:%s", namespace, name);
		wrapper = (struct command_handler_wrapper *)switch_core_hash_find(hash, full_name);
	}
	if (wrapper) {
		return wrapper->fn;
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
 * Parse the resource from a JID
 * @param jid the full Jabber ID
 * @param buf the buffer to store the resource
 * @param size the buffer size
 * @return the resource, or NULL if resource isn't found or is too large for buffer
 */
static char *parse_resource_from_jid(const char *jid, char *buf, int size)
{
	if (size > 0 && !zstr(jid)) {
		char *tok = strstr(jid, "/");
		if (tok && *(++tok)) {
			if (strlen(tok) < size - 1) {
				strncpy(buf, tok, size);
				return buf;
			}
		}
	}
	return NULL;
}

/**
 * Get exclusive access to Rayo call data.
 * @param call_uuid the FreeSWITCH call UUID
 * @return the call or NULL.  Call rayo_call_unlock() when done with call pointer.
 */
static struct rayo_call *rayo_call_locate(const char *call_uuid)
{
	struct rayo_call *call = NULL;
	switch_core_session_t *session = switch_core_session_locate(call_uuid);
	if (session) {
		call = (struct rayo_call *)switch_channel_get_private(switch_core_session_get_channel(session), RAYO_PRIVATE_VAR);
		if (call) {
			switch_mutex_lock(call->mutex);
		} else {
			switch_core_session_rwunlock(session);
		}
	}
	return call;
}

/**
 * Get exclusive access to Rayo call data.
 * @param call_jid the call JID
 * @return the call or NULL.  Call rayo_call_unlock() when done with call pointer.
 */
static struct rayo_call *rayo_call_locate_from_jid(const char *call_jid)
{
	char call_uuid[SWITCH_UUID_FORMATTED_LENGTH + 1];
	call_uuid[SWITCH_UUID_FORMATTED_LENGTH] = '\0';
	if (!zstr(call_jid) && strstr(call_jid, "@")) {
		char *tok;
		strncpy(call_uuid, call_jid, sizeof(call_uuid) - sizeof(char));
		tok = strstr(call_uuid, "@");
		if (tok) {
			*tok = '\0';
		}
		return rayo_call_locate(call_uuid);
	}
	return NULL;
}

/**
 * Unlock Rayo call.
 */
static void rayo_call_unlock(struct rayo_call *call)
{
	if (call) {
		switch_core_session_rwunlock(call->session);
		switch_mutex_unlock(call->mutex);
	}
}

/**
 * Send bind + session reply to Rayo client <stream>
 * @param rsession the Rayo session to use
 * @return the error code
 */
static int rayo_send_header_bind(struct rayo_session *rsession)
{
	char *header = switch_mprintf(
		"<stream:stream xmlns='"IKS_NS_CLIENT"' xmlns:db='jabber:server:dialback'"
		" from='%s' id='%s' xml:lang='en' version='1.0'"
		" xmlns:stream='http://etherx.jabber.org/streams'><stream:features>"
		"<bind xmlns='"IKS_NS_XMPP_BIND"'/>"
		"<session xmlns='"IKS_NS_XMPP_SESSION"'/>"
		"</stream:features>", rsession->server_jid, rsession->id);

	int result = iks_send_raw(rsession->parser, header);
	switch_safe_free(header);
	return result;
}

/**
 * Check if session has control of offered call. Take control if nobody does.
 * @param rsession the Rayo session
 * @param call the Rayo call
 * @param call_jid the call JID
 * @param call_uuid the internal call UUID
 * @return 1 if session has call control
 */
static int rayo_session_has_call_control(struct rayo_session *rsession, struct rayo_call *call)
{
	int control = 0;

	if (zstr(rsession->client_jid_full)) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(call->session), SWITCH_LOG_CRIT, "Null client JID!!\n");
		return 0;
	}

	/* nobody in charge */
	if (zstr(call->dcp_jid)) {
		/* was offered to this session? */
		if (switch_core_hash_find(call->pcps, rsession->client_jid_full)) {
			/* take charge */
			call->dcp_jid = switch_core_session_strdup(call->session, rsession->client_jid_full);
			switch_channel_set_variable(switch_core_session_get_channel(call->session), "rayo_dcp_jid", call->dcp_jid);
			control = 1;
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(call->session), SWITCH_LOG_INFO, "%s has control of call\n", call->dcp_jid);
		}
	} else if (!strcmp(call->dcp_jid, rsession->client_jid_full)) {
		control = 1;
	}

	if (!control) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(call->session), SWITCH_LOG_INFO, "%s does not have control of call\n", rsession->client_jid_full);
	}

	return control;
}

/**
 * Check Rayo command for errors.
 * @param rsession the Rayo session
 * @param call the Rayo call
 * @param node the <iq> node
 * @return error response or NULL if OK
 */
static int rayo_session_command_ok(struct rayo_session *rsession, struct rayo_call *call, iks *node)
{
	iks *response = NULL;
	char *from = iks_find_attrib(node, "from");
	char *to = iks_find_attrib(node, "to");
	int bad = zstr(to) || zstr(iks_find_attrib(node, "id"));

	/* set if missing in request */
	from = zstr(from) ? rsession->client_jid_full : from;
	to = zstr(to) ? rsession->server_jid : to;

	if (bad) {
		response = create_iq_error(node, to, from, STANZA_ERROR_BAD_REQUEST);
	} else if (rsession->state == SS_NEW) {
		response = create_iq_error(node, to, from, STANZA_ERROR_NOT_AUTHORIZED);
	} else if (!call) {
		response = create_iq_error(node, to, from, STANZA_ERROR_ITEM_NOT_FOUND);
	} else if (rsession->state != SS_ONLINE) {
		response = create_iq_error(node, to, from, STANZA_ERROR_UNEXPECTED_REQUEST);
	} else if (!rayo_session_has_call_control(rsession, call)) {
		response = create_iq_error(node, to, from, STANZA_ERROR_CONFLICT);
	}

	if (response) {
		iks_send(rsession->parser, response);
		iks_delete(response);
		return 0;
	}
	return 1;
}

/**
 * Handle <iq><accept> request
 * @param rsession the Rayo session
 * @param call the Rayo call
 * @param node the <iq> node
 */
static void on_rayo_accept(struct rayo_session *rsession, struct rayo_call *call, iks *node)
{
	/* if we get this far, session has control of the call */
	iks *response = create_iq_result(call->jid, call->dcp_jid, iks_find_attrib(node, "id"));
	iks_send(rsession->parser, response);
	iks_delete(response);
}

/**
 * Handle <iq><answer> request
 * @param rsession the Rayo session
 * @param call the Rayo call
 * @param node the <iq> node
 */
static void on_rayo_answer(struct rayo_session *rsession, struct rayo_call *call, iks *node)
{
	iks *response = NULL;
	/* TODO set signaling headers */
	/* send answer to call */
	if (switch_core_session_execute_application_async(call->session, "answer", "") == SWITCH_STATUS_SUCCESS) {
		response = create_iq_result(call->jid, call->dcp_jid, iks_find_attrib(node, "id"));
	} else {
		response = create_iq_error(node, call->jid, call->dcp_jid, STANZA_ERROR_INTERNAL_SERVER_ERROR);
	}
	iks_send(rsession->parser, response);
	iks_delete(response);
}

/**
 * Handle <iq><redirect> request
 * @param rsession the Rayo session
 * @param call the Rayo call
 * @param node the <iq> node
 */
static void on_rayo_redirect(struct rayo_session *rsession, struct rayo_call *call, iks *node)
{
	iks *response = NULL;
	iks *redirect = iks_find(node, "redirect");
	char *redirect_to = iks_find_attrib(redirect, "to");

	if (zstr(redirect_to)) {
		response = create_iq_error(node, call->jid, call->dcp_jid, STANZA_ERROR_BAD_REQUEST);
	} else {
		/* TODO set signaling headers */
		/* send redirect to call */
		if (switch_core_session_execute_application_async(call->session, "redirect", redirect_to) == SWITCH_STATUS_SUCCESS) {
			response = create_iq_result(call->jid, call->dcp_jid, iks_find_attrib(node, "id"));
		} else {
			response = create_iq_error(node, call->jid, call->dcp_jid, STANZA_ERROR_INTERNAL_SERVER_ERROR);
		}
	}
	iks_send(rsession->parser, response);
	iks_delete(response);
}

/**
 * Handle <iq><hangup> or <iq><reject> request
 * @param rsession the Rayo session
 * @param call the Rayo call
 * @param node the <iq> node
 */
static void on_rayo_hangup(struct rayo_session *rsession, struct rayo_call *call, iks *node)
{
	iks *response = NULL;
	iks *hangup = iks_child(node);
	iks *reason = iks_child(hangup);
	char *hangup_cause = NULL;

	/* get hangup cause */
	if (!reason && !strcmp("hangup", iks_name(hangup))) {
		/* no reason required in <hangup> */
		hangup_cause = RAYO_CAUSE_HANGUP;
	} else if (reason && !strcmp("reject", iks_name(hangup))) {
		char *reason_name = iks_name(reason);
		/* reason required for <reject> */
		if (!strcmp("busy", reason_name)) {
			hangup_cause = RAYO_CAUSE_BUSY;
		} else if (!strcmp("decline", reason_name)) {
			hangup_cause = RAYO_CAUSE_DECLINE;
		} else if (!strcmp("error", reason_name)) {
			hangup_cause = RAYO_CAUSE_ERROR;
		}
	}

	/* do hangup */
	if (!zstr(hangup_cause)) {
		/* TODO set signaling headers */
		if (switch_core_session_execute_application_async(call->session, "hangup", hangup_cause) == SWITCH_STATUS_SUCCESS) {
			response = create_iq_result(call->jid, call->dcp_jid, iks_find_attrib(node, "id"));
		} else {
			response = create_iq_error(node, call->jid, call->dcp_jid, STANZA_ERROR_INTERNAL_SERVER_ERROR);
		}
	} else {
		response = create_iq_error(node, call->jid, call->dcp_jid, STANZA_ERROR_BAD_REQUEST);
	}

	iks_send(rsession->parser, response);
	iks_delete(response);
}

/**
 * Handle <iq><stop> request
 * @param rsession the Rayo session
 * @param call the Rayo call
 * @param node the <iq> node
 */
static void on_rayo_stop(struct rayo_session *rsession, struct rayo_call *call, iks *node)
{
	char *to = iks_find_attrib(node, "to");
	char resource_buf[SWITCH_UUID_FORMATTED_LENGTH + 1];
	char *resource = parse_resource_from_jid(to, resource_buf, SWITCH_UUID_FORMATTED_LENGTH + 1);
	iks *response = NULL;
	if (zstr(resource)) {
		response = create_iq_error(node, to, call->dcp_jid, STANZA_ERROR_BAD_REQUEST);
	} else {
		/* TODO implement */
		response = create_iq_error(node, to, call->dcp_jid, STANZA_ERROR_FEATURE_NOT_IMPLEMENTED);
	}
	iks_send(rsession->parser, response);
	iks_delete(response);
}

/**
 * Handle Rayo Play (input/output/prompt) Component request
 * @param rsession the Rayo session
 * @param call the Rayo call
 * @param node the <iq> node
 */
static void on_rayo_play_component(struct rayo_session *rsession, struct rayo_call *call, iks *node)
{
	char *play = iks_string(NULL, node);
	/* forward document to call thread by executing custom application */
	if (!play || switch_core_session_execute_application_async(call->session, "rayo_play", play) != SWITCH_STATUS_SUCCESS) {
		iks *response = create_iq_error(node, call->jid, call->dcp_jid, STANZA_ERROR_INTERNAL_SERVER_ERROR);
		iks_send(rsession->parser, response);
		iks_delete(response);
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(call->session), SWITCH_LOG_INFO, "Failed to execute rayo_play!\n");
	}
	if (play) {
		iks_free(play);
	}
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
	char *type = iks_find_attrib(node, "type");
	enum presence_status status = PS_UNKNOWN;

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s, presence, state = %s\n", rsession->id, rayo_session_state_to_string(rsession->state));

	/*
	   From RFC-6121:
	   Entity is available when <presence/> received.
	   Entity is unavailable when <presence type='unavailable'/> is received.

	   From Rayo-XEP:
	   Entity is available when <presence to='foo' from='bar'><show>chat</show></presence> is received.
	   Entity is unavailable when <presence to='foo' from='bar'><show>dnd</show></presence> is received.
	*/

	/* figure out if online/offline */
	if (zstr(type)) {
		iks *show = iks_find(node, "show");
		if (show) {
			/* <presence><show>chat</show></presence> */
			char *status_str = iks_cdata(iks_child(show));
			if (!zstr(status_str) && !strcmp("chat", status_str)) {
				status = PS_ONLINE;
			} else {
				status = PS_OFFLINE;
			}
		} else {
			/* <presence/> */
			status = PS_ONLINE;
		}
	} else if (!strcmp("unavailable", type)) {
		status = PS_OFFLINE;
	} else if (!strcmp("error", type)) {
		/* TODO */
	} else if (!strcmp("probe", type)) {
		/* TODO */
	} else if (!strcmp("subscribe", type)) {
		/* TODO */
	} else if (!strcmp("subscribed", type)) {
		/* TODO */
	} else if (!strcmp("unsubscribe", type)) {
		/* TODO */
	} else if (!strcmp("unsubscribed", type)) {
		/* TODO */
	}

	if (status == PS_ONLINE && rsession->state == SS_SESSION_ESTABLISHED) {
		rsession->state = SS_ONLINE;
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s, %s is ONLINE\n", rsession->id, rsession->client_jid_full);
	} else if (status == PS_OFFLINE && rsession->state == SS_ONLINE) {
		rsession->state = SS_SESSION_ESTABLISHED;
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s, %s is OFFLINE\n", rsession->id, rsession->client_jid_full);
	}

	return IKS_FILTER_EAT;
}

/**
 * Handle <iq><ping> request
 * @param rsession the Rayo session
 * @param call unused
 * @param node the <iq> node
 */
static void on_iq_set_xmpp_ping(struct rayo_session *rsession, struct rayo_call *call, iks *node)
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
 * @param rsession the Rayo session
 * @param call unused
 * @param node the <iq> node
 */
static void on_iq_set_xmpp_session(struct rayo_session *rsession, struct rayo_call *call, iks *node)
{
	iks *reply;

	switch(rsession->state) {
	case SS_NEW:
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "%s, iq UNEXPECTED <session>, state = %s\n", rsession->id, rayo_session_state_to_string(rsession->state));
		reply = create_iq_error(node, rsession->server_jid, rsession->client_jid_full, STANZA_ERROR_NOT_AUTHORIZED);
		break;

	case SS_AUTHENTICATED:
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "%s, iq UNEXPECTED <session>, state = %s\n", rsession->id, rayo_session_state_to_string(rsession->state));
		reply = create_iq_error(node, rsession->server_jid, rsession->client_jid_full, STANZA_ERROR_UNEXPECTED_REQUEST);
		break;

	case SS_RESOURCE_BOUND:
		reply = iks_new("iq");
		iks_insert_attrib(reply, "type", "result");
		iks_insert_attrib(reply, "from", rsession->server_jid);
		iks_insert_attrib(reply, "to", rsession->client_jid_full);
		iks_insert_attrib(reply, "id", iks_find_attrib(node, "id"));
		rsession->state = SS_SESSION_ESTABLISHED;
		break;

	case SS_SESSION_ESTABLISHED:
	case SS_ONLINE:
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "%s, iq UNEXPECTED <session>, state = %s\n", rsession->id, rayo_session_state_to_string(rsession->state));
		reply = create_iq_error(node, rsession->server_jid, rsession->client_jid_full, STANZA_ERROR_UNEXPECTED_REQUEST);
		break;

	default:
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "%s, iq UNEXPECTED <session>, state = %s\n", rsession->id, rayo_session_state_to_string(rsession->state));
		reply = create_iq_error(node, rsession->server_jid, rsession->client_jid_full, STANZA_ERROR_SERVICE_UNAVAILABLE);
		break;
	}

	iks_send(rsession->parser, reply);
	iks_delete(reply);
}

/**
 * Handle <iq><bind> request
 * @param rsession the Rayo session
 * @param call unused
 * @param node the <iq> node
 */
static void on_iq_set_xmpp_bind(struct rayo_session *rsession, struct rayo_call *call, iks *node)
{
	iks *reply;

	switch(rsession->state) {
	case SS_AUTHENTICATED: {
		iks *bind = iks_find(node, "bind");
		iks *resource = iks_find(bind, "resource");
		iks *x;
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
		rsession->client_jid_full = switch_core_sprintf(rsession->pool, "%s/%s", rsession->client_jid, resource_id);

		/* create reply */
		reply = iks_new("iq");
		iks_insert_attrib(reply, "type", "result");
		iks_insert_attrib(reply, "id", iks_find_attrib(node, "id"));

		x = iks_insert(reply, "bind");
		iks_insert_attrib(x, "xmlns", IKS_NS_XMPP_BIND);
		iks_insert_cdata(iks_insert(x, "jid"), rsession->client_jid_full, strlen(rsession->client_jid_full));

		rsession->state = SS_RESOURCE_BOUND;

		/* remember route to client */
		switch_mutex_lock(globals.client_routes_mutex);
		switch_core_hash_insert(globals.client_routes, rsession->client_jid_full, rsession);
		switch_mutex_unlock(globals.client_routes_mutex);
		break;
	}
	case SS_RESOURCE_BOUND:
	case SS_ONLINE:
		/* already bound a single resource */
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "%s, iq UNEXPECTED <bind>, state = %s\n", rsession->id, rayo_session_state_to_string(rsession->state));
		reply = create_iq_error(node, rsession->server_jid, rsession->client_jid_full, STANZA_ERROR_NOT_ALLOWED);
		break;

	case SS_NEW:
		/* new */
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "%s, iq UNEXPECTED <bind>, state = %s\n", rsession->id, rayo_session_state_to_string(rsession->state));
		reply = create_iq_error(node, rsession->server_jid, rsession->client_jid_full, STANZA_ERROR_NOT_AUTHORIZED);
		break;

	default:
		/* shutdown/error/destroy */
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "%s, iq UNEXPECTED <bind>, state = %s\n", rsession->id, rayo_session_state_to_string(rsession->state));
		reply = create_iq_error(node, rsession->server_jid, rsession->client_jid_full, STANZA_ERROR_SERVICE_UNAVAILABLE);
		break;
	}

	iks_send(rsession->parser, reply);
	iks_delete(reply);
}

/**
 * Handle <iq> get requests
 * @param user_data the Rayo session
 * @param node the <iq> node
 * @return IKS_FILTER_EAT
 */
static int on_iq_get(void *user_data, ikspak *pak)
{
	struct rayo_session *rsession = (struct rayo_session *)user_data;
	iks *node = pak->x;
	iks *response = create_iq_error(node, rsession->server_jid, rsession->client_jid_full, STANZA_ERROR_FEATURE_NOT_IMPLEMENTED);
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
	return iks_send_raw(rsession->parser, "<success xmlns='"IKS_NS_XMPP_SASL"'/>");
}

/**
 * Send <failure> reply to Rayo client <auth>
 * @param rsession the Rayo session to use.
 * @param reason the reason for failure
 */
static int rayo_send_auth_failure(struct rayo_session *rsession, const char *reason)
{
	int result;
	char *reply = switch_mprintf("<failure xmlns='"IKS_NS_XMPP_SASL"'>"
		"<%s/></failure>", reason);
	result = iks_send_raw(rsession->parser, reply);
	return result;
}

/**
 * Parse authzid, authcid, and password tokens from base64 PLAIN auth message.
 * @param message the base-64 encoded authentication message
 * @param authzid the authorization id in the message - free this string when done with parsed message
 * @param authcid the authentication id in the message
 * @param password the password in the message
 */
static void parse_plain_auth_message(const char *message, char **authzid, char **authcid, char **password)
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
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "authzid = %s\n", *authzid);
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
 * @return 1 if authenticated
 */
static int verify_plain_auth(const char *authzid, const char *authcid, const char *password)
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
		"<stream:stream xmlns='"IKS_NS_CLIENT"' xmlns:db='jabber:server:dialback'"
		" from='%s' id='%s' xml:lang='en' version='1.0'"
		" xmlns:stream='http://etherx.jabber.org/streams'><stream:features>"
		"<mechanisms xmlns='"IKS_NS_XMPP_SASL"'><mechanism>"
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
	int handled = 0;
	struct rayo_session *rsession = (struct rayo_session *)user_data;
	iks *iq = pak->x;
	iks *command = iks_child(iq);

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s, iq, state = %s\n", rsession->id, rayo_session_state_to_string(rsession->state));

	if (command) {
		command_handler fn = NULL;

		/* is this a Rayo command? */
		fn = get_command_handler(globals.rayo_command_handlers, iks_name(command), iks_find_attrib(command, "xmlns"));
		if (fn) {
			struct rayo_call *call = rayo_call_locate_from_jid(iks_find_attrib(iq, "to"));
			if (rayo_session_command_ok(rsession, call, iq)) {
				fn(rsession, call, iq);
				handled = 1;
			}
			rayo_call_unlock(call);
		} else { /* is this an XMPP command? */
			fn = get_command_handler(globals.command_handlers, iks_name(command), iks_find_attrib(command, "xmlns"));
			if (fn) {
				fn(rsession, NULL, iq);
				handled = 1;
			}
		}
	}

	if (!handled) {
		char *from = iks_find_attrib(iq, "to");
		char *to = iks_find_attrib(iq, "from");
		iks *reply;
		from = zstr(from) ? rsession->server_jid : from;
		to = zstr(to) ? rsession->client_jid_full : to;
		reply = create_iq_error(iq, from, to, STANZA_ERROR_FEATURE_NOT_IMPLEMENTED);
	}

	return IKS_FILTER_EAT;
}

/**
 * Handle XML stream callback
 * @param user_data the Rayo session
 * @param type stream type (start/normal/stop/etc)
 * @param node optional XML node
 * @return IKS_OK
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
		} else if (rsession->state == SS_SHUTDOWN) {
			/* strange... I expect IKS_NODE_STOP, this is a workaround. */
			rsession->state = SS_DESTROY;
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
		if (rsession->state != SS_SHUTDOWN) {
			iks_send_raw(rsession->parser, "</stream:stream>");
		}
		rsession->state = SS_DESTROY;
		break;
	}

	if (pak) {
		iks_filter_packet(rsession->filter, pak);
	}

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
 * Receives events from FreeSWITCH core and routes them to the proper Rayo session.
 * @param event received from FreeSWITCH core.  It will be destroyed by the core after this function returns.
 */
static void route_call_event(switch_event_t *event)
{
	char *uuid = switch_event_get_header(event, "unique-id");
	char *dcp_jid = switch_event_get_header(event, "variable_rayo_dcp_jid");
	char *event_subclass = switch_event_get_header(event, "Event-Subclass");

	switch_log_printf(SWITCH_CHANNEL_UUID_LOG(uuid), SWITCH_LOG_DEBUG, "got event %s %s\n", switch_event_name(event->event_id), zstr(event_subclass) ? "" : event_subclass);

	/* this event is for a rayo call */
	if (!zstr(dcp_jid)) {
		struct rayo_session *rsession;
		switch_log_printf(SWITCH_CHANNEL_UUID_LOG(uuid), SWITCH_LOG_DEBUG, "%s call event %s\n", dcp_jid, switch_event_name(event->event_id));

		/* find session that is connected to client */
		switch_mutex_lock(globals.client_routes_mutex);
		rsession = (struct rayo_session *)switch_core_hash_find(globals.client_routes, dcp_jid);
		if (rsession) {
			/* send event to session */
			switch_event_t *dup_event = NULL;
			switch_event_dup(&dup_event, event);
			if (switch_queue_trypush(rsession->event_queue, dup_event) != SWITCH_STATUS_SUCCESS) {
				switch_log_printf(SWITCH_CHANNEL_UUID_LOG(uuid), SWITCH_LOG_CRIT, "failed to deliver call event to %s!\n", dcp_jid);
				switch_event_destroy(&dup_event);
			}
		} else {
			/* TODO orphaned call... maybe allow events to queue so they can be delivered on reconnect? */
			switch_log_printf(SWITCH_CHANNEL_UUID_LOG(uuid), SWITCH_LOG_DEBUG, "Orphaned call event %s to %s\n", switch_event_name(event->event_id), dcp_jid);
		}
		switch_mutex_unlock(globals.client_routes_mutex);
	}
}

/**
 * Create a Rayo <presence> event
 * @param name the event name
 * @param namespace the event namespace
 * @param from
 * @param to
 * @return the event XML node
 */
static iks* create_rayo_event(const char *name, const char *namespace, const char *from, const char *to)
{
	iks *event = iks_new("presence");
	iks *x;
	/* iks makes copies of attrib name and value */
	iks_insert_attrib(event, "from", from);
	iks_insert_attrib(event, "to", to);
	x = iks_insert(event, name);
	if (!zstr(namespace)) {
		iks_insert_attrib(x, "xmlns", namespace);
	}
	return event;
}

/**
 * Handle Rayo offer event
 * @param rsession the Rayo session
 * @param event the offer event
 */
static void on_rayo_offer_event(struct rayo_session *rsession, switch_event_t *event)
{
	char *event_str;
	iks *revent, *offer;

	switch_event_serialize(event, &event_str, SWITCH_FALSE);
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s\n", event_str);

	/* TODO add headers */

	/* send offer to client */
	revent = create_rayo_event("offer", "urn:xmpp:rayo:1",
		switch_event_get_header(event, "variable_rayo_call_jid"),
		rsession->client_jid_full);
	offer = iks_child(revent);
	iks_insert_attrib(offer, "to", switch_event_get_header(event, "Caller-Destination-Number"));
	iks_insert_attrib(offer, "from", switch_event_get_header(event, "Caller-Caller-ID-Number"));
	iks_send(rsession->parser, revent);
	iks_delete(revent);
}

/**
 * Handle call hangup event
 * @param rsession the Rayo session
 * @param event the hangup event
 */
static void on_call_hangup_event(struct rayo_session *rsession, switch_event_t *event)
{
	iks *revent = create_rayo_event("end", "urn:xmpp:rayo:1",
		switch_event_get_header(event, "variable_rayo_call_jid"),
		switch_event_get_header(event, "variable_rayo_dcp_jid"));
	iks *end = iks_find(revent, "end");
	iks_insert(end, "hangup");
	iks_send(rsession->parser, revent);
	iks_delete(revent);
}

/**
 * Handle call answer event
 * @param rsession the Rayo session
 * @param event the answer event
 */
static void on_call_answer_event(struct rayo_session *rsession, switch_event_t *event)
{
	iks *revent = create_rayo_event("answered", "urn:xmpp:rayo:1",
		switch_event_get_header(event, "variable_rayo_call_jid"),
		switch_event_get_header(event, "variable_rayo_dcp_jid"));
	iks_send(rsession->parser, revent);
	iks_delete(revent);
}

/**
 * Handle call ringing event
 * @param rsession the Rayo session
 * @param event the ringing event
 */
static void on_call_ringing_event(struct rayo_session *rsession, switch_event_t *event)
{
	iks *revent = create_rayo_event("ringing", "urn:xmpp:rayo:1",
		switch_event_get_header(event, "variable_rayo_call_jid"),
		switch_event_get_header(event, "variable_rayo_dcp_jid"));
	iks_send(rsession->parser, revent);
	iks_delete(revent);
}

/**
 * Handle events delivered to this session
 * @param rsession the Rayo session to handle the event
 * @param event the event.  This event must be destroyed by this function.
 */
static void rayo_session_handle_event(struct rayo_session *rsession, switch_event_t *event)
{
	if (event) {
		switch (event->event_id) {
		case SWITCH_EVENT_CHANNEL_HANGUP:
			on_call_hangup_event(rsession, event);
		case SWITCH_EVENT_CHANNEL_PROGRESS_MEDIA:
		case SWITCH_EVENT_CHANNEL_PROGRESS:
			on_call_ringing_event(rsession, event);
			break;
		case SWITCH_EVENT_CHANNEL_ANSWER:
			on_call_answer_event(rsession, event);
			break;
		case SWITCH_EVENT_CUSTOM: {
			char *event_subclass = switch_event_get_header(event, "Event-Subclass");
			if (!strcmp(RAYO_EVENT_XMPP_SEND, event_subclass)) {
				/* send raw XMPP message from FS */
				char *msg = switch_event_get_body(event);
				iks_send_raw(rsession->parser, msg);
			} else if (!strcmp(RAYO_EVENT_OFFER, event_subclass)) {
				on_rayo_offer_event(rsession, event);
			}
			/* else don't care */
			break;
		}
		default:
			/* don't care */
			break;
		}
		switch_event_destroy(&event);
	}
}

/**
 * Cleanup the session
 * @param rsession the session
 */
static void rayo_session_destroy(struct rayo_session *rsession)
{
	void *queue_item = NULL;

	rsession->state = SS_DESTROY;

	/* remove session from map */
	switch_mutex_lock(globals.client_routes_mutex);
	switch_core_hash_delete(globals.client_routes, rsession->client_jid_full);
	switch_mutex_unlock(globals.client_routes_mutex);

	/* flush pending events */
	while (switch_queue_trypop(rsession->event_queue, &queue_item) == SWITCH_STATUS_SUCCESS) {
		switch_event_t *event = (switch_event_t *)queue_item;
		rayo_session_handle_event(rsession, event);
	}

	/* close connection */
	if (rsession->parser) {
		iks_disconnect(rsession->parser);
	}

	if (rsession->incoming) {
		switch_socket_shutdown(rsession->socket, SWITCH_SHUTDOWN_READWRITE);
		switch_socket_close(rsession->socket);
	}

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s Session destroyed\n", rsession->id);

	switch_core_destroy_memory_pool(&rsession->pool);
}

/**
 * Thread that handles Rayo XML stream
 * @param thread this thread
 * @param obj the Rayo session
 * @return NULL
 */
static void *SWITCH_THREAD_FUNC rayo_session_thread(switch_thread_t *thread, void *obj)
{
	iksparser *parser;
	struct rayo_session *rsession = (struct rayo_session *)obj;
	switch_pollfd_t *read_pollfd = NULL;
	int err_count = 0;

	switch_thread_rwlock_rdlock(globals.shutdown_rwlock);

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
		/* make outbound connection */
		/* TODO */
	}

	/* set up pollfd to monitor listen socket */
	if (switch_socket_create_pollset(&read_pollfd, rsession->socket, SWITCH_POLLIN | SWITCH_POLLERR, rsession->pool) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s, create pollset error!\n", rsession->id);
		goto done;
	}

	while (rayo_session_ready(rsession)) {
		void *queue_item;

		/* read any messages from client */
		int result = iks_recv(parser, 0);
		switch (result) {
		case IKS_OK:
			err_count = 0;
			break;
		case IKS_NET_RWERR:
		case IKS_NET_NOCONN:
		case IKS_NET_NOSOCK:
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "%s iks_recv() error = %s, ending session\n", rsession->id, net_error_to_string(result));
			rsession->state = SS_ERROR;
			goto done;
		default:
			if (err_count++ == 0) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "%s iks_recv() error = %s\n", rsession->id, net_error_to_string(result));
			}
			if (err_count >= 50) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "%s too many iks_recv() error = %s, ending session\n", rsession->id, net_error_to_string(result));
				rsession->state = SS_ERROR;
				goto done;
			}
		}

		/* wait up to 20ms for any FreeSWITCH events */
		if (switch_queue_pop_timeout(rsession->event_queue, &queue_item, 20 * 1000) == SWITCH_STATUS_SUCCESS) {
			switch_event_t *event = (switch_event_t *)queue_item;
			rayo_session_handle_event(rsession, event);

			/* handle all queued events */
			while (switch_queue_trypop(rsession->event_queue, &queue_item) == SWITCH_STATUS_SUCCESS) {
				event = (switch_event_t *)queue_item;
				rayo_session_handle_event(rsession, event);
			}
		}

		/* check for shutdown */
		if (rsession->state != SS_DESTROY && globals.shutdown && rsession->state != SS_SHUTDOWN) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "%s detected shutdown\n", rsession->id);
			iks_send_raw(rsession->parser, "</stream:stream>");
			rsession->state = SS_SHUTDOWN;
		}
	}

  done:

	rayo_session_destroy(rsession);
	switch_thread_rwlock_unlock(globals.shutdown_rwlock);

	return NULL;
}

/**
 * Create a new Rayo session
 * @param pool the memory pool for this session
 * @param socket the socket for this session
 * @param incoming 1 if this session was created by a direct client connection
 * @return the new session or NULL
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
	switch_queue_create(&rsession->event_queue, MAX_QUEUE_LEN, pool);

	return rsession;
}

/**
 * Thread that listens for new Rayo client connections
 * @param thread this thread
 * @param obj the Rayo server
 * @return NULL
 */
static void *SWITCH_THREAD_FUNC rayo_server_thread(switch_thread_t *thread, void *obj)
{
	struct rayo_server *server = (struct rayo_server *)obj;
	switch_memory_pool_t *pool = NULL;
	uint32_t errs = 0;

	switch_thread_rwlock_rdlock(globals.shutdown_rwlock);

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

		rv = switch_socket_create_pollset(&server->read_pollfd, server->socket, SWITCH_POLLIN | SWITCH_POLLERR, server->pool);
		if (rv) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Create pollset for server socket %s:%u error!\n", server->addr, server->port);
			goto sock_fail;
		}

		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Rayo server listening on %s:%u\n", server->addr, server->port);

		break;
   sock_fail:
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Socket Error! Rayo server could not listen on %s:%u\n", server->addr, server->port);
		switch_yield(100000);
	}

	/* Listen for XMPP client connections */
	while (!globals.shutdown) {
		switch_socket_t *socket = NULL;
		switch_status_t rv;
		int32_t fdr;

		if (pool == NULL && switch_core_new_memory_pool(&pool) != SWITCH_STATUS_SUCCESS) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Failed to create memory pool for new client connection!\n");
			goto fail;
		}

		/* is there a new connection? */
		rv = switch_poll(server->read_pollfd, 1, &fdr, 1000 * 1000 /* 1000 ms */);
		if (rv != SWITCH_STATUS_SUCCESS) {
			continue;
		}

		/* accept the connection */
		if ((rv = switch_socket_accept(&socket, server->socket, pool))) {
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
				break;
			}
			pool = NULL; /* session now owns the pool */
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

	if (pool) {
		switch_core_destroy_memory_pool(&pool);
	}

fail:
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Rayo server %s:%u thread done\n", server->addr, server->port);
	switch_thread_rwlock_unlock(globals.shutdown_rwlock);
	return NULL;
}

/**
 * Add a new server to listen for Rayo client connections.
 * @param addr the IP address
 * @param port the port
 * @return SWITCH_STATUS_SUCCESS if successful
 */
static switch_status_t add_rayo_server(const char *addr, const char *port)
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
 * @return SWITCH_STATUS_SUCCESS on successful configuration
 */
static switch_status_t do_config(switch_memory_pool_t *pool)
{
	char *cf = "rayo.conf";
	switch_xml_t cfg, xml;
	switch_status_t status = SWITCH_STATUS_SUCCESS;

	switch_thread_rwlock_rdlock(globals.shutdown_rwlock);

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
				const char *var = switch_xml_attr_soft(param, "name");
				const char *val = switch_xml_attr_soft(param, "value");
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "param: %s = %s\n", var, val);
				if (!strcasecmp(var, "foo")) {
					/* TODO remove */
				} else {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "Unsupported param: %s\n", var);
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
				switch_core_hash_insert(globals.users, user, switch_core_strdup(pool, password));
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
				} else if (zstr(globals.domain)) {
					/* first successful listener is domain... TODO rework this */
					globals.domain = switch_core_strdup(pool, val);
				}
			}
		}
	}

	switch_xml_free(xml);

	switch_thread_rwlock_unlock(globals.shutdown_rwlock);

	return status;
}

/**
 * Offer a call to a Rayo session
 * @param rsession the session
 * @param call the call
 * @return SWITCH_STATUS_SUCCESS if the session has been offered
 */
static switch_status_t rayo_session_offer_call(struct rayo_session *rsession, struct rayo_call *call)
{
	switch_event_t* offer_event = NULL;

	/* TODO check if session can be destroyed while this is happening */
	/* send offer event to session */
	switch_event_create_subclass(&offer_event, SWITCH_EVENT_CUSTOM, RAYO_EVENT_OFFER);
	switch_channel_event_set_data(switch_core_session_get_channel(call->session), offer_event);
	switch_core_hash_insert(call->pcps, rsession->client_jid_full, "1");
	if (switch_queue_trypush(rsession->event_queue, offer_event) == SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(call->session), SWITCH_LOG_INFO, "Offered call to %s\n", rsession->client_jid_full);
		return SWITCH_STATUS_SUCCESS;
	}

	switch_core_hash_delete(call->pcps, rsession->client_jid_full);
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(call->session), SWITCH_LOG_INFO, "Failed to queue call offer event to %s!\n", rsession->client_jid_full);
	switch_event_destroy(&offer_event);
	return SWITCH_STATUS_FALSE;
}

#define app_send_iq_error(session, iq, error) _app_send_iq_error(session, iq, &error)

/**
 * Send IQ error to controlling client from call
 * @param session the session that detected the error
 * @param iq the request that caused the error
 * @param error the error message
 */
static void _app_send_iq_error(switch_core_session_t *session, switch_xml_t iq, const stanza_error *error)
{
	switch_channel_t *channel = switch_core_session_get_channel(session);
	app_iks *response = _app_create_iq_error(iq, switch_channel_get_variable(channel, "rayo_call_jid"),
											 switch_channel_get_variable(channel, "rayo_dcp_jid"), error);
	app_iks_send(session, response);
	app_iks_delete(response);
}

typedef switch_bool_t (*validation_function)(const char *, const char **);

static switch_bool_t is_bool(const char *val, const char **test_name) {
	*test_name = "is_bool";
	return !zstr(val) && (!strcasecmp("true", val) || !strcasecmp("false", val));
}

static switch_bool_t is_not_negative(const char *val, const char **test_name) {
	*test_name = "is_not_negative";
	return !zstr(val) && switch_is_number(val) && atoi(val) >= 0;
}

static switch_bool_t is_positive_or_neg_one(const char *val, const char **test_name) {
	*test_name = "is_positive_or_neg_one";
	if (!zstr(val) && switch_is_number(val)) {
		int v = atoi(val);
		if (v == -1 || v > 0) {
			return SWITCH_TRUE;
		}
	}
	return SWITCH_FALSE;
}

/**
 * Search node for attribute, returning default if not set
 * @param node the XML node to search
 * @param attrib the attribute to find
 * @param default_value the value to return if attribute is not set
 * @param value the value
 * @param fn (optional) validation function
 * @return SWITCH_TRUE if valid
 */
static switch_bool_t get_param(switch_core_session_t *session, switch_xml_t node, const char *attrib, const char *default_value, const char **value, validation_function fn)
{
	const char *test_name = NULL;
	*value = switch_xml_attr(node, attrib);
	*value = zstr(*value) ? default_value : *value;
	if (fn) {
		if (!fn(*value, &test_name)) {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "<%s %s='%s'> !%s\n", switch_xml_name(node), attrib, *value, test_name);
		} else {
			return SWITCH_TRUE;
		}
	} else {
		return SWITCH_TRUE;
	}
	return SWITCH_FALSE;
}

/**
 * @param node the XML node to search
 * @param attrib the attribute to find
 * @param default_value the value to return if attribute is not set
 * @param value the value
 * @param fn (optional) validation function
 * @return SWITCH_TRUE if valid
 */
static switch_bool_t get_int_param(switch_core_session_t *session, switch_xml_t node, const char *attrib, const char *default_value, int *value, validation_function fn)
{
	const char *value_str = NULL;
	if (get_param(session, node, attrib, default_value, &value_str, fn)) {
		*value = atoi(value_str);
		return SWITCH_TRUE;
	}
	return SWITCH_FALSE;
}

/**
 * @param node the XML node to search
 * @param attrib the attribute to find
 * @param default_value the value to return if attribute is not set
 * @param value the value
 * @param fn (optional) validation function
 * @return SWITCH_TRUE if valid
 */
static switch_bool_t get_bool_param(switch_core_session_t *session, switch_xml_t node, const char *attrib, const char *default_value, switch_bool_t *value)
{
	const char *value_str = NULL;
	if (get_param(session, node, attrib, default_value, &value_str, is_bool)) {
		*value = switch_true(value_str);
		return SWITCH_TRUE;
	}
	return SWITCH_FALSE;
}

/**
 * <output> component params
 */
struct output_params {
	/** Offset through which the output should be skipped */
	int start_offset;
	/** Should component start paused? */
	switch_bool_t start_paused;
	/** Duration of silence between repeats */
	int repeat_interval;
	/** Number of times to play */
	int repeat_times;
	/** Maximum amount of time output should be run */
	int max_time;
	/** renderer */
	const char *renderer;
};

/**
 * Parse params from <output>
 * @param output the output component
 * @param params the output params
 * @return SWITCH_STATUS_SUCCESS if the params are valid
 */
static switch_status_t parse_output_params(switch_core_session_t *session, switch_xml_t output, struct output_params *params)
{
	if (get_int_param(session, output, "start-offset", "0", &params->start_offset, is_not_negative) &&
		get_bool_param(session, output, "start-paused", "false", &params->start_paused) &&
		get_int_param(session, output, "repeat-interval", "0", &params->repeat_interval, is_not_negative) &&
		get_int_param(session, output, "max-time", "-1", &params->max_time, is_positive_or_neg_one) &&
		get_param(session, output, "renderer", "", &params->renderer, NULL)) {
		return SWITCH_STATUS_SUCCESS;
	}
	return SWITCH_STATUS_FALSE;
}

#define RAYO_PLAY_USAGE ""
/**
 * Process input/output/prompt component
 */
SWITCH_STANDARD_APP(rayo_play_app)
{
	switch_xml_t iq, output;
	switch_channel_t *channel = switch_core_session_get_channel(session);
	const char *dcp_jid = switch_channel_get_variable(channel, "rayo_dcp_jid");
	char *iq_str = switch_core_session_strdup(session, data);
	char *command;
	struct output_params oparams = { 0 };

	if (zstr(dcp_jid)) {
		/* shouldn't happen if APP was executed by this module */
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "No Rayo client controlling this session!\n");
		return;
	}

	if (zstr(iq_str)) {
		/* shouldn't happen if APP was executed by this module */
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Missing args!\n");
		/* can't send iq error- no <iq> request! */
		return;
	}

	iq = switch_xml_parse_str(iq_str, strlen(iq_str));
	if (!iq) {
		/* shouldn't happen if APP was executed by this module */
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Bad request!\n");
		/* can't send iq error- no <iq> request! */
		return;
	}

	if (!iq->child) {
		/* shouldn't happen if APP was executed by this module */
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Bad request!\n");
		app_send_iq_error(session, iq, STANZA_ERROR_BAD_REQUEST);
		return;
	}

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Got command: %s\n", data);

	command = switch_xml_name(iq->child);
	if (!strcmp("prompt", command)) {
		output = switch_xml_child(iq->child, "output");
		/* TODO input */
	} else if (!strcmp("output", command)) {
		output = iq->child;
	} else if (!strcmp("input", command)) {
		/* TODO input */
		app_send_iq_error(session, iq, STANZA_ERROR_FEATURE_NOT_IMPLEMENTED);
		return;
	} else {
		app_send_iq_error(session, iq, STANZA_ERROR_FEATURE_NOT_IMPLEMENTED);
		return;
	}

	/* validate output params */
	if (parse_output_params(session, output, &oparams) != SWITCH_STATUS_SUCCESS) {
		app_send_iq_error(session, iq, STANZA_ERROR_BAD_REQUEST);
	} else {
		app_send_iq_error(session, iq, STANZA_ERROR_FEATURE_NOT_IMPLEMENTED);
	}
}

/**
 * Create Rayo call
 * @param session
 * @return the call
 */
static struct rayo_call *rayo_call_create(switch_core_session_t *session)
{
	switch_channel_t *channel = switch_core_session_get_channel(session);
	struct rayo_call *call = switch_core_session_alloc(session, sizeof(*call));
	call->session = session;
	call->jid = switch_core_session_sprintf(session, "%s@%s", switch_core_session_get_uuid(session), globals.domain);
	call->dcp_jid = "";
	switch_core_hash_init(&call->pcps, switch_core_session_get_pool(session));
	switch_mutex_init(&call->mutex, SWITCH_MUTEX_UNNESTED, switch_core_session_get_pool(session));
	switch_channel_set_private(channel, RAYO_PRIVATE_VAR, call);
	switch_channel_set_variable(channel, "rayo_call_jid", call->jid); /* tags events with JID */
	return call;
}

#define RAYO_USAGE ""
/**
 * Offer call and park channel
 */
SWITCH_STANDARD_APP(rayo_app)
{
	switch_channel_t *channel = switch_core_session_get_channel(session);
	switch_hash_index_t *hi = NULL;
	int offered = 0;
	struct rayo_call *call = switch_channel_get_private(channel, RAYO_PRIVATE_VAR);
	if (call) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "Call has already been offered!\n");
		goto done;
	}

	call = rayo_call_create(session);

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Offering call for Rayo 3PCC\n");

	/* Offer call to all ONLINE clients */
	/* TODO load balance this so first session doesn't always get request first? */
	switch_mutex_lock(globals.client_routes_mutex);
	for (hi = switch_hash_first(NULL, globals.client_routes); hi; hi = switch_hash_next(hi)) {
		struct rayo_session *rsession;
		const void *key;
		void *val;
		switch_hash_this(hi, &key, NULL, &val);
		rsession = (struct rayo_session *)val;
		switch_assert(rsession);

		/* is session available to take call? */
		if (rsession->state == SS_ONLINE) {
			offered |= (rayo_session_offer_call(rsession, call) == SWITCH_STATUS_SUCCESS);
		}
	}
	switch_mutex_unlock(globals.client_routes_mutex);

done:

	if (offered) {
		switch_ivr_park(session, NULL);
	} else {
		switch_channel_hangup(switch_core_session_get_channel(session), SWITCH_CAUSE_CALL_REJECTED);
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
	switch_thread_rwlock_create(&globals.shutdown_rwlock, pool);
	switch_core_hash_init(&globals.users, pool);
	switch_core_hash_init(&globals.command_handlers, pool);
	switch_core_hash_init(&globals.rayo_command_handlers, pool);
	switch_core_hash_init(&globals.client_routes, pool);
	switch_mutex_init(&globals.client_routes_mutex, SWITCH_MUTEX_UNNESTED, pool);

	/* XMPP commands */
	add_command_handler(globals.command_handlers, IKS_NS_XMPP_BIND":bind", on_iq_set_xmpp_bind, globals.pool);
	add_command_handler(globals.command_handlers, IKS_NS_XMPP_SESSION":session", on_iq_set_xmpp_session, globals.pool);
	add_command_handler(globals.command_handlers, "urn:xmpp:ping:ping", on_iq_set_xmpp_ping, globals.pool);

	/* Rayo call commands */
	add_command_handler(globals.rayo_command_handlers, "urn:xmpp:rayo:1:accept", on_rayo_accept, globals.pool);
	add_command_handler(globals.rayo_command_handlers, "urn:xmpp:rayo:1:answer", on_rayo_answer, globals.pool);
	add_command_handler(globals.rayo_command_handlers, "urn:xmpp:rayo:1:redirect", on_rayo_redirect, globals.pool);
	add_command_handler(globals.rayo_command_handlers, "urn:xmpp:rayo:1:reject", on_rayo_hangup, globals.pool); /* handles both reject and hangup */
	add_command_handler(globals.rayo_command_handlers, "urn:xmpp:rayo:1:hangup", on_rayo_hangup, globals.pool); /* handles both reject and hangup */
	add_command_handler(globals.rayo_command_handlers, "urn:xmpp:rayo:ext:1:stop", on_rayo_stop, globals.pool);
	add_command_handler(globals.rayo_command_handlers, "urn:xmpp:rayo:output:1:output", on_rayo_play_component, globals.pool);
	add_command_handler(globals.rayo_command_handlers, "urn:xmpp:rayo:input:1:input", on_rayo_play_component, globals.pool);
	add_command_handler(globals.rayo_command_handlers, "urn:xmpp:rayo:prompt:1:prompt", on_rayo_play_component, globals.pool);

	switch_event_bind(modname, SWITCH_EVENT_CHANNEL_PROGRESS_MEDIA, NULL, route_call_event, NULL);
	switch_event_bind(modname, SWITCH_EVENT_CHANNEL_PROGRESS, NULL, route_call_event, NULL);
	switch_event_bind(modname, SWITCH_EVENT_CHANNEL_ANSWER, NULL, route_call_event, NULL);
	switch_event_bind(modname, SWITCH_EVENT_CHANNEL_HANGUP, NULL, route_call_event, NULL);
	switch_event_bind(modname, SWITCH_EVENT_CUSTOM, RAYO_EVENT_OFFER, route_call_event, NULL);
	switch_event_bind(modname, SWITCH_EVENT_CUSTOM, RAYO_EVENT_XMPP_SEND, route_call_event, NULL);

	SWITCH_ADD_APP(app_interface, "rayo", "Offer call control to Rayo client(s)", "", rayo_app, RAYO_USAGE, SAF_SUPPORT_NOMEDIA);
	SWITCH_ADD_APP(app_interface, "rayo_play", "Execute Rayo output/input/prompt component (internal module use only)", "", rayo_play_app, RAYO_PLAY_USAGE, 0);

	/* configure / open sockets */
	if(do_config(globals.pool) != SWITCH_STATUS_SUCCESS) {
		return SWITCH_STATUS_TERM;
	}

	return SWITCH_STATUS_SUCCESS;
}

/**
 * Shutdown module.  Notifies threads to stop.
 */
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_rayo_shutdown)
{
	/* notify threads to stop */
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Notifying of shutdown\n");
	globals.shutdown = 1;

	/* wait for threads to finish */
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Waiting for server and session threads to stop\n");
	switch_thread_rwlock_wrlock(globals.shutdown_rwlock);

	/* cleanup module */
	switch_event_unbind_callback(route_call_event);

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Module shutdown\n");

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
