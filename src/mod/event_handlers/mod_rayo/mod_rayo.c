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

#define RAYO_EVENT_OFFER "rayo::offer"

#define RAYO_CAUSE_HANGUP SWITCH_CAUSE_NORMAL_CLEARING
#define RAYO_CAUSE_DECLINE SWITCH_CAUSE_CALL_REJECTED
#define RAYO_CAUSE_BUSY SWITCH_CAUSE_USER_BUSY
#define RAYO_CAUSE_ERROR SWITCH_CAUSE_NORMAL_TEMPORARY_FAILURE

struct rayo_session;

/** A command handler function */
typedef void (*iq_set_command_handler_fn)(struct rayo_session *, iks *);

/**
 * Function pointer wrapper for the command handlers hash
 */
struct iq_set_command_handler {
	iq_set_command_handler_fn fn;
};

/**
 * Module state
 */
static struct {
	/** module memory pool */
	switch_memory_pool_t *pool;
	/** module shutdown flag */
	int shutdown;
	/** prevents module shutdown until all sessions/servers are finished */
	switch_thread_rwlock_t *shutdown_rwlock;
	/** users mapped to passwords */
	switch_hash_t *users;
	/** <iq> set commands mapped to functions */
	switch_hash_t *iq_set_command_handlers;
	/** map of call uuid to client full JID */
	switch_hash_t *calls;
	/** synchronizes access to calls hash */
	switch_mutex_t *calls_mutex;
	/** map of client full JID to session */
	switch_hash_t *sessions;
	/** synchronizes access to sessions hash */
	switch_mutex_t *sessions_mutex;
	/** handle to event bind */
    switch_event_node_t *node;
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
	/** resource part of full Jabber ID */
	char *client_resource_id;
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
	/** number of active calls */
	int active_calls_count;
	/** active calls controlled by this session */
	switch_hash_t *active_calls;
	/** calls offered by this session */
	switch_hash_t *offered_calls;
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
static iks *_create_iq_error(iks *iq, char *from, char *to, const stanza_error *error)
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
 * Check if session has control of offered call.  If not, take control
 * if nobody else has control.
 * @param rsession the Rayo session
 * @param call_jid the call JID
 * @return 1 if session has call control
 */
static int has_call_control(struct rayo_session *rsession, char *call_jid)
{
	int control = 0;
	char *uuid = switch_core_hash_find(rsession->active_calls, call_jid);
	if (!zstr(uuid)) {
		/* already have control */
		return 1;
	} 
	uuid = switch_core_hash_find(rsession->offered_calls, call_jid);
	if (!zstr(uuid)) {
		char *client_jid_full;
		/* does anybody own this call? */
		switch_mutex_lock(globals.calls_mutex);
		client_jid_full = (char *)switch_core_hash_find(globals.calls, uuid);
		if (zstr(client_jid_full)) {
			/* take control */
			switch_core_hash_insert(globals.calls, uuid, strdup(call_jid));
			switch_core_hash_delete(rsession->active_calls, call_jid);
			switch_core_hash_insert(rsession->active_calls, call_jid, uuid);
			rsession->active_calls_count++;
			control = 1;
		} else if (!strcmp(client_jid_full, rsession->client_jid_full)) {
			/* already have control... remove from offered calls */
			switch_core_hash_delete(rsession->active_calls, call_jid);
			switch_core_hash_insert(rsession->active_calls, call_jid, uuid);
			rsession->active_calls_count++;
			control = 1;
		}
		switch_mutex_unlock(globals.calls_mutex);
	}
	
	if (control) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "%s, Rayo client %s has control of call %s\n", rsession->id, rsession->client_jid_full, call_jid);
	} else {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "%s, Rayo client %s does not have control of call %s\n", rsession->id, rsession->client_jid_full, call_jid);
	}
	
	return control;
}

/**
 * Parse Rayo <iq> request and check for errors
 * @param rsession the Rayo session
 * @param node the <iq> node
 * @param call_jid the parsed to attribute
 * @param client_jid the parsed from attribute
 * @return error response or NULL if OK
 */
static iks *parse_rayo_request(struct rayo_session *rsession, iks *node, char **call_jid, char **client_jid, char **id)
{
	iks *response = NULL;
	
	*call_jid = iks_find_attrib(node, "to");
	*client_jid = iks_find_attrib(node, "from");
	*id = iks_find_attrib(node, "id");
	
	if (zstr(*client_jid)) {
		*client_jid = rsession->client_jid_full;
	}
	
	/* check if request is well formed, session is in the right state, and session has control of the call */
	if (zstr(*call_jid)) {
		response = create_iq_error(node, rsession->server_jid, *client_jid, STANZA_ERROR_BAD_REQUEST);
	} else if (rsession->state == SS_NEW) {
		response = create_iq_error(node, *call_jid, *client_jid, STANZA_ERROR_NOT_AUTHORIZED);
	} else if (zstr(*id)) {
		response = create_iq_error(node, *call_jid, *client_jid, STANZA_ERROR_BAD_REQUEST);
	} else if (rsession->state != SS_ONLINE) {
		response = create_iq_error(node, *call_jid, *client_jid, STANZA_ERROR_UNEXPECTED_REQUEST);
	} else if (!has_call_control(rsession, *call_jid)) {
		response = create_iq_error(node, *call_jid, *client_jid, STANZA_ERROR_CONFLICT);
	}

	return response;
}

/**
 * Handle <iq><accept> request
 * @param rsession the Rayo session
 * @param node the <iq> node
 */
static void on_iq_set_rayo_accept(struct rayo_session *rsession, iks *node)
{
	char *call_jid, *client_jid, *id;
	iks *response = parse_rayo_request(rsession, node, &call_jid, &client_jid, &id);
	if (!response) {
		/* all good */
		response = iks_new("iq");
		iks_insert_attrib(response, "to", client_jid);
		iks_insert_attrib(response, "from", call_jid);
		iks_insert_attrib(response, "type", "result");
		iks_insert_attrib(response, "id", id);
	}
	iks_send(rsession->parser, response);
	iks_delete(response);
}

/**
 * Handle <iq><answer> request
 * @param rsession the Rayo session
 * @param node the <iq> node
 */
static void on_iq_set_rayo_answer(struct rayo_session *rsession, iks *node)
{
}

/**
 * Handle <iq><redirect> request
 * @param rsession the Rayo session
 * @param node the <iq> node
 */
static void on_iq_set_rayo_redirect(struct rayo_session *rsession, iks *node)
{
}

/**
 * Handle <iq><reject> request
 * @param rsession the Rayo session
 * @param node the <iq> node
 */
static void on_iq_set_rayo_reject(struct rayo_session *rsession, iks *node)
{
}

/**
 * Handle <iq><hangup> request
 * @param rsession the Rayo session
 * @param node the <iq> node
 */
static void on_iq_set_rayo_hangup(struct rayo_session *rsession, iks *node)
{
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
			if (!zstr(status_str) && !strcmp("show", status_str)) {
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
 * @param rsession the Rayo session
 * @param node the <iq> node
 */
static void on_iq_set_xmpp_session(struct rayo_session *rsession, iks *node)
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
 * @param node the <iq> node
 */
static void on_iq_set_xmpp_bind(struct rayo_session *rsession, iks *node)
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
		rsession->client_resource_id = resource_id;
		rsession->client_jid_full = switch_core_sprintf(rsession->pool, "%s/%s", rsession->client_jid, rsession->client_resource_id);

		/* create reply */
		reply = iks_new("iq");	
		iks_insert_attrib(reply, "type", "result");
		iks_insert_attrib(reply, "id", iks_find_attrib(node, "id"));

		x = iks_insert(reply, "bind");
		iks_insert_attrib(x, "xmlns", IKS_NS_XMPP_BIND);
		iks_insert_cdata(iks_insert(x, "jid"), rsession->client_jid_full, strlen(rsession->client_jid_full));

		rsession->state = SS_RESOURCE_BOUND;
		
		/* map resource to session */
		switch_mutex_lock(globals.sessions_mutex);
		switch_core_hash_insert(globals.sessions, rsession->client_jid_full, rsession);
		switch_mutex_unlock(globals.sessions_mutex);
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
		/* no handlers */
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
static void handle_event(switch_event_t *event)
{
	char *uuid = switch_event_get_header(event, "unique-id");
	if (!zstr(uuid)) {
		/* is a client interested in this event? */
		char *client_jid_full;
		switch_mutex_lock(globals.calls_mutex);
		client_jid_full = (char *)switch_core_hash_find(globals.calls, uuid);
		switch_mutex_unlock(globals.calls_mutex);
		if (!zstr(client_jid_full)) {
			struct rayo_session *rsession;
			/* find session that is connected to client */
			switch_mutex_lock(globals.sessions_mutex);
			rsession = (struct rayo_session *)switch_core_hash_find(globals.sessions, client_jid_full);
			if (rsession) {
				/* send event to session */
				switch_event_t *dup_event = NULL;
				switch_event_dup(&dup_event, event);
				if (switch_queue_trypush(rsession->event_queue, dup_event) != SWITCH_STATUS_SUCCESS) {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "%s, failed to deliver event!\n", rsession->id);
					switch_event_destroy(&dup_event);
				}
			} else {
				/* TODO orphaned call... maybe allow events to queue so they can be delivered on reconnect? */
			}
			switch_mutex_unlock(globals.sessions_mutex);
		}
	}
}

/**
 * Create a Rayo call JID
 * @param rsession the Rayo session
 * @param uuid the call UUID
 * @return the call JID  (must be freed)
 */
static char *create_rayo_call_jid(struct rayo_session *rsession, char *uuid)
{
	return switch_mprintf("%s@%s", uuid, rsession->server_jid);
}

/**
 * Create a Rayo <presence> event
 * @param rsession the Rayo session
 * @param name the event name
 * @param namespace the event namespace
 * @param uuid the FreeSWITCH call UUID
 * @return the event XML node
 */
static iks* create_rayo_event(struct rayo_session *rsession, char *name, char *namespace, char *from)
{
	iks *event = iks_new("presence");
	iks *x;
	/* iks makes copies of attrib name and value */
	iks_insert_attrib(event, "from", from);
	iks_insert_attrib(event, "to", rsession->client_jid_full);
	x = iks_insert(event, name);
	if (!zstr(namespace)) {
		iks_insert_attrib(x, "xmlns", namespace);
	}
	return event;
}

/**
 * Handle Rayo offer event from rayo APP
 * @param rsession the Rayo session
 * @param event the offer event
 */
static void on_rayo_offer_event(struct rayo_session *rsession, switch_event_t *event)
{
	int offered = 0;
	char *uuid = switch_event_get_header(event, "unique-id");
	switch_core_session_t *session = switch_core_session_locate(uuid);
	if (rsession->state == SS_ONLINE && session) {
		switch_channel_t *channel = switch_core_session_get_channel(session);
		switch_caller_profile_t *caller_profile = switch_channel_get_caller_profile(channel);
		iks *revent, *offer;
		char *to = switch_mprintf("tel:%s", caller_profile->destination_number);
		char *from = switch_mprintf("tel:%s", caller_profile->caller_id_number);
		char *call_jid = create_rayo_call_jid(rsession, uuid);

		/* map call JID to FreeSWITCH call UUID */
		switch_core_hash_insert(rsession->offered_calls, call_jid, uuid);

		/* send offer to client */
		revent = create_rayo_event(rsession, "offer", "urn:xmpp:rayo:1", call_jid);
		offer = iks_child(revent);
		iks_insert_attrib(offer, "to", to);
		iks_insert_attrib(offer, "from", from);
		iks_send(rsession->parser, revent);
		iks_delete(revent);
		switch_safe_free(to);
		switch_safe_free(from);
	}
	if (!offered) {
		/* TODO decline call */
	}
	if (session) {
		switch_core_session_rwunlock(session);
	}
}

/**
 * Handle events delivered to this session
 * @param rsession the Rayo session to handle the event
 * @param event the event.  This event must be destroyed by this function.
 */
static void rayo_session_handle_event(struct rayo_session *rsession, switch_event_t *event)
{
	if (event) {
		char *event_text = NULL;
		if (switch_event_serialize(event, &event_text, SWITCH_FALSE) == SWITCH_STATUS_SUCCESS) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s, got event: %s\n", rsession->id, event_text);
		}
		
		switch (event->event_id) {
			case SWITCH_EVENT_CUSTOM: {
				char *event_subclass = switch_event_get_header(event, "Event-Subclass");
				if (!strcasecmp(RAYO_EVENT_OFFER, event_subclass)) {
					/* handle offer */
					on_rayo_offer_event(rsession, event);
				}
				/* else don't care */
				break;
			}
			default:
				/* don't care */
				break;
		}
		
		switch_safe_free(event_text);
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
	switch_mutex_lock(globals.sessions_mutex);
	switch_core_hash_delete(globals.sessions, rsession->client_jid_full);
	switch_mutex_unlock(globals.sessions_mutex);

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
			break;
		default:
			if (err_count++ == 0) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "%s iks_recv() error = %s\n", rsession->id, net_error_to_string(result));
			}
			if (err_count >= 50) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "%s too many iks_recv() error = %s, ending session\n", rsession->id, net_error_to_string(result));
				rsession->state = SS_ERROR;
			}
			break;
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
	rsession->client_resource_id = "";
	switch_core_hash_init(&rsession->active_calls, pool);
	switch_core_hash_init(&rsession->offered_calls, pool);
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
				}
			}
		}
	}

	switch_xml_free(xml);

	switch_thread_rwlock_unlock(globals.shutdown_rwlock);
	
	return status;
}

/**
 * Offer a call for Rayo 3PCC
 * @param session_uuid call UUID
 * @return SWITCH_STATUS_SUCCESS on success
 */
static switch_status_t offer_call(char *session_uuid)
{
	switch_hash_index_t *hi = NULL;
	int offered = 0;
	
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Offering call %s for Rayo 3PCC\n", session_uuid);

	/* Offer call to all ONLINE sessions */
	/* TODO load balance this so first session doesn't always get request first? */
	switch_mutex_lock(globals.sessions_mutex);
	for (hi = switch_hash_first(NULL, globals.sessions); hi; hi = switch_hash_next(hi)) {
		struct rayo_session *rsession;
		switch_event_t* offer_event = NULL;
		const void *key;
		void *val;
		switch_hash_this(hi, &key, NULL, &val);
		rsession = (struct rayo_session *)val;
		switch_assert(rsession);
		
		/* is session available to take call? */
		if (rsession->state != SS_ONLINE) {
			continue;
		}
		
		/* send offer event to session */
		switch_event_create_subclass(&offer_event, SWITCH_EVENT_CUSTOM, RAYO_EVENT_OFFER);
		switch_event_add_header_string(offer_event, SWITCH_STACK_BOTTOM, "unique-id", session_uuid);
		if (switch_queue_trypush(rsession->event_queue, offer_event) == SWITCH_STATUS_SUCCESS) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "%s Offered call to session %s, %s\n", session_uuid, rsession->id, rsession->client_jid_full);
			offered = 1;
		} else  {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "%s Failed to queue call offer event to %s, %s!\n", session_uuid, rsession->id, rsession->client_jid_full);
			switch_event_destroy(&offer_event);
		}
	}
	switch_mutex_unlock(globals.sessions_mutex);

	return offered ? SWITCH_STATUS_SUCCESS : SWITCH_STATUS_FALSE;
}

#define RAYO_USAGE ""
/**
 * Offer call and park channel
 */
SWITCH_STANDARD_APP(rayo_app)
{
	if (offer_call(switch_core_session_get_uuid(session)) == SWITCH_STATUS_SUCCESS) {
		switch_ivr_park(session, NULL);
	} else {
		switch_channel_hangup(switch_core_session_get_channel(session), RAYO_CAUSE_DECLINE);
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
	switch_core_hash_init(&globals.iq_set_command_handlers, pool);
	switch_core_hash_init(&globals.calls, pool);
	switch_mutex_init(&globals.calls_mutex, SWITCH_MUTEX_UNNESTED, pool);
	switch_core_hash_init(&globals.sessions, pool);
	switch_mutex_init(&globals.sessions_mutex, SWITCH_MUTEX_UNNESTED, pool);
	
	/* XMPP commands */
	add_iq_set_command_handler(IKS_NS_XMPP_BIND":bind", on_iq_set_xmpp_bind);
	add_iq_set_command_handler(IKS_NS_XMPP_SESSION":session", on_iq_set_xmpp_session);
	add_iq_set_command_handler("urn:xmpp:ping:ping", on_iq_set_xmpp_ping);
	
	/* Rayo call commands */
	add_iq_set_command_handler("urn:xmpp:rayo:1:accept", on_iq_set_rayo_accept);
	add_iq_set_command_handler("urn:xmpp:rayo:1:answer", on_iq_set_rayo_answer);
	add_iq_set_command_handler("urn:xmpp:rayo:1:redirect", on_iq_set_rayo_redirect);
	add_iq_set_command_handler("urn:xmpp:rayo:1:reject", on_iq_set_rayo_reject);
	add_iq_set_command_handler("urn:xmpp:rayo:1:hangup", on_iq_set_rayo_hangup);

	/* set up core event handler */
	if (switch_event_bind_removable(modname, SWITCH_EVENT_ALL, SWITCH_EVENT_SUBCLASS_ANY, handle_event, NULL, &globals.node) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Couldn't bind to events!\n");
		return SWITCH_STATUS_GENERR;
	}

	SWITCH_ADD_APP(app_interface, "rayo", "Offer call control to Rayo client(s)", "", rayo_app, RAYO_USAGE, SAF_SUPPORT_NOMEDIA);
	
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
	switch_event_unbind(&globals.node);

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
