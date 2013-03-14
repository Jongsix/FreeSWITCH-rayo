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

#include "mod_rayo.h"
#include "rayo_components.h"
#include "iks_helpers.h"
#include "sasl.h"

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_rayo_shutdown);
SWITCH_MODULE_LOAD_FUNCTION(mod_rayo_load);
SWITCH_MODULE_DEFINITION(mod_rayo, mod_rayo_load, mod_rayo_shutdown, NULL);

#define MAX_QUEUE_LEN 25000

#define RAYO_EVENT_XMPP_SEND "rayo::xmpp_send"

#define RAYO_CAUSE_HANGUP SWITCH_CAUSE_NORMAL_CLEARING
#define RAYO_CAUSE_DECLINE SWITCH_CAUSE_CALL_REJECTED
#define RAYO_CAUSE_BUSY SWITCH_CAUSE_USER_BUSY
#define RAYO_CAUSE_ERROR SWITCH_CAUSE_NORMAL_TEMPORARY_FAILURE

#define RAYO_END_REASON_HANGUP "hangup"
#define RAYO_END_REASON_ERROR "error"
#define RAYO_END_REASON_BUSY "busy"
#define RAYO_END_REASON_REJECT "reject"
#define RAYO_END_REASON_TIMEOUT "timeout"

#define RAYO_SIP_REQUEST_HEADER "sip_r_"
#define RAYO_SIP_RESPONSE_HEADER "sip_rh_"
#define RAYO_SIP_PROVISIONAL_RESPONSE_HEADER "sip_ph_"
#define RAYO_SIP_BYE_RESPONSE_HEADER "sip_bye_h_"

struct rayo_session;
struct rayo_call;

/**
 * A rayo actor - this is an entity that can be controlled by a rayo client
 */
struct rayo_actor {
	/** Type of actor */
	enum rayo_actor_type type;
	/** Sub-type of actor */
	char *subtype;
	/** Internal ID */
	char *id;
	/** actor JID */
	char *jid;
	/** Actor pool */
	switch_memory_pool_t *pool;
	/** synchronizes access to this actor */
	switch_mutex_t *mutex;
	/** an atomically incrementing sequence for this actor */
	int seq;
	/** Actor data */
	void *data;
	/** number of users of this actor */
	int ref_count;
	/** destroy flag */
	int destroy;
};

typedef void (*rayo_server_command_handler)(struct rayo_session *, iks *);

/**
 * Function pointer wrapper for the handlers hash
 */
struct rayo_command_handler {
	enum rayo_actor_type type;
	const char *subtype;
	union {
		rayo_server_command_handler server;
		rayo_call_command_handler call;
		rayo_mixer_command_handler mixer;
		rayo_component_command_handler component;
	} fn;
};

/**
 * A server listening for clients
 */
struct rayo_server {
	/** base actor */
	struct rayo_actor *actor;
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
	/** socket poll descriptor */
	switch_pollfd_t *pollfd;
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
	/** true if no activity last poll */
	int idle;
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
	/** Active XMPP actors mapped by JID */
	switch_hash_t *actors;
	/** XMPP actors pending destruction */
	switch_hash_t *destroy_actors;
	/** Active XMPP actors mapped by internal ID */
	switch_hash_t *actors_by_id;
	/** synchronizes access to actors */
	switch_mutex_t *actors_mutex;
	/** map of DCP JID to session */
	switch_hash_t *clients;
	/** synchronizes access to clients */
	switch_mutex_t *clients_mutex;
	/** domain for calls/mixers/server/etc */
	char *domain;
	/** Maximum idle time before call is considered abandoned */
	int max_idle_ms;
	/** Conference profile to use for mixers */
	char *mixer_conf_profile;
	/** to URI prefixes mapped to gateways */
	switch_hash_t *dial_gateways;
} globals;

/**
 * An outbound dial gateway
 */
struct dial_gateway {
	/** URI prefix to match */
	const char *uri_prefix;
	/** dial prefix to match */
	const char *dial_prefix;
	/** number of digits to strip from dialstring */
	int strip;
};

/**
 * A call controlled by Rayo
 */
struct rayo_call {
	/** base actor */
	struct rayo_actor *actor;
	/** Definitive controlling party JID */
	char *dcp_jid;
	/** Potential controlling parties */
	switch_hash_t *pcps;
	/** current idle start time */
	switch_time_t idle_start_time;
	/** true if joined */
	int joined;
	/** true if playing in channel thread */
	int playing;
	/** set if response needs to be sent to IQ request */
	const char *dial_id;
};

/**
 * A conference
 */
struct rayo_mixer {
	/** base actor */
	struct rayo_actor *actor;
	/** member JIDs */
	switch_hash_t *members;
	/** subscriber JIDs */
	switch_hash_t *subscribers;
};

/**
 * A member of a mixer
 */
struct rayo_mixer_member {
	/** JID of member */
	const char *jid;
	/** Controlling party JID */
	const char *dcp_jid;
};

/**
 * A subscriber to mixer events
 */
struct rayo_mixer_subscriber {
	/** JID of subscriber */
	const char *jid;
	/** Number of controlled parties in mixer */
	int ref_count;
};

/**
 * A Rayo component
 */
struct rayo_component {
	/** base actor */
	struct rayo_actor *actor;
	/** component type (input/output/prompt/etc) */
	const char *type;
	/** Parent actor type (mixer/call) */
	enum rayo_actor_type parent_type;
	/** Parent actor internal ID (uuid or name) */
	const char *parent_id;
	/** client JID */
	const char *client_jid;
	/** external ref */
	const char *ref;
	/** component data */
	void *data;
};

/**
 * Convert Rayo state to string
 * @param state the Rayo state
 * @return the string value of state or "UNKNOWN"
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
 * Convert Rayo actor type to string
 * @param type the Rayo actor type
 * @return the string value of type or "UNKNOWN"
 */
static const char *rayo_actor_type_to_string(enum rayo_actor_type type)
{
	switch(type) {
		case RAT_CALL: return "CALL";
		case RAT_CALL_COMPONENT: return "CALL_COMPONENT";
		case RAT_MIXER: return "MIXER";
		case RAT_MIXER_COMPONENT: return "MIXER_COMPONENT";
		case RAT_SERVER: return "SERVER";
	}
	return "UNKNOWN";
}

/**
 * Handle XMPP stream logging callback
 * @param user_data the Rayo session
 * @param data the log message
 * @param size of the log message
 * @param is_incoming true if this is a log for a received message
 */
static void on_log(void *user_data, const char *data, size_t size, int is_incoming)
{
	if (size > 0) {
		struct rayo_session *rsession = (struct rayo_session *)user_data;
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s %s %s\n", rsession->id, is_incoming ? "RECV" : "SEND", data);
	}
}

/**
 * Add an outbound dialing gateway
 * @param uri_prefix to match
 * @param dial_prefix to use
 * @param strip number of digits to strip from dialstring
 */
static void dial_gateway_add(const char *uri_prefix, const char *dial_prefix, int strip)
{
	struct dial_gateway *gateway = switch_core_alloc(globals.pool, sizeof(*gateway));
	gateway->uri_prefix = uri_prefix ? switch_core_strdup(globals.pool, uri_prefix) : "";
	gateway->dial_prefix = dial_prefix ? switch_core_strdup(globals.pool, dial_prefix) : "";
	gateway->strip = strip > 0 ? strip : 0;
	switch_core_hash_insert(globals.dial_gateways, uri_prefix, gateway);
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "dial-gateway uriprefix = %s, dialprefix = %s, strip = %i\n", uri_prefix, dial_prefix, strip);
}

/**
 * Find outbound dial gateway for the specified dialstring
 */
static struct dial_gateway *dial_gateway_find(const char *uri)
{
	switch_hash_index_t *hi = NULL;
	int match_len = 0;
	struct dial_gateway *gateway = (struct dial_gateway *)switch_core_hash_find(globals.dial_gateways, "default");

	/* find longest prefix match */
	for (hi = switch_core_hash_first(globals.dial_gateways); hi; hi = switch_core_hash_next(hi)) {
		struct dial_gateway *candidate = NULL;
		const void *prefix;
		int prefix_len = 0;
		void *val;
		switch_core_hash_this(hi, &prefix, NULL, &val);
		candidate = (struct dial_gateway *)val;
		switch_assert(candidate);

		prefix_len = strlen(prefix);
		if (!zstr(prefix) && !strncmp(prefix, uri, prefix_len) && prefix_len > match_len) {
			match_len = prefix_len;
			gateway = candidate;
		}
	}
	return gateway;
}

/**
 * Add command handler function
 * @param name the command name
 * @param handler the command handler functions
 */
static void rayo_command_handler_add(const char *name, struct rayo_command_handler *handler)
{
	char full_name[1024];
	full_name[1023] = '\0';
	snprintf(full_name, sizeof(full_name) - 1, "%i:%s:%s", handler->type, handler->subtype, name);
	switch_core_hash_insert(globals.command_handlers, full_name, handler);
}

/**
 * Add server command handler function
 * @param name the command name
 * @param fn the command callback function
 */
static void rayo_server_command_handler_add(const char *name, rayo_server_command_handler fn)
{
	struct rayo_command_handler *handler = switch_core_alloc(globals.pool, sizeof (*handler));
	handler->type = RAT_SERVER;
	handler->subtype = "";
	handler->fn.server = fn;
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Adding server command: %s\n", name);
	rayo_command_handler_add(name, handler);
}

/**
 * Add Rayo command handler function
 * @param name the command name
 * @param fn the command callback function
 */
void rayo_call_command_handler_add(const char *name, rayo_call_command_handler fn)
{
	struct rayo_command_handler *handler = switch_core_alloc(globals.pool, sizeof (*handler));
	handler->type = RAT_CALL;
	handler->subtype = "";
	handler->fn.call = fn;
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Adding call command: %s\n", name);
	rayo_command_handler_add(name, handler);
}

/**
 * Add Rayo command handler function
 * @param name the command name
 * @param fn the command callback function
 */
void rayo_mixer_command_handler_add(const char *name, rayo_mixer_command_handler fn)
{
	struct rayo_command_handler *handler = switch_core_alloc(globals.pool, sizeof (*handler));
	handler->type = RAT_MIXER;
	handler->subtype = "";
	handler->fn.mixer = fn;
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Adding mixer command: %s\n", name);
	rayo_command_handler_add(name, handler);
}

/**
 * Add Rayo command handler function
 * @param subtype the command subtype
 * @param name the command name
 * @param fn the command callback function
 */
void rayo_call_component_command_handler_add(const char *subtype, const char *name, rayo_component_command_handler fn)
{
	struct rayo_command_handler *handler = switch_core_alloc(globals.pool, sizeof (*handler));
	handler->type = RAT_CALL_COMPONENT;
	handler->subtype = switch_core_strdup(globals.pool, subtype);
	handler->fn.component = fn;
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Adding call %s component command: %s\n", subtype, name);
	rayo_command_handler_add(name, handler);
}

/**
 * Add Rayo command handler function
 * @param subtype the command subtype
 * @param name the command name
 * @param fn the command callback function
 */
void rayo_mixer_component_command_handler_add(const char *subtype, const char *name, rayo_component_command_handler fn)
{
	struct rayo_command_handler *handler = switch_core_alloc(globals.pool, sizeof (*handler));
	handler->type = RAT_MIXER_COMPONENT;
	handler->subtype = switch_core_strdup(globals.pool, subtype);
	handler->fn.component = fn;
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Adding mixer %s component command: %s\n", subtype, name);
	rayo_command_handler_add(name, handler);
}

/**
 * Get command handler function from hash
 * @param hash the hash to search
 * @param iq_type the type of command (get/set)
 * @param name the command name
 * @param namespace the command namespace
 * @return the command handler function or NULL
 */
static struct rayo_command_handler *rayo_command_handler_find(struct rayo_actor *actor, const char *iq_type, const char *name, const char *namespace)
{
	struct rayo_command_handler *handler = NULL;
	char full_name[1024];
	full_name[1023] = '\0';
	if (zstr(name) || zstr(iq_type) || zstr(namespace)) {
		return NULL;
	}
	snprintf(full_name, sizeof(full_name) - 1, "%i:%s:%s:%s:%s", actor->type, actor->subtype, iq_type, namespace, name);

	handler = (struct rayo_command_handler *)switch_core_hash_find(globals.command_handlers, full_name);
	return handler;
}

#define rayo_actor_locate(jid) _rayo_actor_locate(jid, __FILE__, __LINE__)
/**
 * Get access to Rayo actor with JID.
 * @param jid the JID
 * @return the actor or NULL.  Call rayo_actor_unlock() when done with pointer.
 */
static struct rayo_actor *_rayo_actor_locate(const char *jid, const char *file, int line)
{
	struct rayo_actor *actor = NULL;
	switch_mutex_lock(globals.actors_mutex);
	actor = (struct rayo_actor *)switch_core_hash_find(globals.actors, jid);
	if (actor) {
		if (!actor->destroy) {
			actor->ref_count++;
			switch_log_printf(SWITCH_CHANNEL_ID_LOG, file, "", line, "", SWITCH_LOG_DEBUG, "Locate %s: ref count = %i\n", actor->jid, actor->ref_count);
		} else {
			actor = NULL;
		}
	}
	switch_mutex_unlock(globals.actors_mutex);
	return actor;
}

#define rayo_actor_locate_by_id(id) _rayo_actor_locate_by_id(id, __FILE__, __LINE__)
/**
 * Get exclusive access to Rayo actor with internal ID
 * @param id the internal ID
 * @return the actor or NULL.  Call rayo_actor_unlock() when done with pointer.
 */
static struct rayo_actor *_rayo_actor_locate_by_id(const char *id, const char *file, int line)
{
	struct rayo_actor *actor = NULL;
	if (!zstr(id)) {
		switch_mutex_lock(globals.actors_mutex);
		actor = (struct rayo_actor *)switch_core_hash_find(globals.actors_by_id, id);
		if (actor) {
			if (!actor->destroy) {
				actor->ref_count++;
				switch_log_printf(SWITCH_CHANNEL_ID_LOG, file, "", line, "", SWITCH_LOG_DEBUG, "Locate %s: ref count = %i\n", actor->jid, actor->ref_count);
			} else {
				actor = NULL;
			}
		}
		switch_mutex_unlock(globals.actors_mutex);
	}
	return actor;
}

#define rayo_actor_destroy(actor) _rayo_actor_destroy(actor, __FILE__, __LINE__)
/**
 * Destroy a rayo actor
 */
static void _rayo_actor_destroy(struct rayo_actor *actor, const char *file, int line)
{
	switch_memory_pool_t *pool = actor->pool;
	switch_mutex_lock(globals.actors_mutex);
	if (!actor->destroy) {
		switch_log_printf(SWITCH_CHANNEL_ID_LOG, file, "", line, "", SWITCH_LOG_DEBUG, "Destroy %s requested: ref_count = %i\n", actor->jid, actor->ref_count);
		switch_core_hash_delete(globals.actors, actor->jid);
		if (!zstr(actor->id)) {
			switch_core_hash_delete(globals.actors_by_id, actor->id);
		}
	}
	actor->destroy = 1;
	if (actor->ref_count <= 0) {
		switch_log_printf(SWITCH_CHANNEL_ID_LOG, file, "", line, "", SWITCH_LOG_DEBUG, "Destroying %s\n", actor->jid);
		switch_core_hash_delete(globals.destroy_actors, actor->jid);
		switch_core_destroy_memory_pool(&pool);
	} else {
		switch_core_hash_insert(globals.destroy_actors, actor->jid, actor);
	}
	switch_mutex_unlock(globals.actors_mutex);
}

#define rayo_actor_unlock(actor) _rayo_actor_unlock(actor, __FILE__, __LINE__)
/**
 * Unlock rayo actor
 */
static void _rayo_actor_unlock(struct rayo_actor *actor, const char *file, int line)
{
	if (actor) {
		switch_mutex_lock(globals.actors_mutex);
		actor->ref_count--;
		switch_log_printf(SWITCH_CHANNEL_ID_LOG, file, "", line, "", SWITCH_LOG_DEBUG, "Unlock %s: ref count = %i\n", actor->jid, actor->ref_count);
		if (actor->ref_count <= 0 && actor->destroy) {
			_rayo_actor_destroy(actor, file, line);
		}
		switch_mutex_unlock(globals.actors_mutex);
	}
}

/**
 * Get next number in sequence
 */
int rayo_actor_seq_next(struct rayo_actor *actor)
{
	int seq;
	switch_mutex_lock(actor->mutex);
	seq = actor->seq++;
	switch_mutex_unlock(actor->mutex);
	return seq;
}

#define rayo_call_locate(call_uuid) _rayo_call_locate(call_uuid, __FILE__, __LINE__)
/**
 * Get exclusive access to Rayo call data.  Use to access call data outside channel thread.
 * @param call_uuid the FreeSWITCH call UUID
 * @return the call or NULL.
 */
static struct rayo_call *_rayo_call_locate(const char *call_uuid, const char *file, int line)
{
	struct rayo_actor *actor = _rayo_actor_locate_by_id(call_uuid, file, line);
	if (actor && actor->type == RAT_CALL) {
		return (struct rayo_call *)actor->data;
	} else if (actor) {
		rayo_actor_unlock(actor);
	}
	return NULL;
}

#define rayo_call_unlock(call) _rayo_call_unlock(call, __FILE__, __LINE__)
/**
 * Unlock Rayo call.
 */
static void _rayo_call_unlock(struct rayo_call *call, const char *file, int line)
{
	if (call) {
		_rayo_actor_unlock(call->actor, file, line);
	}
}

#define rayo_call_destroy(call) _rayo_call_destroy(call, __FILE__, __LINE__)
/**
 * Destroy Rayo call.
 */
static void _rayo_call_destroy(struct rayo_call *call, const char *file, int line)
{
	if (call) {
		_rayo_actor_destroy(call->actor, file, line);
	}
}

/**
 * @param call the Rayo call
 * @return the Rayo call DCP JID
 */
const char *rayo_call_get_dcp_jid(struct rayo_call *call)
{
	return call->dcp_jid;
}

/**
 * @param call the Rayo call
 * @return true if joined
 */
int rayo_call_is_joined(struct rayo_call *call)
{
	return call->joined;
}

/**
 * @param call the Rayo call
 * @return true if playing
 */
int rayo_call_is_playing(struct rayo_call *call)
{
	return call->playing;
}

/**
 * @param call the Rayo call
 * @return the base actor
 */
struct rayo_actor *rayo_call_get_actor(struct rayo_call *call)
{
	return call->actor;
}

#define rayo_mixer_locate(mixer_name) _rayo_mixer_locate(mixer_name, __FILE__, __LINE__)
/**
 * Get access to Rayo mixer data.
 * @param mixer_name the mixer name
 * @return the mixer or NULL. Call rayo_mixer_unlock() when done with mixer pointer.
 */
static struct rayo_mixer *_rayo_mixer_locate(const char *mixer_name, const char *file, int line)
{
	struct rayo_actor *actor = _rayo_actor_locate_by_id(mixer_name, file, line);
	if (actor && actor->type == RAT_MIXER) {
		return (struct rayo_mixer *)actor->data;
	} else if (actor) {
		rayo_actor_unlock(actor);
	}
	return NULL;
}

#define rayo_mixer_unlock(mixer) _rayo_mixer_unlock(mixer, __FILE__, __LINE__)
/**
 * Unlock Rayo mixer.
 */
static void _rayo_mixer_unlock(struct rayo_mixer *mixer, const char *file, int line)
{
	if (mixer) {
		_rayo_actor_unlock(mixer->actor, file, line);
	}
}

#define rayo_mixer_destroy(mixer) _rayo_mixer_destroy(mixer, __FILE__, __LINE__)
/**
 * Destroy Rayo mixer.
 */
static void _rayo_mixer_destroy(struct rayo_mixer *mixer, const char *file, int line)
{
	if (mixer) {
		_rayo_actor_destroy(mixer->actor, file, line);
	}
}

/**
 * @param call the Rayo mixer
 * @return the base actor
 */
struct rayo_actor *rayo_mixer_get_actor(struct rayo_mixer *mixer)
{
	return mixer->actor;
}

#define rayo_actor_create(type, subtype, id, jid, data, size) _rayo_actor_create(type, subtype, id, jid, data, size, __FILE__, __LINE__)
/**
 * Create a rayo actor
 * @param type of actor (MIXER, CALL, SERVER, COMPONENT)
 * @param subtype of actor (input/output/prompt)
 * @param id internal ID
 * @param jid external ID
 * @param data to allocate
 * @param size of data to allocate
 */
static struct rayo_actor *_rayo_actor_create(enum rayo_actor_type type, const char *subtype, const char *id, const char *jid, void **data, size_t size, const char *file, int line)
{
	switch_memory_pool_t *pool;
	struct rayo_actor *actor = NULL;

	/* create base actor */
	switch_core_new_memory_pool(&pool);
	actor = switch_core_alloc(pool, sizeof(*actor));
	actor->type = type;
	actor->subtype = switch_core_strdup(pool, subtype);
	actor->pool = pool;
	if (!zstr(id)) {
		actor->id = switch_core_strdup(pool, id);
	}
	actor->jid = switch_core_strdup(pool, jid);
	actor->data = switch_core_alloc(pool, size);
	actor->seq = 1;
	actor->ref_count = 1;
	actor->destroy = 0;
	*data = actor->data;
	switch_mutex_init(&actor->mutex, SWITCH_MUTEX_NESTED, pool);

	/* add to hash of actors, so commands can route to call */
	switch_mutex_lock(globals.actors_mutex);
	if (!zstr(id)) {
		switch_core_hash_insert(globals.actors_by_id, actor->id, actor);
	}
	switch_core_hash_insert(globals.actors, actor->jid, actor);
	switch_mutex_unlock(globals.actors_mutex);

	switch_log_printf(SWITCH_CHANNEL_ID_LOG, file, "", line, "", SWITCH_LOG_DEBUG, "Create %s\n", actor->jid);

	return actor;
}

/**
 * @return the JID
 */
const char *rayo_actor_get_jid(struct rayo_actor *actor)
{
	return actor->jid;
}

/**
 * @return the internal ID
 */
const char *rayo_actor_get_id(struct rayo_actor *actor)
{
	return actor->id;
}

/**
 * @return the pool
 */
switch_memory_pool_t *rayo_actor_get_pool(struct rayo_actor *actor)
{
	return actor->pool;
}

#define rayo_call_create(uuid) _rayo_call_create(uuid, __FILE__, __LINE__)
/**
 * Create Rayo call
 * @param uuid uuid to assign call, if NULL one is picked
 * @param file file that called this function
 * @param line number of file that called this function
 * @return the call
 */
static struct rayo_call *_rayo_call_create(const char *uuid, const char *file, int line)
{
	char *call_jid;
	struct rayo_actor *actor = NULL;
	struct rayo_call *call = NULL;
	char uuid_id_buf[SWITCH_UUID_FORMATTED_LENGTH + 1];

	if (zstr(uuid)) {
		switch_uuid_str(uuid_id_buf, sizeof(uuid_id_buf));
		uuid = uuid_id_buf;
	}
	call_jid = switch_mprintf("%s@%s", uuid, globals.domain);

	actor = _rayo_actor_create(RAT_CALL, "", uuid, call_jid, (void **)&call, sizeof(*call), file, line);

	/* create call */
	call->dcp_jid = "";
	call->idle_start_time = switch_micro_time_now();
	call->joined = 0;
	call->actor = actor;
	switch_core_hash_init(&call->pcps, actor->pool);
	switch_safe_free(call_jid);
	return call;
}

#define rayo_mixer_create(name) _rayo_mixer_create(name, __FILE__, __LINE__)
/**
 * Create Rayo mixer
 * @param name of this mixer
 * @return the mixer
 */
static struct rayo_mixer *_rayo_mixer_create(const char *name, const char *file, int line)
{
	struct rayo_actor *actor = NULL;
	struct rayo_mixer *mixer = NULL;
	char *mixer_jid = switch_mprintf("%s@%s", name, globals.domain);

	actor = _rayo_actor_create(RAT_MIXER, "", name, mixer_jid, (void **)&mixer, sizeof(*mixer), file, line);
	switch_core_hash_init(&mixer->members, actor->pool);
	switch_core_hash_init(&mixer->subscribers, actor->pool);
	mixer->actor = actor;
	switch_safe_free(mixer_jid);

	return mixer;
}

/**
 * Create Rayo component
 * @param type of this component
 * @param id internal ID of this component
 * @param parent the parent that owns this component
 * @param client_jid the client that created this component
 * @return the component
 */
struct rayo_component *_rayo_component_create(const char *type, const char *id, struct rayo_actor *parent, const char *client_jid, const char *file, int line)
{
	enum rayo_actor_type actor_type;
	struct rayo_component *component = NULL;
	char *ref = switch_mprintf("%s-%d", type, rayo_actor_seq_next(parent));
	char *jid = switch_mprintf("%s/%s", rayo_actor_get_jid(parent), ref);
	struct rayo_actor *actor = NULL;
	if (zstr(id)) {
		id = jid;
	}
	if (parent->type == RAT_CALL) {
		actor_type = RAT_CALL_COMPONENT;
	} else if (parent->type == RAT_MIXER) {
		actor_type = RAT_MIXER_COMPONENT;
	} else {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "Not allowed to create component with parent %s, type (%s)\n",
			rayo_actor_get_jid(parent), rayo_actor_type_to_string(parent->type));
		return NULL;
	}
	actor = _rayo_actor_create(actor_type, type, id, jid, (void **)&component, sizeof(*component), file, line);
	component->actor = actor;
	component->client_jid = switch_core_strdup(actor->pool, client_jid);
	component->parent_type = parent->type;
	component->parent_id = switch_core_strdup(actor->pool, parent->id);
	component->ref = switch_core_strdup(actor->pool, ref);
	component->data = NULL;
	switch_safe_free(ref);
	switch_safe_free(jid);
	return component;
}

/**
 * Destroy Rayo component
 */
void _rayo_component_destroy(struct rayo_component *component, const char *file, int line)
{
	if (component) {
		_rayo_actor_destroy(component->actor, file, line);
	}
}

/**
 * @return component ref
 */
const char *rayo_component_get_ref(struct rayo_component *component)
{
	return component->ref;
}

/**
 * @return JID of client that created this component
 */
const char *rayo_component_get_client_jid(struct rayo_component *component)
{
	return component->client_jid;
}

/**
 * @return component's parent type (CALL/MIXER)
 */
enum rayo_actor_type rayo_component_get_parent_type(struct rayo_component *component)
{
	return component->parent_type;
}

/**
 * @return component's parent internal ID (UUID for calls, name for mixers)
 */
const char *rayo_component_get_parent_id(struct rayo_component *component)
{
	return component->parent_id;
}

/**
 * @return private data
 */
void *rayo_component_get_data(struct rayo_component *component)
{
	return component->data;
}

/**
 * @param data private data
 */
void rayo_component_set_data(struct rayo_component *component, void *data)
{
	component->data = data;
}

/**
 * @return private data
 */
struct rayo_actor *rayo_component_get_actor(struct rayo_component *component)
{
	return component->actor;
}

/**
 * Get access to Rayo component data.
 * @param id the component internal ID
 * @return the component or NULL. Call rayo_component_unlock() when done with component pointer.
 */
struct rayo_component *_rayo_component_locate(const char *id, const char *file, int line)
{
	struct rayo_actor *actor = _rayo_actor_locate_by_id(id, file, line);
	if (actor && (actor->type == RAT_MIXER_COMPONENT || actor->type == RAT_CALL_COMPONENT)) {
		return (struct rayo_component *)actor->data;
	} else if (actor) {
		rayo_actor_unlock(actor);
	}
	return NULL;
}

/**
 * Unlock Rayo component
 */
void _rayo_component_unlock(struct rayo_component *component, const char *file, int line)
{
	if (component) {
		_rayo_actor_unlock(component->actor, file, line);
	}
}

/**
 * Send XMPP message from anybody to client
 * @param msg the message to send
 */
void rayo_iks_send(iks *msg) {
	switch_event_t *event;
	const char *dcp_jid = iks_find_attrib_soft(msg, "to");

	/* send XMPP message to Rayo session via event */
	if (switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, RAYO_EVENT_XMPP_SEND) == SWITCH_STATUS_SUCCESS) {
		char *msg_str = iks_string(NULL, msg);
		switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "variable_rayo_dcp_jid", dcp_jid);
		switch_event_add_body(event, "%s", msg_str);
		switch_event_fire(&event);
		iks_free(msg_str);
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
		"<stream:stream xmlns='"IKS_NS_CLIENT"' xmlns:db='"IKS_NS_XMPP_DIALBACK"'"
		" from='%s' id='%s' xml:lang='en' version='1.0'"
		" xmlns:stream='"IKS_NS_XMPP_STREAMS"'><stream:features>"
		"<bind xmlns='"IKS_NS_XMPP_BIND"'/>"
		"<session xmlns='"IKS_NS_XMPP_SESSION"'/>"
		"</stream:features>", rsession->server_jid, rsession->id);

	int result = iks_send_raw(rsession->parser, header);
	switch_safe_free(header);
	return result;
}

/**
 * Check if client has control of offered call. Take control if nobody else does.
 * @param rsession the Rayo session
 * @param call the Rayo call
 * @param session the session
 * @param call_jid the call JID
 * @param call_uuid the internal call UUID
 * @return 1 if session has call control
 */
static int rayo_client_has_call_control(struct rayo_session *rsession, struct rayo_call *call, switch_core_session_t *session)
{
	int control = 0;

	if (zstr(rsession->client_jid_full)) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_CRIT, "Null client JID!!\n");
		return 0;
	}

	/* nobody in charge */
	if (zstr(call->dcp_jid)) {
		/* was offered to this session? */
		if (switch_core_hash_find(call->pcps, rsession->client_jid_full)) {
			/* take charge */
			call->dcp_jid = switch_core_strdup(call->actor->pool, rsession->client_jid_full);
			switch_channel_set_variable(switch_core_session_get_channel(session), "rayo_dcp_jid", call->dcp_jid);
			control = 1;
			switch_log_printf(SWITCH_CHANNEL_UUID_LOG(rayo_call_get_uuid(call)), SWITCH_LOG_INFO, "%s has control of call\n", call->dcp_jid);
		}
	} else if (!strcmp(call->dcp_jid, rsession->client_jid_full)) {
		control = 1;
	}

	if (!control) {
		switch_log_printf(SWITCH_CHANNEL_UUID_LOG(rayo_call_get_uuid(call)), SWITCH_LOG_INFO, "%s does not have control of call\n", rsession->client_jid_full);
	}

	return control;
}

/**
 * Check Rayo server command for errors.
 * @param rsession the Rayo session
 * @param node the <iq> node
 * @return 1 if OK
 */
static int rayo_server_command_ok(struct rayo_session *rsession, iks *node)
{
	iks *response = NULL;
	char *to = iks_find_attrib(node, "to");
	int bad = zstr(iks_find_attrib(node, "id"));

	if (zstr(to)) {
		to = rsession->server_jid;
		iks_insert_attrib(node, "to", to);
	}

	/* check if AUTHENTICATED and to= server JID */
	if (bad) {
		response = iks_new_iq_error(node, STANZA_ERROR_BAD_REQUEST);
	} else if (rsession->state == SS_NEW) {
		response = iks_new_iq_error(node, STANZA_ERROR_REGISTRATION_REQUIRED);
	}

	if (response) {
		iks_send(rsession->parser, response);
		iks_delete(response);
		return 0;
	}
	return 1;
}

/**
 * Check Rayo call command for errors.
 * @param rsession the Rayo session
 * @param call the Rayo call
 * @param session the session
 * @param node the <iq> node
 * @return 1 if OK
 */
static int rayo_call_command_ok(struct rayo_session *rsession, struct rayo_call *call, switch_core_session_t *session, iks *node)
{
	iks *response = NULL;
	int bad = zstr(iks_find_attrib(node, "id"));

	if (bad) {
		response = iks_new_iq_error(node, STANZA_ERROR_BAD_REQUEST);
	} else if (rsession->state == SS_NEW) {
		response = iks_new_iq_error(node, STANZA_ERROR_REGISTRATION_REQUIRED);
	} else if (rsession->state != SS_ONLINE) {
		response = iks_new_iq_error(node, STANZA_ERROR_UNEXPECTED_REQUEST);
	} else if (!rayo_client_has_call_control(rsession, call, session)) {
		response = iks_new_iq_error(node, STANZA_ERROR_CONFLICT);
	}

	if (response) {
		iks_send(rsession->parser, response);
		iks_delete(response);
		return 0;
	}
	return 1;
}

/**
 * Check Rayo component command for errors.
 * @param rsession the session
 * @param component the component
 * @param node the <iq> node
 * @return 0 if error
 */
static int rayo_component_command_ok(struct rayo_session *rsession, struct rayo_component *component, iks *node)
{
	iks *response = NULL;
	char *from = iks_find_attrib(node, "from");
	int bad = zstr(iks_find_attrib(node, "id"));

	if (bad) {
		response = iks_new_iq_error(node, STANZA_ERROR_BAD_REQUEST);
	} else if (rsession->state == SS_NEW) {
		response = iks_new_iq_error(node, STANZA_ERROR_REGISTRATION_REQUIRED);
	} else if (rsession->state != SS_ONLINE) {
		response = iks_new_iq_error(node, STANZA_ERROR_UNEXPECTED_REQUEST);
	} else if (strcmp(component->client_jid, from)) {
		/* does not have control of this component */
		response = iks_new_iq_error(node, STANZA_ERROR_CONFLICT);
	}
	if (response) {
		iks_send(rsession->parser, response);
		iks_delete(response);
		return 0;
	}

	return 1;
}

/**
 * Add signaling headers to channel -- only works on SIP
 * @param session the channel
 * @param iq_cmd the request containing <header>
 * @param type header type
 */
static void add_signaling_headers(switch_core_session_t *session, iks *iq_cmd, const char *type)
{
	switch_channel_t *channel = switch_core_session_get_channel(session);
	iks *header = NULL;
	for (header = iks_find(iq_cmd, "header"); header; header = iks_next_tag(header)) {
		if (!strcmp("header", iks_name(header))) {
			const char *name = iks_find_attrib_soft(header, "name");
			const char *value = iks_find_attrib_soft(header, "value");
			if (!zstr(name) && !zstr(value)) {
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Adding header: %s: %s\n", name, value);
				switch_channel_set_variable_name_printf(channel, value, "%s%s", type, name);
			}
		}
	}
}

/**
 * Handle <iq><accept> request
 * @param call the Rayo call
 * @param session the session
 * @param node the <iq> node
 */
static iks *on_rayo_accept(struct rayo_call *call, switch_core_session_t *session, iks *node)
{
	iks *response = NULL;

	/* send ringing */
	add_signaling_headers(session, iks_find(node, "accept"), RAYO_SIP_RESPONSE_HEADER);
	switch_channel_pre_answer(switch_core_session_get_channel(session));
	response = iks_new_iq_result(node);
	return response;
}

/**
 * Handle <iq><answer> request
 * @param call the Rayo call
 * @param session the session
 * @param node the <iq> node
 */
static iks *on_rayo_answer(struct rayo_call *call, switch_core_session_t *session, iks *node)
{
	iks *response = NULL;

	/* send answer to call */
	add_signaling_headers(session, iks_find(node, "answer"), RAYO_SIP_RESPONSE_HEADER);
	switch_channel_answer(switch_core_session_get_channel(session));
	response = iks_new_iq_result(node);
	return response;
}

/**
 * Handle <iq><redirect> request
 * @param call the Rayo call
 * @param session the session
 * @param node the <iq> node
 */
static iks *on_rayo_redirect(struct rayo_call *call, switch_core_session_t *session, iks *node)
{
	iks *response = NULL;
	iks *redirect = iks_find(node, "redirect");
	char *redirect_to = iks_find_attrib(redirect, "to");

	if (zstr(redirect_to)) {
		response = iks_new_iq_error_detailed(node, STANZA_ERROR_BAD_REQUEST, "Missing redirect to attrib");
	} else {
		switch_core_session_message_t msg = { 0 };
		add_signaling_headers(session, redirect, RAYO_SIP_RESPONSE_HEADER);

		/* Tell the channel to deflect the call */
		msg.from = __FILE__;
		msg.string_arg = switch_core_session_strdup(session, redirect_to);
		msg.message_id = SWITCH_MESSAGE_INDICATE_DEFLECT;
		switch_core_session_receive_message(session, &msg);
		response = iks_new_iq_result(node);
	}
	return response;
}

/**
 * Handle <iq><hangup> or <iq><reject> request
 * @param call the Rayo call
 * @param session the session
 * @param node the <iq> node
 */
static iks *on_rayo_hangup(struct rayo_call *call, switch_core_session_t *session, iks *node)
{
	iks *response = NULL;
	iks *hangup = iks_child(node);
	iks *reason = iks_child(hangup);
	int hangup_cause = RAYO_CAUSE_HANGUP;

	/* get hangup cause */
	if (!reason && !strcmp("hangup", iks_name(hangup))) {
		/* no reason in <hangup> */
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
		} else {
			response = iks_new_iq_error_detailed(node, STANZA_ERROR_BAD_REQUEST, "invalid reject reason");
		}
	} else {
		response = iks_new_iq_error(node, STANZA_ERROR_BAD_REQUEST);
	}

	/* do hangup */
	if (!response) {
		add_signaling_headers(session, hangup, RAYO_SIP_REQUEST_HEADER);
		add_signaling_headers(session, hangup, RAYO_SIP_RESPONSE_HEADER);
		switch_ivr_kill_uuid(rayo_call_get_uuid(call), hangup_cause);
		response = iks_new_iq_result(node);
	}

	return response;
}

static ATTRIB_RULE(join_direction)
{
	/* for now, only allow duplex
	return !strcmp("send", value) || !strcmp("recv", value) || !strcmp("duplex", value); */
	return !strcmp("duplex", value);
}

static ATTRIB_RULE(join_media)
{
	return !strcmp("bridge", value) || !strcmp("direct", value);
}

/**
 * <join> command validation
 */
ELEMENT(RAYO_JOIN)
	ATTRIB(direction, duplex, join_direction)
	ATTRIB(media, bridge, join_media)
	ATTRIB(call-id,, any)
	ATTRIB(mixer-name,, any)
ELEMENT_END

/**
 * Join calls together
 * @param call the call that joins
 * @param session the session
 * @param node the join request
 * @param call_id to join
 * @param media mode (direct/bridge)
 * @return the response
 */
static iks *join_call(struct rayo_call *call, switch_core_session_t *session, iks *node, const char *call_id, const char *media)
{
	iks *response = NULL;
	/* take call out of media path if media = "direct" */
	const char *bypass = !strcmp("direct", media) ? "true" : "false";

	/* check if joining to rayo call */
	struct rayo_call *b_call = rayo_call_locate(call_id);
	if (!b_call) {
		/* not a rayo call */
		response = iks_new_iq_error_detailed(node, STANZA_ERROR_SERVICE_UNAVAILABLE, "b-leg is not a rayo call");
	} else if (b_call->joined) {
		/* don't support multiple joined calls */
		response = iks_new_iq_error_detailed(node, STANZA_ERROR_CONFLICT, "multiple joined calls not supported");
		rayo_call_unlock(b_call);
	} else {
		rayo_call_unlock(b_call);

		/* bridge this call to call-id */
		switch_channel_set_variable(switch_core_session_get_channel(session), "bypass_media", bypass);
		if (switch_ivr_uuid_bridge(rayo_call_get_uuid(call), call_id) == SWITCH_STATUS_SUCCESS) {
			response = iks_new_iq_result(node);
		} else {
			response = iks_new_iq_error_detailed(node, STANZA_ERROR_INTERNAL_SERVER_ERROR, "failed to bridge call");
		}
	}
	return response;
}

/**
 * Join call to a mixer
 * @param call the call that joins
 * @param session the session
 * @param node the join request
 * @return the response
 */
static iks *join_mixer(struct rayo_call *call, switch_core_session_t *session, iks *node, const char *mixer_name)
{
	iks *response = NULL;
	char *conf_args = switch_mprintf("%s@%s", mixer_name, globals.mixer_conf_profile);
	if (switch_core_session_execute_application_async(session, "conference", conf_args) == SWITCH_STATUS_SUCCESS) {
		response = iks_new_iq_result(node);
	} else {
		response = iks_new_iq_error_detailed(node, STANZA_ERROR_INTERNAL_SERVER_ERROR, "failed execute conference app");
	}
	switch_safe_free(conf_args);
	return response;
}

/**
 * Handle <iq><join> request
 * @param call the Rayo call
 * @param session the session
 * @param node the <iq> node
 */
static iks *on_rayo_join(struct rayo_call *call, switch_core_session_t *session, iks *node)
{
	iks *response = NULL;
	iks *join = iks_find(node, "join");
	const char *mixer_name;
	const char *call_id;

	/* validate input attributes */
	if (!VALIDATE_RAYO_JOIN(join)) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Bad join attrib\n");
		response = iks_new_iq_error(node, STANZA_ERROR_BAD_REQUEST);
		goto done;
	}
	mixer_name = iks_find_attrib(join, "mixer-name");
	call_id = iks_find_attrib(join, "call-id");

	/* can't join both mixer and call */
	if (!zstr(mixer_name) && !zstr(call_id)) {
		response = iks_new_iq_error_detailed(node, STANZA_ERROR_BAD_REQUEST, "mixer-name and call-id are mutually exclusive");
		goto done;
	}

	/* need to join *something* */
	if (zstr(mixer_name) && zstr(call_id)) {
		response = iks_new_iq_error_detailed(node, STANZA_ERROR_BAD_REQUEST, "mixer-name or call-id is required");
		goto done;
	}

	if (call->joined) {
		/* already joined */
		response = iks_new_iq_error_detailed(node, STANZA_ERROR_CONFLICT, "call is already joined");
		goto done;
	}

	if (!zstr(mixer_name)) {
		/* join conference */
		response = join_mixer(call, session, node,  mixer_name);
	} else {
		/* bridge calls */
		response = join_call(call, session, node, call_id, iks_find_attrib(join, "media"));
	}

done:
	return response;
}

/**
 * unjoin call to a bridge
 * @param call the call that unjoined
 * @param session the session
 * @param node the unjoin request
 * @param call_id the b-leg uuid
 * @return the response
 */
static iks *unjoin_call(struct rayo_call *call, switch_core_session_t *session, iks *node, const char *call_id)
{
	iks *response = NULL;
	const char *bleg = switch_channel_get_variable(switch_core_session_get_channel(session), SWITCH_BRIDGE_UUID_VARIABLE);

	/* bleg must match call_id */
	if (!zstr(bleg) && !strcmp(bleg, call_id)) {
		/* unbridge call */
		response = iks_new_iq_result(node);
		rayo_iks_send(response); // send before park so events arrive in order to client
		iks_delete(response);
		response = NULL;
		switch_ivr_park_session(session);
	} else {
		/* not bridged or wrong b-leg UUID */
		response = iks_new_iq_error(node, STANZA_ERROR_SERVICE_UNAVAILABLE);
	}

	return response;
}

/**
 * unjoin call to a mixer
 * @param call the call that unjoined
 * @param session the session
 * @param node the unjoin request
 * @param mixer_name the mixer name
 * @return the response
 */
static iks *unjoin_mixer(struct rayo_call *call, switch_core_session_t *session, iks *node, const char *mixer_name)
{
	switch_channel_t *channel = switch_core_session_get_channel(session);
	const char *conf_member_id = switch_channel_get_variable(channel, "conference_member_id");
	const char *conf_name = switch_channel_get_variable(channel, "conference_name");
	char *kick_command;
	iks *response = NULL;
	switch_stream_handle_t stream = { 0 };
	SWITCH_STANDARD_STREAM(stream);

	/* not conferenced, or wrong conference */
	if (zstr(conf_name) || strcmp(mixer_name, conf_name)) {
		response = iks_new_iq_error_detailed_printf(node, STANZA_ERROR_SERVICE_UNAVAILABLE, "not joined to %s", mixer_name);
		goto done;
	} else if (zstr(conf_member_id)) {
		/* shouldn't happen */
		response = iks_new_iq_error_detailed(node, STANZA_ERROR_SERVICE_UNAVAILABLE, "channel doesn't have conference member ID");
		goto done;
	}

	/* ack command */
	response = iks_new_iq_result(node);
	rayo_iks_send(response);  // send before park so events arrive in order to client
	iks_delete(response);
	response = NULL;

	/* kick the member */
	kick_command = switch_core_session_sprintf(session, "%s hup %s", mixer_name, conf_member_id);
	switch_api_execute("conference", kick_command, NULL, &stream);

done:
	switch_safe_free(stream.data);

	return response;
}

/**
 * Handle <iq><unjoin> request
 * @param call the Rayo call
 * @param session the session
 * @param node the <iq> node
 */
static iks *on_rayo_unjoin(struct rayo_call *call, switch_core_session_t *session, iks *node)
{
	iks *response = NULL;
	iks *unjoin = iks_find(node, "unjoin");
	const char *call_id = iks_find_attrib(unjoin, "call-id");
	const char *mixer_name = iks_find_attrib(unjoin, "mixer-name");

	if (!zstr(call_id) && !zstr(mixer_name)) {
		response = iks_new_iq_error(node, STANZA_ERROR_BAD_REQUEST);
	} else if (!call->joined) {
		/* not joined to anything */
		response = iks_new_iq_error(node, STANZA_ERROR_SERVICE_UNAVAILABLE);
	} else if (!zstr(call_id)) {
		response = unjoin_call(call, session, node, call_id);
	} else if (!zstr(mixer_name)) {
		response = unjoin_mixer(call, session, node, mixer_name);
	} else {
		/* missing mixer or call */
		response = iks_new_iq_error(node, STANZA_ERROR_BAD_REQUEST);
	}

	return response;
}

/**
 * Thread that handles originating new calls
 * @param thread this thread
 * @param obj the Rayo session
 * @return NULL
 */
static void *SWITCH_THREAD_FUNC rayo_dial_thread(switch_thread_t *thread, void *node)
{
	iks *iq = (iks *)node;
	iks *dial = iks_find(iq, "dial");
	iks *response = NULL;
	const char *dcp_jid = iks_find_attrib(iq, "from");
	const char *dial_to = iks_find_attrib(dial, "to");
	const char *dial_from = iks_find_attrib(dial, "from");
	const char *dial_timeout_ms = iks_find_attrib(dial, "timeout");
	struct dial_gateway *gateway = NULL;
	struct rayo_call *call = NULL;
	switch_stream_handle_t stream = { 0 };
	SWITCH_STANDARD_STREAM(stream);

	switch_thread_rwlock_rdlock(globals.shutdown_rwlock);

	/* create call and link to DCP */
	call = rayo_call_create(NULL);
	call->dcp_jid = switch_core_strdup(rayo_call_get_pool(call), dcp_jid);
	call->dial_id = iks_find_attrib(iq, "id");
	switch_log_printf(SWITCH_CHANNEL_UUID_LOG(rayo_call_get_uuid(call)), SWITCH_LOG_INFO, "%s has control of call\n", dcp_jid);

	/* set rayo channel variables so channel originate event can be identified as coming from Rayo */
	stream.write_function(&stream, "{origination_uuid=%s,rayo_dcp_jid=%s,rayo_call_jid=%s",
		rayo_call_get_uuid(call), dcp_jid, rayo_call_get_jid(call));

	/* set originate channel variables */
	if (!zstr(dial_from)) {
		/* caller ID */
		/* TODO parse caller ID name and number from URI */
		stream.write_function(&stream, ",origination_caller_id_number=%s,origination_caller_id_name=%s", dial_from, dial_from);
	}
	if (!zstr(dial_timeout_ms) && switch_is_number(dial_timeout_ms)) {
		/* timeout */
		int dial_timeout_sec = round((double)atoi(dial_timeout_ms) / 1000.0);
		stream.write_function(&stream, ",originate_timeout=%i", dial_timeout_sec);
	}

	/* set outbound signaling headers - only works on SIP */
	{
		iks *header = NULL;
		for (header = iks_find(dial, "header"); header; header = iks_next_tag(header)) {
			if (!strcmp("header", iks_name(header))) {
				const char *name = iks_find_attrib_soft(header, "name");
				const char *value = iks_find_attrib_soft(header, "value");
				if (!zstr(name) && !zstr(value)) {
					switch_log_printf(SWITCH_CHANNEL_UUID_LOG(rayo_call_get_uuid(call)), SWITCH_LOG_DEBUG, "Adding header: %s: %s\n", name, value);
					stream.write_function(&stream, ",%s%s=%s", RAYO_SIP_REQUEST_HEADER, name, value);
				}
			}
		}
	}

	stream.write_function(&stream, "}");

	/* build dialstring and dial call */
	gateway = dial_gateway_find(dial_to);
	if (gateway) {
		iks *join = iks_find(dial, "join");
		const char *dial_to_stripped = dial_to + gateway->strip;
		switch_stream_handle_t api_stream = { 0 };
		SWITCH_STANDARD_STREAM(api_stream);

		if (join) {
			/* check join args */
			const char *call_id = iks_find_attrib(join, "call-id");
			const char *mixer_name = iks_find_attrib(join, "mixer-name");

			if (!zstr(call_id) && !zstr(mixer_name)) {
				/* can't join both */
				response = iks_new_iq_error(iq, STANZA_ERROR_BAD_REQUEST);
				goto done;
			} else if (zstr(call_id) && zstr(mixer_name)) {
				/* nobody to join to? */
				response = iks_new_iq_error(iq, STANZA_ERROR_BAD_REQUEST);
				goto done;
			} else if (!zstr(call_id)) {
				/* bridge */
				struct rayo_call *b_call = rayo_call_locate(call_id);
				/* is b-leg available? */
				if (!b_call) {
					response = iks_new_iq_error_detailed(iq, STANZA_ERROR_SERVICE_UNAVAILABLE, "b-leg not found");
					goto done;
				} else if (b_call->joined) {
					response = iks_new_iq_error_detailed(iq, STANZA_ERROR_SERVICE_UNAVAILABLE, "b-leg already joined to another call");
					rayo_call_unlock(b_call);
					goto done;
				}
				rayo_call_unlock(b_call);
				stream.write_function(&stream, "%s%s &rayo(bridge %s)", gateway->dial_prefix, dial_to_stripped, call_id);
			} else {
				/* conference */
				stream.write_function(&stream, "%s%s &rayo(conference %s@%s)", gateway->dial_prefix, dial_to_stripped, mixer_name, globals.mixer_conf_profile);
			}
		} else {
			stream.write_function(&stream, "%s%s &rayo", gateway->dial_prefix, dial_to_stripped);
		}

		switch_log_printf(SWITCH_CHANNEL_UUID_LOG(rayo_call_get_uuid(call)), SWITCH_LOG_DEBUG, "Using dialstring: %s\n", (char *)stream.data);

		/* <iq><ref> response will be sent when originate event is received- otherwise error is returned */
		if (switch_api_execute("originate", stream.data, NULL, &api_stream) == SWITCH_STATUS_SUCCESS) {
			switch_log_printf(SWITCH_CHANNEL_UUID_LOG(rayo_call_get_uuid(call)), SWITCH_LOG_DEBUG, "Got originate result: %s\n", (char *)api_stream.data);

			/* check for failure */
			if (strncmp("+OK", api_stream.data, strlen("+OK"))) {
				switch_log_printf(SWITCH_CHANNEL_UUID_LOG(rayo_call_get_uuid(call)), SWITCH_LOG_INFO, "Failed to originate call\n");

				if (call->dial_id) {
					/* map failure reason to iq error */
					if (!strncmp("-ERR DESTINATION_OUT_OF_ORDER", api_stream.data, strlen("-ERR DESTINATION_OUT_OF_ORDER"))) {
						/* this -ERR is received when out of sessions */
						response = iks_new_iq_error(iq, STANZA_ERROR_RESOURCE_CONSTRAINT);
					} else {
						response = iks_new_iq_error_detailed(iq, STANZA_ERROR_INTERNAL_SERVER_ERROR, api_stream.data);
					}
				}
			}
		} else if (call->dial_id) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Failed to exec originate API\n");
			response = iks_new_iq_error_detailed(iq, STANZA_ERROR_INTERNAL_SERVER_ERROR, "Failed to execute originate API");
		}

		switch_safe_free(api_stream.data);
	} else {
		/* will only happen if misconfigured */
		switch_log_printf(SWITCH_CHANNEL_UUID_LOG(rayo_call_get_uuid(call)), SWITCH_LOG_CRIT, "No dial gateway found for %s!\n", dial_to);
		response = iks_new_iq_error_detailed_printf(iq, STANZA_ERROR_INTERNAL_SERVER_ERROR, "No dial gateway found for %s!\n", dial_to);
		goto done;
	}

done:

	/* response when error */
	if (response) {
		/* send response to client */
		rayo_iks_send(response);
		iks_delete(response);

		/* destroy call */
		if (call) {
			rayo_call_unlock(call);
			rayo_call_destroy(call);
		}
	}

	iks_delete(dial);
	switch_safe_free(stream.data);
	switch_thread_rwlock_unlock(globals.shutdown_rwlock);

	return NULL;
}

/**
 * Dial a new call
 * @param rsession requesting the call
 * @param node the request
 */
static void on_rayo_dial(struct rayo_session *rsession, iks *node)
{
	switch_thread_t *thread;
	switch_threadattr_t *thd_attr = NULL;
	iks *dial = iks_find(node, "dial");

	if (rsession->state != SS_ONLINE) {
		iks *response = iks_new_iq_error_detailed(node, STANZA_ERROR_UNEXPECTED_REQUEST, "rayo client is not online");
		iks_send(rsession->parser, response);
		iks_delete(response);
	} else if (!zstr(iks_find_attrib(dial, "to"))) {
		iks *node_dup = iks_copy(node);
		iks_insert_attrib(node_dup, "from", rsession->client_jid_full); /* save DCP jid in case it isn't specified */

		/* start dial thread */
		switch_threadattr_create(&thd_attr, rsession->pool);
		switch_threadattr_detach_set(thd_attr, 1);
		switch_threadattr_stacksize_set(thd_attr, SWITCH_THREAD_STACKSIZE);
		switch_thread_create(&thread, thd_attr, rayo_dial_thread, node_dup, rsession->pool);
	} else {
		iks *response = iks_new_iq_error_detailed(node, STANZA_ERROR_BAD_REQUEST, "missing dial to attribute");
		iks_send(rsession->parser, response);
		iks_delete(response);
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
		/* TODO presence error */
	} else if (!strcmp("probe", type)) {
		/* TODO presence probe */
	} else if (!strcmp("subscribe", type)) {
		/* TODO presence subscribe */
	} else if (!strcmp("subscribed", type)) {
		/* TODO presence subscribed */
	} else if (!strcmp("unsubscribe", type)) {
		/* TODO presence unsubscribe */
	} else if (!strcmp("unsubscribed", type)) {
		/* TODO presence unsubscribed */
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
 * @param node the <iq> node
 */
static void on_iq_xmpp_ping(struct rayo_session *rsession, iks *node)
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
 * Handle service discovery request
 * @param rsession the Rayo session
 * @param node the <iq> node
 */
static void on_iq_get_xmpp_disco(struct rayo_session *rsession, iks *node)
{
	iks *response = iks_new("iq");

	/* make sure this message is sent to the server */
	if (!strcmp(rsession->server_jid, iks_find_attrib_soft(node, "to"))) {
		iks *x;
		response = iks_new_iq_result(node);
		x = iks_insert(response, "query");
		iks_insert_attrib(x, "xmlns", IKS_NS_XMPP_DISCO);
		x = iks_insert(x, "feature");
		iks_insert_attrib(x, "var", RAYO_NS);

		/* TODO The response MUST also include features for the application formats and transport methods supported by
		 * the responding entity, as described in the relevant specifications.
		 */
	} else {
		response = iks_new_iq_error(node, STANZA_ERROR_BAD_REQUEST);
	}

	iks_send(rsession->parser, response);
	iks_delete(response);
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
		reply = iks_new_iq_error(node, STANZA_ERROR_NOT_AUTHORIZED);
		break;

	case SS_AUTHENTICATED:
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "%s, iq UNEXPECTED <session>, state = %s\n", rsession->id, rayo_session_state_to_string(rsession->state));
		reply = iks_new_iq_error(node, STANZA_ERROR_UNEXPECTED_REQUEST);
		break;

	case SS_RESOURCE_BOUND:
		reply = iks_new_iq_result(node);
		rsession->state = SS_SESSION_ESTABLISHED;
		break;

	case SS_SESSION_ESTABLISHED:
	case SS_ONLINE:
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "%s, iq UNEXPECTED <session>, state = %s\n", rsession->id, rayo_session_state_to_string(rsession->state));
		reply = iks_new_iq_error(node, STANZA_ERROR_UNEXPECTED_REQUEST);
		break;

	default:
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "%s, iq UNEXPECTED <session>, state = %s\n", rsession->id, rayo_session_state_to_string(rsession->state));
		reply = iks_new_iq_error(node, STANZA_ERROR_SERVICE_UNAVAILABLE);
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
		rsession->client_jid_full = switch_core_sprintf(rsession->pool, "%s/%s", rsession->client_jid, resource_id);

		/* create reply */
		reply = iks_new_iq_result(node);
		x = iks_insert(reply, "bind");
		iks_insert_attrib(x, "xmlns", IKS_NS_XMPP_BIND);
		iks_insert_cdata(iks_insert(x, "jid"), rsession->client_jid_full, strlen(rsession->client_jid_full));

		rsession->state = SS_RESOURCE_BOUND;

		/* remember route to client */
		switch_mutex_lock(globals.clients_mutex);
		switch_core_hash_insert(globals.clients, rsession->client_jid_full, rsession);
		switch_mutex_unlock(globals.clients_mutex);
		break;
	}
	case SS_RESOURCE_BOUND:
	case SS_ONLINE:
		/* already bound a single resource */
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "%s, iq UNEXPECTED <bind>, state = %s\n", rsession->id, rayo_session_state_to_string(rsession->state));
		reply = iks_new_iq_error(node, STANZA_ERROR_NOT_ALLOWED);
		break;

	case SS_NEW:
		/* new */
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "%s, iq UNEXPECTED <bind>, state = %s\n", rsession->id, rayo_session_state_to_string(rsession->state));
		reply = iks_new_iq_error(node, STANZA_ERROR_NOT_AUTHORIZED);
		break;

	default:
		/* shutdown/error/destroy */
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "%s, iq UNEXPECTED <bind>, state = %s\n", rsession->id, rayo_session_state_to_string(rsession->state));
		reply = iks_new_iq_error(node, STANZA_ERROR_SERVICE_UNAVAILABLE);
		break;
	}

	iks_send(rsession->parser, reply);
	iks_delete(reply);
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
	switch_safe_free(reply);
	return result;
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
		"<stream:stream xmlns='"IKS_NS_CLIENT"' xmlns:db='"IKS_NS_XMPP_DIALBACK"'"
		" from='%s' id='%s' xml:lang='en' version='1.0'"
		" xmlns:stream='"IKS_NS_XMPP_STREAMS"'><stream:features>"
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
	const char *xmlns, *mechanism;

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s, auth, state = %s\n", rsession->id, rayo_session_state_to_string(rsession->state));

	/* wrong state for authentication */
	if (rsession->state != SS_NEW) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "%s, auth UNEXPECTED, state = %s\n", rsession->id, rayo_session_state_to_string(rsession->state));
		/* TODO on_auth unexpected error */
		rsession->state = SS_ERROR;
		return;
	}

	/* unsupported authentication type */
	xmlns = iks_find_attrib_soft(node, "xmlns");
	if (strcmp(IKS_NS_XMPP_SASL, xmlns)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "%s, auth, state = %s, unsupported namespace: %s!\n", rsession->id, rayo_session_state_to_string(rsession->state), xmlns);
		/* TODO on_auth namespace error */
		rsession->state = SS_ERROR;
		return;
	}

	/* unsupported SASL authentication mechanism */
	mechanism = iks_find_attrib_soft(node, "mechanism");
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
		/* TODO use library for SASL! */
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
 * Handle <iq> message callback
 * @param user_data the Rayo session
 * @param pak the <iq> packet
 * @return IKS_FILTER_EAT
 */
static int on_iq(void *user_data, ikspak *pak)
{
	struct rayo_command_handler *handler = NULL;
	struct rayo_actor *actor = NULL;
	struct rayo_session *rsession = (struct rayo_session *)user_data;
	iks *iq = pak->x;
	iks *command = iks_child(iq);
	const char *iq_type = iks_find_attrib_soft(iq, "type");
	const char *to = iks_find_attrib_soft(iq, "to");
	const char *from = iks_find_attrib_soft(iq, "from");

	if (zstr(to)) {
		to = rsession->server_jid;
	}

	/* assume client JID */
	if (zstr(from)) {
		iks_insert_attrib(iq, "from", rsession->client_jid_full);
	}

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s, iq, state = %s\n", rsession->id, rayo_session_state_to_string(rsession->state));

	if (command) {
		actor = rayo_actor_locate(to);
		if (!actor) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Failed to locate %s\n", to);
			goto done;
		}

		handler = rayo_command_handler_find(actor, iq_type, iks_name(command), iks_find_attrib(command, "xmlns"));
		if (!handler) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Handler not found for %s, %s\n", to, iks_name(command));
			goto done;
		}

		switch (actor->type) {
		case RAT_MIXER: {
			struct rayo_mixer *mixer = (struct rayo_mixer *)actor->data;
			iks *response = handler->fn.mixer(mixer, iq);
			if (response) {
				iks_send(rsession->parser, response);
				iks_delete(response);
			}
			break;
		}
		case RAT_CALL: {
			struct rayo_call *call = (struct rayo_call *)actor->data;
			switch_core_session_t *session = switch_core_session_locate(rayo_call_get_uuid(call));
			if (!session) {
				/* trigger not found response */
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Session not found for %s\n", to);
				rayo_actor_unlock(actor);
				actor = NULL;
				goto done;
			}
			if (rayo_call_command_ok(rsession, call, session, iq)) {
				iks *response;
				switch_mutex_lock(actor->mutex);
				response = handler->fn.call(call, session, iq);
				switch_mutex_unlock(actor->mutex);
				call->idle_start_time = switch_micro_time_now();
				if (response) {
					iks_send(rsession->parser, response);
					iks_delete(response);
				}
			}
			switch_core_session_rwunlock(session);
			break;
		}
		case RAT_CALL_COMPONENT:
		case RAT_MIXER_COMPONENT: {
			struct rayo_component *component = (struct rayo_component *)actor->data;
			if (rayo_component_command_ok(rsession, component, iq)) {
				iks *response;
				switch_mutex_lock(actor->mutex);
				response = handler->fn.component(component, iq);
				switch_mutex_unlock(actor->mutex);
				if (response) {
					iks_send(rsession->parser, response);
					iks_delete(response);
				}
			}
			break;
		}
		case RAT_SERVER:
			if (rayo_server_command_ok(rsession, iq)) {
				handler->fn.server(rsession, iq);
			}
			break;
		}
	}

done:
	if (!actor) {
		iks *reply;
		if (zstr(iks_find_attrib(iq, "to"))) {
			iks_insert_attrib(iq, "to", rsession->server_jid);
		}
		if (zstr(iks_find_attrib(iq, "from"))) {
			iks_insert_attrib(iq, "from", rsession->client_jid_full);
		}
		reply = iks_new_iq_error(iq, STANZA_ERROR_ITEM_NOT_FOUND);
		iks_send(rsession->parser, reply);
		iks_delete(reply);
	} else if (!handler) {
		iks *reply;
		if (zstr(iks_find_attrib(iq, "to"))) {
			iks_insert_attrib(iq, "to", rsession->server_jid);
		}
		if (zstr(iks_find_attrib(iq, "from"))) {
			iks_insert_attrib(iq, "from", rsession->client_jid_full);
		}
		reply = iks_new_iq_error(iq, STANZA_ERROR_FEATURE_NOT_IMPLEMENTED);
		iks_send(rsession->parser, reply);
		iks_delete(reply);
	}

	rayo_actor_unlock(actor);

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

	rsession->idle = 0;

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s, node, state = %s, type = %s\n", rsession->id, rayo_session_state_to_string(rsession->state), iks_node_type_to_string(type));

	switch(type) {
	case IKS_NODE_START:
		if (rsession->state == SS_NEW) {
			rsession->server_jid = switch_core_strdup(rsession->pool, iks_find_attrib_soft(node, "to"));
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
 * Send event to mixer subscribers
 * @param mixer the mixer
 * @param rayo_event the event to send
 */
static void broadcast_mixer_event(struct rayo_mixer *mixer, iks *rayo_event)
{
	switch_hash_index_t *hi = NULL;
	for (hi = switch_core_hash_first(mixer->subscribers); hi; hi = switch_core_hash_next(hi)) {
		const void *key;
		void *val;
		struct rayo_mixer_subscriber *subscriber;
		switch_core_hash_this(hi, &key, NULL, &val);
		subscriber = (struct rayo_mixer_subscriber *)val;
		switch_assert(subscriber);
		iks_insert_attrib(rayo_event, "to", subscriber->jid);
		rayo_iks_send(rayo_event);
	}
}

/**
 * Handle mixer delete member event
 */
static void on_mixer_delete_member_event(struct rayo_mixer *mixer, switch_event_t *event)
{
	iks *delete_member_event, *x;
	const char *uuid = switch_event_get_header(event, "Unique-ID");
	struct rayo_call *call;
	struct rayo_mixer_member *member;
	struct rayo_mixer_subscriber *subscriber;

	/* not a rayo mixer */
	if (!mixer) {
		return;
	}

	/* remove member from mixer */
	member = (struct rayo_mixer_member *)switch_core_hash_find(mixer->members, uuid);
	if (!member) {
		/* not a member */
		return;
	}
	switch_core_hash_delete(mixer->members, uuid);

	/* flag call as available to join another mixer */
	call = rayo_call_locate(uuid);
	if (call) {
		call->joined = 0;
		rayo_call_unlock(call);
	}

	/* send mixer unjoined event to member DCP */
	delete_member_event = create_rayo_event("unjoined", RAYO_NS, member->jid, member->dcp_jid);
	x = iks_find(delete_member_event, "unjoined");
	iks_insert_attrib(x, "mixer-name", rayo_mixer_get_name(mixer));
	rayo_iks_send(delete_member_event);
	iks_delete(delete_member_event);

	/* broadcast member unjoined event to subscribers */
	delete_member_event = create_rayo_event("unjoined", RAYO_NS, rayo_mixer_get_jid(mixer), "");
	x = iks_find(delete_member_event, "unjoined");
	iks_insert_attrib(x, "call-id", uuid);
	broadcast_mixer_event(mixer, delete_member_event);
	iks_delete(delete_member_event);

	/* remove member DCP as subscriber to mixer */
	subscriber = (struct rayo_mixer_subscriber *)switch_core_hash_find(mixer->subscribers, member->dcp_jid);
	if (subscriber) {
		subscriber->ref_count--;
		if (subscriber->ref_count <= 0) {
			switch_core_hash_delete(mixer->subscribers, member->dcp_jid);
		}
	}
}

/**
 * Handle mixer destroy event
 */
static void on_mixer_destroy_event(struct rayo_mixer *mixer, switch_event_t *event)
{
	if (mixer) {
		/* remove from hash and destroy */
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "destroying mixer: %s\n", rayo_mixer_get_name(mixer));
		rayo_mixer_unlock(mixer); /* release original lock */
		rayo_mixer_destroy(mixer);
	} else {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "destroy: mixer not found\n");
	}
}

/**
 * Handle mixer add member event
 */
static void on_mixer_add_member_event(struct rayo_mixer *mixer, switch_event_t *event)
{
	iks *add_member_event = NULL, *x;
	const char *uuid = switch_event_get_header(event, "Unique-ID");
	struct rayo_call *call = rayo_call_locate(uuid);

	if (!mixer) {
		/* new mixer */
		const char *mixer_name = switch_event_get_header(event, "Conference-Name");
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "creating mixer: %s\n", mixer_name);
		mixer = rayo_mixer_create(mixer_name);
	}

	if (call) {
		struct rayo_mixer_member *member = NULL;
		/* add member DCP as subscriber to mixer */
		struct rayo_mixer_subscriber *subscriber = (struct rayo_mixer_subscriber *)switch_core_hash_find(mixer->subscribers, call->dcp_jid);
		if (!subscriber) {
			subscriber = switch_core_alloc(rayo_mixer_get_pool(mixer), sizeof(*subscriber));
			subscriber->ref_count = 0;
			subscriber->jid = switch_core_strdup(rayo_mixer_get_pool(mixer), call->dcp_jid);
			switch_core_hash_insert(mixer->subscribers, call->dcp_jid, subscriber);
		}
		subscriber->ref_count++;

		/* add call as member of mixer */
		member = switch_core_alloc(rayo_mixer_get_pool(mixer), sizeof(*member));
		member->jid = switch_core_strdup(rayo_mixer_get_pool(mixer), rayo_call_get_jid(call));
		member->dcp_jid = subscriber->jid;
		switch_core_hash_insert(mixer->members, uuid, member);

		call->joined = 1;

		/* send mixer joined event to member DCP */
		add_member_event = create_rayo_event("joined", RAYO_NS, rayo_call_get_jid(call), call->dcp_jid);
		x = iks_find(add_member_event, "joined");
		iks_insert_attrib(x, "mixer-name", rayo_mixer_get_name(mixer));
		rayo_iks_send(add_member_event);
		iks_delete(add_member_event);

		rayo_call_unlock(call);
	}

	/* broadcast member joined event to subscribers */
	add_member_event = create_rayo_event("joined", RAYO_NS, rayo_mixer_get_jid(mixer), "");
	x = iks_find(add_member_event, "joined");
	iks_insert_attrib(x, "call-id", uuid);
	broadcast_mixer_event(mixer, add_member_event);
	iks_delete(add_member_event);
}

/**
 * Receives mixer events from FreeSWITCH core and routes them to the proper Rayo session(s).
 * @param event received from FreeSWITCH core.  It will be destroyed by the core after this function returns.
 */
static void route_mixer_event(switch_event_t *event)
{
	const char *action = switch_event_get_header(event, "Action");
	const char *profile = switch_event_get_header(event, "Conference-Profile-Name");
	const char *mixer_name = switch_event_get_header(event, "Conference-Name");
	struct rayo_mixer *mixer = NULL;

	if (strcmp(profile, globals.mixer_conf_profile)) {
		/* don't care about other conferences */
		goto done;
	}

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "looking for mixer: %s\n", mixer_name);
	mixer = rayo_mixer_locate(mixer_name);

	if (!strcmp("add-member", action)) {
		on_mixer_add_member_event(mixer, event);
	} else if (!strcmp("conference-destroy", action)) {
		on_mixer_destroy_event(mixer, event);
	} else if (!strcmp("del-member", action)) {
		on_mixer_delete_member_event(mixer, event);
	}
	/* TODO speaking events */

done:
	rayo_mixer_unlock(mixer);
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
		switch_mutex_lock(globals.clients_mutex);
		rsession = (struct rayo_session *)switch_core_hash_find(globals.clients, dcp_jid);
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
		switch_mutex_unlock(globals.clients_mutex);
	}
}

/**
 * Handle call originate event - create rayo call and send <iq><ref> to client.
 * @param rsession The Rayo session
 * @param event the originate event
 */
static void on_call_originate_event(struct rayo_session *rsession, switch_event_t *event)
{
	switch_core_session_t *session = NULL;
	const char *uuid = switch_event_get_header(event, "Unique-ID");
	struct rayo_call *call = rayo_call_locate(uuid);

	if (call && (session = switch_core_session_locate(uuid))) {
		iks *response, *ref;

		switch_channel_set_private(switch_core_session_get_channel(session), "rayo_call_private", call);
		switch_core_session_rwunlock(session);

		/* send response to DCP */
		response = iks_new("iq");
		iks_insert_attrib(response, "from", rsession->server_jid);
		iks_insert_attrib(response, "to", rayo_call_get_dcp_jid(call));
		iks_insert_attrib(response, "id", call->dial_id);
		iks_insert_attrib(response, "type", "result");
		ref = iks_insert(response, "ref");
		iks_insert_attrib(ref, "xmlns", RAYO_NS);
		iks_insert_attrib(ref, "id", uuid);
		iks_send(rsession->parser, response);
		iks_delete(response);
		call->dial_id = NULL;
	}
	rayo_call_unlock(call);
}

/**
 * Add <header> to node
 * @param node to add <header> to
 * @param name of header
 * @param value of header
 */
static void add_header(iks *node, const char *name, const char *value)
{
	if (!zstr(name) && !zstr(value)) {
		iks *header = iks_insert(node, "header");
		iks_insert_attrib(header, "name", name);
		iks_insert_attrib(header, "value", value);
	}
}

/**
 * Get rayo cause code from FS hangup cause
 * @param cause FS hangup cause
 * @return rayo end cause
 */
static const char *switch_cause_to_rayo_cause(switch_call_cause_t cause)
{
	switch (cause) {
		case SWITCH_CAUSE_NONE:
		case SWITCH_CAUSE_NORMAL_CLEARING:
			return RAYO_END_REASON_HANGUP;

		case SWITCH_CAUSE_UNALLOCATED_NUMBER:
		case SWITCH_CAUSE_NO_ROUTE_TRANSIT_NET:
		case SWITCH_CAUSE_NO_ROUTE_DESTINATION:
		case SWITCH_CAUSE_CHANNEL_UNACCEPTABLE:
			return RAYO_END_REASON_ERROR;

		case SWITCH_CAUSE_CALL_AWARDED_DELIVERED:
			return RAYO_END_REASON_HANGUP;

		case SWITCH_CAUSE_USER_BUSY:
			return RAYO_END_REASON_BUSY;

		case SWITCH_CAUSE_NO_USER_RESPONSE:
		case SWITCH_CAUSE_NO_ANSWER:
			return RAYO_END_REASON_TIMEOUT;

		case SWITCH_CAUSE_SUBSCRIBER_ABSENT:
			return RAYO_END_REASON_ERROR;

		case SWITCH_CAUSE_CALL_REJECTED:
			return RAYO_END_REASON_REJECT;

		case SWITCH_CAUSE_NUMBER_CHANGED:
		case SWITCH_CAUSE_REDIRECTION_TO_NEW_DESTINATION:
		case SWITCH_CAUSE_EXCHANGE_ROUTING_ERROR:
		case SWITCH_CAUSE_DESTINATION_OUT_OF_ORDER:
		case SWITCH_CAUSE_INVALID_NUMBER_FORMAT:
			return RAYO_END_REASON_ERROR;

		case SWITCH_CAUSE_FACILITY_REJECTED:
			return RAYO_END_REASON_REJECT;

		case SWITCH_CAUSE_RESPONSE_TO_STATUS_ENQUIRY:
		case SWITCH_CAUSE_NORMAL_UNSPECIFIED:
			return RAYO_END_REASON_HANGUP;

		case SWITCH_CAUSE_NORMAL_CIRCUIT_CONGESTION:
		case SWITCH_CAUSE_NETWORK_OUT_OF_ORDER:
		case SWITCH_CAUSE_NORMAL_TEMPORARY_FAILURE:
		case SWITCH_CAUSE_SWITCH_CONGESTION:
		case SWITCH_CAUSE_ACCESS_INFO_DISCARDED:
		case SWITCH_CAUSE_REQUESTED_CHAN_UNAVAIL:
		case SWITCH_CAUSE_PRE_EMPTED:
		case SWITCH_CAUSE_FACILITY_NOT_SUBSCRIBED:
		case SWITCH_CAUSE_OUTGOING_CALL_BARRED:
		case SWITCH_CAUSE_INCOMING_CALL_BARRED:
		case SWITCH_CAUSE_BEARERCAPABILITY_NOTAUTH:
		case SWITCH_CAUSE_BEARERCAPABILITY_NOTAVAIL:
		case SWITCH_CAUSE_SERVICE_UNAVAILABLE:
		case SWITCH_CAUSE_BEARERCAPABILITY_NOTIMPL:
		case SWITCH_CAUSE_CHAN_NOT_IMPLEMENTED:
		case SWITCH_CAUSE_FACILITY_NOT_IMPLEMENTED:
		case SWITCH_CAUSE_SERVICE_NOT_IMPLEMENTED:
		case SWITCH_CAUSE_INVALID_CALL_REFERENCE:
		case SWITCH_CAUSE_INCOMPATIBLE_DESTINATION:
		case SWITCH_CAUSE_INVALID_MSG_UNSPECIFIED:
		case SWITCH_CAUSE_MANDATORY_IE_MISSING:
			return RAYO_END_REASON_ERROR;

		case SWITCH_CAUSE_MESSAGE_TYPE_NONEXIST:
		case SWITCH_CAUSE_WRONG_MESSAGE:
		case SWITCH_CAUSE_IE_NONEXIST:
		case SWITCH_CAUSE_INVALID_IE_CONTENTS:
		case SWITCH_CAUSE_WRONG_CALL_STATE:
		case SWITCH_CAUSE_RECOVERY_ON_TIMER_EXPIRE:
		case SWITCH_CAUSE_MANDATORY_IE_LENGTH_ERROR:
		case SWITCH_CAUSE_PROTOCOL_ERROR:
			return RAYO_END_REASON_ERROR;

		case SWITCH_CAUSE_INTERWORKING:
		case SWITCH_CAUSE_SUCCESS:
		case SWITCH_CAUSE_ORIGINATOR_CANCEL:
			return RAYO_END_REASON_HANGUP;

		case SWITCH_CAUSE_CRASH:
		case SWITCH_CAUSE_SYSTEM_SHUTDOWN:
		case SWITCH_CAUSE_LOSE_RACE:
		case SWITCH_CAUSE_MANAGER_REQUEST:
		case SWITCH_CAUSE_BLIND_TRANSFER:
		case SWITCH_CAUSE_ATTENDED_TRANSFER:
		case SWITCH_CAUSE_ALLOTTED_TIMEOUT:
		case SWITCH_CAUSE_USER_CHALLENGE:
		case SWITCH_CAUSE_MEDIA_TIMEOUT:
		case SWITCH_CAUSE_PICKED_OFF:
		case SWITCH_CAUSE_USER_NOT_REGISTERED:
		case SWITCH_CAUSE_PROGRESS_TIMEOUT:
		case SWITCH_CAUSE_INVALID_GATEWAY:
		case SWITCH_CAUSE_GATEWAY_DOWN:
		case SWITCH_CAUSE_INVALID_URL:
		case SWITCH_CAUSE_INVALID_PROFILE:
		case SWITCH_CAUSE_NO_PICKUP:
			return RAYO_END_REASON_ERROR;
	}
	return RAYO_END_REASON_HANGUP;
}

/**
 * Handle call end event
 * @param event the hangup event
 */
static void on_call_end_event(switch_event_t *event)
{
	struct rayo_call *call = rayo_call_locate(switch_event_get_header(event, "Unique-ID"));

	/* forward event to each offered client */
	if (call) {
		char *cause_str = switch_event_get_header(event, "variable_hangup_cause");
		switch_call_cause_t cause = SWITCH_CAUSE_NONE;
		int no_offered_clients = 1;
		switch_hash_index_t *hi = NULL;
		iks *revent = create_rayo_event("end", RAYO_NS,
			rayo_call_get_jid(call),
			rayo_call_get_dcp_jid(call));
		iks *end = iks_find(revent, "end");

		if (cause_str) {
			cause = switch_channel_str2cause(cause_str);
		}
		iks_insert(end, switch_cause_to_rayo_cause(cause));

		#if 0
		{
			char *event_str;
			if (switch_event_serialize(event, &event_str, SWITCH_FALSE) == SWITCH_STATUS_SUCCESS) {
				switch_log_printf(SWITCH_CHANNEL_UUID_LOG(rayo_call_get_uuid(call)), SWITCH_LOG_DEBUG, "%s\n", event_str);
				switch_safe_free(event_str);
			}
		}
		#endif

		/* add signaling headers */
		{
			switch_event_header_t *header;
			/* get all variables prefixed with sip_r_ */
			for (header = event->headers; header; header = header->next) {
				if (!strncmp("variable_sip_r_", header->name, 15)) {
					add_header(end, header->name + 15, header->value);
				}
			}
		}

		for (hi = switch_hash_first(NULL, call->pcps); hi; hi = switch_hash_next(hi)) {
			const void *key;
			void *val;
			const char *client_jid = NULL;
			switch_hash_this(hi, &key, NULL, &val);
			client_jid = (const char *)key;
			switch_assert(client_jid);
			iks_insert_attrib(revent, "to", client_jid);
			switch_log_printf(SWITCH_CHANNEL_UUID_LOG(rayo_call_get_uuid(call)), SWITCH_LOG_DEBUG, "Sending <end> to offered client %s\n", client_jid);
			rayo_iks_send(revent);
			no_offered_clients = 0;
		}

		if (no_offered_clients) {
			/* send to DCP only */
			switch_log_printf(SWITCH_CHANNEL_UUID_LOG(rayo_call_get_uuid(call)), SWITCH_LOG_DEBUG, "Sending <end> to DCP %s\n", rayo_call_get_dcp_jid(call));
			rayo_iks_send(revent);
		}

		iks_delete(revent);
		rayo_call_unlock(call); /* decrement ref from creation */
		rayo_call_destroy(call);
		rayo_call_unlock(call); /* decrement this ref */
	}
}

/**
 * Handle call answer event
 * @param rsession the Rayo session
 * @param event the answer event
 */
static void on_call_answer_event(struct rayo_session *rsession, switch_event_t *event)
{
	iks *revent = create_rayo_event("answered", RAYO_NS,
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
	iks *revent = create_rayo_event("ringing", RAYO_NS,
		switch_event_get_header(event, "variable_rayo_call_jid"),
		switch_event_get_header(event, "variable_rayo_dcp_jid"));
	iks_send(rsession->parser, revent);
	iks_delete(revent);
}

/**
 * Handle call bridge event
 * @param rsession the Rayo session
 * @param event the bridge event
 */
static void on_call_bridge_event(struct rayo_session *rsession, switch_event_t *event)
{
	const char *a_uuid = switch_event_get_header(event, "Unique-ID");
	const char *b_uuid = switch_event_get_header(event, "Bridge-B-Unique-ID");
	struct rayo_call *call = rayo_call_locate(a_uuid);
	struct rayo_call *b_call;

	/* send A-leg event */
	iks *revent = create_rayo_event("joined", RAYO_NS,
		switch_event_get_header(event, "variable_rayo_call_jid"),
		switch_event_get_header(event, "variable_rayo_dcp_jid"));
	iks *joined = iks_find(revent, "joined");
	iks_insert_attrib(joined, "call-id", b_uuid);

	if (call) {
		call->joined = 1;
		rayo_call_unlock(call);
	}
	iks_send(rsession->parser, revent);
	iks_delete(revent);

	/* send B-leg event */
	b_call = rayo_call_locate(b_uuid);
	if (b_call) {
		revent = create_rayo_event("joined", RAYO_NS, rayo_call_get_jid(b_call), rayo_call_get_dcp_jid(b_call));
		joined = iks_find(revent, "joined");
		rayo_call_unlock(b_call);
		iks_insert_attrib(joined, "call-id", a_uuid);

		b_call->joined = 1;

		rayo_iks_send(revent); /* DCP might be different, so can't send on this session */
		iks_delete(revent);
	}
}

/**
 * Handle call unbridge event
 * @param rsession the Rayo session
 * @param event the unbridge event
 */
static void on_call_unbridge_event(struct rayo_session *rsession, switch_event_t *event)
{
	const char *a_uuid = switch_event_get_header(event, "Unique-ID");
	const char *b_uuid = switch_event_get_header(event, "Bridge-B-Unique-ID");
	struct rayo_call *call = rayo_call_locate(a_uuid);
	struct rayo_call *b_call;

	/* send A-leg event */
	iks *revent = create_rayo_event("unjoined", RAYO_NS,
		switch_event_get_header(event, "variable_rayo_call_jid"),
		switch_event_get_header(event, "variable_rayo_dcp_jid"));
	iks *joined = iks_find(revent, "unjoined");
	iks_insert_attrib(joined, "call-id", b_uuid);
	iks_send(rsession->parser, revent);
	iks_delete(revent);

	if (call) {
		call->joined = 0;
		rayo_call_unlock(call);
	}

	/* send B-leg event */
	b_call = rayo_call_locate(b_uuid);
	if (b_call) {
		revent = create_rayo_event("unjoined", RAYO_NS, rayo_call_get_jid(b_call), rayo_call_get_dcp_jid(b_call));
		joined = iks_find(revent, "unjoined");
		iks_insert_attrib(joined, "call-id", a_uuid);
		rayo_iks_send(revent); /* DCP might be different, so can't send on this session */
		iks_delete(revent);

		b_call->joined = 0;
		rayo_call_unlock(b_call);
	}
}

/**
 * Handle call execute event
 * @param rsession the Rayo session
 * @param event the ringing event
 */
static void on_call_execute_event(struct rayo_session *rsession, switch_event_t *event)
{
	struct rayo_call *call = rayo_call_locate(switch_event_get_header(event, "Unique-ID"));
	if (call) {
		if (!strcmp("playback", switch_event_get_header(event, "Application"))) {
			switch_mutex_lock(call->actor->mutex);
			call->playing = 1;
			switch_log_printf(SWITCH_CHANNEL_UUID_LOG(rayo_call_get_uuid(call)), SWITCH_LOG_DEBUG, "Call started playing\n");
			switch_mutex_unlock(call->actor->mutex);
		}
		rayo_call_unlock(call);
	}
}

/**
 * Handle call execute complete event
 * @param rsession the Rayo session
 * @param event the ringing event
 */
static void on_call_execute_complete_event(struct rayo_session *rsession, switch_event_t *event)
{
	struct rayo_call *call = rayo_call_locate(switch_event_get_header(event, "Unique-ID"));
	if (call) {
		if (!strcmp("playback", switch_event_get_header(event, "Application"))) {
			switch_mutex_lock(call->actor->mutex);
			switch_log_printf(SWITCH_CHANNEL_UUID_LOG(rayo_call_get_uuid(call)), SWITCH_LOG_DEBUG, "Call stopped playing\n");
			call->playing = 0;
			switch_mutex_unlock(call->actor->mutex);
		}
		rayo_call_unlock(call);
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
		switch (event->event_id) {
		case SWITCH_EVENT_CHANNEL_ORIGINATE:
			on_call_originate_event(rsession, event);
			break;
		case SWITCH_EVENT_CHANNEL_DESTROY:
			on_call_end_event(event);
			break;
		case SWITCH_EVENT_CHANNEL_PROGRESS_MEDIA:
			on_call_ringing_event(rsession, event);
			break;
		case SWITCH_EVENT_CHANNEL_ANSWER:
			on_call_answer_event(rsession, event);
			break;
		case SWITCH_EVENT_CHANNEL_BRIDGE:
			on_call_bridge_event(rsession, event);
			break;
		case SWITCH_EVENT_CHANNEL_UNBRIDGE:
			on_call_unbridge_event(rsession, event);
			break;
		case SWITCH_EVENT_CHANNEL_EXECUTE:
			on_call_execute_event(rsession, event);
 			break;
		case SWITCH_EVENT_CHANNEL_EXECUTE_COMPLETE:
			on_call_execute_complete_event(rsession, event);
			break;
		case SWITCH_EVENT_CUSTOM: {
			char *event_subclass = switch_event_get_header(event, "Event-Subclass");
			if (!strcmp(RAYO_EVENT_XMPP_SEND, event_subclass)) {
				/* send raw XMPP message from FS */
				char *msg = switch_event_get_body(event);
				iks_send_raw(rsession->parser, msg);
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
	switch_memory_pool_t *pool;

	rsession->state = SS_DESTROY;

	/* remove session from map */
	switch_mutex_lock(globals.clients_mutex);
	switch_core_hash_delete(globals.clients, rsession->client_jid_full);
	switch_mutex_unlock(globals.clients_mutex);

	/* flush pending events */
	while (switch_queue_trypop(rsession->event_queue, &queue_item) == SWITCH_STATUS_SUCCESS) {
		switch_event_t *event = (switch_event_t *)queue_item;
		rayo_session_handle_event(rsession, event);
	}

	/* close connection */
	if (rsession->parser) {
		iks_disconnect(rsession->parser);
	}

	if (rsession->filter) {
		iks_filter_delete(rsession->filter);
	}

	if (rsession->parser) {
		iks_parser_delete(rsession->parser);
	}

	if (rsession->incoming) {
		switch_socket_shutdown(rsession->socket, SWITCH_SHUTDOWN_READWRITE);
		switch_socket_close(rsession->socket);
	}

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s Session destroyed\n", rsession->id);

	pool = rsession->pool;
	switch_core_destroy_memory_pool(&pool);
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
	iks_filter_add_rule(rsession->filter, on_iq, rsession,
		IKS_RULE_TYPE, IKS_PAK_IQ,
		IKS_RULE_SUBTYPE, IKS_TYPE_SET,
		IKS_RULE_DONE);
	iks_filter_add_rule(rsession->filter, on_iq, rsession,
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
		/* TODO connect error checking */
	} else {
		/* TODO make outbound connection */
	}

	/* set up pollfd to monitor listen socket */
	if (switch_socket_create_pollset(&read_pollfd, rsession->socket, SWITCH_POLLIN | SWITCH_POLLERR, rsession->pool) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s, create pollset error!\n", rsession->id);
		goto done;
	}

	while (rayo_session_ready(rsession)) {
		void *event;
		int result;

		/* read any messages from client */
		rsession->idle = 1;
		result = iks_recv(parser, 0);
		switch (result) {
		case IKS_OK:
			err_count = 0;
			break;
		case IKS_NET_RWERR:
		case IKS_NET_NOCONN:
		case IKS_NET_NOSOCK:
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "%s iks_recv() error = %s, ending session\n", rsession->id, iks_net_error_to_string(result));
			rsession->state = SS_ERROR;
			goto done;
		default:
			if (err_count++ == 0) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "%s iks_recv() error = %s\n", rsession->id, iks_net_error_to_string(result));
			}
			if (err_count >= 50) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "%s too many iks_recv() error = %s, ending session\n", rsession->id, iks_net_error_to_string(result));
				rsession->state = SS_ERROR;
				goto done;
			}
		}

		/* handle all queued events */
		while (switch_queue_trypop(rsession->event_queue, &event) == SWITCH_STATUS_SUCCESS) {
			rayo_session_handle_event(rsession, (switch_event_t *)event);
			rsession->idle = 0;
		}

		/* check for shutdown */
		if (rsession->state != SS_DESTROY && globals.shutdown && rsession->state != SS_SHUTDOWN) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "%s detected shutdown\n", rsession->id);
			iks_send_raw(rsession->parser, "</stream:stream>");
			rsession->state = SS_SHUTDOWN;
			rsession->idle = 0;
		}

		if (rsession->idle) {
			int fdr = 0;
			switch_poll(rsession->pollfd, 1, &fdr, 20000);
		} else {
			switch_os_yield();
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
	switch_socket_create_pollset(&rsession->pollfd, rsession->socket, SWITCH_POLLIN | SWITCH_POLLERR, pool);

	return rsession;
}

/**
 * Destroy the server
 * @param server the server
 */
static void rayo_server_destroy(struct rayo_server *server)
{
	/* shutdown server */
	switch_socket_shutdown(server->socket, SWITCH_SHUTDOWN_READWRITE);
	switch_socket_close(server->socket);

	rayo_actor_destroy(server->actor);
}

/**
 * @param server the server
 * @return the server memory pool
 */
static switch_memory_pool_t *rayo_server_get_pool(struct rayo_server *server)
{
	return server->actor->pool;
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
		rv = switch_sockaddr_info_get(&sa, server->addr, SWITCH_UNSPEC, server->port, 0, rayo_server_get_pool(server));
		if (rv)
			goto fail;
		rv = switch_socket_create(&server->socket, switch_sockaddr_get_family(sa), SOCK_STREAM, SWITCH_PROTO_TCP, rayo_server_get_pool(server));
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

		rv = switch_socket_create_pollset(&server->read_pollfd, server->socket, SWITCH_POLLIN | SWITCH_POLLERR, rayo_server_get_pool(server));
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

	rayo_server_destroy(server);

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
static switch_status_t rayo_server_create(const char *addr, const char *port)
{
	struct rayo_actor *actor = NULL;
	struct rayo_server *new_server = NULL;
	switch_thread_t *thread;
	switch_threadattr_t *thd_attr = NULL;

	if (zstr(addr)) {
		return SWITCH_STATUS_FALSE;
	}

	actor = rayo_actor_create(RAT_SERVER, "", addr, addr, (void **)&new_server, sizeof(*new_server));
	new_server->addr = switch_core_strdup(actor->pool, addr);
	new_server->port = zstr(port) ? IKS_JABBER_PORT : atoi(port);
	new_server->actor = actor;

	/* start the server thread */
	switch_threadattr_create(&thd_attr, actor->pool);
	switch_threadattr_detach_set(thd_attr, 1);
	switch_threadattr_stacksize_set(thd_attr, SWITCH_THREAD_STACKSIZE);
	switch_thread_create(&thread, thd_attr, rayo_server_thread, new_server, actor->pool);

	return SWITCH_STATUS_SUCCESS;
}

/**
 * Create an offer for a call
 * @param call the call
 * @param session the session
 * @return the offer
 */
static iks *rayo_create_offer(struct rayo_call *call, switch_core_session_t *session)
{
	switch_channel_t *channel = switch_core_session_get_channel(session);
	switch_caller_profile_t *profile = switch_channel_get_caller_profile(channel);
	iks *presence = iks_new("presence");
	iks *offer = iks_insert(presence, "offer");

	iks_insert_attrib(presence, "from", rayo_call_get_jid(call));
	iks_insert_attrib(offer, "from", profile->caller_id_number);
	iks_insert_attrib(offer, "to", profile->destination_number);
	iks_insert_attrib(offer, "xmlns", RAYO_NS);

	/* add signaling headers */
	{
		switch_event_header_t *var;
		add_header(offer, "from", switch_channel_get_variable(channel, "sip_full_from"));
		add_header(offer, "to", switch_channel_get_variable(channel, "sip_full_to"));
		add_header(offer, "via", switch_channel_get_variable(channel, "sip_full_via"));

		/* get all variables prefixed with sip_r_ */
		for (var = switch_channel_variable_first(channel); var; var = var->next) {
			if (!strncmp("sip_r_", var->name, 6)) {
				add_header(offer, var->name + 6, var->value);
			}
		}
		switch_channel_variable_last(channel);
	}

	return presence;
}

/**
 * Monitor rayo call activity - detect idle
 */
static switch_status_t rayo_call_on_read_frame(switch_core_session_t *session, switch_frame_t **frame, switch_io_flag_t flags, int i)
{
	switch_channel_t *channel = switch_core_session_get_channel(session);
	struct rayo_call *call = (struct rayo_call *)switch_channel_get_private(channel, "rayo_call_private");
	if (call) {
		switch_time_t now = switch_micro_time_now();
		switch_time_t idle_start = call->idle_start_time;
		int idle_duration_ms = (now - idle_start) / 1000;
		/* detect idle session (rayo-client has stopped controlling call) and terminate call */
		if (!rayo_call_is_joined(call) && idle_duration_ms > globals.max_idle_ms) {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_WARNING, "Ending abandoned call.  idle_duration_ms = %i ms\n", idle_duration_ms);
			switch_channel_hangup(channel, RAYO_CAUSE_HANGUP);
		}
	}
	return SWITCH_STATUS_SUCCESS;
}

#define RAYO_USAGE "[bridge <uuid>|conference <name>]"
/**
 * Offer call and park channel
 */
SWITCH_STANDARD_APP(rayo_app)
{
	int ok = 0;
	switch_channel_t *channel = switch_core_session_get_channel(session);
	struct rayo_call *call = (struct rayo_call *)switch_channel_get_private(channel, "rayo_call_private");
	const char *app = ""; /* optional app to execute */
	const char *app_args = ""; /* app args */

	/* is outbound call already under control? */
	if (switch_channel_direction(channel) == SWITCH_CALL_DIRECTION_OUTBOUND) {
		/* check origination args */
		if (!zstr(data)) {
			char *argv[2] = { 0 };
			char *args = switch_core_session_strdup(session, data);
			int argc = switch_separate_string(args, ' ', argv, sizeof(argv) / sizeof(argv[0]));
			if (argc) {
				if (!strcmp("conference", argv[0])) {
					app = "conference";
					app_args = argv[1];
				} else if (!strcmp("bridge", argv[0])) {
					app = "intercept";
					app_args = argv[1];
				} else {
					switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "Invalid rayo args: %s\n", data);
					goto done;
				}
			}
		}
		if (!call) {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_CRIT, "Missing rayo call!!\n");
			goto done;
		}
		ok = 1;
	} else {
		/* inbound call - offer control */
		switch_hash_index_t *hi = NULL;
		iks *offer = NULL;
		if (call) {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "Call is already under Rayo 3PCC!\n");
			goto done;
		}
		call = rayo_call_create(switch_core_session_get_uuid(session));
		switch_channel_set_variable(switch_core_session_get_channel(session), "rayo_call_jid", rayo_call_get_jid(call));
		switch_channel_set_private(switch_core_session_get_channel(session), "rayo_call_private", call);

		offer = rayo_create_offer(call, session);
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Offering call for Rayo 3PCC\n");

		/* Offer call to all ONLINE clients */
		/* TODO load balance offers so first session doesn't always get offer first? */
		switch_mutex_lock(globals.clients_mutex);
		for (hi = switch_hash_first(NULL, globals.clients); hi; hi = switch_hash_next(hi)) {
			struct rayo_session *rsession;
			const void *key;
			void *val;
			switch_hash_this(hi, &key, NULL, &val);
			rsession = (struct rayo_session *)val;
			switch_assert(rsession);

			/* is session available to take call? */
			if (rsession->state == SS_ONLINE) {
				ok = 1;
				switch_core_hash_insert(call->pcps, rsession->client_jid_full, "1");
				iks_insert_attrib(offer, "to", rsession->client_jid_full);
				rayo_iks_send(offer);
			}
			iks_delete(offer);
		}
		switch_mutex_unlock(globals.clients_mutex);

		/* nobody to offer to */
		if (!ok) {
			rayo_call_unlock(call); /* decrement ref from creation */
			rayo_call_destroy(call);
			switch_channel_hangup(channel, RAYO_CAUSE_DECLINE);
		}
	}

done:

	if (ok) {
		switch_channel_set_variable(channel, "hangup_after_bridge", "false");
		switch_channel_set_variable(channel, "transfer_after_bridge", "false");
		switch_channel_set_variable(channel, "park_after_bridge", "true");
		switch_channel_set_variable(channel, SWITCH_SEND_SILENCE_WHEN_IDLE_VARIABLE, "5000"); /* required so that output mixing works */
		switch_core_event_hook_add_read_frame(session, rayo_call_on_read_frame);
		if (!zstr(app)) {
			switch_core_session_execute_application(session, app, app_args);
		}
		switch_ivr_park(session, NULL);
	}
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

	/* set defaults */
	globals.max_idle_ms = 30000;
	globals.mixer_conf_profile = "sla";

	/* get params */
	{
		switch_xml_t settings = switch_xml_child(cfg, "settings");
		if (settings) {
			switch_xml_t param;
			for (param = switch_xml_child(settings, "param"); param; param = param->next) {
				const char *var = switch_xml_attr_soft(param, "name");
				const char *val = switch_xml_attr_soft(param, "value");
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "param: %s = %s\n", var, val);
				if (!strcasecmp(var, "max-idle-sec")) {
					if (switch_is_number(val)) {
						int max_idle_sec = atoi(val);
						if (max_idle_sec > 0) {
							globals.max_idle_ms = max_idle_sec * 1000;
						}
					}
				} else if (!strcasecmp(var, "mixer-conf-profile")) {
					if (!zstr(val)) {
						globals.mixer_conf_profile = switch_core_strdup(pool, val);
					}
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

	/* configure dial gateways */
	{
		switch_xml_t dial_gateways = switch_xml_child(cfg, "dial-gateways");

		/* set defaults */
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Setting default dial-gateways\n");
		dial_gateway_add("default", "sofia/gateway/outbound/", 0);
		dial_gateway_add("tel:", "sofia/gateway/outbound/", 4);
		dial_gateway_add("user", "", 0);
		dial_gateway_add("sofia", "", 0);

		if (dial_gateways) {
			switch_xml_t dg;
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Setting configured dial-gateways\n");
			for (dg = switch_xml_child(dial_gateways, "dial-gateway"); dg; dg = dg->next) {
				const char *uri_prefix = switch_xml_attr_soft(dg, "uriprefix");
				const char *dial_prefix = switch_xml_attr_soft(dg, "dialprefix");
				const char *strip_str = switch_xml_attr_soft(dg, "strip");
				int strip = 0;

				if (!zstr(strip_str) && switch_is_number(strip_str)) {
					strip = atoi(strip_str);
					if (strip < 0) {
						strip = 0;
					}
				}
				if (!zstr(uri_prefix)) {
					dial_gateway_add(uri_prefix, dial_prefix, strip);
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
				if (rayo_server_create(val, port) != SWITCH_STATUS_SUCCESS) {
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

static void rayo_actor_dump(struct rayo_actor *actor, switch_stream_handle_t *stream)
{
	stream->write_function(stream, "TYPE='%s',SUBTYPE='%s',ID='%s',JID='%s',REFS=%i", rayo_actor_type_to_string(actor->type), actor->subtype, actor->id, actor->jid, actor->ref_count);
}

static void rayo_session_dump(struct rayo_session *rsession, switch_stream_handle_t *stream)
{
	stream->write_function(stream, "JID='%s',STATE='%s'", rsession->client_jid_full, rayo_session_state_to_string(rsession->state));
}

SWITCH_STANDARD_API(rayo_api)
{
	switch_hash_index_t *hi;

	stream->write_function(stream, "CLIENTS:\n");
	switch_mutex_lock(globals.clients_mutex);
	for (hi = switch_core_hash_first(globals.clients); hi; hi = switch_core_hash_next(hi)) {
		struct rayo_session *rsession = NULL;
		const void *key;
		void *val;
		switch_core_hash_this(hi, &key, NULL, &val);
		rsession = (struct rayo_session *)val;
		switch_assert(rsession);
		stream->write_function(stream, "\t");
		rayo_session_dump(rsession, stream);
		stream->write_function(stream, "\n");
	}
	switch_mutex_unlock(globals.clients_mutex);

	stream->write_function(stream, "\nACTORS:\n");
	switch_mutex_lock(globals.actors_mutex);
	for (hi = switch_core_hash_first(globals.actors); hi; hi = switch_core_hash_next(hi)) {
		struct rayo_actor *actor = NULL;
		const void *key;
		void *val;
		switch_core_hash_this(hi, &key, NULL, &val);
		actor = (struct rayo_actor *)val;
		switch_assert(actor);
		stream->write_function(stream, "\t");
		rayo_actor_dump(actor, stream);
		stream->write_function(stream, "\n");
	}

	stream->write_function(stream, "\nDEAD ACTORS:\n");
	for (hi = switch_core_hash_first(globals.destroy_actors); hi; hi = switch_core_hash_next(hi)) {
		struct rayo_actor *actor = NULL;
		const void *key;
		void *val;
		switch_core_hash_this(hi, &key, NULL, &val);
		actor = (struct rayo_actor *)val;
		switch_assert(actor);
		stream->write_function(stream, "\t");
		rayo_actor_dump(actor, stream);
		stream->write_function(stream, "\n");
	}
	switch_mutex_unlock(globals.actors_mutex);

	return SWITCH_STATUS_SUCCESS;
}

/**
 * Load module
 */
SWITCH_MODULE_LOAD_FUNCTION(mod_rayo_load)
{
	switch_api_interface_t *api_interface;
	switch_application_interface_t *app_interface;

	*module_interface = switch_loadable_module_create_module_interface(pool, modname);

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Loading module\n");

	memset(&globals, 0, sizeof(globals));
	globals.pool = pool;
	switch_thread_rwlock_create(&globals.shutdown_rwlock, pool);
	switch_core_hash_init(&globals.users, pool);
	switch_core_hash_init(&globals.command_handlers, pool);
	switch_core_hash_init(&globals.clients, pool);
	switch_mutex_init(&globals.clients_mutex, SWITCH_MUTEX_UNNESTED, pool);
	switch_core_hash_init(&globals.actors, pool);
	switch_core_hash_init(&globals.destroy_actors, pool);
	switch_core_hash_init(&globals.actors_by_id, pool);
	switch_mutex_init(&globals.actors_mutex, SWITCH_MUTEX_NESTED, pool);
	switch_core_hash_init(&globals.dial_gateways, pool);

	/* server commands */
	rayo_server_command_handler_add("set:"IKS_NS_XMPP_BIND":bind", on_iq_set_xmpp_bind);
	rayo_server_command_handler_add("set:"IKS_NS_XMPP_SESSION":session", on_iq_set_xmpp_session);
	rayo_server_command_handler_add("get:"IKS_NS_XMPP_PING":ping", on_iq_xmpp_ping);
	rayo_server_command_handler_add("get:"IKS_NS_XMPP_DISCO":query", on_iq_get_xmpp_disco);
	rayo_server_command_handler_add("set:"RAYO_NS":dial", on_rayo_dial);

	/* Rayo call commands */
	rayo_call_command_handler_add("set:"RAYO_NS":accept", on_rayo_accept);
	rayo_call_command_handler_add("set:"RAYO_NS":answer", on_rayo_answer);
	rayo_call_command_handler_add("set:"RAYO_NS":redirect", on_rayo_redirect);
	rayo_call_command_handler_add("set:"RAYO_NS":reject", on_rayo_hangup); /* handles both reject and hangup */
	rayo_call_command_handler_add("set:"RAYO_NS":hangup", on_rayo_hangup); /* handles both reject and hangup */
	rayo_call_command_handler_add("set:"RAYO_NS":join", on_rayo_join);
	rayo_call_command_handler_add("set:"RAYO_NS":unjoin", on_rayo_unjoin);

	switch_event_bind(modname, SWITCH_EVENT_CHANNEL_ORIGINATE, NULL, route_call_event, NULL);
	switch_event_bind(modname, SWITCH_EVENT_CHANNEL_PROGRESS_MEDIA, NULL, route_call_event, NULL);
	switch_event_bind(modname, SWITCH_EVENT_CHANNEL_ANSWER, NULL, route_call_event, NULL);
	switch_event_bind(modname, SWITCH_EVENT_CHANNEL_DESTROY, NULL, on_call_end_event, NULL);
	switch_event_bind(modname, SWITCH_EVENT_CHANNEL_BRIDGE, NULL, route_call_event, NULL);
	switch_event_bind(modname, SWITCH_EVENT_CHANNEL_UNBRIDGE, NULL, route_call_event, NULL);
	switch_event_bind(modname, SWITCH_EVENT_CHANNEL_EXECUTE, NULL, route_call_event, NULL);
	switch_event_bind(modname, SWITCH_EVENT_CHANNEL_EXECUTE_COMPLETE, NULL, route_call_event, NULL);
	switch_event_bind(modname, SWITCH_EVENT_CUSTOM, RAYO_EVENT_XMPP_SEND, route_call_event, NULL);

	switch_event_bind(modname, SWITCH_EVENT_CUSTOM, "conference::maintenance", route_mixer_event, NULL);

	SWITCH_ADD_APP(app_interface, "rayo", "Offer call control to Rayo client(s)", "", rayo_app, RAYO_USAGE, SAF_SUPPORT_NOMEDIA);
	SWITCH_ADD_API(api_interface, "rayo", "Query rayo status", rayo_api, "show");

	/* set up rayo components */
	rayo_components_load(module_interface, pool);

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

	rayo_components_shutdown();

	/* cleanup module */
	switch_event_unbind_callback(route_call_event);
	switch_event_unbind_callback(on_call_end_event);
	switch_event_unbind_callback(route_mixer_event);

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
