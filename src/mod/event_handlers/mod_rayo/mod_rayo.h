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
 * mod_rayo.h -- Rayo server / node implementation.  Allows MxN clustering of FreeSWITCH and Rayo Clients (like Adhearsion)
 *
 */
#ifndef MOD_RAYO_H
#define MOD_RAYO_H

#include <switch.h>
#include <iksemel.h>

#define RAYO_EVENT_XMPP_SEND "rayo::xmpp_send"

#define RAYO_VERSION "1"
#define RAYO_BASE "urn:xmpp:rayo:"

#define RAYO_NS RAYO_BASE RAYO_VERSION
#define RAYO_CLIENT_NS RAYO_BASE "client:" RAYO_VERSION

struct rayo_actor;
struct rayo_call;
struct rayo_mixer;
struct rayo_component;

typedef void (* rayo_actor_cleanup_fn)(struct rayo_actor *);
typedef void (* rayo_actor_event_fn)(struct rayo_actor *, switch_event_t *event);

/**
 * Type of actor
 */
enum rayo_actor_type {
	RAT_CLIENT,
	RAT_SERVER,
	RAT_CALL,
	RAT_MIXER,
	RAT_CALL_COMPONENT,
	RAT_MIXER_COMPONENT
};

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
	/** number of users of this actor */
	int ref_count;
	/** destroy flag */
	int destroy;
	/** optional cleanup */
	rayo_actor_cleanup_fn cleanup_fn;
	/** optional event handling function */
	rayo_actor_event_fn event_fn;
};

/**
 * A Rayo component
 */
struct rayo_component {
	/** base actor class */
	struct rayo_actor base;
	/** component type (input/output/prompt/etc) */
	const char *type;
	/** parent to this component */
	struct rayo_actor *parent;
	/** owning client JID */
	const char *client_jid;
	/** external ref */
	const char *ref;
};

#define RAYO_COMPONENT(subclass) ((struct rayo_component *)subclass)

extern struct rayo_actor *rayo_actor_locate(const char *jid, const char *file, int line);
extern struct rayo_actor *rayo_actor_locate_by_id(const char *id, const char *file, int line);
extern int rayo_actor_seq_next(struct rayo_actor *actor);
extern void rayo_actor_set_event_fn(struct rayo_actor *actor, rayo_actor_event_fn event);
extern void rayo_actor_rdlock(struct rayo_actor *actor, const char *file, int line);
extern void rayo_actor_unlock(struct rayo_actor *actor, const char *file, int line);
extern void rayo_actor_destroy(struct rayo_actor *actor, const char *file, int line);
#define RAYO_LOCATE(jid) rayo_actor_locate(jid, __FILE__, __LINE__)
#define RAYO_LOCATE_BY_ID(id) rayo_actor_locate_by_id(id, __FILE__, __LINE__)
#define RAYO_SET_EVENT_FN(actor, event) rayo_actor_set_event_fn(RAYO_ACTOR(actor), event)
#define RAYO_ACTOR(x) ((struct rayo_actor *)x)
#define RAYO_JID(x) RAYO_ACTOR(x)->jid
#define RAYO_ID(x) RAYO_ACTOR(x)->id
#define RAYO_POOL(x) RAYO_ACTOR(x)->pool
#define RAYO_RDLOCK(x) rayo_actor_rdlock(RAYO_ACTOR(x), __FILE__, __LINE__)
#define RAYO_UNLOCK(x) rayo_actor_unlock(RAYO_ACTOR(x), __FILE__, __LINE__)
#define RAYO_DESTROY(x) rayo_actor_destroy(RAYO_ACTOR(x), __FILE__, __LINE__)
#define RAYO_SEQ_NEXT(x) rayo_actor_seq_next(RAYO_ACTOR(x))

extern const char *rayo_call_get_dcp_jid(struct rayo_call *call);

#define rayo_mixer_get_name(mixer) RAYO_ID(mixer)

#define rayo_component_init(component, pool, type, id, parent, client_jid) _rayo_component_init(component, pool, type, id, parent, client_jid, __FILE__, __LINE__)
extern struct rayo_component *_rayo_component_init(struct rayo_component *component, switch_memory_pool_t *pool, const char *type, const char *id, struct rayo_actor *parent, const char *client_jid, const char *file, int line);

typedef iks *(*rayo_call_command_handler)(struct rayo_call *, switch_core_session_t *session, iks *);
extern void rayo_call_command_handler_add(const char *name, rayo_call_command_handler fn);

typedef iks *(*rayo_mixer_command_handler)(struct rayo_mixer *, iks *);
extern void rayo_mixer_command_handler_add(const char *name, rayo_mixer_command_handler fn);

typedef iks *(*rayo_component_command_handler)(struct rayo_component *, iks *);
extern void rayo_call_component_command_handler_add(const char *subtype, const char *name, rayo_component_command_handler fn);
extern void rayo_mixer_component_command_handler_add(const char *subtype, const char *name, rayo_component_command_handler fn);

extern void rayo_send(iks *msg);

#endif


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
