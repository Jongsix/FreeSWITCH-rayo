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

#define RAYO_VERSION "1"
#define RAYO_BASE "urn:xmpp:rayo:"

#define RAYO_NS RAYO_BASE RAYO_VERSION
#define RAYO_CLIENT_NS RAYO_BASE "client:" RAYO_VERSION

struct rayo_actor;
struct rayo_call;
struct rayo_mixer;
struct rayo_component;

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

extern const char *rayo_actor_get_id(struct rayo_actor *actor);
extern const char *rayo_actor_get_jid(struct rayo_actor *actor);
extern switch_memory_pool_t *rayo_actor_get_pool(struct rayo_actor *actor);
extern int rayo_actor_seq_next(struct rayo_actor *actor);

extern struct rayo_actor *rayo_call_get_actor(struct rayo_call *call);
#define rayo_call_get_jid(call) rayo_actor_get_jid(rayo_call_get_actor(call))
extern const char *rayo_call_get_dcp_jid(struct rayo_call *call);
#define rayo_call_get_uuid(call) rayo_actor_get_id(rayo_call_get_actor(call))
#define rayo_call_get_pool(call) rayo_actor_get_pool(rayo_call_get_actor(call))

extern struct rayo_actor *rayo_mixer_get_actor(struct rayo_mixer *mixer);
#define rayo_mixer_get_name(mixer) rayo_actor_get_id(rayo_mixer_get_actor(mixer))
#define rayo_mixer_get_jid(mixer) rayo_actor_get_jid(rayo_mixer_get_actor(mixer))
#define rayo_mixer_get_pool(mixer) rayo_actor_get_pool(rayo_mixer_get_actor(mixer))

extern struct rayo_actor *rayo_component_get_actor(struct rayo_component *component);
#define rayo_component_locate(id) _rayo_component_locate(id, __FILE__, __LINE__)
extern struct rayo_component *_rayo_component_locate(const char *id, const char *file, int line);
#define rayo_component_unlock(component) _rayo_component_unlock(component, __FILE__, __LINE__)
extern void _rayo_component_unlock(struct rayo_component *component, const char *file, int line);
#define rayo_component_create(type, id, parent, client_jid) _rayo_component_create(type, id, parent, client_jid, __FILE__, __LINE__)
extern struct rayo_component *_rayo_component_create(const char *type, const char *id, struct rayo_actor *parent, const char *client_jid, const char *file, int line);
#define rayo_component_destroy(component) _rayo_component_destroy(component, __FILE__, __LINE__)
extern void _rayo_component_destroy(struct rayo_component *component, const char *file, int line);
#define rayo_component_get_id(component) rayo_actor_get_id(rayo_component_get_actor(component))
extern const char *rayo_component_get_ref(struct rayo_component *component);
#define rayo_component_get_jid(component) rayo_actor_get_jid(rayo_component_get_actor(component))
extern const char *rayo_component_get_parent_id(struct rayo_component *component);
extern enum rayo_actor_type rayo_component_get_parent_type(struct rayo_component *component);
extern const char *rayo_component_get_client_jid(struct rayo_component *component);
#define rayo_component_get_pool(component) rayo_actor_get_pool(rayo_component_get_actor(component))
extern void *rayo_component_get_data(struct rayo_component *component);
extern void rayo_component_set_data(struct rayo_component *component, void *data);

typedef iks *(*rayo_call_command_handler)(struct rayo_call *, switch_core_session_t *session, iks *);
extern void rayo_call_command_handler_add(const char *name, rayo_call_command_handler fn);

typedef iks *(*rayo_mixer_command_handler)(struct rayo_mixer *, iks *);
extern void rayo_mixer_command_handler_add(const char *name, rayo_mixer_command_handler fn);

typedef iks *(*rayo_component_command_handler)(struct rayo_component *, iks *);
extern void rayo_call_component_command_handler_add(const char *subtype, const char *name, rayo_component_command_handler fn);
extern void rayo_mixer_component_command_handler_add(const char *subtype, const char *name, rayo_component_command_handler fn);

extern void rayo_iks_send(iks *msg);

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
