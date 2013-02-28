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
 * rayo_components.c -- Rayo component interface
 *
 */

#include "rayo_components.h"

#include <switch.h>
#include "mod_rayo.h"
#include "iks_helpers.h"

/**
 * A call component
 */
struct call_component_interface {
	rayo_call_component_start_fn start;
	rayo_call_component_stop_fn stop;
};

static struct {
	/** call components mapped by command */
	switch_hash_t *call_component_interfaces;
	/** active components mapped by JID */
	switch_hash_t *active_components;
	/** synchronizes access to active components */
	switch_mutex_t *mutex;
	/** Memory pool to use */
	switch_memory_pool_t *pool;
} globals;

/**
 * Create a component ref
 * @param call the rayo call
 * @param type the component type "(nput/output/record/prompt/etc)
 * @return the component ref
 */
static char *call_component_ref_create(struct rayo_call *call, const char *type)
{
	return switch_core_session_sprintf(call->session, "%s-%d", type, call->next_ref++);
}

/**
 * Create a component Jabber ID
 * @param call the rayo call
 * @param component_ref the component ref
 * @return the Jabber ID
 */
static char *call_component_jid_create(struct rayo_call *call, const char *component_ref)
{
	return switch_core_session_sprintf(call->session, "%s/%s", call->jid, component_ref);
}

/**
 * Send IQ error to controlling client from call
 * @param call the call
 * @param iq the request that caused the error
 * @param error the error message
 */
void rayo_call_component_send_iq_error(struct rayo_call *call, iks *iq, const char *error_name, const char *error_type)
{
	iks *response = iks_new_iq_error(iq, error_name, error_type);
	rayo_call_iks_send(call, response);
	iks_delete(response);
}

/**
 * Notify of new call component
 * @param call the call
 * @param iq that requested the component
 * @param type the type of component
 * @return the component JID
 */
const char *rayo_call_component_send_start(struct rayo_call *call, iks *iq, const char *type)
{
	iks *x, *response = NULL;
	const char *ref = call_component_ref_create(call, type);
	const char *jid = call_component_jid_create(call, ref);

	/* add to set of active components */
	switch_mutex_lock(globals.mutex);
	/* For now, we only have call components so a struct isn't required in the hash value */
	switch_core_hash_insert(globals.active_components, jid, type);
	switch_mutex_unlock(globals.mutex);

	response = iks_new_iq_result(iq);
	x = iks_insert(response, "ref");
	iks_insert_attrib(x, "xmlns", RAYO_NS);
	iks_insert_attrib(x, "id", ref);
	rayo_call_iks_send(call, response);
	iks_delete(response);
	
	return jid;
}

/**
 * Send component complete presence to client
 * @param call the call
 * @param jid the component JID
 * @param reason the completion reason
 * @param reason_namespace the completion reason namespace
 * @param reason_detail optional detail
 */
void rayo_call_component_send_complete(struct rayo_call *call, const char *jid, const char *reason, const char *reason_namespace)
{
	switch_channel_t *channel = switch_core_session_get_channel(call->session);
	iks *response = iks_new("presence");
	iks *x;
	iks_insert_attrib(response, "from", jid);
	iks_insert_attrib(response, "to", switch_channel_get_variable(channel, "rayo_dcp_jid"));
	iks_insert_attrib(response, "type", "unavailable");
	x = iks_insert(response, "complete");
	iks_insert_attrib(x, "xmlns", RAYO_EXT_NS);
	x = iks_insert(x, reason);
	iks_insert_attrib(x, "xmlns", reason_namespace);
	rayo_call_iks_send(call, response);
	iks_delete(response);

	/* remove from set of active components */
	switch_mutex_lock(globals.mutex);
	switch_core_hash_delete(globals.active_components, jid);
	switch_mutex_unlock(globals.mutex);
}

#define RAYO_COMPONENT_USAGE ""
/**
 * Process call components (output, input, prompt, record)
 */
SWITCH_STANDARD_APP(rayo_call_component_app)
{
	iksparser *parser = NULL;
	iks *iq;
	char *command;
	struct rayo_call *call = rayo_call_get(session);
	struct call_component_interface *component_interface = NULL;

	switch_mutex_lock(call->mutex);
	if (!call && zstr(call->dcp_jid)) {
		switch_mutex_unlock(call->mutex);
		/* shouldn't happen if APP was executed by this module */
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "No Rayo client controlling this session!\n");
		goto done;
	}
	switch_mutex_unlock(call->mutex);

	if (zstr(data)) {
		/* shouldn't happen if APP was executed by this module */
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Missing args!\n");
		/* can't send iq error- no <iq> request! */
		goto done;
	}

	parser = iks_dom_new(&iq);
	if (!parser) {
		goto done;
	}
	if (iks_parse(parser, data, 0, 1) != IKS_OK) {
		/* shouldn't happen if APP was executed by this module */
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Bad request!\n");
		/* can't send iq error- no <iq> request! */
		goto done;
	}

	if (!iks_has_children(iq)) {
		/* shouldn't happen if APP was executed by this module */
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Bad request!\n");
		rayo_call_component_send_iq_error(call, iq, STANZA_ERROR_BAD_REQUEST);
		goto done;
	} 

	/* execute component start function */
	command = iks_name(iks_child(iq));
	component_interface = switch_core_hash_find(globals.call_component_interfaces, command);
	if (component_interface && component_interface->start) {
		component_interface->start(call, iq);
	} else {
		rayo_call_component_send_iq_error(call, iq, STANZA_ERROR_FEATURE_NOT_IMPLEMENTED);
	}

done:
	if (iq) {
		iks_delete(iq);
	}
	if (parser) {
		iks_parser_delete(parser);
	}
}

/**
 * Handle Rayo call Component request
 * @param server_jid the server JID
 * @param call the Rayo call
 * @param node the <iq> node
 * @return the response
 */
static iks *on_rayo_call_component(const char *server_jid, struct rayo_call *call, iks *node)
{
	iks *response = NULL;
	char *play = iks_string(NULL, node);
	/* forward document to call thread by executing custom application */
	if (!play || switch_core_session_execute_application_async(call->session, "rayo_call_component", play) != SWITCH_STATUS_SUCCESS) {
		response = iks_new_iq_error(node, STANZA_ERROR_INTERNAL_SERVER_ERROR);
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(call->session), SWITCH_LOG_INFO, "Failed to execute rayo_call_component!\n");
	}
	if (play) {
		iks_free(play);
	}
	return response;
}

/**
 * Handle <iq><stop> request
 * @param server_jid the server JID
 * @param call the Rayo call
 * @param node the <iq> node
 * @return the response
 */
static iks *on_rayo_stop(const char *server_jid, struct rayo_call *call, iks *node)
{
	char *component_jid = iks_find_attrib(node, "to");
	iks *response = NULL;
	const char *component = NULL;

	switch_mutex_lock(globals.mutex);
	component = switch_core_hash_find(globals.active_components, component_jid);
	switch_mutex_unlock(globals.mutex);
	
	if (zstr(component)) {
		response = iks_new_iq_error(node, STANZA_ERROR_ITEM_NOT_FOUND);
	} else {
		struct call_component_interface *component_interface = switch_core_hash_find(globals.call_component_interfaces, component);
		if (component_interface && component_interface->stop) {
			response = component_interface->stop(call, node);
		} else {
			response = iks_new_iq_error(node, STANZA_ERROR_FEATURE_NOT_IMPLEMENTED);
		}
	}
	return response;
}

/**
 * Register rayo component callbacks
 * @param command the command to start the component
 * @param start the start function
 * @param stop the stop function
 */
void rayo_call_component_interface_add(const char *command, rayo_call_component_start_fn start, rayo_call_component_stop_fn stop)
{
	struct call_component_interface *component = switch_core_alloc(globals.pool, sizeof(*component));
	char *short_command = strrchr(command, ':');
	short_command++;
	component->start = start;
	component->stop = stop;

	/* maps command without namespace to component callbacks */
	switch_core_hash_insert(globals.call_component_interfaces, short_command, component); 

	/* maps full command to call component routing function */
	rayo_command_handler_add(command, on_rayo_call_component);
}

/**
 * Handle configuration
 */
switch_status_t rayo_components_load(switch_loadable_module_interface_t **module_interface, switch_memory_pool_t *pool)
{
	switch_application_interface_t *app_interface;

	rayo_command_handler_add("set:"RAYO_NS":stop", on_rayo_stop);

	SWITCH_ADD_APP(app_interface, "rayo_call_component", "Execute Rayo call component (internal module use only)", "", rayo_call_component_app, RAYO_COMPONENT_USAGE, 0);

	switch_core_hash_init(&globals.call_component_interfaces, pool);
	switch_core_hash_init(&globals.active_components, pool);
	switch_mutex_init(&globals.mutex, SWITCH_MUTEX_UNNESTED, pool);
	globals.pool = pool;

	rayo_input_component_load();
	rayo_output_component_load();
	rayo_record_component_load();
	rayo_prompt_component_load();

	return SWITCH_STATUS_SUCCESS;
}

/**
 * Handle shutdown
 */
switch_status_t rayo_components_shutdown(void)
{
	rayo_input_component_shutdown();
	rayo_output_component_shutdown();
	rayo_record_component_shutdown();
	rayo_prompt_component_shutdown();
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