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
struct call_component {
	rayo_call_component_fn start;
	rayo_call_component_fn stop;
};

static struct {
	/** call components mapped by command */
	switch_hash_t *call_components;
	/** active components mapped by JID */
	switch_hash_t *active_components;
	/** Memory pool to use */
	switch_memory_pool_t *pool;
} globals;

/**
 * Create a component ref
 * @param call the rayo call
 * @param type the component type "(nput/output/record/prompt/etc)
 * @return the component ref
 */
char *rayo_call_component_ref_create(struct rayo_call *call, const char *type)
{
	return switch_core_session_sprintf(call->session, "%s-%d", type, call->next_ref++);
}

/**
 * Create a component Jabber ID
 * @param call the rayo call
 * @param component_ref the component ref
 * @return the Jabber ID
 */
char *rayo_call_component_jid_create(struct rayo_call *call, char *component_ref)
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
	switch_channel_t *channel = switch_core_session_get_channel(call->session);
	iks *response = iks_new_iq_error(iq,
		switch_channel_get_variable(channel, "rayo_call_jid"),
		switch_channel_get_variable(channel, "rayo_dcp_jid"),
		error_name, error_type);
	rayo_call_iks_send(call, response);
	iks_delete(response);
}

/**
 * Send component ref to controlling client from call
 * @param call the call
 * @param iq the request that requested the component
 * @param ref the component ref
 */
void rayo_call_component_send_ref(struct rayo_call *call, iks *iq, const char *ref)
{
	switch_channel_t *channel = switch_core_session_get_channel(call->session);
	iks *x, *response = NULL;

	response = iks_new_iq_result(
		switch_channel_get_variable(channel, "rayo_call_jid"),
		switch_channel_get_variable(channel, "rayo_dcp_jid"),
		iks_find_attrib(iq, "id"));
	x = iks_insert(response, "ref");
	iks_insert_attrib(x, "xmlns", "urn:xmpp:rayo:1");
	iks_insert_attrib(x, "id", ref);

	rayo_call_iks_send(call, response);
	iks_delete(response);

	/* TODO remember active call component */
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
	iks_insert_attrib(x, "xmlns", "urn:xmpp:rayo:ext:1");
	x = iks_insert(x, reason);
	iks_insert_attrib(x, "xmlns", reason_namespace);
	rayo_call_iks_send(call, response);
	iks_delete(response);
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
	struct call_component *component = NULL;

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
	component = switch_core_hash_find(globals.call_components, command);
	if (component && component->start) {
		component->start(session, call, iq);
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
		response = iks_new_iq_error(node, call->jid, call->dcp_jid, STANZA_ERROR_INTERNAL_SERVER_ERROR);
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
	if (!strcmp(call->jid, component_jid) || !strcmp(server_jid, component_jid)) {
		/* call/server instead of component */
		response = iks_new_iq_error(node, component_jid, call->dcp_jid, STANZA_ERROR_FEATURE_NOT_IMPLEMENTED);
	} else if (zstr(call->output_jid) || strcmp(call->output_jid, component_jid)) {
		/* component doesn't exist */
		response = iks_new_iq_error(node, component_jid, call->dcp_jid, STANZA_ERROR_ITEM_NOT_FOUND);
	} else if (switch_core_session_execute_application_async(call->session, "break", "") != SWITCH_STATUS_SUCCESS) {
		/* failed to send break */
		response = iks_new_iq_error(node, component_jid, call->dcp_jid, STANZA_ERROR_INTERNAL_SERVER_ERROR);
	} else {
		/* success */
		response = iks_new_iq_result(component_jid, call->dcp_jid, iks_find_attrib(node, "id"));
	}
	return response;
}

/**
 * Register rayo component callbacks
 * @param command the command to start the component
 * @param start the start function
 * @param stop the stop function
 */
void rayo_call_component_add(const char *command, rayo_call_component_fn start, rayo_call_component_fn stop)
{
	struct call_component *component = switch_core_alloc(globals.pool, sizeof(*component));
	char *short_command = strrchr(command, ':');
	short_command++;
	component->start = start;
	component->stop = stop;

	/* maps command without namespace to component callbacks */
	switch_core_hash_insert(globals.call_components, short_command, component); 

	/* maps full command to call component routing function */
	rayo_command_handler_add(command, on_rayo_call_component);
}

/**
 * Handle configuration
 */
switch_status_t rayo_components_load(switch_loadable_module_interface_t **module_interface, switch_memory_pool_t *pool)
{
	switch_application_interface_t *app_interface;

	rayo_command_handler_add("urn:xmpp:rayo:ext:1:stop", on_rayo_stop);

	SWITCH_ADD_APP(app_interface, "rayo_call_component", "Execute Rayo call component (internal module use only)", "", rayo_call_component_app, RAYO_COMPONENT_USAGE, 0);

	switch_core_hash_init(&globals.call_components, pool);
	switch_core_hash_init(&globals.active_components, pool);
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