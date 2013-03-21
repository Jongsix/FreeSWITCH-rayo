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
 * Send IQ error to controlling client from call
 * @param call the call
 * @param iq the request that caused the error
 * @param error the error message
 */
void rayo_component_send_iq_error(iks *iq, const char *error_name, const char *error_type)
{
	iks *response = iks_new_iq_error(iq, error_name, error_type);
	rayo_iks_send(response);
	iks_delete(response);
}

/**
 * Send IQ error to controlling client from call
 * @param call the call
 * @param iq the request that caused the error
 * @param error the error message
 * @param detail text
 */
void rayo_component_send_iq_error_detailed(iks *iq, const char *error_name, const char *error_type, const char *detail)
{
	iks *response = iks_new_iq_error_detailed(iq, error_name, error_type, detail);
	rayo_iks_send(response);
	iks_delete(response);
}

/**
 * Send component start reply
 * @param component the component
 * @param iq the start request
 */
void rayo_component_send_start(struct rayo_component *component, iks *iq)
{
	iks *response = iks_new_iq_result(iq);
	iks *ref = iks_insert(response, "ref");
	iks_insert_attrib(ref, "xmlns", RAYO_NS);
	iks_insert_attrib(ref, "id", rayo_component_get_ref(component));
	rayo_iks_send(response);
	iks_delete(response);
}

/**
 * Create component complete event
 * @param component the component
 * @param reason the completion reason
 * @param reason_namespace the completion reason namespace
 * @param meta metadata to add as child of reason
 * @return the event
 */
iks *rayo_component_create_complete_event_with_metadata(struct rayo_component *component, const char *reason, const char *reason_namespace, iks *meta)
{
	iks *response = iks_new("presence");
	iks *x;
	iks_insert_attrib(response, "from", rayo_component_get_jid(component));
	iks_insert_attrib(response, "to", rayo_component_get_client_jid(component));
	iks_insert_attrib(response, "type", "unavailable");
	x = iks_insert(response, "complete");
	iks_insert_attrib(x, "xmlns", RAYO_EXT_NS);
	x = iks_insert(x, reason);
	iks_insert_attrib(x, "xmlns", reason_namespace);
	if (meta) {
		x = iks_insert_node(x, meta);
	}

	return response;
}


/**
 * Create component complete event
 * @param component the component
 * @param reason the completion reason
 * @param reason_namespace the completion reason namespace
 * @return the event
 */
iks *rayo_component_create_complete_event(struct rayo_component *component, const char *reason, const char *reason_namespace)
{
	return rayo_component_create_complete_event_with_metadata(component, reason, reason_namespace, NULL);
}

/**
 * Send rayo component complete event
 */
void rayo_component_send_complete_event(struct rayo_component *component, iks *response)
{
	rayo_iks_send(response);
	iks_delete(response);
	rayo_component_unlock(component);
	rayo_component_destroy(component);
}

/**
 * Send rayo complete
 */
void rayo_component_send_complete(struct rayo_component *component, const char *reason, const char *reason_namespace)
{
	rayo_component_send_complete_event(component, rayo_component_create_complete_event(component, reason, reason_namespace));
}

/**
 * Send rayo complete
 */
void rayo_component_send_complete_with_metadata(struct rayo_component *component, const char *reason, const char *reason_namespace, iks *meta)
{
	rayo_component_send_complete_event(component, rayo_component_create_complete_event_with_metadata(component, reason, reason_namespace, meta));
}


/**
 * Background API data
 */
struct component_bg_api_cmd {
	const char *cmd;
	const char *args;
	switch_memory_pool_t *pool;
	struct rayo_component *component;
};

/**
 * Thread that outputs to component
 * @param thread this thread
 * @param obj the Rayo mixer context
 * @return NULL
 */
static void *SWITCH_THREAD_FUNC component_bg_api_thread(switch_thread_t *thread, void *obj)
{
	struct component_bg_api_cmd *cmd = (struct component_bg_api_cmd *)obj;
	switch_stream_handle_t stream = { 0 };
	switch_memory_pool_t *pool = cmd->pool;
	SWITCH_STANDARD_STREAM(stream);

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "BGAPI EXEC: %s %s\n", cmd->cmd, cmd->args);
	if (switch_api_execute(cmd->cmd, cmd->args, NULL, &stream) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "BGAPI EXEC FAILURE\n");
		rayo_component_send_complete(cmd->component, COMPONENT_COMPLETE_ERROR);
	} else {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "BGAPI EXEC RESULT: %s\n", (char *)stream.data);
	}
	switch_safe_free(stream.data);
	switch_core_destroy_memory_pool(&pool);
	return NULL;
}

/**
 * Run a background API command
 * @param cmd API command
 * @param args API args
 */
void rayo_component_api_execute_async(struct rayo_component *component, const char *cmd, const char *args)
{
	switch_thread_t *thread;
	switch_threadattr_t *thd_attr = NULL;
	struct component_bg_api_cmd *bg_cmd = NULL;
	switch_memory_pool_t *pool;

	/* set up command */
	switch_core_new_memory_pool(&pool);
	bg_cmd = switch_core_alloc(pool, sizeof(*bg_cmd));
	bg_cmd->pool = pool;
	bg_cmd->cmd = switch_core_strdup(pool, cmd);
	bg_cmd->args = switch_core_strdup(pool, args);
	bg_cmd->component = component;

	/* create thread */
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s BGAPI START\n", rayo_component_get_jid(component));
	switch_threadattr_create(&thd_attr, pool);
	switch_threadattr_detach_set(thd_attr, 1);
	switch_threadattr_stacksize_set(thd_attr, SWITCH_THREAD_STACKSIZE);
	switch_thread_create(&thread, thd_attr, component_bg_api_thread, bg_cmd, pool);
}

/**
 * Handle configuration
 */
switch_status_t rayo_components_load(switch_loadable_module_interface_t **module_interface, switch_memory_pool_t *pool)
{
	rayo_input_component_load();
	rayo_output_component_load(module_interface, pool);
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