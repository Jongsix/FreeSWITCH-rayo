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
 * Create new call component
 * @param id the internal ID
 * @param call the parent call
 * @param type the type of component
 * @param client_jid of requesting client
 * @return the component
 */
struct rayo_component *rayo_call_component_create(const char *id, struct rayo_call *call, const char *type, const char *client_jid)
{
	const char *ref = switch_core_sprintf(rayo_call_get_pool(call), "%s-%d", type, rayo_call_seq_next(call));
	const char *jid = switch_core_sprintf(rayo_call_get_pool(call), "%s/%s", rayo_call_get_uuid(call), ref);
	struct rayo_component *component = rayo_component_create(type, id, jid, ref, rayo_call_get_actor(call), client_jid);
	return component;
}

/**
 * Create new mixer component
 * @param id the internal id
 * @param mixer the parent mixer
 * @param type the type of component
 * @param client_jid of requesting client
 * @return the component
 */
struct rayo_component *rayo_mixer_component_create(const char *id, struct rayo_mixer *mixer, const char *type, const char *client_jid)
{
	const char *ref = switch_core_sprintf(rayo_mixer_get_pool(mixer), "%s-%d", type, rayo_mixer_seq_next(mixer));
	const char *jid = switch_core_sprintf(rayo_mixer_get_pool(mixer), "%s/%s", rayo_mixer_get_name(mixer), ref);
	struct rayo_component *component = rayo_component_create(type, id, jid, ref, rayo_mixer_get_actor(mixer), client_jid);
	return component;
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
 * @return the event
 */
iks *rayo_component_create_complete_event(struct rayo_component *component, const char *reason, const char *reason_namespace)
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
	
	return response;
}

/**
 * Send rayo component complete event
 */
void rayo_component_send_complete_event(struct rayo_component *component, iks *response)
{
	rayo_iks_send(response);
	iks_delete(response);
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
 * Handle configuration
 */
switch_status_t rayo_components_load(switch_loadable_module_interface_t **module_interface, switch_memory_pool_t *pool)
{
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