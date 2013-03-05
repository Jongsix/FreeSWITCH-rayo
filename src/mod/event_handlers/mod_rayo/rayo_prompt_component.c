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
 * prompt_component.c -- Rayo prompt component implementation
 *
 */
#include "rayo_components.h"
#include "iks_helpers.h"

/**
 * <prompt> component validation
 */
static const struct iks_attrib_definition prompt_attribs_def[] = {
	ATTRIB(barge-in, true, bool),
	LAST_ATTRIB
};

/**
 * <prompt> component attributes
 */
struct prompt_attribs {
	int size;
	struct iks_attrib barge_in;
};

/**
 * Start execution of prompt component
 */
static void start_call_prompt_component(struct rayo_call *call, switch_core_session_t *session, iks *iq)
{
	struct prompt_attribs p_attribs;
	iks *prompt = iks_child(iq);

	/* validate prompt attributes */
	memset(&p_attribs, 0, sizeof(p_attribs));
	if (!iks_attrib_parse(session, prompt, prompt_attribs_def, (struct iks_attribs *)&p_attribs)) {
		rayo_component_send_iq_error(iq, STANZA_ERROR_BAD_REQUEST);
		return;
	}

	/* TODO implement */

	rayo_component_send_iq_error(iq, STANZA_ERROR_FEATURE_NOT_IMPLEMENTED);
}

/**
 * Stop execution of prompt component
 */
static iks *stop_call_prompt_component(struct rayo_call *call, switch_core_session_t *session, iks *iq)
{
	return NULL;
}

/**
 * Initialize prompt component
 * @return SWITCH_STATUS_SUCCESS if successful
 */
switch_status_t rayo_prompt_component_load(void)
{
	rayo_call_component_interface_add("set:"RAYO_PROMPT_NS":prompt", start_call_prompt_component, stop_call_prompt_component);
	return SWITCH_STATUS_SUCCESS;
}

/**
 * Shutdown prompt component
 * @return SWITCH_STATUS_SUCCESS if successful
 */
switch_status_t rayo_prompt_component_shutdown(void)
{
	return SWITCH_STATUS_SUCCESS;
}
