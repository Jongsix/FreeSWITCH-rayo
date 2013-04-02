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
 * rayo_prompt_component.c -- Rayo prompt component implementation
 *
 */
#include "rayo_components.h"
#include "rayo_elements.h"

/**
 * Send stop to component
 */
static void rayo_component_send_stop(struct rayo_actor *from, struct rayo_actor *to)
{
	struct rayo_message *reply;
	iks *stop = iks_new("iq");
	iks *x;
	iks_insert_attrib(stop, "from", RAYO_JID(from));
	iks_insert_attrib(stop, "to", RAYO_JID(to));
	iks_insert_attrib(stop, "type", "set");
	iks_insert_attrib_printf(stop, "id", "mod_rayo-%d", RAYO_SEQ_NEXT(from));
	x = iks_insert(stop, "stop");
	iks_insert_attrib(x, "xmlns", RAYO_EXT_NS);
	reply = RAYO_SEND(from, to, rayo_message_create(stop));
	if (reply) {
		/* don't care */
		rayo_message_destroy(reply);
	}
}

/**
 * Prompt state
 */
struct prompt_component {
	struct rayo_component base;
	int barge_in;
	iks *iq;
	struct rayo_actor *input;
	struct rayo_actor *output;
};

#define PROMPT_COMPONENT(x) ((struct prompt_component *)x)

/**
 * Handle start of output.
 */
static iks *prompt_component_handle_output_start(struct rayo_actor *output, struct rayo_actor *prompt, iks *iq, void *data)
{
	PROMPT_COMPONENT(prompt)->output = output;
	RAYO_RDLOCK(output);
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s, started output\n", RAYO_JID(prompt));

	if (PROMPT_COMPONENT(prompt)->barge_in) {
		/* start input */
		struct rayo_message *reply;
		iks *cmd = iks_new("iq");
		iks *input = iks_find(PROMPT_COMPONENT(prompt)->iq, "prompt");
		input = iks_find(input, "input");
		iks_insert_attrib(cmd, "from", RAYO_JID(prompt));
		iks_insert_attrib(cmd, "to", RAYO_JID(RAYO_COMPONENT(prompt)->parent));
		iks_insert_attrib(cmd, "id", iks_find_attrib(PROMPT_COMPONENT(prompt)->iq, "id"));
		iks_insert_attrib(cmd, "type", "set");
		input = iks_copy_within(input, iks_stack(cmd));
		iks_insert_node(cmd, input);
		reply = RAYO_SEND(prompt, RAYO_COMPONENT(prompt)->parent, rayo_message_create(cmd));
		if (reply) {
			/* handle response */
			RAYO_SEND(RAYO_COMPONENT(prompt)->parent, prompt, reply);
		}
	} else {
		/* send ref to client */
		rayo_component_send_start(RAYO_COMPONENT(prompt), PROMPT_COMPONENT(prompt)->iq);
	}

	return NULL;
}

/**
 * Handle start of input.
 */
static iks *prompt_component_handle_input_start(struct rayo_actor *input, struct rayo_actor *prompt, iks *iq, void *data)
{
	PROMPT_COMPONENT(prompt)->input = input;
	RAYO_RDLOCK(input);
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s, started input\n", RAYO_JID(prompt));
	if (PROMPT_COMPONENT(prompt)->barge_in) {
		/* send ref to client */
		rayo_component_send_start(RAYO_COMPONENT(prompt), PROMPT_COMPONENT(prompt)->iq);
	}
	return NULL;
}

/**
 * Handle start of input/output.
 */
static iks *prompt_component_handle_io_start(struct rayo_actor *component, struct rayo_actor *prompt, iks *iq, void *data)
{
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s, got <ref> from %s: %s\n",
		RAYO_JID(prompt), RAYO_JID(component), iks_string(iks_stack(iq), iq));
	if (!strcmp("input", component->subtype)) {
		return prompt_component_handle_input_start(component, prompt, iq, data);
	} else if (!strcmp("output", component->subtype)) {
		return prompt_component_handle_output_start(component, prompt, iq, data);
	}
	return NULL;
}

/**
 * Handle barge event
 */
static iks *prompt_component_handle_input_start_timers_error(struct rayo_actor *input, struct rayo_actor *prompt, iks *iq, void *data)
{
	/* this is only expected if input component is gone */
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s, start timers failed for %s: %s\n",
		RAYO_JID(prompt), RAYO_JID(input), iks_string(iks_stack(iq), iq));
	return NULL;
}

/**
 * Handle input failure.
 */
static iks *prompt_component_handle_input_error(struct rayo_actor *input, struct rayo_actor *prompt, iks *iq, void *data)
{
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s, <input> error: %s\n",
		RAYO_JID(prompt), iks_string(iks_stack(iq), iq));

	if (PROMPT_COMPONENT(prompt)->output) {
		rayo_component_send_stop(prompt, PROMPT_COMPONENT(prompt)->output);
	}

	/* forward error to client */
	iq = PROMPT_COMPONENT(prompt)->iq;
	iks_insert_attrib(iq, "from", RAYO_JID(prompt));
	iks_insert_attrib(iq, "to", RAYO_COMPONENT(prompt)->client_jid);
	RAYO_SEND_BY_JID(prompt, RAYO_COMPONENT(prompt)->client_jid, rayo_message_create(iq));

	/* done */
	RAYO_UNLOCK(prompt);
	RAYO_DESTROY(prompt);

	return NULL;
}

/**
 * Handle output failure.
 */
static iks *prompt_component_handle_output_error(struct rayo_actor *output, struct rayo_actor *prompt, iks *iq, void *data)
{
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s, <output> error: %s\n",
		RAYO_JID(prompt), iks_string(iks_stack(iq), iq));

	/* forward error to client */
	iq = iks_copy(iq);
	iks_insert_attrib(iq, "from", RAYO_JID(prompt));
	iks_insert_attrib(iq, "to", RAYO_COMPONENT(prompt)->client_jid);
	RAYO_SEND_BY_JID(prompt, RAYO_COMPONENT(prompt)->client_jid, rayo_message_create(iq));

	/* done */
	RAYO_UNLOCK(prompt);
	RAYO_DESTROY(prompt);

	return NULL;
}

/**
 * Handle barge event
 */
static iks *prompt_component_handle_input_barge(struct rayo_actor *input, struct rayo_actor *prompt, iks *presence, void *data)
{
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s, got <start-of-input> from %s: %s\n",
		RAYO_JID(prompt), RAYO_JID(input), iks_string(iks_stack(presence), presence));
	/* stop output */
	if (PROMPT_COMPONENT(prompt)->output) {
		rayo_component_send_stop(prompt, PROMPT_COMPONENT(prompt)->output);
	}
	return NULL;
}

/**
 * Handle completion event
 */
static iks *prompt_component_handle_input_complete(struct rayo_actor *input, struct rayo_actor *prompt, iks *presence, void *data)
{
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s, got <complete> from %s\n", RAYO_JID(prompt), RAYO_JID(input));

	if (PROMPT_COMPONENT(prompt)->output) {
		rayo_component_send_stop(prompt, PROMPT_COMPONENT(prompt)->output);
	}

	/* release input */
	PROMPT_COMPONENT(prompt)->input = NULL;
	RAYO_UNLOCK(input);

	/* forward to client */
	presence = iks_copy(presence);
	iks_insert_attrib(presence, "from", RAYO_JID(prompt));
	iks_insert_attrib(presence, "to", RAYO_COMPONENT(prompt)->client_jid);
	rayo_component_send_complete_event(RAYO_COMPONENT(prompt), presence);

	return NULL;
}

/**
 * Handle completion event
 */
static iks *prompt_component_handle_output_complete(struct rayo_actor *output, struct rayo_actor *prompt, iks *presence, void *data)
{
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s, got <complete> from %s\n", RAYO_JID(prompt), RAYO_JID(output));
	if (PROMPT_COMPONENT(prompt)->input) {
		if (PROMPT_COMPONENT(prompt)->barge_in) {
			/* start input timers */
			struct rayo_message *reply;
			iks *cmd = iks_new("iq");
			iks *x;
			iks_insert_attrib(cmd, "from", RAYO_JID(prompt));
			iks_insert_attrib(cmd, "to", RAYO_JID(PROMPT_COMPONENT(prompt)->input));
			iks_insert_attrib(cmd, "type", "set");
			x = iks_insert(cmd, "start-timers");
			iks_insert_attrib(x, "xmlns", RAYO_INPUT_NS);
			reply = RAYO_SEND(prompt, PROMPT_COMPONENT(prompt)->input, rayo_message_create(cmd));
			if (reply) {
				/* process reply */
				RAYO_SEND(PROMPT_COMPONENT(prompt)->input, prompt, reply);
			}
		} else {
			/* start input */
			struct rayo_message *reply;
			iks *cmd = iks_new("iq");
			iks *input = iks_find(PROMPT_COMPONENT(prompt)->iq, "prompt");
			input = iks_find(input, "input");
			iks_insert_attrib(cmd, "from", RAYO_JID(prompt));
			iks_insert_attrib(cmd, "to", RAYO_JID(RAYO_COMPONENT(prompt)->parent));
			iks_insert_attrib(cmd, "id", iks_find_attrib(PROMPT_COMPONENT(prompt)->iq, "id"));
			iks_insert_attrib(cmd, "type", "set");
			input = iks_copy_within(input, iks_stack(cmd));
			iks_insert_node(cmd, input);
			reply = RAYO_SEND(prompt, RAYO_COMPONENT(prompt)->parent, rayo_message_create(cmd));
			if (reply) {
				/* handle response */
				RAYO_SEND(RAYO_COMPONENT(prompt)->parent, prompt, reply);
			}
		}
	}

	/* release output */
	PROMPT_COMPONENT(prompt)->output = NULL;
	RAYO_UNLOCK(output);

	return NULL;
}

/**
 * Start execution of prompt component
 */
static iks *start_call_prompt_component(struct rayo_actor *client, struct rayo_actor *call, iks *iq, void *session_data)
{
	switch_core_session_t *session = (switch_core_session_t *)session_data;
	switch_memory_pool_t *pool;
	struct prompt_component *prompt_component = NULL;
	iks *prompt = iks_find(iq, "prompt");
	iks *input;
	iks *output;
	struct rayo_message *reply = NULL;
	iks *cmd;

	if (!VALIDATE_RAYO_PROMPT(prompt)) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Bad <prompt> attrib\n");
		return iks_new_iq_error_detailed(iq, STANZA_ERROR_BAD_REQUEST, "Bad <prompt> attrib value");
	}

	output = iks_find(prompt, "output");
	if (!output) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Missing <output>\n");
		return iks_new_iq_error_detailed(iq, STANZA_ERROR_BAD_REQUEST, "Missing <output>");
	}

	input = iks_find(prompt, "input");
	if (!input) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Missing <input>\n");
		return iks_new_iq_error_detailed(iq, STANZA_ERROR_BAD_REQUEST, "Missing <input>");
	}

	/* create prompt component, linked to call */
	switch_core_new_memory_pool(&pool);
	prompt_component = switch_core_alloc(pool, sizeof(*prompt_component));
	rayo_component_init(RAYO_COMPONENT(prompt_component), pool, "prompt", NULL, call, iks_find_attrib(iq, "from"));
	prompt_component->barge_in = iks_find_bool_attrib(prompt, "barge-in");
	prompt_component->iq = iks_copy(iq);

	/* start output */
	cmd = iks_new("iq");
	iks_insert_attrib(cmd, "from", RAYO_JID(prompt_component));
	iks_insert_attrib(cmd, "to", RAYO_JID(call));
	iks_insert_attrib(cmd, "id", iks_find_attrib(iq, "id"));
	iks_insert_attrib(cmd, "type", "set");
	output = iks_copy_within(output, iks_stack(cmd));
	iks_insert_node(cmd, output);
	reply = RAYO_SEND(prompt_component, call, rayo_message_create(cmd));
	if (reply) {
		/* handle response */
		RAYO_SEND(call, prompt_component, reply);
	}

	return NULL;
}

/**
 * Stop execution of prompt component
 */
static iks *stop_call_prompt_component(struct rayo_actor *client, struct rayo_actor *component, iks *iq, void *data)
{
	/* TODO implement */
	return NULL;
}

/**
 * Initialize prompt component
 * @return SWITCH_STATUS_SUCCESS if successful
 */
switch_status_t rayo_prompt_component_load(void)
{
	/* Prompt is a convenience component that wraps <input> and <output> */
	rayo_actor_command_handler_add(RAT_CALL, "", "set:"RAYO_PROMPT_NS":prompt", start_call_prompt_component);
	rayo_actor_command_handler_add(RAT_CALL_COMPONENT, "prompt", "set:"RAYO_EXT_NS":stop", stop_call_prompt_component);
	rayo_actor_command_handler_add(RAT_CALL_COMPONENT, "prompt", "result:"RAYO_NS":ref", prompt_component_handle_io_start);
	rayo_actor_command_handler_add(RAT_CALL_COMPONENT, "prompt", "error:"RAYO_OUTPUT_NS":output", prompt_component_handle_output_error);
	rayo_actor_command_handler_add(RAT_CALL_COMPONENT, "prompt", "error:"RAYO_INPUT_NS":input", prompt_component_handle_input_error);
	rayo_actor_command_handler_add(RAT_CALL_COMPONENT, "prompt", "error:"RAYO_INPUT_NS":start-timers", prompt_component_handle_input_start_timers_error);
	rayo_actor_event_handler_add(RAT_CALL_COMPONENT, "input", RAT_CALL_COMPONENT, "prompt", ":"RAYO_INPUT_NS":start-of-input", prompt_component_handle_input_barge);
	rayo_actor_event_handler_add(RAT_CALL_COMPONENT, "input", RAT_CALL_COMPONENT, "prompt", "unavailable:"RAYO_EXT_NS":complete", prompt_component_handle_input_complete);
	rayo_actor_event_handler_add(RAT_CALL_COMPONENT, "output", RAT_CALL_COMPONENT, "prompt", "unavailable:"RAYO_EXT_NS":complete", prompt_component_handle_output_complete);

	/* TODO wrap output commands */

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
