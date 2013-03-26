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
 * input_component.c -- Rayo input component implementation
 *
 */
#include "rayo_components.h"
#include "rayo_elements.h"
#include "srgs.h"
#include "nlsml.h"

#define MAX_DTMF 64

#define INPUT_INITIAL_TIMEOUT "initial-timeout", RAYO_INPUT_COMPLETE_NS
#define INPUT_INTER_DIGIT_TIMEOUT "inter-digit-timeout", RAYO_INPUT_COMPLETE_NS
#define INPUT_MAX_SILENCE "max-silence", RAYO_INPUT_COMPLETE_NS
#define INPUT_MIN_CONFIDENCE "min-confidence", RAYO_INPUT_COMPLETE_NS
#define INPUT_MATCH "match", RAYO_INPUT_COMPLETE_NS
#define INPUT_NOMATCH "nomatch", RAYO_INPUT_COMPLETE_NS

#define RAYO_INPUT_COMPONENT_PRIVATE_VAR "__rayo_input_component"

struct input_handler;

/**
 * Input component state
 */
struct input_component {
	/** component base class */
	struct rayo_component base;
	/** true if speech detection */
	int speech_mode;
	/** Number of collected digits */
	int num_digits;
	/** The collected digits */
	char digits[MAX_DTMF + 1];
	/** time when last digit was received */
	switch_time_t last_digit_time;
	/** timeout before first digit is received */
	int initial_timeout;
	/** timeout after first digit is received */
	int inter_digit_timeout;
	/** stop flag */
	int stop;
	/** true if input barges in on output */
	int barge_in;
	/** optional output linked to this input */
	const char *output_file;
	/** global data */
	struct input_handler *handler;
};

#define INPUT_COMPONENT(x) ((struct input_component *)x)

/**
 * Call input state
 */
struct input_handler {
	/** The grammar parser */
	struct srgs_parser *parser;
	/** media bug to monitor frames / control input lifecycle */
	switch_media_bug_t *bug;
	/** active input component - TODO multiple inputs */
	struct input_component *component;
	/** synchronizes media bug and dtmf callbacks */
	switch_mutex_t *mutex;
};

/**
 * Process DTMF press
 */
static switch_status_t input_component_on_dtmf(switch_core_session_t *session, const switch_dtmf_t *dtmf, switch_dtmf_direction_t direction)
{
	switch_channel_t *channel = switch_core_session_get_channel(session);
	struct input_handler *handler = (struct input_handler *)switch_channel_get_private(channel, RAYO_INPUT_COMPONENT_PRIVATE_VAR);

	if (handler) {
		struct input_component *component;
		enum srgs_match_type match;
		switch_mutex_lock(handler->mutex);
		component = handler->component;
		component->digits[component->num_digits] = dtmf->digit;
		component->num_digits++;
		component->digits[component->num_digits] = '\0';
		component->last_digit_time = switch_micro_time_now();
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Collected digits = \"%s\"\n", component->digits);

		match = srgs_match(handler->parser, component->digits);

		switch (match) {
			case SMT_MATCH_PARTIAL: {
				/* need more digits */
				break;
			}
			case SMT_NO_MATCH: {
				/* notify of no-match and remove input component */
				handler->component = NULL;
				switch_core_media_bug_remove(session, &handler->bug);
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "NO MATCH = %s\n", component->digits);
				rayo_component_send_complete(RAYO_COMPONENT(component), INPUT_NOMATCH);
				break;
			}
			case SMT_MATCH: {
				iks *result = nlsml_create_dtmf_match(component->digits);
				/* notify of match and remove input component */
				handler->component = NULL;
				switch_core_media_bug_remove(session, &handler->bug);
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "MATCH = %s\n", component->digits);
				rayo_component_send_complete_with_metadata(RAYO_COMPONENT(component), INPUT_MATCH, result);
				iks_delete(result);
				break;
			}
		}
		switch_mutex_unlock(handler->mutex);
	}
    return SWITCH_STATUS_SUCCESS;
}

/**
 * Monitor for input
 */
static switch_bool_t input_component_bug_callback(switch_media_bug_t *bug, void *user_data, switch_abc_type_t type)
{
	switch_core_session_t *session = switch_core_media_bug_get_session(bug);
	struct input_handler *handler = (struct input_handler *)user_data;
	struct input_component *component;
	switch_mutex_lock(handler->mutex);
	component = handler->component;
	switch(type) {
		case SWITCH_ABC_TYPE_INIT: {
			switch_core_event_hook_add_recv_dtmf(session, input_component_on_dtmf);
			break;
		}
		case SWITCH_ABC_TYPE_READ_REPLACE: {
			switch_frame_t *rframe = switch_core_media_bug_get_read_replace_frame(bug);
			/* check for timeout */
			if (component) {
				int elapsed_ms = (switch_micro_time_now() - component->last_digit_time) / 1000;
				if (component->num_digits && component->inter_digit_timeout > 0 && elapsed_ms > component->inter_digit_timeout) {
					handler->component = NULL;
					switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "inter-digit-timeout\n");
					rayo_component_send_complete(RAYO_COMPONENT(component), INPUT_INTER_DIGIT_TIMEOUT);
				} else if (!component->num_digits && component->initial_timeout > 0 && elapsed_ms > component->initial_timeout) {
					handler->component = NULL;
					switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "initial-timeout\n");
					rayo_component_send_complete(RAYO_COMPONENT(component), INPUT_INITIAL_TIMEOUT);
				}
			}
			switch_core_media_bug_set_read_replace_frame(bug, rframe);
			break;
		}
		case SWITCH_ABC_TYPE_CLOSE:
			/* check for hangup */
			if (component) {
				if (component->stop) {
					handler->component = NULL;
					rayo_component_send_complete(RAYO_COMPONENT(component), COMPONENT_COMPLETE_STOP);
				} else {
					handler->component = NULL;
					rayo_component_send_complete(RAYO_COMPONENT(component), COMPONENT_COMPLETE_HANGUP);
				}
			}
			switch_core_event_hook_remove_recv_dtmf(session, input_component_on_dtmf);
			break;
		default:
			break;
	}
	switch_mutex_unlock(handler->mutex);
	return SWITCH_TRUE;
}

/**
 * Validate input request
 * @param input request to validate
 * @param error message
 * @return 0 if error, 1 if valid
 */
static int validate_call_input(iks *input, const char **error)
{
	iks *grammar;
	const char *content_type;

	/* validate input attributes */
	if (!VALIDATE_RAYO_INPUT(input)) {
		*error = "Bad <input> attrib value";
		return 0;
	}

	/* missing grammar */
	grammar = iks_find(input, "grammar");
	if (!grammar) {
		*error = "Missing <grammar>";
		return 0;
	}

	/* only support srgs */
	content_type = iks_find_attrib(grammar, "content-type");
	if (!zstr(content_type) && strcmp("application/srgs+xml", content_type)) {
		*error = "Unsupported content type";
		return 0;
	}

	/* missing grammar body */
	if (zstr(iks_find_cdata(input, "grammar"))) {
		*error = "Grammar content is missing";
		return 0;
	}

	return 1;
}

/**
 * Start call input for the given component
 * @param component the input or prompt component
 * @param session the session
 * @param input the input request
 * @param iq the original input/prompt request
 * @param output_file optional output file linked to this input
 * @param barge_in true if start of input stops output
 */
static int start_call_input(struct input_component *component, switch_core_session_t *session, iks *input, iks *iq, const char *output_file, int barge_in)
{
	/* set up input component for new detection */
	struct input_handler *handler = (struct input_handler *)switch_channel_get_private(switch_core_session_get_channel(session), RAYO_INPUT_COMPONENT_PRIVATE_VAR);
	if (!handler) {
		/* create input component */
		handler = switch_core_session_alloc(session, sizeof(*handler));
		handler->parser = srgs_parser_new(switch_core_session_get_uuid(session)); /* TODO cleanup on call hangup */
		switch_mutex_init(&handler->mutex, SWITCH_MUTEX_NESTED, switch_core_session_get_pool(session));
		switch_channel_set_private(switch_core_session_get_channel(session), RAYO_INPUT_COMPONENT_PRIVATE_VAR, handler);
	}
	handler->component = component;
	component->num_digits = 0;
	component->digits[0] = '\0';
	component->stop = 0;
	component->speech_mode = 0;
	component->output_file = output_file;
	component->barge_in = barge_in;
	component->handler = handler;

	/* parse the grammar */
	if (!srgs_parse(handler->parser, iks_find_cdata(input, "grammar"))) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Failed to parse grammar body\n");
		rayo_component_send_iq_error_detailed(iq, STANZA_ERROR_BAD_REQUEST, "Failed to parse grammar body");
		RAYO_UNLOCK(component);
		RAYO_DESTROY(component);
		return 0;
	}

	/* is this voice or dtmf srgs grammar? */
	if (!strcasecmp("dtmf", iks_find_attrib_soft(input, "mode"))) {
		component->last_digit_time = switch_micro_time_now();
		component->initial_timeout = iks_find_int_attrib(input, "initial-timeout");
		component->inter_digit_timeout = iks_find_int_attrib(input, "inter-digit-timeout");

		/* acknowledge command */
		rayo_component_send_start(RAYO_COMPONENT(component), iq);

		/* start dtmf input detection */
		if (switch_core_media_bug_add(session, "rayo_input_component", NULL, input_component_bug_callback, handler, 0, SMBF_READ_REPLACE, &handler->bug) != SWITCH_STATUS_SUCCESS) {
			rayo_component_send_complete(RAYO_COMPONENT(component), COMPONENT_COMPLETE_ERROR);
			return 0;
		}
	} else {
		const char *jsgf_path;
		char *grammar = NULL;
		component->speech_mode = 1;
		jsgf_path = srgs_to_jsgf_file(handler->parser, SWITCH_GLOBAL_dirs.grammar_dir, "gram");
		if (!jsgf_path) {
			rayo_component_send_iq_error_detailed(iq, STANZA_ERROR_INTERNAL_SERVER_ERROR, "Grammar error");
			RAYO_UNLOCK(component);
			RAYO_DESTROY(component);
			return 0;
		}

		/* acknowledge command */
		rayo_component_send_start(RAYO_COMPONENT(component), iq);

		/* TODO configurable speech detection - different engines, grammar passthrough, dtmf handled by recognizer */
		grammar = switch_mprintf("{no-input-timeout=%s,speech-timeout=%s,start-input-timers=%s,confidence-threshold=%d}%s",
			iks_find_attrib(input, "initial-timeout"), iks_find_attrib(input, "max-silence"),
			zstr(component->output_file) ? "true" : "false",
			(int)ceil(iks_find_decimal_attrib(input, "min-confidence") * 100.0), jsgf_path);
		/* start speech detection */
		switch_channel_set_variable(switch_core_session_get_channel(session), "fire_asr_events", "true");
		if (switch_ivr_detect_speech(session, "pocketsphinx", grammar, "mod_rayo_grammar", "", NULL) != SWITCH_STATUS_SUCCESS) {
			rayo_component_send_complete(RAYO_COMPONENT(component), COMPONENT_COMPLETE_ERROR);
			switch_safe_free(grammar);
			return 0;
		}
		switch_safe_free(grammar);
	}

	return 1;
}

/**
 * Start execution of input component
 */
static iks *start_call_input_component(struct rayo_call *call, switch_core_session_t *session, iks *iq)
{
	char *component_id = switch_mprintf("%s-input", switch_core_session_get_uuid(session));
	switch_memory_pool_t *pool = NULL;
	struct input_component *input_component = NULL;
	iks *input = iks_find(iq, "input");
	const char *error = NULL;

	if (!validate_call_input(input, &error)) {
		rayo_component_send_iq_error_detailed(iq, STANZA_ERROR_BAD_REQUEST, error);
		return NULL;
	}

	/* create component */
	switch_core_new_memory_pool(&pool);
	input_component = switch_core_alloc(pool, sizeof(*input_component));
	rayo_component_init(RAYO_COMPONENT(input_component), pool, "input", component_id, RAYO_ACTOR(call), iks_find_attrib(iq, "from"));
	switch_safe_free(component_id);

	/* start input */
	start_call_input(input_component, session, iks_find(iq, "input"), iq, NULL, 0);
	return NULL;
}

/**
 * Stop execution of input component
 */
static iks *stop_call_input_component(struct rayo_component *component, iks *iq)
{
	struct input_component *input_component = (struct input_component *)component;

	if (input_component && !input_component->stop) {
		switch_core_session_t *session = switch_core_session_locate(component->parent->id);
		if (session) {
			switch_mutex_lock(input_component->handler->mutex);
			if (input_component->speech_mode) {
				input_component->stop = 1;
				switch_ivr_stop_detect_speech(session);
				rayo_component_send_complete(component, COMPONENT_COMPLETE_STOP);
			} else if (input_component->handler->bug) {
				input_component->stop = 1;
				switch_core_media_bug_remove(session, &input_component->handler->bug);
			}
			switch_mutex_unlock(input_component->handler->mutex);
			switch_core_session_rwunlock(session);
		}
	}
	return iks_new_iq_result(iq);
}

/**
 * Handle speech detection event
 */
static void on_detected_speech_event(switch_event_t *event)
{
	const char *speech_type = switch_event_get_header(event, "Speech-Type");
	char *event_str = NULL;
	switch_event_serialize(event, &event_str, SWITCH_FALSE);
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s\n", event_str);
	if (!speech_type) {
		return;
	}
	if (!strcasecmp("detected-speech", speech_type)) {
		const char *uuid = switch_event_get_header(event, "Unique-ID");
		char *component_id = switch_mprintf("%s-input", uuid);
		struct rayo_component *component = RAYO_COMPONENT_LOCATE(component_id);
		switch_safe_free(component_id);
		if (component) {
			const char *result = switch_event_get_body(event);
			switch_mutex_lock(INPUT_COMPONENT(component)->handler->mutex);
			INPUT_COMPONENT(component)->handler->component = NULL;
			switch_mutex_unlock(INPUT_COMPONENT(component)->handler->mutex);
			if (zstr(result)) {
				rayo_component_send_complete(component, INPUT_NOMATCH);
			} else {
				enum nlsml_match_type match_type = nlsml_parse(result, uuid);
				switch (match_type) {
				case NMT_NOINPUT:
					rayo_component_send_complete(component, INPUT_INITIAL_TIMEOUT);
					break;
				case NMT_MATCH:
					rayo_component_send_complete_with_metadata_string(component, INPUT_MATCH, result);
					break;
				case NMT_BAD_XML:
					switch_log_printf(SWITCH_CHANNEL_UUID_LOG(uuid), SWITCH_LOG_WARNING, "Failed to parse NLSML result: %s!\n", result);
					rayo_component_send_complete(component, INPUT_NOMATCH);
					break;
				case NMT_NOMATCH:
					rayo_component_send_complete(component, INPUT_NOMATCH);
					break;
				default:
					switch_log_printf(SWITCH_CHANNEL_UUID_LOG(uuid), SWITCH_LOG_CRIT, "Unknown NLSML match type: %i, %s!\n", match_type, result);
					rayo_component_send_complete(component, INPUT_NOMATCH);
					break;
				}
			}
			RAYO_UNLOCK(component);
		}
	} else if (!strcasecmp("closed", speech_type)) {
		const char *uuid = switch_event_get_header(event, "Unique-ID");
		char *component_id = switch_mprintf("%s-input", uuid);
		struct rayo_component *component = RAYO_COMPONENT_LOCATE(component_id);
		switch_safe_free(component_id);
		if (component) {
			char *channel_state = switch_event_get_header(event, "Channel-State");
			switch_mutex_lock(INPUT_COMPONENT(component)->handler->mutex);
			INPUT_COMPONENT(component)->handler->component = NULL;
			switch_mutex_unlock(INPUT_COMPONENT(component)->handler->mutex);
			switch_log_printf(SWITCH_CHANNEL_UUID_LOG(uuid), SWITCH_LOG_DEBUG, "Recognizer closed\n");
			if (channel_state && !strcmp("CS_HANGUP", channel_state)) {
				rayo_component_send_complete(component, COMPONENT_COMPLETE_HANGUP);
			} else {
				/* shouldn't get here... */
				rayo_component_send_complete(component, COMPONENT_COMPLETE_ERROR);
			}
			RAYO_UNLOCK(component);
		}
	}
	switch_safe_free(event_str);
}

/**
 * Process input/output responses to prompt component and forward events to client
 */
static void prompt_component_event_handler(struct rayo_actor *actor, switch_event_t *event)
{
	//struct rayo_component *io_component = RAYO_COMPONENT(actor);
	//struct prompt_component *prompt_component = (struct prompt_component *)io_component->parent;

	char *event_subclass = switch_event_get_header(event, "Event-Subclass");
	if (!strcmp(RAYO_EVENT_XMPP_SEND, event_subclass)) {
		/* send raw XMPP message from FS */
		char *msg = switch_event_get_body(event);
		iks *response;
		iksparser *p = iks_dom_new(&response);

		/* parse message to check for response */
		if (iks_parse(p, msg, 0, 1) == IKS_OK) {
			if (!strcmp("iq", iks_name(response))) {
				const char *type = iks_find_attrib_soft(response, "type");
				if (strcmp("result", type) || !iks_find(response, "ref")) {
					/* component was not created- command is done */
					/* TODO complete input with error */
				} else {

				}
			} else if (!strcmp("presence", iks_name(response))) {
				/* completion event */
				/* TODO start input timers */
			}
		} else {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "\nFailed to parse XMPP response\n");
			/* TODO complete input with error */
		}
		iks_parser_delete(p);
	}
}

enum sub_component_state {
	SCS_NONE,
	SCS_START,
	SCS_DONE,
	SCS_ERROR
};

struct prompt_component {
	struct rayo_component base;
	enum sub_component_state output_state;
	enum sub_component_state input_state;
};

/**
 * Start execution of prompt component
 */
static iks *start_call_prompt_component(struct rayo_call *call, switch_core_session_t *session, iks *iq)
{
	switch_memory_pool_t *pool;
	struct prompt_component *prompt_component = NULL;
	struct input_component *input_component = NULL;
	struct rayo_component *output_component = NULL;
	char *input_component_id;
	iks *prompt = iks_find(iq, "prompt");
	iks *input;
	iks *output;
	const char *error = NULL;

	if (!VALIDATE_RAYO_PROMPT(prompt)) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Bad <prompt> attrib\n");
		rayo_component_send_iq_error_detailed(iq, STANZA_ERROR_BAD_REQUEST, "Bad <prompt> attrib value");
		return NULL;
	}

	output = iks_find(prompt, "output");
	if (!output) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Missing <output>\n");
		rayo_component_send_iq_error_detailed(iq, STANZA_ERROR_BAD_REQUEST, "Missing <output>");
		return NULL;
	}

	if (!VALIDATE_RAYO_OUTPUT(output)) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Bad <output> attrib\n");
		rayo_component_send_iq_error_detailed(iq, STANZA_ERROR_BAD_REQUEST, "Bad <output> attrib value");
		return NULL;
	}

	input = iks_find(prompt, "input");
	if (!input) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Missing <input>\n");
		rayo_component_send_iq_error_detailed(iq, STANZA_ERROR_BAD_REQUEST, "Missing <input>");
		return NULL;
	}

	if (!validate_call_input(input, &error)) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "%s\n", error);
		rayo_component_send_iq_error_detailed(iq, STANZA_ERROR_BAD_REQUEST, error);
		return NULL;
	}

	/* create prompt component, linked to call */
	switch_core_new_memory_pool(&pool);
	prompt_component = switch_core_alloc(pool, sizeof(*prompt_component));
	rayo_component_init(RAYO_COMPONENT(prompt_component), pool, "prompt", NULL, RAYO_ACTOR(call), iks_find_attrib(iq, "from"));

	/* create input component, linked to prompt component */
	input_component_id = switch_mprintf("%s-input", switch_core_session_get_uuid(session));
	pool = NULL;
	switch_core_new_memory_pool(&pool);
	input_component = switch_core_alloc(pool, sizeof(*input_component));
	rayo_component_init(RAYO_COMPONENT(input_component), pool, "input", input_component_id, RAYO_ACTOR(prompt_component), RAYO_JID(prompt_component));
	rayo_actor_set_event_fn(RAYO_ACTOR(input_component), prompt_component_event_handler);
	switch_safe_free(input_component_id);

	/* create output component, linked to prompt component */
	output_component = create_output_component(RAYO_ACTOR(prompt_component), output, RAYO_JID(prompt_component));
	rayo_actor_set_event_fn(RAYO_ACTOR(output_component), prompt_component_event_handler);

	/* start input and output */
	start_call_input(input_component, session, input, iq, RAYO_JID(output_component), iks_find_bool_attrib(prompt, "barge-in"));
	start_call_output(output_component, session, output, iq);

	return NULL;
}

/**
 * Stop execution of prompt component
 */
static iks *stop_call_prompt_component(struct rayo_component *component, iks *iq)
{
	return NULL;
}

/**
 * Initialize input component
 * @return SWITCH_STATUS_SUCCESS if successful
 */
switch_status_t rayo_input_component_load(void)
{
	srgs_init();
	nlsml_init();

	rayo_call_command_handler_add("set:"RAYO_INPUT_NS":input", start_call_input_component);
	rayo_call_component_command_handler_add("input", "set:"RAYO_EXT_NS":stop", stop_call_input_component);
	switch_event_bind("rayo_input_component", SWITCH_EVENT_DETECTED_SPEECH, SWITCH_EVENT_SUBCLASS_ANY, on_detected_speech_event, NULL);

	/* Prompt is a special <input> linked to <output> */
	rayo_call_command_handler_add("set:"RAYO_PROMPT_NS":prompt", start_call_prompt_component);
	rayo_call_component_command_handler_add("prompt", "set:"RAYO_EXT_NS":stop", stop_call_prompt_component);

	return SWITCH_STATUS_SUCCESS;
}

/**
 * Shutdown input component
 * @return SWITCH_STATUS_SUCCESS if successful
 */
switch_status_t rayo_input_component_shutdown(void)
{
	switch_event_unbind_callback(on_detected_speech_event);
	return SWITCH_STATUS_SUCCESS;
}
