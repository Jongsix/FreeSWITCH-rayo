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

static struct {
	/** grammar parser */
	struct srgs_parser *parser;
} globals;

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
	/** grammar to match */
	struct srgs_grammar *grammar;
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

		match = srgs_grammar_match(component->grammar, component->digits);

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
				rayo_component_send_complete_with_metadata(RAYO_COMPONENT(component), INPUT_MATCH, result, 0);
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
static iks *start_call_input(struct input_component *component, switch_core_session_t *session, iks *input, iks *iq, const char *output_file, int barge_in)
{
	/* set up input component for new detection */
	struct input_handler *handler = (struct input_handler *)switch_channel_get_private(switch_core_session_get_channel(session), RAYO_INPUT_COMPONENT_PRIVATE_VAR);
	if (!handler) {
		/* create input component */
		handler = switch_core_session_alloc(session, sizeof(*handler));
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
	if (!(component->grammar = srgs_parse(globals.parser, iks_find_cdata(input, "grammar")))) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Failed to parse grammar body\n");
		RAYO_UNLOCK(component);
		RAYO_DESTROY(component);
		return iks_new_iq_error_detailed(iq, STANZA_ERROR_BAD_REQUEST, "Failed to parse grammar body");
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
		}
	} else {
		const char *jsgf_path;
		char *grammar = NULL;
		component->speech_mode = 1;
		jsgf_path = srgs_grammar_to_jsgf_file(component->grammar, SWITCH_GLOBAL_dirs.grammar_dir, "gram");
		if (!jsgf_path) {
			RAYO_UNLOCK(component);
			RAYO_DESTROY(component);
			return iks_new_iq_error_detailed(iq, STANZA_ERROR_INTERNAL_SERVER_ERROR, "Grammar error");
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
		}
		switch_safe_free(grammar);
	}

	return NULL;
}

/**
 * Start execution of input component
 */
static iks *start_call_input_component(struct rayo_actor *client, struct rayo_actor *call, iks *iq, void *session_data)
{
	switch_core_session_t *session = (switch_core_session_t *)session_data;
	char *component_id = switch_mprintf("%s-input", switch_core_session_get_uuid(session));
	switch_memory_pool_t *pool = NULL;
	struct input_component *input_component = NULL;
	iks *input = iks_find(iq, "input");
	const char *error = NULL;

	if (!validate_call_input(input, &error)) {
		return iks_new_iq_error_detailed(iq, STANZA_ERROR_BAD_REQUEST, error);
	}

	/* create component */
	switch_core_new_memory_pool(&pool);
	input_component = switch_core_alloc(pool, sizeof(*input_component));
	rayo_component_init(RAYO_COMPONENT(input_component), pool, "input", component_id, call, iks_find_attrib(iq, "from"));
	switch_safe_free(component_id);

	/* start input */
	return start_call_input(input_component, session, iks_find(iq, "input"), iq, NULL, 0);
}

/**
 * Stop execution of input component
 */
static iks *stop_call_input_component(struct rayo_actor *client, struct rayo_actor *component, iks *iq, void *data)
{
	struct input_component *input_component = INPUT_COMPONENT(component);

	if (input_component && !input_component->stop) {
		switch_core_session_t *session = switch_core_session_locate(RAYO_COMPONENT(component)->parent->id);
		if (session) {
			switch_mutex_lock(input_component->handler->mutex);
			if (input_component->speech_mode) {
				input_component->stop = 1;
				switch_ivr_stop_detect_speech(session);
				rayo_component_send_complete(RAYO_COMPONENT(component), COMPONENT_COMPLETE_STOP);
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
					rayo_component_send_complete_with_metadata_string(component, INPUT_MATCH, result, 0);
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
 * Send stop to component
 */
static void rayo_component_send_stop(struct rayo_actor *from, const char *to_jid)
{
	iks *stop = iks_new("iq");
	iks *x;
	iks_insert_attrib(stop, "from", RAYO_JID(from));
	iks_insert_attrib(stop, "to", to_jid);
	iks_insert_attrib(stop, "type", "set");
	iks_insert_attrib_printf(stop, "id", "%05x", RAYO_SEQ_NEXT(from));
	x = iks_insert(stop, "stop");
	iks_insert_attrib(x, "xmlns", RAYO_EXT_NS);
	RAYO_SEND_BY_JID(from, to_jid, rayo_message_create(stop));
}

/**
 * Prompt input/output component state
 */
enum rayo_component_state {
	RCS_NONE,
	RCS_START,
	RCS_DONE,
	RCS_ERROR
};

/**
 * Prompt state
 */
struct prompt_component {
	struct rayo_component base;
	enum rayo_component_state prompt_state;
	const char *input_jid;
	enum rayo_component_state input_state;
	const char *output_jid;
	enum rayo_component_state output_state;
};

#define PROMPT_COMPONENT(x) ((struct prompt_component *)x)

/**
 * Handle start of input.
 */
static iks *prompt_component_handle_input_start(struct rayo_actor *input, struct rayo_actor *prompt, iks *iq, void *data)
{
	if (PROMPT_COMPONENT(prompt)->input_jid && !strcmp(RAYO_JID(input), PROMPT_COMPONENT(prompt)->input_jid)) {
		PROMPT_COMPONENT(prompt)->input_state = RCS_START;
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s, started input\n", RAYO_JID(prompt));
	}
	return NULL;
}

/**
 * Handle start of output.
 */
static iks *prompt_component_handle_output_start(struct rayo_actor *output, struct rayo_actor *prompt, iks *iq, void *data)
{
	if (PROMPT_COMPONENT(prompt)->output_jid && !strcmp(RAYO_JID(output), PROMPT_COMPONENT(prompt)->output_jid)) {
		PROMPT_COMPONENT(prompt)->output_state = RCS_START;
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s, started output\n", RAYO_JID(prompt));
	}
	return NULL;
}

/**
 * Handle start of input/output.
 */
static iks *prompt_component_handle_io_start(struct rayo_actor *component, struct rayo_actor *prompt, iks *iq, void *data)
{
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s, got <ref> from %s\n", RAYO_JID(prompt), RAYO_JID(component));
	if (!strcmp("input", component->subtype)) {
		return prompt_component_handle_input_start(component, prompt, iq, data);
	} else if (!strcmp("output", component->subtype)) {
		return prompt_component_handle_output_start(component, prompt, iq, data);
	}
	return NULL;
}

/**
 * Handle input failure.
 */
static iks *prompt_component_handle_input_error(struct rayo_actor *input, struct rayo_actor *prompt, iks *iq, void *data)
{
	if (PROMPT_COMPONENT(prompt)->input_jid && !strcmp(RAYO_JID(input), PROMPT_COMPONENT(prompt)->input_jid)) {
		PROMPT_COMPONENT(prompt)->input_state = RCS_ERROR;
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s, <input> error\n", RAYO_JID(prompt));
		if (PROMPT_COMPONENT(prompt)->output_state <= RCS_START && PROMPT_COMPONENT(prompt)->output_jid) {
			/* stop output */
			rayo_component_send_stop(prompt, PROMPT_COMPONENT(prompt)->output_jid);
		}
	}
	return NULL;
}

/**
 * Handle output failure.
 */
static iks *prompt_component_handle_output_error(struct rayo_actor *output, struct rayo_actor *prompt, iks *iq, void *data)
{
	if (PROMPT_COMPONENT(prompt)->output_jid && !strcmp(RAYO_JID(output), PROMPT_COMPONENT(prompt)->output_jid)) {
		PROMPT_COMPONENT(prompt)->output_state = RCS_ERROR;
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s, <output> error\n", RAYO_JID(prompt));
		if (PROMPT_COMPONENT(prompt)->input_state <= RCS_START && PROMPT_COMPONENT(prompt)->input_jid) {
			/* stop input */
			rayo_component_send_stop(prompt, PROMPT_COMPONENT(prompt)->input_jid);
		}
	}
	return NULL;
}

/**
 * Handle input/output failure
 */
static iks *prompt_component_handle_io_error(struct rayo_actor *component, struct rayo_actor *prompt, iks *iq, void *data)
{
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s, got error from %s\n", RAYO_JID(prompt), RAYO_JID(component));
	if (!strcmp("input", component->subtype)) {
		return prompt_component_handle_input_error(component, prompt, iq, data);
	} else if (!strcmp("output", component->subtype)) {
		return prompt_component_handle_output_error(component, prompt, iq, data);
	}

	/* TODO finish this */

	return NULL;
}

/**
 * Handle completion event
 */
static iks *prompt_component_handle_input_complete(struct rayo_actor *component, struct rayo_actor *prompt, iks *presence, void *data)
{
	/* TODO */
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s, got <complete> from %s\n", RAYO_JID(prompt), RAYO_JID(component));
	return NULL;
}

/**
 * Handle completion event
 */
static iks *prompt_component_handle_output_complete(struct rayo_actor *component, struct rayo_actor *prompt, iks *presence, void *data)
{
	/* TODO */
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s, got <complete> from %s\n", RAYO_JID(prompt), RAYO_JID(component));
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
	struct input_component *input_component = NULL;
	struct rayo_component *output_component = NULL;
	char *input_component_id;
	iks *prompt = iks_find(iq, "prompt");
	iks *input;
	iks *output;
	const char *error = NULL;
	iks *reply = NULL;

	if (!VALIDATE_RAYO_PROMPT(prompt)) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Bad <prompt> attrib\n");
		return iks_new_iq_error_detailed(iq, STANZA_ERROR_BAD_REQUEST, "Bad <prompt> attrib value");
	}

	output = iks_find(prompt, "output");
	if (!output) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Missing <output>\n");
		return iks_new_iq_error_detailed(iq, STANZA_ERROR_BAD_REQUEST, "Missing <output>");
	}

	if (!VALIDATE_RAYO_OUTPUT(output)) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Bad <output> attrib\n");
		return iks_new_iq_error_detailed(iq, STANZA_ERROR_BAD_REQUEST, "Bad <output> attrib value");
	}

	input = iks_find(prompt, "input");
	if (!input) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Missing <input>\n");
		return iks_new_iq_error_detailed(iq, STANZA_ERROR_BAD_REQUEST, "Missing <input>");
	}

	if (!validate_call_input(input, &error)) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "%s\n", error);
		return iks_new_iq_error_detailed(iq, STANZA_ERROR_BAD_REQUEST, error);
	}

	/* create prompt component, linked to call */
	switch_core_new_memory_pool(&pool);
	prompt_component = switch_core_alloc(pool, sizeof(*prompt_component));
	rayo_component_init(RAYO_COMPONENT(prompt_component), pool, "prompt", NULL, call, iks_find_attrib(iq, "from"));

	/* create input component linked to prompt component */
	input_component_id = switch_mprintf("%s-input", switch_core_session_get_uuid(session));
	pool = NULL;
	switch_core_new_memory_pool(&pool);
	input_component = switch_core_alloc(pool, sizeof(*input_component));
	rayo_component_init(RAYO_COMPONENT(input_component), pool, "input", input_component_id, RAYO_ACTOR(prompt_component), RAYO_JID(prompt_component));
	switch_safe_free(input_component_id);

	/* create output component linked to prompt component */
	output_component = create_output_component(RAYO_ACTOR(prompt_component), output, RAYO_JID(prompt_component));

	/* start input and output */
	reply = start_call_input(input_component, session, input, iq, RAYO_JID(output_component), iks_find_bool_attrib(prompt, "barge-in"));
	if (!reply) {
		reply = start_call_output(output_component, session, output, iq);
	}
	/* TODO handle reply */

	return NULL;
}

/**
 * Stop execution of prompt component
 */
static iks *stop_call_prompt_component(struct rayo_actor *client, struct rayo_actor *component, iks *iq, void *data)
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

	globals.parser = srgs_parser_new(NULL);

	rayo_actor_command_handler_add(RAT_CALL, "", "set:"RAYO_INPUT_NS":input", start_call_input_component);
	rayo_actor_command_handler_add(RAT_CALL_COMPONENT, "input", "set:"RAYO_EXT_NS":stop", stop_call_input_component);
	switch_event_bind("rayo_input_component", SWITCH_EVENT_DETECTED_SPEECH, SWITCH_EVENT_SUBCLASS_ANY, on_detected_speech_event, NULL);

	/* Prompt is a special <input> linked to <output> */
	rayo_actor_command_handler_add(RAT_CALL, "", "set:"RAYO_PROMPT_NS":prompt", start_call_prompt_component);
	rayo_actor_command_handler_add(RAT_CALL_COMPONENT, "prompt", "set:"RAYO_EXT_NS":stop", stop_call_prompt_component);
	rayo_actor_command_handler_add(RAT_CALL_COMPONENT, "prompt", "result:"RAYO_NS":ref", prompt_component_handle_io_start);
	rayo_actor_command_handler_add(RAT_CALL_COMPONENT, "prompt", "error:"RAYO_PROMPT_NS":prompt", prompt_component_handle_io_error);
	rayo_actor_event_handler_add(RAT_CALL_COMPONENT, "input", RAT_CALL_COMPONENT, "prompt", "unavailable:"RAYO_EXT_NS":complete", prompt_component_handle_input_complete);
	rayo_actor_event_handler_add(RAT_CALL_COMPONENT, "output", RAT_CALL_COMPONENT, "prompt", "unavailable:"RAYO_EXT_NS":complete", prompt_component_handle_output_complete);

	return SWITCH_STATUS_SUCCESS;
}

/**
 * Shutdown input component
 * @return SWITCH_STATUS_SUCCESS if successful
 */
switch_status_t rayo_input_component_shutdown(void)
{
	srgs_parser_destroy(globals.parser);
	switch_event_unbind_callback(on_detected_speech_event);
	return SWITCH_STATUS_SUCCESS;
}
