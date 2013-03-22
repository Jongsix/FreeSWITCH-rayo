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
#include "iks_helpers.h"
#include "srgs.h"
#include "nlsml.h"

#define MAX_DTMF 64

/* not yet supported by adhearsion */
#define INPUT_INITIAL_TIMEOUT "initial-timeout", RAYO_INPUT_COMPLETE_NS
#define INPUT_INTER_DIGIT_TIMEOUT "inter-digit-timeout", RAYO_INPUT_COMPLETE_NS
#define INPUT_MAX_SILENCE "max-silence", RAYO_INPUT_COMPLETE_NS
#define INPUT_MIN_CONFIDENCE "min-confidence", RAYO_INPUT_COMPLETE_NS
#define INPUT_MATCH "match", RAYO_INPUT_COMPLETE_NS
#define INPUT_NOMATCH "nomatch", RAYO_INPUT_COMPLETE_NS

#define RAYO_INPUT_COMPONENT_PRIVATE_VAR "__rayo_input_component"

static ATTRIB_RULE(input_mode)
{
	return !strcasecmp("any", value) || !strcasecmp("dtmf", value) || !strcasecmp("speech", value);
}

/**
 * <input> component validation
 */
ELEMENT(RAYO_INPUT)
	ATTRIB(mode, any, input_mode)
	ATTRIB(terminator,, any)
	ATTRIB(recognizer, en-US, any)
	ATTRIB(initial-timeout, -1, positive_or_neg_one)
	ATTRIB(inter-digit-timeout, -1, positive_or_neg_one)
	ATTRIB(sensitivity, 0.5, decimal_between_zero_and_one)
	ATTRIB(min-confidence, 0, decimal_between_zero_and_one)
	ATTRIB(max-silence, -1, positive_or_neg_one)
ELEMENT_END

/**
 * Current digit collection state
 */
struct input_handler {
	/** true if speech detection */
	int speech_mode;
	/** Number of collected digits */
	int num_digits;
	/** The collected digits */
	char digits[MAX_DTMF + 1];
	/** The grammar parser */
	struct srgs_parser *parser;
	/** The component */
	struct rayo_component *component;
	/** time when last digit was received */
	switch_time_t last_digit_time;
	/** timeout before first digit is received */
	int initial_timeout;
	/** timeout after first digit is received */
	int inter_digit_timeout;
	/** stop flag */
	int stop;
	/** done flag */
	int done;
	/** media bug to monitor frames / control input lifecycle */
	switch_media_bug_t *bug;
};

/**
 * Process DTMF press
 */
static switch_status_t input_component_on_dtmf(switch_core_session_t *session, const switch_dtmf_t *dtmf, switch_dtmf_direction_t direction)
{
	switch_channel_t *channel = switch_core_session_get_channel(session);
	struct input_handler *handler = (struct input_handler *)switch_channel_get_private(channel, RAYO_INPUT_COMPONENT_PRIVATE_VAR);
	if (handler && !handler->done) {
		enum srgs_match_type match;
		handler->digits[handler->num_digits] = dtmf->digit;
		handler->num_digits++;
		handler->digits[handler->num_digits] = '\0';
		handler->last_digit_time = switch_micro_time_now();
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Collected digits = \"%s\"\n", handler->digits);

		match = srgs_match(handler->parser, handler->digits);

		switch (match) {
			case SMT_MATCH_PARTIAL: {
				/* need more digits */
				break;
			}
			case SMT_NO_MATCH: {
				/* notify of no-match and remove input handler */
				handler->done = 1;
				switch_core_media_bug_remove(session, &handler->bug);
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "NO MATCH = %s\n", handler->digits);
				rayo_component_send_complete(handler->component, INPUT_NOMATCH);
				break;
			}
			case SMT_MATCH: {
				iks *result = nlsml_create_dtmf_match(handler->digits);
				/* notify of match and remove input handler */
				handler->done = 1;
				switch_core_media_bug_remove(session, &handler->bug);
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "MATCH = %s\n", handler->digits);
				rayo_component_send_complete_with_metadata(handler->component, INPUT_MATCH, result);
				iks_delete(result);
				break;
			}
		}
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
	switch(type) {
		case SWITCH_ABC_TYPE_INIT: {
			switch_core_event_hook_add_recv_dtmf(session, input_component_on_dtmf);
			break;
		}
		case SWITCH_ABC_TYPE_READ_REPLACE: {
			switch_frame_t *rframe = switch_core_media_bug_get_read_replace_frame(bug);
			/* check for timeout */
			if (!handler->done) {
				int elapsed_ms = (switch_micro_time_now() - handler->last_digit_time) / 1000;
				if (handler->num_digits && handler->inter_digit_timeout > 0 && elapsed_ms > handler->inter_digit_timeout) {
					handler->done = 1;
					switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "inter-digit-timeout\n");
					rayo_component_send_complete(handler->component, INPUT_INTER_DIGIT_TIMEOUT);
				} else if (!handler->num_digits && handler->initial_timeout > 0 && elapsed_ms > handler->initial_timeout) {
					handler->done = 1;
					switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "initial-timeout\n");
					rayo_component_send_complete(handler->component, INPUT_INITIAL_TIMEOUT);
				}
			}
			switch_core_media_bug_set_read_replace_frame(bug, rframe);
			break;
		}
		case SWITCH_ABC_TYPE_CLOSE:
			/* check for hangup */
			if (handler->done) {
				/* ignore */
			} else if (handler->stop) {
				handler->done = 1;
				rayo_component_send_complete(handler->component, COMPONENT_COMPLETE_STOP);
			} else {
				handler->done = 1;
				rayo_component_send_complete(handler->component, COMPONENT_COMPLETE_HANGUP);
			}
			switch_core_event_hook_remove_recv_dtmf(session, input_component_on_dtmf);
			break;
		default:
			break;
	}
	return SWITCH_TRUE;
}

char *create_input_component_id(const char *uuid)
{
	return switch_mprintf("%s-input", uuid);
}

/**
 * Start execution of input component
 */
static iks *start_call_input_component(struct rayo_call *call, switch_core_session_t *session, iks *iq)
{
	char *component_id = NULL;
	iks *input = iks_child(iq);
	iks *grammar = NULL;
	char *content_type = NULL;
	char *srgs = NULL;
	struct input_handler *handler = NULL;

	/* validate input attributes */
	if (!VALIDATE_RAYO_INPUT(input)) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Bad input attrib\n");
		rayo_component_send_iq_error_detailed(iq, STANZA_ERROR_BAD_REQUEST, "Bad <input> attrib value");
		return NULL;
	}

	/* missing grammar */
	grammar = iks_find(input, "grammar");
	if (!grammar) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Missing <input><grammar>\n");
		rayo_component_send_iq_error_detailed(iq, STANZA_ERROR_BAD_REQUEST, "Missing <grammar>");
		return NULL;
	}

	/* only support srgs */
	content_type = iks_find_attrib(grammar, "content-type");
	if (!zstr(content_type) && strcmp("application/srgs+xml", content_type)) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Unsupported content type\n");
		rayo_component_send_iq_error_detailed(iq, STANZA_ERROR_BAD_REQUEST, "Unsupported content type");
		return NULL;
	}

	/* missing grammar body */
	srgs = iks_find_cdata(input, "grammar");
	if (zstr(srgs)) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Grammar body is missing\n");
		rayo_component_send_iq_error_detailed(iq, STANZA_ERROR_BAD_REQUEST, "Grammar body is missing");
		return NULL;
	}
	//switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Grammar = %s\n", srgs);

	/* set up input handler for new detection */
	handler = (struct input_handler *)switch_channel_get_private(switch_core_session_get_channel(session), RAYO_INPUT_COMPONENT_PRIVATE_VAR);
	if (!handler) {
		/* create input handler */
		handler = switch_core_session_alloc(session, sizeof(*handler));
		handler->parser = srgs_parser_new(switch_core_session_get_uuid(session));
		switch_channel_set_private(switch_core_session_get_channel(session), RAYO_INPUT_COMPONENT_PRIVATE_VAR, handler);
	}

	/* parse the grammar */
	if (!srgs_parse(handler->parser, srgs)) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Failed to parse grammar body\n");
		rayo_component_send_iq_error_detailed(iq, STANZA_ERROR_BAD_REQUEST, "Failed to parse grammar body");
		return NULL;
	}

	/* create component */
	component_id = create_input_component_id(switch_core_session_get_uuid(session));
	handler->component = rayo_component_create("input", component_id, rayo_call_get_actor(call), iks_find_attrib(iq, "from"));
	switch_safe_free(component_id);
	if (!handler->component) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_CRIT, "Failed to create input component!\n");
		rayo_component_send_iq_error_detailed(iq, STANZA_ERROR_INTERNAL_SERVER_ERROR, "Failed to create input component!");
		return NULL;
	}
	rayo_component_set_data(handler->component, handler);
	handler->num_digits = 0;
	handler->digits[0] = '\0';
	handler->stop = 0;
	handler->done = 0;
	handler->speech_mode = 0;
	handler->bug = NULL;

	/* is this voice or dtmf srgs grammar? */
	if (!strcasecmp("dtmf", iks_find_attrib_soft(input, "mode"))) {
		handler->last_digit_time = switch_micro_time_now();
		handler->initial_timeout = iks_find_int_attrib(input, "initial-timeout");
		handler->inter_digit_timeout = iks_find_int_attrib(input, "inter-digit-timeout");

		/* acknowledge command */
		rayo_component_send_start(handler->component, iq);

		/* start dtmf input detection */
		if (switch_core_media_bug_add(session, "rayo_input_component", NULL, input_component_bug_callback, handler, 0, SMBF_READ_REPLACE, &handler->bug) != SWITCH_STATUS_SUCCESS) {
			rayo_component_send_complete(handler->component, COMPONENT_COMPLETE_ERROR);
			return NULL;
		}
	} else {
		const char *jsgf_path;
		char *grammar = NULL;
		handler->speech_mode = 1;
		jsgf_path = srgs_to_jsgf_file(handler->parser, SWITCH_GLOBAL_dirs.grammar_dir, "gram");
		if (!jsgf_path) {
			rayo_component_send_iq_error_detailed(iq, STANZA_ERROR_INTERNAL_SERVER_ERROR, "Grammar error");
			rayo_component_unlock(handler->component);
			rayo_component_destroy(handler->component);
			return NULL;
		}

		/* acknowledge command */
		rayo_component_send_start(handler->component, iq);

		/* TODO configurable speech detection - different engines, grammar passthrough, dtmf handled by recognizer */
		grammar = switch_mprintf("{no-input-timeout=%s,speech-timeout=%s,start-input-timers=true,confidence-threshold=%d}%s",
			iks_find_attrib(input, "initial-timeout"), iks_find_attrib(input, "max-silence"),
			(int)ceil(iks_find_decimal_attrib(input, "min-confidence") * 100.0), jsgf_path);
		/* start speech detection */
		switch_channel_set_variable(switch_core_session_get_channel(session), "fire_asr_events", "true");
		if (switch_ivr_detect_speech(session, "pocketsphinx", grammar, "mod_rayo_grammar", "", NULL) != SWITCH_STATUS_SUCCESS) {
			rayo_component_send_complete(handler->component, COMPONENT_COMPLETE_ERROR);
		}
		switch_safe_free(grammar);
	}

	return NULL;
}

/**
 * Stop execution of input component
 */
static iks *stop_input_component(struct rayo_component *component, iks *iq)
{
	struct input_handler *handler = (struct input_handler *)rayo_component_get_data(component);

	if (handler && !handler->done && !handler->stop) {
		switch_core_session_t *session = switch_core_session_locate(rayo_component_get_parent_id(component));
		if (session) {
			if (handler->speech_mode) {
				handler->stop = 1;
				handler->done = 1;
				switch_ivr_stop_detect_speech(session);
				rayo_component_send_complete(component, COMPONENT_COMPLETE_STOP);
			} else if (handler->bug) {
				handler->stop = 1;
				switch_core_media_bug_remove(session, &handler->bug);
			}
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
		char *component_id = create_input_component_id(uuid);
		struct rayo_component *component = rayo_component_locate(component_id);
		switch_safe_free(component_id);
		if (component) {
			const char *result = switch_event_get_body(event);
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
			rayo_component_unlock(component);
		}
	} else if (!strcasecmp("closed", speech_type)) {
		const char *uuid = switch_event_get_header(event, "Unique-ID");
		char *component_id = create_input_component_id(uuid);
		struct rayo_component *component = rayo_component_locate(component_id);
		switch_safe_free(component_id);
		if (component) {
			char *channel_state = switch_event_get_header(event, "Channel-State");
			switch_log_printf(SWITCH_CHANNEL_UUID_LOG(uuid), SWITCH_LOG_DEBUG, "Recognizer closed\n");
			if (channel_state && !strcmp("CS_HANGUP", channel_state)) {
				rayo_component_send_complete(component, COMPONENT_COMPLETE_HANGUP);
			} else {
				/* shouldn't get here... */
				rayo_component_send_complete(component, COMPONENT_COMPLETE_ERROR);
			}
			rayo_component_unlock(component);
		}
	}
	switch_safe_free(event_str);
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
	rayo_call_component_command_handler_add("input", "set:"RAYO_EXT_NS":stop", stop_input_component);
	switch_event_bind("rayo_input_component", SWITCH_EVENT_DETECTED_SPEECH, SWITCH_EVENT_SUBCLASS_ANY, on_detected_speech_event, NULL);
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
