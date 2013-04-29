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

#define MAX_DTMF 1024

/* not yet supported by adhearsion */
//#define INPUT_INITIAL_TIMEOUT "initial-timeout", RAYO_INPUT_COMPLETE_NS
//#define INPUT_INTER_DIGIT_TIMEOUT "inter-digit-timeout", RAYO_INPUT_COMPLETE_NS
//#define INPUT_MAX_SILENCE "max-silence", RAYO_INPUT_COMPLETE_NS
//#define INPUT_MIN_CONFIDENCE "min-confidence", RAYO_INPUT_COMPLETE_NS
#define INPUT_NOMATCH "nomatch", RAYO_INPUT_COMPLETE_NS

/* this is not part of rayo spec */
#define INPUT_NOINPUT "noinput", RAYO_INPUT_COMPLETE_NS
#define INPUT_SUCCESS "success", RAYO_INPUT_COMPLETE_NS

#define RAYO_INPUT_COMPONENT_PRIVATE_VAR "__rayo_input_component"

/**
 * Send DTMF match to client
 * @param component the component
 * @param digits the matching digits
 */
static void send_input_component_dtmf_match(struct rayo_component *component, const char *digits)
{
	iks *presence = rayo_component_create_complete_event(component, INPUT_SUCCESS);
	iks *x = iks_find(presence, "complete");
	x = iks_find(x, "success");
	iks_insert_attrib(x, "mode", "dtmf");
	iks_insert_attrib(x, "confidence", "1.0");
	x = iks_insert(x, "utterance");
	iks_insert_cdata(x, digits, strlen(digits));
	rayo_component_send_complete_event(component, presence);
}

static ATTRIB_RULE(input_mode)
{
	attrib->type = IAT_STRING;
	attrib->test = "(any || dtmf || speech)";
	attrib->v.s = (char *)value;
	/* for now, only allow dtmf;
	return !strcmp("any", value) || !strcmp("dtmf", value) || !strcmp("speech", value); */
	return !strcmp("dtmf", value);
}

/**
 * <input> component validation
 */
static const struct iks_attrib_definition input_attribs_def[] = {
	ATTRIB(mode, any, input_mode),
	ATTRIB(terminator,, any),
	ATTRIB(recognizer, en-US, any),
	ATTRIB(initial-timeout, -1, positive_or_neg_one),
	ATTRIB(inter-digit-timeout, -1, positive_or_neg_one),
	ATTRIB(sensitivity, 0.5, decimal_between_zero_and_one),
	ATTRIB(min-confidence, 0, decimal_between_zero_and_one),
	ATTRIB(max-silence, -1, positive_or_neg_one),
	LAST_ATTRIB
};

/**
 * <input> component attributes
 */
struct input_attribs {
	int size;
	struct iks_attrib mode;
	struct iks_attrib terminator;
	struct iks_attrib recognizer;
	struct iks_attrib initial_timeout;
	struct iks_attrib inter_digit_timeout;
	struct iks_attrib sensitivity;
	struct iks_attrib min_confidence;
	struct iks_attrib max_silence;
};

/**
 * Current digit collection state
 */
struct input_handler {
	/** Number of collected digits */
	int num_digits;
	/** The collected digits */
	char digits[MAX_DTMF + 1];
	/** The grammar parser */
	struct srgs_parser *parser;
	/** The component */
	struct rayo_component *component;
	/** component jid */
	const char *jid;
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
				/* notify of match and remove input handler */
				handler->done = 1;
				switch_core_media_bug_remove(session, &handler->bug);
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "MATCH = %s\n", handler->digits);
				send_input_component_dtmf_match(handler->component, handler->digits);
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
					rayo_component_send_complete(handler->component, INPUT_NOMATCH);
				} else if (!handler->num_digits && handler->initial_timeout > 0 && elapsed_ms > handler->initial_timeout) {
					handler->done = 1;
					switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "initial-timeout\n");
					rayo_component_send_complete(handler->component, INPUT_NOINPUT);
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

/**
 * Start execution of input component
 */
static iks *start_call_input_component(struct rayo_call *call, switch_core_session_t *session, iks *iq)
{
	struct input_attribs i_attribs;
	iks *input = iks_child(iq);
	iks *grammar = NULL;
	char *content_type = NULL;
	char *srgs = NULL;
	struct input_handler *handler = NULL;

	/* validate input attributes */
	memset(&i_attribs, 0, sizeof(i_attribs));
	if (!iks_attrib_parse(session, input, input_attribs_def, (struct iks_attribs *)&i_attribs)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Bad input attrib\n");
		rayo_component_send_iq_error(iq, STANZA_ERROR_BAD_REQUEST);
		return NULL;
	}

	/* missing grammar */
	grammar = iks_find(input, "grammar");
	if (!grammar) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Missing <input><grammar>\n");
		rayo_component_send_iq_error(iq, STANZA_ERROR_BAD_REQUEST);
		return NULL;
	}

	/* only support srgs */
	content_type = iks_find_attrib(grammar, "content-type");
	if (!zstr(content_type) && strcmp("application/srgs+xml", content_type)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Unsupported content type\n");
		rayo_component_send_iq_error(iq, STANZA_ERROR_BAD_REQUEST);
		return NULL;
	}

	/* missing grammar body */
	srgs = iks_find_cdata(input, "grammar");
	if (zstr(srgs)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Grammar body is missing\n");
		rayo_component_send_iq_error(iq, STANZA_ERROR_BAD_REQUEST);
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
	handler->num_digits = 0;
	handler->digits[0] = '\0';
	handler->component = NULL;
	handler->stop = 0;
	handler->done = 0;
	handler->bug = NULL;
	handler->last_digit_time = switch_micro_time_now();
	handler->initial_timeout = GET_INT(i_attribs, initial_timeout);
	handler->inter_digit_timeout = GET_INT(i_attribs, inter_digit_timeout);

	/* parse the grammar */
	if (!srgs_parse(handler->parser, srgs)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Failed to parse grammar body\n");
		rayo_component_send_iq_error(iq, STANZA_ERROR_BAD_REQUEST);
		return NULL;
	}

	/* create component */
	handler->component = rayo_call_component_create(NULL, call, "input", iks_find_attrib(iq, "from"));
	rayo_component_set_data(handler->component, handler);

	/* start input detection */
	switch_core_media_bug_add(session, "rayo_input_component", NULL, input_component_bug_callback, handler, 0, SMBF_READ_REPLACE, &handler->bug);

	/* acknowledge command */
	rayo_component_send_start(handler->component, iq);
	
	return NULL;
}

/**
 * Stop execution of input component
 */
static iks *stop_input_component(struct rayo_component *component, iks *iq)
{
	struct input_handler *handler = (struct input_handler *)rayo_component_get_data(component);
	
	if (handler && !handler->done && !handler->stop && handler->bug) {
		switch_core_session_t *session = switch_core_session_locate(rayo_component_get_parent_id(component));
		if (session) {
			handler->stop = 1;
			switch_core_media_bug_remove(session, &handler->bug);
			switch_core_session_rwunlock(session);
		}
	}
	return iks_new_iq_result(iq);
}

/**
 * Initialize input component
 * @return SWITCH_STATUS_SUCCESS if successful
 */
switch_status_t rayo_input_component_load(void)
{
	rayo_call_command_handler_add("set:"RAYO_INPUT_NS":input", start_call_input_component);
	rayo_component_command_handler_add("input", "set:"RAYO_NS":stop", stop_input_component); /* TODO remove when punchblock is updated */
	rayo_component_command_handler_add("input", "set:"RAYO_EXT_NS":stop", stop_input_component);
	return SWITCH_STATUS_SUCCESS;
}

/**
 * Shutdown input component
 * @return SWITCH_STATUS_SUCCESS if successful
 */
switch_status_t rayo_input_component_shutdown(void)
{
	return SWITCH_STATUS_SUCCESS;
}
