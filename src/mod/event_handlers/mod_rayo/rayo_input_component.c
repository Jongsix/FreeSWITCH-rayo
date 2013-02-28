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

/**
 * Send DTMF match to client
 * @param call the call that created the component_ref
 * @param jid the component JID
 * @param digits the matching digits
 */
static void send_input_component_dtmf_match(struct rayo_call *call, const char *jid, const char *digits)
{
	switch_channel_t *channel = switch_core_session_get_channel(call->session);
	iks *response = iks_new("presence");
	iks *x;

	iks_insert_attrib(response, "from", jid);
	iks_insert_attrib(response, "to", switch_channel_get_variable(channel, "rayo_dcp_jid"));
	iks_insert_attrib(response, "type", "unavailable");
	x = iks_insert(response, "complete");
	iks_insert_attrib(x, "xmlns", RAYO_EXT_NS);
	x = iks_insert(x, "success"); /* TODO rayo spec says this should be "match" */
	iks_insert_attrib(x, "xmlns", RAYO_INPUT_COMPLETE_NS);
	iks_insert_attrib(x, "mode", "dtmf");
	iks_insert_attrib(x, "confidence", "1.0");
	x = iks_insert(x, "utterance");
	iks_insert_cdata(x, digits, strlen(digits));
	rayo_call_iks_send(call, response);
	iks_delete(response);
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

/* not yet supported by adhearsion */
//#define INPUT_INITIAL_TIMEOUT "initial-timeout", RAYO_INPUT_COMPLETE_NS
//#define INPUT_INTER_DIGIT_TIMEOUT "inter-digit-timeout", RAYO_INPUT_COMPLETE_NS
//#define INPUT_MAX_SILENCE "max-silence", RAYO_INPUT_COMPLETE_NS
//#define INPUT_MIN_CONFIDENCE "min-confidence", RAYO_INPUT_COMPLETE_NS
#define INPUT_NOMATCH "nomatch", RAYO_INPUT_COMPLETE_NS

/* this is not part of rayo spec */
#define INPUT_NOINPUT "noinput", RAYO_INPUT_COMPLETE_NS

#define RAYO_INPUT_COMPONENT_PRIVATE_VAR "__rayo_input_component"

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
	/** The call */
	struct rayo_call *call;
	/** component jid */
	const char *jid;
	/** stop flag */
	int stop;
	/** done flag */
	int done;
};

static switch_status_t input_component_on_hangup(switch_core_session_t *session);

/**
 * channel state callbacks
 */
static const switch_state_handler_table_t input_component_state_handlers = {
	/*.on_init */ NULL,
	/*.on_routing */ NULL,
	/*.on_execute */ NULL,
	/*.on_hangup */ input_component_on_hangup,
	/*.on_exchange_media */ NULL,
	/*.on_soft_execute */ NULL,
	/*.on_consume_media */ NULL,
	/*.on_hibernate */ NULL
};

/**
 * Monitor for hangup and send complete
 */
static switch_status_t input_component_on_hangup(switch_core_session_t *session)
{
	switch_channel_t *channel = switch_core_session_get_channel(session);
	struct input_handler *handler = (struct input_handler *)switch_channel_get_private(channel, RAYO_INPUT_COMPONENT_PRIVATE_VAR);
	if (handler && !handler->done) {
		handler->done = 1;
		rayo_call_component_send_complete(handler->call, handler->jid, COMPONENT_COMPLETE_HANGUP);
	}
	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t input_component_on_dtmf(switch_core_session_t *session, const switch_dtmf_t *dtmf, switch_dtmf_direction_t direction);

/**
 * Monitor DTMF timeouts
 */
static switch_status_t input_component_on_read_frame(switch_core_session_t *session, switch_frame_t **frame, switch_io_flag_t flags, int i)
{
	switch_channel_t *channel = switch_core_session_get_channel(session);
	struct input_handler *handler = (struct input_handler *)switch_channel_get_private(channel, RAYO_INPUT_COMPONENT_PRIVATE_VAR);
	if (handler) {
		enum srgs_match_type match = srgs_match(handler->parser, NULL);
		switch (match) {
			case SMT_NO_MATCH: {
				if (handler->stop) {
					handler->done = 1;
					switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Stopped\n");
					rayo_call_component_send_complete(handler->call, handler->jid, COMPONENT_COMPLETE_STOP);
					switch_core_event_hook_remove_recv_dtmf(session, input_component_on_dtmf);
					switch_core_event_hook_remove_read_frame(session, input_component_on_read_frame);
				}
				break;
			}
			case SMT_TIMEOUT: {
				handler->done = 1;
				if (handler->num_digits == 0) {
					switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "initial-timeout\n");
					rayo_call_component_send_complete(handler->call, handler->jid, INPUT_NOINPUT);
				} else {
					switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "inter-digit-timeout\n");
					rayo_call_component_send_complete(handler->call, handler->jid, INPUT_NOMATCH);
				}
				switch_core_event_hook_remove_recv_dtmf(session, input_component_on_dtmf);
				switch_core_event_hook_remove_read_frame(session, input_component_on_read_frame);
				break;
			}
			case SMT_MATCH: {
				handler->done = 1;
				send_input_component_dtmf_match(handler->call, handler->jid, handler->digits);
				switch_core_event_hook_remove_recv_dtmf(session, input_component_on_dtmf);
				switch_core_event_hook_remove_read_frame(session, input_component_on_read_frame);
				break;
			}
		}
	}
	return SWITCH_STATUS_SUCCESS;
}

/**
 * Process DTMF press
 */
static switch_status_t input_component_on_dtmf(switch_core_session_t *session, const switch_dtmf_t *dtmf, switch_dtmf_direction_t direction)
{
	switch_channel_t *channel = switch_core_session_get_channel(session);
	struct input_handler *handler = (struct input_handler *)switch_channel_get_private(channel, RAYO_INPUT_COMPONENT_PRIVATE_VAR);
	if (handler) {
		enum srgs_match_type match;
		handler->digits[handler->num_digits] = dtmf->digit;
		handler->num_digits++;
		handler->digits[handler->num_digits] = '\0';
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Collected digits = \"%s\"\n", handler->digits);

		match = srgs_match(handler->parser, handler->digits + handler->num_digits - 1);

		switch (match) {
			case SMT_NO_MATCH: {
				/* need more digits */
				break;
			}
			case SMT_TIMEOUT: {
				/* notify of no-match and remove input handler */
				handler->done = 1;
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "NO MATCH = %s\n", handler->digits);
				rayo_call_component_send_complete(handler->call, handler->jid, INPUT_NOMATCH);

				switch_core_event_hook_remove_recv_dtmf(session, input_component_on_dtmf);
				switch_core_event_hook_remove_read_frame(session, input_component_on_read_frame);
				break;
			}
			case SMT_MATCH: {
				/* notify of match and remove input handler */
				handler->done = 1;
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "MATCH = %s\n", handler->digits);
				send_input_component_dtmf_match(handler->call, handler->jid, handler->digits);

				switch_core_event_hook_remove_recv_dtmf(session, input_component_on_dtmf);
				switch_core_event_hook_remove_read_frame(session, input_component_on_read_frame);
				break;
			}
		}
	}
    return SWITCH_STATUS_SUCCESS;
}

/**
 * Start execution of input component
 */
static void start_call_input_component(struct rayo_call *call, iks *iq)
{
	switch_core_session_t *session = call->session;
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
		rayo_call_component_send_iq_error(call, iq, STANZA_ERROR_BAD_REQUEST);
		return;
	}

	/* missing grammar */
	grammar = iks_find(input, "grammar");
	if (!grammar) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Missing <input><grammar>\n");
		rayo_call_component_send_iq_error(call, iq, STANZA_ERROR_BAD_REQUEST);
		return;
	}

	/* only support srgs */
	content_type = iks_find_attrib(grammar, "content-type");
	if (!zstr(content_type) && strcmp("application/srgs+xml", content_type)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Unsupported content type\n");
		rayo_call_component_send_iq_error(call, iq, STANZA_ERROR_BAD_REQUEST);
		return;
	}

	/* missing grammar body */
	srgs = iks_find_cdata(input, "grammar");
	if (zstr(srgs)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Grammar body is missing\n");
		rayo_call_component_send_iq_error(call, iq, STANZA_ERROR_BAD_REQUEST);
		return;
	}
	//switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Grammar = %s\n", srgs);

	/* set up input handler for new detection */
	handler = (struct input_handler *)switch_channel_get_private(switch_core_session_get_channel(session), RAYO_INPUT_COMPONENT_PRIVATE_VAR);
	if (!handler) {
		/* create input handler */
		handler = switch_core_session_alloc(session, sizeof(*handler));
		handler->parser = srgs_parser_new(switch_core_session_get_pool(session), switch_core_session_get_uuid(session));
		switch_channel_set_private(switch_core_session_get_channel(session), RAYO_INPUT_COMPONENT_PRIVATE_VAR, handler);
	}
	handler->num_digits = 0;
	handler->digits[0] = '\0';
	handler->call = call;
	handler->stop = 0;
	handler->done = 0;

	/* parse the grammar */
	if (!srgs_parse(handler->parser, srgs, i_attribs.initial_timeout.v.i, i_attribs.inter_digit_timeout.v.i)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Failed to parse grammar body\n");
		rayo_call_component_send_iq_error(call, iq, STANZA_ERROR_BAD_REQUEST);
		return;
	}

	/* all good, acknowledge command */
	handler->jid = rayo_call_component_send_start(call, iq, "input");

	/* install input callbacks */
	switch_core_event_hook_add_recv_dtmf(session, input_component_on_dtmf);
	switch_core_event_hook_add_read_frame(session, input_component_on_read_frame);
	switch_channel_add_state_handler(switch_core_session_get_channel(session), &input_component_state_handlers);
}

/**
 * Stop execution of input component
 */
static iks *stop_call_input_component(struct rayo_call *call, iks *iq)
{
	switch_channel_t *channel = switch_core_session_get_channel(call->session);
	struct input_handler *handler = (struct input_handler *)switch_channel_get_private(channel, RAYO_INPUT_COMPONENT_PRIVATE_VAR);
	if (handler) {
		handler->stop = 1;
	}
	return iks_new_iq_result(iq);
}

/**
 * Initialize input component
 * @return SWITCH_STATUS_SUCCESS if successful
 */
switch_status_t rayo_input_component_load(void)
{
	
	rayo_call_component_interface_add("set:"RAYO_INPUT_NS":input", start_call_input_component, stop_call_input_component);
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
