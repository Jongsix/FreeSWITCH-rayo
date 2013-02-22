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
 * components.c -- Rayo component implementations
 *
 */
#include <switch.h>

#include "mod_rayo.h"
#include "iks_helpers.h"
#include "srgs.h"

#define MAX_DTMF 1024


/**
 * Create a component ref
 */
static char *create_component_ref(switch_core_session_t *session, struct rayo_call *call, const char *type) 
{
	return switch_core_session_sprintf(session, "%s-%d", type, call->next_ref++);
}

/**
 * @param call 
 * @param component_ref
 * @return JID for component
 */
static char *create_call_component_jid(switch_core_session_t *session, struct rayo_call *call, char *component_ref)
{
	return switch_core_session_sprintf(session, "%s/%s", call->jid, component_ref);
}

/**
 * Send IQ error to controlling client from call
 * @param session the session that detected the error
 * @param iq the request that caused the error
 * @param error the error message
 */
void app_send_iq_error(switch_core_session_t *session, iks *iq, const char *error_name, const char *error_type)
{
	switch_event_t *event;
	switch_channel_t *channel = switch_core_session_get_channel(session);
	iks *response = iks_new_iq_error(iq, 
		switch_channel_get_variable(channel, "rayo_call_jid"),
		switch_channel_get_variable(channel, "rayo_dcp_jid"),
		error_name, error_type);

	/* send message to Rayo session via event */
	if (switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, RAYO_EVENT_XMPP_SEND) == SWITCH_STATUS_SUCCESS) {
		char *response_str = iks_string(NULL, response);
		switch_channel_event_set_data(channel, event);
		switch_event_add_body(event, "%s", response_str);
		switch_event_fire(&event);
		iks_free(response_str);
	}

	iks_delete(response);
}

/**
 * Send component ref to controlling client from call
 * @param session the session that created the component
 * @param iq the request that requested the component
 * @param ref the component ref
 */
static void send_component_ref(switch_core_session_t *session, iks *iq, const char *ref)
{
	switch_event_t *event;
	switch_channel_t *channel = switch_core_session_get_channel(session);
	iks *x, *response = NULL;

	response = iks_new_iq_result(
		switch_channel_get_variable(channel, "rayo_call_jid"),
		switch_channel_get_variable(channel, "rayo_dcp_jid"),
		iks_find_attrib(iq, "id"));
	x = iks_insert(response, "ref");
	iks_insert_attrib(x, "xmlns", "urn:xmpp:rayo:1");
	iks_insert_attrib(x, "id", ref);

	if (switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, RAYO_EVENT_XMPP_SEND) == SWITCH_STATUS_SUCCESS) {
		char *response_str = iks_string(NULL, response);
		switch_channel_event_set_data(channel, event);
		switch_event_add_body(event, "%s", response_str);
		switch_event_fire(&event);
		iks_free(response_str);
	}
	iks_delete(response);
}

/**
 * Send component complete presence to client
 * @param session the session that created the component
 * @param jid the component JID
 * @param reason the completion reason
 * @param reason_namespace the completion reason namespace
 * @param reason_detail optional detail
 */
static void send_component_complete(switch_core_session_t *session, const char *jid, const char *reason, const char *reason_namespace)
{
	switch_event_t *event;
	switch_channel_t *channel = switch_core_session_get_channel(session);
	char *response = switch_mprintf(
		"<presence from='%s' to='%s' type='unavailable'>"
		"<complete xmlns='urn:xmpp:rayo:ext:1'><%s xmlns='%s'/></complete></presence>",
		jid,
		switch_channel_get_variable(channel, "rayo_dcp_jid"),
		reason,
		reason_namespace);

	if (switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, RAYO_EVENT_XMPP_SEND) == SWITCH_STATUS_SUCCESS) {
		switch_channel_event_set_data(channel, event);
		switch_event_add_body(event, "%s", response);
		switch_event_fire(&event);
	}
	switch_safe_free(response);
}

/**
 * Send DTMF match to client
 * @param session the sesion that created the component_ref
 * @param jid the component JID
 * @param digits the matching digits 
 */
static void send_input_component_dtmf_match(switch_core_session_t *session, const char *jid, const char *digits)
{
	switch_event_t *event;
	switch_channel_t *channel = switch_core_session_get_channel(session);
	iks *response = iks_new("presence");
	iks *x;
	
	iks_insert_attrib(response, "from", jid);
	iks_insert_attrib(response, "to", switch_channel_get_variable(channel, "rayo_dcp_jid"));
	iks_insert_attrib(response, "type", "unavailable");
	x = iks_insert(response, "complete");
	iks_insert_attrib(x, "xmlns", "urn:xmpp:rayo:ext:1");
	x = iks_insert(x, "success"); /* TODO rayo spec says this should be "match" */
	iks_insert_attrib(x, "xmlns", "urn:xmpp:rayo:input:complete:1");
	iks_insert_attrib(x, "mode", "dtmf");
	iks_insert_attrib(x, "confidence", "1.0");
	x = iks_insert(x, "utterance");
	iks_insert_cdata(x, digits, strlen(digits));

	if (switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, RAYO_EVENT_XMPP_SEND) == SWITCH_STATUS_SUCCESS) {
		char *response_str = iks_string(NULL, response);
		switch_channel_event_set_data(channel, event);
		switch_event_add_body(event, "%s", response_str);
		switch_event_fire(&event);
		iks_free(response_str);
	}
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
//#define INPUT_INITIAL_TIMEOUT "initial-timeout", "urn:xmpp:rayo:input:complete:1"
//#define INPUT_INTER_DIGIT_TIMEOUT "inter-digit-timeout", "urn:xmpp:rayo:input:complete:1"
//#define INPUT_MAX_SILENCE "max-silence", "urn:xmpp:rayo:input:complete:1"
//#define INPUT_MIN_CONFIDENCE "min-confidence", "urn:xmpp:rayo:input:complete:1"
#define INPUT_NOMATCH "nomatch", "urn:xmpp:rayo:input:complete:1"

/* this is not part of rayo spec */
#define INPUT_NOINPUT "noinput", "urn:xmpp:rayo:input:complete:1"

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
	/** terminating digits */
	int term_digit_mask;
	/** timeout before digits have been collected */
	int initial_timeout;
	/** timeout between digits */
	int inter_digit_timeout;
	/** TODO */
	int max_silence;
	/** Time last digit was received */
	switch_time_t last_digit_time;
	/** True if first digit has been collected */
	int got_first_digit;
	/** True if enough digits have been collected, but more can still be collected */
	int lazy_match;
};

/**
 * Get digit mask
 * @param digit to mask
 * @return mask value
 */
static int get_digit_mask(char digit)
{
	switch (digit) {
		case '0': return 1;
		case '1': return 1 << 1;
		case '2': return 1 << 2;
		case '3': return 1 << 3;
		case '4': return 1 << 4;
		case '5': return 1 << 5;
		case '6': return 1 << 6;
		case '7': return 1 << 7;
		case '8': return 1 << 8;
		case '9': return 1 << 9;
		case 'A':
		case 'a': return 1 << 10;
		case 'B':
		case 'b': return 1 << 11;
		case 'C':
		case 'c': return 1 << 12;
		case 'D':
		case 'd': return 1 << 13;
		case '*': return 1 << 14;
		case '#': return 1 << 15;
	}
	return 0;
}

/**
 * Get digit mask from digit string
 * @param digits the digits
 * @return the mask
 */
static int get_digit_mask_from_string(const char *digits)
{
	int mask = 0;
	if (digits) {
		while (*digits) {
			mask |= get_digit_mask(*digits);
			digits++;
		}
	}
	return mask;
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
		switch_time_t elapsed = switch_time_now() - handler->last_digit_time;
		if (handler->initial_timeout > 0 && !handler->got_first_digit && elapsed > (handler->initial_timeout * 1000)) {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "%i initial-timeout\n", handler->initial_timeout);
			switch_mutex_lock(handler->call->mutex);
			send_component_complete(session, handler->call->input_jid, INPUT_NOINPUT);

			switch_core_event_hook_remove_recv_dtmf(session, input_component_on_dtmf);
			switch_core_event_hook_remove_read_frame(session, input_component_on_read_frame);
			handler->call->input_jid = "";
			switch_mutex_unlock(handler->call->mutex);
		} else if (handler->inter_digit_timeout > 0 && handler->got_first_digit && elapsed > (handler->inter_digit_timeout * 1000)) {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "%i inter-digit-timeout\n", handler->inter_digit_timeout);
			switch_mutex_lock(handler->call->mutex);
			send_component_complete(session, handler->call->input_jid, INPUT_NOMATCH);

			switch_core_event_hook_remove_recv_dtmf(session, input_component_on_dtmf);
			switch_core_event_hook_remove_read_frame(session, input_component_on_read_frame);
			handler->call->input_jid = "";
			switch_mutex_unlock(handler->call->mutex);
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
		enum match_type match;
		handler->digits[handler->num_digits] = dtmf->digit;
		handler->num_digits++;
		handler->digits[handler->num_digits] = '\0';
		handler->last_digit_time = switch_micro_time_now();
		handler->got_first_digit = 1;
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Collected digits = \"%s\"\n", handler->digits);

		/* check for match */
		if (get_digit_mask(dtmf->digit) & handler->term_digit_mask) {
			/* got terminating digit */
			if (handler->lazy_match) {
				match = MT_MATCH;
			} else {
				match = MT_NO_MATCH;
			}
		} else {
			match = srgs_match(handler->parser, handler->digits);
		}

		switch (match) {
			case MT_MATCH_PARTIAL: {
				/* need more digits */
				break;
			}
			case MT_MATCH_LAZY: {
				/* If we get a term digit or there is a timeout, this is a good enough match */
				handler->lazy_match = 1;
			}
			case MT_NO_MATCH: {
				/* notify of no-match and remove input handler */
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "NO MATCH = %s\n", handler->digits);
				switch_mutex_lock(handler->call->mutex);
				send_component_complete(session, handler->call->input_jid, INPUT_NOMATCH);

				switch_core_event_hook_remove_recv_dtmf(session, input_component_on_dtmf);
				switch_core_event_hook_remove_read_frame(session, input_component_on_read_frame);
				handler->call->input_jid = "";
				switch_mutex_unlock(handler->call->mutex);
				break;
			}
			case MT_MATCH: {
				/* notify of match and remove input handler */
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "MATCH = %s\n", handler->digits);
				switch_mutex_lock(handler->call->mutex);
				send_input_component_dtmf_match(session, handler->call->input_jid, handler->digits);

				switch_core_event_hook_remove_recv_dtmf(session, input_component_on_dtmf);
				switch_core_event_hook_remove_read_frame(session, input_component_on_read_frame);
				handler->call->input_jid = "";
				switch_mutex_unlock(handler->call->mutex);
				break;
			}
		}
	}
    return SWITCH_STATUS_SUCCESS;
}

/**
 * Start execution of input component
 */
void start_input_component(switch_core_session_t *session, struct rayo_call *call, iks *iq)
{
	struct input_attribs i_attribs;
	char *ref = NULL;
	iks *input = iks_child(iq);
	iks *grammar = NULL;
	char *content_type = NULL;
	char *srgs = NULL;
	struct input_handler *handler = NULL;

	switch_mutex_lock(call->mutex);

	/* already have input component? */
	if (!zstr(call->input_jid)) {
		app_send_iq_error(session, iq, STANZA_ERROR_CONFLICT);
		goto done;
	}

	/* validate input attributes */
	memset(&i_attribs, 0, sizeof(i_attribs));
	if (!iks_attrib_parse(session, input, input_attribs_def, (struct iks_attribs *)&i_attribs)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Bad input attrib\n");
		app_send_iq_error(session, iq, STANZA_ERROR_BAD_REQUEST);
		goto done;
	}

	/* missing grammar */
	grammar = iks_find(input, "grammar");
	if (!grammar) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Missing <input><grammar>\n");
		app_send_iq_error(session, iq, STANZA_ERROR_BAD_REQUEST);
		goto done;
	}

	/* only support srgs */
	content_type = iks_find_attrib(grammar, "content-type");
	if (!zstr(content_type) && strcmp("application/srgs+xml", content_type)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Unsupported content type\n");
		app_send_iq_error(session, iq, STANZA_ERROR_BAD_REQUEST);
		goto done;
	}

	/* missing grammar body */
	srgs = iks_find_cdata(input, "grammar");
	if (zstr(srgs)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Grammar body is missing\n");
		app_send_iq_error(session, iq, STANZA_ERROR_BAD_REQUEST);
		goto done;
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
	handler->last_digit_time = switch_micro_time_now();
	handler->got_first_digit = 0;
	handler->lazy_match = 0;
	handler->term_digit_mask = get_digit_mask_from_string(i_attribs.terminator.v.s);
	handler->initial_timeout = i_attribs.initial_timeout.v.i;
	handler->inter_digit_timeout = i_attribs.inter_digit_timeout.v.i;
	handler->max_silence = i_attribs.max_silence.v.i;

	/* parse the grammar */
	if (!srgs_parse(handler->parser, srgs)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Failed to parse grammar body\n");
		app_send_iq_error(session, iq, STANZA_ERROR_BAD_REQUEST);
		goto done;
	}

	/* create JID */
	ref = create_component_ref(session, call, "input");
	call->input_jid = create_call_component_jid(session, call, ref);
	
	/* install input callbacks */
	switch_core_event_hook_add_recv_dtmf(session, input_component_on_dtmf);
	switch_core_event_hook_add_read_frame(session, input_component_on_read_frame);

	/* all good, acknowledge command */
	send_component_ref(session, iq, ref);

done:

	switch_mutex_unlock(call->mutex);
}

/**
 * <output> component validation
 */
static const struct iks_attrib_definition output_attribs_def[] = {
	ATTRIB(start-offset, 0, not_negative),
	ATTRIB(start-paused, false, bool),
	ATTRIB(repeat-interval, 0, not_negative),
	ATTRIB(repeat-times, 1, positive),
	ATTRIB(max-time, -1, positive_or_neg_one),
	ATTRIB(renderer,, any),
	LAST_ATTRIB
};

/**
 * <output> component attributes
 */
struct output_attribs {
	int size;
	struct iks_attrib start_offset;
	struct iks_attrib start_paused;
	struct iks_attrib repeat_interval;
	struct iks_attrib repeat_times;
	struct iks_attrib max_time;
	struct iks_attrib renderer;
};

/* adhearsion uses incorrect reason for finish... this is a temporary fix */
#define OUTPUT_FINISH_AHN "success", "urn:xmpp:rayo:output:complete:1"
#define OUTPUT_FINISH "finish", "urn:xmpp:rayo:output:complete:1"
#define OUTPUT_MAX_TIME "max-time", "urn:xmpp:rayo:output:complete:1"

/**
 * <output> a <speak> document
 * @param session the session to play to
 * @param document the document to play
 * @param timeout the time to stop playing.  0 if unbounded.
 * @return status
 */
switch_status_t output_speak_document(switch_core_session_t *session, iks *document, switch_time_t timeout)
{
	switch_status_t status = SWITCH_STATUS_FALSE;
	char *name;
	int max_time_ms = -1;

	if (!document) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "No document to play!\n");
		return SWITCH_STATUS_FALSE;
	}

	/* calculate relative timeout */
	if (timeout) {
		switch_time_t now = switch_micro_time_now();
		if (now >= timeout) {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Reached <speak> timeout!\n");
			return SWITCH_STATUS_FALSE;
		}
		max_time_ms = (int)((timeout - now) / 1000);

		/* Add extra frame or two of time to ensure play returns after timeout so we can detect it. */
		max_time_ms += 40; 
	}

	name = iks_name(document);
	if (!strcmp("speak", name)) {
		char *ssml = iks_string(NULL, document);
		char *filename = NULL;

		/* append timeout param and SSML file format and the SSML document */
		filename = switch_mprintf("{timeout=%i}ssml://%s", max_time_ms, ssml);

		/* play the file */
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Playing %s\n", filename);
		status = switch_ivr_play_file(session, NULL, filename, NULL);

		iks_free(ssml);
		switch_safe_free(filename);
	} else {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Expected <speak>, got: <%s>!\n", name);
	}
	return status;
}

/**
 * <output> a <speak> document
 * @param session the session to play to
 * @param silence_ms the duration of silence to play
 * @param timeout the time to stop playing.  0 if unbounded.
 * @return status
 */
switch_status_t output_silence(switch_core_session_t *session, int silence_ms, switch_time_t timeout)
{
	switch_status_t status;
	char *filename = NULL;
	int max_time_ms = -1;

	/* calculate relative timeout */
	if (timeout) {
		switch_time_t now = switch_micro_time_now();
		if (now >= timeout) {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Reached <silence> timeout!\n");
			return SWITCH_STATUS_FALSE;
		}
		max_time_ms = (int)((timeout - now) / 1000);

		/* Add extra frame or two of time to ensure play returns after timeout so we can detect it. */
		max_time_ms += 40; 
	}

	/* append timeout param and SSML file format and the SSML document */
	filename = switch_mprintf("{timeout=%i}silence_stream://%i", max_time_ms, silence_ms);

	/* play the file */
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Playing %s\n", filename);
	status = switch_ivr_play_file(session, NULL, filename, NULL);

	switch_safe_free(filename);
	
	return status;
}

/**
 * <output> <document>s
 * @param session the session to play to
 * @param document the document(s) to play
 * @param timeout the time to stop playing.  0 if unbounded.
 * @return status
 */
switch_status_t output_documents(switch_core_session_t *session, iks *document, switch_time_t timeout)
{
	/* play each <document> */
	for (; document; document = iks_next_tag(document)) {
		if (!strcmp("document", iks_name(document))) {
			/* play the <speak> document */
			switch_status_t status;
			if ((status = output_speak_document(session, iks_child(document), timeout)) != SWITCH_STATUS_SUCCESS) {
				return status;
			}
		} else {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Expected <document>, got: <%s>!\n", iks_name(document));
		}
	}
	return SWITCH_STATUS_SUCCESS;
}

/**
 * Start execution of output component
 */
void start_output_component(switch_core_session_t *session, struct rayo_call *call, iks *iq)
{
	struct output_attribs o_attribs;
	char *ref = NULL;
	iks *output = iks_find(iq, "output");
	iks *document = NULL;
	switch_time_t timeout = 0;
	int using_document = 1;
	int i;
	int repeat_times;
	int repeat_interval;

	switch_mutex_lock(call->mutex);

	/* already have output component? */
	if (!zstr(call->output_jid)) {
		app_send_iq_error(session, iq, STANZA_ERROR_CONFLICT);
		switch_mutex_unlock(call->mutex);
		return;
	}

	/* validate output attributes */
	memset(&o_attribs, 0, sizeof(o_attribs));
	if (!iks_attrib_parse(session, output, output_attribs_def, (struct iks_attribs *)&o_attribs)) {
		app_send_iq_error(session, iq, STANZA_ERROR_BAD_REQUEST);
		switch_mutex_unlock(call->mutex);
		return;
	}
	repeat_times = o_attribs.repeat_times.v.i;
	repeat_interval = o_attribs.repeat_interval.v.i;

	/* TODO open SSML files here.. then play the open handles below- if bad XML, we'll detect it */

	/* find document to speak */
	document = iks_find(output, "document");
	if (!document) {
		/* adhearsion non-standard <output> request */
		document = iks_find(output, "speak");
		using_document = 0;
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Have <speak> instead of <document>\n");
	}

	/* nothing to speak? */
	if (!document) {
		app_send_iq_error(session, iq, STANZA_ERROR_BAD_REQUEST);
		switch_mutex_unlock(call->mutex);
		return;
	}

	/* acknowledge command */
	ref = create_component_ref(session, call, "output");
	call->output_jid = create_call_component_jid(session, call, ref);
	send_component_ref(session, iq, ref);

	switch_mutex_unlock(call->mutex);

	/* is a timeout requested? */
	if (o_attribs.max_time.v.i > 0) {
		timeout = switch_micro_time_now() + (o_attribs.max_time.v.i * 1000);
	}

	/* render document(s) */
	for (i = 0; i < repeat_times; i++) {

		/* play silence between documents */
		if (i > 0 && repeat_interval > 0) {
			if (output_silence(session, repeat_interval, timeout) != SWITCH_STATUS_SUCCESS) {
				break;
			}
		}

		/* play document */
		if (using_document) {
			if (output_documents(session, document, timeout) != SWITCH_STATUS_SUCCESS) {
				break;
			}
		} else {
			if (output_speak_document(session, document, timeout) != SWITCH_STATUS_SUCCESS) {
				break;
			}
		}
	}

	/* done */
	switch_mutex_lock(call->mutex);
	if (timeout && switch_micro_time_now() >= timeout) {
		send_component_complete(session, call->output_jid, OUTPUT_MAX_TIME);
	} else {
		send_component_complete(session, call->output_jid, OUTPUT_FINISH_AHN);
	}
	call->output_jid = "";
	switch_mutex_unlock(call->mutex);
}

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
void start_prompt_component(switch_core_session_t *session, struct rayo_call *call, iks *iq)
{
	struct prompt_attribs p_attribs;
	iks *prompt = iks_child(iq);

	switch_mutex_lock(call->mutex);
	
	if (!zstr(call->output_jid) || !zstr(call->input_jid)) {
		/* already have output component */
		app_send_iq_error(session, iq, STANZA_ERROR_CONFLICT);
		switch_mutex_unlock(call->mutex);
		return;
	}

	/* validate prompt attributes */
	memset(&p_attribs, 0, sizeof(p_attribs));
	if (!iks_attrib_parse(session, prompt, prompt_attribs_def, (struct iks_attribs *)&p_attribs)) {
		app_send_iq_error(session, iq, STANZA_ERROR_BAD_REQUEST);
		switch_mutex_unlock(call->mutex);
		return;
	}
	switch_mutex_unlock(call->mutex);
	
	/* TODO implement */
	
	app_send_iq_error(session, iq, STANZA_ERROR_FEATURE_NOT_IMPLEMENTED);
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