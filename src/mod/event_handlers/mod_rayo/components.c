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
static char *create_component_ref(struct rayo_call *call, const char *type)
{
	return switch_core_session_sprintf(call->session, "%s-%d", type, call->next_ref++);
}

/**
 * @param call
 * @param component_ref
 * @return JID for component
 */
static char *create_call_component_jid(struct rayo_call *call, char *component_ref)
{
	return switch_core_session_sprintf(call->session, "%s/%s", call->jid, component_ref);
}

/**
 * Send IQ error to controlling client from call
 * @param call the call
 * @param iq the request that caused the error
 * @param error the error message
 */
void call_send_iq_error(struct rayo_call *call, iks *iq, const char *error_name, const char *error_type)
{
	switch_channel_t *channel = switch_core_session_get_channel(call->session);
	iks *response = iks_new_iq_error(iq,
		switch_channel_get_variable(channel, "rayo_call_jid"),
		switch_channel_get_variable(channel, "rayo_dcp_jid"),
		error_name, error_type);
	call_iks_send(call, response);
	iks_delete(response);
}

/**
 * Send component ref to controlling client from call
 * @param call the call
 * @param iq the request that requested the component
 * @param ref the component ref
 */
static void send_component_ref(struct rayo_call *call, iks *iq, const char *ref)
{
	switch_channel_t *channel = switch_core_session_get_channel(call->session);
	iks *x, *response = NULL;

	response = iks_new_iq_result(
		switch_channel_get_variable(channel, "rayo_call_jid"),
		switch_channel_get_variable(channel, "rayo_dcp_jid"),
		iks_find_attrib(iq, "id"));
	x = iks_insert(response, "ref");
	iks_insert_attrib(x, "xmlns", "urn:xmpp:rayo:1");
	iks_insert_attrib(x, "id", ref);

	call_iks_send(call, response);
	iks_delete(response);
}

/**
 * Send component complete presence to client
 * @param call the call
 * @param jid the component JID
 * @param reason the completion reason
 * @param reason_namespace the completion reason namespace
 * @param reason_detail optional detail
 */
static void send_component_complete(struct rayo_call *call, const char *jid, const char *reason, const char *reason_namespace)
{
	switch_channel_t *channel = switch_core_session_get_channel(call->session);
	iks *response = iks_new("presence");
	iks *x;
	iks_insert_attrib(response, "from", jid);
	iks_insert_attrib(response, "to", switch_channel_get_variable(channel, "rayo_dcp_jid"));
	iks_insert_attrib(response, "type", "unavailable");
	x = iks_insert(response, "complete");
	iks_insert_attrib(x, "xmlns", "urn:xmpp:rayo:ext:1");
	x = iks_insert(x, reason);
	iks_insert_attrib(x, "xmlns", reason_namespace);
	call_iks_send(call, response);
	iks_delete(response);
}

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
	iks_insert_attrib(x, "xmlns", "urn:xmpp:rayo:ext:1");
	x = iks_insert(x, "success"); /* TODO rayo spec says this should be "match" */
	iks_insert_attrib(x, "xmlns", "urn:xmpp:rayo:input:complete:1");
	iks_insert_attrib(x, "mode", "dtmf");
	iks_insert_attrib(x, "confidence", "1.0");
	x = iks_insert(x, "utterance");
	iks_insert_cdata(x, digits, strlen(digits));
	call_iks_send(call, response);
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
};

static switch_status_t input_component_on_dtmf(switch_core_session_t *session, const switch_dtmf_t *dtmf, switch_dtmf_direction_t direction);

/**
 * Monitor DTMF timeouts
 */
static switch_status_t input_component_on_read_frame(switch_core_session_t *session, switch_frame_t **frame, switch_io_flag_t flags, int i)
{
	switch_channel_t *channel = switch_core_session_get_channel(session);
	struct input_handler *handler = (struct input_handler *)switch_channel_get_private(channel, RAYO_INPUT_COMPONENT_PRIVATE_VAR);
	if (handler) {
		enum match_type match = srgs_match(handler->parser, NULL);
		switch (match) {
			case MT_NO_MATCH: {
				/* need more digits */
				break;
			}
			case MT_TIMEOUT: {
				switch_mutex_lock(handler->call->mutex);
				if (handler->num_digits == 0) {
					switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "initial-timeout\n");
					send_component_complete(handler->call, handler->call->input_jid, INPUT_NOINPUT);
				} else {
					switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "inter-digit-timeout\n");
					send_component_complete(handler->call, handler->call->input_jid, INPUT_NOMATCH);
				}
				switch_core_event_hook_remove_recv_dtmf(session, input_component_on_dtmf);
				switch_core_event_hook_remove_read_frame(session, input_component_on_read_frame);
				handler->call->input_jid = "";
				switch_mutex_unlock(handler->call->mutex);
				break;
			}
			case MT_MATCH: {
				switch_mutex_lock(handler->call->mutex);
				send_input_component_dtmf_match(handler->call, handler->call->input_jid, handler->digits);
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
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Collected digits = \"%s\"\n", handler->digits);

		match = srgs_match(handler->parser, handler->digits + handler->num_digits - 1);

		switch (match) {
			case MT_NO_MATCH: {
				/* need more digits */
				break;
			}
			case MT_TIMEOUT: {
				/* notify of no-match and remove input handler */
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "NO MATCH = %s\n", handler->digits);
				switch_mutex_lock(handler->call->mutex);
				send_component_complete(handler->call, handler->call->input_jid, INPUT_NOMATCH);

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
				send_input_component_dtmf_match(handler->call, handler->call->input_jid, handler->digits);

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
void start_call_input_component(switch_core_session_t *session, struct rayo_call *call, iks *iq)
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
		call_send_iq_error(call, iq, STANZA_ERROR_CONFLICT);
		goto done;
	}

	/* validate input attributes */
	memset(&i_attribs, 0, sizeof(i_attribs));
	if (!iks_attrib_parse(session, input, input_attribs_def, (struct iks_attribs *)&i_attribs)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Bad input attrib\n");
		call_send_iq_error(call, iq, STANZA_ERROR_BAD_REQUEST);
		goto done;
	}

	/* missing grammar */
	grammar = iks_find(input, "grammar");
	if (!grammar) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Missing <input><grammar>\n");
		call_send_iq_error(call, iq, STANZA_ERROR_BAD_REQUEST);
		goto done;
	}

	/* only support srgs */
	content_type = iks_find_attrib(grammar, "content-type");
	if (!zstr(content_type) && strcmp("application/srgs+xml", content_type)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Unsupported content type\n");
		call_send_iq_error(call, iq, STANZA_ERROR_BAD_REQUEST);
		goto done;
	}

	/* missing grammar body */
	srgs = iks_find_cdata(input, "grammar");
	if (zstr(srgs)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Grammar body is missing\n");
		call_send_iq_error(call, iq, STANZA_ERROR_BAD_REQUEST);
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

	/* parse the grammar */
	if (!srgs_parse(handler->parser, srgs, i_attribs.initial_timeout.v.i, i_attribs.inter_digit_timeout.v.i)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Failed to parse grammar body\n");
		call_send_iq_error(call, iq, STANZA_ERROR_BAD_REQUEST);
		goto done;
	}

	/* create JID */
	ref = create_component_ref(call, "input");
	call->input_jid = create_call_component_jid(call, ref);

	/* install input callbacks */
	switch_core_event_hook_add_recv_dtmf(session, input_component_on_dtmf);
	switch_core_event_hook_add_read_frame(session, input_component_on_read_frame);

	/* all good, acknowledge command */
	send_component_ref(call, iq, ref);

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
void start_call_output_component(switch_core_session_t *session, struct rayo_call *call, iks *iq)
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
		call_send_iq_error(call, iq, STANZA_ERROR_CONFLICT);
		switch_mutex_unlock(call->mutex);
		return;
	}

	/* validate output attributes */
	memset(&o_attribs, 0, sizeof(o_attribs));
	if (!iks_attrib_parse(session, output, output_attribs_def, (struct iks_attribs *)&o_attribs)) {
		call_send_iq_error(call, iq, STANZA_ERROR_BAD_REQUEST);
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
		call_send_iq_error(call, iq, STANZA_ERROR_BAD_REQUEST);
		switch_mutex_unlock(call->mutex);
		return;
	}

	/* acknowledge command */
	ref = create_component_ref(call, "output");
	call->output_jid = create_call_component_jid(call, ref);
	send_component_ref(call, iq, ref);

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
		send_component_complete(call, call->output_jid, OUTPUT_MAX_TIME);
	} else {
		send_component_complete(call, call->output_jid, OUTPUT_FINISH_AHN);
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
void start_call_prompt_component(switch_core_session_t *session, struct rayo_call *call, iks *iq)
{
	struct prompt_attribs p_attribs;
	iks *prompt = iks_child(iq);

	switch_mutex_lock(call->mutex);

	if (!zstr(call->output_jid) || !zstr(call->input_jid)) {
		/* already have output component */
		call_send_iq_error(call, iq, STANZA_ERROR_CONFLICT);
		switch_mutex_unlock(call->mutex);
		return;
	}

	/* validate prompt attributes */
	memset(&p_attribs, 0, sizeof(p_attribs));
	if (!iks_attrib_parse(session, prompt, prompt_attribs_def, (struct iks_attribs *)&p_attribs)) {
		call_send_iq_error(call, iq, STANZA_ERROR_BAD_REQUEST);
		switch_mutex_unlock(call->mutex);
		return;
	}
	switch_mutex_unlock(call->mutex);

	/* TODO implement */

	call_send_iq_error(call, iq, STANZA_ERROR_FEATURE_NOT_IMPLEMENTED);
}

/* 1000 Hz beep for 250ms */
#define RECORD_BEEP "tone_stream://%(250,0,1000)"

enum record_direction {
	RD_DUPLEX,
	RD_SEND,
	RD_RECV
};

/**
 * Validate <record direction="">
 */
static ATTRIB_RULE(record_direction)
{
	attrib->type = IAT_INTEGER;
	attrib->test = "(duplex || send || recv)";
	if (!strcmp("duplex", value)) {
		attrib->v.i = RD_DUPLEX;
	} else if (!strcmp("send", value)) {
		attrib->v.i = RD_SEND;
	} else if (!strcmp("recv", value)) {
		attrib->v.i = RD_RECV;
	} else {
		return 0;
	}
	return 1;
}

/**
 * <record> component validation
 */
static const struct iks_attrib_definition record_attribs_def[] = {
	ATTRIB(format, mp3, any),
	ATTRIB(start-beep, false, bool),
	ATTRIB(stop-beep, false, bool),
	ATTRIB(start-paused, false, bool),
	ATTRIB(max-duration, -1, positive_or_neg_one),
	ATTRIB(initial-timeout, -1, positive_or_neg_one),
	ATTRIB(final-timeout, -1, positive_or_neg_one),
	ATTRIB(direction, duplex, record_direction),
	ATTRIB(mix, false, bool),
	LAST_ATTRIB
};

/**
 * <record> component attributes
 */
struct record_attribs {
	int size;
	struct iks_attrib format;
	struct iks_attrib start_beep;
	struct iks_attrib stop_beep;
	struct iks_attrib start_paused;
	struct iks_attrib max_duration;
	struct iks_attrib initial_timeout;
	struct iks_attrib final_timeout;
	struct iks_attrib direction;
	struct iks_attrib mix;
};

/**
 * Handle RECORD_STOP event from FreeSWITCH.
 * @param event received from FreeSWITCH core.  It will be destroyed by the core after this function returns.
 */
static void on_record_stop_event(switch_event_t *event)
{
	/* locate call and lock it since event is handled outside of channel thread */
	struct rayo_call *call = rayo_call_locate(switch_event_get_header(event, "Unique-ID"));
	if (call) {
		switch_core_session_t *session = call->session;
		switch_channel_t *channel = switch_core_session_get_channel(session);
		iks *x = NULL, *presence = NULL;
		const char *file = switch_event_get_header(event, "Record-File-Path");
		char *uri = switch_core_session_sprintf(session, "file://%s", file);

		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Recording %s done.\n", file);

		/* send complete event to client */
		presence = iks_new("presence");
		iks_insert_attrib(presence, "from", switch_channel_get_variable(channel, file)); // file is mapped to JID here
		iks_insert_attrib(presence, "to", call->dcp_jid);
		iks_insert_attrib(presence, "type", "unavailable");
		x = iks_insert(presence, "complete");
		iks_insert_attrib(x, "xmlns", "urn:xmpp:rayo:ext:1");
		x = iks_insert(x, "success");
		iks_insert_attrib(x, "xmlns", "urn:xmpp:rayo:ext:complete:1");
		x = iks_insert(x, "recording");
		iks_insert_attrib(x, "xmlns", "urn:xmpp:rayo:record:complete:1");
		iks_insert_attrib(x, "uri", uri);
		iks_insert_attrib(x, "duration", "30"); // TODO
		iks_insert_attrib(x, "size", "30"); // TODO
		call_iks_send(call, presence);
		iks_delete(presence);
		
		rayo_call_unlock(call);
	}
}

/**
 * Start execution of record component
 */
void start_call_record_component(switch_core_session_t *session, struct rayo_call *call, iks *iq)
{
	struct record_attribs r_attribs;
	iks *record = iks_child(iq);
	switch_channel_t *channel = switch_core_session_get_channel(session);
	char *ref = NULL;
	char *jid = NULL;
	char *file = NULL;
	int max_duration_sec = 0;

	/* validate record attributes */
	memset(&r_attribs, 0, sizeof(r_attribs));
	if (!iks_attrib_parse(session, record, record_attribs_def, (struct iks_attribs *)&r_attribs)) {
		call_send_iq_error(call, iq, STANZA_ERROR_BAD_REQUEST);
		return;
	}

	ref = create_component_ref(call, "record");
	jid = create_call_component_jid(call, ref);

	/* create record filename from session UUID and ref */
	/* for example: 1234-1234-1234-1234/record-30.wav */
	file = switch_core_session_sprintf(session, "%s%srecordings%s%s.%s", SWITCH_GLOBAL_dirs.base_dir, SWITCH_PATH_SEPARATOR, SWITCH_PATH_SEPARATOR, 
									   switch_core_session_get_uuid(session), r_attribs.format.v.s);

	switch_channel_set_variable(channel, "RECORD_HANGUP_ON_ERROR", "false");
	switch_channel_set_variable(channel, "RECORD_TOGGLE_ON_REPEAT", "");
	switch_channel_set_variable(channel, "RECORD_CHECK_BRIDGE", "");
	switch_channel_set_variable(channel, "RECORD_MIN_SEC", "0");
	switch_channel_set_variable(channel, "RECORD_STEREO", "");
	switch_channel_set_variable(channel, "RECORD_READ_ONLY", "");
	switch_channel_set_variable(channel, "RECORD_WRITE_ONLY", "");
	switch_channel_set_variable(channel, "RECORD_APPEND", "");
	switch_channel_set_variable(channel, "RECORD_ANSWER_REQ", "");

	/* map recording file to JID so we can find it on RECORD_STOP event */
	switch_channel_set_variable(channel, file, jid);

	/* allow dialplan override for these variables */
	//switch_channel_set_variable(channel, "RECORD_PRE_BUFFER_FRAMES", "");
	//switch_channel_set_variable(channel, "record_sample_rate", "");
	//switch_channel_set_variable(channel, "enable_file_write_buffering", "");

	/* max duration attribute is in milliseconds- convert to seconds */
	if (r_attribs.max_duration.v.i > 0) {
		max_duration_sec = ceil((double)r_attribs.max_duration.v.i / 1000.0);
	}

	switch (r_attribs.direction.v.i) {
		case RD_DUPLEX:
			if (r_attribs.mix.v.i) {
				/* STEREO */
				switch_channel_set_variable(channel, "RECORD_STEREO", "true");
			} /* else MONO (default) */
			break;
		case RD_SEND:
			/* record audio sent from the caller */
			switch_channel_set_variable(channel, "RECORD_READ_ONLY", "true");
			break;
		case RD_RECV:
			/* record audio received by the caller */
			switch_channel_set_variable(channel, "RECORD_WRITE_ONLY", "true");
			break;
	};

	/* TODO need hangup hook for cleanup */
	
	if (r_attribs.start_beep.v.i) {
		if (!switch_ivr_play_file(session, NULL, RECORD_BEEP, NULL) != SWITCH_STATUS_SUCCESS) {
			call_send_iq_error(call, iq, STANZA_ERROR_INTERNAL_SERVER_ERROR);
		}
	}

	if (switch_ivr_record_session(session, file, max_duration_sec, NULL) == SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Recording started: file = %s\n", file);
		send_component_ref(call, iq, ref);
	} else {
		call_send_iq_error(call, iq, STANZA_ERROR_INTERNAL_SERVER_ERROR);
	}
}

#define RAYO_COMPONENT_USAGE ""
/**
 * Process call components (output, input, prompt, record)
 */
SWITCH_STANDARD_APP(rayo_call_component_app)
{
	iksparser *parser = NULL;
	iks *iq;
	char *command;
	struct rayo_call *call = get_rayo_call(session);

	switch_mutex_lock(call->mutex);
	if (!call && zstr(call->dcp_jid)) {
		switch_mutex_unlock(call->mutex);
		/* shouldn't happen if APP was executed by this module */
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "No Rayo client controlling this session!\n");
		goto done;
	}
	switch_mutex_unlock(call->mutex);

	if (zstr(data)) {
		/* shouldn't happen if APP was executed by this module */
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Missing args!\n");
		/* can't send iq error- no <iq> request! */
		goto done;
	}

	parser = iks_dom_new(&iq);
	if (!parser) {
		goto done;
	}
	if (iks_parse(parser, data, 0, 1) != IKS_OK) {
		/* shouldn't happen if APP was executed by this module */
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Bad request!\n");
		/* can't send iq error- no <iq> request! */
		goto done;
	}

	if (!iks_has_children(iq)) {
		/* shouldn't happen if APP was executed by this module */
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Bad request!\n");
		call_send_iq_error(call, iq, STANZA_ERROR_BAD_REQUEST);
		goto done;
	} 
	
	command = iks_name(iks_child(iq));
	if (!strcmp("prompt", command)) {
		start_call_prompt_component(session, call, iq);
	} else if (!strcmp("input", command)) {
		start_call_input_component(session, call, iq);
	} else if (!strcmp("output", command)) {
		start_call_output_component(session, call, iq);
	} else if (!strcmp("record", command)) {
		start_call_record_component(session, call, iq);
	} else {
		call_send_iq_error(call, iq, STANZA_ERROR_FEATURE_NOT_IMPLEMENTED);
	}

done:
	if (iq) {
		iks_delete(iq);
	}
	if (parser) {
		iks_parser_delete(parser);
	}
}

/**
 * Handle Rayo call Component request
 * @param server_jid the server JID
 * @param call the Rayo call
 * @param node the <iq> node
 * @return the response
 */
static iks *on_rayo_call_component(const char *server_jid, struct rayo_call *call, iks *node)
{
	iks *response = NULL;
	char *play = iks_string(NULL, node);
	/* forward document to call thread by executing custom application */
	if (!play || switch_core_session_execute_application_async(call->session, "rayo_call_component", play) != SWITCH_STATUS_SUCCESS) {
		response = iks_new_iq_error(node, call->jid, call->dcp_jid, STANZA_ERROR_INTERNAL_SERVER_ERROR);
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(call->session), SWITCH_LOG_INFO, "Failed to execute rayo_call_component!\n");
	}
	if (play) {
		iks_free(play);
	}
	return response;
}

/**
 * Handle <iq><stop> request
 * @param server_jid the server JID
 * @param call the Rayo call
 * @param node the <iq> node
 * @return the response
 */
static iks *on_rayo_stop(const char *server_jid, struct rayo_call *call, iks *node)
{
	char *component_jid = iks_find_attrib(node, "to");
	iks *response = NULL;
	if (!strcmp(call->jid, component_jid) || !strcmp(server_jid, component_jid)) {
		/* call/server instead of component */
		response = iks_new_iq_error(node, component_jid, call->dcp_jid, STANZA_ERROR_FEATURE_NOT_IMPLEMENTED);
	} else if (zstr(call->output_jid) || strcmp(call->output_jid, component_jid)) {
		/* component doesn't exist */
		response = iks_new_iq_error(node, component_jid, call->dcp_jid, STANZA_ERROR_ITEM_NOT_FOUND);
	} else if (switch_core_session_execute_application_async(call->session, "break", "") != SWITCH_STATUS_SUCCESS) {
		/* failed to send break */
		response = iks_new_iq_error(node, component_jid, call->dcp_jid, STANZA_ERROR_INTERNAL_SERVER_ERROR);
	} else {
		/* success */
		response = iks_new_iq_result(component_jid, call->dcp_jid, iks_find_attrib(node, "id"));
	}
	return response;
}

/**
 * Handle configuration
 */
switch_status_t load_components(switch_loadable_module_interface_t **module_interface)
{
	switch_application_interface_t *app_interface;
	
	add_rayo_command_handler("urn:xmpp:rayo:ext:1:stop", on_rayo_stop);
	add_rayo_command_handler("urn:xmpp:rayo:output:1:output", on_rayo_call_component);
	add_rayo_command_handler("urn:xmpp:rayo:input:1:input", on_rayo_call_component);
	add_rayo_command_handler("urn:xmpp:rayo:prompt:1:prompt", on_rayo_call_component);
	add_rayo_command_handler("urn:xmpp:rayo:record:1:record", on_rayo_call_component);
	
	switch_event_bind("mod_rayo_components", SWITCH_EVENT_RECORD_STOP, NULL, on_record_stop_event, NULL);
	
	SWITCH_ADD_APP(app_interface, "rayo_call_component", "Execute Rayo call component (internal module use only)", "", rayo_call_component_app, RAYO_COMPONENT_USAGE, 0);

	return SWITCH_STATUS_SUCCESS;
}

/**
 * Handle shutdown
 */
switch_status_t shutdown_components(void)
{
	switch_event_unbind_callback(on_record_stop_event);
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