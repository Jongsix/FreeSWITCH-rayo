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
 * Create a UUID
 */
static char *create_uuid_str(switch_core_session_t *session)
{
	char ref[SWITCH_UUID_FORMATTED_LENGTH + 1];
	ref[SWITCH_UUID_FORMATTED_LENGTH] = '\0';
	switch_uuid_str(ref, sizeof(ref));
	return switch_core_session_strdup(session, ref);
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
	char *response = NULL;
	
	response = switch_mprintf(
		"<presence from='%s' to='%s' type='unavailable'>"
		"<complete xmlns='urn:xmpp:rayo:ext:1'><match xmlns='urn:xmpp:rayo:input:complete:1'>"
		"<result xmlns='http://www.w3c.org/2000/11/nlsml' xmlns:xf='http://www.w3.org/2000/xforms'>"
		"<input><input mode='dtmf' confidence='100'>%s</input></input></match></complete></presence>",
		jid,
		switch_channel_get_variable(channel, "rayo_dcp_jid"),
		digits);

	if (switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, RAYO_EVENT_XMPP_SEND) == SWITCH_STATUS_SUCCESS) {
		switch_channel_event_set_data(channel, event);
		switch_event_add_body(event, "%s", response);
		switch_event_fire(&event);
	}
	switch_safe_free(response);
}

/**
 * Assign value to attribute if valid input mode (
 * @param attrib to assign to
 * @param value assigned
 * @return SWTICH_TRUE if value is valid
 */
static int is_input_mode(struct iks_attrib *attrib, const char *value) {
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
	{ "mode", "any", is_input_mode, SWITCH_FALSE },
	{ "terminator", "", iks_attrib_is_any, SWITCH_FALSE },
	{ "recognizer", "en-US", iks_attrib_is_any /* should be ISO 639-3 codes */, SWITCH_FALSE },
	{ "initial-timeout", "-1", iks_attrib_is_positive_or_neg_one, SWITCH_FALSE },
	{ "inter-digit-timeout", "-1", iks_attrib_is_positive_or_neg_one, SWITCH_FALSE },
	{ "sensitivity", "0.5", iks_attrib_is_decimal_between_zero_and_one, SWITCH_FALSE },
	{ "min-confidence", "0", iks_attrib_is_decimal_between_zero_and_one, SWITCH_FALSE },
	{ "max-silence", "-1", iks_attrib_is_positive_or_neg_one, SWITCH_FALSE },
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

#define INPUT_INITIAL_TIMEOUT "initial-timeout", "urn:xmpp:rayo:input:complete:1"
#define INPUT_INTER_DIGIT_TIMEOUT "inter-digit-timeout", "urn:xmpp:rayo:input:complete:1"
#define INPUT_MAX_SILENCE "max-silence", "urn:xmpp:rayo:input:complete:1"
#define INPUT_MIN_CONFIDENCE "min-confidence", "urn:xmpp:rayo:input:complete:1"
#define INPUT_NOMATCH "nomatch", "urn:xmpp:rayo:input:complete:1"

#define RAYO_INPUT_COMPONENT_PRIVATE_VAR "__rayo_input_component"

/**
 * Current digit collection state
 */
struct input_handler {
	int num_digits;
	char digits[MAX_DTMF * 2 + 1];
	struct srgs_parser *parser;
	struct rayo_call *call;
};

/**
 * Process hangup
 */
static switch_status_t input_component_on_hangup(switch_core_session_t *session)
{
	switch_channel_t *channel = switch_core_session_get_channel(session);
	struct input_handler *handler = (struct input_handler *)switch_channel_get_private(channel, RAYO_INPUT_COMPONENT_PRIVATE_VAR);
	if (handler) {
		switch_channel_set_private(channel, RAYO_INPUT_COMPONENT_PRIVATE_VAR, NULL);
		if (handler->parser) {
			srgs_destroy(handler->parser);
			handler->parser = NULL;
		}
	}
	return SWITCH_STATUS_SUCCESS;
}

/**
 * Process DTMF press
 */
static switch_status_t input_component_on_dtmf(switch_core_session_t *session, const switch_dtmf_t *dtmf, switch_dtmf_direction_t direction)
{
	/* TODO digit timeouts */
	switch_channel_t *channel = switch_core_session_get_channel(session);
	struct input_handler *handler = (struct input_handler *)switch_channel_get_private(channel, RAYO_INPUT_COMPONENT_PRIVATE_VAR);
	if (handler) {
		enum match_type match;
		handler->digits[handler->num_digits * 2] = dtmf->digit;
		handler->digits[handler->num_digits * 2 + 1] = ' ';
		handler->num_digits++;
		handler->digits[handler->num_digits * 2] = '\0';
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Collected digits = \"%s\"\n", handler->digits);

		/* check for match */
		match = srgs_match(handler->parser, handler->digits);
		switch (match) {
			case MT_NOT_ENOUGH_INPUT: {
				/* don't care */
				break;
			}
			case MT_NO_MATCH: {
				/* notify of no-match and remove input handler */
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "NO MATCH = %s\n", handler->digits);
				switch_mutex_lock(handler->call->mutex);
				send_component_complete(session, handler->call->input_jid, INPUT_NOMATCH);

				switch_core_event_hook_remove_recv_dtmf(session, input_component_on_dtmf);
				srgs_destroy(handler->parser);
				handler->parser = NULL;
				handler->call->input_jid = "";
				switch_mutex_unlock(handler->call->mutex);
				break;
			}	
			case MT_MATCH: {
				/* notify of match and remove input handler */
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "GOT MATCH = %s\n", handler->digits);
				switch_mutex_lock(handler->call->mutex);
				send_input_component_dtmf_match(session, handler->call->input_jid, handler->digits);

				switch_core_event_hook_remove_recv_dtmf(session, input_component_on_dtmf);
				srgs_destroy(handler->parser);
				handler->parser = NULL;
				handler->call->input_jid = "";
				switch_mutex_unlock(handler->call->mutex);
				break;
			}
		}
	}
    return SWITCH_STATUS_SUCCESS;
}

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
	struct srgs_parser *parser = NULL;
	struct input_handler *handler = NULL;

	switch_mutex_lock(call->mutex);

	/* already have input component? */
	if (!zstr(call->input_jid)) {
		app_send_iq_error(session, iq, STANZA_ERROR_CONFLICT);
		switch_mutex_unlock(call->mutex);
		return;
	}

	/* validate input attributes */
	memset(&i_attribs, 0, sizeof(i_attribs));
	if (!iks_attrib_parse(session, input, input_attribs_def, (struct iks_attribs *)&i_attribs)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Bad input attrib\n");
		app_send_iq_error(session, iq, STANZA_ERROR_BAD_REQUEST);
		switch_mutex_unlock(call->mutex);
		return;
	}

	/* missing grammar */
	grammar = iks_find(input, "grammar");
	if (!grammar) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Missing <input><grammar>\n");
		app_send_iq_error(session, iq, STANZA_ERROR_BAD_REQUEST);
		switch_mutex_unlock(call->mutex);
		return;
	}

	/* only support srgs */
	content_type = iks_find_attrib(grammar, "content-type");
	if (!zstr(content_type) && strcmp("application/srgs+xml", content_type)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Unsupported content type\n");
		app_send_iq_error(session, iq, STANZA_ERROR_BAD_REQUEST);
		switch_mutex_unlock(call->mutex);
		return;
	}

	/* missing grammar body */
	srgs = iks_find_cdata(input, "grammar");
	if (zstr(srgs)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Grammar body is missing\n");
		app_send_iq_error(session, iq, STANZA_ERROR_BAD_REQUEST);
		switch_mutex_unlock(call->mutex);
		return;
	}

	/* parse the grammar */
	parser = srgs_parser_new();
	if (!srgs_parse(parser, srgs)) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Failed to parse grammar body\n");
		app_send_iq_error(session, iq, STANZA_ERROR_BAD_REQUEST);
		switch_mutex_unlock(call->mutex);
		srgs_destroy(parser);
		return;
	}

	/* create input handler */
	handler = (struct input_handler *)switch_channel_get_private(switch_core_session_get_channel(session), RAYO_INPUT_COMPONENT_PRIVATE_VAR);
	if (!handler) {
		handler = switch_core_session_alloc(session, sizeof(*handler));
		switch_channel_set_private(switch_core_session_get_channel(session), RAYO_INPUT_COMPONENT_PRIVATE_VAR, handler);
	} else if (handler->parser) {
		srgs_destroy(handler->parser);
	}
	handler->parser = parser;
	handler->num_digits = 0;
	handler->digits[0] = '\0';
	handler->call = call;

	/* create JID */
	ref = create_uuid_str(session);
	call->input_jid = create_call_component_jid(session, call, ref);
	
	/* install input callbacks */
	switch_core_event_hook_add_recv_dtmf(session, input_component_on_dtmf);
	switch_channel_add_state_handler(switch_core_session_get_channel(session), &input_component_state_handlers);

	/* all good, acknowledge command */
	send_component_ref(session, iq, ref);

	switch_mutex_unlock(call->mutex);
}

/**
 * <output> component validation
 */
static const struct iks_attrib_definition output_attribs_def[] = {
	{ "start-offset", "0", iks_attrib_is_not_negative, SWITCH_FALSE },
	{ "start-paused", "false", iks_attrib_is_bool, SWITCH_FALSE },
	{ "repeat-interval", "0", iks_attrib_is_not_negative, SWITCH_FALSE },
	{ "repeat-times", "1", iks_attrib_is_positive, SWITCH_FALSE },
	{ "max-time", "-1", iks_attrib_is_positive_or_neg_one, SWITCH_FALSE },
	{ "renderer", "", iks_attrib_is_any, SWITCH_FALSE },
	LAST_ATTRIB
};


/* adhearsion uses incorrect reason for finish... this is a temporary fix */
#define OUTPUT_FINISH_AHN "success", "urn:xmpp:rayo:output:complete:1"
#define OUTPUT_FINISH "finish", "urn:xmpp:rayo:output:complete:1"
#define OUTPUT_MAX_TIME "max-time", "urn:xmpp:rayo:output:complete:1"

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

/**
 * <output> a document
 * @param session the session to play to
 * @param document the document to play
 * @param args input args
 * @return status
 */
switch_status_t output_document(switch_core_session_t *session, iks *document, switch_input_args_t *args)
{
	switch_status_t status = SWITCH_STATUS_FALSE;
	char *name;
	if (!document) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "No document to play!\n");
		return SWITCH_STATUS_FALSE;
	}
	name = iks_name(document);
	if (!strcmp("speak", name)) {
		char *ssml = iks_string(NULL, document);
		char *inline_ssml = switch_mprintf("ssml://%s", ssml);
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Playing %s\n", inline_ssml);
		status = switch_ivr_play_file(session, NULL, inline_ssml, args);
		iks_free(ssml);
		switch_safe_free(inline_ssml);
	} else {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Expected <speak>, got: <%s>!\n", name);
	}
	return status;
}

/**
 * Start execution of output component
 */
void start_output_component(switch_core_session_t *session, struct rayo_call *call, iks *iq)
{
	struct output_attribs o_attribs;
	char *ref = NULL;
	iks *output = iks_child(iq);
	iks *document = NULL;

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

	/* acknowledge command */
	ref = create_uuid_str(session);
	call->output_jid = create_call_component_jid(session, call, ref);
	send_component_ref(session, iq, ref);
	
	switch_mutex_unlock(call->mutex);

	/* render document(s) */
	document = iks_find(output, "document");
	if (!document) {
		output_document(session, iks_child(output), NULL);
	} else {
		for (; document; document = iks_next(document)) {
			output_document(session, iks_child(document), NULL);
		}
	}

	/* done */
	switch_mutex_lock(call->mutex);
	send_component_complete(session, call->output_jid, OUTPUT_FINISH_AHN);
	call->output_jid = "";
	switch_mutex_unlock(call->mutex);
}

/**
 * <prompt> component validation
 */
static const struct iks_attrib_definition prompt_attribs_def[] = {
	{ "barge-in", "true", iks_attrib_is_bool, SWITCH_FALSE },
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