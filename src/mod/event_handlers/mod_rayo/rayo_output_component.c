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
 * output_component.c -- Rayo output component implementation
 *
 */
#include "rayo_components.h"
#include "iks_helpers.h"

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
		rayo_call_component_send_iq_error(call, iq, STANZA_ERROR_CONFLICT);
		switch_mutex_unlock(call->mutex);
		return;
	}

	/* validate output attributes */
	memset(&o_attribs, 0, sizeof(o_attribs));
	if (!iks_attrib_parse(session, output, output_attribs_def, (struct iks_attribs *)&o_attribs)) {
		rayo_call_component_send_iq_error(call, iq, STANZA_ERROR_BAD_REQUEST);
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
		rayo_call_component_send_iq_error(call, iq, STANZA_ERROR_BAD_REQUEST);
		switch_mutex_unlock(call->mutex);
		return;
	}

	/* acknowledge command */
	ref = rayo_call_component_ref_create(call, "output");
	call->output_jid = rayo_call_component_jid_create(call, ref);
	rayo_call_component_send_ref(call, iq, ref);

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
		rayo_call_component_send_complete(call, call->output_jid, OUTPUT_MAX_TIME);
	} else {
		rayo_call_component_send_complete(call, call->output_jid, OUTPUT_FINISH_AHN);
	}
	call->output_jid = "";
	switch_mutex_unlock(call->mutex);
}

/**
 * Stop execution of output component
 */
void stop_call_output_component(switch_core_session_t *session, struct rayo_call *call, iks *iq)
{
	/* TODO */
}

/**
 * Initialize input component
 * @return SWITCH_STATUS_SUCCESS if successful
 */
switch_status_t rayo_output_component_load(void)
{
	rayo_call_component_add("urn:xmpp:rayo:output:1:output", start_call_output_component, stop_call_output_component);
	return SWITCH_STATUS_SUCCESS;
}

/**
 * Shutdown output component
 * @return SWITCH_STATUS_SUCCESS if successful
 */
switch_status_t rayo_output_component_shutdown(void)
{
	return SWITCH_STATUS_SUCCESS;
}
