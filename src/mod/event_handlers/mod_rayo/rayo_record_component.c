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
 * record_component.c -- Rayo record component implementation
 *
 */
#include "rayo_components.h"
#include "iks_helpers.h"


/**
 * A record component
 */
struct record_component {
	/** pause flag */
	int pause;
	int max_duration;
	int initial_timeout;
	int final_timeout;
	const char *direction;
	int mix;
	int start_beep;
	int stop_beep;
};

#define RECORD_COMPONENT(x) ((struct record_component *)(rayo_component_get_data(x)))

/* 1000 Hz beep for 250ms */
#define RECORD_BEEP "tone_stream://%(250,0,1000)"

/**
 * Validate <record direction="">
 */
static ATTRIB_RULE(record_direction)
{
	return (!strcmp("duplex", value) ||
		!strcmp("send", value) ||
		!strcmp("recv", value));
}

/**
 * <record> component validation
 */
ELEMENT(RAYO_RECORD)
	ATTRIB(format, mp3, any)
	ATTRIB(start-beep, false, bool)
	ATTRIB(stop-beep, false, bool)
	ATTRIB(start-paused, false, bool)
	ATTRIB(max-duration, -1, positive_or_neg_one)
	ATTRIB(initial-timeout, -1, positive_or_neg_one)
	ATTRIB(final-timeout, -1, positive_or_neg_one)
	ATTRIB(direction, duplex, record_direction)
	ATTRIB(mix, false, bool)
ELEMENT_END

/**
 * Handle RECORD_STOP event from FreeSWITCH.
 * @param event received from FreeSWITCH core.  It will be destroyed by the core after this function returns.
 */
static void on_record_stop_event(switch_event_t *event)
{
	const char *uuid = switch_event_get_header(event, "Unique-ID");
	const char *file = switch_event_get_header(event, "Record-File-Path");
	struct rayo_component *component = rayo_component_locate(file);

	if (component) {
		struct record_component *record = RECORD_COMPONENT(component);
		switch_core_session_t *session;
		const char *duration = switch_event_get_header(event, "Record-File-Duration");
		const char *size = switch_event_get_header(event, "Record-File-Size");
		char *uri = switch_mprintf("file://%s", file);
		iks *presence = NULL;
		iks *x = NULL;

		switch_log_printf(SWITCH_CHANNEL_UUID_LOG(uuid), SWITCH_LOG_DEBUG, "Recording %s done.\n", file);

		if (record->stop_beep && (session = switch_core_session_locate(uuid))) {
			switch_ivr_displace_session(session, RECORD_BEEP, 0, "");
			switch_core_session_rwunlock(session);
		}

		/* send complete event to client */
		presence = rayo_component_create_complete_event(component, "recording", RAYO_RECORD_COMPLETE_NS);
		x = iks_find(presence, "complete");
		iks_insert_attrib(x, "xmlns", RAYO_EXT_NS);
		x = iks_insert(x, "recording");
		iks_insert_attrib(x, "xmlns", RAYO_RECORD_COMPLETE_NS);
		iks_insert_attrib(x, "uri", uri);
		if (!zstr(duration)) {
			iks_insert_attrib(x, "duration", duration);
		}
		if (!zstr(size)) {
			iks_insert_attrib(x, "size", size);
		}
		rayo_component_unlock(component);
		rayo_component_send_complete_event(component, presence);

		switch_safe_free(uri);
	}
}

/**
 * Create a record component
 */
static struct rayo_component *record_component_create(struct rayo_actor *actor, const char *client_jid, iks *record)
{
	struct rayo_component *component = NULL;
	struct record_component *record_component = NULL;
	char *file;

	/* validate record attributes */
	if (!VALIDATE_RAYO_RECORD(record)) {
		return NULL;
	}

	/* create record filename from session UUID and ref */
	/* for example: 1234-1234-1234-1234/record-30.wav */
	file = switch_mprintf("%s%srecordings%s%s-%i.%s", SWITCH_GLOBAL_dirs.base_dir, SWITCH_PATH_SEPARATOR, SWITCH_PATH_SEPARATOR,
		rayo_actor_get_id(actor), rayo_actor_seq_next(actor), iks_find_attrib(record, "format"));

	component = rayo_component_create("record", file, actor, client_jid);
	record_component = switch_core_alloc(rayo_actor_get_pool(actor), sizeof(*record_component));
	record_component->max_duration = iks_find_int_attrib(record, "max-duration");
	record_component->initial_timeout = iks_find_int_attrib(record, "initial-timeout");
	record_component->final_timeout = iks_find_int_attrib(record, "final-timeout");
	record_component->direction = switch_core_strdup(rayo_actor_get_pool(actor), iks_find_attrib_soft(record, "direction"));
	record_component->mix = iks_find_bool_attrib(record, "mix");
	record_component->start_beep = iks_find_bool_attrib(record, "start-beep");
	record_component->stop_beep = iks_find_bool_attrib(record, "stop-beep");
	rayo_component_set_data(component, record_component);

	switch_safe_free(file);

	return component;
}

/**
 * Start execution of call record component
 */
static iks *start_call_record_component(struct rayo_call *call, switch_core_session_t *session, iks *iq)
{
	struct rayo_component *component = NULL;
	struct record_component *record_component = NULL;
	iks *record = iks_child(iq);
	switch_channel_t *channel = switch_core_session_get_channel(session);
	int max_duration_sec = 0;

	component = record_component_create(rayo_call_get_actor(call), iks_find_attrib(iq, "from"), record);
	if (!component) {
		rayo_component_send_iq_error(iq, STANZA_ERROR_BAD_REQUEST);
		return NULL;
	}
	record_component = RECORD_COMPONENT(component);

	switch_channel_set_variable(channel, "RECORD_HANGUP_ON_ERROR", "false");
	switch_channel_set_variable(channel, "RECORD_TOGGLE_ON_REPEAT", "");
	switch_channel_set_variable(channel, "RECORD_CHECK_BRIDGE", "");
	switch_channel_set_variable(channel, "RECORD_MIN_SEC", "0");
	switch_channel_set_variable(channel, "RECORD_STEREO", "");
	switch_channel_set_variable(channel, "RECORD_READ_ONLY", "");
	switch_channel_set_variable(channel, "RECORD_WRITE_ONLY", "");
	switch_channel_set_variable(channel, "RECORD_APPEND", "");
	switch_channel_set_variable(channel, "RECORD_WRITE_OVER", "true");
	switch_channel_set_variable(channel, "RECORD_ANSWER_REQ", "");
	switch_channel_set_variable(channel, "RECORD_SILENCE_THRESHOLD", "200");
	if (record_component->initial_timeout > 0) {
		switch_channel_set_variable_printf(channel, "RECORD_INITIAL_TIMEOUT_MS", "%i", record_component->initial_timeout);
	} else {
		switch_channel_set_variable(channel, "RECORD_INITIAL_TIMEOUT_MS", "");
	}
	if (record_component->final_timeout > 0) {
		switch_channel_set_variable_printf(channel, "RECORD_FINAL_TIMEOUT_MS", "%i", record_component->final_timeout);
	} else {
		switch_channel_set_variable(channel, "RECORD_FINAL_TIMEOUT_MS", "");
	}
	/* allow dialplan override for these variables */
	//switch_channel_set_variable(channel, "RECORD_PRE_BUFFER_FRAMES", "");
	//switch_channel_set_variable(channel, "record_sample_rate", "");
	//switch_channel_set_variable(channel, "enable_file_write_buffering", "");

	/* max duration attribute is in milliseconds- convert to seconds */
	if (record_component->max_duration > 0) {
		max_duration_sec = ceil((double)record_component->max_duration / 1000.0);
	}

	if (!strcmp(record_component->direction, "duplex")) {
		if (record_component->mix) {
			/* STEREO */
			switch_channel_set_variable(channel, "RECORD_STEREO", "true");
		} /* else MONO (default) */
	} else if (!strcmp(record_component->direction, "send")) {
		/* record audio sent from the caller */
		switch_channel_set_variable(channel, "RECORD_READ_ONLY", "true");
	} else if (!strcmp(record_component->direction, "recv")) {
		/* record audio received by the caller */
		switch_channel_set_variable(channel, "RECORD_WRITE_ONLY", "true");
	};

/* TODO not in channel thread */
#if 0
	if (record_component->start_beep) {
		switch_ivr_play_file(session, NULL, RECORD_BEEP, NULL);
	}
#endif

	if (switch_ivr_record_session(session, (char *)rayo_component_get_id(component), max_duration_sec, NULL) == SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Recording started: file = %s\n", rayo_component_get_id(component));
		rayo_component_send_start(component, iq);
	} else {
		rayo_component_unlock(component);
		rayo_component_destroy(component);
		rayo_component_send_iq_error(iq, STANZA_ERROR_INTERNAL_SERVER_ERROR);
	}
	return NULL;
}

/**
 * Stop execution of record component
 */
static iks *stop_record_component(struct rayo_component *component, iks *iq)
{
	switch_core_session_t *session = switch_core_session_locate(rayo_component_get_parent_id(component));
	if (session) {
		switch_ivr_stop_record_session(session, rayo_component_get_id(component));
		switch_core_session_rwunlock(session);
	}
	return iks_new_iq_result(iq);
}

/**
 * Pause execution of record component
 */
static iks *pause_record_component(struct rayo_component *component, iks *iq)
{
	/* TODO implement <pause> */
	return iks_new_iq_result(iq);
}

/**
 * Resume execution of record component
 */
static iks *resume_record_component(struct rayo_component *component, iks *iq)
{
	/* TODO implement <resume> */
	return iks_new_iq_result(iq);
}

/**
 * Initialize record component
 * @return SWITCH_STATUS_SUCCESS if successful
 */
switch_status_t rayo_record_component_load(void)
{
	switch_event_bind("rayo_record_component", SWITCH_EVENT_RECORD_STOP, NULL, on_record_stop_event, NULL);
	rayo_call_command_handler_add("set:"RAYO_RECORD_NS":record", start_call_record_component);
	rayo_component_command_handler_add("record", "set:"RAYO_RECORD_NS":pause", pause_record_component);
	rayo_component_command_handler_add("record", "set:"RAYO_RECORD_NS":resume", resume_record_component);
	rayo_component_command_handler_add("record", "set:"RAYO_EXT_NS":stop", stop_record_component);
	return SWITCH_STATUS_SUCCESS;
}

/**
 * Shutdown record component
 * @return SWITCH_STATUS_SUCCESS if successful
 */
switch_status_t rayo_record_component_shutdown(void)
{
	switch_event_unbind_callback(on_record_stop_event);
	return SWITCH_STATUS_SUCCESS;
}
