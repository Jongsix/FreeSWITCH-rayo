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
	const char *uuid = switch_event_get_header(event, "Unique-ID");
	const char *file = switch_event_get_header(event, "Record-File-Path");
	struct rayo_component *component = rayo_component_locate(file);

	if (component) {
		const char *duration = switch_event_get_header(event, "Record-File-Duration");
		const char *size = switch_event_get_header(event, "Record-File-Size");
		char *uri = switch_mprintf("file://%s", file);
		iks *presence = NULL;
		iks *x = NULL;

		switch_log_printf(SWITCH_CHANNEL_UUID_LOG(uuid), SWITCH_LOG_DEBUG, "Recording %s done.\n", file);

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
		rayo_component_send_complete_event(component, presence);

		switch_safe_free(uri);
	}
}

/**
 * Start execution of record component
 */
static iks *start_call_record_component(struct rayo_call *call, switch_core_session_t *session, iks *iq)
{
	struct record_attribs r_attribs;
	iks *record = iks_child(iq);
	switch_channel_t *channel = switch_core_session_get_channel(session);
	char *file = NULL;
	int max_duration_sec = 0;

	/* validate record attributes */
	memset(&r_attribs, 0, sizeof(r_attribs));
	if (!iks_attrib_parse(session, record, record_attribs_def, (struct iks_attribs *)&r_attribs)) {
		rayo_component_send_iq_error(iq, STANZA_ERROR_BAD_REQUEST);
		return NULL;
	}

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

	if (r_attribs.start_beep.v.i) {
		switch_ivr_play_file(session, NULL, RECORD_BEEP, NULL);
	}

	if (switch_ivr_record_session(session, file, max_duration_sec, NULL) == SWITCH_STATUS_SUCCESS) {
		struct rayo_component *component;
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Recording started: file = %s\n", file);
		component = rayo_call_component_create(file, call, "record", iks_find_attrib(iq, "from"));
		rayo_component_send_start(component, iq);
	} else {
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
 * Initialize record component
 * @return SWITCH_STATUS_SUCCESS if successful
 */
switch_status_t rayo_record_component_load(void)
{
	switch_event_bind("rayo_record_component", SWITCH_EVENT_RECORD_STOP, NULL, on_record_stop_event, NULL);
	rayo_call_command_handler_add("set:"RAYO_RECORD_NS":record", start_call_record_component);
	rayo_component_command_handler_add("record", "set:"RAYO_NS":stop", stop_record_component); /* TODO remove after punchblock is updated */
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
