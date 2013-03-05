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
#define OUTPUT_FINISH_AHN "success", RAYO_OUTPUT_COMPLETE_NS
#define OUTPUT_FINISH "finish", RAYO_OUTPUT_COMPLETE_NS
#define OUTPUT_MAX_TIME "max-time", RAYO_OUTPUT_COMPLETE_NS


/**
 * Start execution of output component
 */
static iks *start_call_output_component(struct rayo_call *call, switch_core_session_t *session,  iks *iq)
{
	struct rayo_component *component = NULL;
	struct output_attribs o_attribs;
	iks *output = iks_find(iq, "output");
	char *filename = NULL;
	char *document_str = NULL;
	int timeout_ms = 0;

	/* validate output attributes */
	memset(&o_attribs, 0, sizeof(o_attribs));
	if (!iks_attrib_parse(session, output, output_attribs_def, (struct iks_attribs *)&o_attribs)) {
		rayo_component_send_iq_error(iq, STANZA_ERROR_BAD_REQUEST);
		return NULL;
	}

	/* acknowledge command */
	component = rayo_call_component_create(NULL, call, "output", iks_find_attrib(iq, "from"));
	rayo_component_send_start(component, iq);

	/* is a timeout requested? */
	if (o_attribs.max_time.v.i > 0) {
		timeout_ms = (o_attribs.max_time.v.i * 1000);
	}

	document_str = iks_string(NULL, output);
	if (timeout_ms > 0) {
		filename = switch_mprintf("{timeout=%i,rayo_id=%s}rayo://%s", timeout_ms, rayo_component_get_id(component), document_str);
	} else {
		filename = switch_mprintf("{rayo_id=%s}rayo://%s", rayo_component_get_id(component), document_str);
	}

	switch_core_session_execute_application_async(session, "playback", filename);
	iks_free(document_str);
	switch_safe_free(filename);
	return NULL;
}

/**
 * Stop execution of output component
 */
static iks *stop_output_component(struct rayo_component *component, iks *iq)
{
	iks *response = NULL;
	const char *component_jid = iks_find_attrib(iq, "to");
	switch_core_session_t *session = switch_core_session_locate(rayo_component_get_parent_id(component));

	/* stop play */
	if (session) {
		if (switch_core_session_execute_application_async(session, "break", "") == SWITCH_STATUS_SUCCESS) {
			response = iks_new_iq_result(iq);
		} else {
			response = iks_new_iq_error(iq, STANZA_ERROR_INTERNAL_SERVER_ERROR);
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "Failed to stop <output> component %s!\n",
				component_jid);
		}
		switch_core_session_rwunlock(session);
	} else {
		response = iks_new_iq_error(iq, STANZA_ERROR_ITEM_NOT_FOUND);
	}
	return response;
}

/**
 * Rayo document playback state
 */
struct rayo_file_context {
	/** handle to current file */
	switch_file_handle_t fh;
	/** documents to play */
	iks *docs;
	/** current document being played */
	iks *cur_doc;
	/** current file string being played */
	char *ssml;
	/** ID of the rayo output component */
	char *component_id;
};

/**
 * open next file for reading
 * @param handle the file handle
 */
static switch_status_t next_file(switch_file_handle_t *handle)
{
	struct rayo_file_context *context = handle->private_info;
	char *file;

  top:

	if (switch_test_flag((&context->fh), SWITCH_FILE_OPEN)) {
		switch_core_file_close(&context->fh);
	}

	if (!context->cur_doc) {
		iks *doc = iks_find(context->docs, "document");
		if (!doc) {
			doc = iks_find(context->docs, "speak");
		}
		if (!doc) {
			iks_delete(context->docs);
			context->cur_doc = NULL;
			return SWITCH_STATUS_FALSE;
		}
		context->cur_doc = doc;
	} else {
		context->cur_doc = iks_next(context->cur_doc);
	}
	/* TODO repeats */
	/* TODO silence gaps */

	if (!context->cur_doc) {
		return SWITCH_STATUS_FALSE;
	}

	if (switch_test_flag(handle, SWITCH_FILE_FLAG_WRITE)) {
		/* unsupported */
		return SWITCH_STATUS_FALSE;
	}

	switch_safe_free(context->ssml);
	file = iks_string(NULL, context->cur_doc);
	context->ssml = switch_mprintf("ssml://%s", file);
	iks_free(file);
	if (switch_core_file_open(&context->fh, context->ssml, handle->channels, handle->samplerate, handle->flags, NULL) != SWITCH_STATUS_SUCCESS) {
		goto top;
	}

	handle->samples = context->fh.samples;
	handle->format = context->fh.format;
	handle->sections = context->fh.sections;
	handle->seekable = context->fh.seekable;
	handle->speed = context->fh.speed;
	handle->interval = context->fh.interval;

	if (switch_test_flag((&context->fh), SWITCH_FILE_NATIVE)) {
		switch_set_flag(handle, SWITCH_FILE_NATIVE);
	} else {
		switch_clear_flag(handle, SWITCH_FILE_NATIVE);
	}

	return SWITCH_STATUS_SUCCESS;
}

/**
 * Transforms Rayo document into sub-format and opens file_string.
 * @param handle
 * @param path the inline Rayo document
 * @return SWITCH_STATUS_SUCCESS if opened
 */
static switch_status_t rayo_file_open(switch_file_handle_t *handle, const char *path)
{
	switch_status_t status = SWITCH_STATUS_FALSE;
	struct rayo_file_context *context = switch_core_alloc(handle->memory_pool, sizeof(*context));
	iksparser *parser = iks_dom_new(&context->docs);
	if (iks_parse(parser, path, 0, 1) == IKS_OK) {
		handle->private_info = context;
		status = next_file(handle);
	}
	iks_parser_delete(parser);
	context->component_id = switch_event_get_header(handle->params, "rayo_id");
	if (!zstr(context->component_id)) {
		context->component_id = strdup(context->component_id);
	}
	return status;
}

/**
 * Close SSML document.
 * @param handle
 * @return SWITCH_STATUS_SUCCESS
 */
static switch_status_t rayo_file_close(switch_file_handle_t *handle)
{
	struct rayo_file_context *context = (struct rayo_file_context *)handle->private_info;
	struct rayo_component *component = NULL;

	/* close SSML file */
	if (switch_test_flag((&context->fh), SWITCH_FILE_OPEN)) {
		return switch_core_file_close(&context->fh);
	}

	/* notify of component completion */
	if (!zstr(context->component_id)) {
		component = rayo_component_locate(context->component_id);
		if (component) {
			/* send completion and destroy */
			rayo_component_send_complete(component, OUTPUT_FINISH_AHN);
			/* TODO hangup / timed out */
		} else {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Failed to find component: %s\n", context->component_id);
		}
	} else {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Missing component ID\n");
	}

	/* cleanup internals */
	switch_safe_free(context->ssml);
	context->ssml = NULL;
	if (context->docs) {
		iks_delete(context->docs);
		context->docs = NULL;
	}
	switch_safe_free(context->component_id);

	return SWITCH_STATUS_SUCCESS;
}

/**
 * Read from SSML document
 * @param handle
 * @param data
 * @param len
 * @return
 */
static switch_status_t rayo_file_read(switch_file_handle_t *handle, void *data, size_t *len)
{
	switch_status_t status;
	struct rayo_file_context *context = (struct rayo_file_context *)handle->private_info;
	size_t llen = *len;

	status = switch_core_file_read(&context->fh, data, len);
	if (status != SWITCH_STATUS_SUCCESS) {
		if ((status = next_file(handle)) != SWITCH_STATUS_SUCCESS) {
			return status;
		}
		*len = llen;
		status = switch_core_file_read(&context->fh, data, len);
	}
	return status;
}

static char *rayo_supported_formats[] = { "rayo", NULL };

/**
 * Initialize output component
 * @return SWITCH_STATUS_SUCCESS if successful
 */
switch_status_t rayo_output_component_load(switch_loadable_module_interface_t **module_interface, switch_memory_pool_t *pool)
{
	switch_file_interface_t *file_interface;
	rayo_call_command_handler_add("set:"RAYO_OUTPUT_NS":output", start_call_output_component);
	rayo_component_command_handler_add("output", "set:"RAYO_EXT_NS":stop", stop_output_component);

	file_interface = switch_loadable_module_create_interface(*module_interface, SWITCH_FILE_INTERFACE);
	file_interface->interface_name = "mod_rayo";
	file_interface->extens = rayo_supported_formats;
	file_interface->file_open = rayo_file_open;
	file_interface->file_close = rayo_file_close;
	file_interface->file_read = rayo_file_read;
	
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
