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
 * An output component
 */
struct output_component {
	/* stop flag */
	int stop;
};

#define OUTPUT_COMPONENT(x) ((struct output_component *)(rayo_component_get_data(x)))

/**
 * <output> component validation
 */
ELEMENT(RAYO_OUTPUT)
	ATTRIB(start-offset, 0, not_negative)
	ATTRIB(start-paused, false, bool)
	ATTRIB(repeat-interval, 0, not_negative)
	ATTRIB(repeat-times, 1, positive)
	ATTRIB(max-time, -1, positive_or_neg_one)
	ATTRIB(renderer,, any)
ELEMENT_END

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
	struct output_component *output_component = NULL;
	iks *output = iks_find(iq, "output");
	char *document_str = NULL;
	switch_stream_handle_t stream = { 0 };
	int max_time;
	int repeat_interval;
	int repeat_times;

	/* validate output attributes */
	if (!VALIDATE_RAYO_OUTPUT(output)) {
		iks_new_iq_error(iq, STANZA_ERROR_BAD_REQUEST);
		return NULL;
	}
	max_time = iks_find_int_attrib(output, "max-time");
	repeat_interval = iks_find_int_attrib(output, "repeat-interval");
	repeat_times = iks_find_int_attrib(output, "repeat-times");

	/* acknowledge command */
	component = rayo_call_component_create(NULL, call, "output", iks_find_attrib(iq, "from"));
	output_component = switch_core_alloc(rayo_component_get_pool(component), sizeof(*output_component));
	output_component->stop = 0;
	rayo_component_set_data(component, output_component);
	rayo_component_send_start(component, iq);

	/* build playback command */
	SWITCH_STANDARD_STREAM(stream);

	stream.write_function(&stream, "{rayo_id=%s", rayo_component_get_id(component));

	if (max_time > 0) {
		stream.write_function(&stream, ",timeout=%i", max_time * 1000);
	}

	if (repeat_interval > 0) {
		stream.write_function(&stream, ",repeat_interval=%i", repeat_interval);
	}

	if (repeat_times > 0) {
		stream.write_function(&stream, ",repeat_times=%i", repeat_times);
	}

	document_str = iks_string(NULL, output);
	stream.write_function(&stream, "}rayo://%s", document_str);

	if (rayo_call_is_joined(call) || rayo_call_is_playing(call)) {
		/* mixed */
		switch_ivr_displace_session(session, stream.data, 0, "m");
	} else {
		/* normal play */
		switch_core_session_execute_application_async(session, "playback", stream.data);
	}
	iks_free(document_str);
	switch_safe_free(stream.data);
	rayo_component_unlock(component);
	return NULL;
}

/**
 * Background API data
 */
struct bg_api_cmd {
	const char *cmd;
	const char *args;
	switch_memory_pool_t *pool;
};

/**
 * Thread that outputs to component
 * @param thread this thread
 * @param obj the Rayo mixer context
 * @return NULL
 */
static void *SWITCH_THREAD_FUNC bg_api_thread(switch_thread_t *thread, void *obj)
{
	struct bg_api_cmd *cmd = (struct bg_api_cmd *)obj;
	switch_stream_handle_t stream = { 0 };
	switch_memory_pool_t *pool = cmd->pool;
	SWITCH_STANDARD_STREAM(stream);

	switch_api_execute(cmd->cmd, cmd->args, NULL, &stream);
	switch_safe_free(stream.data);
	switch_core_destroy_memory_pool(&pool);
	return NULL;
}

/**
 * Run a background API command
 * @param cmd API command
 * @param args API args
 */
static void rayo_api_execute_async(const char *cmd, const char *args)
{
	switch_thread_t *thread;
	switch_threadattr_t *thd_attr = NULL;
	struct bg_api_cmd *bg_cmd = NULL;
	switch_memory_pool_t *pool;

	/* set up command */
	switch_core_new_memory_pool(&pool);
	bg_cmd = switch_core_alloc(pool, sizeof(*bg_cmd));
	bg_cmd->pool = pool;
	bg_cmd->cmd = switch_core_strdup(pool, cmd);
	bg_cmd->args = switch_core_strdup(pool, args);

	/* create thread */
	switch_threadattr_create(&thd_attr, pool);
	switch_threadattr_detach_set(thd_attr, 1);
	switch_threadattr_stacksize_set(thd_attr, SWITCH_THREAD_STACKSIZE);
	switch_thread_create(&thread, thd_attr, bg_api_thread, bg_cmd, pool);
}

/**
 * Start execution of output component
 */
static iks *start_mixer_output_component(struct rayo_mixer *mixer, iks *iq)
{
	struct output_component *output_component = NULL;
	struct rayo_component *component = NULL;
	iks *output = iks_find(iq, "output");
	char *document_str = NULL;
	switch_stream_handle_t stream = { 0 };
	int max_time;
	int repeat_interval;
	int repeat_times;

	/* validate output attributes */
	if (!VALIDATE_RAYO_OUTPUT(output)) {
		iks_new_iq_error(iq, STANZA_ERROR_BAD_REQUEST);
		return NULL;
	}
	max_time = iks_find_int_attrib(output, "max-time");
	repeat_interval = iks_find_int_attrib(output, "repeat-interval");
	repeat_times = iks_find_int_attrib(output, "repeat-times");

	/* acknowledge command */
	component = rayo_mixer_component_create(NULL, mixer, "output", iks_find_attrib(iq, "from"));
	output_component = switch_core_alloc(rayo_component_get_pool(component), sizeof(*output_component));
	output_component->stop = 0;
	rayo_component_set_data(component, output_component);
	rayo_component_send_start(component, iq);

	/* build conference command */
	SWITCH_STANDARD_STREAM(stream);

	stream.write_function(&stream, "%s play {rayo_id=%s", rayo_mixer_get_name(mixer), rayo_component_get_id(component));

	if (max_time > 0) {
		stream.write_function(&stream, ",timeout=%i", max_time * 1000);
	}

	if (repeat_interval > 0) {
		stream.write_function(&stream, ",repeat_interval=%i", repeat_interval);
	}

	if (repeat_times > 0) {
		stream.write_function(&stream, ",repeat_times=%i", repeat_times);
	}

	document_str = iks_string(NULL, output);
	stream.write_function(&stream, "}rayo://%s", document_str);
	
	rayo_api_execute_async("conference", stream.data);
	iks_free(document_str);
	switch_safe_free(stream.data);
	return NULL;
}

/**
 * Stop execution of output component
 */
static iks *stop_output_component(struct rayo_component *component, iks *iq)
{
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "%s stopping\n", rayo_component_get_jid(component));
	OUTPUT_COMPONENT(component)->stop = 1;
	return iks_new_iq_result(iq);
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
	/** The component */
	struct rayo_component *component;
	/** silence between repeats */
	int repeat_interval;
	/** number of times to repeat */
	int repeat_times;
};

/**
 * open next file for reading
 * @param handle the file handle
 */
static switch_status_t next_file(switch_file_handle_t *handle)
{
	struct rayo_file_context *context = handle->private_info;
	struct output_component *output = context->component ? OUTPUT_COMPONENT(context->component) : NULL;
	char *file;

  top:

	if (output && output->stop) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "%s stop requested\n", rayo_component_get_jid(context->component));
		return SWITCH_STATUS_FALSE;
	}

	if (switch_test_flag((&context->fh), SWITCH_FILE_OPEN)) {
		switch_core_file_close(&context->fh);
	}

	if (switch_test_flag(handle, SWITCH_FILE_FLAG_WRITE)) {
		/* unsupported */
		return SWITCH_STATUS_FALSE;
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

	/* done? */
	if (!context->cur_doc) {
		if (context->repeat_times > 1) {
			/* repeat all document(s) */
			context->repeat_times--;
			if (!context->repeat_interval) {
				goto top;
			}
		} else {
			/* no more files to play */
			return SWITCH_STATUS_FALSE;
		}
	}

	if (!context->cur_doc) {
		/* play silence between repeats */
		switch_safe_free(context->ssml);
		context->ssml = switch_mprintf("silence_stream://%i", context->repeat_interval);
	} else {
		/* play next document */
		switch_safe_free(context->ssml);
		file = iks_string(NULL, context->cur_doc);
		context->ssml = switch_mprintf("ssml://%s", file);
		iks_free(file);
	}
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
	const char *val;
	iksparser *parser = iks_dom_new(&context->docs);

	/* get additional params */
	val = switch_event_get_header(handle->params, "rayo_id");
	if (!zstr(val)) {
		context->component = rayo_component_locate(val);
	}

	val = switch_event_get_header(handle->params, "repeat_interval");
	if (!zstr(val) && switch_is_number(val)) {
		context->repeat_interval = atoi(val);
	}

	val = switch_event_get_header(handle->params, "repeat_times");
	if (!zstr(val) && switch_is_number(val)) {
		context->repeat_times = atoi(val);
	}

	/* parse rayo doc */
	if (iks_parse(parser, path, 0, 1) == IKS_OK) {
		handle->private_info = context;
		status = next_file(handle);
	} else {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Parse error! %s\n", path);
	}

	iks_parser_delete(parser);

	if (status != SWITCH_STATUS_SUCCESS && context->component) {
		/* TODO send error */
		rayo_component_send_complete(context->component, OUTPUT_FINISH_AHN);
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

	/* notify of component completion */
	if (context->component) {
		/* send completion and destroy */
		rayo_component_send_complete(context->component, OUTPUT_FINISH_AHN);
		/* TODO hangup / timed out */
	}

	/* cleanup internals */
	switch_safe_free(context->ssml);
	context->ssml = NULL;
	if (context->docs) {
		iks_delete(context->docs);
		context->docs = NULL;
	}

	/* close SSML file */
	if (switch_test_flag((&context->fh), SWITCH_FILE_OPEN)) {
		return switch_core_file_close(&context->fh);
	}

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

	/* done? */
	if (context->component && OUTPUT_COMPONENT(context->component)->stop) {
		return SWITCH_STATUS_FALSE;
	}

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
	rayo_mixer_command_handler_add("set:"RAYO_OUTPUT_NS":output", start_mixer_output_component);
	rayo_component_command_handler_add("output", "set:"RAYO_NS":stop", stop_output_component); /* TODO remove when punchblock is updated */
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
