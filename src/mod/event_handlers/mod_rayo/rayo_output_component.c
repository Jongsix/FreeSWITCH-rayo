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
	/** document to play */
	iks *document;
	/** maximum time to play */
	int max_time;
	/** silence between repeats */
	int repeat_interval;
	/** number of times to repeat */
	int repeat_times;
	/** component file handle */
	switch_file_handle_t *fh;
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
 * Create new output component
 */
static struct rayo_component *create_output_component(struct rayo_actor *actor, iks *output, const char *client_jid)
{
	struct rayo_component *component = NULL;
	struct output_component *output_component = NULL;

	/* validate output attributes */
	if (!VALIDATE_RAYO_OUTPUT(output)) {
		return NULL;
	}

	component = rayo_component_create("output", NULL, actor, client_jid);
	output_component = switch_core_alloc(rayo_component_get_pool(component), sizeof(*output_component));
	output_component->document = iks_copy(output);
	output_component->repeat_interval = iks_find_int_attrib(output, "repeat-interval");
	output_component->repeat_times = iks_find_int_attrib(output, "repeat-times");
	output_component->max_time = iks_find_int_attrib(output, "max-time");
	rayo_component_set_data(component, output_component);
	return component;
}

/**
 * Start execution of call output component
 */
static iks *start_call_output_component(struct rayo_call *call, switch_core_session_t *session,  iks *iq)
{
	struct rayo_component *component = NULL;
	struct output_component *output_component = NULL;
	iks *output = iks_find(iq, "output");
	switch_stream_handle_t stream = { 0 };

	component = create_output_component(rayo_call_get_actor(call), output, iks_find_attrib(iq, "from"));
	if (!component) {
		return iks_new_iq_error(iq, STANZA_ERROR_BAD_REQUEST);
	}
	output_component = OUTPUT_COMPONENT(component);

	/* acknowledge command */
	rayo_component_send_start(component, iq);

	/* build playback command */
	SWITCH_STANDARD_STREAM(stream);

	if (output_component->max_time > 0) {
		stream.write_function(&stream, "{timeout=%i}", output_component->max_time * 1000);
	}

	stream.write_function(&stream, "rayo://%s", rayo_component_get_jid(component));
	if (rayo_call_is_joined(call) || rayo_call_is_playing(call)) {
		/* mixed */
		switch_ivr_displace_session(session, stream.data, 0, "m");
	} else {
		/* normal play */
		switch_core_session_execute_application_async(session, "playback", stream.data);
	}
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

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "BGAPI EXEC: %s %s\n", cmd->cmd, cmd->args);
	if (switch_api_execute(cmd->cmd, cmd->args, NULL, &stream) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "BGAPI EXEC FAILURE\n");
		/* TODO send complete on failure */
		/* TODO make component-specific thread */
	} else {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "BGAPI EXEC RESULT: %s\n", (char *)stream.data);
	}
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
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "BGAPI START\n");
	switch_threadattr_create(&thd_attr, pool);
	switch_threadattr_detach_set(thd_attr, 1);
	switch_threadattr_stacksize_set(thd_attr, SWITCH_THREAD_STACKSIZE);
	switch_thread_create(&thread, thd_attr, bg_api_thread, bg_cmd, pool);
}

/**
 * Start execution of mixer output component
 */
static iks *start_mixer_output_component(struct rayo_mixer *mixer, iks *iq)
{
	struct output_component *output_component = NULL;
	struct rayo_component *component = NULL;
	iks *output = iks_find(iq, "output");
	switch_stream_handle_t stream = { 0 };

	component = create_output_component(rayo_mixer_get_actor(mixer), output, iks_find_attrib(iq, "from"));
	if (!component) {
		return iks_new_iq_error(iq, STANZA_ERROR_BAD_REQUEST);
	}
	output_component = OUTPUT_COMPONENT(component);

	/* build conference command */
	SWITCH_STANDARD_STREAM(stream);

	stream.write_function(&stream, "%s play ", rayo_mixer_get_name(mixer), rayo_component_get_id(component));

	if (output_component->max_time > 0) {
		stream.write_function(&stream, "{timeout=%i}", output_component->max_time * 1000);
	}

	stream.write_function(&stream, "rayo://%s", rayo_component_get_jid(component));
	rayo_api_execute_async("conference", stream.data);

	switch_safe_free(stream.data);
	rayo_component_unlock(component);

	return NULL;
}

/**
 * Stop execution of output component
 */
static iks *stop_output_component(struct rayo_component *component, iks *iq)
{
	if (OUTPUT_COMPONENT(component)->fh) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "%s stopping\n", rayo_component_get_jid(component));
		switch_set_flag(OUTPUT_COMPONENT(component)->fh, SWITCH_FILE_DONE);
		return iks_new_iq_result(iq);
	}
	/* unlikely- got here before fh assigned */
	return iks_new_iq_error(iq, STANZA_ERROR_INTERNAL_SERVER_ERROR);
}

/**
 * Pause execution of output component
 */
static iks *pause_output_component(struct rayo_component *component, iks *iq)
{
	if (OUTPUT_COMPONENT(component)->fh) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "%s pausing\n", rayo_component_get_jid(component));
		switch_set_flag(OUTPUT_COMPONENT(component)->fh, SWITCH_FILE_PAUSE);
		return iks_new_iq_result(iq);
	}
	/* unlikely- got here before fh assigned */
	return iks_new_iq_error(iq, STANZA_ERROR_INTERNAL_SERVER_ERROR);
}

/**
 * Resume execution of output component
 */
static iks *resume_output_component(struct rayo_component *component, iks *iq)
{
	if (OUTPUT_COMPONENT(component)->fh) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "%s resuming\n", rayo_component_get_jid(component));
		switch_clear_flag(OUTPUT_COMPONENT(component)->fh, SWITCH_FILE_PAUSE);
		return iks_new_iq_result(iq);
	}
	/* unlikely- got here before fh assigned */
	return iks_new_iq_error(iq, STANZA_ERROR_INTERNAL_SERVER_ERROR);
}

/**
 * Speed up execution of output component
 */
static iks *speed_up_output_component(struct rayo_component *component, iks *iq)
{
	if (OUTPUT_COMPONENT(component)->fh) {
		OUTPUT_COMPONENT(component)->fh->speed++;
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "%s speeding up to %i\n", rayo_component_get_jid(component), OUTPUT_COMPONENT(component)->fh->speed);
		return iks_new_iq_result(iq);
	}
	/* unlikely- got here before fh assigned */
	return iks_new_iq_error(iq, STANZA_ERROR_INTERNAL_SERVER_ERROR);
}

/**
 * Slow down execution of output component
 */
static iks *speed_down_output_component(struct rayo_component *component, iks *iq)
{
	if (OUTPUT_COMPONENT(component)->fh) {
		OUTPUT_COMPONENT(component)->fh->speed--;
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "%s slowing down to %i\n", rayo_component_get_jid(component), OUTPUT_COMPONENT(component)->fh->speed);
		return iks_new_iq_result(iq);
	}
	/* unlikely- got here before fh assigned */
	return iks_new_iq_error(iq, STANZA_ERROR_INTERNAL_SERVER_ERROR);
}

/**
 * Increase volume of output component
 */
static iks *volume_up_output_component(struct rayo_component *component, iks *iq)
{
	if (OUTPUT_COMPONENT(component)->fh) {
		OUTPUT_COMPONENT(component)->fh->vol++;
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "%s increasing volume to %i\n", rayo_component_get_jid(component), OUTPUT_COMPONENT(component)->fh->vol);
		return iks_new_iq_result(iq);
	}
	/* unlikely- got here before fh assigned */
	return iks_new_iq_error(iq, STANZA_ERROR_INTERNAL_SERVER_ERROR);
}

/**
 * Lower volume of output component
 */
static iks *volume_down_output_component(struct rayo_component *component, iks *iq)
{
	if (OUTPUT_COMPONENT(component)->fh) {
		OUTPUT_COMPONENT(component)->fh->vol--;
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "%s lowering volume to %i\n", rayo_component_get_jid(component), OUTPUT_COMPONENT(component)->fh->vol);
		return iks_new_iq_result(iq);
	}
	/* unlikely- got here before fh assigned */
	return iks_new_iq_error(iq, STANZA_ERROR_INTERNAL_SERVER_ERROR);
}

ATTRIB_RULE(seek_direction)
{
	return !strcmp("forward", value) || !strcmp("back", value);
}

ELEMENT(RAYO_OUTPUT_SEEK)
	ATTRIB(direction,, seek_direction)
	ATTRIB(amount,-1, positive)
ELEMENT_END

/**
 * Seek output component
 */
static iks *seek_output_component(struct rayo_component *component, iks *iq)
{
	iks *seek = iks_find(iq, "seek");
	iks *response = NULL;
	if (!OUTPUT_COMPONENT(component)->fh) {
		/* unlikely- got here before fh assigned */
		response = iks_new_iq_error(iq, STANZA_ERROR_INTERNAL_SERVER_ERROR);
	} else if (!VALIDATE_RAYO_OUTPUT_SEEK(seek)) {
		response = iks_new_iq_error(iq, STANZA_ERROR_BAD_REQUEST);
	} else {
		struct output_component *output = OUTPUT_COMPONENT(component);
		int is_forward = !strcmp("forward", iks_find_attrib(seek, "direction"));
		int amount_ms = iks_find_int_attrib(seek, "amount");
		int samples_per_ms = 0;
		int32_t target = 0;
		unsigned int pos = 0;
		if (rayo_component_get_parent_type(component) == RAT_MIXER) {
			/* TODO get sample rate from mixer */
			samples_per_ms = 16000 / 1000;
		} else {
			/* TODO get sample rate from call */
			samples_per_ms = 8000 / 1000;
		}
		if (!is_forward) {
			amount_ms *= -1;
		}
		target = (int32_t)output->fh->pos + (amount_ms * samples_per_ms);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "%s seeking %i ms\n",
			rayo_component_get_jid(component), amount_ms);
		switch_core_file_seek(output->fh, &pos, target, SWITCH_SEEK_SET);
		return iks_new_iq_result(iq);
	}

	return response;
}

/**
 * Rayo document playback state
 */
struct rayo_file_context {
	/** handle to current file */
	switch_file_handle_t fh;
	/** current document being played */
	iks *cur_doc;
	/** current file string being played */
	char *ssml;
	/** The component */
	struct rayo_component *component;
	/** number of times played */
	int play_count;
};

/**
 * open next file for reading
 * @param handle the file handle
 */
static switch_status_t next_file(switch_file_handle_t *handle)
{
	struct rayo_file_context *context = handle->private_info;
	struct output_component *output = context->component ? OUTPUT_COMPONENT(context->component) : NULL;

  top:

	if (switch_test_flag((&context->fh), SWITCH_FILE_OPEN)) {
		switch_core_file_close(&context->fh);
	}

	if (switch_test_flag(handle, SWITCH_FILE_FLAG_WRITE)) {
		/* unsupported */
		return SWITCH_STATUS_FALSE;
	}

	if (!context->cur_doc) {
		context->cur_doc = iks_find(output->document, "document");
		if (!context->cur_doc) {
			iks_delete(output->document);
			output->document = NULL;
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Missing <document>\n");
			return SWITCH_STATUS_FALSE;
		}
	} else {
		context->cur_doc = iks_next_tag(context->cur_doc);
	}

	/* done? */
	if (!context->cur_doc) {
		if (++context->play_count < output->repeat_times) {
			/* repeat all document(s) */
			if (!output->repeat_interval) {
				goto top;
			}
		} else {
			/* no more files to play */
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Done playing\n");
			return SWITCH_STATUS_FALSE;
		}
	}

	if (!context->cur_doc) {
		/* play silence between repeats */
		switch_safe_free(context->ssml);
		context->ssml = switch_mprintf("silence_stream://%i", output->repeat_interval);
	} else {
		/* play next document */
		iks *speak = NULL;

		switch_safe_free(context->ssml);
		context->ssml = NULL;
 		speak = iks_find(context->cur_doc, "speak");
		if (speak) {
			char *ssml_str = iks_string(NULL, speak);
			context->ssml = switch_mprintf("ssml://%s", ssml_str);
			iks_free(ssml_str);
		} else if (iks_has_children(context->cur_doc)) {
			const char *ssml_str = iks_cdata(iks_child(context->cur_doc));
			if (zstr(ssml_str)) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Empty <speak> CDATA\n");
				return SWITCH_STATUS_FALSE;
			}
			context->ssml = switch_mprintf("ssml://%s", ssml_str);
		} else {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Missing <speak>\n");
			return SWITCH_STATUS_FALSE;
		}
	}
	if (switch_core_file_open(&context->fh, context->ssml, handle->channels, handle->samplerate, handle->flags, NULL) != SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Failed to open %s\n", context->ssml);
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

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Got path %s\n", path);

	context->component = rayo_component_locate(path);

	if (context->component) {
		OUTPUT_COMPONENT(context->component)->fh = handle;
		handle->private_info = context;
		context->cur_doc = NULL;
		context->play_count = 0;
		status = next_file(handle);
	} else {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "File error! %s\n", path);
	}

	if (status != SWITCH_STATUS_SUCCESS && context->component) {
		/* TODO send error */
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Status = %i\n", status);
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

	if (context && context->component) {
		struct output_component *output = OUTPUT_COMPONENT(context->component);

		/* send completion and destroy */
		rayo_component_send_complete(context->component, OUTPUT_FINISH_AHN);
		/* TODO hangup / timed out */

		/* cleanup internals */
		switch_safe_free(context->ssml);
		context->ssml = NULL;
		if (output->document) {
			iks_delete(output->document);
			output->document = NULL;
		}

		/* close SSML file */
		if (switch_test_flag((&context->fh), SWITCH_FILE_OPEN)) {
			return switch_core_file_close(&context->fh);
		}
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

/**
 * Seek file
 */
static switch_status_t rayo_file_seek(switch_file_handle_t *handle, unsigned int *cur_sample, int64_t samples, int whence)
{
	struct rayo_file_context *context = handle->private_info;

	if (samples == 0 && whence == SWITCH_SEEK_SET) {
		/* restart from beginning */
		context->cur_doc = NULL;
		context->play_count = 0;
		return next_file(handle);
	}

	if (!handle->seekable) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "File is not seekable\n");
		return SWITCH_STATUS_NOTIMPL;
	}

	return switch_core_file_seek(&context->fh, cur_sample, samples, whence);
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
	rayo_call_component_command_handler_add("output", "set:"RAYO_EXT_NS":stop", stop_output_component);
	rayo_call_component_command_handler_add("output", "set:"RAYO_OUTPUT_NS":pause", pause_output_component);
	rayo_call_component_command_handler_add("output", "set:"RAYO_OUTPUT_NS":resume", resume_output_component);
	rayo_call_component_command_handler_add("output", "set:"RAYO_OUTPUT_NS":speed-up", speed_up_output_component);
	rayo_call_component_command_handler_add("output", "set:"RAYO_OUTPUT_NS":speed-down", speed_down_output_component);
	rayo_call_component_command_handler_add("output", "set:"RAYO_OUTPUT_NS":volume-up", volume_up_output_component);
	rayo_call_component_command_handler_add("output", "set:"RAYO_OUTPUT_NS":volume-down", volume_down_output_component);
	rayo_call_component_command_handler_add("output", "set:"RAYO_OUTPUT_NS":seek", seek_output_component);

	rayo_mixer_command_handler_add("set:"RAYO_OUTPUT_NS":output", start_mixer_output_component);
	rayo_mixer_component_command_handler_add("output", "set:"RAYO_EXT_NS":stop", stop_output_component);
	rayo_mixer_component_command_handler_add("output", "set:"RAYO_OUTPUT_NS":pause", pause_output_component);
	rayo_mixer_component_command_handler_add("output", "set:"RAYO_OUTPUT_NS":resume", resume_output_component);
	rayo_mixer_component_command_handler_add("output", "set:"RAYO_OUTPUT_NS":speed-up", speed_up_output_component);
	rayo_mixer_component_command_handler_add("output", "set:"RAYO_OUTPUT_NS":speed-down", speed_down_output_component);
	rayo_mixer_component_command_handler_add("output", "set:"RAYO_OUTPUT_NS":volume-up", volume_up_output_component);
	rayo_mixer_component_command_handler_add("output", "set:"RAYO_OUTPUT_NS":volume-down", volume_down_output_component);
	rayo_mixer_component_command_handler_add("output", "set:"RAYO_OUTPUT_NS":seek", seek_output_component);

	file_interface = switch_loadable_module_create_interface(*module_interface, SWITCH_FILE_INTERFACE);
	file_interface->interface_name = "mod_rayo";
	file_interface->extens = rayo_supported_formats;
	file_interface->file_open = rayo_file_open;
	file_interface->file_close = rayo_file_close;
	file_interface->file_read = rayo_file_read;
	file_interface->file_seek = rayo_file_seek;

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
