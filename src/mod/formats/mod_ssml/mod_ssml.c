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
 *
 * Chris Rienzo <chris.rienzo@grasshopper.com>
 *
 *
 * mod_ssml.c -- SSML audio rendering format
 *
 */
#include <switch.h>

SWITCH_MODULE_LOAD_FUNCTION(mod_ssml_load);
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_ssml_shutdown);
SWITCH_MODULE_DEFINITION(mod_ssml, mod_ssml_load, mod_ssml_shutdown, NULL);

/**
 * Wraps file_string context
 */
struct ssml_context {
	switch_file_handle_t fh;
};

/**
 * Transforms SSML into file_string format and opens file_string.
 * @param handle
 * @param path the inline SSML
 * @return SWITCH_STATUS_SUCCESS if opened
 */
static switch_status_t ssml_file_open(switch_file_handle_t *handle, const char *path)
{
	struct ssml_context *context = switch_core_alloc(handle->memory_pool, sizeof(*context));
	char *ssml_dup = strdup(path);
	switch_xml_t ssml = switch_xml_parse_str(ssml_dup, strlen(ssml_dup));
	switch_status_t status = SWITCH_STATUS_FALSE;

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Open: %s\n", path);

	if (ssml) {
		const char *files[1024];
		int file_count = 0;
		int file_length = strlen("file_string://") + 1;
		char *file_string = NULL;
		switch_xml_t audio;

		/* get files to play */
		/* TODO TTS */
		for (audio = switch_xml_child(ssml, "audio"); audio && file_count < 1024; audio = audio->next) {
			const char *file = switch_xml_attr_soft(audio, "src");
			if (!zstr(file)) {
				files[file_count++] = file;
				file_length += 1 + strlen(file);
			}
		}

		if (file_count) {

			/* transform XML into file_string */
			int i;
			char *fs = file_string = malloc(sizeof(char) * (file_length));
			*fs = '\0';
			strcat(fs, "file_string://");
			fs += strlen("file_string://");
			for (i = 0; i < file_count; i++) {
				if (i != 0) {
					*fs = '!';
					fs++;
				}
				strcat(fs, files[i]);
				fs += strlen(files[i]);
			}

			/* open file_string */
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Opening file %s\n", file_string);
			if ((status = switch_core_file_open(&context->fh, file_string, handle->channels, handle->samplerate, handle->flags, NULL)) == SWITCH_STATUS_SUCCESS) {
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
			}
			switch_safe_free(file_string);
		}
		switch_safe_free(ssml_dup);
		handle->private_info = context;
	}
	return status;
}

/**
 * Close SSML document.
 * @param handle
 * @return SWITCH_STATUS_SUCCESS
 */
static switch_status_t ssml_file_close(switch_file_handle_t *handle)
{
	struct ssml_context *context = (struct ssml_context *)handle->private_info;
	if (switch_test_flag((&context->fh), SWITCH_FILE_OPEN)) {
		return switch_core_file_close(&context->fh);
	}

	return SWITCH_STATUS_SUCCESS;
}

/**
 * Seek SSML document.
 * @param handle
 * @param cur_sample
 * @param samples
 * @param whence
 * @return
 */
static switch_status_t ssml_file_seek(switch_file_handle_t *handle, unsigned int *cur_sample, int64_t samples, int whence)
{
	struct ssml_context *context = (struct ssml_context *)handle->private_info;
	return switch_core_file_seek(&context->fh, cur_sample, samples, whence);
}

/**
 * Read from SSML document
 * @param handle
 * @param data
 * @param len
 * @return
 */
static switch_status_t ssml_file_read(switch_file_handle_t *handle, void *data, size_t *len)
{
	struct ssml_context *context = (struct ssml_context *)handle->private_info;
	return switch_core_file_read(&context->fh, data, len);
}

static char *supported_formats[] = { "ssml" };

SWITCH_MODULE_LOAD_FUNCTION(mod_ssml_load)
{
	switch_file_interface_t *file_interface;

	*module_interface = switch_loadable_module_create_module_interface(pool, modname);
	file_interface = switch_loadable_module_create_interface(*module_interface, SWITCH_FILE_INTERFACE);
	file_interface->interface_name = modname;
	file_interface->extens = supported_formats;
	file_interface->file_open = ssml_file_open;
	file_interface->file_close = ssml_file_close;
	file_interface->file_read = ssml_file_read;
	file_interface->file_seek = ssml_file_seek;

	/* indicate that the module should continue to be loaded */
	return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_ssml_shutdown)
{
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
 * vim:set softtabstop=4 shiftwidth=4 tabstop=4:
 */
