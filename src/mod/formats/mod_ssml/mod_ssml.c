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

#define MAX_VOICE_FILES 1024
#define MAX_VOICE_PRIORITY 999
#define VOICE_NAME_PRIORITY 1000
#define VOICE_GENDER_PRIORITY 1000
#define VOICE_LANG_PRIORITY 1000000

/**
 * Module configuration
 */
static struct {
	/** Mapping of language-gender to voice */
	switch_hash_t *voice_cache;
	/** Mapping of voice names */
	switch_hash_t *voice_map;
	/** Mapping of interpret-as value to phrase:macro */
	switch_hash_t *interpret_as_map;
} globals;

/**
 * SSML parser state
 */
struct ssml_parser {
	/** requested name */
	const char *name;
	/** requested language */
	const char *language;
	/** requested gender */
	const char *gender;
	/** files to play */
	const char **files;
	/** number of files */
	int num_files;
	/** max files to play */
	int max_files;
};

/**
 * SSML playback state
 */
struct ssml_context {
	/** handle to current file */
	switch_file_handle_t fh;
	/** files to play */
	const char **files;
	/** number of files */
	int num_files;
	/** current file being played */
	int index;
};

/**
 * A TTS voice
 */
struct voice {
	/** higher priority = more likely to pick */
	int priority;
	/** voice gender */
	char *gender;
	/** voice name */
	char *name;
	/** voice language */
	char *language;
	/** internal file prefix */
	char *prefix;
};

/**
 * Score the voice on how close it is to desired language, name, and gender
 * @param voice the voice to score
 * @param language the desired language
 * @param name the desired name
 * @param gender the desired gender
 * @return the score
 */
static int score_voice(struct voice *voice, const char *language, const char *name, const char *gender)
{
	/* language > gender,name > priority */
	int score = voice->priority;
	if (!zstr(gender) && !strcmp(gender, voice->gender)) {
		score += VOICE_GENDER_PRIORITY;
	}
	if (!zstr(name) && !strcmp(name, voice->name)) {
		score += VOICE_NAME_PRIORITY;
	}
	if (!zstr(language) && !strcmp(language, voice->language)) {
		score += VOICE_LANG_PRIORITY;
	}
	return score;
}

/**
 * Search for best voice based on name, language, gender
 * @param language voice language - this is highest priority
 * @param name voice name - this is low priority
 * @param gender voice gender - this is low priority
 * @return the voice or NULL
 */
static struct voice *find_voice(const char *language, const char *name, const char *gender)
{
	switch_hash_index_t *hi = NULL;
	struct voice *voice = (struct voice *)switch_core_hash_find(globals.voice_map, name);
	char *lang_name_gender = NULL;
	int best_score = 0;

	/* check cache */
	lang_name_gender = switch_mprintf("%s-%s-%s", language, name, gender);
	voice = (struct voice *)switch_core_hash_find(globals.voice_cache, lang_name_gender);
	if (voice) {
		/* that was easy! */
		return voice;
	}

	/* find best language, name, gender match */
	for (hi = switch_hash_first(NULL, globals.voice_map); hi; hi = switch_hash_next(hi)) {
		const void *key;
		void *val;
		struct voice *candidate;
		int candidate_score = 0;
		switch_hash_this(hi, &key, NULL, &val);
		candidate = (struct voice *)val;
		candidate_score = score_voice(candidate, language, name, gender);
		if (candidate_score > best_score) {
			voice = candidate;
			best_score = candidate_score;
		}
	}

	/* remember for next time */
	if (voice) {
		switch_core_hash_insert(globals.voice_cache, lang_name_gender, voice);
	}

	return voice;
}

/**
 * Process <say-as> or <speak>
 * @param pool memory pool to use
 * @param say_as the XML node
 * @param voice default voice
 * @return the file
 */
static const char *parse_say_as_element(switch_memory_pool_t *pool, switch_xml_t say_as, const char *voice)
{
	const char *phrase_macro = (const char *)switch_core_hash_find(globals.interpret_as_map, switch_xml_attr_soft(say_as, "interpret-as"));
	const char *body = switch_xml_txt(say_as);
	if (!zstr(body)) {
		return switch_core_sprintf(pool, "%s%s", zstr(phrase_macro) ? voice : phrase_macro, body);
	}
	return NULL;
}

/**
 * Process <audio>
 * @param pool memory pool to use
 * @param audio the XML node
 * @return the file
 */
static const char *parse_audio_element(switch_memory_pool_t *pool, switch_xml_t audio)
{
	return switch_xml_attr_soft(audio, "src");
}

/**
 * Get list of audio files / TTS phrases from <voice> or <speak>
 * @param pool memory pool to use
 * @param xml the XML node to parse
 * @param ssml_parser parser state
 * @return number of files
 */
static int parse_voice_element(switch_memory_pool_t *pool, switch_xml_t xml, struct ssml_parser *parser)
{
	switch_xml_t child;
	struct voice *voice = NULL;
	const char *xml_name = switch_xml_name(xml);

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Parsing <%s>\n", xml_name);

	if (!strcmp("speak", xml_name)) {
		/* is the <speak> element- find default voice */
		voice = find_voice(switch_xml_attr_soft(xml, "xml:lang"), "", "");
	} else {
		/* a <voice> element */
		const char *gender = switch_xml_attr_soft(xml, "gender");
		const char *name = switch_xml_attr_soft(xml, "name");
		const char *language = switch_xml_attr_soft(xml, "xml:lang");
		if (!zstr(gender)) {
			parser->gender = gender;
		}
		if (!zstr(name)) {
			parser->name = name;
		}
		if (!zstr(language)) {
			parser->language = language;
		}
		voice = find_voice(language, name, gender);
	}

	if (voice) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Using voice %s, %s, %s, %s, %i\n", voice->language, voice->gender, voice->name, voice->prefix, voice->priority);
	}

	/* check body for text */
	if (!xml->child) {
		if (voice) {
			const char *file = parse_say_as_element(pool, xml, voice->prefix);
			if (!zstr(file)) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Adding file: %s\n", file);
				parser->files[parser->num_files++] = file;
			}
		}
	}

	/* look for <audio>, <say-as> elements */
	for (child = xml->child; child && parser->num_files < parser->max_files; child = child->next) {
		const char *name = switch_xml_name(child);
		if (!strcmp("voice", name)) {
			struct ssml_parser new_parser = *parser;
			parser->num_files += parse_voice_element(pool, child, &new_parser);
		} else {
			const char *file = NULL;
			if (!strcmp("audio", name)) {
				/* Audio URI */
				file = parse_audio_element(pool, child);
			} else if (!strcmp("say-as", name)) {
				if (voice) {
					file = parse_say_as_element(pool, child, voice->prefix);
				}
			}
			if (!zstr(file)) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Adding file: %s\n", file);
				parser->files[parser->num_files++] = file;
			}
		}
	}
	return parser->num_files;
}

/**
 * open next file for reading
 * @param handle the file handle
 */
static switch_status_t next_file(switch_file_handle_t *handle)
{
	struct ssml_context *context = handle->private_info;
	const char *file;

  top:

	context->index++;

	if (switch_test_flag((&context->fh), SWITCH_FILE_OPEN)) {
		switch_core_file_close(&context->fh);
	}

	if (context->index >= context->num_files) {
		return SWITCH_STATUS_FALSE;
	}

	file = context->files[context->index];

	if (switch_test_flag(handle, SWITCH_FILE_FLAG_WRITE)) {
		/* unsupported */
		return SWITCH_STATUS_FALSE;
	}

	if (switch_core_file_open(&context->fh, file, handle->channels, handle->samplerate, handle->flags, NULL) != SWITCH_STATUS_SUCCESS) {
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
 * Transforms SSML into file_string format and opens file_string.
 * @param handle
 * @param path the inline SSML
 * @return SWITCH_STATUS_SUCCESS if opened
 */
static switch_status_t ssml_file_open(switch_file_handle_t *handle, const char *path)
{
	struct ssml_context *context = switch_core_alloc(handle->memory_pool, sizeof(*context));
	char *ssml_dup = switch_core_strdup(handle->memory_pool, path);
	switch_xml_t ssml = switch_xml_parse_str(ssml_dup, strlen(ssml_dup));
	switch_status_t status = SWITCH_STATUS_FALSE;

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Open: %s\n", path);

	if (ssml) {
		struct ssml_parser *parser = switch_core_alloc(handle->memory_pool, sizeof(*parser));
		parser->name = "";
		parser->language = "";
		parser->gender = "";
		parser->files = switch_core_alloc(handle->memory_pool, sizeof(const char *) * MAX_VOICE_FILES);
		parser->max_files = MAX_VOICE_FILES;
		parser->num_files = 0;

		/* parse list of audio / TTS requests */
		if (parse_voice_element(handle->memory_pool, ssml, parser)) {
			context->files = parser->files;
			context->num_files = parser->num_files;
			context->index = -1;
			handle->private_info = context;
			status = next_file(handle);
		}
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
	if (!handle->seekable) {
		return SWITCH_STATUS_NOTIMPL;
	}
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
	switch_status_t status;
	struct ssml_context *context = (struct ssml_context *)handle->private_info;
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
 * Configure module
 * @param pool memory pool to use
 * @return SWITCH_STATUS_SUCCESS if module is configured
 */
static switch_status_t do_config(switch_memory_pool_t *pool)
{
	char *cf = "ssml.conf";
	switch_xml_t cfg, xml;

	if (!(xml = switch_xml_open_cfg(cf, &cfg, NULL))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "open of %s failed\n", cf);
		return SWITCH_STATUS_TERM;
	}

	/* get voices */
	{
		int priority = MAX_VOICE_PRIORITY;
		switch_xml_t voices = switch_xml_child(cfg, "voices");
		if (voices) {
			switch_xml_t voice;
			for (voice = switch_xml_child(voices, "voice"); voice; voice = voice->next) {
				const char *name = switch_xml_attr_soft(voice, "name");
				const char *language = switch_xml_attr_soft(voice, "language");
				const char *gender = switch_xml_attr_soft(voice, "gender");
				const char *prefix = switch_xml_attr_soft(voice, "prefix");
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "voice map (%s, %s, %s) = %s\n", name, language, gender, prefix);
				if (!zstr(name) && !zstr(prefix)) {
					struct voice *v = (struct voice *)switch_core_alloc(pool, sizeof(*v));
					v->name = switch_core_strdup(pool, name);
					v->language = switch_core_strdup(pool, language);
					v->gender = switch_core_strdup(pool, gender);
					v->prefix = switch_core_strdup(pool, prefix);
					v->priority = priority--;
					switch_core_hash_insert(globals.voice_map, name, v);
				}
			}
		}
	}

	/* get interpret-as mappings */
	{
		switch_xml_t mappings = switch_xml_child(cfg, "interpret-as");
		if (mappings) {
			switch_xml_t map;
			for (map = switch_xml_child(mappings, "map"); map; map = map->next) {
				const char *var = switch_xml_attr_soft(map, "name");
				const char *val = switch_xml_attr_soft(map, "prefix");
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "interpret-as map: %s = %s\n", var, val);
				if (!zstr(var)) {
					switch_core_hash_insert(globals.interpret_as_map, var, switch_core_strdup(pool, val));
				}
			}
		}
	}

	switch_xml_free(xml);

	return SWITCH_STATUS_SUCCESS;
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

	switch_core_hash_init(&globals.voice_cache, pool);
	switch_core_hash_init(&globals.voice_map, pool);
	switch_core_hash_init(&globals.interpret_as_map, pool);
	return do_config(pool);
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
