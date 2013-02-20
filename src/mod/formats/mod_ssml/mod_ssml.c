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
#include <iksemel.h>

SWITCH_MODULE_LOAD_FUNCTION(mod_ssml_load);
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_ssml_shutdown);
SWITCH_MODULE_DEFINITION(mod_ssml, mod_ssml_load, mod_ssml_shutdown, NULL);

#define MAX_VOICE_FILES 256
#define MAX_VOICE_PRIORITY 999
#define VOICE_NAME_PRIORITY 1000
#define VOICE_GENDER_PRIORITY 1000
#define VOICE_LANG_PRIORITY 1000000

/**
 * Module configuration
 */
static struct {
	/** Mapping of mod-name-language-gender to voice */
	switch_hash_t *voice_cache;
	/** Mapping of voice names */
	switch_hash_t *say_voice_map;
	/** Mapping of voice names */
	switch_hash_t *tts_voice_map;
	/** Mapping of interpret-as value to macro */
	switch_hash_t *interpret_as_map;
	/** Mapping of ISO language code to say-module */
	switch_hash_t *language_map;
} globals;

/** 
 * A say language
 */
struct language {
	/** The ISO language code */
	char *iso;
	/** The FreeSWITCH language code */
	char *language;
	/** The say module name */
	char *say_module;
};

/**
 * A say macro
 */
struct macro {
	/** interpret-as name (cardinal...) */
	char *name;
	/** language (en-US, en-UK, ...) */
	char *language;
	/** type (number, items, persons, messages...) */
	char *type;
	/** method (pronounced, counted, iterated...) */
	char *method;
};

/**
 * A TTS voice
 */
struct voice {
	/** higher priority = more likely to pick */
	int priority;
	/** voice gender */
	char *gender;
	/** voice name / macro */
	char *name;
	/** voice language */
	char *language;
	/** internal file prefix */
	char *prefix;
};

#define TAG_LEN 32
#define NAME_LEN 128
#define LANGUAGE_LEN 6
#define GENDER_LEN 8

/**
 * SSML voice state
 */
struct ssml_voice_attribs {
	/** tag name */
	char tag_name[TAG_LEN];
	/** requested name */
	char name[NAME_LEN];
	/** requested language */
	char language[LANGUAGE_LEN];
	/** requested gender */
	char gender[GENDER_LEN];
	/** voice to use */
	struct voice *tts_voice;
	/** say macro to use */
	struct macro *say_macro;
	/** previous attribs */
	struct ssml_voice_attribs *parent;
};

/**
 * A file to play
 */
struct ssml_file {
	/** prefix to add to file handle */
	char *prefix;
	/** the file to play */
	const char *name;
};

/**
 * SSML parser state
 */
struct ssml_parser {
	/** current attribs */
	struct ssml_voice_attribs *attribs;
	/** files to play */
	struct ssml_file *files;
	/** number of files */
	int num_files;
	/** max files to play */
	int max_files;
	/** memory pool to use */
	switch_memory_pool_t *pool;
	/** desired sample rate */
	int sample_rate;
};

/**
 * SSML playback state
 */
struct ssml_context {
	/** handle to current file */
	switch_file_handle_t fh;
	/** files to play */
	struct ssml_file *files;
	/** number of files */
	int num_files;
	/** current file being played */
	int index;
};

/**
 * Score the voice on how close it is to desired language, name, and gender
 * @param voice the voice to score
 * @param attribs the desired voice attributes
 * @param lang_required if true, language must match
 * @return the score
 */
static int score_voice(struct voice *voice, struct ssml_voice_attribs *attribs, int lang_required)
{
	/* language > gender,name > priority */
	int score = voice->priority;
	if (!zstr_buf(attribs->gender) && !strcmp(attribs->gender, voice->gender)) {
		score += VOICE_GENDER_PRIORITY;
	}
	if (!zstr_buf(attribs->name) && !strcmp(attribs->name, voice->name)) {
		score += VOICE_NAME_PRIORITY;
	}
	if (!zstr_buf(attribs->language) && !strcmp(attribs->language, voice->language)) {
		score += VOICE_LANG_PRIORITY;
	} else if (lang_required) {
		score = 0;
	}
	return score;
}

/**
 * Search for best voice based on attributes
 * @param attribs the desired voice attributes
 * @param map the map to search
 * @param type "say" or "tts"
 * @param lang_required if true, language must match
 * @return the voice or NULL
 */
static struct voice *find_voice(struct ssml_voice_attribs *attribs, switch_hash_t *map, char *type, int lang_required)
{
	switch_hash_index_t *hi = NULL;
	struct voice *voice = (struct voice *)switch_core_hash_find(map, attribs->name);
	char *lang_name_gender = NULL;
	int best_score = 0;

	/* check cache */
	lang_name_gender = switch_mprintf("%s-%s-%s-%s", type, attribs->language, attribs->name, attribs->gender);
	voice = (struct voice *)switch_core_hash_find(globals.voice_cache, lang_name_gender);
	if (voice) {
		/* that was easy! */
		return voice;
	}

	/* find best language, name, gender match */
	for (hi = switch_hash_first(NULL, map); hi; hi = switch_hash_next(hi)) {
		const void *key;
		void *val;
		struct voice *candidate;
		int candidate_score = 0;
		switch_hash_this(hi, &key, NULL, &val);
		candidate = (struct voice *)val;
		candidate_score = score_voice(candidate, attribs, lang_required);
		if (candidate_score > 0 && candidate_score > best_score) {
			voice = candidate;
			best_score = candidate_score;
		}
	}

	/* remember for next time */
	if (voice) {
		switch_core_hash_insert(globals.voice_cache, lang_name_gender, voice);
	}

	switch_safe_free(lang_name_gender);

	return voice;
}

/**
 * Search for best voice based on attributes
 * @param attribs the desired voice attributes
 * @return the voice or NULL
 */
static struct voice *find_tts_voice(struct ssml_voice_attribs *attribs)
{
	return find_voice(attribs, globals.tts_voice_map, "tts", 0);
}

/**
 * Search for best voice based on attributes
 * @param attribs the desired voice attributes
 * @return the voice or NULL
 */
static struct voice *find_say_voice(struct ssml_voice_attribs *attribs)
{
	return find_voice(attribs, globals.say_voice_map, "say", 1);
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

	
	file = context->files[context->index].name;
	context->fh.prefix = context->files[context->index].prefix;

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
 * Process anything else
 */
static void process_default_open(struct ssml_parser *parsed_data, char *name, char **atts)
{
	struct ssml_voice_attribs *attribs = parsed_data->attribs;

	/* only allow language change in <speak>, <p>, and <s> */
	if (!strcmp("speak", name) || !strcmp("p", name) || !strcmp("s", name)) {
		if (atts) {
			int i = 0;
			while (atts[i]) {
				if (!strcmp("xml:lang", atts[i])) {
					if (!zstr(atts[i + 1])) {
					strncpy(attribs->language, atts[i + 1], LANGUAGE_LEN);
					attribs->language[LANGUAGE_LEN - 1] = '\0';
					}
				}
				i += 2;
			}
		}
	}
	attribs->tts_voice = find_tts_voice(attribs);
}

/**
 * Process <voice>
 */
static void process_voice_open(struct ssml_parser *parsed_data, char **atts)
{
	struct ssml_voice_attribs *attribs = parsed_data->attribs;
	if (atts) {
		int i = 0;
		while (atts[i]) {
			if (!strcmp("xml:lang", atts[i])) {
				if (!zstr(atts[i + 1])) {
					strncpy(attribs->language, atts[i + 1], LANGUAGE_LEN);
					attribs->language[LANGUAGE_LEN - 1] = '\0';
				}
			} else if (!strcmp("name", atts[i])) {
				if (!zstr(atts[i + 1])) {
					strncpy(attribs->name, atts[i + 1], NAME_LEN);
					attribs->name[NAME_LEN - 1] = '\0';
				}
			} else if (!strcmp("gender", atts[i])) {
				if (!zstr(atts[i + 1])) {
					strncpy(attribs->gender, atts[i + 1], GENDER_LEN);
					attribs->gender[GENDER_LEN - 1] = '\0';
				}
			}
			i += 2;
		}
	}
	attribs->tts_voice = find_tts_voice(attribs);
}

/**
 * Process <say-as>
 */
static void process_say_as_open(struct ssml_parser *parsed_data, char **atts)
{
	struct ssml_voice_attribs *attribs = parsed_data->attribs;
	if (atts) {
		int i = 0;
		while (atts[i]) {
			if (!strcmp("interpret-as", atts[i])) {
				char *interpret_as = atts[i + 1];
				if (!zstr(interpret_as)) {
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "interpret-as: %s\n", atts[i + 1]);
					attribs->say_macro = (struct macro *)switch_core_hash_find(globals.interpret_as_map, interpret_as);
				}
				break;
			}
			i += 2;
		}
	}
	attribs->tts_voice = find_tts_voice(attribs);
}

/**
 * Process <audio>- this is a URL to play
 */
static void process_audio_open(struct ssml_parser *parsed_data, char **atts)
{
	if (atts) {
		int i = 0;
		while (atts[i]) {
			if (!strcmp("src", atts[i])) {
				char *src = atts[i + 1];
				if (!zstr(src) && parsed_data->num_files < parsed_data->max_files) {
					/* get the URI */
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Adding <audio>: \"%s\"\n", src);
					parsed_data->files[parsed_data->num_files].name = switch_core_strdup(parsed_data->pool, src);
					parsed_data->files[parsed_data->num_files++].prefix = NULL;
				}
				return;
			}
			i += 2;
		}
	}
}

/**
 * Process a tag
 */
static int tag_hook(void *user_data, char *name, char **atts, int type)
{
	struct ssml_parser *parsed_data = (struct ssml_parser *)user_data;
	switch (type) {
		case IKS_OPEN: {
			struct ssml_voice_attribs *new_attribs = malloc(sizeof *new_attribs);
			struct ssml_voice_attribs *parent = parsed_data->attribs;
			if (parent) {
				/* inherit parent attribs */
				*new_attribs = *parent;
				new_attribs->parent = parent;
			} else {
				new_attribs->name[0] = '\0';
				new_attribs->language[0] = '\0';
				new_attribs->gender[0] = '\0';
				new_attribs->parent = NULL;
			}
			new_attribs->tts_voice = NULL;
			new_attribs->say_macro = NULL;
			strncpy(new_attribs->tag_name, name, TAG_LEN);
			new_attribs->tag_name[TAG_LEN - 1] = '\0';
			parsed_data->attribs = new_attribs;

			if (!strcmp("audio", name)) {
				process_audio_open(parsed_data, atts);
			} else if (!strcmp("voice", name)) {
				process_voice_open(parsed_data, atts);
			} else if (!strcmp("say-as", name)) {
				process_say_as_open(parsed_data, atts);
			} else {
				process_default_open(parsed_data, name, atts);
			}
			break;
		}
		case IKS_CLOSE: {
			if (parsed_data->attribs) {
				struct ssml_voice_attribs *parent = parsed_data->attribs->parent;
				free(parsed_data->attribs);
				parsed_data->attribs = parent;
			}
			break;
		}
		case IKS_SINGLE:
			break;
	}
	return IKS_OK;
}

/**
 * Try to get file(s) from say module
 * @param parsed_data
 * @param to_say
 * @return 1 if successful
 */
static int get_file_from_macro(struct ssml_parser *parsed_data, char *to_say)
{
	struct ssml_voice_attribs *attribs = parsed_data->attribs;
	struct macro *say_macro = attribs->say_macro;
	struct voice *say_voice = find_say_voice(attribs);
	struct language *language;
	char *file_string = NULL;
	char *gender = NULL;
	switch_say_interface_t *si;

	/* voice is required */
	if (!say_voice) {
		return 0;
	}

	language = switch_core_hash_find(globals.language_map, say_voice->language);
	/* language is required */
	if (!language) {
		return 0;
	}

	/* convert SSML gender to FS gender */
	if (!zstr_buf(say_voice->gender)) {
		if (!strcmp("male", say_voice->gender)) {
			gender = "masculine";
		} else if (!strcmp("female", say_voice->gender)) {
			gender = "feminine";
		} else if (!strcmp("neutral", say_voice->gender)) {
			gender = "neuter";
		}
	}

	/* TODO prefix */

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Trying macro: %s, %s, %s, %s, %s\n", language->language, to_say, say_macro->type, say_macro->method, gender);

	if ((si = switch_loadable_module_get_say_interface(language->say_module)) && si->say_string_function) {
		switch_say_args_t say_args = {0};
		say_args.type = switch_ivr_get_say_type_by_name(say_macro->type);
		say_args.method = switch_ivr_get_say_method_by_name(say_macro->method);
		say_args.gender = switch_ivr_get_say_gender_by_name(gender);
		say_args.ext = "wav";
		si->say_string_function(NULL, to_say, &say_args, &file_string);
	}
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Adding macro: \"%s\", prefix=\"%s\"\n", file_string, say_voice->prefix);
	if (!zstr(file_string)) {
		parsed_data->files[parsed_data->num_files].name = switch_core_strdup(parsed_data->pool, file_string);
		parsed_data->files[parsed_data->num_files++].prefix = switch_core_strdup(parsed_data->pool, say_voice->prefix);
		return 1;
	}
	switch_safe_free(file_string);

	return 0;
}

/**
 * Get TTS file for voice
 */
static int get_file_from_voice(struct ssml_parser *parsed_data, char *to_say)
{
	struct ssml_voice_attribs *attribs = parsed_data->attribs;
	char *file = switch_core_sprintf(parsed_data->pool, "%s%s", attribs->tts_voice->prefix, to_say);
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Adding <%s>: \"%s\"\n", attribs->tag_name, file);
	parsed_data->files[parsed_data->num_files].name = file;
	parsed_data->files[parsed_data->num_files++].prefix = NULL;
	return 1;
}

/**
 * Process cdata- this is the text to speak
 */
static int cdata_hook(void *user_data, char *data, size_t len)
{
	struct ssml_parser *parsed_data = (struct ssml_parser *)user_data;
	struct ssml_voice_attribs *attribs = parsed_data->attribs;
	if (len && attribs && attribs->tts_voice &&
			parsed_data->num_files < parsed_data->max_files &&
			(!strcmp("speak", attribs->tag_name) ||
			!strcmp("voice", attribs->tag_name) ||
			!strcmp("say-as", attribs->tag_name) ||
			!strcmp("s", attribs->tag_name) ||
			!strcmp("p", attribs->tag_name))) {

		int i = 0;
		int empty = 1;
		char *to_say;

		/* is CDATA empty? */
		for (i = 0; i < len && empty; i++) {
			empty &= !isgraph(data[i]);
		}
		if (empty) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Skipping empty tts\n");
			return IKS_OK;
		}

		/* try macro */
		to_say = malloc(len + 1);
		strncpy(to_say, data, len);
		to_say[len] = '\0';
		if (!attribs->say_macro || !get_file_from_macro(parsed_data, to_say)) {
			/* use voice instead */
			get_file_from_voice(parsed_data, to_say);
		}
		free(to_say);
	}
	return IKS_OK;
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
		struct ssml_parser *parsed_data = switch_core_alloc(handle->memory_pool, sizeof(*parsed_data));
		iksparser *parser = iks_sax_new(parsed_data, tag_hook, cdata_hook);
		parsed_data->attribs = NULL;
		parsed_data->files = switch_core_alloc(handle->memory_pool, sizeof(struct ssml_file) * MAX_VOICE_FILES);
		parsed_data->max_files = MAX_VOICE_FILES;
		parsed_data->num_files = 0;
		parsed_data->pool = handle->memory_pool;
		parsed_data->sample_rate = handle->samplerate;
		if (iks_parse(parser, path, 0, 1) == IKS_OK && parsed_data->num_files) {
			context->files = parsed_data->files;
			context->num_files = parsed_data->num_files;
			context->index = -1;
			handle->private_info = context;
			status = next_file(handle);
		}
		iks_parser_delete(parser);
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
 * TTS playback state
 */
struct tts_context {
	/** handle to TTS engine */
	switch_speech_handle_t sh;
	/** TTS flags */
	switch_speech_flag_t flags;
	/** number of samples to read at a time */
	int frame_size;
	/** done flag */
	int done;
	/** frames of silence to send before/after sending TTS */
	int lead_in_out;
	int lead;
};

/**
 * Do TTS as file format
 * @param handle
 * @param path the inline SSML
 * @return SWITCH_STATUS_SUCCESS if opened
 */
static switch_status_t tts_file_open(switch_file_handle_t *handle, const char *path)
{
	switch_status_t status = SWITCH_STATUS_SUCCESS;
	struct tts_context *context = switch_core_alloc(handle->memory_pool, sizeof(*context));
	char *arg_string = switch_core_strdup(handle->memory_pool, path);
	char *args[3] = { 0 };
	int argc = switch_separate_string(arg_string, '|', args, (sizeof(args) / sizeof(args[0])));
	char *module;
	char *voice;
	char *document;

	/* path is module:(optional)profile|voice|{param1=val1,param2=val2}TTS document */
	if (argc != 3) {
		return SWITCH_STATUS_FALSE;
	}
	module = args[0];
	voice = args[1];
	document = args[2];

	memset(context, 0, sizeof(*context));
	context->flags = SWITCH_SPEECH_FLAG_NONE;
	context->lead_in_out = 10;
	context->lead = context->lead_in_out;
	if ((status = switch_core_speech_open(&context->sh, module, voice, handle->samplerate, handle->interval, &context->flags, NULL)) == SWITCH_STATUS_SUCCESS) {
		if ((status = switch_core_speech_feed_tts(&context->sh, document, &context->flags)) == SWITCH_STATUS_SUCCESS) {
			handle->channels = 1;
			handle->samples = 0;
			handle->format = 0;
			handle->sections = 0;
			handle->seekable = 0;
			handle->speed = 0;
			context->frame_size = handle->samplerate / 1000 * 20; /* TODO get actual interval */
		} else {
			switch_core_speech_close(&context->sh, &context->flags);
		}
	}
	handle->private_info = context;
	return status;
}

/**
 * Read audio from TTS engine
 * @param handle
 * @param data
 * @param len
 * @return
 */
static switch_status_t tts_file_read(switch_file_handle_t *handle, void *data, size_t *len)
{
	switch_status_t status = SWITCH_STATUS_SUCCESS;
	struct tts_context *context = (struct tts_context *)handle->private_info;
	switch_size_t rlen;

	if (*len > context->frame_size) {
		*len = context->frame_size;
	}
	rlen = *len * 2;

	if (context->lead) {
		memset(data, 0, *len);
		context->lead--;
	} else if (!context->done) {
		context->flags = SWITCH_SPEECH_FLAG_BLOCKING;
		if ((status = switch_core_speech_read_tts(&context->sh, data, &rlen, &context->flags))) {
			context->done = 1;
			context->lead = context->lead_in_out;
		}
	} else {
		switch_core_speech_flush_tts(&context->sh);
		memset(data, 0, *len);
		status = SWITCH_STATUS_FALSE;
	}
	*len = rlen / 2;
	return status;
}

/**
 * Close TTS engine
 * @param handle
 * @return SWITCH_STATUS_SUCCESS
 */
static switch_status_t tts_file_close(switch_file_handle_t *handle)
{
	struct tts_context *context = (struct tts_context *)handle->private_info;
	switch_core_speech_close(&context->sh, &context->flags);
	return SWITCH_STATUS_SUCCESS;
}

/**
 * Configure voices
 * @param pool memory pool to use
 * @param map voice map to load
 * @param type type of voices (for logging)
 */
static void do_config_voices(switch_memory_pool_t *pool, switch_xml_t voices, switch_hash_t *map, const char *type)
{
	if (voices) {
		int priority = MAX_VOICE_PRIORITY;
		switch_xml_t voice;
		for (voice = switch_xml_child(voices, "voice"); voice; voice = voice->next) {
			const char *name = switch_xml_attr_soft(voice, "name");
			const char *language = switch_xml_attr_soft(voice, "language");
			const char *gender = switch_xml_attr_soft(voice, "gender");
			const char *prefix = switch_xml_attr_soft(voice, "prefix");
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "%s map (%s, %s, %s) = %s\n", type, name, language, gender, prefix);
			if (!zstr(name) && !zstr(prefix)) {
				struct voice *v = (struct voice *)switch_core_alloc(pool, sizeof(*v));
				v->name = switch_core_strdup(pool, name);
				v->language = switch_core_strdup(pool, language);
				v->gender = switch_core_strdup(pool, gender);
				v->prefix = switch_core_strdup(pool, prefix);
				v->priority = priority--;
				switch_core_hash_insert(map, name, v);
			}
		}
	}
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
	do_config_voices(pool, switch_xml_child(cfg, "tts-voices"), globals.tts_voice_map, "tts");
	do_config_voices(pool, switch_xml_child(cfg, "say-voices"), globals.say_voice_map, "say");

	/* get languages */
	{
		switch_xml_t languages = switch_xml_child(cfg, "language-map");
		if (languages) {
			switch_xml_t language;
			for (language = switch_xml_child(languages, "language"); language; language = language->next) {
				const char *iso = switch_xml_attr_soft(language, "iso");
				const char *say_module = switch_xml_attr_soft(language, "say-module");
				const char *lang = switch_xml_attr_soft(language, "language");
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "language map: %s = (%s, %s) \n", iso, say_module, lang);
				if (!zstr(iso) && !zstr(say_module) && !zstr(lang)) {
					struct language *l = (struct language *)switch_core_alloc(pool, sizeof(*l));
					l->iso = switch_core_strdup(pool, iso);
					l->say_module = switch_core_strdup(pool, say_module);
					l->language = switch_core_strdup(pool, lang);
					switch_core_hash_insert(globals.language_map, iso, l);
				}
			}
		}
	}
	
	/* get macros */
	{
		switch_xml_t macros = switch_xml_child(cfg, "macros");
		if (macros) {
			switch_xml_t macro;
			for (macro = switch_xml_child(macros, "macro"); macro; macro = macro->next) {
				const char *name = switch_xml_attr_soft(macro, "name");
				const char *method = switch_xml_attr_soft(macro, "method");
				const char *type = switch_xml_attr_soft(macro, "type");
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "macro: %s = (%s, %s) \n", name, method, type);
				if (!zstr(name) && !zstr(type)) {
					struct macro *m = (struct macro *)switch_core_alloc(pool, sizeof(*m));
					m->name = switch_core_strdup(pool, name);
					m->method = switch_core_strdup(pool, method);
					m->type = switch_core_strdup(pool, type);
					switch_core_hash_insert(globals.interpret_as_map, name, m);
				}
			}
		}
	}

	switch_xml_free(xml);

	return SWITCH_STATUS_SUCCESS;
}

static char *ssml_supported_formats[] = { "ssml", NULL };
static char *tts_supported_formats[] = { "tts", NULL };

SWITCH_MODULE_LOAD_FUNCTION(mod_ssml_load)
{
	switch_file_interface_t *file_interface;

	*module_interface = switch_loadable_module_create_module_interface(pool, modname);
	file_interface = switch_loadable_module_create_interface(*module_interface, SWITCH_FILE_INTERFACE);
	file_interface->interface_name = modname;
	file_interface->extens = ssml_supported_formats;
	file_interface->file_open = ssml_file_open;
	file_interface->file_close = ssml_file_close;
	file_interface->file_read = ssml_file_read;

	file_interface = switch_loadable_module_create_interface(*module_interface, SWITCH_FILE_INTERFACE);
	file_interface->interface_name = modname;
	file_interface->extens = tts_supported_formats;
	file_interface->file_open = tts_file_open;
	file_interface->file_close = tts_file_close;
	file_interface->file_read = tts_file_read;

	switch_core_hash_init(&globals.voice_cache, pool);
	switch_core_hash_init(&globals.tts_voice_map, pool);
	switch_core_hash_init(&globals.say_voice_map, pool);
	switch_core_hash_init(&globals.interpret_as_map, pool);
	switch_core_hash_init(&globals.language_map, pool);
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
