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
	struct voice *voice;
	/** previous attribs */
	struct ssml_voice_attribs *parent;
};

/**
 * SSML parser state
 */
struct ssml_parser {
	/** current attribs */
	struct ssml_voice_attribs *attribs;
	/** files to play */
	const char **files;
	/** number of files */
	int num_files;
	/** max files to play */
	int max_files;
	/** memory pool to use */
	switch_memory_pool_t *pool;
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
 * Score the voice on how close it is to desired language, name, and gender
 * @param voice the voice to score
 * @param attribs the desired voice attributes
 * @return the score
 */
static int score_voice(struct voice *voice, struct ssml_voice_attribs *attribs)
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
	}
	return score;
}

/**
 * Search for best voice based on attributes
 * @param attribs the desired voice attributes
 * @return the voice or NULL
 */
static struct voice *find_voice(struct ssml_voice_attribs *attribs)
{
	switch_hash_index_t *hi = NULL;
	struct voice *voice = (struct voice *)switch_core_hash_find(globals.voice_map, attribs->name);
	char *lang_name_gender = NULL;
	int best_score = 0;

	/* check cache */
	lang_name_gender = switch_mprintf("%s-%s-%s", attribs->language, attribs->name, attribs->gender);
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
		candidate_score = score_voice(candidate, attribs);
		if (candidate_score > best_score) {
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
	attribs->voice = find_voice(attribs);
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
	attribs->voice = find_voice(attribs);
}

/**
 * Process <say-as>
 */
static void process_say_as_open(struct ssml_parser *parsed_data, char **atts)
{
	struct voice *phrase_macro = NULL;
	struct ssml_voice_attribs *attribs = parsed_data->attribs;
	if (atts) {
		int i = 0;
		while (atts[i]) {
			if (!strcmp("interpret-as", atts[i])) {
				char *interpret_as = atts[i + 1];
				if (!zstr(interpret_as)) {
					phrase_macro = (struct voice *)switch_core_hash_find(globals.interpret_as_map, interpret_as);
				}
				break;
			}
			i += 2;
		}
	}
	if (phrase_macro) {
		attribs->voice = phrase_macro;
	} else {
		attribs->voice = find_voice(attribs);
	}
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
					switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Adding audio: %s\n", src);
					parsed_data->files[parsed_data->num_files++] = switch_core_strdup(parsed_data->pool, src);
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
				new_attribs->voice = NULL;
			} else {
				new_attribs->name[0] = '\0';
				new_attribs->language[0] = '\0'; 
				new_attribs->gender[0] = '\0'; 
				new_attribs->parent = NULL;
				new_attribs->voice = NULL;
			}
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
 * Process cdata- this is the text to speak
 */
static int cdata_hook(void *user_data, char *data, size_t len)
{
	struct ssml_parser *parsed_data = (struct ssml_parser *)user_data;
	struct ssml_voice_attribs *attribs = parsed_data->attribs;
	if (len && attribs && attribs->voice &&
			parsed_data->num_files < parsed_data->max_files && 
			(!strcmp("speak", attribs->tag_name) ||
			!strcmp("voice", attribs->tag_name) ||
			!strcmp("say-as", attribs->tag_name) ||
			!strcmp("s", attribs->tag_name) ||
			!strcmp("p", attribs->tag_name))) {
		/* is CDATA empty? */
		int i = 0;
		int empty = 1;
		for (i = 0; i < len && empty; i++) {
			empty &= isspace(data[i]);
		}
		if (!empty) {
			/* get the text */
			int prefix_len = strlen(attribs->voice->prefix);
			char *file = switch_core_alloc(parsed_data->pool, prefix_len + len + 1);
			file[prefix_len + len] = '\0';
			strncpy(file, attribs->voice->prefix, prefix_len);
			strncpy(file + prefix_len, data, len);
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Adding tts: %s\n", file);
			parsed_data->files[parsed_data->num_files++] = file;
		} else {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Skipping empty tts\n");
		}
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
		parsed_data->files = switch_core_alloc(handle->memory_pool, sizeof(const char *) * MAX_VOICE_FILES);
		parsed_data->max_files = MAX_VOICE_FILES;
		parsed_data->num_files = 0;
		parsed_data->pool = handle->memory_pool;
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
 * SSML playback state
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
	struct tts_context *context = switch_core_alloc(handle->memory_pool, sizeof(*handle));
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
