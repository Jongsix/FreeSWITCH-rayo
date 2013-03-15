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
 * srgs.c -- Parses / converts / matches SRGS grammars
 *
 */
#include <switch.h>
#include <iksemel.h>
#include <pcre.h>

#include "srgs.h"

#define MAX_RECURSION 100

/**
 * SRGS node types
 */
enum srgs_node_type {
	/** undefined */
	SNT_UNKNOWN,
	/** <grammar> */
	SNT_ROOT,
	/** <rule> */
	SNT_RULE,
	/** <one-of> */
	SNT_ONE_OF,
	/** <item> */
	SNT_ITEM,
	/** <ruleref> unresolved reference to node */
	SNT_UNRESOLVED_REF,
	/** <ruleref> resolved reference to node */
	SNT_REF,
	/** <item> string */
	SNT_STRING,
	/** <tag> */
	SNT_TAG,
	/** <lexicon> */
	SNT_LEXICON,
	/** <example> */
	SNT_EXAMPLE,
	/** <token> */
	SNT_TOKEN,
	/** <meta> */
	SNT_META
};

/**
 * <rule> value
 */
struct rule_value {
	char is_public;
	char *id;
	char *regex;
};

/**
 * <item> value
 */
struct item_value {
	int repeat_min;
	int repeat_max;
	const char *weight;
};

/**
 * <ruleref> value
 */
union ref_value {
	struct srgs_node *node;
	char *uri;
};

/**
 * A node in the SRGS parse tree
 */
struct srgs_node {
	/** Type of node */
	enum srgs_node_type type;
	/** True if node has been inspected for loops */
	char visited;
	/** Node value */
	union {
		char *root;
		const char *string;
		union ref_value ref;
		struct rule_value rule;
		struct item_value item;
	} value;
	/** parent node */
	struct srgs_node *parent;
	/** child node */
	struct srgs_node *child;
	/** sibling node */
	struct srgs_node *next;
	/** number of child nodes */
	int num_children;
};

/**
 * A parsed grammar
 */
struct srgs_grammar {
	/** grammar encoding */
	char *encoding;
	/** grammar language */
	char *language;
	/** true if digit grammar */
	int digit_mode;
	/** grammar parse tree root */
	struct srgs_node *root;
	/** root rule */
	struct srgs_node *root_rule;
	/** compiled grammar regex */
	pcre *compiled_regex;
	/** grammar in regex format */
	char *regex;
	/** grammar in JSGF format */
	char *jsgf;
	/** grammar as JSGF file */
	char *jsgf_file_name;
};

/**
 * The SRGS SAX parser
 */
struct srgs_parser {
	/** parser memory pool */
	switch_memory_pool_t *pool;
	/** The current parsed grammar */
	struct srgs_grammar *grammar;
	/** current node being parsed */
	struct srgs_node *cur;
	/** grammar cache */
	switch_hash_t *cache;
	/** rule names mapped to node */
	switch_hash_t *rules;
	/** optional uuid for logging */
	const char *uuid;
};

/**
 * Convert entity name to node type
 * @param name of entity
 * @return the type or UNKNOWN
 */
static enum srgs_node_type string_to_node_type(char *name)
{
	if (!strcmp("grammar", name)) {
		return SNT_ROOT;
	}
	if (!strcmp("item", name)) {
		return SNT_ITEM;
	}
	if (!strcmp("one-of", name)) {
		return SNT_ONE_OF;
	}
	if (!strcmp("ruleref", name)) {
		return SNT_UNRESOLVED_REF;
	}
	if (!strcmp("rule", name)) {
		return SNT_RULE;
	}
	if (!strcmp("tag", name)) {
		return SNT_TAG;
	}
	if (!strcmp("lexicon", name)) {
		return SNT_LEXICON;
	}
	if (!strcmp("example", name)) {
		return SNT_EXAMPLE;
	}
	if (!strcmp("token", name)) {
		return SNT_TOKEN;
	}
	if (!strcmp("meta", name)) {
		return SNT_META;
	}
	return SNT_UNKNOWN;
}

/**
 * Convert node type to entity name
 * @param type of node
 * @return the name or UNKNOWN
 */
static const char *node_type_to_string(enum srgs_node_type type)
{
	switch (type) {
		case SNT_ROOT: return "grammar";
		case SNT_RULE: return "rule";
		case SNT_ONE_OF: return "one-of";
		case SNT_ITEM: return "item";
		case SNT_UNRESOLVED_REF:
		case SNT_REF: return "ruleref";
		case SNT_STRING: return "string";
		case SNT_TAG: return "tag";
		case SNT_LEXICON: return "lexicon";
		case SNT_EXAMPLE: return "example";
		case SNT_TOKEN: return "token";
		case SNT_META: return "meta";
		case SNT_UNKNOWN: return "UNKNOWN";
	}
	return "UNKNOWN";
}

/**
 * Log node
 */
static void sn_log_node_open(struct srgs_node *node)
{
	switch (node->type) {
		case SNT_ROOT:
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG1, "<grammar>\n");
			return;
		case SNT_RULE:
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG1, "<rule id='%s' scope='%s'>\n", node->value.rule.id, node->value.rule.is_public ? "public" : "private");
			return;
		case SNT_ONE_OF:
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG1, "<one-of>\n");
			return;
		case SNT_ITEM:
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG1, "<item repeat='%i'>\n", node->value.item.repeat_min);
			return;
		case SNT_UNRESOLVED_REF:
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG1, "<ruleref (unresolved) uri='%s'\n", node->value.ref.uri);
			return;
		case SNT_REF:
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG1, "<ruleref uri='#%s'>\n", node->value.ref.node->value.rule.id);
			return;
		case SNT_STRING:
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG1, "%s\n", node->value.string);
			return;
		case SNT_TAG:
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG1, "<tag>\n");
			return;
		case SNT_LEXICON:
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG1, "<lexicon>\n");
			return;
		case SNT_EXAMPLE:
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG1, "<example>\n");
			return;
		case SNT_TOKEN:
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG1, "<token>\n");
			return;
		case SNT_META:
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG1, "<meta>\n");
			return;
		case SNT_UNKNOWN:
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG1, "<unknown>\n");
			return;
	}
}

/**
 * Log node
 */
static void sn_log_node_close(struct srgs_node *node)
{
	switch (node->type) {
		case SNT_ROOT:
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG1, "</grammar>\n");
			return;
		case SNT_RULE:
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG1, "</rule>\n");
			return;
		case SNT_ONE_OF:
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG1, "</one-of>\n");
			return;
		case SNT_ITEM:
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG1, "</item>\n");
			return;
		case SNT_UNRESOLVED_REF:
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG1, "</ruleref (unresolved)>\n");
			return;
		case SNT_REF:
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG1, "</ruleref>\n");
			return;
		case SNT_STRING:
			return;
		case SNT_TAG:
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG1, "</tag>\n");
			return;
		case SNT_LEXICON:
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG1, "</lexicon>\n");
			return;
		case SNT_EXAMPLE:
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG1, "</example>\n");
			return;
		case SNT_TOKEN:
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG1, "</token>\n");
			return;
		case SNT_META:
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG1, "</meta>\n");
			return;
		case SNT_UNKNOWN:
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG1, "</unknown>\n");
			return;
	}
}

/**
 * Create a new node
 * @param pool to use
 * @param type of node
 * @return the node
 */
static struct srgs_node *sn_new(switch_memory_pool_t *pool, enum srgs_node_type type)
{
	struct srgs_node *node = switch_core_alloc(pool, sizeof(*node));
	node->type = type;
	node->visited = 0;
	node->num_children = 0;
	return node;
}

/**
 * @param node to search
 * @return the last sibling of node
 */
static struct srgs_node *sn_find_last_sibling(struct srgs_node *node)
{
	if (node && node->next) {
		return sn_find_last_sibling(node->next);
	}
	return node;
}

/**
 * Add child node
 * @param pool to use
 * @param parent node to add child to
 * @param type the child node type
 * @return the child node
 */
static struct srgs_node *sn_insert(switch_memory_pool_t *pool, struct srgs_node *parent, enum srgs_node_type type)
{
	struct srgs_node *sibling = sn_find_last_sibling(parent->child);
	struct srgs_node *child = sn_new(pool, type);
	child->parent = parent;
	child->next = NULL;
	parent->num_children++;
	if (sibling) {
		sibling->next = child;
	} else {
		parent->child = child;
	}
	return child;
}

/**
 * Add string child node
 * @param pool to use
 * @param parent node to add string to
 * @param string to add - this function does not copy the string
 * @return the string child node
 */
static struct srgs_node *sn_insert_string(switch_memory_pool_t *pool, struct srgs_node *parent, char *string)
{
	struct srgs_node *child = sn_insert(pool, parent, SNT_STRING);
	child->value.string = string;
	return child;
}

/**
 * Process <rule> attributes
 * @param parser the parser state
 * @param atts the attributes
 * @return IKS_OK if ok
 */
static int process_rule(struct srgs_parser *parser, char **atts)
{
	struct srgs_node *rule = parser->cur;
	rule->value.rule.is_public = 0;
	rule->value.rule.id = NULL;
	if (atts) {
		int i = 0;
		while (atts[i]) {
			if (!strcmp("scope", atts[i])) {
				rule->value.rule.is_public = !zstr(atts[i + 1]) && !strcmp("public", atts[i + 1]);
			} else if (!strcmp("id", atts[i])) {
				if (!zstr(atts[i + 1])) {
					rule->value.rule.id = switch_core_strdup(parser->pool, atts[i + 1]);
				}
			}
			i += 2;
		}
	}

	if (zstr(rule->value.rule.id)) {
		switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_INFO, "Missing rule ID: %s\n", rule->value.rule.id);
		return IKS_BADXML;
	}

	if (switch_core_hash_find(parser->rules, rule->value.rule.id)) {
		switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_INFO, "Duplicate rule ID: %s\n", rule->value.rule.id);
		return IKS_BADXML;
	}
	switch_core_hash_insert(parser->rules, rule->value.rule.id, rule);

	return IKS_OK;
}

/**
 * Process <ruleref> attributes
 * @param parser the parser state
 * @param atts the attributes
 * @return IKS_OK if ok
 */
static int process_ruleref(struct srgs_parser *parser, char **atts)
{
	struct srgs_node *ruleref = parser->cur;
	if (atts) {
		int i = 0;
		while (atts[i]) {
			if (!strcmp("uri", atts[i])) {
				char *uri = atts[i + 1];
				if (zstr(uri)) {
					switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_INFO, "Empty <ruleref> uri\n");
					return IKS_BADXML;
				}
				/* only allow local reference */
				if (uri[0] != '#' || strlen(uri) < 2) {
					switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_INFO, "Only local rule refs allowed\n");
					return IKS_BADXML;
				}
				ruleref->value.ref.uri = switch_core_strdup(parser->pool, uri);
				return IKS_OK;
			}
			i += 2;
		}
	}
	return IKS_OK;
}

/**
 * Process <item> attributes
 * @param parser the parser state
 * @param atts the attributes
 * @return IKS_OK if ok
 */
static int process_item(struct srgs_parser *parser, char **atts)
{
	struct srgs_node *item = parser->cur;
	item->value.item.repeat_min = 1;
	item->value.item.repeat_max = 1;
	item->value.item.weight = NULL;
	if (atts) {
		int i = 0;
		while (atts[i]) {
			if (!strcmp("repeat", atts[i])) {
				/* repeats of 0 are not supported by this code */
				char *repeat = atts[i + 1];
				if (zstr(repeat)) {
					switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_INFO, "Empty <item> repeat atribute\n");
					return IKS_BADXML;
				}
				if (switch_is_number(repeat)) {
					/* single number */
					int repeat_val = atoi(repeat);
					if (repeat_val < 1) {
						switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_INFO, "<item> repeat must be >= 0\n");
						return IKS_BADXML;
					}
					item->value.item.repeat_min = repeat_val;
					item->value.item.repeat_max = repeat_val;
				} else {
					/* range */
					char *min = switch_core_strdup(parser->pool, repeat);
					char *max = strchr(min, '-');
					if (max) {
						*max = '\0';
						max++;
					} else {
						switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_INFO, "<item> repeat must be a number or range\n");
						return IKS_BADXML;
					}
					if (switch_is_number(min) && (switch_is_number(max) || zstr(max))) {
						int min_val = atoi(min);
						int max_val = zstr(max) ? INT_MAX : atoi(max);
						/* max must be >= min and > 0
						   min must be >= 0 */
						if ((max_val <= 0) || (max_val < min_val) || (min_val < 0)) {
							switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_INFO, "<item> repeat range invalid\n");
							return IKS_BADXML;
						}
						item->value.item.repeat_min = min_val;
						item->value.item.repeat_max = max_val;
					} else {
						switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_INFO, "<item> repeat range is not a number\n");
						return IKS_BADXML;
					}
				}
			} else if (!strcmp("weight", atts[i])) {
				const char *weight = atts[i + 1];
				if (zstr(weight) || !switch_is_number(weight) || atof(weight) < 0) {
					switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_INFO, "<item> weight is not a number >= 0\n");
					return IKS_BADXML;
				}
				item->value.item.weight = switch_core_strdup(parser->pool, weight);
			}
			i += 2;
		}
	}
	return IKS_OK;
}

/**
 * Process <grammar> attributes
 * @param parser the parser state
 * @param atts the attributes
 * @return IKS_OK if ok
 */
static int process_root(struct srgs_parser *parser, char **atts)
{
	if (atts) {
		int i = 0;
		while (atts[i]) {
			if (!strcmp("mode", atts[i])) {
				char *mode = atts[i + 1];
				if (zstr(mode)) {
					return IKS_BADXML;
				}
				parser->grammar->digit_mode = !strcasecmp(mode, "dtmf");
			} else if(!strcmp("encoding", atts[i])) {
				char *encoding = atts[i + 1];
				if (zstr(encoding)) {
					switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_INFO, "<grammar> encoding is empty\n");
					return IKS_BADXML;
				}
				parser->grammar->encoding = switch_core_strdup(parser->pool, encoding);
			} else if (!strcmp("language", atts[i])) {
				char *language = atts[i + 1];
				if (zstr(language)) {
					switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_INFO, "<grammar> language is empty\n");
					return IKS_BADXML;
				}
				parser->grammar->language = switch_core_strdup(parser->pool, language);
			} else if (!strcmp("root", atts[i])) {
				char *root = atts[i + 1];
				if (zstr(root)) {
					switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_INFO, "<grammar> root is empty\n");
					return IKS_BADXML;
				}
				parser->cur->value.root = switch_core_strdup(parser->pool, root);
			}
			i += 2;
		}
	}
	return IKS_OK;
}

/**
 * Process a tag
 * @param user_data the parser
 * @param name the tag name
 * @param atts tag attributes
 * @param type the tag type OPEN/CLOSE/etc
 * @return IKS_OK if XML is good
 */
static int tag_hook(void *user_data, char *name, char **atts, int type)
{
	struct srgs_parser *parser = (struct srgs_parser *)user_data;
	enum srgs_node_type ntype = string_to_node_type(name);

	switch (ntype) {
	case SNT_ROOT:
		/* grammar only allowed at root */
		if (parser->cur->type != SNT_ROOT) {
			switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_INFO, "<grammar> must be root of document\n");
			return IKS_BADXML;
		}
		return process_root(parser, atts);
	case SNT_UNKNOWN:
		switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_INFO, "unknown type\n");
		return IKS_BADXML;
	default:
		/* proceed and add to parse tree */
		break;
	}

	switch (type) {
		case IKS_OPEN: {
			int result = IKS_OK;
			parser->cur = sn_insert(parser->pool, parser->cur, ntype);
			if (ntype == SNT_UNRESOLVED_REF) {
				result = process_ruleref(parser, atts);
			} else if (ntype == SNT_ITEM) {
				result = process_item(parser, atts);
			} else if (ntype == SNT_RULE) {
				result = process_rule(parser, atts);
			}
			sn_log_node_open(parser->cur);
			return result;
		}
		case IKS_CLOSE: {
			sn_log_node_close(parser->cur);
			parser->cur = parser->cur->parent;
			break;
		}
		case IKS_SINGLE: {
			int result = IKS_OK;
			parser->cur = sn_insert(parser->pool, parser->cur, ntype);
			if (ntype == SNT_UNRESOLVED_REF) {
				result = process_ruleref(parser, atts);
			}
			sn_log_node_open(parser->cur);
			sn_log_node_close(parser->cur);
			parser->cur = parser->cur->parent;
			return result;
		}
	}
	return IKS_OK;
}

/**
 * Process cdata
 * @param user_data the parser
 * @param data the CDATA
 * @param len the CDATA length
 * @return IKS_OK
 */
static int cdata_hook(void *user_data, char *data, size_t len)
{
	struct srgs_parser *parser = (struct srgs_parser *)user_data;
	if (len) {
		if (parser->cur->type == SNT_ITEM /* TODO || parser->cur->type == SNT_RULE || parser->cur->type == SNT_TOKEN */) {
			struct srgs_node *string = parser->cur;
			int i;
			if (parser->grammar->digit_mode) {
				for (i = 0; i < len; i++) {
					if (isdigit(data[i]) || data[i] == '#' || data[i] == '*') {
						char *digit = switch_core_alloc(parser->pool, sizeof(char) * 2);
						digit[0] = data[i];
						digit[1] = '\0';
						string = sn_insert_string(parser->pool, string, digit);
						sn_log_node_open(string);
					}
				}
			} else {
				char *data_dup = switch_core_alloc(parser->pool, sizeof(char) * (len + 1));
				char *start = data_dup;
				char *end = start + len - 1;
				memcpy(data_dup, data, len);
				/* remove start whitespace */
				for (; start && *start && !isgraph(*start); start++) {
				}
				if (!zstr(start)) {
					/* remove end whitespace */
					for (; end != start && *end && !isgraph(*end); end--) {
						*end = '\0';
					}
					if (!zstr(start)) {
						string = sn_insert_string(parser->pool, string, start);
					}
				}
			}
		}
	}
	return IKS_OK;
}

/**
 * Create a new parser.
 * @param uuid optional uuid for logging
 * @return the created parser
 */
struct srgs_parser *srgs_parser_new(const char *uuid)
{
	switch_memory_pool_t *pool = NULL;
	struct srgs_parser *parser = NULL;
	switch_core_new_memory_pool(&pool);
	if (pool) {
		parser = switch_core_alloc(pool, sizeof(*parser));
		parser->pool = pool;
		parser->uuid = zstr(uuid) ? "" : uuid;
		switch_core_hash_init(&parser->cache, pool);
		switch_core_hash_init(&parser->rules, pool);
	}
	return parser;
}

/**
 * Destroy the parser.
 * @param parser to destroy
 */
void srgs_parser_destroy(struct srgs_parser *parser)
{
	switch_memory_pool_t *pool = parser->pool;
	switch_hash_index_t *hi = NULL;

	/* clean up all cached grammars */
	for (hi = switch_core_hash_first(parser->cache); hi; hi = switch_core_hash_next(hi)) {
		struct srgs_grammar *grammar = NULL;
		const void *key;
		void *val;
		switch_core_hash_this(hi, &key, NULL, &val);
		grammar = (struct srgs_grammar *)val;
		switch_assert(grammar);
		if (grammar->compiled_regex) {
			pcre_free(grammar->compiled_regex);
		}
		if (grammar->jsgf_file_name) {
			switch_file_remove(grammar->jsgf_file_name, pool);
		}
	}
	switch_core_destroy_memory_pool(&pool);
}

/**
 * Create regexes
 * @param parser the parser
 * @param node root node
 * @param stream set to NULL
 * @return 1 if successful
 */
static int create_regexes(struct srgs_parser *parser, struct srgs_node *node, switch_stream_handle_t *stream)
{
	sn_log_node_open(node);
	switch (node->type) {
		case SNT_ROOT:
			if (node->child) {
				int num_rules = 0;
				struct srgs_node *child = node->child;
				if (parser->grammar->root_rule) {
					if (!create_regexes(parser, parser->grammar->root_rule, NULL)) {
						return 0;
					}
					parser->grammar->regex = switch_core_sprintf(parser->pool, "^%s$", parser->grammar->root_rule->value.rule.regex);
				} else {
					switch_stream_handle_t new_stream = { 0 };
					SWITCH_STANDARD_STREAM(new_stream);
					if (node->num_children > 1) {
						new_stream.write_function(&new_stream, "%s", "^(?:");
					} else {
						new_stream.write_function(&new_stream, "%s", "^");
					}
					for (; child; child = child->next) {
						if (!create_regexes(parser, child, &new_stream)) {
							switch_safe_free(new_stream.data);
							return 0;
						}
						if (child->type == SNT_RULE && child->value.rule.is_public) {
							if (num_rules > 0) {
								new_stream.write_function(&new_stream, "%s", "|");
							}
							new_stream.write_function(&new_stream, "%s", child->value.rule.regex);
							num_rules++;
						}
					}
					if (node->num_children > 1) {
						new_stream.write_function(&new_stream, "%s", ")$");
					} else {
						new_stream.write_function(&new_stream, "%s", "$");
					}
					parser->grammar->regex = switch_core_strdup(parser->pool, new_stream.data);
					switch_safe_free(new_stream.data);
				}
				switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_DEBUG, "document regex = %s\n", parser->grammar->regex);
			}
			break;
		case SNT_RULE:
			if (node->value.rule.regex) {
				return 1;
			} else if (node->child) {
				struct srgs_node *item = node->child;
				switch_stream_handle_t new_stream = { 0 };
				SWITCH_STANDARD_STREAM(new_stream);
				for (; item; item = item->next) {
					if (!create_regexes(parser, item, &new_stream)) {
						switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_DEBUG, "%s regex failed = %s\n", node->value.rule.id, node->value.rule.regex);
						switch_safe_free(new_stream.data);
						return 0;
					}
				}
				node->value.rule.regex = switch_core_strdup(parser->pool, new_stream.data);
				switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_DEBUG, "%s regex = %s\n", node->value.rule.id, node->value.rule.regex);
				switch_safe_free(new_stream.data);
			}
			break;
		case SNT_STRING: {
			int i;
			for (i = 0; i < strlen(node->value.string); i++) {
				switch (node->value.string[i]) {
					case '[':
					case '\\':
					case '^':
					case '$':
					case '.':
					case '|':
					case '?':
					case '*':
					case '+':
					case '(':
					case ')':
						/* escape special PCRE regex characters */
						stream->write_function(stream, "\\%c", node->value.string[i]);
						break;
					default:
						stream->write_function(stream, "%c", node->value.string[i]);
						break;
				}
			}
			if (node->child) {
				if (!create_regexes(parser, node->child, stream)) {
					return 0;
				}
			}
			break;
		}
		case SNT_ITEM:
			if (node->child) {
				struct srgs_node *item = node->child;
				if (node->value.item.repeat_min != 1 || node->value.item.repeat_max != 1) {
					stream->write_function(stream, "%s", "(?:");
				}
				for(; item; item = item->next) {
					if (!create_regexes(parser, item, stream)) {
						return 0;
					}
				}
				if (node->value.item.repeat_min != 1 || node->value.item.repeat_max != 1) {
					if (node->value.item.repeat_min != node->value.item.repeat_max) {
						if (node->value.item.repeat_min == 0 && node->value.item.repeat_max == INT_MAX) {
								stream->write_function(stream, ")*");
						} else if (node->value.item.repeat_min == 0 && node->value.item.repeat_max == 1) {
								stream->write_function(stream, ")?");
						} else if (node->value.item.repeat_min == 1 && node->value.item.repeat_max == INT_MAX) {
							stream->write_function(stream, ")+");
						} else if (node->value.item.repeat_max == INT_MAX) {
							stream->write_function(stream, "){%i,1000}", node->value.item.repeat_min);
						} else {
							stream->write_function(stream, "){%i,%i}", node->value.item.repeat_min, node->value.item.repeat_max);
						}
					} else {
						stream->write_function(stream, "){%i}", node->value.item.repeat_min);
					}
				}
			}
			break;
		case SNT_ONE_OF:
			if (node->child) {
				struct srgs_node *item = node->child;
				if (node->num_children > 1) {
					stream->write_function(stream, "%s", "(?:");
				}
				for (; item; item = item->next) {
					if (item != node->child) {
						stream->write_function(stream, "%s", "|");
					}
					if (!create_regexes(parser, item, stream)) {
						return 0;
					}
				}
				if (node->num_children > 1) {
					stream->write_function(stream, "%s", ")");
				}
			}
			break;
		case SNT_REF: {
			struct srgs_node *rule = node->value.ref.node;
			if (!rule->value.rule.regex) {
				switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_DEBUG, "ruleref: create %s regex\n", rule->value.rule.id);
				if (!create_regexes(parser, rule, NULL)) {
					return 0;
				}
			}
			if (!rule->value.rule.regex) {
				return 0;
			}
			stream->write_function(stream, "%s", rule->value.rule.regex);
			break;
		}
		case SNT_UNKNOWN:
			switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_DEBUG, "create_regexes() bad type = %s\n", node_type_to_string(node->type));
			return 0;
		default:
			/* ignore */
			return 1;
	}
	sn_log_node_close(node);
	return 1;
}

/**
 * Compile regex
 */
static pcre *get_compiled_regex(struct srgs_parser *parser)
{
	int erroffset = 0;
	const char *errptr = "";
	int options = 0;
	const char *regex;

	if (!parser) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "parser is NULL!\n");
		return NULL;
	}
	if (!parser->grammar) {
		switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_CRIT, "grammar is NULL!\n");
		return NULL;
	}

	if (!parser->grammar->compiled_regex && (regex = srgs_to_regex(parser))) {
		if (!(parser->grammar->compiled_regex = pcre_compile(regex, options, &errptr, &erroffset, NULL))) {
			switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_WARNING, "Failed to compile grammar regex: %s\n", regex);
		}
	}
	return parser->grammar->compiled_regex;
}

/**
 * Resolve all unresolved references and detect loops.
 * @param parser the parser
 * @param node the current node
 * @param level the recursion level
 */
static int resolve_refs(struct srgs_parser *parser, struct srgs_node *node, int level)
{
	sn_log_node_open(node);
	if (node->visited) {
		switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_INFO, "Loop detected.\n");
		return 0;
	}
	node->visited = 1;

	if (level > MAX_RECURSION) {
		switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_INFO, "Recursion too deep.\n");
		return 0;
	}

	if (node->type == SNT_ROOT && node->value.root) {
		struct srgs_node *rule = (struct srgs_node *)switch_core_hash_find(parser->rules, node->value.root);
		if (!rule) {
			switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_INFO, "Root rule not found: %s\n", node->value.root);
			return 0;
		}
		parser->grammar->root_rule = rule;
	}

	if (node->type == SNT_UNRESOLVED_REF) {
		/* resolve reference to local rule- drop first character # from URI */
		struct srgs_node *rule = (struct srgs_node *)switch_core_hash_find(parser->rules, node->value.ref.uri + 1);
		if (!rule) {
			switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_INFO, "Local rule not found: %s\n", node->value.ref.uri);
			return 0;
		}

		/* link to rule */
		node->type = SNT_REF;
		node->value.ref.node = rule;
	}

	/* travel through rule to detect loops */
	if (node->type == SNT_REF) {
		if (!resolve_refs(parser, node->value.ref.node, level + 1)) {
			return 0;
		}
	}

	/* resolve children refs */
	if (node->child) {
		struct srgs_node *child = node->child;
		for (; child; child = child->next) {
			if (!resolve_refs(parser, child, level + 1)) {
				return 0;
			}
		}
	}

	node->visited = 0;
	sn_log_node_close(node);
	return 1;
}

/**
 * Parse the document into rules to match
 * @param parser the parser
 * @param document the document to parse
 * @return true if successful
 */
int srgs_parse(struct srgs_parser *parser, const char *document)
{
	struct srgs_grammar *grammar = NULL;
	if (!parser) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "NULL parser!!\n");
		return 0;
	}

	if (zstr(document)) {
		switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_INFO, "Missing grammar document\n");
		return 0;
	}

	/* check for cached grammar */
	grammar = (struct srgs_grammar *)switch_core_hash_find(parser->cache, document);
	if (!grammar) {
		int result = 0;
		iksparser *p = iks_sax_new(parser, tag_hook, cdata_hook);
		switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_DEBUG, "Parsing new grammar\n");
		grammar = switch_core_alloc(parser->pool, sizeof (*grammar));
		parser->grammar = grammar;
		parser->grammar->root = sn_new(parser->pool, SNT_ROOT);
		parser->cur = parser->grammar->root;
		switch_core_hash_delete_multi(parser->rules, NULL, NULL);
		if (iks_parse(p, document, 0, 1) == IKS_OK) {
			switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_DEBUG, "Resolving references\n");
			if (resolve_refs(parser, parser->grammar->root, 0)) {
				result = 1;
			}
		}
		iks_parser_delete(p);
		if (result) {
			switch_core_hash_insert(parser->cache, document, parser->grammar);
		} else {
			switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_INFO, "Failed to parse grammar\n");
			return 0;
		}
	} else {
		switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_DEBUG, "Using cached grammar\n");
		parser->grammar = grammar;
	}
	return 1;
}

/**
 * Find a match
 * @param parser the parser
 * @param input the input to compare
 * @return the match result
 */
enum srgs_match_type srgs_match(struct srgs_parser *parser, const char *input)
{
	int result = 0;
	int ovector[30];
	int workspace[1024];
	pcre *compiled_regex = get_compiled_regex(parser);
	if (!compiled_regex) {
		return SMT_NO_MATCH;
	}
	result = pcre_dfa_exec(compiled_regex, NULL, input, strlen(input), 0, PCRE_PARTIAL,
		ovector, sizeof(ovector) / sizeof(ovector[0]),
		workspace, sizeof(workspace) / sizeof(workspace[0]));
	switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_DEBUG, "match = %i\n", result);
	if (result > 0) {
		return SMT_MATCH;
	}
	if (result == PCRE_ERROR_PARTIAL) {
		return SMT_MATCH_PARTIAL;
	}
	return SMT_NO_MATCH;
}

/**
 * Generate regex from SRGS document.  Call this after parsing SRGS document.
 * @param parser the parser
 * @return the regex or NULL
 */
const char *srgs_to_regex(struct srgs_parser *parser)
{
	if (!parser || !parser->grammar) {
		switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_INFO, "parser or grammar is NULL!\n");
		return NULL;
	}
	if (!parser->grammar->regex && !create_regexes(parser, parser->grammar->root, NULL)) {
		return NULL;
	}
	return parser->grammar->regex;
}

/**
 * Create JSGF grammar
 * @param parser the parser
 * @param node root node
 * @param stream set to NULL
 * @return 1 if successful
 */
static int create_jsgf(struct srgs_parser *parser, struct srgs_node *node, switch_stream_handle_t *stream)
{
	sn_log_node_open(node);
	switch (node->type) {
		case SNT_ROOT:
			if (node->child) {
				struct srgs_node *child;
				switch_stream_handle_t new_stream = { 0 };
				SWITCH_STANDARD_STREAM(new_stream);

				new_stream.write_function(&new_stream, "#JSGF V1.0");
				if (!zstr(parser->grammar->encoding)) {
					new_stream.write_function(&new_stream, " %s", parser->grammar->encoding);
					if (!zstr(parser->grammar->language)) {
						new_stream.write_function(&new_stream, " %s", parser->grammar->language);
					}
				}

				new_stream.write_function(&new_stream,
					";\ngrammar org.freeswitch.srgs_to_jsgf;\n"
					"public ");

				/* output root rule */
				if (parser->grammar->root_rule) {
					if (!create_jsgf(parser, parser->grammar->root_rule, &new_stream)) {
						switch_safe_free(new_stream.data);
						return 0;
					}
				} else {
					int num_rules = 0;
					int first = 1;

					for (child = node->child; child; child = child->next) {
						if (child->type == SNT_RULE && child->value.rule.is_public) {
							num_rules++;
						}
					}

					if (num_rules > 1) {
						new_stream.write_function(&new_stream, "<root> =");
						for (child = node->child; child; child = child->next) {
							if (child->type == SNT_RULE && child->value.rule.is_public) {
								if (!first) {
									new_stream.write_function(&new_stream, "%s", " |");
								}
								first = 0;
								new_stream.write_function(&new_stream, " <%s>", child->value.rule.id);
							}
						}
						new_stream.write_function(&new_stream, ";\n");
					} else {
						for (child = node->child; child; child = child->next) {
							if (child->type == SNT_RULE && child->value.rule.is_public) {
								parser->grammar->root_rule = child;
								if (!create_jsgf(parser, child, &new_stream)) {
									switch_safe_free(new_stream.data);
									return 0;
								} else {
									break;
								}
							}
						}
					}
				}

				/* output all rule definitions */
				for (child = node->child; child; child = child->next) {
					if (child->type == SNT_RULE && child != parser->grammar->root_rule) {
						if (!create_jsgf(parser, child, &new_stream)) {
							switch_safe_free(new_stream.data);
							return 0;
						}
					}
				}
				parser->grammar->jsgf = switch_core_strdup(parser->pool, new_stream.data);
				switch_safe_free(new_stream.data);
				switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_DEBUG, "document jsgf = %s\n", parser->grammar->jsgf);
			}
			break;
		case SNT_RULE:
			if (node->child) {
				struct srgs_node *item = node->child;
				stream->write_function(stream, "<%s> =", node->value.rule.id);
				for (; item; item = item->next) {
					if (!create_jsgf(parser, item, stream)) {
						switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_DEBUG, "%s jsgf rule failed\n", node->value.rule.id);
						return 0;
					}
				}
				stream->write_function(stream, ";\n");
			}
			break;
		case SNT_STRING: {
			int len = strlen(node->value.string);
			int i;
			stream->write_function(stream, " \"");
			for (i = 0; i < len; i++) {
				switch (node->value.string[i]) {
					case '\\':
					case '"':
						stream->write_function(stream, "\\");
						break;
					default:
						break;
				}
				stream->write_function(stream, "%c", node->value.string[i]);
			}
			stream->write_function(stream, "\"");
			if (node->child) {
				if (!create_jsgf(parser, node->child, stream)) {
					return 0;
				}
			}
			break;
		}
		case SNT_ITEM:
			if (node->child) {
				struct srgs_node *item;
				if (node->value.item.repeat_min == 0 && node->value.item.repeat_max == 1) {
					/* optional item */
					stream->write_function(stream, " [");
					for(item = node->child; item; item = item->next) {
						if (!create_jsgf(parser, item, stream)) {
							return 0;
						}
					}
					stream->write_function(stream, " ]");
				} else {
					/* minimum repeats */
					int i;
					for (i = 0; i < node->value.item.repeat_min; i++) {
						if (node->value.item.repeat_min != 1 && node->value.item.repeat_max != 1) {
							stream->write_function(stream, " (");
						}
						for(item = node->child; item; item = item->next) {
							if (!create_jsgf(parser, item, stream)) {
								return 0;
							}
						}
						if (node->value.item.repeat_min != 1 && node->value.item.repeat_max != 1) {
							stream->write_function(stream, " )");
						}
					}
					if (node->value.item.repeat_max == INT_MAX) {
						stream->write_function(stream, "*");
					} else {
						for (;i < node->value.item.repeat_max; i++) {
							stream->write_function(stream, " [");
							for(item = node->child; item; item = item->next) {
								if (!create_jsgf(parser, item, stream)) {
									return 0;
								}
							}
							stream->write_function(stream, " ]");
						}
					}
				}
			}
			break;
		case SNT_ONE_OF:
			if (node->child) {
				struct srgs_node *item = node->child;
				if (node->num_children > 1) {
					stream->write_function(stream, " (");
				}
				for (; item; item = item->next) {
					if (item != node->child) {
						stream->write_function(stream, " |");
					}
					stream->write_function(stream, " (");
					if (!create_jsgf(parser, item, stream)) {
						return 0;
					}
					stream->write_function(stream, " )");
				}
				if (node->num_children > 1) {
					stream->write_function(stream, " )");
				}
			}
			break;
		case SNT_REF: {
			struct srgs_node *rule = node->value.ref.node;
			stream->write_function(stream, " <%s>", rule->value.rule.id);
			break;
		}
		case SNT_UNKNOWN:
			switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_DEBUG, "create_jsgf() bad type = %s\n", node_type_to_string(node->type));
			return 0;
		default:
			/* ignore */
			return 1;
	}
	sn_log_node_close(node);
	return 1;
}

/**
 * Generate JSGF from SRGS document.  Call this after parsing SRGS document.
 * @param parser the parser
 * @return the JSGF document or NULL
 */
const char *srgs_to_jsgf(struct srgs_parser *parser)
{
	if (!parser) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "parser is NULL!\n");
		return NULL;
	}
	if (!parser->grammar) {
		switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_CRIT, "grammar is NULL!\n");
		return NULL;
	}
	if (!parser->grammar->jsgf && !create_jsgf(parser, parser->grammar->root, NULL)) {
		return NULL;
	}
	return parser->grammar->jsgf;
}

/**
 * Generate JSGF file from SRGS document.  Call this after parsing SRGS document.
 * @param parser the parser
 * @param basedir the base path to use if file does not already exist
 * @param ext the extension to use
 * @return the path or NULL
 */
const char *srgs_to_jsgf_file(struct srgs_parser *parser, const char *basedir, const char *ext)
{
	if (!parser) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "parser is NULL!\n");
		return NULL;
	}
	if (!parser->grammar) {
		switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_CRIT, "grammar is NULL!\n");
		return NULL;
	}
	if (!parser->grammar->jsgf_file_name) {
		char file_name_buf[SWITCH_UUID_FORMATTED_LENGTH + 1];
		switch_file_t *file;
		switch_size_t len;
		const char *jsgf = srgs_to_jsgf(parser);
                switch_uuid_str(file_name_buf, sizeof(file_name_buf));
		parser->grammar->jsgf_file_name = switch_core_sprintf(parser->pool, "%s%s%s.%s", basedir, SWITCH_PATH_SEPARATOR, file_name_buf, ext);
		if (!jsgf) {
			return NULL;
		}

		/* write grammar to file */
		if (switch_file_open(&file, parser->grammar->jsgf_file_name, SWITCH_FOPEN_WRITE | SWITCH_FOPEN_TRUNCATE | SWITCH_FOPEN_CREATE, SWITCH_FPROT_OS_DEFAULT, parser->pool) != SWITCH_STATUS_SUCCESS) {
			switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_WARNING, "Failed to create jsgf file: %s!\n", parser->grammar->jsgf_file_name);
			parser->grammar->jsgf_file_name = NULL;
			return NULL;
		}
		len = strlen(jsgf);
		switch_file_write(file, jsgf, &len);
		switch_file_close(file);
	}
	return parser->grammar->jsgf_file_name;
}

/* For Emacs:
 * Local Variables:
 * mode:c
 * indent-tabs-mode:t
 * tab-width:4
 * c-basic-offset:4
 * End:
 * For VIM:
 * vim:set softtabstop=4 shiftwidth=4 tabstop=4
 */
