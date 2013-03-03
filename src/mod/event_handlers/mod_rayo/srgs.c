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
 * srgs.c -- Parses SRGS "dtmf" mode grammar and performs matches against digit strings
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
	/** <item> digit */
	SNT_DIGIT
};

/**
 * <grammar> value
 */
struct root_value {
	char *regex;
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
		struct root_value root;
		char digit;
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
 * The SRGS SAX parser
 */
struct srgs_parser {
	/** parser memory pool */
	switch_memory_pool_t *pool;
	/** The document root */
	struct srgs_node *root;
	/** current node being parsed */
	struct srgs_node *cur;
	/** grammar cache */
	switch_hash_t *cache;
	/** rule names mapped to node */
	switch_hash_t *rules;
	/** optional uuid for logging */
	const char *uuid;
	/** compiled grammar regex */
	pcre *compiled_regex;
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
		case SNT_DIGIT: return "digit";
		case SNT_UNKNOWN: return "UNKOWN";
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
		case SNT_DIGIT:
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG1, "%c\n", node->value.digit);
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
		case SNT_DIGIT:
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
 * Add digit child node
 * @param pool to use
 * @param parent node to add digit to
 * @return the digit child node
 */
static struct srgs_node *sn_insert_digit(switch_memory_pool_t *pool, struct srgs_node *parent, char digit)
{
	struct srgs_node *child = sn_insert(pool, parent, SNT_DIGIT);
	child->value.digit = digit;
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
					return IKS_BADXML;
				}
				/* only allow local reference */
				if (uri[0] != '#' || strlen(uri) < 2) {
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
	if (atts) {
		int i = 0;
		while (atts[i]) {
			if (!strcmp("repeat", atts[i])) {
				char *repeat = atts[i + 1];
				if (zstr(repeat)) {
					return IKS_BADXML;
				}
				if (switch_is_number(repeat)) {
					int repeat_val = atoi(repeat);
					if (repeat_val < 1) {
						return IKS_BADXML;
					}
					item->value.item.repeat_min = repeat_val;
					item->value.item.repeat_max = repeat_val;
					return IKS_OK;
				} else {
					/* TODO support repeat range */
					return IKS_BADXML;
				}
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

	/* grammar only allowed at root */
	if (ntype == SNT_ROOT) {
		if (parser->cur->type != SNT_ROOT) {
			return IKS_BADXML;
		}
		return IKS_OK;
	}
	if (ntype == SNT_UNKNOWN) {
		return IKS_BADXML;
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
		if (parser->cur->type == SNT_ITEM) {
			struct srgs_node *digit = parser->cur;
			int i;
			for (i = 0; i < len; i++) {
				if (isdigit(data[i]) || data[i] == '#' || data[i] == '*') {
					digit = sn_insert_digit(parser->pool, digit, data[i]);
					sn_log_node_open(digit);
				}
			}
		}
	}
	return IKS_OK;
}

/**
 * Create a new parser.
 * @param pool the pool to use
 * @param uuid optional uuid for logging
 * @return the created parser
 */
struct srgs_parser *srgs_parser_new(switch_memory_pool_t *pool, const char *uuid)
{
	struct srgs_parser *parser = NULL;
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
 * Compile regex
 */
static int compile_regex(struct srgs_parser *parser)
{
	int erroffset = 0;
	const char *errptr = "";
	int options = 0;
	const char *regex = parser->root->value.root.regex;

	/* compile regex */
	parser->compiled_regex = pcre_compile(regex, options, &errptr, &erroffset, NULL);
	if (!parser->compiled_regex) {
		switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_WARNING, "Failed to compile grammar regex: %s\n", regex);
		return 0;
	}
	return 1;
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
				node->value.root.regex = switch_core_strdup(parser->pool, new_stream.data);
				switch_safe_free(new_stream.data);
				switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_DEBUG, "document regex = %s\n", node->value.root.regex);
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
		case SNT_DIGIT:
			if (node->value.digit == '*') {
				stream->write_function(stream, "\\*");
			} else {
				stream->write_function(stream, "%c", node->value.digit);
			}
			if (node->child) {
				if (!create_regexes(parser, node->child, stream)) {
					return 0;
				}
			}
			break;
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
						stream->write_function(stream, "){%i,%i}", node->value.item.repeat_min, node->value.item.repeat_max);
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
		default:
			switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_DEBUG, "create_regexes() bad type = %s\n", node_type_to_string(node->type));
			return 0;
	}
	sn_log_node_close(node);
	return 1;
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
	pcre *compiled_regex = NULL;
	if (!parser) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT, "NULL parser!!\n");
		return 0;
	}

	if (zstr(document)) {
		switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_INFO, "Missing grammar document\n");
		return 0;
	}

	/* check for cached grammar */
	compiled_regex = (pcre *)switch_core_hash_find(parser->cache, document);
	if (!compiled_regex) {
		int result = 0;
		iksparser *p = iks_sax_new(parser, tag_hook, cdata_hook);
		switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_DEBUG, "Parsing new grammar\n");
		parser->root = sn_new(parser->pool, SNT_ROOT);
		parser->cur = parser->root;
		switch_core_hash_delete_multi(parser->rules, NULL, NULL);
		if (iks_parse(p, document, 0, 1) == IKS_OK) {
			switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_DEBUG, "Resolving references\n");
			if (resolve_refs(parser, parser->root, 0)) {
				switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_DEBUG, "Creating rule regexes\n");
				if (create_regexes(parser, parser->root, NULL)) {
					switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_DEBUG, "Compile regex\n");
					if (compile_regex(parser)) {
						result = 1;
					}
				}
			}
		}
		iks_parser_delete(p);
		if (result) {
			switch_core_hash_insert(parser->cache, document, parser->compiled_regex);
		} else {
			switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_INFO, "Failed to parse grammar\n");
			return 0;
		}
	} else {
		switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_DEBUG, "Using cached grammar\n");
		parser->compiled_regex = compiled_regex;
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
	result = pcre_dfa_exec(parser->compiled_regex, NULL, input, strlen(input), 0, PCRE_PARTIAL,
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
