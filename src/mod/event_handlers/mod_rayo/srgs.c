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

struct rule_value {
	char is_public;
	char *id;
};

struct item_value {
	int repeat_min;
	int repeat_max;
};

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
 * Print parsed tree to stdout
 * @param node the root node
 */
void sn_output(struct srgs_node *node) {
	if (node) {
		if (node->type != SNT_DIGIT) {
			printf("<%s>", node_type_to_string(node->type));
		} else {
			printf("%c", node->value.digit);
		}
		if (node->child) {
			sn_output(node->child);
		}
		if (node->type != SNT_DIGIT) {
			printf("</%s>", node_type_to_string(node->type));
		}
		if (node->next) {
			sn_output(node->next);
		}
	}
}


static enum match_type sn_match(struct srgs_node *node, const char *input, int *index, int level);

/**
 * Check <one-of> for match against input
 * @param one-of to match
 * @param input to match
 * @param index number of digits compared
 * @param level recursion level
 * @return NO_MATCH, MATCH_PARTIAL, MATCH_LAZY, MATCH
 */
static enum match_type sn_match_one_of(struct srgs_node *node, const char *input, int *index, int level)
{
	struct srgs_node *item;
	enum match_type match = MT_NO_MATCH;
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "match <one-of> %s\n", input);

	/* check for matches in items... this is an OR operation */
	for (item = node->child; item && !(match & MT_MATCH); item = item->next) {
		int num_matched = *index;
		match |= sn_match(item, input, &num_matched, level + 1);
	}
	return match;
}

/**
 * Check <item> for match against input
 * @param item to match
 * @param input to match
 * @param index number of digits compared
 * @param level recursion level
 * @return NO_MATCH, MATCH_PARTIAL, MATCH_LAZY, MATCH
 */
static enum match_type sn_match_item(struct srgs_node *node, const char *input, int *index, int level)
{
	/* TODO min/max repeat */
//	int i;
//	int lazy_match = 0;
	struct srgs_node *child;
	enum match_type match = MT_MATCH;

//	for (i = 0; i < node->value.item.repeat_max; i++) {
		//switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "match #%i <%s> %s\n", i, node_type_to_string(node->type), input);

		/* check for matches in items... this is an AND operation */
		for (child = node->child; child && match == MT_MATCH; child = child->next) {
			match = sn_match(child, input, index, level + 1);
		}
//	}
	return match;
}

/**
 * Check <rule> for match against input
 * @param rule to match
 * @param input to match
 * @param index number of digits compared
 * @param level recursion level
 * @return NO_MATCH, MATCH_PARTIAL, MATCH_LAZY, MATCH
 */
static enum match_type sn_match_rule(struct srgs_node *node, const char *input, int *index, int level)
{
	struct srgs_node *child;
	enum match_type match = MT_MATCH;

	/* check for matches in items... this is an AND operation */
	for (child = node->child; child && match == MT_MATCH; child = child->next) {
		match = sn_match(child, input, index, level + 1);
	}
	return match;
}

/**
 * Check digit for match against input
 * @param rule to match
 * @param input to match
 * @param index number of digits compared
 * @param level recursion level
 * @return NO_MATCH, MATCH_PARTIAL, MATCH_LAZY, MATCH
 */
static enum match_type sn_match_digit(struct srgs_node *node, const char *input, int *index, int level)
{
	if (!*input) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "End of input\n");
		return MT_MATCH_PARTIAL;
	}

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "compare digits (input) %c == (node) %c\n", *input, node->value.digit);
	if (node->value.digit != *input) {
		return MT_NO_MATCH;
	}

	/* have more digits to match */
	if (node->child) {
		return sn_match(node->child, input, index, level + 1);
	}

	/* reached last digit and matched entire string */
	if (*index + 1 == strlen(input)) {
		return MT_MATCH;
	}

	/* still more input digits to match */
	return MT_MATCH_PARTIAL;
}

/**
 * Check for match against input
 * @param rule to match
 * @param input to match
 * @param index number of digits compared
 * @param level recursion level
 * @return NO_MATCH, MATCH_PARTIAL, MATCH_LAZY, MATCH
 */
static enum match_type sn_match(struct srgs_node *node, const char *input, int *index, int level)
{
	if (!node) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "NULL node\n");
		return MT_NO_MATCH;
	}

	if (level > MAX_RECURSION) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Match recursion too deep!\n");
		return MT_NO_MATCH;
	}

	switch (node->type) {
		case SNT_ONE_OF:
			return sn_match_one_of(node, input, index, level);
		case SNT_RULE:
			return sn_match_rule(node, input, index, level);
		case SNT_ITEM:
			return sn_match_item(node, input, index, level);
		case SNT_DIGIT:
			return sn_match_digit(node, input, index, level);
		default:
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "unsuppored match <%s> %s\n", node_type_to_string(node->type), input);
			break;
	}
	return MT_NO_MATCH;
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
				switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_DEBUG, "<rule scope=\'%s\'>  is_public = %i\n", atts[i + 1], rule->value.rule.is_public);
			} else if (!strcmp("id", atts[i])) {
				if (!zstr(atts[i + 1])) {
					switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_DEBUG, "<rule id=\'%s\'>\n", atts[i + 1]);
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
				switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_DEBUG, "<ruleref uri=\'%s\'>\n", uri);
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
				switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_DEBUG, "<item repeat=\"%s\">\n", repeat);
				if (zstr(repeat)) {
					return IKS_BADXML;
				}
				if (switch_is_number(repeat)) {
					int repeat_val = atoi(repeat);
					if (repeat_val < 1) {
						return IKS_BADXML;
					}
					item->value.item.repeat_min = repeat_val;
					item->value.item.repeat_min = repeat_val;
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
			//switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "PUSH <%s> <- <%s>\n", node_type_to_string(parser->cur->type), name);
			parser->cur = sn_insert(parser->pool, parser->cur, ntype);
			if (ntype == SNT_UNRESOLVED_REF) {
				return process_ruleref(parser, atts);
			} else if (ntype == SNT_ITEM) {
				return process_item(parser, atts);
			} else if (ntype == SNT_RULE) {
				return process_rule(parser, atts);
			}
			break;
		}
		case IKS_CLOSE: {
			//switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "POP <%s> <- <%s>\n", node_type_to_string(parser->cur->type), name);
			parser->cur = parser->cur->parent;
			break;
		}
		case IKS_SINGLE:
			break;
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
					//switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "<%s> Add digit %c\n", node_type_to_string(parser->cur->type), data[i]);
					digit = sn_insert_digit(parser->pool, digit, data[i]);
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
	struct srgs_parser *parser = switch_core_alloc(pool, sizeof(*parser));
	parser->pool = pool;
	parser->uuid = zstr(uuid) ? "" : uuid;
	switch_core_hash_init(&parser->cache, pool);
	switch_core_hash_init(&parser->rules, pool);
	return parser;
}

/**
 * Resolve all unresolved references and detect loops.
 * @param parser the parser
 * @param node the current node
 * @param level the recursion level
 */
int resolve_refs(struct srgs_parser *parser, struct srgs_node *node, int level)
{
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
		if (!resolve_refs(parser, node->child, level + 1)) {
			return 0;
		}
	}

	/* resolve sibling refs */
	if (node->next) {
		if (!resolve_refs(parser, node->next, level)) {
			return 0;
		}
	}

	node->visited = 0;
	return 1;
}

/**
 * Parse the document into rules to match
 * @param parser the parser
 * @param document the document to parse
 */
int srgs_parse(struct srgs_parser *parser, const char *document)
{
	if (zstr(document)) {
		switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_INFO, "Missing grammar document\n");
		return 0;
	}

	/* check for cached grammar */
	parser->root = (struct srgs_node *)switch_core_hash_find(parser->cache, document);
	if (!parser->root) {
		int result = 0;
		iksparser *p = iks_sax_new(parser, tag_hook, cdata_hook);
		switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_DEBUG, "Parsing new grammar\n");
		parser->root = sn_new(parser->pool, SNT_ROOT);
		parser->cur = parser->root;
		switch_core_hash_delete_multi(parser->rules, NULL, NULL);
		result = (iks_parse(p, document, 0, 1) == IKS_OK && resolve_refs(parser, parser->root, 0));
		iks_parser_delete(p);
		if (result) {
			switch_core_hash_insert(parser->cache, document, parser->root);
		}
		return result;
	} else {
		switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_DEBUG, "Using cached grammar\n");
	}
	return 1;
}

/**
 * Find a match
 * @param parser the parser
 * @param input the input to compare
 * @return the match result
 */
enum match_type srgs_match(struct srgs_parser *parser, const char *input)
{
	int match = MT_NO_MATCH;

	if (parser->root) {
		struct srgs_node *rule;
		for (rule = parser->root->child; rule && !(match & MT_MATCH); rule = rule->next) {
			if (rule->type == SNT_RULE && rule->value.rule.is_public) {
				int index = 0;
				switch_log_printf(SWITCH_CHANNEL_UUID_LOG(parser->uuid), SWITCH_LOG_DEBUG, "Testing rule: %s = %s\n", input, rule->value.rule.id);
				match |= sn_match(rule, input, &index, 0);
			}
		}
		if (match & MT_MATCH) {
			/* return match */
			return MT_MATCH;
		}
	}
	return match;
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
