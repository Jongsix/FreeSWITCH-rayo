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
	/** The SAX parser */
	iksparser *p;
	/** The document root */
	struct srgs_node *root;
	/** current node being parsed */
	struct srgs_node *cur;
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
 * @param type of node
 * @return the node
 */
static struct srgs_node *sn_new(enum srgs_node_type type)
{
	struct srgs_node *node = malloc(sizeof(*node));
	memset(node, 0, sizeof(*node));
	node->type = type;
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
 * @param parent node to add child to
 * @param type the child node type
 * @return the child node
 */
static struct srgs_node *sn_insert(struct srgs_node *parent, enum srgs_node_type type)
{
	struct srgs_node *sibling = sn_find_last_sibling(parent->child);
	struct srgs_node *child = sn_new(type);
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
 * @param parent node to add digit to
 * @return the digit child node
 */
static struct srgs_node *sn_insert_digit(struct srgs_node *parent, char digit)
{
	struct srgs_node *child = sn_insert(parent, SNT_DIGIT);
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

/**
 * Delete tree
 * @param node the root node
 */
static void sn_delete(struct srgs_node *node)
{
	if (node) {
		if (node->child) {
			sn_delete(node->child);
			node->child = NULL;
		}
		if (node->next) {
			sn_delete(node->next);
			node->next = NULL;
		}
		switch (node->type) {
			case SNT_RULE:
				if (node->value.rule.id) {
					free(node->value.rule.id);
					node->value.rule.id = NULL;
				}
				break;
			case SNT_UNRESOLVED_REF:
				if (node->value.ref.uri) {
					free(node->value.ref.uri);
					node->value.ref.uri = NULL;
				}
				break;
			default:
				break;
		}
		free(node);
	}
}

/**
 * Check <rule> for match against input
 * @param rule to match
 * @param input to match
 * @return MATCH, NO_MATCH, NOT_ENOUGH_INPUT
 */
static enum match_type sn_match(struct srgs_node *node, const char *input)
{
	if (!node) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "NULL node\n");
		return MT_NO_MATCH;
	}
	if (!*input) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "End of input\n");
		return MT_NOT_ENOUGH_INPUT;
	}
	
	switch (node->type) {
		case SNT_ONE_OF: {
			struct srgs_node *item;
			enum match_type match = MT_NO_MATCH;
			
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "match <one-of> %s\n", input);
			
			/* check for matches in items... this is an OR operation */
			for (item = node->child; item && !(match & MT_MATCH); item = item->next) {
				/* detects partial (0x2) and full matches (0x1) */
				match |= sn_match(item, input);
			}
			if (match & MT_MATCH) {
				return MT_MATCH;
			}
			return match;
		}
		case SNT_RULE:
		case SNT_ITEM: {
			struct srgs_node *child;
			enum match_type match = MT_MATCH;
			
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "match <%s> %s\n", node_type_to_string(node->type), input);
			
			/* check for matches in items... this is an AND operation */
			for (child = node->child; child && match == MT_MATCH; child = child->next) {
				match = sn_match(child, input);
			}
			return match;
		}
		case SNT_DIGIT: {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "compare digits (input) %c == (node) %c\n", *input, node->value.digit);
			if (node->value.digit != *input) {
				return MT_NO_MATCH;
			}
			if (node->child) {
				return sn_match(node->child, input + 1);
			}
			return MT_MATCH;
		}
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
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "<rule scope=\'%s\'>  is_public = %i\n", atts[i + 1], rule->value.rule.is_public);
			} else if (!strcmp("id", atts[i])) {
				if (!zstr(atts[i + 1])) {
					rule->value.rule.id = strdup(atts[i + 1]);
				}
			}
			i += 2;
		}
	}
	if (zstr(rule->value.rule.id)) {
		return IKS_BADXML;
	}
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
				if (uri[0] != '#') {
					return IKS_BADXML;
				}
				ruleref->value.ref.uri = strdup(uri);
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
	item->value.item.repeat_min = 1; // min
	item->value.item.repeat_max = 1; // max
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
					item->value.item.repeat_min = repeat_val;
					return IKS_OK;
				} else {
					/* TODO support range */
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
			parser->cur = sn_insert(parser->cur, ntype);
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
					digit = sn_insert_digit(digit, data[i]);
				}
			}
		}
	}
	return IKS_OK;
}

/**
 * Create a new parser.  Call srgs_destroy() when done
 * @param parser the created parser
 */
struct srgs_parser *srgs_parser_new(void)
{
	struct srgs_parser *parser = malloc(sizeof(struct srgs_parser));
	memset(parser, 0, sizeof(*parser));
	parser->p = iks_sax_new(parser, tag_hook, cdata_hook);
	return parser;
}

/**
 * Resolve all unresolved references
 */
int resolve_refs(struct srgs_parser *parser)
{
	/* TODO */
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
		return 0;
	}

	iks_parser_reset(parser->p);
	if (parser->root) {
		sn_delete(parser->root);
	}
	parser->root = sn_new(SNT_ROOT);
	parser->cur = parser->root;
	if (iks_parse(parser->p, document, 0, 1) != IKS_OK) {
		return 0;
	}
	
	return resolve_refs(parser);
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
				/* detects partial (0x2) and full matches (0x1) */
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Testing rule: %s = %s\n", input, rule->value.rule.id);
				match |= sn_match(rule, input);
			}
		}
		if (match & MT_MATCH) {
			/* return match */
			return MT_MATCH;
		}
	}
	return match;
}

/**
 * Destroy the parser
 */
void srgs_destroy(struct srgs_parser *parser)
{
	if (parser) {
		if (parser->root) {
			sn_delete(parser->root);
			parser->root = NULL;
			parser->cur = NULL;
		}
		if (parser->p) {
			iks_parser_delete(parser->p);
		}
		free(parser);
	}
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
