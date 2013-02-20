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
 * srgs.c -- Transforms SRGS into regex rules
 *
 */
#include <switch.h>
#include <iksemel.h>

#include "srgs.h"

/**
 * A rule to match
 */
struct srgs_rule {
	char *name;
	char *regex;
};

/**
 * The parser state
 */ 
struct srgs_parser {
	struct srgs_rule **rules;
	int num_rules;
};

/**
 * Create a new parser.  Call srgs_destroy() when done
 * @param parser the created parser
 */
struct srgs_parser *srgs_parser_new(void)
{
	return malloc(sizeof(struct srgs_parser));
}

/**
 * Parse the document into rules to match
 * @param parser the parser
 * @param document the document to parse
 */
int srgs_parse(struct srgs_parser *parser, const char *document)
{
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
	return MT_NOT_ENOUGH_INPUT;
}

/**
 * Destroy the parser
 */
void srgs_destroy(struct srgs_parser *parser)
{
	if (parser) {
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
