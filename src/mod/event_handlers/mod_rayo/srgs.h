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
 * srgs.h -- Transforms SRGS into regex rules
 *
 */
#ifndef SRGS_H
#define SRGS_H

#include <switch.h>

struct srgs_parser;

enum srgs_match_type {
	SMT_NO_MATCH,
	SMT_MATCH,
	SMT_TIMEOUT
};

extern struct srgs_parser *srgs_parser_new(switch_memory_pool_t *pool, const char *uuid);
extern void srgs_reset(struct srgs_parser *parser);
extern int srgs_parse(struct srgs_parser *parser, const char *document, int input_timeout_ms, int digit_timeout_ms);
extern enum srgs_match_type srgs_match(struct srgs_parser *parser, const char *input);

#endif

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
