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
 * iks_helpers.h -- iksemel constants and helpers
 *
 */
#ifndef IKS_EXT_H
#define IKS_EXT_H

#include <iksemel.h>
#include <switch.h>

/* See RFC-3920 XMPP core for error definitions */
#define STANZA_ERROR_BAD_REQUEST "bad-request", "modify"
#define STANZA_ERROR_CONFLICT "conflict", "cancel"
#define STANZA_ERROR_FEATURE_NOT_IMPLEMENTED "feature-not-implemented", "modify"
#define STANZA_ERROR_FORBIDDEN "forbidden", "auth"
#define STANZA_ERROR_GONE "gone", "modify"
#define STANZA_ERROR_INTERNAL_SERVER_ERROR "internal-server-error", "wait"
#define STANZA_ERROR_ITEM_NOT_FOUND "item-not-found", "cancel"
#define STANZA_ERROR_JID_MALFORMED "jid-malformed", "modify"
#define STANZA_ERROR_NOT_ACCEPTABLE "not-acceptable", "modify"
#define STANZA_ERROR_NOT_ALLOWED "not-allowed", "cancel"
#define STANZA_ERROR_NOT_AUTHORIZED "not-authorized", "auth"
#define STANZA_ERROR_RECIPIENT_UNAVAILABLE "recipient-unavailable", "wait"
#define STANZA_ERROR_REDIRECT "redirect", "modify"
#define STANZA_ERROR_REGISTRATION_REQUIRED "registration-required", "auth"
#define STANZA_ERROR_REMOTE_SERVER_NOT_FOUND "remote-server-not-found", "cancel"
#define STANZA_ERROR_REMOTE_SERVER_TIMEOUT "remote-server-timeout", "wait"
#define STANZA_ERROR_RESOURCE_CONSTRAINT "resource-constraint", "wait"
#define STANZA_ERROR_SERVICE_UNAVAILABLE "service-unavailable", "cancel"
#define STANZA_ERROR_UNDEFINED_CONDITION "undefined-condition", "wait"
#define STANZA_ERROR_UNEXPECTED_REQUEST "unexpected-request", "wait"

extern iks *iks_new_iq_error(iks *iq, const char *from, const char *to, const char *error_name, const char *error_type);
extern iks *iks_new_iq_result(const char *from, const char *to, const char *id);
extern char *iks_find_attrib_soft(iks *xml, const char *attrib);
extern const char *iks_node_type_to_string(int type);
extern const char *iks_net_error_to_string(int err);


/**
 * Type of attribute value
 */
enum iks_attrib_type {
	IAT_STRING = 0,
	IAT_INTEGER,
	IAT_DECIMAL
};

/**
 * An attribute in XML node
 */
struct iks_attrib {
	union {
		char *s;
		int i;
		double d;
	} v;
	enum iks_attrib_type type;
	const char *test;
};

/** A function to validate and convert string attrib */
typedef int (*iks_attrib_conversion_function)(struct iks_attrib *, const char *);

/**
 * Defines rules for attribute validation
 */
struct iks_attrib_definition {
	const char *name;
	const char *default_value;
	iks_attrib_conversion_function fn;
};


/**
 * Attributes to get
 */
struct iks_attribs {
	int size;
	struct iks_attrib attrib[];
};

#define LAST_ATTRIB { NULL, NULL, NULL }
#define EMPTY_ATTRIB(name, rule) { #name, "", iks_attrib_is_ ## rule }
#define ATTRIB(name, default_value, rule) { #name, #default_value, iks_attrib_is_ ## rule }
#define ATTRIB_RULE(rule) int iks_attrib_is_ ## rule (struct iks_attrib *attrib, const char *value)

extern ATTRIB_RULE(bool);
extern ATTRIB_RULE(not_negative);
extern ATTRIB_RULE(positive);
extern ATTRIB_RULE(positive_or_neg_one);
extern ATTRIB_RULE(any);
extern ATTRIB_RULE(decimal_between_zero_and_one);

extern int iks_attrib_parse(switch_core_session_t *session, iks *node, const struct iks_attrib_definition *attrib_def, struct iks_attribs *attribs);

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
