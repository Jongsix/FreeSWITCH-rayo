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
 * xml_attrib.h -- XML attribute validation
 *
 */
#ifndef XML_ATTRIB_H
#define XML_ATTRIB_H

/**
 * Type of attribute value
 */
enum xml_attrib_type {
	XAT_STRING = 0,
	XAT_INTEGER,
	XAT_DECIMAL
};

/**
 * An attribute in XML node
 */
struct xml_attrib {
	union {
		char *s;
		int i;
		double d;
	} v;
	enum xml_attrib_type type;
	const char *test;
};

/** A function to validate and convert string attrib */
typedef switch_bool_t (*xml_attrib_conversion_function)(struct xml_attrib *, const char *);

/**
 * Defines rules for attribute validation
 */
struct xml_attrib_definition {
	const char *name;
	const char *default_value;
	xml_attrib_conversion_function fn;
	int is_last;
};

#define LAST_ATTRIB { NULL, NULL, NULL, SWITCH_TRUE }

/**
 * Attributes to get
 */
struct xml_attribs {
	int size;
	struct xml_attrib attrib[];
};


extern switch_bool_t xml_attrib_is_bool(struct xml_attrib *attrib, const char *value);
extern switch_bool_t xml_attrib_is_not_negative(struct xml_attrib *attrib, const char *value);
extern switch_bool_t xml_attrib_is_positive(struct xml_attrib *attrib, const char *value);
extern switch_bool_t xml_attrib_is_positive(struct xml_attrib *attrib, const char *value);
extern switch_bool_t xml_attrib_is_positive_or_neg_one(struct xml_attrib *attrib, const char *value);
extern switch_bool_t xml_attrib_is_any(struct xml_attrib *attrib, const char *value);
extern switch_bool_t xml_attrib_is_decimal_between_zero_and_one(struct xml_attrib *attrib, const char *value);
extern switch_bool_t xml_attrib_parse(switch_core_session_t *session, switch_xml_t node, const struct xml_attrib_definition *attrib_def, struct xml_attribs *attribs);


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

