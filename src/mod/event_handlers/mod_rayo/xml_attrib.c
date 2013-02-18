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
 * xml_attrib.c -- XML attribute validation functions
 *
 */
#include <switch.h>
#include "xml_attrib.h"

/**
 * Assign value to attribute if boolean
 * @param attrib to assign to
 * @param value assigned
 * @return SWTICH_TRUE if value is valid
 */
switch_bool_t xml_attrib_is_bool(struct xml_attrib *attrib, const char *value) {
	attrib->type = XAT_INTEGER;
	attrib->test = "(true || false)";
	if (!zstr(value) && (!strcasecmp("true", value) || !strcasecmp("false", value))) {
		attrib->v.i = switch_true(value);
		return SWITCH_TRUE;
	}
	return SWITCH_FALSE;
}

/**
 * Assign value to attribute if not negative
 * @param attrib to assign to
 * @param value assigned
 * @return SWTICH_TRUE if value is valid
 */
switch_bool_t xml_attrib_is_not_negative(struct xml_attrib *attrib, const char *value) {
	attrib->type = XAT_INTEGER;
	attrib->test = "(>= 0)";
	if (!zstr(value) && switch_is_number(value)) {
		attrib->v.i = atoi(value);
		if (attrib->v.i >= 0) {
			return SWITCH_TRUE;
		}
	}
	return SWITCH_FALSE;
}

/**
 * Assign value to attribute if positive
 * @param attrib to assign to
 * @param value assigned
 * @return SWTICH_TRUE if value is valid
 */
switch_bool_t xml_attrib_is_positive(struct xml_attrib *attrib, const char *value) {
	attrib->type = XAT_INTEGER;
	attrib->test = "(> 0)";
	if (!zstr(value) && switch_is_number(value)) {
		attrib->v.i = atoi(value);
		if (attrib->v.i > 0) {
			return SWITCH_TRUE;
		}
	}
	return SWITCH_FALSE;
}

/**
 * Assign value to attribute if positive or -1
 * @param attrib to assign to
 * @param value assigned
 * @return SWTICH_TRUE if value is valid
 */
switch_bool_t xml_attrib_is_positive_or_neg_one(struct xml_attrib *attrib, const char *value) {
	attrib->type = XAT_INTEGER;
	attrib->test = "(-1 || > 0)";
	if (!zstr(value) && switch_is_number(value)) {
		attrib->v.i = atoi(value);
		if (attrib->v.i == -1 || attrib->v.i > 0) {
			return SWITCH_TRUE;
		}
	}
	return SWITCH_FALSE;
}

/**
 * Assign value to attribute
 * @param attrib to assign to
 * @param value assigned
 * @return SWTICH_TRUE if value is valid
 */
switch_bool_t xml_attrib_is_any(struct xml_attrib *attrib, const char *value) {
	attrib->type = XAT_STRING;
	attrib->test = "(*)";
	attrib->v.s = (char *)value;
	return SWITCH_TRUE;
}

/**
 * Assign value to attribute if 0.0 <= x <= 1.0
 * @param attrib to assign to
 * @param value assigned
 * @return SWTICH_TRUE if value is valid
 */
switch_bool_t xml_attrib_is_decimal_between_zero_and_one(struct xml_attrib *attrib, const char *value) {
	attrib->type = XAT_DECIMAL;
	attrib->test = "(>= 0.0 && <= 1.0)";
	if (!zstr(value) && switch_is_number(value)) {
		attrib->v.d = atof(value);
		if (attrib->v.d >= 0.0 || attrib->v.d <= 1.0) {
			return SWITCH_TRUE;
		}
	}
	return SWITCH_FALSE;
}

/**
 * Search node for attribute, returning default if not set
 * @param attrib_def the attribute validation definition
 * @param attrib the attribute to set
 * @param node XML node to search
 * @return SWITCH_TRUE if successful
 */
static switch_bool_t get_attrib(const struct xml_attrib_definition *attrib_def, struct xml_attrib *attrib, switch_xml_t node)
{
	const char *value = switch_xml_attr(node, attrib_def->name);
	value = zstr(value) ? attrib_def->default_value : value;
	if (attrib_def->fn(attrib, value)) {
		return SWITCH_TRUE;
	}
	attrib->type = XAT_STRING;
	attrib->v.s = (char *)value; /* remember bad value */
	return SWITCH_FALSE;
}

/**
 * Get attribs from XML node
 * @param session the session getting the attribs
 * @param node the XML node to search
 * @param attrib_def the attributes to get
 * @param attribs struct to fill
 * @return SWITCH_TRUE if the attribs are valid
 */
switch_bool_t xml_attrib_parse(switch_core_session_t *session, switch_xml_t node, const struct xml_attrib_definition *attrib_def, struct xml_attribs *attribs)
{
	struct xml_attrib *attrib = attribs->attrib;
	switch_bool_t success = SWITCH_TRUE;
	for (; success && !attrib_def->is_last; attrib_def++) {
		success &= get_attrib(attrib_def, attrib, node);
		if (!success) {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "FAILED: <%s %s='%s'> !%s\n", switch_xml_name(node), attrib_def->name, attrib->v.s, attrib->test);
		}
		attrib++;
	}
	return success;
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
