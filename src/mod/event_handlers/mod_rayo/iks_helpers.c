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
 * iks_helpers.c -- iksemel helpers
 *
 */
#include "iks_helpers.h"
#include <switch.h>

/**
 * Create a <presence> event
 * @param name the event name
 * @param namespace the event namespace
 * @param from
 * @param to
 * @return the event XML node
 */
iks *iks_new_presence(const char *name, const char *namespace, const char *from, const char *to)
{
	iks *event = iks_new("presence");
	iks *x;
	/* iks makes copies of attrib name and value */
	iks_insert_attrib(event, "from", from);
	iks_insert_attrib(event, "to", to);
	x = iks_insert(event, name);
	if (!zstr(namespace)) {
		iks_insert_attrib(x, "xmlns", namespace);
	}
	return event;
}

/**
 * Create <iq> error response from <iq> request
 * @param iq the <iq> get/set request
 * @param from
 * @param to
 * @param error_name the XMPP stanza error
 * @param error_type
 * @return the <iq> error response
 */
iks *iks_new_iq_error(iks *iq, const char *error_name, const char *error_type)
{
	iks *response = iks_copy(iq);
	iks *x;

	/* <iq> */
	iks_insert_attrib(response, "from", iks_find_attrib(iq, "to"));
	iks_insert_attrib(response, "to", iks_find_attrib(iq, "from"));
	iks_insert_attrib(response, "type", "error");

	/* <error> */
	x = iks_insert(response, "error");
	iks_insert_attrib(x, "type", error_type);

	/* e.g. <feature-not-implemented> */
	x = iks_insert(x, error_name);
	iks_insert_attrib(x, "xmlns", IKS_NS_XMPP_STANZAS);

	return response;
}

/**
 * Create <iq> error response from <iq> request
 * @param iq the <iq> get/set request
 * @param from
 * @param to
 * @param error_name the XMPP stanza error
 * @param error_type
 * @param detail_text optional text to include in message
 * @return the <iq> error response
 */
iks *iks_new_iq_error_detailed(iks *iq, const char *error_name, const char *error_type, const char *detail_text)
{
	iks *reply = iks_new_iq_error(iq, error_name, error_type);
	if (!zstr(detail_text)) {
		iks *error = iks_find(reply, "error");
		iks *text = iks_insert(error, "text");
		iks_insert_attrib(text, "xml:lang", "en");
		iks_insert_attrib(text, "xmlns", IKS_NS_XMPP_STANZAS);
		iks_insert_cdata(text, detail_text, strlen(detail_text));
	}
	return reply;
}

/**
 * Create <iq> error response from <iq> request
 * @param iq the <iq> get/set request
 * @param from
 * @param to
 * @param error_name the XMPP stanza error
 * @param error_type
 * @param detail_text_format format string
 * @param ...
 * @return the <iq> error response
 */
iks *iks_new_iq_error_detailed_printf(iks *iq, const char *error_name, const char *error_type, const char *detail_text_format, ...)
{
	iks *reply = NULL;
	char *data;
	va_list ap;
	int ret;

	va_start(ap, detail_text_format);
	ret = switch_vasprintf(&data, detail_text_format, ap);
	va_end(ap);

	if (ret == -1) {
		return NULL;
	}
	reply = iks_new_iq_error_detailed(iq, error_name, error_type, data);
	free(data);
	return reply;
}

/**
 * Create <iq> result response from request
 * @param iq the request
 * @return the result response
 */
iks *iks_new_iq_result(iks *iq)
{
	iks *response = iks_new("iq");
	iks_insert_attrib(response, "from", iks_find_attrib(iq, "to"));
	iks_insert_attrib(response, "to", iks_find_attrib(iq, "from"));
	iks_insert_attrib(response, "type", "result");
	iks_insert_attrib(response, "id", iks_find_attrib(iq, "id"));
	return response;
}

/**
 * Get attribute value of node, returning empty string if non-existent or not set.
 * @param xml the XML node to search
 * @param attrib the Attribute name
 * @return the attribute value
 */
const char *iks_find_attrib_soft(iks *xml, const char *attrib)
{
	char *value = iks_find_attrib(xml, attrib);
	return zstr(value) ? "" : value;
}

/**
 * Get attribute value of node, returning default value if missing.  The default value
 * is set in the node if missing.
 * @param xml the XML node to search
 * @param attrib the Attribute name
 * @return the attribute value
 */
const char *iks_find_attrib_default(iks *xml, const char *attrib, const char *def)
{
	char *value = iks_find_attrib(xml, attrib);
	if (!value) {
		iks_insert_attrib(xml, attrib, def);
		return def;
	}
	return value;
}

/**
 * Get attribute integer value of node
 * @param xml the XML node to search
 * @param attrib the Attribute name
 * @return the attribute value
 */
int iks_find_int_attrib(iks *xml, const char *attrib)
{
	return atoi(iks_find_attrib_soft(xml, attrib));
}

/**
 * Get attribute boolean value of node
 * @param xml the XML node to search
 * @param attrib the Attribute name
 * @return the attribute value
 */
int iks_find_bool_attrib(iks *xml, const char *attrib)
{
	return switch_true(iks_find_attrib_soft(xml, attrib));
}

/**
 * Get attribute double value of node
 * @param xml the XML node to search
 * @param attrib the Attribute name
 * @return the attribute value
 */
double iks_find_decimal_attrib(iks *xml, const char *attrib)
{
	return atof(iks_find_attrib_soft(xml, attrib));
}

/**
 * Convert iksemel XML node type to string
 * @param type the XML node type
 * @return the string value of type or "UNKNOWN"
 */
const char *iks_node_type_to_string(int type)
{
	switch(type) {
		case IKS_NODE_START: return "NODE_START";
		case IKS_NODE_NORMAL: return "NODE_NORMAL";
		case IKS_NODE_ERROR: return "NODE_ERROR";
		case IKS_NODE_STOP: return "NODE_START";
		default: return "NODE_UNKNOWN";
	}
}

/**
 * Convert iksemel error code to string
 * @param err the iksemel error code
 * @return the string value of error or "UNKNOWN"
 */
const char *iks_net_error_to_string(int err)
{
	switch (err) {
		case IKS_OK: return "OK";
		case IKS_NOMEM: return "NOMEM";
		case IKS_BADXML: return "BADXML";
		case IKS_HOOK: return "HOOK";
		case IKS_NET_NODNS: return "NET_NODNS";
		case IKS_NET_NOSOCK: return "NET_NOSOCK";
		case IKS_NET_NOCONN: return "NET_NOCONN";
		case IKS_NET_RWERR: return "NET_RWERR";
		case IKS_NET_NOTSUPP: return "NET_NOTSUPP";
		case IKS_NET_TLSFAIL: return "NET_TLSFAIL";
		case IKS_NET_DROPPED: return "NET_DROPPED";
		case IKS_NET_UNKNOWN: return "NET_UNKNOWN";
		default: return "UNKNOWN";
	}
}

/**
 * Insert attribute using format string
 * @param xml node to insert attribute into
 * @param name of attribute
 * @param fmt format string
 * @param ... format string args
 */
iks *iks_insert_attrib_printf(iks *xml, const char *name, const char *fmt, ...)
{
	iks *node;
	char *data;
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = switch_vasprintf(&data, fmt, ap);
	va_end(ap);

	if (ret == -1) {
		return NULL;
	}
	node = iks_insert_attrib(xml, name, data);
	free(data);

	return node;
}

/**
 * Validate boolean
 * @param value
 * @return SWTICH_TRUE if boolean
 */
int iks_attrib_is_bool(const char *value)
{
	if (!zstr(value) && (!strcasecmp("true", value) || !strcasecmp("false", value))) {
		return SWITCH_TRUE;
	}
	return SWITCH_FALSE;
}

/**
 * Validate integer
 * @param value
 * @return SWTICH_TRUE if not negative
 */
int iks_attrib_is_not_negative(const char *value)
{
	if (!zstr(value) && switch_is_number(value)) {
		int value_i = atoi(value);
		if (value_i >= 0) {
			return SWITCH_TRUE;
		}
	}
	return SWITCH_FALSE;
}

/**
 * Validate integer
 * @param value
 * @return SWTICH_TRUE if positive
 */
int iks_attrib_is_positive(const char *value)
{
	if (!zstr(value) && switch_is_number(value)) {
		int value_i = atoi(value);
		if (value_i > 0) {
			return SWITCH_TRUE;
		}
	}
	return SWITCH_FALSE;
}

/**
 * Validate integer
 * @param value
 * @return SWTICH_TRUE if positive or -1
 */
int iks_attrib_is_positive_or_neg_one(const char *value)
{
	if (!zstr(value) && switch_is_number(value)) {
		int value_i = atoi(value);
		if (value_i == -1 || value_i > 0) {
			return SWITCH_TRUE;
		}
	}
	return SWITCH_FALSE;
}

/**
 * Validate string
 * @param value
 * @return SWTICH_TRUE
 */
int iks_attrib_is_any(const char *value)
{
	return SWITCH_TRUE;
}

/**
 * Validate decimal
 * @param value
 * @return SWTICH_TRUE if 0.0 <= x <= 1.0
 */
int iks_attrib_is_decimal_between_zero_and_one(const char *value)
{
	if (!zstr(value) && switch_is_number(value)) {
		double value_d = atof(value);
		if (value_d >= 0.0 || value_d <= 1.0) {
			return SWITCH_TRUE;
		}
	}
	return SWITCH_FALSE;
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
