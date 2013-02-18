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
 * Create <iq> error response from <iq> request
 * @param iq the <iq> get/set request
 * @param from
 * @param to
 * @param error_name the XMPP stanza error
 * @param error_type
 * @return the <iq> error response
 */
iks *iks_new_iq_error(iks *iq, const char *from, const char *to, const char *error_name, const char *error_type)
{
	iks *response = iks_copy(iq);
	iks *x;

	/* <iq> */
	iks_insert_attrib(response, "from", from);
	iks_insert_attrib(response, "to", to);
	iks_insert_attrib(response, "type", "error");

	/* <error> */
	x = iks_insert(response, "error");
	iks_insert_attrib(x, "type", error_type);

	/* e.g. <feature-not-implemented> */
	x = iks_insert(x, error_name);
	iks_insert_attrib(x, "xmlns", "urn:ietf:params:xml:ns:xmpp-stanzas");

	return response;
}

/**
 * Create <iq> result response
 * @param from
 * @param to
 * @param id
 * @return the result response
 */
iks *iks_new_iq_result(const char *from, const char *to, const char *id)
{
	iks *response = iks_new("iq");
	iks_insert_attrib(response, "from", from);
	iks_insert_attrib(response, "to", to);
	iks_insert_attrib(response, "type", "result");
	iks_insert_attrib(response, "id", id);
	return response;
}


/**
 * Get attribute value of node, returning empty string if non-existent or not set.
 * @param xml the XML node to search
 * @param attrib the Attribute name
 * @return the attribute value
 */
char *iks_find_attrib_soft(iks *xml, const char *attrib)
{
	char *value = iks_find_attrib(xml, attrib);
	return zstr(value) ? "" : value;
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
