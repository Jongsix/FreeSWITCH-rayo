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
 * mod_rayo.h -- Rayo server / node implementation.  Allows MxN clustering of FreeSWITCH and Rayo Clients (like Adhearsion)
 *
 */
#ifndef MOD_RAYO_H
#define MOD_RAYO_H

#include <switch.h>


#define RAYO_EVENT_XMPP_SEND "rayo::xmpp_send"
#define RAYO_EVENT_OFFER "rayo::offer"

#define RAYO_CAUSE_HANGUP "NORMAL_CLEARING"
#define RAYO_CAUSE_DECLINE "CALL_REJECTED"
#define RAYO_CAUSE_BUSY "USER_BUSY"
#define RAYO_CAUSE_ERROR "TEMPORARY_FAILURE"

/**
 * A call controlled by Rayo
 */
struct rayo_call {
	/** The session this call belongs to */
	switch_core_session_t *session;
	/** The call JID */
	char *jid;
	/** Definitive controlling party JID */
	char *dcp_jid;
	/** Potential controlling parties */
	switch_hash_t *pcps;
	/** synchronizes access to this call */
	switch_mutex_t *mutex;
	/** input component JID */
	char *input_jid;
	/** output component JID */
	char *output_jid;
};

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
