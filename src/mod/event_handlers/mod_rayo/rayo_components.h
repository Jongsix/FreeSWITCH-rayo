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
 * components.c -- Rayo component implementations
 *
 */
#ifndef RAYO_COMPONENTS_H
#define RAYO_COMPONENTS_H

#include <switch.h>
#include <iksemel.h>

#include "mod_rayo.h"

#define COMPONENT_COMPLETE_STOP "stop", "urn:xmpp:rayo:ext:complete:1"
#define COMPONENT_COMPLETE_ERROR "error", "urn:xmpp:rayo:ext:complete:1"
#define COMPONENT_COMPLETE_HANGUP "hangup", "urn:xmpp:rayo:ext:complete:1"

extern switch_status_t rayo_components_load(switch_loadable_module_interface_t **module_interface, switch_memory_pool_t *pool);
extern switch_status_t rayo_input_component_load(void);
extern switch_status_t rayo_output_component_load(void);
extern switch_status_t rayo_prompt_component_load(void);
extern switch_status_t rayo_record_component_load(void);

extern switch_status_t rayo_components_shutdown(void);
extern switch_status_t rayo_input_component_shutdown(void);
extern switch_status_t rayo_output_component_shutdown(void);
extern switch_status_t rayo_prompt_component_shutdown(void);
extern switch_status_t rayo_record_component_shutdown(void);

typedef void (* rayo_call_component_start_fn)(struct rayo_call *call, iks *iq);
typedef iks *(* rayo_call_component_stop_fn)(struct rayo_call *call, iks *iq);
extern void rayo_call_component_interface_add(const char *command, rayo_call_component_start_fn start, rayo_call_component_stop_fn stop);

extern const char *rayo_call_component_send_start(struct rayo_call *call, const char *request_id, const char *type);
extern void rayo_call_component_send_complete(struct rayo_call *call, const char *jid, const char *reason, const char *reason_namespace);
extern void rayo_call_component_send_iq_error(struct rayo_call *call, iks *iq, const char *error_name, const char *error_type);

#endif
