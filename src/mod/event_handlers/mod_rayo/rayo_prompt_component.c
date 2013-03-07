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
 * prompt_component.c -- Rayo prompt component implementation
 *
 */
#include "rayo_components.h"
#include "iks_helpers.h"

#if 0
/**
 * <prompt> component validation
 */
ELEMENT(RAYO_PROMPT)
	ATTRIB(barge-in, true, bool)
ELEMENT_END
#endif

/**
 * Initialize prompt component
 * @return SWITCH_STATUS_SUCCESS if successful
 */
switch_status_t rayo_prompt_component_load(void)
{
	return SWITCH_STATUS_SUCCESS;
}

/**
 * Shutdown prompt component
 * @return SWITCH_STATUS_SUCCESS if successful
 */
switch_status_t rayo_prompt_component_shutdown(void)
{
	return SWITCH_STATUS_SUCCESS;
}
