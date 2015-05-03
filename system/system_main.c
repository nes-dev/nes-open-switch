/*
 *  Copyright (c) 2008-2015
 *      NES <nes.open.switch@gmail.com>
 *
 *  All rights reserved. This source file is the sole property of NES, and
 *  contain proprietary and confidential information related to NES.
 *
 *  Licensed under the NES RED License, Version 1.0 (the "License"); you may
 *  not use this file except in compliance with the License. You may obtain a
 *  copy of the License bundled along with this file. Any kind of reproduction
 *  or duplication of any part of this file which conflicts with the License
 *  without prior written consent from NES is strictly prohibited.
 *
 *  Unless required by applicable law and agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *  License for the specific language governing permissions and limitations
 *  under the License.
 */
//set ts=4 sw=4

#ifndef __SYSTEM_MAIN_C__
#	define __SYSTEM_MAIN_C__


#include "systemMIB.h"
#include "entityMIB_agent.h"

#include "system_ext.h"
#include "system_defines.h"
#include "switch_ext.h"

#include "lib/freeRange.h"
#include "lib/thread.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>


static xThreadInfo_t oSystemThread =
{
	.u32Index = XTHREAD_ID (ModuleId_system_c, 0),
	.u8SchedPolicy = SCHED_RR,
	.u8Priority = 1,
	.poStart = &system_start,
};


void *
system_init (
	void *pvArgv)
{
	xFreeRange_createRange (&oSysORIndex_FreeRange, sysORIndex_start_c, sysORIndex_end_c);
	
	oSystem.u16Descr_len = strlen (pcSwitchDescr);
	memcpy (oSystem.au8Descr, pcSwitchDescr, oSystem.u16Descr_len);
	oSystem.u16Contact_len = strlen (pcSwitchContact);
	memcpy (oSystem.au8Contact, pcSwitchContact, oSystem.u16Contact_len);
	oSystem.u16Name_len = strlen (pcSwitchName);
	memcpy (oSystem.au8Name, pcSwitchName, oSystem.u16Name_len);
	oSystem.u16Location_len = 0;
	memset (oSystem.au8Location, 0, sizeof (oSystem.au8Location));
	
	return NULL;
}

void *
system_main (
	void *pvArgv)
{
	systemMIB_init ();
	entityMIB_init ();
	
	if (xThread_create (&oSystemThread) == NULL)
	{
		System_log (xLog_err_c, "xThread_create() failed\n");
		return NULL;
	}
	
	return NULL;
}

void *
system_start (
	void *pvArgv)
{
	while (1)
	{
		xThread_sleep (1);
	}
	return NULL;
}


#endif	// __SYSTEM_MAIN_C__
