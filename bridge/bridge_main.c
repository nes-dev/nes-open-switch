/*
 *  Copyright (c) 2013, 2014
 *      NES <nes.open.switch@gmail.com>
 *
 *  All rights reserved. This source file is the sole property of NES, and
 *  contain proprietary and confidential information related to NES.
 *
 *  Licensed under the NES PROF License, Version 1.0 (the "License"); you may
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

#ifndef __BRIDGE_MAIN_C__
#	define __BRIDGE_MAIN_C__


#include "ieee8021QBridgeMib_agent.h"
#include "ieee8021PbMib_agent.h"
#include "ieee8021PbbMib_agent.h"
#include "ieee8021PbbTeMib_agent.h"

#include "switch_ext.h"
#include "bridge_ext.h"
#include "bridge_defines.h"

#include "lib/thread.h"

#include <stdbool.h>
#include <stdint.h>


static xThreadInfo_t oBridgeThread =
{
	.u32Index = XTHREAD_ID (ModuleId_bridge_c, 0),
	.u8SchedPolicy = SCHED_RR,
	.u8Priority = 1,
	.poStart = &bridge_start,
};


void *
bridge_main (
	void *pvArgv)
{
	ieee8021QBridgeMib_init ();
	ieee8021PbMib_init ();
	ieee8021PbbMib_init ();
	ieee8021PbbTeMib_init ();
	
	if (xThread_create (&oBridgeThread) == NULL)
	{
		Bridge_log (xLog_err_c, "xThread_create() failed\n");
		return NULL;
	}
	
	return NULL;
}

void *
bridge_start (
	void *pvArgv)
{
	while (1)
	{
// 		Bridge_log (xLog_debug_c, "looping ...\n");
		xThread_sleep (1);
	}
	return NULL;
}


#endif	// __BRIDGE_MAIN_C__
