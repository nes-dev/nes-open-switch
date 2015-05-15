/*
 *  Copyright (c) 2008-2015
 *      NES Dev <nes.open.switch@gmail.com>
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

#ifndef __INET_MAIN_C__
#	define __INET_MAIN_C__


#include "neInetMIB_agent.h"
#include "clnsMIB_agent.h"
#include "ipMIB_agent.h"
#include "icmpMIB_agent.h"
#include "ipForward_agent.h"

#include "switch_ext.h"
#include "ethernet_ext.h"
#include "inet_ext.h"
#include "inet_defines.h"

#include "lib/thread.h"

#include <stdbool.h>
#include <stdint.h>

#include <net/ethernet.h>


static xThreadInfo_t oInetThread =
{
	.u32Index = XTHREAD_ID (ModuleId_inet_c, 0),
	.u8SchedPolicy = SCHED_RR,
	.u8Priority = 1,
	.poStart = &inet_start,
};


void *
inet_main (
	void *pvArgv)
{
	neInetMIB_init ();
	clnsMIB_init ();
	ipMIB_init ();
	icmpMIB_init ();
	ipForward_init ();
	
	if (xThread_create (&oInetThread) == NULL)
	{
		Inet_log (xLog_err_c, "xThread_create() failed\n");
		return NULL;
	}
	
	return NULL;
}

void *
inet_start (
	void *pvArgv)
{
	while (1)
	{
// 		Inet_log (xLog_debug_c, "looping ...\n");
		xThread_sleep (1);
	}
	return NULL;
}


#endif	// __INET_MAIN_C__
