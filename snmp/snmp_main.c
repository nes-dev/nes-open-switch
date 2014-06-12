/*
 *  Copyright (c) 2013, 2014
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

#ifndef __SNMP_MAIN_C__
#	define __SNMP_MAIN_C__


#include "snmpMIB_agent.h"

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include "snmp_ext.h"
#include "snmp_defines.h"
#include "switch_ext.h"

#include "lib/thread.h"
#include "lib/sync.h"

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>


static xThreadInfo_t oSnmpThread =
{
	.u32Index = XTHREAD_ID (ModuleId_snmp_c, 0),
	.u8SchedPolicy = SCHED_RR,
	.u8Priority = 1,
	.poStart = &snmp_start,
	.poStop = &snmp_stop,
};

static xMLock_t oSnmpLock;
static SnmpState_t oSnmpState = SnmpState_stopped_c;
static bool bSnmpAgentMaster = true;


void *
snmp_main (
	void *pvArgv)
{
	xMLock_init (&oSnmpLock, NULL);
	
	xMLock_lock (&oSnmpLock);
	oSnmpState = SnmpState_stopped_c;
	xMLock_unlock (&oSnmpLock);
	
	setenv ("SNMPCONFPATH", ".", 1);
	snmp_enable_stderrlog ();
	if (bSnmpAgentMaster == false)
	{
		netsnmp_ds_set_boolean (NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_AGENT_ROLE, 1);
	}
	
	init_agent (APP_NAME);
	
	snmpMIB_init ();
	
	init_snmp (APP_NAME);
	if (bSnmpAgentMaster == true)
	{
		init_master_agent ();
	}
	
	oSnmpThread.pvData = &bSnmpAgentMaster;
	if (xThread_create (&oSnmpThread) == NULL)
	{
		Snmp_log (xLog_err_c, "xThread_create() failed\n");
		return NULL;
	}
	
	return NULL;
}

void *
snmp_start (
	void *pvArgv)
{
	xMLock_lock (&oSnmpLock);
	oSnmpState = SnmpState_running_c;
	xMLock_unlock (&oSnmpLock);
	
	Snmp_log (xLog_info_c, "SNMP agent starting ...\n");
	
	while (oSnmpState != SnmpState_shutdown_c)
	{
		agent_check_and_process (1);
	}
	
	Snmp_log (xLog_info_c, "SNMP agent stopping ...\n");
	snmp_shutdown (APP_NAME);
	
	return NULL;
}

void *
snmp_stop (
	void *pvArgv)
{
	xMLock_lock (&oSnmpLock);
	oSnmpState = SnmpState_shutdown_c;
	xMLock_unlock (&oSnmpLock);
	
	Snmp_log(xLog_info_c, "stopping SNMP agent\n");
	
	return NULL;
}


#endif	// __SNMP_MAIN_C__
