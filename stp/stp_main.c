/*
 *  Copyright (c) 2008-2015
 *      NES Repo <nes.repo@gmail.com>
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

#ifndef __STP_MAIN_C__
#	define __STP_MAIN_C__


#include "ieee8021SpanningTreeMib_agent.h"
#include "ieee8021MstpMib_agent.h"

#include "stp_ext.h"
#include "stp_defines.h"
#include "switch_ext.h"

#include "lib/bitmap.h"
#include "lib/sync.h"
#include "lib/message.h"
#include "lib/thread.h"


static xThreadInfo_t oStpThread =
{
	.u32Index = XTHREAD_ID (ModuleId_stp_c, 0),
	.u8SchedPolicy = SCHED_RR,
	.u8Priority = 1,
	.poStart = &stp_start,
};

static xMessageQueue_t *poStpMessageQueue = NULL;


void *
stp_main (void *pvArgv)
{
	register void *pvRetCode = NULL;
	register uint32_t u32ModuleOp = (uintptr_t) pvArgv;
	
	switch (u32ModuleOp)
	{
	default:
		break;
		
	case ModuleOp_start_c:
		ieee8021SpanningTreeMib_init ();
		ieee8021MstpMib_init ();
		
		if ((poStpMessageQueue = xMessageQueue_create (oStpThread.u32Index)) == NULL)
		{
			return NULL;
		}
		
		if (xThread_create (&oStpThread) == NULL)
		{
			Stp_log (xLog_err_c, "xThread_create() failed\n");
			goto stp_main_cleanup;
		}
		break;
	}
	
	pvRetCode = (void*) true;
	
stp_main_cleanup:
	
	return pvRetCode;
}

void *
stp_start (void *pvArgv)
{
	xThread_waitPrepare (&oStpThread);
	
	while (xThread_wait (&oStpThread, NULL))
	{
		if (xBitmap_getBit (oStpThread.au8Flags, xThreadInfo_flagsMessage_c))
		{
			register xMessage_t *poMsg = NULL;
			
			while ((poMsg = xMessageAck_getMessage (poStpMessageQueue)) != NULL)
			{
				/* TODO */
				
				if (!xMessageAck_remove (poMsg, poStpMessageQueue))
				{
					break;
				}
			}
			
			while ((poMsg = xMessageDst_getMessage (poStpMessageQueue)) != NULL)
			{
				/* TODO */
				
				switch (poMsg->poMsgInfo->u32Type)
				{
				default:
					break;
				}
				
				if (!xMessageDst_remove (poMsg, poStpMessageQueue))
				{
					break;
				}
			}
			
			xMessage_cleanupThread (poStpMessageQueue, &oStpThread);
		}
	}
	
	return NULL;
}


#endif	// __STP_MAIN_C__
