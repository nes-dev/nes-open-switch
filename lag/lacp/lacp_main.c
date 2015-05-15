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

#ifndef __LACP_MAIN_C__
#	define __LACP_MAIN_C__


#include "lag_ext.h"
#include "lacp_ext.h"
#include "lacp_defines.h"
#include "switch_ext.h"
#include "lacpUtils.h"

#include "lib/bitmap.h"
#include "lib/sync.h"
#include "lib/message.h"
#include "lib/thread.h"


static xThreadInfo_t oLacpThread =
{
	.u32Index = XTHREAD_ID (ModuleId_lag_c, TaskId_lacp_c),
	.u8SchedPolicy = SCHED_RR,
	.u8Priority = 1,
	.poStart = &lacp_start,
};

static xMessageQueue_t *poLacpMessageQueue = NULL;


void *
lacp_main (
	void *pvArgv)
{
	if ((poLacpMessageQueue = xMessageQueue_create (oLacpThread.u32Index)) == NULL)
	{
		return NULL;
	}
	
	if (xThread_create (&oLacpThread) == NULL)
	{
		Lacp_log (xLog_err_c, "xThread_create() failed\n");
		return NULL;
	}
	
	return NULL;
}

void *
lacp_start (
	void *pvArgv)
{
	xThread_waitPrepare (&oLacpThread);
	
	while (xThread_wait (&oLacpThread, NULL))
	{
		if (xBitmap_getBit (oLacpThread.au8Flags, xThreadInfo_flagsMessage_c))
		{
			register xMessage_t *poMsg = NULL;
			
			while ((poMsg = xMessageAck_getMessage (poLacpMessageQueue)) != NULL)
			{
				/* TODO */
				
				if (!xMessageAck_remove (poMsg, poLacpMessageQueue))
				{
					break;
				}
			}
			
			while ((poMsg = xMessageDst_getMessage (poLacpMessageQueue)) != NULL)
			{
				/* TODO */
				
				switch (poMsg->poMsgInfo->u32Type)
				{
				default:
					break;
					
				case lacpMessage_PduRx_c:
					dot3adAggPortLacp_processPduRx (poMsg->pvData);
					break;
				}
				
				if (!xMessageDst_remove (poMsg, poLacpMessageQueue))
				{
					break;
				}
			}
			
			xMessage_cleanupThread (poLacpMessageQueue, &oLacpThread);
		}
	}
	
	return NULL;
}


#endif	// __LACP_MAIN_C__
