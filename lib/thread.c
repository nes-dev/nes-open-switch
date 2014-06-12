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

#ifndef __THREAD_C__
#	define __THREAD_C__



#include "thread.h"
#include "lib/binaryTree.h"
#include "lib/buffer.h"
#include "lib/sync.h"

#include <stdint.h>
#include <string.h>
#include <pthread.h>

#define MOD_NAME "THREAD"

#if 0
#include "lib/log.h"

#define Thread_log(_pri, _frmt, _args ...) xLog_str (MOD_NAME, _pri, _frmt, ## _args)
#else
#define Thread_log(_pri, _frmt, _args ...)
#endif

static xBTree_NodeCmp_t xThread_taskCmp;
xThreadData_t oThreadData =
{
	.oBTree = xBTree_initInline (&xThread_taskCmp),
	.oLock = xRwLock_initInline (),
};
static xThreadRoutine_t xThread_taskInit;


int8_t
xThread_taskCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register xThreadInfo_t *pE1 = NULL, *pE2 = NULL;
	
	pE1 = xBTree_entry (pNode1, xThreadInfo_t, oBTreeNode);
	pE2 = xBTree_entry (pNode2, xThreadInfo_t, oBTreeNode);
	
	return pE1->u32Index > pE2->u32Index ? 1: pE1->u32Index < pE2->u32Index ? -1: 0;
}

xThreadInfo_t *
xThread_create (
	xThreadInfo_t *poThread)
{
	pthread_attr_t	oPAttr, *poPAttr = NULL;
	xThreadInfo_t   *poNewThread = NULL;
	xBTree_Node_t *pNode = NULL;
	int32_t			i32RetStatus = 0;
	
	Thread_log (xLog_debug_c, "poThread{u32Index(%#X)}\n", poThread->u32Index);
	
	if (poThread == NULL)
	{
		Thread_log (xLog_debug_c, "\n");
		goto THREAD_CREATE_CLEANUP;
	}
	xRwLock_rdLock (&oThreadData.oLock);
	if ((pNode = xBTree_nodeFind (&poThread->oBTreeNode, &oThreadData.oBTree)) != NULL)
	{
		poNewThread = xBTree_entry (pNode, xThreadInfo_t, oBTreeNode);
		Thread_log (xLog_debug_c, "poThread(%p:%#X), poNewThread(%p:%#X)\n", poThread, poThread->u32Index, poNewThread, poNewThread->u32Index);
		xRwLock_unlock (&oThreadData.oLock);
		goto THREAD_CREATE_CLEANUP;
	}
	xRwLock_unlock (&oThreadData.oLock);
	
	if ((i32RetStatus = pthread_attr_init (&oPAttr)) != 0)
	{
		Thread_log (xLog_debug_c, "pthread_attr_init(): %s\n", strerror (i32RetStatus));
		goto THREAD_CREATE_CLEANUP;
	}
	poPAttr = &oPAttr;
	
	if (
		(i32RetStatus = pthread_attr_setdetachstate (&oPAttr, PTHREAD_CREATE_DETACHED)) != 0 ||
		(i32RetStatus = pthread_attr_setschedpolicy (&oPAttr, poThread->u8SchedPolicy)) != 0 ||
		(i32RetStatus = pthread_attr_setschedparam (&oPAttr, &(struct sched_param) {.sched_priority = poThread->u8Priority})) != 0)
	{
		Thread_log (xLog_debug_c, "pthread_attr_xxxxxxx(): %s\n", strerror (i32RetStatus));
		goto THREAD_CREATE_CLEANUP;
	}
	xCond_init (&poThread->oSignal, NULL);
	xMLock_init (&poThread->oLock, NULL);
	
	if ((i32RetStatus = pthread_create (&poThread->oPThread, &oPAttr, &xThread_taskInit, poThread)) != 0)
	{
		Thread_log (xLog_debug_c, "pthread_create(): %s\n", strerror (i32RetStatus));
		goto THREAD_CREATE_CLEANUP;
	}
	poNewThread = poThread;
	
THREAD_CREATE_CLEANUP:
	if (poPAttr != NULL)
	{
		pthread_attr_destroy (poPAttr);
	}
	Thread_log (xLog_debug_c, "\n");
	return poNewThread;
}

void *
xThread_taskInit (
	void *pvThread)
{
	register xThreadInfo_t *poThread = pvThread;
	
	Thread_log (xLog_debug_c, "poThread{u32Index(%#X)}\n", poThread->u32Index);
	
	xRwLock_wrLock (&oThreadData.oLock);
	xMLock_lock (&poThread->oLock);
	xBTree_nodeAdd (&poThread->oBTreeNode, &oThreadData.oBTree);
	xMLock_unlock (&poThread->oLock);
	xRwLock_unlock (&oThreadData.oLock);
	
	poThread->poStart (poThread);
	
	xRwLock_wrLock (&oThreadData.oLock);
	xMLock_lock (&poThread->oLock);
	xBTree_nodeRemove (&poThread->oBTreeNode, &oThreadData.oBTree);
	xMLock_unlock (&poThread->oLock);
	xRwLock_unlock (&oThreadData.oLock);
	
	return pvThread;
}

xThreadInfo_t *
xThread_getByIndex (
	uint32_t u32Index)
{
	register xThreadInfo_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (xThreadInfo_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oThreadData.oBTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, xThreadInfo_t, oBTreeNode);
}

xThreadInfo_t *
xThread_getNext (
	xThreadInfo_t *pThread)
{
	xBTree_Node_t *pNode = pThread == NULL ?
		xBTree_nodeGetFirst (&oThreadData.oBTree):
		xBTree_nodeGetNext (&pThread->oBTreeNode, &oThreadData.oBTree);
		
	Thread_log (xLog_debug_c, "\n");
	
	return pNode == NULL ? NULL: xBTree_entry (pNode, xThreadInfo_t, oBTreeNode);
}



#endif	// __THREAD_C__
