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

#ifndef __SYNC_C__
#	define __SYNC_C__



#include "sync.h"
#include "lib/lib.h"
#include "lib/list.h"
#include "lib/bitmap.h"
#include "lib/binaryTree.h"
#include "lib/buffer.h"
#include "lib/thread.h"

#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>

#define MOD_NAME "SYNC"
#define PTHREAD_OK 0

#if 0
#include "lib/log.h"

#define Sync_log(_pri, _frmt, _args ...) xLog_str (MOD_NAME, _pri, _frmt, ## _args)
#else
#define Sync_log(_pri, _frmt, _args ...)
#endif

typedef struct xMessageData_t
{
	xBTree_t oBTree;
	xRwLock_t oLock;
} xMessageData_t;

typedef struct xMessageSrc_t
{
	xMessage_t oMsg;
	xMessageInfo_t oMsgInfo;
} xMessageSrc_t;

typedef struct xMessageDst_t
{
	xMessage_t oMsg;
	xSList_Node_t oDstNode;
} xMessageDst_t;


static xBTree_NodeCmp_t xMessageQueue_NodeCmp;
static xMessageData_t oMessageData =
{
	.oBTree = xBTree_initInline (&xMessageQueue_NodeCmp),
	.oLock = xRwLock_initInline (),
};
static xMessageQueue_t *
xMessageQueue_getByIndex (uint32_t u32Index);


int8_t
xMessageQueue_NodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register xMessageQueue_t *pE1 = NULL, *pE2 = NULL;
	
	pE1 = xBTree_entry (pNode1, xMessageQueue_t, oBTreeNode);
	pE2 = xBTree_entry (pNode2, xMessageQueue_t, oBTreeNode);
	
	return pE1->u32Index > pE2->u32Index ? 1: pE1->u32Index < pE2->u32Index ? -1: 0;
}


xMessageQueue_t *
xMessageQueue_create (
	uint32_t u32Index)
{
	xMessageQueue_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (xMessageQueue_t))) == NULL)
	{
		return NULL;
	}
	
	xRwLock_wrLock (&oMessageData.oLock);
	poEntry->u32Index = u32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oMessageData.oBTree) != NULL)
	{
		xRwLock_unlock (&oMessageData.oLock);
		xBuffer_free (poEntry);
		return NULL;
	}
	xSList_headInit (&poEntry->oTxList);
	xSList_headInit (&poEntry->oRxList);
	xSList_headInit (&poEntry->oAckList);
	xRwLock_init (&poEntry->oLock, NULL);
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oMessageData.oBTree);
	xRwLock_unlock (&oMessageData.oLock);
	return poEntry;
}

xMessageQueue_t *
xMessageQueue_getByIndex (
	uint32_t u32Index)
{
	register xMessageQueue_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (xMessageQueue_t))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->u32Index = u32Index;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oMessageData.oBTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, xMessageQueue_t, oBTreeNode);
}

void
xMessageQueue_remove (xMessageQueue_t *poEntry)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oMessageData.oBTree) == NULL)
	{
		return;
	}
	
	xRwLock_wrLock (&oMessageData.oLock);
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oMessageData.oBTree);
	xRwLock_unlock (&oMessageData.oLock);
	xRwLock_destroy (&poEntry->oLock);
	xBuffer_free (poEntry);
	return;
}


xMessage_t *
xMessage_allocate (
	uint16_t u32Type, void *pvData)
{
	xMessageSrc_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (xMessageSrc_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->oMsgInfo.u32Type = u32Type;
	poEntry->oMsg.pvData = pvData;
	poEntry->oMsg.poMsgInfo = &poEntry->oMsgInfo;
	xSList_nodeInit (&poEntry->oMsg.oQNode);
	xSList_headInit (&poEntry->oMsgInfo.oDstList);
	xRwLock_init (&poEntry->oMsgInfo.oLock, NULL);
	
	return &poEntry->oMsg;
}

bool
xMessage_send (
	xMessage_t *poMessage, xMessageQueue_t *poQueueSrc)
{
	register bool bMsgAdded = false;
	register xSList_Node_t *poDstNode = NULL;
	
	poMessage->u32Index = poQueueSrc->u32Index;
	xSList_push (&poMessage->oQNode, &poQueueSrc->oTxList);
	
	xRwLock_rdLock (&oThreadData.oLock);
	xRwLock_rdLock (&oMessageData.oLock);
	
	xSList_scanTail (poDstNode, &poMessage->poMsgInfo->oDstList)
	{
		xThreadInfo_t *poThread = NULL;
		xMessageQueue_t *poQueueDst = NULL;
		register xMessageDst_t *poMsgDst = xSList_entry (poDstNode, xMessageDst_t, oDstNode);
		
		if (poMsgDst->oMsg.u32Index == 0 ||
			(poThread = xThread_getByIndex (poMsgDst->oMsg.u32Index)) == NULL ||
			(poQueueDst = xMessageQueue_getByIndex (poMsgDst->oMsg.u32Index)) == NULL)
		{
			continue;
		}
		
		xMLock_lock (&poThread->oLock);
		xRwLock_wrLock (&poQueueDst->oLock);
		xSList_push (&poMsgDst->oMsg.oQNode, &poQueueDst->oRxList);
		xRwLock_unlock (&poQueueDst->oLock);
		
		xBitmap_setBit (poThread->ubFlags, xThreadInfo_flagsMessage_c, true);
		xMLock_unlock (&poThread->oLock);
		xCond_broadcast (&poThread->oSignal);
		
		bMsgAdded = true;
	}
	if (!bMsgAdded)
	{
		xSList_nodeRem (&poMessage->oQNode, &poQueueSrc->oTxList);
	}
	
	xRwLock_unlock (&oMessageData.oLock);
	xRwLock_unlock (&oThreadData.oLock);
	
	return true;
}

bool
xMessage_free (
	xMessage_t *poMessage, xMessageQueue_t *poQueueSrc)
{
	xMessageSrc_t *poMsgSrc = xGetParentByMemberPtr (poMessage, xMessageSrc_t, oMsg);
	
	xRwLock_wrLock (&poQueueSrc->oLock);
	xSList_nodeRem (&poMsgSrc->oMsg.oQNode, &poQueueSrc->oAckList);
	xRwLock_unlock (&poQueueSrc->oLock);
	
	xBuffer_free (poMsgSrc);
	return true;
}


xMessage_t *
xMessageDst_create (
	uint32_t u32Index, xMessage_t *poMessage)
{
	xMessageDst_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (xMessageDst_t))) == NULL)
	{
		return NULL;
	}
	
	poEntry->oMsg.u32Index = u32Index;
	poEntry->oMsg.pvData = poMessage->pvData;
	poEntry->oMsg.poMsgInfo = poMessage->poMsgInfo;
	xSList_nodeInit (&poEntry->oMsg.oQNode);
	xSList_nodeInit (&poEntry->oDstNode);
	
	xRwLock_wrLock (&poMessage->poMsgInfo->oLock);
	xSList_push (&poEntry->oDstNode, &poMessage->poMsgInfo->oDstList);
	xRwLock_unlock (&poMessage->poMsgInfo->oLock);
	
	return &poEntry->oMsg;
}

bool
xMessageDst_remove (
	xMessage_t *poMsg, xMessageQueue_t *poQueueDst)
{
	bool bRxComplete = false;
	xMessageInfo_t *poMsgInfo = poMsg->poMsgInfo;
	
	xRwLock_wrLock (&poMsgInfo->oLock);
	xRwLock_wrLock (&poQueueDst->oLock);
	
	xSList_nodeRem (&poMsg->oQNode, &poQueueDst->oRxList);
	poMsgInfo->u16RxCount++;
	bRxComplete = xSList_count (&poMsgInfo->oDstList) == poMsgInfo->u16RxCount;
	
	xRwLock_unlock (&poQueueDst->oLock);
	xRwLock_unlock (&poMsgInfo->oLock);
	
	
	if (!bRxComplete)
	{
		return true;
	}
	
	
	{
		register xSList_Node_t *poDstNode = NULL;
		register xSList_Node_t *poNxtNode = NULL;
		
		xSList_scanTailSafe (poDstNode, poNxtNode, &poMsgInfo->oDstList)
		{
			register xMessageDst_t *poMsgDst = xSList_entry (poDstNode, xMessageDst_t, oDstNode);
			
			if (!xBitmap_getBit (poMsgDst->oMsg.ubFlags, xMessage_flagsAckInline_c))
			{
				xSList_nodeRem (&poMsgDst->oDstNode, &poMsgInfo->oDstList);
				xBuffer_free (poMsgDst);
			}
		}
	}
	
	
	if (bRxComplete && xSList_count (&poMsgInfo->oDstList) != 0)
	{
		xThreadInfo_t *poThread = NULL;
		xMessageQueue_t *poQueueSrc = NULL;
		xMessageSrc_t *poMsgSrc = xGetParentByMemberPtr (poMsgInfo, xMessageSrc_t, oMsgInfo);
		
		xRwLock_rdLock (&oThreadData.oLock);
		xRwLock_rdLock (&oMessageData.oLock);
		
		if ((poThread = xThread_getByIndex (poMsgSrc->oMsg.u32Index)) == NULL ||
			(poQueueSrc = xMessageQueue_getByIndex (poMsgSrc->oMsg.u32Index)) == NULL)
		{
			xRwLock_unlock (&oMessageData.oLock);
			xRwLock_unlock (&oThreadData.oLock);
			return false;
		}
		
		xMLock_lock (&poThread->oLock);
		xRwLock_wrLock (&poQueueSrc->oLock);
		xSList_nodeRem (&poMsgSrc->oMsg.oQNode, &poQueueSrc->oTxList);
		xSList_push (&poMsgSrc->oMsg.oQNode, &poQueueSrc->oAckList);
		xRwLock_unlock (&poQueueSrc->oLock);
		
		xBitmap_setBit (poThread->ubFlags, xThreadInfo_flagsMessage_c, true);
		xMLock_unlock (&poThread->oLock);
		xCond_broadcast (&poThread->oSignal);
		
		xRwLock_unlock (&oMessageData.oLock);
		xRwLock_unlock (&oThreadData.oLock);
	}
	
	return true;
}



#endif	// __SYNC_C__
