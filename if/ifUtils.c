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

#ifndef __IF_UTILS_C__
#	define __IF_UTILS_C__



#include "ifUtils.h"
#include "ifMIB.h"

#include "lib/lib.h"
#include "lib/binaryTree.h"
#include "lib/sync.h"
#include "lib/buffer.h"

#include <stdbool.h>
#include <stdint.h>


static bool
	neIfTypeStatusModifier (
		ifEntry_t *poEntry, ifType_statusModifier_t *pfStatusModifier,
		uint8_t u8OperStatus, bool bPropagate);
static inline int32_t
	ifStatus_getHigherLayerStatus (uint8_t u8OperStatus);


static int8_t
ifTypeTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ifTypeEntry_t *pEntry1 = xBTree_entry (pNode1, ifTypeEntry_t, oBTreeNode);
	register ifTypeEntry_t *pEntry2 = xBTree_entry (pNode2, ifTypeEntry_t, oBTreeNode);
	
	return
		(pEntry1->i32Type < pEntry2->i32Type) ? -1:
		(pEntry1->i32Type == pEntry2->i32Type) ? 0: 1;
}

static xBTree_t oIfTypeTable_BTree = xBTree_initInline (&ifTypeTable_BTreeNodeCmp);

ifTypeEntry_t *
ifTypeTable_createExt (
	int32_t i32Type)
{
	register ifTypeEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->i32Type = i32Type;
	
	poEntry->pfRowHandler = NULL;
	poEntry->pfEnableHandler = NULL;
	poEntry->pfStatusHandler = &ifType_statusRx;
	poEntry->pfStatusModifier = NULL;
	poEntry->pfStackHandler = NULL;
	
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oIfTypeTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oIfTypeTable_BTree);
	return poEntry;
}

ifTypeEntry_t *
ifTypeTable_getByIndex (
	int32_t i32Type)
{
	register ifTypeEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32Type = i32Type;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oIfTypeTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, ifTypeEntry_t, oBTreeNode);
}

bool
ifTypeTable_removeExt (ifTypeEntry_t *poEntry)
{
	register bool bRetCode = false;
	
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oIfTypeTable_BTree) == NULL)
	{
		goto ifTypeTable_removeExt_cleanup;
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oIfTypeTable_BTree);
	xBuffer_free (poEntry);
	
	bRetCode = true;
	
ifTypeTable_removeExt_cleanup:
	
	return bRetCode;
}


int8_t
ifStatus_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ifStatusEntry_t *pEntry1 = xBTree_entry (pNode1, ifStatusEntry_t, oBTreeNode);
	register ifStatusEntry_t *pEntry2 = xBTree_entry (pNode2, ifStatusEntry_t, oBTreeNode);
	
	return
		(pEntry1->i32Type < pEntry2->i32Type) ||
		(pEntry1->i32Type == pEntry2->i32Type && pEntry1->u8OperStatus < pEntry2->u8OperStatus) ||
		(pEntry1->i32Type == pEntry2->i32Type && pEntry1->u8OperStatus == pEntry2->u8OperStatus && pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->i32Type == pEntry2->i32Type && pEntry1->u8OperStatus == pEntry2->u8OperStatus && pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

ifStatusEntry_t *
ifStatus_createEntry (
	int32_t i32Type,
	uint8_t u8OperStatus,
	uint32_t u32Index,
	xBTree_t *pIfStatus_BTree)
{
	register ifStatusEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->i32Type = i32Type;
	poEntry->u8OperStatus = u8OperStatus;
	poEntry->u32Index = u32Index;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, pIfStatus_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, pIfStatus_BTree);
	return poEntry;
}

void
ifStatus_removeEntry (
	ifStatusEntry_t *poEntry,
	xBTree_t *pIfStatus_BTree)
{
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, pIfStatus_BTree) == NULL)
	{
		return;    /* Nothing to remove */
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, pIfStatus_BTree);
	xBuffer_free (poEntry);   /* XXX - release any other internal resources */
	return;
}


bool
ifEnable_modify (
	ifEntry_t *poEntry, uint8_t u8AdminStatus)
{
	register bool bRetCode = false;
	register ifTypeEntry_t *poIfTypeEntry = NULL;
	
	if ((poIfTypeEntry = ifTypeTable_getByIndex (poEntry->i32Type)) == NULL)
	{
		goto ifEnable_modify_cleanup;
	}
	
	bRetCode = poIfTypeEntry->pfEnableHandler == NULL && u8AdminStatus == xAdminStatus_up_c ?
		ifStatus_modify (poEntry->u32Index, poEntry->i32Type, u8AdminStatus, false, true): xCallback_tryExec (poIfTypeEntry->pfEnableHandler, poEntry, u8AdminStatus);
		
ifEnable_modify_cleanup:
	
	return bRetCode;
}

int32_t
ifStatus_getHigherLayerStatus (
	uint8_t u8OperStatus)
{
	register int32_t i32HigherOperStatus = u8OperStatus;
	
	switch (u8OperStatus)
	{
	case xOperStatus_up_c:
	case xOperStatus_down_c:
		break;
		
	case xOperStatus_testing_c:
// 	case xOperStatus_unknown_c:
	case xOperStatus_dormant_c:
// 	case xOperStatus_notPresent_c:
	case xOperStatus_lowerLayerDown_c:
		i32HigherOperStatus = xOperStatus_down_c;
		break;
	}
	
	return i32HigherOperStatus;
}

bool
ifStatus_modify (
	uint32_t u32IfIndex, int32_t i32Type, uint8_t u8OperStatus, bool bPropagate, bool bLocked)
{
	register bool bRetCode = false;
	ifStatus_List_t oIfStatusList = ifStatus_List_init ();
	
	if (ifStatus_createEntry (i32Type, u8OperStatus, u32IfIndex, &oIfStatusList) == NULL)
	{
		goto ifStatus_modify_cleanup;
	}
	
	bRetCode = ifStatus_change (&oIfStatusList, i32Type, bPropagate, bLocked);
	
ifStatus_modify_cleanup:
	
	ifStatus_cleanup (&oIfStatusList);
	
	return bRetCode;
}

bool
ifStatus_change (
	ifStatus_List_t *pIfStatusList, int32_t i32Type, bool bPropagate, bool bLocked)
{
	register bool bRetCode = false;
	register xBTree_Node_t *pNode = NULL;
	register xBTree_Node_t *pNextNode = NULL;
	
	bLocked ? true: ifTable_rdLock ();
	
	if (i32Type != 0)
	{
		goto ifStatus_change_aligned;
	}
	
	xBTree_scanSafe (pNode, pNextNode, pIfStatusList)
	{
		register ifStatusEntry_t *poEntry = xBTree_entry (pNode, ifStatusEntry_t, oBTreeNode);
		
		if (poEntry->i32Type != 0 && i32Type != 0)
		{
			if (i32Type == poEntry->i32Type)
			{
				break;
			}
			else if (i32Type != poEntry->i32Type)
			{
				goto ifStatus_change_cleanup;
			}
		}
		
		register ifEntry_t *poIfEntry = NULL;
		
		if ((poIfEntry = ifTable_getByIndex (poEntry->u32Index)) == NULL)
		{
			xBTree_nodeRemove (&poEntry->oBTreeNode, pIfStatusList);
			xBuffer_free (poEntry);
			continue;
		}
		
		ifEntry_rdLock (poIfEntry);
		poEntry->i32Type = poIfEntry->i32Type;
		ifEntry_unLock (poIfEntry);
		
		i32Type = poEntry->i32Type;
		xBTree_nodeUpdate (&poEntry->oBTreeNode, pIfStatusList);
	}
	
	
ifStatus_change_aligned:
	
	bRetCode = ifType_statusRx (pIfStatusList, i32Type, bPropagate, bLocked);
	
ifStatus_change_cleanup:
	
	bLocked ? true: ifTable_unLock ();
	
	return bRetCode;
}

bool
ifType_statusRx (
	xBTree_t *pIfTree, int32_t i32Type, bool bPropagate, bool bLocked)
{
	bool retCode = true;
	register ifTypeEntry_t *poIfTypeEntry = NULL;
	register ifType_statusModifier_t *pfStatusModifier = NULL;
	register xBTree_Node_t *pNode = NULL;
	register xBTree_Node_t *pNextNode = NULL;
	xBTree_t oUpperIfTree = xBTree_initInline (&ifStatus_BTreeNodeCmp);
	xBTree_t oTmpIfTree = xBTree_initInline (&ifStatus_BTreeNodeCmp);
	
	bLocked ? true: ifTable_rdLock ();
	ifStack_rdLock ();
	
	
	if ((poIfTypeEntry = ifTypeTable_getByIndex (i32Type)) == NULL)
	{
		goto ifType_statusRx_cleanup;
	}
	pfStatusModifier = poIfTypeEntry->pfStatusModifier;
	
	xBTree_scanSafe (pNode, pNextNode, pIfTree)
	{
		register uint32_t u32Index = 0;
		register uint8_t u8OperStatus = 0;
		register ifEntry_t *poIfEntry = NULL;
		register ifStatusEntry_t *poEntry = xBTree_entry (pNode, ifStatusEntry_t, oBTreeNode);
		
		u32Index = poEntry->u32Index;
		u8OperStatus = poEntry->u8OperStatus;
		xBTree_nodeRemove (&poEntry->oBTreeNode, pIfTree);
		xBuffer_free (poEntry);
		
		
		if (u32Index == 0 ||
			(poIfEntry = ifTable_getByIndex (u32Index)) == NULL ||
			!neIfTypeStatusModifier (poIfEntry, pfStatusModifier, u8OperStatus, bPropagate))
		{
			continue;
		}
		
		register uint32_t u32UpperIfIndex = 0;
		register int32_t i32UpperIfStatus = ifStatus_getHigherLayerStatus (u8OperStatus);
		register ifStackEntry_t *poIfStackEntry = NULL;
		
		while (
			(poIfStackEntry = ifStackTable_LToH_getNextIndex (u32UpperIfIndex, u32Index)) != NULL &&
			poIfStackEntry->u32LowerLayer == u32Index)
		{
			register int32_t i32UpperIfType = 0;
			
			u32UpperIfIndex = poIfStackEntry->u32HigherLayer;
			
			if (u32UpperIfIndex == 0 ||
				(poIfEntry = ifTable_getByIndex (u32UpperIfIndex)) == NULL)
			{
				continue;
			}
			
			ifEntry_rdLock (poIfEntry);
			i32UpperIfType = poIfEntry->i32Type;
			ifEntry_unLock (poIfEntry);
			
			if (ifStatus_createEntry (i32UpperIfType, i32UpperIfStatus, u32UpperIfIndex, &oUpperIfTree) == NULL)
			{
				retCode = false;
				continue;
			}
		}
	}
	
	
	i32Type = 0;
	xBTree_scanSafe (pNode, pNextNode, &oUpperIfTree)
	{
		register ifStatusEntry_t *poEntry = xBTree_entry (pNode, ifStatusEntry_t, oBTreeNode);
		
		if (i32Type != 0 && i32Type != poEntry->i32Type)
		{
			register ifType_statusHandler_t *pfStatusHandler = &ifType_statusRx;
			
			if ((poIfTypeEntry = ifTypeTable_getByIndex (i32Type)) != NULL &&
				poIfTypeEntry->pfStatusHandler != NULL)
			{
				pfStatusHandler = poIfTypeEntry->pfStatusHandler;
			}
			
			pfStatusHandler (&oTmpIfTree, i32Type, false, bLocked);
			xBTree_init (&oTmpIfTree, &ifStatus_BTreeNodeCmp);
		}
		
		i32Type = poEntry->i32Type;
		xBTree_nodeRemove (&poEntry->oBTreeNode, &oUpperIfTree);
		xBTree_nodeAdd (&poEntry->oBTreeNode, &oTmpIfTree);
	}
	
	if (xBTree_count (&oTmpIfTree) != 0)
	{
		register ifType_statusHandler_t *pfStatusHandler = &ifType_statusRx;
		
		if ((poIfTypeEntry = ifTypeTable_getByIndex (i32Type)) != NULL &&
			poIfTypeEntry->pfStatusHandler != NULL)
		{
			pfStatusHandler = poIfTypeEntry->pfStatusHandler;
		}
		
		pfStatusHandler (&oTmpIfTree, i32Type, false, bLocked);
		xBTree_init (&oTmpIfTree, &ifStatus_BTreeNodeCmp);
	}
	
	
ifType_statusRx_cleanup:
	
	ifStack_unLock ();
	bLocked ? true: ifTable_unLock ();
	
	return retCode;
}

bool
neIfTypeStatusModifier (
	ifEntry_t *poEntry, ifType_statusModifier_t *pfStatusModifier,
	uint8_t u8OperStatus, bool bPropagate)
{
	register bool bStatusModified = false;
	
	if (poEntry == NULL)
	{
		return false;
	}
	
	
	ifEntry_wrLock (poEntry);
	
// 	if (u8OperStatus == xOperStatus_notPresent_c)
// 	{
// 		goto neIfTypeStatusModifier_unlock;
// 	}
	
	if (poEntry->oNe.u8RowStatus == xRowStatus_active_c &&
		poEntry->i32AdminStatus == xAdminStatus_up_c &&
		(bPropagate || poEntry->i32OperStatus != u8OperStatus))
	{
		if (!xCallback_tryExec (pfStatusModifier, poEntry, u8OperStatus, bPropagate))
		{
			goto neIfTypeStatusModifier_unlock;
		}
		
		poEntry->i32OperStatus = u8OperStatus;
		bStatusModified = true;
	}
	
neIfTypeStatusModifier_unlock:
	
	ifEntry_unLock (poEntry);
	
	
// neIfTypeStatusModifier_cleanup:
	
	return bStatusModified || bPropagate;
}

bool
neIfRowStatus_update (
	ifEntry_t *poEntry, uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	register ifTypeEntry_t *poIfTypeEntry = NULL;
	
	if ((poIfTypeEntry = ifTypeTable_getByIndex (poEntry->i32Type)) == NULL)
	{
		goto neIfRowStatus_update_cleanup;
	}
	
	bRetCode = xCallback_tryExec (poIfTypeEntry->pfRowHandler, poEntry, u8RowStatus);
	
neIfRowStatus_update_cleanup:
	
	return bRetCode;
}

bool
ifType_stackModify (
	ifEntry_t *poHigherEntry, ifEntry_t *poLowerEntry,
	uint8_t u8Action, bool bLocked)
{
	register bool bRetCode = false;
	
	if (poHigherEntry == NULL || poLowerEntry == NULL)
	{
		return false;
	}
	
	if (!bLocked)
	{
		ifEntry_wrLock (poLowerEntry);
		ifEntry_wrLock (poHigherEntry);
	}
	
	
	register ifTypeEntry_t *poHigherIfTypeEntry = NULL;
	register ifTypeEntry_t *poLowerIfTypeEntry = NULL;
	
	if ((poHigherIfTypeEntry = ifTypeTable_getByIndex (poHigherEntry->i32Type)) == NULL)
	{
		goto ifType_stackModify_cleanup;
	}
	poLowerIfTypeEntry =
		poHigherEntry->i32Type == poHigherEntry->i32Type ? poHigherIfTypeEntry: ifTypeTable_getByIndex (poLowerEntry->i32Type);
	if (poLowerIfTypeEntry == NULL)
	{
		goto ifType_stackModify_cleanup;
	}
	
	
	switch (u8Action & (ifTypeStack_actionAdd_c | ifTypeStack_actionRemove_c))
	{
	case ifTypeStack_actionAdd_c:
		u8Action |= ifTypeStack_actionPreProcess_c;
		if (!xCallback_tryExec (poLowerIfTypeEntry->pfStackHandler, poHigherEntry, poLowerEntry, u8Action | ifTypeStack_actionLowerIf_c, true) ||
			!xCallback_tryExec (poHigherIfTypeEntry->pfStackHandler, poHigherEntry, poLowerEntry, u8Action | ifTypeStack_actionHigherIf_c, true))
		{
			goto ifType_stackModify_cleanup;
		}
		
		u8Action ^= ifTypeStack_actionPreProcess_c;
		u8Action |= ifTypeStack_actionPostProcess_c;
		if (!xCallback_tryExec (poLowerIfTypeEntry->pfStackHandler, poHigherEntry, poLowerEntry, u8Action | ifTypeStack_actionLowerIf_c, true) ||
			!xCallback_tryExec (poHigherIfTypeEntry->pfStackHandler, poHigherEntry, poLowerEntry, u8Action | ifTypeStack_actionHigherIf_c, true))
		{
			goto ifType_stackModify_cleanup;
		}
		
		bRetCode = true;
		break;
		
	case ifTypeStack_actionRemove_c:
		u8Action |= ifTypeStack_actionPreProcess_c;
		if (!xCallback_tryExec (poHigherIfTypeEntry->pfStackHandler, poHigherEntry, poLowerEntry, u8Action | ifTypeStack_actionHigherIf_c, true) ||
			!xCallback_tryExec (poLowerIfTypeEntry->pfStackHandler, poHigherEntry, poLowerEntry, u8Action | ifTypeStack_actionLowerIf_c, true))
		{
			goto ifType_stackModify_cleanup;
		}
		
		u8Action ^= ifTypeStack_actionPreProcess_c;
		u8Action |= ifTypeStack_actionPostProcess_c;
		if (!xCallback_tryExec (poHigherIfTypeEntry->pfStackHandler, poHigherEntry, poLowerEntry, u8Action | ifTypeStack_actionHigherIf_c, true) ||
			!xCallback_tryExec (poLowerIfTypeEntry->pfStackHandler, poHigherEntry, poLowerEntry, u8Action | ifTypeStack_actionLowerIf_c, true))
		{
			goto ifType_stackModify_cleanup;
		}
		
		bRetCode = true;
		break;
	}
	
ifType_stackModify_cleanup:
	
	if (!bLocked)
	{
		ifEntry_unLock (poLowerEntry);
		ifEntry_unLock (poHigherEntry);
	}
	
	return bRetCode;
}



#endif	// __IF_UTILS_C__
