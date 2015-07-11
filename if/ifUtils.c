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
		ifEntry_t *poEntry, neIfTypeStatusModifier_t *pfStatusModifier,
		int32_t i32OperStatus, bool bPropagate);
static inline int32_t
	neIfStatus_getHigherLayerStatus (int32_t i32OperStatus);


static int8_t
neIfTypeTable_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register neIfTypeEntry_t *pEntry1 = xBTree_entry (pNode1, neIfTypeEntry_t, oBTreeNode);
	register neIfTypeEntry_t *pEntry2 = xBTree_entry (pNode2, neIfTypeEntry_t, oBTreeNode);
	
	return
		(pEntry1->i32Type < pEntry2->i32Type) ? -1:
		(pEntry1->i32Type == pEntry2->i32Type) ? 0: 1;
}

static xBTree_t oNeIfTypeTable_BTree = xBTree_initInline (&neIfTypeTable_BTreeNodeCmp);

neIfTypeEntry_t *
neIfTypeTable_createExt (
	int32_t i32Type)
{
	register neIfTypeEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->i32Type = i32Type;
	
	poEntry->pfEnableHandler = NULL;
	poEntry->pfStatusHandler = &neIfTypeStatusRx;
	poEntry->pfStatusModifier = NULL;
	poEntry->pfStackHandler = NULL;
	
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oNeIfTypeTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oNeIfTypeTable_BTree);
	return poEntry;
}

neIfTypeEntry_t *
neIfTypeTable_getByIndex (
	int32_t i32Type)
{
	register neIfTypeEntry_t *poTmpEntry = NULL;
	register xBTree_Node_t *poNode = NULL;
	
	if ((poTmpEntry = xBuffer_cAlloc (sizeof (*poTmpEntry))) == NULL)
	{
		return NULL;
	}
	
	poTmpEntry->i32Type = i32Type;
	if ((poNode = xBTree_nodeFind (&poTmpEntry->oBTreeNode, &oNeIfTypeTable_BTree)) == NULL)
	{
		xBuffer_free (poTmpEntry);
		return NULL;
	}
	
	xBuffer_free (poTmpEntry);
	return xBTree_entry (poNode, neIfTypeEntry_t, oBTreeNode);
}

bool
neIfTypeTable_removeExt (neIfTypeEntry_t *poEntry)
{
	register bool bRetCode = false;
	
	if (poEntry == NULL ||
		xBTree_nodeFind (&poEntry->oBTreeNode, &oNeIfTypeTable_BTree) == NULL)
	{
		goto neIfTypeTable_removeExt_cleanup;
	}
	
	xBTree_nodeRemove (&poEntry->oBTreeNode, &oNeIfTypeTable_BTree);
	xBuffer_free (poEntry);
	
	bRetCode = true;
	
neIfTypeTable_removeExt_cleanup:
	
	return bRetCode;
}


int8_t
neIfStatus_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register neIfStatusEntry_t *pEntry1 = xBTree_entry (pNode1, neIfStatusEntry_t, oBTreeNode);
	register neIfStatusEntry_t *pEntry2 = xBTree_entry (pNode2, neIfStatusEntry_t, oBTreeNode);
	
	return
		(pEntry1->i32Type < pEntry2->i32Type) ||
		(pEntry1->i32Type == pEntry2->i32Type && pEntry1->i32OperStatus < pEntry2->i32OperStatus) ||
		(pEntry1->i32Type == pEntry2->i32Type && pEntry1->i32OperStatus == pEntry2->i32OperStatus && pEntry1->u32Index < pEntry2->u32Index) ? -1:
		(pEntry1->i32Type == pEntry2->i32Type && pEntry1->i32OperStatus == pEntry2->i32OperStatus && pEntry1->u32Index == pEntry2->u32Index) ? 0: 1;
}

neIfStatusEntry_t *
neIfStatus_createEntry (
	int32_t i32Type,
	int32_t i32OperStatus,
	uint32_t u32Index,
	xBTree_t *pIfStatus_BTree)
{
	register neIfStatusEntry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return NULL;
	}
	
	poEntry->i32Type = i32Type;
	poEntry->i32OperStatus = i32OperStatus;
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
neIfStatus_removeEntry (
	neIfStatusEntry_t *poEntry,
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
neIfEnable_modify (
	ifEntry_t *poEntry, int32_t i32AdminStatus)
{
	register bool bRetCode = false;
	register neIfTypeEntry_t *poIfTypeEntry = NULL;
	
	if ((poIfTypeEntry = neIfTypeTable_getByIndex (poEntry->i32Type)) == NULL)
	{
		goto neIfEnable_modify_cleanup;
	}
	
	bRetCode = poIfTypeEntry->pfEnableHandler == NULL ? true: poIfTypeEntry->pfEnableHandler (poEntry, i32AdminStatus);
	
neIfEnable_modify_cleanup:
	
	return bRetCode;
}

int32_t
neIfStatus_getHigherLayerStatus (
	int32_t i32OperStatus)
{
	register int32_t i32HigherOperStatus = i32OperStatus;
	
	switch (i32OperStatus)
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
neIfStatus_modify (uint32_t u32IfIndex, int32_t i32Type, int32_t i32OperStatus, bool bPropagate, bool bLocked)
{
	neIfStatus_list_t oNeIfStatus_list = neIfStatus_list_init ();
	
	if (neIfStatus_createEntry (i32Type, i32OperStatus, u32IfIndex, &oNeIfStatus_list) == NULL)
	{
		return false;
	}
	
	return neIfStatus_change (&oNeIfStatus_list, i32Type, bPropagate, bLocked);
}

bool
neIfStatus_change (xBTree_t *pIfTree, int32_t i32Type, bool bPropagate, bool bLocked)
{
	register bool bRetCode = false;
	register xBTree_Node_t *pNode = NULL;
	register xBTree_Node_t *pNextNode = NULL;
	
	bLocked ? true: ifTable_rdLock ();
	
	if (i32Type != 0)
	{
		goto neIfStatus_change_aligned;
	}
	
	xBTree_scanSafe (pNode, pNextNode, pIfTree)
	{
		register neIfStatusEntry_t *poEntry = xBTree_entry (pNode, neIfStatusEntry_t, oBTreeNode);
		
		if (poEntry->i32Type != 0 && i32Type != 0)
		{
			if (i32Type == poEntry->i32Type)
			{
				break;
			}
			else if (i32Type != poEntry->i32Type)
			{
				goto neIfStatus_change_cleanup;
			}
		}
		
		register ifEntry_t *poIfEntry = NULL;
		
		if ((poIfEntry = ifTable_getByIndex (poEntry->u32Index)) == NULL)
		{
			xBTree_nodeRemove (&poEntry->oBTreeNode, pIfTree);
			xBuffer_free (poEntry);
			continue;
		}
		
		ifEntry_rdLock (poIfEntry);
		poEntry->i32Type = poIfEntry->i32Type;
		ifEntry_unLock (poIfEntry);
		
		i32Type = poEntry->i32Type;
		xBTree_nodeUpdate (&poEntry->oBTreeNode, pIfTree);
	}
	
	
neIfStatus_change_aligned:
	
	bRetCode = neIfTypeStatusRx (pIfTree, i32Type, bPropagate, bLocked);
	
	
neIfStatus_change_cleanup:
	
	bLocked ? true: ifTable_unLock ();
	
	xBTree_scanSafe (pNode, pNextNode, pIfTree)
	{
		register neIfStatusEntry_t *poEntry = xBTree_entry (pNode, neIfStatusEntry_t, oBTreeNode);
		
		xBTree_nodeRemove (&poEntry->oBTreeNode, pIfTree);
		xBuffer_free (poEntry);
	}
	
	return bRetCode;
}

bool
neIfTypeStatusRx (
	xBTree_t *pIfTree, int32_t i32Type, bool bPropagate, bool bLocked)
{
	bool retCode = true;
	register neIfTypeEntry_t *poIfTypeEntry = NULL;
	register neIfTypeStatusModifier_t *pfStatusModifier = NULL;
	register xBTree_Node_t *pNode = NULL;
	register xBTree_Node_t *pNextNode = NULL;
	xBTree_t oUpperIfTree = xBTree_initInline (&neIfStatus_BTreeNodeCmp);
	xBTree_t oTmpIfTree = xBTree_initInline (&neIfStatus_BTreeNodeCmp);
	
	bLocked ? true: ifTable_rdLock ();
	ifStack_rdLock ();
	
	
	if ((poIfTypeEntry = neIfTypeTable_getByIndex (i32Type)) != NULL)
	{
		pfStatusModifier = poIfTypeEntry->pfStatusModifier;
	}
	
	xBTree_scanSafe (pNode, pNextNode, pIfTree)
	{
		register uint32_t u32Index = 0;
		register int32_t i32OperStatus = 0;
		register ifEntry_t *poIfEntry = NULL;
		register neIfStatusEntry_t *poEntry = xBTree_entry (pNode, neIfStatusEntry_t, oBTreeNode);
		
		u32Index = poEntry->u32Index;
		i32OperStatus = poEntry->i32OperStatus;
		xBTree_nodeRemove (&poEntry->oBTreeNode, pIfTree);
		xBuffer_free (poEntry);
		
		
		if (u32Index == 0 ||
			(poIfEntry = ifTable_getByIndex (u32Index)) == NULL ||
			!neIfTypeStatusModifier (poIfEntry, pfStatusModifier, i32OperStatus, bPropagate))
		{
			continue;
		}
		
		register uint32_t u32UpperIfIndex = 0;
		register int32_t i32UpperIfStatus = neIfStatus_getHigherLayerStatus (i32OperStatus);
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
			
			if (neIfStatus_createEntry (i32UpperIfType, i32UpperIfStatus, u32UpperIfIndex, &oUpperIfTree) == NULL)
			{
				retCode = false;
				continue;
			}
		}
	}
	
	
	i32Type = 0;
	xBTree_scanSafe (pNode, pNextNode, &oUpperIfTree)
	{
		register neIfStatusEntry_t *poEntry = xBTree_entry (pNode, neIfStatusEntry_t, oBTreeNode);
		
		if (i32Type != 0 && i32Type != poEntry->i32Type)
		{
			register neIfTypeStatusHandler_t *pfStatusHandler = &neIfTypeStatusRx;
			
			if ((poIfTypeEntry = neIfTypeTable_getByIndex (i32Type)) != NULL &&
				poIfTypeEntry->pfStatusHandler != NULL)
			{
				pfStatusHandler = poIfTypeEntry->pfStatusHandler;
			}
			
			pfStatusHandler (&oTmpIfTree, i32Type, false, bLocked);
			xBTree_init (&oTmpIfTree, &neIfStatus_BTreeNodeCmp);
		}
		
		i32Type = poEntry->i32Type;
		xBTree_nodeRemove (&poEntry->oBTreeNode, &oUpperIfTree);
		xBTree_nodeAdd (&poEntry->oBTreeNode, &oTmpIfTree);
	}
	
	if (xBTree_count (&oTmpIfTree) != 0)
	{
		register neIfTypeStatusHandler_t *pfStatusHandler = &neIfTypeStatusRx;
		
		if ((poIfTypeEntry = neIfTypeTable_getByIndex (i32Type)) != NULL &&
			poIfTypeEntry->pfStatusHandler != NULL)
		{
			pfStatusHandler = poIfTypeEntry->pfStatusHandler;
		}
		
		pfStatusHandler (&oTmpIfTree, i32Type, false, bLocked);
		xBTree_init (&oTmpIfTree, &neIfStatus_BTreeNodeCmp);
	}
	
	
	ifStack_unLock ();
	bLocked ? true: ifTable_unLock ();
	
	return retCode;
}

bool
neIfTypeStatusModifier (
	ifEntry_t *poEntry, neIfTypeStatusModifier_t *pfStatusModifier,
	int32_t i32OperStatus, bool bPropagate)
{
	register bool bStatusModified = false;
	
	if (poEntry == NULL)
	{
		return false;
	}
	
	
	ifEntry_wrLock (poEntry);
	
// 	if (i32OperStatus == xOperStatus_notPresent_c)
// 	{
// 		goto neIfTypeStatusModifier_unlock;
// 	}
	
	if (poEntry->oNe.u8RowStatus == xRowStatus_active_c &&
		poEntry->i32AdminStatus == xAdminStatus_up_c &&
		(bPropagate || poEntry->i32OperStatus != i32OperStatus))
	{
		if (pfStatusModifier != NULL &&
			!pfStatusModifier (poEntry, i32OperStatus, bPropagate))
		{
			goto neIfTypeStatusModifier_unlock;
		}
		
		poEntry->i32OperStatus = i32OperStatus;
		bStatusModified = true;
	}
	
neIfTypeStatusModifier_unlock:
	
	ifEntry_unLock (poEntry);
	
	
// neIfTypeStatusModifier_cleanup:
	
	return bStatusModified || bPropagate;
}

bool
neIfTypeStackModify (
	ifData_t *poHigherIfEntry, ifData_t *poLowerIfEntry,
	uint8_t u8Action, bool bLocked)
{
	register bool bRetCode = false;
	
	if (poHigherIfEntry == NULL || poLowerIfEntry == NULL)
	{
		return false;
	}
	
	if (!bLocked)
	{
		ifData_wrLock (poLowerIfEntry);
		ifData_wrLock (poHigherIfEntry);
	}
	
	
	register neIfTypeEntry_t *poHigherIfTypeEntry = NULL;
	register neIfTypeEntry_t *poLowerIfTypeEntry = NULL;
	
	if ((poHigherIfTypeEntry = neIfTypeTable_getByIndex (poHigherIfEntry->oIf.i32Type)) == NULL)
	{
		goto neIfTypeStackModify_cleanup;
	}
	poLowerIfTypeEntry =
		poHigherIfEntry->oIf.i32Type == poHigherIfEntry->oIf.i32Type ? poHigherIfTypeEntry: neIfTypeTable_getByIndex (poLowerIfEntry->oIf.i32Type);
	if (poLowerIfTypeEntry == NULL)
	{
		goto neIfTypeStackModify_cleanup;
	}
	
	
	switch (u8Action & (neIfTypeStack_actionAdd_c | neIfTypeStack_actionRemove_c))
	{
	case neIfTypeStack_actionAdd_c:
		u8Action |= neIfTypeStack_actionPreProcess_c;
		if (!xCallback_tryExec (poLowerIfTypeEntry->pfStackHandler, poHigherIfEntry, poLowerIfEntry, u8Action | neIfTypeStack_actionLowerIf_c, true) ||
			!xCallback_tryExec (poHigherIfTypeEntry->pfStackHandler, poHigherIfEntry, poLowerIfEntry, u8Action | neIfTypeStack_actionHigherIf_c, true))
		{
			goto neIfTypeStackModify_cleanup;
		}
		
		u8Action ^= neIfTypeStack_actionPreProcess_c;
		u8Action |= neIfTypeStack_actionPostProcess_c;
		if (!xCallback_tryExec (poLowerIfTypeEntry->pfStackHandler, poHigherIfEntry, poLowerIfEntry, u8Action | neIfTypeStack_actionLowerIf_c, true) ||
			!xCallback_tryExec (poHigherIfTypeEntry->pfStackHandler, poHigherIfEntry, poLowerIfEntry, u8Action | neIfTypeStack_actionHigherIf_c, true))
		{
			goto neIfTypeStackModify_cleanup;
		}
		
		bRetCode = true;
		break;
		
	case neIfTypeStack_actionRemove_c:
		u8Action |= neIfTypeStack_actionPreProcess_c;
		if (!xCallback_tryExec (poHigherIfTypeEntry->pfStackHandler, poHigherIfEntry, poLowerIfEntry, u8Action | neIfTypeStack_actionHigherIf_c, true) ||
			!xCallback_tryExec (poLowerIfTypeEntry->pfStackHandler, poHigherIfEntry, poLowerIfEntry, u8Action | neIfTypeStack_actionLowerIf_c, true))
		{
			goto neIfTypeStackModify_cleanup;
		}
		
		u8Action ^= neIfTypeStack_actionPreProcess_c;
		u8Action |= neIfTypeStack_actionPostProcess_c;
		if (!xCallback_tryExec (poHigherIfTypeEntry->pfStackHandler, poHigherIfEntry, poLowerIfEntry, u8Action | neIfTypeStack_actionHigherIf_c, true) ||
			!xCallback_tryExec (poLowerIfTypeEntry->pfStackHandler, poHigherIfEntry, poLowerIfEntry, u8Action | neIfTypeStack_actionLowerIf_c, true))
		{
			goto neIfTypeStackModify_cleanup;
		}
		
		bRetCode = true;
		break;
	}
	
neIfTypeStackModify_cleanup:
	
	if (!bLocked)
	{
		ifData_unLock (poLowerIfEntry);
		ifData_unLock (poHigherIfEntry);
	}
	
	return bRetCode;
}



#endif	// __IF_UTILS_C__
