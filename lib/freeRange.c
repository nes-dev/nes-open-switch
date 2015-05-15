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

#ifndef __FREE_RANGE_C__
#	define __FREE_RANGE_C__



#include "freeRange.h"
#include "lib/binaryTree.h"
#include "lib/buffer.h"

#include <stdbool.h>
#include <stdint.h>


int8_t
xFreeRange_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register xFreeRange_Entry_t *pEntry1 = xBTree_entry (pNode1, xFreeRange_Entry_t, oBTreeNode);
	register xFreeRange_Entry_t *pEntry2 = xBTree_entry (pNode2, xFreeRange_Entry_t, oBTreeNode);
	
	return
		(pEntry1->u32Start < pEntry2->u32Start) ? -1:
		(pEntry1->u32Start == pEntry2->u32Start) ? 0: 1;
}


bool
xFreeRange_createRange (
	xFreeRange_t *poRange,
	uint32_t u32Start, uint32_t u32End)
{
	if (u32Start > u32End)
	{
		return false;
	}
	
	xFreeRange_Entry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return false;
	}
	
	poEntry->u32Start = u32Start;
	poEntry->u32End = u32End;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, poRange) != NULL)
	{
		xBuffer_free (poEntry);
		return false;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, poRange);
	return true;
}

bool
xFreeRange_getFreeIndex (
	xFreeRange_t *poRange,
	bool bInRange, uint32_t u32Start, uint32_t u32End,
	uint32_t *pu32Index)
{
	register bool bRetCode = false;
	
	if (u32Start > u32End || pu32Index == NULL)
	{
		goto xFreeRange_getFreeIndex_cleanup;
	}
	
	register xBTree_Node_t *poNode = NULL;
	
	xBTree_scan (poNode, poRange)
	{
		register xFreeRange_Entry_t *poEntry = xGetParentByMemberPtr (poNode, xFreeRange_Entry_t, oBTreeNode);
		
		if (!bInRange ||
			((poEntry->u32Start <= u32Start && u32Start <= poEntry->u32End) ||
			 (poEntry->u32Start <= u32End && u32End <= poEntry->u32End)))
		{
			*pu32Index =
				!bInRange ? poEntry->u32Start:
				poEntry->u32Start <= u32Start && u32Start <= poEntry->u32End ? u32Start: poEntry->u32Start;
				
			bRetCode = true;
			break;
		}
	}
	
xFreeRange_getFreeIndex_cleanup:
	
	return bRetCode;
}

bool
xFreeRange_allocateIndex (
	xFreeRange_t *poRange,
	uint32_t u32Index)
{
	register bool bRetCode = false;
	register xBTree_Node_t *poNode = NULL;
	register xFreeRange_Entry_t *poEntry = NULL;
	
	xBTree_scan (poNode, poRange)
	{
		poEntry = xGetParentByMemberPtr (poNode, xFreeRange_Entry_t, oBTreeNode);
		
		if (poEntry->u32Start <= u32Index && u32Index <= poEntry->u32End)
		{
			bRetCode = true;
			break;
		}
	}
	
	if (!bRetCode)
	{
		goto xFreeRange_allocateIndex_cleanup;
	}
	bRetCode = false;
	
	
	register uint32_t u32RangeStart = poEntry->u32Start;
	register uint32_t u32RangeEnd = poEntry->u32End;
	
	if (u32RangeStart == u32Index)
	{
		xBTree_nodeRemove (&poEntry->oBTreeNode, poRange);
		
		if (u32RangeStart == u32RangeEnd)
		{
			xBuffer_free (poEntry);
		}
		else
		{
			poEntry->u32Start++;
			xBTree_nodeAdd (&poEntry->oBTreeNode, poRange);
		}
	}
	else if (u32RangeEnd == u32Index)
	{
		poEntry->u32End--;
	}
	else
	{
		poEntry->u32End = u32Index - 1;
		if (!xFreeRange_createRange (poRange, u32Index + 1, u32RangeEnd))
		{
			goto xFreeRange_allocateIndex_cleanup;
		}
	}
	
	bRetCode = true;
	
xFreeRange_allocateIndex_cleanup:
	
	return bRetCode;
}

bool
xFreeRange_removeIndex (
	xFreeRange_t *poRange,
	uint32_t u32Index)
{
	register bool bRetCode = false;
	register xBTree_Node_t *poNode = NULL;
	register xFreeRange_Entry_t *poEntry = NULL;
	
	xBTree_scan (poNode, poRange)
	{
		poEntry = xGetParentByMemberPtr (poNode, xFreeRange_Entry_t, oBTreeNode);
		
		if (poEntry->u32Start == u32Index + 1 || u32Index - 1 == poEntry->u32End)
		{
			bRetCode = true;
			break;
		}
	}
	
	
	if (bRetCode)
	{
		bRetCode = false;
		
		if (u32Index - 1 == poEntry->u32End)
		{
			poEntry->u32End++;
			goto xFreeRange_removeIndex_success;
		}
		
		xBTree_nodeRemove (&poEntry->oBTreeNode, poRange);
		poEntry->u32Start++;
		xBTree_nodeAdd (&poEntry->oBTreeNode, poRange);
	}
	else if (!xFreeRange_createRange (poRange, u32Index, u32Index))
	{
		goto xFreeRange_removeIndex_cleanup;
	}
	
xFreeRange_removeIndex_success:
	
	bRetCode = true;
	
xFreeRange_removeIndex_cleanup:
	
	return bRetCode;
}

bool
xFreeRange_destroy (xFreeRange_t *poRange)
{
	register xBTree_Node_t *poNode = NULL;
	register xBTree_Node_t *poNextNode = NULL;
	
	xBTree_scanSafe (poNode, poNextNode, poRange)
	{
		register xFreeRange_Entry_t *poEntry = xGetParentByMemberPtr (poNode, xFreeRange_Entry_t, oBTreeNode);
		
		xBTree_nodeRemove (&poEntry->oBTreeNode, poRange);
		xBuffer_free (poEntry);
	}
	
	return true;
}



#endif	// __FREE_RANGE_C__
