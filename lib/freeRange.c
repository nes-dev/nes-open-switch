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
	xFreeRange_t *poFreeRange,
	uint32_t u32Start, uint32_t u32End)
{
	xFreeRange_Entry_t *poEntry = NULL;
	
	if ((poEntry = xBuffer_cAlloc (sizeof (*poEntry))) == NULL)
	{
		return false;
	}
	
	poEntry->u32Start = u32Start;
	poEntry->u32End = u32End;
	if (xBTree_nodeFind (&poEntry->oBTreeNode, poFreeRange) != NULL)
	{
		xBuffer_free (poEntry);
		return false;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, poFreeRange);
	return true;
}

bool
xFreeRange_getFreeIndex (
	xFreeRange_t *poFreeRange,
	bool bInRange, uint32_t u32Start, uint32_t u32End,
	uint32_t *pu32Index)
{
	return false;
}

bool
xFreeRange_allocateIndex (
	xFreeRange_t *poFreeRange,
	uint32_t u32Index)
{
	return false;
}

bool
xFreeRange_removeIndex (
	xFreeRange_t *poFreeRange,
	uint32_t u32Index)
{
	return false;
}

bool
xFreeRange_destroy (xFreeRange_t *poFreeRange)
{
	return false;
}



#endif	// __FREE_RANGE_C__
