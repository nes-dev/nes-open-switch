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

#ifndef __IFUTILS_C__
#	define __IFUTILS_C__



#include "ifUtils.h"
#include "ifMIB.h"

#include "lib/lib.h"
#include "lib/binaryTree.h"
#include "lib/sync.h"
#include "lib/buffer.h"

#include <stdbool.h>
#include <stdint.h>


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
	
	if (xBTree_nodeFind (&poEntry->oBTreeNode, &oNeIfTypeTable_BTree) != NULL)
	{
		xBuffer_free (poEntry);
		return NULL;
	}
	
	xBTree_nodeAdd (&poEntry->oBTreeNode, &oNeIfTypeTable_BTree);
	return poEntry;
}

bool
neIfEnable_modify (
	ifData_t *poIfEntry, int32_t i32AdminStatus)
{
	return false;
}

bool
neIfStatus_modify (uint32_t u32IfIndex, int32_t i32OperStatus, bool bPropagate, bool bLocked)
{
	return false;
}



#endif	// __IFUTILS_C__
