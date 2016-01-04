/*
 *  Copyright (c) 2008-2016
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

#ifndef __IFUTILS_H__
#	define __IFUTILS_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include "ifMIB.h"

#include "lib/binaryTree.h"

#include <stdbool.h>
#include <stdint.h>


typedef bool (ifType_rowHandler_t)      (ifEntry_t *poIfEntry, uint8_t u8RowStatus);
typedef bool (ifType_enableHandler_t)   (ifEntry_t *poIfEntry, uint8_t u8AdminStatus);
typedef bool (ifType_statusHandler_t)   (xBTree_t *pIfTree, int32_t i32Type, bool bPropagate, bool bLocked);
typedef bool (ifType_statusModifier_t)  (ifEntry_t *poIfEntry, uint8_t u8OperStatus, bool bPropagate);
typedef bool (ifType_stackHandler_t)    (ifEntry_t *poHigherIfEntry, ifEntry_t *poLowerIfEntry, uint8_t u8Action, bool bLocked);

enum
{
	ifTypeStack_actionLowerIf_c             = 0x01,
	ifTypeStack_actionHigherIf_c            = 0x02,
	ifTypeStack_actionPreProcess_c          = 0x04,
	ifTypeStack_actionPostProcess_c         = 0x08,
	ifTypeStack_actionAdd_c                 = 0x10,
	ifTypeStack_actionRemove_c              = 0x20,
};

typedef struct ifTypeEntry_t
{
	/* Index values */
	int32_t i32Type;
	
	ifType_rowHandler_t        *pfRowHandler;
	ifType_enableHandler_t     *pfEnableHandler;
	ifType_statusHandler_t     *pfStatusHandler;
	ifType_statusModifier_t    *pfStatusModifier;
	ifType_stackHandler_t      *pfStackHandler;
	
	xBTree_Node_t oBTreeNode;
} ifTypeEntry_t;

ifTypeEntry_t * ifTypeTable_getByIndex (
	int32_t i32Type);
ifTypeEntry_t * ifTypeTable_createExt (
	int32_t i32Type);
bool ifTypeTable_removeExt (ifTypeEntry_t *poEntry);


typedef struct ifStatusEntry_t
{
	int32_t i32Type;
	uint8_t u8OperStatus;
	uint32_t u32Index;
	
	xBTree_Node_t oBTreeNode;
} ifStatusEntry_t;

extern int8_t ifStatus_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree);
	
ifStatusEntry_t * ifStatus_createEntry (
	int32_t i32Type,
	uint8_t u8OperStatus,
	uint32_t u32Index,
	xBTree_t *pIfStatus_BTree);
void ifStatus_removeEntry (
	ifStatusEntry_t *poEntry,
	xBTree_t *pIfStatus_BTree);
	
typedef xBTree_t ifStatus_List_t;
#define ifStatus_List_init() xBTree_initInline (&ifStatus_BTreeNodeCmp)
#define ifStatus_List_count(_pList) (xBTree_count (_pList))
bool ifStatus_modify (
	uint32_t u32IfIndex, int32_t i32Type,
	uint8_t u8OperStatus, bool bPropagate, bool bLocked);
extern ifType_statusHandler_t ifStatus_change;

inline bool
ifStatus_cleanup (ifStatus_List_t *pIfStatusList)
{
	register xBTree_Node_t *pNode = NULL;
	register xBTree_Node_t *pNextNode = NULL;
	
	xBTree_scanSafe (pNode, pNextNode, pIfStatusList)
	{
		register ifStatusEntry_t *poEntry = xBTree_entry (pNode, ifStatusEntry_t, oBTreeNode);
		
		ifStatus_removeEntry (poEntry, pIfStatusList);
	}
	
	return true;
}

extern ifType_enableHandler_t ifEnable_modify;
extern ifType_statusHandler_t ifType_statusRx;

bool
	neIfRowStatus_update (
		ifEntry_t *poEntry, uint8_t u8RowStatus);

extern ifType_stackHandler_t ifType_stackModify;



#	ifdef __cplusplus
}
#	endif

#endif	// __IFUTILS_H__
