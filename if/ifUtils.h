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

#ifndef __IFUTILS_H__
#	define __IFUTILS_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include "ifMIB.h"

#include "lib/list.h"
#include "lib/binaryTree.h"

#include <stdbool.h>
#include <stdint.h>


typedef bool (neIfTypeCreateHandler_t) (ifEntry_t *poIfEntry, uint8_t u8RowStatus);
typedef bool (neIfTypeEnableHandler_t) (ifEntry_t *poIfEntry, int32_t i32AdminStatus);
typedef bool (neIfTypeStatusHandler_t) (xBTree_t *pIfTree, int32_t i32Type, bool bPropagate, bool bLocked);
typedef bool (neIfTypeStatusModifier_t) (ifEntry_t *poIfEntry, int32_t i32OperStatus, bool bPropagate);
typedef bool (neIfTypeStackHandler_t) (ifEntry_t *poHigherIfEntry, ifEntry_t *poLowerIfEntry, uint8_t u8Action, bool bLocked);

enum
{
	neIfTypeStack_actionLowerIf_c           = 0x01,
	neIfTypeStack_actionHigherIf_c          = 0x02,
	neIfTypeStack_actionPreProcess_c        = 0x04,
	neIfTypeStack_actionPostProcess_c       = 0x08,
	neIfTypeStack_actionAdd_c               = 0x10,
	neIfTypeStack_actionRemove_c            = 0x20,
};

typedef struct neIfTypeEntry_t
{
	/* Index values */
	int32_t i32Type;
	
	neIfTypeCreateHandler_t *pfCreateHandler;
	neIfTypeEnableHandler_t *pfEnableHandler;
	neIfTypeStatusHandler_t *pfStatusHandler;
	neIfTypeStatusModifier_t *pfStatusModifier;
	neIfTypeStackHandler_t *pfStackHandler;
	
	xBTree_Node_t oBTreeNode;
} neIfTypeEntry_t;

neIfTypeEntry_t * neIfTypeTable_getByIndex (
	int32_t i32Type);
neIfTypeEntry_t * neIfTypeTable_createExt (
	int32_t i32Type);
bool neIfTypeTable_removeExt (neIfTypeEntry_t *poEntry);


typedef struct neIfStatusEntry_t
{
	int32_t i32Type;
	int32_t i32OperStatus;
	uint32_t u32Index;
	
	xBTree_Node_t oBTreeNode;
} neIfStatusEntry_t;

extern int8_t neIfStatus_BTreeNodeCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree);
	
neIfStatusEntry_t * neIfStatus_createEntry (
	int32_t i32Type,
	int32_t i32OperStatus,
	uint32_t u32Index,
	xBTree_t *pIfStatus_BTree);
void neIfStatus_removeEntry (
	neIfStatusEntry_t *poEntry,
	xBTree_t *pIfStatus_BTree);
	
typedef xBTree_t neIfStatus_list_t;
#define neIfStatus_list_init() xBTree_initInline (&neIfStatus_BTreeNodeCmp)
bool neIfStatus_modify (
	uint32_t u32IfIndex, int32_t i32Type,
	int32_t i32OperStatus, bool bPropagate, bool bLocked);
extern neIfTypeStatusHandler_t neIfStatus_change;

extern neIfTypeEnableHandler_t neIfEnable_modify;
extern neIfTypeStatusHandler_t neIfTypeStatusRx;

bool
	neIfRowStatus_update (
		ifEntry_t *poEntry, uint8_t u8RowStatus);

extern neIfTypeStackHandler_t neIfTypeStackModify;



#	ifdef __cplusplus
}
#	endif

#endif	// __IFUTILS_H__
