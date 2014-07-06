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


typedef bool (neIfTypeEnableHandler_t) (ifData_t *poIfEntry, int32_t i32AdminStatus);

typedef struct neIfTypeEntry_t
{
	/* Index values */
	int32_t i32Type;
	
	neIfTypeEnableHandler_t *pfEnableHandler;
	
	xBTree_Node_t oBTreeNode;
} neIfTypeEntry_t;

neIfTypeEntry_t * neIfTypeTable_createExt (
	int32_t i32Type);

bool neIfStatus_modify (
	uint32_t u32IfIndex, int32_t i32OperStatus,
	bool bPropagate, bool bLocked);

extern neIfTypeEnableHandler_t neIfEnable_modify;


#	ifdef __cplusplus
}
#	endif

#endif	// __IFUTILS_H__
