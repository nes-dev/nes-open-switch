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

#ifndef __FREE_RANGE_H__
#	define __FREE_RANGE_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include "lib/binaryTree.h"

#include <stdbool.h>
#include <stdint.h>


typedef struct xFreeRange_Entry_t
{
	uint32_t u32Start;
	uint32_t u32End;
	
	xBTree_Node_t oBTreeNode;
} xFreeRange_Entry_t;

typedef xBTree_t xFreeRange_t;
extern xBTree_NodeCmp_t xFreeRange_BTreeNodeCmp;


#define xFreeRange_init(poFreeRange) xBTree_init ((poFreeRange), &xFreeRange_BTreeNodeCmp)
#define xFreeRange_initInline() xBTree_initInline (&xFreeRange_BTreeNodeCmp)

extern bool
	xFreeRange_createRange (
		xFreeRange_t *poFreeRange,
		uint32_t u32Start, uint32_t u32End);
extern bool
	xFreeRange_getFreeIndex (
		xFreeRange_t *poFreeRange,
		bool bInRange, uint32_t u32Start, uint32_t u32End,
		uint32_t *pu32Index);
extern bool
	xFreeRange_allocateIndex (
		xFreeRange_t *poFreeRange,
		uint32_t u32Index);
extern bool
	xFreeRange_removeIndex (
		xFreeRange_t *poFreeRange,
		uint32_t u32Index);
extern bool
	xFreeRange_destroy (xFreeRange_t *poFreeRange);



#	ifdef __cplusplus
}
#	endif

#endif	// __FREE_RANGE_H__
