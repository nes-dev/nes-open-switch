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
/**
 *	Name            : Binary Tree libary
 *	Description     : Binary Tree with Red Black algorithm support.
 *	Version         : 0.0003
 *	Author(s)       : Nells K.S
 *	Maintainer(s)   : Nes Dev
 *	Platform        : NA
 */

#ifndef __BINARY_TREE_H__
#	define __BINARY_TREE_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include <stdint.h>
#include <string.h>

#include "lib/lib.h"

#define	BTREE_RB_BALANCING_USED
#undef	BTREE_AA_BALANCING_USED


typedef struct xBTree_Node_t
{
	struct xBTree_Node_t	   *pLeft;
	struct xBTree_Node_t	   *pParent;
	struct xBTree_Node_t	   *pRight;
#ifdef BTREE_RB_BALANCING_USED
	uint8_t							ub1Color : 1;
#endif	/* BTREE_RB_BALANCING_USED */
} xBTree_Node_t;

typedef struct xBTree_t xBTree_t;

typedef int8_t (xBTree_NodeCmp_t) (xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree);

struct xBTree_t
{
	uint32_t				u32NumNode;
	xBTree_Node_t		   *pRoot;
	xBTree_NodeCmp_t	   *pNodeCmp;
};


#define xBTree_initInline(_pNodeCmp)\
{\
	.u32NumNode = 0,\
	.pRoot = NULL,\
	.pNodeCmp = (_pNodeCmp)\
}
#define xBTree_init(_pBTree, _pNodeCmp)\
{\
	memset ((_pBTree), 0, sizeof (xBTree_t));\
	(_pBTree)->pNodeCmp = (_pNodeCmp);\
}
#define xBTree_nodeInit(_pNode)\
{\
	memset ((_pNode), 0, sizeof (xBTree_Node_t));\
}
#define xBTree_nodeInitInline(_pNode)\
{\
	.pLeft = NULL,\
	.pParent = NULL,\
	.pRight = NULL,\
	.ub1Color = 0\
}
/*extern void
	xBTree_init (
		xBTree_t *pBTree, xBTree_NodeCmp_t *pNodeCmp);
extern void
	xBTree_nodeInit (
		xBTree_Node_t *pNode);*/
extern void
	xBTree_nodeAdd (
		xBTree_Node_t *pBTreeNode, xBTree_t *pBTree);
extern void
	xBTree_nodeRemove (
		xBTree_Node_t *pBTreeNode, xBTree_t *pBTree);
extern void
	xBTree_nodeUpdate (
		xBTree_Node_t *pNode, xBTree_t *pBTree);
extern xBTree_Node_t *
	xBTree_nodeFind (
		xBTree_Node_t *pFindVal, xBTree_t *pBTree);
extern xBTree_Node_t *
	xBTree_nodeFindNext (
		xBTree_Node_t *pValFind, xBTree_t *pBTree);
extern xBTree_Node_t *
	xBTree_findMax (
		xBTree_Node_t *pNode);
extern xBTree_Node_t *
	xBTree_findMin (
		xBTree_Node_t *pNode);
extern xBTree_Node_t *
	xBTree_nodeGetFirst (
		xBTree_t *pBTree);
extern xBTree_Node_t *
	xBTree_nodeGetNext (
		xBTree_Node_t *pPrevNode, xBTree_t *pBTree);

typedef char* (xBTree_nodeVal_t) (xBTree_Node_t *pNode, char *pcNodeDisplayBuff, uint8_t u8NodeDisplaySize);
extern void
	xBTree_display (
		xBTree_Node_t *pNode, xBTree_nodeVal_t *pxBTree_nodeVal, char *pcNodeDisplayBuff, uint8_t u8NodeDisplaySize, xBTree_t *pBTree);


#define xBTree_count(_pBTree)\
	((_pBTree)->u32NumNode)
	
#define xBTree_entry(_pNodePtr, _StructType, _NodeName)\
	xGetParentByMemberPtr (_pNodePtr, _StructType, _NodeName)
	
#define xBTree_scan(_pNode, _pBTree) \
	for (\
		(_pNode) = xBTree_nodeGetFirst (_pBTree);\
		(_pNode) != NULL;\
		(_pNode) = xBTree_nodeGetNext (_pNode, _pBTree)\
	)
	
#define xBTree_scanSafe(_pNode, _pNextNode, _pBTree) \
	for (\
		(_pNode) = xBTree_nodeGetFirst (_pBTree), (_pNextNode) = (_pNode) == NULL ? NULL: xBTree_nodeGetNext (_pNode, _pBTree);\
		(_pNode) != NULL;\
		(_pNode) = (_pNextNode), (_pNextNode) = (_pNode) == NULL ? NULL: xBTree_nodeGetNext (_pNode, _pBTree)\
	)
	
	
#if 0
/* Typical data structure for table ifStackTable row entry */
typedef struct ifStackTable_entry {
	/* Index values */
	int32_t ifStackHigherLayer;
	int32_t ifStackLowerLayer;
	
	/* Column values */
	int32_t ifStackStatus;
	
	/* Illustrate using Binary Tree */
	xBTree_Node_t HighToLowBTreeNode;
	xBTree_Node_t LowToHighBTreeNode;
} ifStackTable_entry;

xBTree_t IfStackHighToLowBTree;
xBTree_t IfStackLowToHighBTree;
#endif



#	ifdef __cplusplus
}
#	endif

#endif	// __BINARY_TREE_H__
