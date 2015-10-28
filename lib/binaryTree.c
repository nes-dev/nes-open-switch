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

#ifndef __BINARY_TREE_C__
#	define __BINARY_TREE_C__



#include "binaryTree.h"

#include <stdlib.h>
#include <string.h>

#define MOD_NAME "BTREE"

#if 0
#include "lib/log.h"

#define Btree_log(_pri, _frmt, _args ...) xLog_print (MOD_NAME, _pri, _frmt, ## _args)
#else
#define Btree_log(_pri, _frmt, _args ...)
#define xLog_append(...)
#endif

#ifdef BTREE_RB_BALANCING_USED
#	define BTREE_RB_BLACK		0
#	define BTREE_RB_RED			1
#endif	/* BTREE_RB_BALANCING_USED */

#define BTREE_SIBLING(n) (\
	(n) == NULL || (n)->pParent == NULL ? NULL:\
	(n) == (n)->pParent->pLeft ? (n)->pParent->pRight: (n)->pParent->pLeft\
)

#define BTREE_UNCLE(n) (\
	(n) == NULL || (n)->pParent == NULL ? NULL: BTREE_SIBLING ((n)->pParent)\
)

#define BTREE_GRAND_PARENT(n) (\
	(n) == NULL || (n)->pParent == NULL ? NULL: (n)->pParent->pParent\
)


static void
	xBTree_nodeDisplay (
		xBTree_Node_t **ppNode, uint32_t u32DepthLevel, uint32_t u32DisplayLevel, uint32_t u32TreeBase, uint32_t *pu32DepthNodes,
		xBTree_nodeVal_t *pxBTree_nodeVal, char *pcNodeDisplayBuff, uint8_t u8NodeDisplaySize, xBTree_t *pBTree);
static void
	xBTree_nodeRotateLeft (
		xBTree_Node_t *pNode, xBTree_t *pBTree);
static void
	xBTree_nodeRotateRight (
		xBTree_Node_t *pNode, xBTree_t *pBTree);
static void
	xBTree_nodeParentUpdate (
		xBTree_Node_t *pNode, xBTree_Node_t *pReplacee, xBTree_t *pBTree);
static void
	xBTree_nodeSwap (
		xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree);


#ifdef BTREE_RB_BALANCING_USED
#define xBTree_RB_insertBalance xBTree_RB_insertRootCheck
static void
	xBTree_RB_insertRootCheck (
		xBTree_Node_t *pNode, xBTree_t *pBTree);
#define xBTree_RB_removeBalance xBTree_RB_removeChildCheck
static void
	xBTree_RB_insertParentCheck (
		xBTree_Node_t *pNode, xBTree_t *pBTree);
static void
	xBTree_RB_insertUncleCheck (
		xBTree_Node_t *pNode, xBTree_t *pBTree);
static void
	xBTree_RB_insertParentAdjust (
		xBTree_Node_t *pNode, xBTree_t *pBTree);
static void
	xBTree_RB_insertGrandParentCheck (
		xBTree_Node_t *pNode, xBTree_t *pBTree);

static void
	xBTree_RB_removeChildCheck (
		xBTree_Node_t *pNode, xBTree_t *pBTree);
static void
	xBTree_RB_removeRootCheck (
		xBTree_Node_t *pNode, xBTree_t *pBTree);
static void
	xBTree_RB_removeSiblingAdjust (
		xBTree_Node_t *pNode, xBTree_t *pBTree);
static void
	xBTree_RB_removeSiblingCheck (
		xBTree_Node_t *pNode, xBTree_t *pBTree);
static void
	xBTree_RB_removeParentCheck (
		xBTree_Node_t *pNode, xBTree_t *pBTree);
static void
	xBTree_RB_removeSiblingChildAdjust (
		xBTree_Node_t *pNode, xBTree_t *pBTree);
static void
	xBTree_RB_removeSiblingChildCheck (
		xBTree_Node_t *pNode, xBTree_t *pBTree);
#endif	/* BTREE_RB_BALANCING_USED */


#ifdef BTREE_AA_BALANCING_USED
static void
	xBTree_ArneAndersson_balance (
		xBTree_t *pBTree);
#endif	/* BTREE_AA_BALANCING_USED */


void
xBTree_nodeAdd (
	xBTree_Node_t *pNode, xBTree_t *pBTree)
{
	Btree_log (xLog_debug_c, "pNode(%p)\n", pNode);
	
	if (pBTree == NULL || pNode == NULL)
	{
		return;
	}
	
	register xBTree_Node_t **ppTmpLoc = &pBTree->pRoot;
	register xBTree_Node_t *pParent = NULL;
	
	while (*ppTmpLoc != NULL)
	{
		pParent = *ppTmpLoc;
		ppTmpLoc = pBTree->pNodeCmp (pNode, *ppTmpLoc, pBTree) <= 0 ? &(*ppTmpLoc)->pLeft: &(*ppTmpLoc)->pRight;
	}
	*ppTmpLoc = pNode;
	pNode->pParent = pParent;
	pBTree->u32NumNode++;
	
#ifdef BTREE_RB_BALANCING_USED
	xBTree_RB_insertBalance (pNode, pBTree);
#elif defined (BTREE_AA_BALANCING_USED)
	xBTree_ArneAndersson_balance (pBTree);
#endif	/* BTREE_AA_BALANCING_USED */
	
	return;
}

void
xBTree_nodeRemove (
	xBTree_Node_t *pNode, xBTree_t *pBTree)
{
	Btree_log (xLog_debug_c, "pNode(%p)\n", pNode);
	
	if (pBTree == NULL || pNode == NULL)
	{
		return;
	}
	
	register xBTree_Node_t *pReplacee = NULL;
	
	if (pNode->pLeft != NULL && pNode->pRight != NULL)
	{
		if (pNode->pLeft != NULL && pReplacee == NULL)
		{
			pReplacee = xBTree_findMax (pNode->pLeft);
		}
		if (pNode->pRight != NULL && pReplacee == NULL)
		{
			pReplacee = xBTree_findMin (pNode->pRight);
		}
		
		if (pReplacee != NULL)
		{
			xBTree_nodeSwap (pNode, pReplacee, pBTree);
		}
	}
	
#ifdef BTREE_RB_BALANCING_USED
	xBTree_RB_removeBalance (pNode, pBTree);
#elif defined (BTREE_AA_BALANCING_USED)
	xBTree_ArneAndersson_balance (pBTree);
#endif	/* BTREE_AA_BALANCING_USED */
	
	pBTree->u32NumNode--;
	return;
}

void
xBTree_nodeUpdate (
	xBTree_Node_t *pNode, xBTree_t *pBTree)
{
	Btree_log (xLog_debug_c, "pNode(%p)\n", pNode);
	
	if (pBTree == NULL || pNode == NULL)
	{
		return;
	}
	
	register xBTree_Node_t *pReplacee = NULL;
	
	if (pNode->pLeft != NULL && pNode->pRight != NULL)
	{
		if (pNode->pLeft != NULL && pReplacee == NULL)
		{
			pReplacee = xBTree_findMax (pNode->pLeft);
		}
		if (pNode->pRight != NULL && pReplacee == NULL)
		{
			pReplacee = xBTree_findMin (pNode->pRight);
		}
		
		if (pReplacee != NULL)
		{
			xBTree_nodeSwap (pNode, pReplacee, pBTree);
		}
	}
	
#ifdef BTREE_RB_BALANCING_USED
	xBTree_RB_removeBalance (pNode, pBTree);
#elif defined (BTREE_AA_BALANCING_USED)
	xBTree_ArneAndersson_balance (pBTree);
#endif	/* BTREE_AA_BALANCING_USED */
	
	
	register xBTree_Node_t **ppTmpLoc = &pBTree->pRoot;
	register xBTree_Node_t *pParent = NULL;
	
	while (*ppTmpLoc != NULL)
	{
		pParent = *ppTmpLoc;
		ppTmpLoc = pBTree->pNodeCmp (pNode, *ppTmpLoc, pBTree) <= 0 ? &(*ppTmpLoc)->pLeft: &(*ppTmpLoc)->pRight;
	}
	*ppTmpLoc = pNode;
	pNode->pParent = pParent;
	
#ifdef BTREE_RB_BALANCING_USED
	xBTree_RB_insertBalance (pNode, pBTree);
#elif defined (BTREE_AA_BALANCING_USED)
	xBTree_ArneAndersson_balance (pBTree);
#endif	/* BTREE_AA_BALANCING_USED */
	
	return;
}

void
xBTree_display (
	xBTree_Node_t *pNode, xBTree_nodeVal_t *pxBTree_nodeVal, char *pcNodeDisplayBuff, uint8_t u8NodeDisplaySize, xBTree_t *pBTree)
{
	if (pNode == NULL || pxBTree_nodeVal == NULL || pcNodeDisplayBuff == NULL || u8NodeDisplaySize == 0 || pBTree == NULL)
	{
		return;
	}
	
	uint32_t u32TreeDepth = 1;
	uint32_t u32TreeBase = 1;
	
	for (uint32_t u32Depth = pBTree->u32NumNode; u32Depth != 0; u32Depth >>= 1, u32TreeDepth++);
	u32TreeBase <<= u32TreeDepth;
	
	for (uint32_t u32DisplayLevel = 0; u32DisplayLevel < u32TreeDepth; u32DisplayLevel++)
	{
		uint32_t u32DepthNodes = 0;
		
		for (uint32_t u32BlankNodes = u32TreeBase >> (u32DisplayLevel + 1); u32BlankNodes != 0; u32BlankNodes--)
		{
			xLog_append ("%-*s", u8NodeDisplaySize + 1, ".");
		}
		
		xBTree_nodeDisplay (&pBTree->pRoot, 0, u32DisplayLevel, u32TreeBase, &u32DepthNodes, pxBTree_nodeVal, pcNodeDisplayBuff, u8NodeDisplaySize, pBTree);
		xLog_append ("\n");
	}
	
	return;
}

void
xBTree_nodeDisplay (
	xBTree_Node_t **ppNode, uint32_t u32DepthLevel, uint32_t u32DisplayLevel, uint32_t u32TreeBase, uint32_t *pu32DepthNodes,
	xBTree_nodeVal_t *pxBTree_nodeVal, char *pcNodeDisplayBuff, uint8_t u8NodeDisplaySize, xBTree_t *pBTree)
{
	if (u32DepthLevel > u32DisplayLevel)
	{
		return;
	}
	
	xBTree_nodeDisplay (
		ppNode != NULL && *ppNode != NULL ? &(*ppNode)->pLeft: NULL, u32DepthLevel + 1, u32DisplayLevel, u32TreeBase, pu32DepthNodes,
		pxBTree_nodeVal, pcNodeDisplayBuff, u8NodeDisplaySize, pBTree);
	
	if (u32DepthLevel == u32DisplayLevel)
	{
		if (ppNode == NULL)
		{
			xLog_append ("%-*s", u8NodeDisplaySize + 1, ".");
		}
		else if (
			*ppNode == NULL)
		{
			xLog_append ("%-*s", u8NodeDisplaySize + 1, "v");
		}
		else
		{
			xLog_append ("%*.*s%c", u8NodeDisplaySize, u8NodeDisplaySize,
					    pxBTree_nodeVal (*ppNode, pcNodeDisplayBuff, u8NodeDisplaySize), (*ppNode)->ub1Color == BTREE_RB_RED ? '_': ' ');
		}
		
		(*pu32DepthNodes)++;
		if (*pu32DepthNodes < 1 << u32DepthLevel)
		{
			for (uint32_t u32BlankNodes = (u32TreeBase >> u32DepthLevel) - 1; u32BlankNodes != 0; u32BlankNodes--)
			{
				xLog_append ("%-*s", u8NodeDisplaySize + 1, ".");
			}
		}
	}
	
	xBTree_nodeDisplay (
		ppNode != NULL && *ppNode != NULL ? &(*ppNode)->pRight: NULL, u32DepthLevel + 1, u32DisplayLevel, u32TreeBase, pu32DepthNodes,
		pxBTree_nodeVal, pcNodeDisplayBuff, u8NodeDisplaySize, pBTree);
	return;
}

xBTree_Node_t *
xBTree_findMax (
	xBTree_Node_t *pNode)
{
	register xBTree_Node_t *pTmpMax = pNode;
	
	Btree_log (xLog_debug_c, "pNode(%p)\n", pNode);
	
	while (pTmpMax != NULL && pTmpMax->pRight != NULL)
	{
		pTmpMax = pTmpMax->pRight;
	}
	
	return pTmpMax;
}

xBTree_Node_t *
xBTree_findMin (
	xBTree_Node_t *pNode)
{
	register xBTree_Node_t *pTmpMin = pNode;
	
	Btree_log (xLog_debug_c, "pNode(%p)\n", pNode);
	
	while (pTmpMin != NULL && pTmpMin->pLeft != NULL)
	{
		pTmpMin = pTmpMin->pLeft;
	}
	
	return pTmpMin;
}

xBTree_Node_t *
xBTree_nodeFind (
	xBTree_Node_t *pValFind, xBTree_t *pBTree)
{
	register xBTree_Node_t *pTmpNode = pBTree->pRoot;
	register xBTree_Node_t *pTmpFind = NULL;
	
	Btree_log (xLog_debug_c, "\n");
	
	while (pTmpNode != NULL)
	{
		register int8_t i8Cmp = pBTree->pNodeCmp (pValFind, pTmpNode, pBTree);
		
		i8Cmp < 0 ? (pTmpNode = pTmpNode->pLeft):
		i8Cmp > 0 ? (pTmpNode = pTmpNode->pRight): 0;
		
		if (i8Cmp == 0)
		{
			pTmpFind = pTmpNode;
			break;
		}
	}
	
	return pTmpFind;
}

xBTree_Node_t *
xBTree_nodeFindNext (
	xBTree_Node_t *pValFind, xBTree_t *pBTree)
{
	register xBTree_Node_t *pTmpNode = pBTree->pRoot;
	register xBTree_Node_t *pPrevNode = NULL;
	register xBTree_Node_t *pNextNode = NULL;
	
	Btree_log (xLog_debug_c, "\n");
	
	while (pTmpNode != NULL)
	{
		register int8_t i8Cmp = pBTree->pNodeCmp (pValFind, pTmpNode, pBTree);
		
		if (i8Cmp < 0)
		{
			pTmpNode = pTmpNode->pLeft;
		}
		else
		{
			pPrevNode = pTmpNode;
			pTmpNode = pTmpNode->pRight;
		}
	}
	
	pNextNode = pPrevNode != NULL ?
		xBTree_nodeGetNext (pPrevNode, pBTree): xBTree_nodeGetFirst (pBTree);
		
	return pNextNode;
}

xBTree_Node_t *
xBTree_nodeGetFirst (
	xBTree_t *pBTree)
{
	register xBTree_Node_t *pFirstNode = pBTree->pRoot;
	
	while (pFirstNode != NULL && pFirstNode->pLeft != NULL)
	{
		pFirstNode = pFirstNode->pLeft;
	}
	
	return pFirstNode;
}

xBTree_Node_t *
xBTree_nodeGetNext (
	xBTree_Node_t *pPrevNode, xBTree_t *pBTree)
{
	register xBTree_Node_t *pNextNode = NULL;
		
	if (pPrevNode->pRight != NULL)
	{
		pNextNode = pPrevNode->pRight;
		
		while (pNextNode->pLeft != NULL)
		{
			pNextNode = pNextNode->pLeft;
		}
	}
	else if (
		pPrevNode->pParent != NULL && pPrevNode == pPrevNode->pParent->pRight)
	{
		pNextNode = pPrevNode;
		
		while (pNextNode != NULL && pNextNode->pParent != NULL && pNextNode == pNextNode->pParent->pRight)
		{
			pNextNode = pNextNode->pParent;
		}
		pNextNode = pNextNode->pParent;
	}
	else if (
		pPrevNode->pParent != NULL && pPrevNode == pPrevNode->pParent->pLeft)
	{
		pNextNode = pPrevNode->pParent;
	}
	
	return pNextNode;
}


/* RB tree utilities */
inline void
xBTree_nodeRotateLeft (
	xBTree_Node_t *pNode, xBTree_t *pBTree)
{
	register xBTree_Node_t *pChild = pNode->pRight;
	
	Btree_log (xLog_debug_c, "pNode(%p)\n", pNode);
	
	if (pChild == NULL)
	{
		return;
	}
	
	pNode->pRight = pChild->pLeft;
	if (pNode->pRight != NULL)
	{
		pNode->pRight->pParent = pNode;
	}
	pChild->pLeft = pNode;
	
	xBTree_nodeParentUpdate (pNode, pChild, pBTree);
	pNode->pParent = pChild;
	return;
}

inline void
xBTree_nodeRotateRight (
	xBTree_Node_t *pNode, xBTree_t *pBTree)
{
	register xBTree_Node_t *pChild = pNode->pLeft;
	
	Btree_log (xLog_debug_c, "pNode(%p)\n", pNode);
	
	if (pChild == NULL)
	{
		return;
	}
	
	pNode->pLeft = pChild->pRight;
	if (pNode->pLeft != NULL)
	{
		pNode->pLeft->pParent = pNode;
	}
	pChild->pRight = pNode;
	
	xBTree_nodeParentUpdate (pNode, pChild, pBTree);
	pNode->pParent = pChild;
	return;
}

inline void
xBTree_nodeParentUpdate (
	xBTree_Node_t *pNode, xBTree_Node_t *pReplacee, xBTree_t *pBTree)
{
	Btree_log (xLog_debug_c, "pNode(%p), pReplacee(%p)\n", pNode, pReplacee);
	
	if (pNode->pParent != NULL)
	{
		if (pNode->pParent->pLeft == pNode)
		{
			pNode->pParent->pLeft = pReplacee;
		}
		else if (
			pNode->pParent->pRight == pNode)
		{
			pNode->pParent->pRight = pReplacee;
		}
	}
	else
	{
		pBTree->pRoot = pReplacee;
	}
	
	if (pReplacee != NULL)
	{
		pReplacee->pParent = pNode->pParent;
	}
	
	return;
}

void
xBTree_nodeSwap (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	Btree_log (xLog_debug_c, "pNode1(%p), pNode2(%p)\n", pNode1, pNode2);
	
	if (pBTree == NULL || pNode1 == NULL || pNode2 == NULL)
	{
		return;
	}
	
	xBTree_Node_t oTmpNode;
	
	memcpy (&oTmpNode, pNode1, sizeof (oTmpNode));
#ifdef BTREE_RB_BALANCING_USED
	pNode1->ub1Color = pNode2->ub1Color;
	pNode2->ub1Color = oTmpNode.ub1Color;
#endif	/* BTREE_RB_BALANCING_USED */
	
	if (pNode1->pLeft != NULL && pNode1->pLeft != pNode2)
	{
		pNode1->pLeft->pParent = pNode2;
	}
	pNode1->pLeft = pNode1->pParent == pNode2 && pNode1 == pNode2->pLeft ? pNode2: pNode2->pLeft;
	if (pNode1->pRight != NULL && pNode1->pRight != pNode2)
	{
		pNode1->pRight->pParent = pNode2;
	}
	pNode1->pRight = pNode1->pParent == pNode2 && pNode1 == pNode2->pRight ? pNode2: pNode2->pRight;
	
	if (pNode2->pLeft != NULL && pNode2->pLeft != pNode1)
	{
		pNode2->pLeft->pParent = pNode1;
	}
	pNode2->pLeft = pNode2->pParent == pNode1 && pNode2 == oTmpNode.pLeft ? pNode1: oTmpNode.pLeft;
	if (pNode2->pRight != NULL && pNode2->pRight != pNode1)
	{
		pNode2->pRight->pParent = pNode1;
	}
	pNode2->pRight = pNode2->pParent == pNode1 && pNode2 == oTmpNode.pRight ? pNode1: oTmpNode.pRight;
	
	if (pNode1 != pNode2->pParent)
	{
		pNode2->pParent != NULL && pNode2->pParent->pLeft == pNode2 ? pNode2->pParent->pLeft = pNode1:
		pNode2->pParent != NULL && pNode2->pParent->pRight == pNode2 ? pNode2->pParent->pRight = pNode1: NULL;
		pNode2->pParent == NULL ? pBTree->pRoot = pNode1: NULL;
		pNode1->pParent = pNode2->pParent;
	}
	else
	{
		pNode1->pParent = pNode2;
	}
	if (pNode2 != oTmpNode.pParent)
	{
		oTmpNode.pParent != NULL && oTmpNode.pParent->pLeft == pNode1 ? oTmpNode.pParent->pLeft = pNode2:
		oTmpNode.pParent != NULL && oTmpNode.pParent->pRight == pNode1 ? oTmpNode.pParent->pRight = pNode2: NULL;
		oTmpNode.pParent == NULL ? pBTree->pRoot = pNode2: NULL;
		pNode2->pParent = oTmpNode.pParent;
	}
	else
	{
		pNode2->pParent = pNode1;
	}
	
	return;
}


#ifdef BTREE_RB_BALANCING_USED
	/**
	 * Rudolf Bayer (RB) tree balancing
	 */


/* RB tree balance operations */
void
xBTree_RB_insertRootCheck (
	xBTree_Node_t *pNode, xBTree_t *pBTree)
{
	Btree_log (xLog_debug_c, "pNode(%p)\n", pNode);
	
	pNode->ub1Color = BTREE_RB_RED;
	
	if (pNode->pParent == NULL)
	{
		pNode->ub1Color = BTREE_RB_BLACK;
	}
	else
	{
		xBTree_RB_insertParentCheck (pNode, pBTree);
	}
	
	return;
}

void
xBTree_RB_insertParentCheck (
	xBTree_Node_t *pNode, xBTree_t *pBTree)
{
	Btree_log (xLog_debug_c, "pNode(%p)\n", pNode);
	
	if (pNode->pParent->ub1Color != BTREE_RB_BLACK)
	{
		xBTree_RB_insertUncleCheck (pNode, pBTree);
	}
	
	return;
}

void
xBTree_RB_insertUncleCheck (
	xBTree_Node_t *pNode, xBTree_t *pBTree)
{
	xBTree_Node_t	   *pUncle = BTREE_UNCLE (pNode),
					   *pGrandParent = BTREE_GRAND_PARENT (pNode);
	
	Btree_log (xLog_debug_c, "pNode(%p)\n", pNode);
	
	if (pUncle != NULL && pUncle->ub1Color == BTREE_RB_RED)
	{
		pNode->pParent->ub1Color = BTREE_RB_BLACK;
		pUncle->ub1Color = BTREE_RB_BLACK;
		pGrandParent->ub1Color = BTREE_RB_RED;
		xBTree_RB_insertRootCheck (pGrandParent, pBTree);
	}
	else
	{
		xBTree_RB_insertParentAdjust (pNode, pBTree);
	}
	
	return;
}

void
xBTree_RB_insertParentAdjust (
	xBTree_Node_t *pNode, xBTree_t *pBTree)
{
	xBTree_Node_t *pGrandParent = BTREE_GRAND_PARENT (pNode);
	
	Btree_log (xLog_debug_c, "pNode(%p)\n", pNode);
	
	if (pNode == pNode->pParent->pRight && pNode->pParent == pGrandParent->pLeft)
	{
		xBTree_nodeRotateLeft (pNode->pParent, pBTree);
		pNode = pNode->pLeft;
	}
	else if (
		pNode == pNode->pParent->pLeft && pNode->pParent == pGrandParent->pRight)
	{
		xBTree_nodeRotateRight (pNode->pParent, pBTree);
		pNode = pNode->pRight;
	}
	
	xBTree_RB_insertGrandParentCheck (pNode, pBTree);
	return;
}

void
xBTree_RB_insertGrandParentCheck (
	xBTree_Node_t *pNode, xBTree_t *pBTree)
{
	xBTree_Node_t	   *pGrandParent = BTREE_GRAND_PARENT (pNode);
	
	Btree_log (xLog_debug_c, "pNode(%p)\n", pNode);
	
	if (pNode->pParent != NULL && pGrandParent != NULL)
	{
		pNode->pParent->ub1Color = BTREE_RB_BLACK;
		pGrandParent->ub1Color = BTREE_RB_RED;
		if (pNode == pNode->pParent->pLeft && pNode->pParent == pGrandParent->pLeft)
		{
			xBTree_nodeRotateRight (pGrandParent, pBTree);
		} else if (
			pNode == pNode->pParent->pRight && pNode->pParent == pGrandParent->pRight)
		{
			xBTree_nodeRotateLeft (pGrandParent, pBTree);
		}
	}
	
	return;
}

void
xBTree_RB_removeChildCheck (
	xBTree_Node_t *pNode, xBTree_t *pBTree)
{
	xBTree_Node_t *pChild = pNode->pLeft != NULL ? pNode->pLeft: pNode->pRight;
	
	Btree_log (xLog_debug_c, "pNode(%p)\n", pNode);
	
	if (pNode->ub1Color == BTREE_RB_BLACK)
	{
		if (pChild != NULL && pChild->ub1Color == BTREE_RB_RED)
		{
			pChild->ub1Color = BTREE_RB_BLACK;
		}
		else
		{
			xBTree_RB_removeRootCheck (pNode, pBTree);
		}
	}
	
	xBTree_nodeParentUpdate (pNode, pChild, pBTree);
	return;
}

void
xBTree_RB_removeRootCheck (
	xBTree_Node_t *pNode, xBTree_t *pBTree)
{
	Btree_log (xLog_debug_c, "pNode(%p)\n", pNode);
	
	if (pNode->pParent != NULL)
	{
		xBTree_RB_removeSiblingAdjust (pNode, pBTree);
	}
	
	return;
}

void
xBTree_RB_removeSiblingAdjust (
	xBTree_Node_t *pNode, xBTree_t *pBTree)
{
	xBTree_Node_t	   *pSibling = BTREE_SIBLING (pNode);
	
	Btree_log (xLog_debug_c, "pNode(%p)\n", pNode);
	
	if (pSibling != NULL && pSibling->ub1Color == BTREE_RB_RED)
	{
		pNode->pParent->ub1Color = BTREE_RB_RED;
		pSibling->ub1Color = BTREE_RB_BLACK;
		if (pNode == pNode->pParent->pLeft)
		{
			xBTree_nodeRotateLeft (pNode->pParent, pBTree);
		}
		else
		{
			xBTree_nodeRotateRight (pNode->pParent, pBTree);
		}
	}
	
	xBTree_RB_removeSiblingCheck (pNode, pBTree);
	return;
}

void
xBTree_RB_removeSiblingCheck (
	xBTree_Node_t *pNode, xBTree_t *pBTree)
{
	xBTree_Node_t	   *pSibling = BTREE_SIBLING (pNode);
	
	Btree_log (xLog_debug_c, "pNode(%p)\n", pNode);
	
	if (pNode->pParent->ub1Color == BTREE_RB_BLACK &&
	    pSibling->ub1Color == BTREE_RB_BLACK &&
	    (pSibling->pLeft == NULL || pSibling->pLeft->ub1Color == BTREE_RB_BLACK) &&
	    (pSibling->pRight == NULL || pSibling->pRight->ub1Color == BTREE_RB_BLACK))
	{
		pSibling->ub1Color = BTREE_RB_RED;
		xBTree_RB_removeRootCheck (pNode->pParent, pBTree);
	}
	else
	{
		xBTree_RB_removeParentCheck (pNode, pBTree);
	}
	
	return;
}

void
xBTree_RB_removeParentCheck (
	xBTree_Node_t *pNode, xBTree_t *pBTree)
{
	xBTree_Node_t	   *pSibling = BTREE_SIBLING (pNode);
	
	Btree_log (xLog_debug_c, "pNode(%p)\n", pNode);
	
	if (pNode->pParent->ub1Color == BTREE_RB_RED &&
	    pSibling != NULL && pSibling->ub1Color == BTREE_RB_BLACK &&
	    (pSibling->pLeft == NULL || pSibling->pLeft->ub1Color == BTREE_RB_BLACK) &&
	    (pSibling->pRight == NULL || pSibling->pRight->ub1Color == BTREE_RB_BLACK))
	{
		pSibling->ub1Color = BTREE_RB_RED;
		pNode->pParent->ub1Color = BTREE_RB_BLACK;
	}
	else
	{
		xBTree_RB_removeSiblingChildAdjust (pNode, pBTree);
	}
	
	return;
}

void
xBTree_RB_removeSiblingChildAdjust (
	xBTree_Node_t *pNode, xBTree_t *pBTree)
{
	xBTree_Node_t	   *pSibling = BTREE_SIBLING (pNode);
	
	Btree_log (xLog_debug_c, "pNode(%p)\n", pNode);
	
	if  (pSibling != NULL && pSibling->ub1Color == BTREE_RB_BLACK)
	{ /* this if statement is trivial, */
		/* due to Case 2 (even though Case two changed the sibling to a sibling's child,
		   the sibling's child can't be red, since no red parent can have a red child). */
		
		/* the following statements just force the red to be on the left of the left of the parent,
		   or right of the right, so case six will rotate correctly. */
		if (pNode == pNode->pParent->pLeft &&
			(pSibling->pRight == NULL || pSibling->pRight->ub1Color == BTREE_RB_BLACK) &&
		    pSibling->pLeft != NULL && pSibling->pLeft->ub1Color == BTREE_RB_RED)
		{ /* this last test is trivial too due to cases 2-4. */
			pSibling->ub1Color = BTREE_RB_RED;
			pSibling->pLeft->ub1Color = BTREE_RB_BLACK;
			xBTree_nodeRotateRight (pSibling, pBTree);
		} else if (
			pNode == pNode->pParent->pRight &&
			(pSibling->pLeft == NULL || pSibling->pLeft->ub1Color == BTREE_RB_BLACK) &&
			pSibling->pRight != NULL && pSibling->pRight->ub1Color == BTREE_RB_RED)
		{/* this last test is trivial too due to cases 2-4. */
			pSibling->ub1Color = BTREE_RB_RED;
			pSibling->pRight->ub1Color = BTREE_RB_BLACK;
			xBTree_nodeRotateLeft (pSibling, pBTree);
		}
	}
	
	xBTree_RB_removeSiblingChildCheck (pNode, pBTree);
	return;
}

void
xBTree_RB_removeSiblingChildCheck (
	xBTree_Node_t *pNode, xBTree_t *pBTree)
{
	xBTree_Node_t	   *pSibling = BTREE_SIBLING (pNode);
	
	Btree_log (xLog_debug_c, "pNode(%p)\n", pNode);
	
	pSibling->ub1Color = pNode->pParent->ub1Color;
	pNode->pParent->ub1Color = BTREE_RB_BLACK;
	
	if (pNode == pNode->pParent->pLeft)
	{
		pSibling->pRight->ub1Color = BTREE_RB_BLACK;
		xBTree_nodeRotateLeft (pNode->pParent, pBTree);
	}
	else
	{
		pSibling->pLeft->ub1Color = BTREE_RB_BLACK;
		xBTree_nodeRotateRight (pNode->pParent, pBTree);
	}
	
	return;
}
#endif	/* BTREE_RB_BALANCING_USED */



#endif	// __BINARY_TREE_C__
