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

#include "lib/binaryTree.h"

#include <stdlib.h>
#include <stdio.h>


/* table ifStackTable row entry data structure */
typedef struct ifStackTable_t
{
	/* Index values */
	int32_t i32HigherLayer;
	int32_t i32LowerLayer;
	
	/* Column values */
	int32_t i32Status;
	
	/* Illustrate using Binary Tree */
	xBTree_Node_t oHighToLowBTreeNode;
	xBTree_Node_t oLowToHighBTreeNode;
} ifStackTable_t;

xBTree_t oIfStackHighToLowBTree;
xBTree_t oIfStackLowToHighBTree;

int8_t ifStackTable_HighToLowCmp (xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree);
int8_t ifStackTable_LowToHighCmp (xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree);


void ListIfStack (void);
char* ifStack_HighToLowGetVal (xBTree_Node_t *pNode, char *pcNodeDisplayBuff, uint8_t u8NodeDisplaySize);
char* ifStack_LowToHighGetVal (xBTree_Node_t *pNode, char *pcNodeDisplayBuff, uint8_t u8NodeDisplaySize);

#define GET_RAND_VAL(c) (/*rand ()*/(uint32_t) (rand () / (RAND_MAX + 1.0) * (c)) + 1)

int
main (
	int argc, char **argv)
{
	uint16_t u16ElemCount = 0x20;
	char acDisplayBuff[6];
// 	char acDisplayBuff[3];
	
	xBTree_init (&oIfStackHighToLowBTree, ifStackTable_HighToLowCmp);
	xBTree_init (&oIfStackLowToHighBTree, ifStackTable_LowToHighCmp);
	
	ifStackTable_t *poStackList = NULL;
	
	if ((poStackList = malloc (sizeof (*poStackList) * u16ElemCount)) == NULL)
	{
		fprintf (stderr, "malloc failed\n");
		return -1;
	}
	
	for (uint16_t u16EIndex = 0; u16EIndex < u16ElemCount; u16EIndex++)
	{
		xBTree_nodeInit (&poStackList[u16EIndex].oHighToLowBTreeNode);
		xBTree_nodeInit (&poStackList[u16EIndex].oLowToHighBTreeNode);
		
		poStackList[u16EIndex].i32HigherLayer = GET_RAND_VAL (u16ElemCount);
		poStackList[u16EIndex].i32LowerLayer = GET_RAND_VAL (u16ElemCount);
		fprintf (
			stderr, "--------> CREATE IF_STACK(%#06X, %#06X) === (%p, %p)\n", poStackList[u16EIndex].i32HigherLayer, poStackList[u16EIndex].i32LowerLayer,
			&poStackList[u16EIndex].oHighToLowBTreeNode, &poStackList[u16EIndex].oLowToHighBTreeNode);
		
		xBTree_nodeAdd (&poStackList[u16EIndex].oHighToLowBTreeNode, &oIfStackHighToLowBTree);
		xBTree_nodeAdd (&poStackList[u16EIndex].oLowToHighBTreeNode, &oIfStackLowToHighBTree);
// 		xBTree_display (oIfStackHighToLowBTree.pRoot, &ifStack_HighToLowGetVal, acDisplayBuff, sizeof (acDisplayBuff) - 1, &oIfStackHighToLowBTree);
// 		xBTree_display (oIfStackLowToHighBTree.pRoot, &ifStack_LowToHighGetVal, acDisplayBuff, sizeof (acDisplayBuff) - 1, &oIfStackLowToHighBTree);
	}
	
	fprintf (stderr, "--------| IF_STACK_COUNT(%u)\n", xBTree_count (&oIfStackHighToLowBTree));
	xBTree_display (oIfStackHighToLowBTree.pRoot, &ifStack_HighToLowGetVal, acDisplayBuff, sizeof (acDisplayBuff) - 1, &oIfStackHighToLowBTree);
	fprintf (stderr, "--------| IF_STACK_COUNT(%u)\n", xBTree_count (&oIfStackLowToHighBTree));
	xBTree_display (oIfStackLowToHighBTree.pRoot, &ifStack_LowToHighGetVal, acDisplayBuff, sizeof (acDisplayBuff) - 1, &oIfStackLowToHighBTree);
	ListIfStack ();
	
	for (uint16_t u16EIndex = 0; u16EIndex < u16ElemCount; u16EIndex++)
	{
		register xBTree_Node_t *poIfStackNodeHighToLow = xBTree_nodeFind (&poStackList[u16EIndex].oHighToLowBTreeNode, &oIfStackHighToLowBTree);
		register xBTree_Node_t *poIfStackNodeLowToHigh = xBTree_nodeFind (&poStackList[u16EIndex].oLowToHighBTreeNode, &oIfStackLowToHighBTree);
		
		fprintf (
			stderr, "--------> FIND IF_STACK(%#06X, %#06X) ==> (%p, %p) === (%p, %p) MATCH(%u)\n", poStackList[u16EIndex].i32HigherLayer, poStackList[u16EIndex].i32LowerLayer,
			&poStackList[u16EIndex].oHighToLowBTreeNode, &poStackList[u16EIndex].oLowToHighBTreeNode, poIfStackNodeHighToLow, poIfStackNodeLowToHigh,
			(&poStackList[u16EIndex].oHighToLowBTreeNode == poIfStackNodeHighToLow && &poStackList[u16EIndex].oLowToHighBTreeNode == poIfStackNodeLowToHigh));
	}
	
	for (uint16_t u16EIndex = 0; u16EIndex < u16ElemCount; u16EIndex++)
	{
		fprintf (
			stderr, "--------> DELETE IF_STACK(%#06X, %#06X) === (%p, %p)\n", poStackList[u16EIndex].i32HigherLayer, poStackList[u16EIndex].i32LowerLayer,
			&poStackList[u16EIndex].oHighToLowBTreeNode, &poStackList[u16EIndex].oLowToHighBTreeNode);
		
		xBTree_nodeRemove (&poStackList[u16EIndex].oHighToLowBTreeNode, &oIfStackHighToLowBTree);
		xBTree_nodeRemove (&poStackList[u16EIndex].oLowToHighBTreeNode, &oIfStackLowToHighBTree);
// 		xBTree_display (oIfStackHighToLowBTree.pRoot, &ifStack_HighToLowGetVal, acDisplayBuff, sizeof (acDisplayBuff) - 1, &oIfStackHighToLowBTree);
// 		xBTree_display (oIfStackLowToHighBTree.pRoot, &ifStack_LowToHighGetVal, acDisplayBuff, sizeof (acDisplayBuff) - 1, &oIfStackLowToHighBTree);
	}
	
	fprintf (stderr, "--------| IF_STACK_COUNT(%u)\n", xBTree_count (&oIfStackHighToLowBTree));
	xBTree_display (oIfStackHighToLowBTree.pRoot, &ifStack_HighToLowGetVal, acDisplayBuff, sizeof (acDisplayBuff) - 1, &oIfStackHighToLowBTree);
	fprintf (stderr, "--------| IF_STACK_COUNT(%u)\n", xBTree_count (&oIfStackLowToHighBTree));
	xBTree_display (oIfStackLowToHighBTree.pRoot, &ifStack_LowToHighGetVal, acDisplayBuff, sizeof (acDisplayBuff) - 1, &oIfStackLowToHighBTree);
	ListIfStack ();
	
	free (poStackList);
	
	return 0;
}

char*
ifStack_HighToLowGetVal (xBTree_Node_t *pNode, char *pcNodeDisplayBuff, uint8_t u8NodeDisplaySize)
{
	ifStackTable_t *poEntry = xBTree_entry (pNode, ifStackTable_t, oHighToLowBTreeNode);
	
	snprintf (pcNodeDisplayBuff, u8NodeDisplaySize + 1, "%02X,%02X", poEntry->i32HigherLayer, poEntry->i32LowerLayer);
// 	snprintf (pcNodeDisplayBuff, u8NodeDisplaySize + 1, "%02X", poEntry->i32HigherLayer);
	return pcNodeDisplayBuff;
}

char*
ifStack_LowToHighGetVal (xBTree_Node_t *pNode, char *pcNodeDisplayBuff, uint8_t u8NodeDisplaySize)
{
	ifStackTable_t *poEntry = xBTree_entry (pNode, ifStackTable_t, oLowToHighBTreeNode);
	
	snprintf (pcNodeDisplayBuff, u8NodeDisplaySize + 1, "%02X,%02X", poEntry->i32LowerLayer, poEntry->i32HigherLayer);
	return pcNodeDisplayBuff;
}

void
ListIfStack (void)
{
	ifStackTable_t *poEntry = NULL;
	xBTree_Node_t *pNode = NULL;
	
	pNode = xBTree_nodeGetFirst (&oIfStackHighToLowBTree);
	while (pNode != NULL)
	{
		poEntry = xBTree_entry (pNode, ifStackTable_t, oHighToLowBTreeNode);
		fprintf (
			stderr, "--------> IF_STACK(%#06X, %#06X), %u, %p, %p\n", poEntry->i32HigherLayer, poEntry->i32LowerLayer, pNode->ub1Color,
			&poEntry->oHighToLowBTreeNode, &poEntry->oLowToHighBTreeNode);
		
		pNode = xBTree_nodeGetNext (pNode, &oIfStackHighToLowBTree);
	}
	return;
}

int8_t
ifStackTable_HighToLowCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ifStackTable_t *pE1 = NULL, *pE2 = NULL;
	
	pE1 = xBTree_entry (pNode1, ifStackTable_t, oHighToLowBTreeNode);
	pE2 = xBTree_entry (pNode2, ifStackTable_t, oHighToLowBTreeNode);
	
	return
		(pE1->i32HigherLayer > pE2->i32HigherLayer) || (pE1->i32HigherLayer == pE2->i32HigherLayer && pE1->i32LowerLayer > pE2->i32LowerLayer) ? 1:
		(pE1->i32HigherLayer < pE2->i32HigherLayer) || (pE1->i32HigherLayer == pE2->i32HigherLayer && pE1->i32LowerLayer < pE2->i32LowerLayer) ? -1: 0;
}

int8_t
ifStackTable_LowToHighCmp (
	xBTree_Node_t *pNode1, xBTree_Node_t *pNode2, xBTree_t *pBTree)
{
	register ifStackTable_t *pE1 = NULL, *pE2 = NULL;
	
	pE1 = xBTree_entry (pNode1, ifStackTable_t, oLowToHighBTreeNode);
	pE2 = xBTree_entry (pNode2, ifStackTable_t, oLowToHighBTreeNode);
	
	return
		(pE1->i32LowerLayer > pE2->i32LowerLayer) || (pE1->i32LowerLayer == pE2->i32LowerLayer && pE1->i32HigherLayer > pE2->i32HigherLayer) ? 1:
		(pE1->i32LowerLayer < pE2->i32LowerLayer) || (pE1->i32LowerLayer == pE2->i32LowerLayer && pE1->i32HigherLayer < pE2->i32HigherLayer) ? -1: 0;
}
