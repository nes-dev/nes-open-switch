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

#ifndef __LIST_C__
#	define __LIST_C__



#include "list.h"


void
xSList_nodeAddTail (
	xSList_Node_t *pNewNode, xSList_Head_t *pList)
{
	pNewNode->pPrev = pList->pLast;
	pList->pLast = pNewNode;
	
	if (pList->pFirst == NULL)
	{
		pList->pFirst = pNewNode;
	}
	pList->u32NumNode++;
	
	return;
}

void
xSList_nodeAddHead (
	xSList_Node_t *pNewNode, xSList_Head_t *pList)
{
	if (pList->pFirst != NULL)
	{
		pList->pFirst->pPrev = pNewNode;
	}
	
	pList->pFirst = pNewNode;
	pNewNode->pPrev = NULL;
	
	if (pList->pLast == NULL)
	{
		pList->pLast = pNewNode;
	}
	pList->u32NumNode++;
	
	return;
}

void
xSList_nodeRem (
	xSList_Node_t *pOldNode, xSList_Head_t *pList)
{
	for (register xSList_Node_t *pNext = NULL, *pNode = pList->pLast; pNode != NULL; pNode = pNode->pPrev)
	{
		if (pNode == pOldNode)
		{
			if (pNext != NULL)
			{
				pNext->pPrev = pOldNode->pPrev;
			}
			
			if (pList->pLast == pOldNode) /* pNext == NULL */
			{
				pList->pLast = pOldNode->pPrev;
			}
			if (pList->pFirst == pOldNode)
			{
				pList->pFirst = pNext;
			}
			
			pOldNode->pPrev = NULL;
			pList->u32NumNode--;
			break;
		}
		
		pNext = pNode;
	}
	
	if (pList->pFirst == pOldNode)
	{
		pList->pFirst = NULL;
	}
	
	return;
}

xSList_Node_t *
xSList_remTail (
	xSList_Head_t *pList)
{
	register xSList_Node_t *pNode = NULL;
	
	if (pList->pLast == NULL)
	{
		return NULL;
	}
	
	pNode = pList->pLast;
	pList->pLast = pNode->pPrev;
	if (pList->pFirst == pNode)
	{
		pList->pFirst = NULL;
	}
	
	pNode->pPrev = NULL;
	pList->u32NumNode--;
	
	return pNode;
}

xSList_Node_t *
xSList_remHead (
	xSList_Head_t *pList)
{
	register xSList_Node_t *pNode = NULL;
	
	if (pList->pFirst == NULL)
	{
		return NULL;
	}
	
	pNode = pList->pFirst;
	xSList_nodeRem (pNode, pList);
	
	return pNode;
}



#endif	// __LIST_C__
