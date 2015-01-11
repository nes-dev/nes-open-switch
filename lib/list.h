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

#ifndef __LIST_H__
#	define __LIST_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include "lib.h"

#include <stddef.h>
#include <stdint.h>


typedef struct xSList_Node_t xSList_Node_t;

typedef struct xSList_Head_t
{
	xSList_Node_t    *pFirst;
	xSList_Node_t    *pLast;
	uint32_t        u32NumNode;
} xSList_Head_t;

struct xSList_Node_t
{
	struct xSList_Node_t *pPrev;
};


#define xSList_headInit(_pList) \
{\
	(_pList)->pFirst = NULL;\
	(_pList)->pLast = NULL;\
	(_pList)->u32NumNode = 0;\
}

#define xSList_headInitInline() \
{\
	.pFirst = NULL,\
	.pLast = NULL,\
	.u32NumNode = 0,\
}

#define xSList_nodeInit(_node) \
{\
	(_node)->pPrev = NULL;\
}

#define xSList_nodeInitInline() \
{\
	.pPrev = NULL,\
}

#define xSList_entry(_ptr, _type_t, _list_field) \
	xGetParentByMemberPtr (_ptr, _type_t, _list_field);\
	
#define xSList_nodeGetTail(_pList) \
	((_pList)->pLast)
	
#define xSList_nodeGetHead(_pList) \
	((_pList)->pFirst)
	
#define xSList_isEmpty(_pList) \
	((_pList)->pFirst == NULL && (_pList)->pLast == NULL)
	
extern void
	xSList_nodeAddTail (
		xSList_Node_t *pNewNode, xSList_Head_t *pList);
extern void
	xSList_nodeAddHead (
		xSList_Node_t *pNewNode, xSList_Head_t *pList);
extern void
	xSList_nodeRem (
		xSList_Node_t *pOldNode, xSList_Head_t *pList);
		
extern xSList_Node_t *
	xSList_remTail (
		xSList_Head_t *pList);
extern xSList_Node_t *
	xSList_remHead (
		xSList_Head_t *pList);
		
#define xSList_push(_pNewNode, _pList) \
	xSList_nodeAddHead (_pNewNode, _pList)
	
#define xSList_pop(_pList) \
    xSList_remTail (_pList)
    
#define xSList_count(_pList) \
	((_pList)->u32NumNode)
	
#define xSList_findElem(_field, _field_val, _list_field, _container_t, _pList) \
({\
	register _container_t *tmp_entry = NULL, *entry = NULL;\
	\
	for (register xSList_Node_t *_elem = (_pList)->pLast; _elem != NULL; _elem = _elem->pPrev)\
	{\
		tmp_entry = xSList_entry (_elem, _list_field, _container_t);\
		\
		if (tmp_entry->_field == (_field_val))\
		{\
			entry = tmp_entry;\
			break;\
		}\
	}\
	\
	entry;\
})

#define xSList_scanTail(_list_elem, _pList) \
	for (\
		(_list_elem) = (_pList)->pLast;\
		(_list_elem) != NULL;\
		(_list_elem) = (_list_elem)->pPrev\
	)\
	
#define xSList_scanTailSafe(_list_elem, _next_elem, _pList) \
	for (\
		(_list_elem) = (_pList)->pLast, (_next_elem) = (_list_elem) == NULL ? NULL: (_list_elem)->pPrev;\
		(_list_elem) != NULL;\
		(_list_elem) = (_next_elem), (_next_elem) = (_list_elem) == NULL ? NULL: (_list_elem)->pPrev\
	)\
	
#define xSList_prevElem(_list_field, _container_t, _elem) (\
	(_elem)->pPrev == NULL ? NULL: xSList_entry ((_elem)->pPrev, _list_field, _container_t)\
)


#if 0
typedef struct if_t {
	xSList_Node_t if_node;
	
	uint16_t index;
	uint32_t speed;
	if_duplex_t duplex;
	if_state_t state;
	
	_if_t dev;
} if_t;

xSList_Head_t if_list = xSList_headInitInline ();

if_t if_1 = {.index = 1};
if_t if_2 = {.index = 2};
if_t if_3 = {.index = 3};

xSList_add (&if_1, &if_list);
xSList_add (&if_2, &if_list);
xSList_add (&if_3, &if_list);
xSList_rem (&if_2, &if_list);

if_t *if_34 = xSList_findElem (index, 34, if_node, if_t, &if_list);
if_t *if_33 = xSList_prevElem (if_node, if_t, &if_34->if_node);
#endif



#	ifdef __cplusplus
}
#	endif

#endif	// __LIST_H__
