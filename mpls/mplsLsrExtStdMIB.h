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

#ifndef __MPLSLSREXTSTDMIB_H__
#	define __MPLSLSREXTSTDMIB_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include "lib/binaryTree.h"
#include "lib/snmp.h"

#include <stdbool.h>
#include <stdint.h>

#define TOBE_REPLACED 1


/**
 *	agent MIB function
 */
void mplsLsrExtStdMIB_init (void);


/**
 *	table mapper(s)
 */
/**
 *	table mplsXCExtTable definitions
 */
#define MPLSXCEXTTUNNELPOINTER 1
#define MPLSXCEXTOPPOSITEDIRXCPTR 2

/* table mplsXCExtTable row entry data structure */
typedef struct mplsXCExtEntry_t
{
	/* Index values */
// 	uint8_t au8Index[24];
// 	size_t u16Index_len;	/* # of uint8_t elements */
// 	uint8_t au8InSegmentIndex[24];
// 	size_t u16InSegmentIndex_len;	/* # of uint8_t elements */
// 	uint8_t au8OutSegmentIndex[24];
// 	size_t u16OutSegmentIndex_len;	/* # of uint8_t elements */
	
	/* Column values */
	xOid_t aoTunnelPointer[128];
	size_t u16TunnelPointer_len;	/* # of xOid_t elements */
	xOid_t aoOppositeDirXCPtr[128];
	size_t u16OppositeDirXCPtr_len;	/* # of xOid_t elements */
	
// 	xBTree_Node_t oBTreeNode;
} mplsXCExtEntry_t;

// extern xBTree_t oMplsXCExtTable_BTree;

/* mplsXCExtTable table mapper */
void mplsXCExtTable_init (void);
mplsXCExtEntry_t * mplsXCExtTable_createEntry (
	uint8_t *pau8Index, size_t u16Index_len,
	uint8_t *pau8InSegmentIndex, size_t u16InSegmentIndex_len,
	uint8_t *pau8OutSegmentIndex, size_t u16OutSegmentIndex_len);
mplsXCExtEntry_t * mplsXCExtTable_getByIndex (
	uint8_t *pau8Index, size_t u16Index_len,
	uint8_t *pau8InSegmentIndex, size_t u16InSegmentIndex_len,
	uint8_t *pau8OutSegmentIndex, size_t u16OutSegmentIndex_len);
mplsXCExtEntry_t * mplsXCExtTable_getNextIndex (
	uint8_t *pau8Index, size_t u16Index_len,
	uint8_t *pau8InSegmentIndex, size_t u16InSegmentIndex_len,
	uint8_t *pau8OutSegmentIndex, size_t u16OutSegmentIndex_len);
void mplsXCExtTable_removeEntry (mplsXCExtEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point mplsXCExtTable_getFirst;
Netsnmp_Next_Data_Point mplsXCExtTable_getNext;
Netsnmp_Get_Data_Point mplsXCExtTable_get;
Netsnmp_Node_Handler mplsXCExtTable_mapper;
#endif	/* SNMP_SRC */



#	ifdef __cplusplus
}
#	endif

#endif /* __MPLSLSREXTSTDMIB_H__ */
