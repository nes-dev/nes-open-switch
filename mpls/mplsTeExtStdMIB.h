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

#ifndef __MPLSTEEXTSTDMIB_H__
#	define __MPLSTEEXTSTDMIB_H__

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
void mplsTeExtStdMIB_init (void);


/**
 *	table mapper(s)
 */
/**
 *	table mplsTunnelExtTable definitions
 */
#define MPLSTUNNELEXTOPPOSITEDIRPTR 1
#define MPLSTUNNELEXTOPPOSITEDIRTNLVALID 2
#define MPLSTUNNELEXTDESTTNLINDEX 3
#define MPLSTUNNELEXTDESTTNLLSPINDEX 4
#define MPLSTUNNELEXTDESTTNLVALID 5
#define MPLSTUNNELEXTINGRESSLSRLOCALIDVALID 6
#define MPLSTUNNELEXTEGRESSLSRLOCALIDVALID 7

enum
{
	/* enums for column mplsTunnelExtOppositeDirTnlValid */
	mplsTunnelExtOppositeDirTnlValid_true_c = 1,
	mplsTunnelExtOppositeDirTnlValid_false_c = 2,

	/* enums for column mplsTunnelExtDestTnlValid */
	mplsTunnelExtDestTnlValid_true_c = 1,
	mplsTunnelExtDestTnlValid_false_c = 2,

	/* enums for column mplsTunnelExtIngressLSRLocalIdValid */
	mplsTunnelExtIngressLSRLocalIdValid_true_c = 1,
	mplsTunnelExtIngressLSRLocalIdValid_false_c = 2,

	/* enums for column mplsTunnelExtEgressLSRLocalIdValid */
	mplsTunnelExtEgressLSRLocalIdValid_true_c = 1,
	mplsTunnelExtEgressLSRLocalIdValid_false_c = 2,
};

/* table mplsTunnelExtTable row entry data structure */
typedef struct mplsTunnelExtEntry_t
{
	/* Index values */
// 	uint32_t u32Index;
// 	uint32_t u32Instance;
// 	uint32_t u32IngressLSRId;
// 	uint32_t u32EgressLSRId;
	
	/* Column values */
	xOid_t aoOppositeDirPtr[128];
	size_t u16OppositeDirPtr_len;	/* # of xOid_t elements */
	uint8_t u8OppositeDirTnlValid;
	uint32_t u32DestTnlIndex;
	uint32_t u32DestTnlLspIndex;
	uint8_t u8DestTnlValid;
	uint8_t u8IngressLSRLocalIdValid;
	uint8_t u8EgressLSRLocalIdValid;
	
// 	xBTree_Node_t oBTreeNode;
} mplsTunnelExtEntry_t;

// extern xBTree_t oMplsTunnelExtTable_BTree;

/* mplsTunnelExtTable table mapper */
void mplsTunnelExtTable_init (void);
mplsTunnelExtEntry_t * mplsTunnelExtTable_createEntry (
	uint32_t u32Index,
	uint32_t u32Instance,
	uint32_t u32IngressLSRId,
	uint32_t u32EgressLSRId);
mplsTunnelExtEntry_t * mplsTunnelExtTable_getByIndex (
	uint32_t u32Index,
	uint32_t u32Instance,
	uint32_t u32IngressLSRId,
	uint32_t u32EgressLSRId);
mplsTunnelExtEntry_t * mplsTunnelExtTable_getNextIndex (
	uint32_t u32Index,
	uint32_t u32Instance,
	uint32_t u32IngressLSRId,
	uint32_t u32EgressLSRId);
void mplsTunnelExtTable_removeEntry (mplsTunnelExtEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point mplsTunnelExtTable_getFirst;
Netsnmp_Next_Data_Point mplsTunnelExtTable_getNext;
Netsnmp_Get_Data_Point mplsTunnelExtTable_get;
Netsnmp_Node_Handler mplsTunnelExtTable_mapper;
#endif	/* SNMP_SRC */



#	ifdef __cplusplus
}
#	endif

#endif /* __MPLSTEEXTSTDMIB_H__ */
