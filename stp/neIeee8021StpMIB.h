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

#ifndef __NEIEEE8021STPMIB_H__
#	define __NEIEEE8021STPMIB_H__

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
void neIeee8021StpMIB_init (void);


/**
 *	table mapper(s)
 */
/**
 *	table neIeee8021MstpCistTable definitions
 */
#define NEIEEE8021MSTPCISTADMINFLAGS 1
#define NEIEEE8021MSTPCISTTEMPLATEID 2

/* table neIeee8021MstpCistTable row entry data structure */
typedef struct neIeee8021MstpCistEntry_t
{
	/* Index values */
	uint32_t u32ComponentId;
	
	/* Column values */
	uint8_t au8AdminFlags[/* TODO: , BITS, "" */ TOBE_REPLACED];
	size_t u16AdminFlags_len;	/* # of uint8_t elements */
	uint32_t u32TemplateId;
	
	xBTree_Node_t oBTreeNode;
} neIeee8021MstpCistEntry_t;

extern xBTree_t oNeIeee8021MstpCistTable_BTree;

/* neIeee8021MstpCistTable table mapper */
void neIeee8021MstpCistTable_init (void);
neIeee8021MstpCistEntry_t * neIeee8021MstpCistTable_createEntry (
	uint32_t u32ComponentId);
neIeee8021MstpCistEntry_t * neIeee8021MstpCistTable_getByIndex (
	uint32_t u32ComponentId);
neIeee8021MstpCistEntry_t * neIeee8021MstpCistTable_getNextIndex (
	uint32_t u32ComponentId);
void neIeee8021MstpCistTable_removeEntry (neIeee8021MstpCistEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point neIeee8021MstpCistTable_getFirst;
Netsnmp_Next_Data_Point neIeee8021MstpCistTable_getNext;
Netsnmp_Get_Data_Point neIeee8021MstpCistTable_get;
Netsnmp_Node_Handler neIeee8021MstpCistTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table neIeee8021MstpTable definitions
 */
#define NEIEEE8021MSTPADMINFLAGS 1
#define NEIEEE8021MSTPMSTITYPE 2

enum
{
	/* enums for column neIeee8021MstpMstiType */
	neIeee8021MstpMstiType_mstp_c = 1,
	neIeee8021MstpMstiType_spb_c = 2,
};

/* table neIeee8021MstpTable row entry data structure */
typedef struct neIeee8021MstpEntry_t
{
	/* Index values */
	uint32_t u32ComponentId;
	uint16_t u16Id;
	
	/* Column values */
	uint8_t au8AdminFlags[/* TODO: , BITS, "" */ TOBE_REPLACED];
	size_t u16AdminFlags_len;	/* # of uint8_t elements */
	int32_t i32MstiType;
	
	xBTree_Node_t oBTreeNode;
} neIeee8021MstpEntry_t;

extern xBTree_t oNeIeee8021MstpTable_BTree;

/* neIeee8021MstpTable table mapper */
void neIeee8021MstpTable_init (void);
neIeee8021MstpEntry_t * neIeee8021MstpTable_createEntry (
	uint32_t u32ComponentId,
	uint16_t u16Id);
neIeee8021MstpEntry_t * neIeee8021MstpTable_getByIndex (
	uint32_t u32ComponentId,
	uint16_t u16Id);
neIeee8021MstpEntry_t * neIeee8021MstpTable_getNextIndex (
	uint32_t u32ComponentId,
	uint16_t u16Id);
void neIeee8021MstpTable_removeEntry (neIeee8021MstpEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point neIeee8021MstpTable_getFirst;
Netsnmp_Next_Data_Point neIeee8021MstpTable_getNext;
Netsnmp_Get_Data_Point neIeee8021MstpTable_get;
Netsnmp_Node_Handler neIeee8021MstpTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table neIeee8021MstpCistPortTable definitions
 */
#define NEIEEE8021MSTPCISTPORTRESTRICTEDDOMAINROLE 1

enum
{
	/* enums for column neIeee8021MstpCistPortRestrictedDomainRole */
	neIeee8021MstpCistPortRestrictedDomainRole_true_c = 1,
	neIeee8021MstpCistPortRestrictedDomainRole_false_c = 2,
};

/* table neIeee8021MstpCistPortTable row entry data structure */
typedef struct neIeee8021MstpCistPortEntry_t
{
	/* Index values */
	uint32_t u32ComponentId;
	uint32_t u32Num;
	
	/* Column values */
	uint8_t u8RestrictedDomainRole;
	
	xBTree_Node_t oBTreeNode;
} neIeee8021MstpCistPortEntry_t;

extern xBTree_t oNeIeee8021MstpCistPortTable_BTree;

/* neIeee8021MstpCistPortTable table mapper */
void neIeee8021MstpCistPortTable_init (void);
neIeee8021MstpCistPortEntry_t * neIeee8021MstpCistPortTable_createEntry (
	uint32_t u32ComponentId,
	uint32_t u32Num);
neIeee8021MstpCistPortEntry_t * neIeee8021MstpCistPortTable_getByIndex (
	uint32_t u32ComponentId,
	uint32_t u32Num);
neIeee8021MstpCistPortEntry_t * neIeee8021MstpCistPortTable_getNextIndex (
	uint32_t u32ComponentId,
	uint32_t u32Num);
void neIeee8021MstpCistPortTable_removeEntry (neIeee8021MstpCistPortEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point neIeee8021MstpCistPortTable_getFirst;
Netsnmp_Next_Data_Point neIeee8021MstpCistPortTable_getNext;
Netsnmp_Get_Data_Point neIeee8021MstpCistPortTable_get;
Netsnmp_Node_Handler neIeee8021MstpCistPortTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table neIeee8021MstpPortTable definitions
 */
#define NEIEEE8021MSTPPORTFLAGS 1

/* table neIeee8021MstpPortTable row entry data structure */
typedef struct neIeee8021MstpPortEntry_t
{
	/* Index values */
	uint32_t u32ComponentId;
	uint16_t u16MstId;
	uint32_t u32Num;
	
	/* Column values */
	uint8_t au8Flags[/* TODO: , BITS, "" */ TOBE_REPLACED];
	size_t u16Flags_len;	/* # of uint8_t elements */
	
	xBTree_Node_t oBTreeNode;
} neIeee8021MstpPortEntry_t;

extern xBTree_t oNeIeee8021MstpPortTable_BTree;

/* neIeee8021MstpPortTable table mapper */
void neIeee8021MstpPortTable_init (void);
neIeee8021MstpPortEntry_t * neIeee8021MstpPortTable_createEntry (
	uint32_t u32ComponentId,
	uint16_t u16MstId,
	uint32_t u32Num);
neIeee8021MstpPortEntry_t * neIeee8021MstpPortTable_getByIndex (
	uint32_t u32ComponentId,
	uint16_t u16MstId,
	uint32_t u32Num);
neIeee8021MstpPortEntry_t * neIeee8021MstpPortTable_getNextIndex (
	uint32_t u32ComponentId,
	uint16_t u16MstId,
	uint32_t u32Num);
void neIeee8021MstpPortTable_removeEntry (neIeee8021MstpPortEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point neIeee8021MstpPortTable_getFirst;
Netsnmp_Next_Data_Point neIeee8021MstpPortTable_getNext;
Netsnmp_Get_Data_Point neIeee8021MstpPortTable_get;
Netsnmp_Node_Handler neIeee8021MstpPortTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table neIeee8021MstpFidToMstiV2Table definitions
 */
#define NEIEEE8021MSTPFIDTOMSTIV2SPTID 1

/* table neIeee8021MstpFidToMstiV2Table row entry data structure */
typedef struct neIeee8021MstpFidToMstiV2Entry_t
{
	/* Index values */
	uint32_t u32ComponentId;
	uint32_t u32Fid;
	
	/* Column values */
	uint16_t u16SptId;
	
	xBTree_Node_t oBTreeNode;
} neIeee8021MstpFidToMstiV2Entry_t;

extern xBTree_t oNeIeee8021MstpFidToMstiV2Table_BTree;

/* neIeee8021MstpFidToMstiV2Table table mapper */
void neIeee8021MstpFidToMstiV2Table_init (void);
neIeee8021MstpFidToMstiV2Entry_t * neIeee8021MstpFidToMstiV2Table_createEntry (
	uint32_t u32ComponentId,
	uint32_t u32Fid);
neIeee8021MstpFidToMstiV2Entry_t * neIeee8021MstpFidToMstiV2Table_getByIndex (
	uint32_t u32ComponentId,
	uint32_t u32Fid);
neIeee8021MstpFidToMstiV2Entry_t * neIeee8021MstpFidToMstiV2Table_getNextIndex (
	uint32_t u32ComponentId,
	uint32_t u32Fid);
void neIeee8021MstpFidToMstiV2Table_removeEntry (neIeee8021MstpFidToMstiV2Entry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point neIeee8021MstpFidToMstiV2Table_getFirst;
Netsnmp_Next_Data_Point neIeee8021MstpFidToMstiV2Table_getNext;
Netsnmp_Get_Data_Point neIeee8021MstpFidToMstiV2Table_get;
Netsnmp_Node_Handler neIeee8021MstpFidToMstiV2Table_mapper;
#endif	/* SNMP_SRC */


/**
 *	table neIeee8021MstpVlanV2Table definitions
 */
#define NEIEEE8021MSTPVLANV2SPTID 1

/* table neIeee8021MstpVlanV2Table row entry data structure */
typedef struct neIeee8021MstpVlanV2Entry_t
{
	/* Index values */
	uint32_t u32ComponentId;
	uint32_t u32Id;
	
	/* Column values */
	uint16_t u16SptId;
	
	xBTree_Node_t oBTreeNode;
} neIeee8021MstpVlanV2Entry_t;

extern xBTree_t oNeIeee8021MstpVlanV2Table_BTree;

/* neIeee8021MstpVlanV2Table table mapper */
void neIeee8021MstpVlanV2Table_init (void);
neIeee8021MstpVlanV2Entry_t * neIeee8021MstpVlanV2Table_createEntry (
	uint32_t u32ComponentId,
	uint32_t u32Id);
neIeee8021MstpVlanV2Entry_t * neIeee8021MstpVlanV2Table_getByIndex (
	uint32_t u32ComponentId,
	uint32_t u32Id);
neIeee8021MstpVlanV2Entry_t * neIeee8021MstpVlanV2Table_getNextIndex (
	uint32_t u32ComponentId,
	uint32_t u32Id);
void neIeee8021MstpVlanV2Table_removeEntry (neIeee8021MstpVlanV2Entry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point neIeee8021MstpVlanV2Table_getFirst;
Netsnmp_Next_Data_Point neIeee8021MstpVlanV2Table_getNext;
Netsnmp_Get_Data_Point neIeee8021MstpVlanV2Table_get;
Netsnmp_Node_Handler neIeee8021MstpVlanV2Table_mapper;
#endif	/* SNMP_SRC */



#	ifdef __cplusplus
}
#	endif

#endif /* __NEIEEE8021STPMIB_H__ */
