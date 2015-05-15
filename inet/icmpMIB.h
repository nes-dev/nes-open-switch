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

#ifndef __ICMPMIB_H__
#	define __ICMPMIB_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include "lib/binaryTree.h"
#include "lib/snmp.h"

#define TOBE_REPLACED 1


/**
 *	agent MIB function
 */
void icmpMIB_init (void);


/**
 *	table mapper(s)
 */
/**
 *	table icmpStatsTable definitions
 */
#define ICMPSTATSIPVERSION 1
#define ICMPSTATSINMSGS 2
#define ICMPSTATSINERRORS 3
#define ICMPSTATSOUTMSGS 4
#define ICMPSTATSOUTERRORS 5

enum
{
	/* enums for column icmpStatsIPVersion */
	icmpStatsIPVersion_unknown_c = 0,
	icmpStatsIPVersion_ipv4_c = 1,
	icmpStatsIPVersion_ipv6_c = 2,
};

/* table icmpStatsTable row entry data structure */
typedef struct icmpStatsEntry_t
{
	/* Index values */
	int32_t i32IPVersion;
	
	/* Column values */
	uint32_t u32InMsgs;
	uint32_t u32InErrors;
	uint32_t u32OutMsgs;
	uint32_t u32OutErrors;
	
	xBTree_Node_t oBTreeNode;
} icmpStatsEntry_t;

extern xBTree_t oIcmpStatsTable_BTree;

/* icmpStatsTable table mapper */
void icmpStatsTable_init (void);
icmpStatsEntry_t * icmpStatsTable_createEntry (
	int32_t i32IPVersion);
icmpStatsEntry_t * icmpStatsTable_getByIndex (
	int32_t i32IPVersion);
icmpStatsEntry_t * icmpStatsTable_getNextIndex (
	int32_t i32IPVersion);
void icmpStatsTable_removeEntry (icmpStatsEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point icmpStatsTable_getFirst;
Netsnmp_Next_Data_Point icmpStatsTable_getNext;
Netsnmp_Get_Data_Point icmpStatsTable_get;
Netsnmp_Node_Handler icmpStatsTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table icmpMsgStatsTable definitions
 */
#define ICMPMSGSTATSIPVERSION 1
#define ICMPMSGSTATSTYPE 2
#define ICMPMSGSTATSINPKTS 3
#define ICMPMSGSTATSOUTPKTS 4

enum
{
	/* enums for column icmpMsgStatsIPVersion */
	icmpMsgStatsIPVersion_unknown_c = 0,
	icmpMsgStatsIPVersion_ipv4_c = 1,
	icmpMsgStatsIPVersion_ipv6_c = 2,
};

/* table icmpMsgStatsTable row entry data structure */
typedef struct icmpMsgStatsEntry_t
{
	/* Index values */
	int32_t i32IPVersion;
	int32_t i32Type;
	
	/* Column values */
	uint32_t u32InPkts;
	uint32_t u32OutPkts;
	
	xBTree_Node_t oBTreeNode;
} icmpMsgStatsEntry_t;

extern xBTree_t oIcmpMsgStatsTable_BTree;

/* icmpMsgStatsTable table mapper */
void icmpMsgStatsTable_init (void);
icmpMsgStatsEntry_t * icmpMsgStatsTable_createEntry (
	int32_t i32IPVersion,
	int32_t i32Type);
icmpMsgStatsEntry_t * icmpMsgStatsTable_getByIndex (
	int32_t i32IPVersion,
	int32_t i32Type);
icmpMsgStatsEntry_t * icmpMsgStatsTable_getNextIndex (
	int32_t i32IPVersion,
	int32_t i32Type);
void icmpMsgStatsTable_removeEntry (icmpMsgStatsEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point icmpMsgStatsTable_getFirst;
Netsnmp_Next_Data_Point icmpMsgStatsTable_getNext;
Netsnmp_Get_Data_Point icmpMsgStatsTable_get;
Netsnmp_Node_Handler icmpMsgStatsTable_mapper;
#endif	/* SNMP_SRC */



#	ifdef __cplusplus
}
#	endif

#endif /* __ICMPMIB_H__ */
