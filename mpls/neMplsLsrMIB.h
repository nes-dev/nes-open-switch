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

#ifndef __NEMPLSLSRMIB_H__
#	define __NEMPLSLSRMIB_H__

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
void neMplsLsrMIB_init (void);


/**
 *	table mapper(s)
 */
/**
 *	table neMplsLabelScopeTable definitions
 */
#define NEMPLSLABELSCOPEINDEX 1
#define NEMPLSLABELSCOPETYPE 2
#define NEMPLSLABELSCOPELABELTYPE 3
#define NEMPLSLABELSCOPEIFINDEX 4
#define NEMPLSLABELSCOPENEIGHBOURADDRTYPE 5
#define NEMPLSLABELSCOPENEIGHBOURADDRESS 6
#define NEMPLSLABELSCOPEROWSTATUS 7
#define NEMPLSLABELSCOPESTORAGETYPE 8

enum
{
	/* enums for column neMplsLabelScopeType */
	neMplsLabelScopeType_platform_c = 1,
	neMplsLabelScopeType_interface_c = 2,
	neMplsLabelScopeType_upstreamAssigned_c = 3,

	/* enums for column neMplsLabelScopeLabelType */
	neMplsLabelScopeLabelType_ethernet_c = 1,
	neMplsLabelScopeLabelType_atm_c = 2,
	neMplsLabelScopeLabelType_frameRelay_c = 3,
	neMplsLabelScopeLabelType_evpl_c = 4,
	neMplsLabelScopeLabelType_pbbTe_c = 5,
	neMplsLabelScopeLabelType_l2sc_c = 6,
	neMplsLabelScopeLabelType_sonet_c = 7,
	neMplsLabelScopeLabelType_sdh_c = 8,
	neMplsLabelScopeLabelType_otn_c = 9,
	neMplsLabelScopeLabelType_dcsc_c = 10,
	neMplsLabelScopeLabelType_waveband_c = 11,
	neMplsLabelScopeLabelType_lambda_c = 12,
	neMplsLabelScopeLabelType_fiber_c = 13,

	/* enums for column neMplsLabelScopeNeighbourAddrType */
	neMplsLabelScopeNeighbourAddrType_unknown_c = 0,
	neMplsLabelScopeNeighbourAddrType_ipv4_c = 1,
	neMplsLabelScopeNeighbourAddrType_ipv6_c = 2,
	neMplsLabelScopeNeighbourAddrType_ipv4z_c = 3,
	neMplsLabelScopeNeighbourAddrType_ipv6z_c = 4,
	neMplsLabelScopeNeighbourAddrType_dns_c = 16,

	/* enums for column neMplsLabelScopeRowStatus */
	neMplsLabelScopeRowStatus_active_c = 1,
	neMplsLabelScopeRowStatus_notInService_c = 2,
	neMplsLabelScopeRowStatus_notReady_c = 3,
	neMplsLabelScopeRowStatus_createAndGo_c = 4,
	neMplsLabelScopeRowStatus_createAndWait_c = 5,
	neMplsLabelScopeRowStatus_destroy_c = 6,

	/* enums for column neMplsLabelScopeStorageType */
	neMplsLabelScopeStorageType_other_c = 1,
	neMplsLabelScopeStorageType_volatile_c = 2,
	neMplsLabelScopeStorageType_nonVolatile_c = 3,
	neMplsLabelScopeStorageType_permanent_c = 4,
	neMplsLabelScopeStorageType_readOnly_c = 5,
};

/* table neMplsLabelScopeTable row entry data structure */
typedef struct neMplsLabelScopeEntry_t
{
	/* Index values */
	uint32_t u32Index;
	
	/* Column values */
	int32_t i32Type;
	int32_t i32LabelType;
	uint32_t u32IfIndex;
	int32_t i32NeighbourAddrType;
	uint8_t au8NeighbourAddress[20];
	size_t u16NeighbourAddress_len;	/* # of uint8_t elements */
	uint8_t u8RowStatus;
	uint8_t u8StorageType;
	
	xBTree_Node_t oBTreeNode;
} neMplsLabelScopeEntry_t;

extern xBTree_t oNeMplsLabelScopeTable_BTree;

/* neMplsLabelScopeTable table mapper */
void neMplsLabelScopeTable_init (void);
neMplsLabelScopeEntry_t * neMplsLabelScopeTable_createEntry (
	uint32_t u32Index);
neMplsLabelScopeEntry_t * neMplsLabelScopeTable_getByIndex (
	uint32_t u32Index);
neMplsLabelScopeEntry_t * neMplsLabelScopeTable_getNextIndex (
	uint32_t u32Index);
void neMplsLabelScopeTable_removeEntry (neMplsLabelScopeEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point neMplsLabelScopeTable_getFirst;
Netsnmp_Next_Data_Point neMplsLabelScopeTable_getNext;
Netsnmp_Get_Data_Point neMplsLabelScopeTable_get;
Netsnmp_Node_Handler neMplsLabelScopeTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table neMplsLabelRangeTable definitions
 */
#define NEMPLSLABELRANGEMIN 1
#define NEMPLSLABELRANGEMAX 2
#define NEMPLSLABELRANGEIFINDEX 3
#define NEMPLSLABELRANGEROWSTATUS 4
#define NEMPLSLABELRANGESTORAGETYPE 5

enum
{
	/* enums for column neMplsLabelRangeRowStatus */
	neMplsLabelRangeRowStatus_active_c = 1,
	neMplsLabelRangeRowStatus_notInService_c = 2,
	neMplsLabelRangeRowStatus_notReady_c = 3,
	neMplsLabelRangeRowStatus_createAndGo_c = 4,
	neMplsLabelRangeRowStatus_createAndWait_c = 5,
	neMplsLabelRangeRowStatus_destroy_c = 6,

	/* enums for column neMplsLabelRangeStorageType */
	neMplsLabelRangeStorageType_other_c = 1,
	neMplsLabelRangeStorageType_volatile_c = 2,
	neMplsLabelRangeStorageType_nonVolatile_c = 3,
	neMplsLabelRangeStorageType_permanent_c = 4,
	neMplsLabelRangeStorageType_readOnly_c = 5,
};

/* table neMplsLabelRangeTable row entry data structure */
typedef struct neMplsLabelRangeEntry_t
{
	/* Index values */
	uint32_t u32ScopeIndex;
	uint8_t au8Min[64];
	size_t u16Min_len;	/* # of uint8_t elements */
	uint8_t au8Max[64];
	size_t u16Max_len;	/* # of uint8_t elements */
	uint32_t u32IfIndex;
	
	/* Column values */
	uint8_t u8RowStatus;
	uint8_t u8StorageType;
	
	xBTree_Node_t oBTreeNode;
} neMplsLabelRangeEntry_t;

extern xBTree_t oNeMplsLabelRangeTable_BTree;

/* neMplsLabelRangeTable table mapper */
void neMplsLabelRangeTable_init (void);
neMplsLabelRangeEntry_t * neMplsLabelRangeTable_createEntry (
	uint32_t u32ScopeIndex,
	uint8_t *pau8Min, size_t u16Min_len,
	uint8_t *pau8Max, size_t u16Max_len,
	uint32_t u32IfIndex);
neMplsLabelRangeEntry_t * neMplsLabelRangeTable_getByIndex (
	uint32_t u32ScopeIndex,
	uint8_t *pau8Min, size_t u16Min_len,
	uint8_t *pau8Max, size_t u16Max_len,
	uint32_t u32IfIndex);
neMplsLabelRangeEntry_t * neMplsLabelRangeTable_getNextIndex (
	uint32_t u32ScopeIndex,
	uint8_t *pau8Min, size_t u16Min_len,
	uint8_t *pau8Max, size_t u16Max_len,
	uint32_t u32IfIndex);
void neMplsLabelRangeTable_removeEntry (neMplsLabelRangeEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point neMplsLabelRangeTable_getFirst;
Netsnmp_Next_Data_Point neMplsLabelRangeTable_getNext;
Netsnmp_Get_Data_Point neMplsLabelRangeTable_get;
Netsnmp_Node_Handler neMplsLabelRangeTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table neMplsInSegmentTable definitions
 */
#define NEMPLSINSEGMENTLABELTYPE 1
#define NEMPLSINSEGMENTLABEL 2

enum
{
	/* enums for column neMplsInSegmentLabelType */
	neMplsInSegmentLabelType_ethernet_c = 1,
	neMplsInSegmentLabelType_atm_c = 2,
	neMplsInSegmentLabelType_frameRelay_c = 3,
	neMplsInSegmentLabelType_evpl_c = 4,
	neMplsInSegmentLabelType_pbbTe_c = 5,
	neMplsInSegmentLabelType_l2sc_c = 6,
	neMplsInSegmentLabelType_sonet_c = 7,
	neMplsInSegmentLabelType_sdh_c = 8,
	neMplsInSegmentLabelType_otn_c = 9,
	neMplsInSegmentLabelType_dcsc_c = 10,
	neMplsInSegmentLabelType_waveband_c = 11,
	neMplsInSegmentLabelType_lambda_c = 12,
	neMplsInSegmentLabelType_fiber_c = 13,
};

/* table neMplsInSegmentTable row entry data structure */
typedef struct neMplsInSegmentEntry_t
{
	/* Index values */
	uint8_t au8Index[24];
	size_t u16Index_len;	/* # of uint8_t elements */
	
	/* Column values */
	int32_t i32LabelType;
	uint8_t au8Label[64];
	size_t u16Label_len;	/* # of uint8_t elements */
	
	xBTree_Node_t oBTreeNode;
} neMplsInSegmentEntry_t;

extern xBTree_t oNeMplsInSegmentTable_BTree;

/* neMplsInSegmentTable table mapper */
void neMplsInSegmentTable_init (void);
neMplsInSegmentEntry_t * neMplsInSegmentTable_createEntry (
	uint8_t *pau8Index, size_t u16Index_len);
neMplsInSegmentEntry_t * neMplsInSegmentTable_getByIndex (
	uint8_t *pau8Index, size_t u16Index_len);
neMplsInSegmentEntry_t * neMplsInSegmentTable_getNextIndex (
	uint8_t *pau8Index, size_t u16Index_len);
void neMplsInSegmentTable_removeEntry (neMplsInSegmentEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point neMplsInSegmentTable_getFirst;
Netsnmp_Next_Data_Point neMplsInSegmentTable_getNext;
Netsnmp_Get_Data_Point neMplsInSegmentTable_get;
Netsnmp_Node_Handler neMplsInSegmentTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table neMplsOutSegmentTable definitions
 */
#define NEMPLSOUTSEGMENTLABELTYPE 1
#define NEMPLSOUTSEGMENTTOPLABEL 2
#define NEMPLSOUTSEGMENTSWAPLABEL 3
#define NEMPLSOUTSEGMENTNEXTHOPPHYSADDRESS 4

enum
{
	/* enums for column neMplsOutSegmentLabelType */
	neMplsOutSegmentLabelType_ethernet_c = 1,
	neMplsOutSegmentLabelType_atm_c = 2,
	neMplsOutSegmentLabelType_frameRelay_c = 3,
	neMplsOutSegmentLabelType_evpl_c = 4,
	neMplsOutSegmentLabelType_pbbTe_c = 5,
	neMplsOutSegmentLabelType_l2sc_c = 6,
	neMplsOutSegmentLabelType_sonet_c = 7,
	neMplsOutSegmentLabelType_sdh_c = 8,
	neMplsOutSegmentLabelType_otn_c = 9,
	neMplsOutSegmentLabelType_dcsc_c = 10,
	neMplsOutSegmentLabelType_waveband_c = 11,
	neMplsOutSegmentLabelType_lambda_c = 12,
	neMplsOutSegmentLabelType_fiber_c = 13,
};

/* table neMplsOutSegmentTable row entry data structure */
typedef struct neMplsOutSegmentEntry_t
{
	/* Index values */
	uint8_t au8Index[24];
	size_t u16Index_len;	/* # of uint8_t elements */
	
	/* Column values */
	int32_t i32LabelType;
	uint8_t au8TopLabel[64];
	size_t u16TopLabel_len;	/* # of uint8_t elements */
	uint8_t au8SwapLabel[64];
	size_t u16SwapLabel_len;	/* # of uint8_t elements */
	uint8_t au8NextHopPhysAddress[8];
	size_t u16NextHopPhysAddress_len;	/* # of uint8_t elements */
	
	xBTree_Node_t oBTreeNode;
} neMplsOutSegmentEntry_t;

extern xBTree_t oNeMplsOutSegmentTable_BTree;

/* neMplsOutSegmentTable table mapper */
void neMplsOutSegmentTable_init (void);
neMplsOutSegmentEntry_t * neMplsOutSegmentTable_createEntry (
	uint8_t *pau8Index, size_t u16Index_len);
neMplsOutSegmentEntry_t * neMplsOutSegmentTable_getByIndex (
	uint8_t *pau8Index, size_t u16Index_len);
neMplsOutSegmentEntry_t * neMplsOutSegmentTable_getNextIndex (
	uint8_t *pau8Index, size_t u16Index_len);
void neMplsOutSegmentTable_removeEntry (neMplsOutSegmentEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point neMplsOutSegmentTable_getFirst;
Netsnmp_Next_Data_Point neMplsOutSegmentTable_getNext;
Netsnmp_Get_Data_Point neMplsOutSegmentTable_get;
Netsnmp_Node_Handler neMplsOutSegmentTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table neMplsXCTable definitions
 */
#define NEMPLSXCTYPE 1

enum
{
	/* enums for column neMplsXCType */
	neMplsXCType_lsp_c = 0,
	neMplsXCType_pw_c = 1,
	neMplsXCType_stitching_c = 2,
	neMplsXCType_hierarchy_c = 3,
	neMplsXCType_p2mp_c = 4,
	neMplsXCType_unknown_c = 5,
};

/* table neMplsXCTable row entry data structure */
typedef struct neMplsXCEntry_t
{
	/* Index values */
	uint8_t au8Index[24];
	size_t u16Index_len;	/* # of uint8_t elements */
	uint8_t au8InSegmentIndex[24];
	size_t u16InSegmentIndex_len;	/* # of uint8_t elements */
	uint8_t au8OutSegmentIndex[24];
	size_t u16OutSegmentIndex_len;	/* # of uint8_t elements */
	
	/* Column values */
	uint8_t au8Type[1];
	size_t u16Type_len;	/* # of uint8_t elements */
	
	xBTree_Node_t oBTreeNode;
} neMplsXCEntry_t;

extern xBTree_t oNeMplsXCTable_BTree;

/* neMplsXCTable table mapper */
void neMplsXCTable_init (void);
neMplsXCEntry_t * neMplsXCTable_createEntry (
	uint8_t *pau8Index, size_t u16Index_len,
	uint8_t *pau8InSegmentIndex, size_t u16InSegmentIndex_len,
	uint8_t *pau8OutSegmentIndex, size_t u16OutSegmentIndex_len);
neMplsXCEntry_t * neMplsXCTable_getByIndex (
	uint8_t *pau8Index, size_t u16Index_len,
	uint8_t *pau8InSegmentIndex, size_t u16InSegmentIndex_len,
	uint8_t *pau8OutSegmentIndex, size_t u16OutSegmentIndex_len);
neMplsXCEntry_t * neMplsXCTable_getNextIndex (
	uint8_t *pau8Index, size_t u16Index_len,
	uint8_t *pau8InSegmentIndex, size_t u16InSegmentIndex_len,
	uint8_t *pau8OutSegmentIndex, size_t u16OutSegmentIndex_len);
void neMplsXCTable_removeEntry (neMplsXCEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point neMplsXCTable_getFirst;
Netsnmp_Next_Data_Point neMplsXCTable_getNext;
Netsnmp_Get_Data_Point neMplsXCTable_get;
Netsnmp_Node_Handler neMplsXCTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table neMplsLabelStackTable definitions
 */
#define NEMPLSLABELSTACKLABELTYPE 1
#define NEMPLSLABELSTACKLABEL 2

enum
{
	/* enums for column neMplsLabelStackLabelType */
	neMplsLabelStackLabelType_ethernet_c = 1,
	neMplsLabelStackLabelType_atm_c = 2,
	neMplsLabelStackLabelType_frameRelay_c = 3,
	neMplsLabelStackLabelType_evpl_c = 4,
	neMplsLabelStackLabelType_pbbTe_c = 5,
	neMplsLabelStackLabelType_l2sc_c = 6,
	neMplsLabelStackLabelType_sonet_c = 7,
	neMplsLabelStackLabelType_sdh_c = 8,
	neMplsLabelStackLabelType_otn_c = 9,
	neMplsLabelStackLabelType_dcsc_c = 10,
	neMplsLabelStackLabelType_waveband_c = 11,
	neMplsLabelStackLabelType_lambda_c = 12,
	neMplsLabelStackLabelType_fiber_c = 13,
};

/* table neMplsLabelStackTable row entry data structure */
typedef struct neMplsLabelStackEntry_t
{
	/* Index values */
	uint8_t au8Index[24];
	size_t u16Index_len;	/* # of uint8_t elements */
	uint32_t u32LabelIndex;
	
	/* Column values */
	int32_t i32LabelType;
	uint8_t au8Label[64];
	size_t u16Label_len;	/* # of uint8_t elements */
	
	xBTree_Node_t oBTreeNode;
} neMplsLabelStackEntry_t;

extern xBTree_t oNeMplsLabelStackTable_BTree;

/* neMplsLabelStackTable table mapper */
void neMplsLabelStackTable_init (void);
neMplsLabelStackEntry_t * neMplsLabelStackTable_createEntry (
	uint8_t *pau8Index, size_t u16Index_len,
	uint32_t u32LabelIndex);
neMplsLabelStackEntry_t * neMplsLabelStackTable_getByIndex (
	uint8_t *pau8Index, size_t u16Index_len,
	uint32_t u32LabelIndex);
neMplsLabelStackEntry_t * neMplsLabelStackTable_getNextIndex (
	uint8_t *pau8Index, size_t u16Index_len,
	uint32_t u32LabelIndex);
void neMplsLabelStackTable_removeEntry (neMplsLabelStackEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point neMplsLabelStackTable_getFirst;
Netsnmp_Next_Data_Point neMplsLabelStackTable_getNext;
Netsnmp_Get_Data_Point neMplsLabelStackTable_get;
Netsnmp_Node_Handler neMplsLabelStackTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table neMplsSegmentMapTable definitions
 */
#define NEMPLSSEGMENTMAPTYPE 1
#define NEMPLSSEGMENTMAPLABELTYPE 2
#define NEMPLSSEGMENTMAPLABEL 3
#define NEMPLSSEGMENTMAPSEGMENT 4

enum
{
	/* enums for column neMplsSegmentMapType */
	neMplsSegmentMapType_egress_c = 1,
	neMplsSegmentMapType_ingress_c = 2,

	/* enums for column neMplsSegmentMapLabelType */
	neMplsSegmentMapLabelType_ethernet_c = 1,
	neMplsSegmentMapLabelType_atm_c = 2,
	neMplsSegmentMapLabelType_frameRelay_c = 3,
	neMplsSegmentMapLabelType_evpl_c = 4,
	neMplsSegmentMapLabelType_pbbTe_c = 5,
	neMplsSegmentMapLabelType_l2sc_c = 6,
	neMplsSegmentMapLabelType_sonet_c = 7,
	neMplsSegmentMapLabelType_sdh_c = 8,
	neMplsSegmentMapLabelType_otn_c = 9,
	neMplsSegmentMapLabelType_dcsc_c = 10,
	neMplsSegmentMapLabelType_waveband_c = 11,
	neMplsSegmentMapLabelType_lambda_c = 12,
	neMplsSegmentMapLabelType_fiber_c = 13,
};

/* table neMplsSegmentMapTable row entry data structure */
typedef struct neMplsSegmentMapEntry_t
{
	/* Index values */
	uint32_t u32InterfaceIndex;
	int32_t i32Type;
	int32_t i32LabelType;
	uint8_t au8Label[64];
	size_t u16Label_len;	/* # of uint8_t elements */
	
	/* Column values */
	uint8_t au8Segment[24];
	size_t u16Segment_len;	/* # of uint8_t elements */
	
	xBTree_Node_t oBTreeNode;
} neMplsSegmentMapEntry_t;

extern xBTree_t oNeMplsSegmentMapTable_BTree;

/* neMplsSegmentMapTable table mapper */
void neMplsSegmentMapTable_init (void);
neMplsSegmentMapEntry_t * neMplsSegmentMapTable_createEntry (
	uint32_t u32InterfaceIndex,
	int32_t i32Type,
	int32_t i32LabelType,
	uint8_t *pau8Label, size_t u16Label_len);
neMplsSegmentMapEntry_t * neMplsSegmentMapTable_getByIndex (
	uint32_t u32InterfaceIndex,
	int32_t i32Type,
	int32_t i32LabelType,
	uint8_t *pau8Label, size_t u16Label_len);
neMplsSegmentMapEntry_t * neMplsSegmentMapTable_getNextIndex (
	uint32_t u32InterfaceIndex,
	int32_t i32Type,
	int32_t i32LabelType,
	uint8_t *pau8Label, size_t u16Label_len);
void neMplsSegmentMapTable_removeEntry (neMplsSegmentMapEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point neMplsSegmentMapTable_getFirst;
Netsnmp_Next_Data_Point neMplsSegmentMapTable_getNext;
Netsnmp_Get_Data_Point neMplsSegmentMapTable_get;
Netsnmp_Node_Handler neMplsSegmentMapTable_mapper;
#endif	/* SNMP_SRC */



#	ifdef __cplusplus
}
#	endif

#endif /* __NEMPLSLSRMIB_H__ */
