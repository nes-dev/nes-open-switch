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

#ifndef __IEEE8021PBBMIB_H__
#	define __IEEE8021PBBMIB_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include "lib/binaryTree.h"
#include "lib/snmp.h"

#include <stdbool.h>

#define TOBE_REPLACED 1


/**
 *	agent MIB function
 */
void ieee8021PbbMib_init (void);


/**
 *	scalar mapper(s)
 */
/** definitions for scalar(s) of ieee8021PbbBackboneEdgeBridgeObjects **/
#define IEEE8021PBBBACKBONEEDGEBRIDGEADDRESS 1
#define IEEE8021PBBBACKBONEEDGEBRIDGENAME 2
#define IEEE8021PBBNUMBEROFICOMPONENTS 3
#define IEEE8021PBBNUMBEROFBCOMPONENTS 4
#define IEEE8021PBBNUMBEROFBEBPORTS 5
#define IEEE8021PBBNEXTAVAILABLEPIPIFINDEX 6

typedef struct ieee8021PbbBackboneEdgeBridgeObjects_t
{
	uint8_t au8BackboneEdgeBridgeAddress[6];
	size_t u16BackboneEdgeBridgeAddress_len;	/* # of uint8_t elements */
	uint8_t au8BackboneEdgeBridgeName[32];
	size_t u16BackboneEdgeBridgeName_len;	/* # of uint8_t elements */
	uint32_t u32NumberOfIComponents;
	uint32_t u32NumberOfBComponents;
	uint32_t u32NumberOfBebPorts;
	uint32_t u32NextAvailablePipIfIndex;
} ieee8021PbbBackboneEdgeBridgeObjects_t;

extern ieee8021PbbBackboneEdgeBridgeObjects_t oIeee8021PbbBackboneEdgeBridgeObjects;

#ifdef SNMP_SRC
Netsnmp_Node_Handler ieee8021PbbBackboneEdgeBridgeObjects_mapper;
#endif	/* SNMP_SRC */



/**
 *	table mapper(s)
 */
/**
 *	table ieee8021PbbVipTable definitions
 */
#define IEEE8021PBBVIPPIPIFINDEX 1
#define IEEE8021PBBVIPISID 2
#define IEEE8021PBBVIPDEFAULTDSTBMAC 3
#define IEEE8021PBBVIPTYPE 4
#define IEEE8021PBBVIPROWSTATUS 5
#define IEEE8021PBBVIPENABLECONNECTIONID 6

enum
{
	/* enums for column ieee8021PbbVipType */
	ieee8021PbbVipType_ingress_c = 0,
	ieee8021PbbVipType_egress_c = 1,

	/* enums for column ieee8021PbbVipRowStatus */
	ieee8021PbbVipRowStatus_active_c = 1,
	ieee8021PbbVipRowStatus_notInService_c = 2,
	ieee8021PbbVipRowStatus_notReady_c = 3,
	ieee8021PbbVipRowStatus_createAndGo_c = 4,
	ieee8021PbbVipRowStatus_createAndWait_c = 5,
	ieee8021PbbVipRowStatus_destroy_c = 6,

	/* enums for column ieee8021PbbVipEnableConnectionId */
	ieee8021PbbVipEnableConnectionId_true_c = 1,
	ieee8021PbbVipEnableConnectionId_false_c = 2,
};

/* table ieee8021PbbVipTable row entry data structure */
typedef struct ieee8021PbbVipEntry_t
{
	/* Index values */
	uint32_t u32BridgeBasePortComponentId;
	uint32_t u32BridgeBasePort;
	
	/* Column values */
	uint32_t u32PipIfIndex;
	uint32_t u32ISid;
	uint8_t au8DefaultDstBMAC[6];
	size_t u16DefaultDstBMAC_len;	/* # of uint8_t elements */
	uint8_t au8Type[1];
	size_t u16Type_len;	/* # of uint8_t elements */
	uint8_t u8RowStatus;
	int32_t i32EnableConnectionId;
	
	uint32_t u32ChassisId;
	struct ieee8021PbbVipEntry_t *pOldEntry;
	
	xBTree_Node_t oBTreeNode;
	xBTree_Node_t oISid_BTreeNode;
} ieee8021PbbVipEntry_t;

extern xBTree_t oIeee8021PbbVipTable_BTree;
extern xBTree_t oIeee8021PbbVipTable_ISid_BTree;

/* ieee8021PbbVipTable table mapper */
void ieee8021PbbVipTable_init (void);
ieee8021PbbVipEntry_t * ieee8021PbbVipTable_createEntry (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort);
ieee8021PbbVipEntry_t * ieee8021PbbVipTable_getByIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort);
ieee8021PbbVipEntry_t * ieee8021PbbVipTable_getNextIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort);
ieee8021PbbVipEntry_t * ieee8021PbbVipTable_ISid_getByIndex (
	uint32_t u32ChassisId,
	uint32_t u32ISid);
ieee8021PbbVipEntry_t * ieee8021PbbVipTable_ISid_getNextIndex (
	uint32_t u32ChassisId,
	uint32_t u32ISid);
void ieee8021PbbVipTable_removeEntry (ieee8021PbbVipEntry_t *poEntry);
ieee8021PbbVipEntry_t * ieee8021PbbVipTable_createExt (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort);
bool ieee8021PbbVipTable_removeExt (ieee8021PbbVipEntry_t *poEntry);
bool ieee8021PbbVipTable_createHier (ieee8021PbbVipEntry_t *poEntry);
bool ieee8021PbbVipTable_removeHier (ieee8021PbbVipEntry_t *poEntry);
bool ieee8021PbbVipRowStatus_handler (
	ieee8021PbbVipEntry_t *poEntry, uint8_t u8RowStatus);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021PbbVipTable_getFirst;
Netsnmp_Next_Data_Point ieee8021PbbVipTable_getNext;
Netsnmp_Get_Data_Point ieee8021PbbVipTable_get;
Netsnmp_Node_Handler ieee8021PbbVipTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021PbbISidToVipTable definitions
 */
#define IEEE8021PBBISIDTOVIPISID 1
#define IEEE8021PBBISIDTOVIPCOMPONENTID 2
#define IEEE8021PBBISIDTOVIPPORT 3

/* table ieee8021PbbISidToVipTable row entry data structure */
typedef struct ieee8021PbbISidToVipEntry_t
{
	/* Index values */
	uint32_t u32ISid;
	
	/* Column values */
	uint32_t u32ComponentId;
	uint32_t u32Port;
	
	xBTree_Node_t oBTreeNode;
} ieee8021PbbISidToVipEntry_t;

extern xBTree_t oIeee8021PbbISidToVipTable_BTree;

/* ieee8021PbbISidToVipTable table mapper */
void ieee8021PbbISidToVipTable_init (void);
ieee8021PbbISidToVipEntry_t * ieee8021PbbISidToVipTable_createEntry (
	uint32_t u32ISid);
ieee8021PbbISidToVipEntry_t * ieee8021PbbISidToVipTable_getByIndex (
	uint32_t u32ISid);
ieee8021PbbISidToVipEntry_t * ieee8021PbbISidToVipTable_getNextIndex (
	uint32_t u32ISid);
void ieee8021PbbISidToVipTable_removeEntry (ieee8021PbbISidToVipEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021PbbISidToVipTable_getFirst;
Netsnmp_Next_Data_Point ieee8021PbbISidToVipTable_getNext;
Netsnmp_Get_Data_Point ieee8021PbbISidToVipTable_get;
Netsnmp_Node_Handler ieee8021PbbISidToVipTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021PbbPipTable definitions
 */
#define IEEE8021PBBPIPIFINDEX 1
#define IEEE8021PBBPIPBMACADDRESS 2
#define IEEE8021PBBPIPNAME 3
#define IEEE8021PBBPIPICOMPONENTID 4
#define IEEE8021PBBPIPVIPMAP 5
#define IEEE8021PBBPIPVIPMAP1 6
#define IEEE8021PBBPIPVIPMAP2 7
#define IEEE8021PBBPIPVIPMAP3 8
#define IEEE8021PBBPIPVIPMAP4 9
#define IEEE8021PBBPIPROWSTATUS 10

enum
{
	/* enums for column ieee8021PbbPipRowStatus */
	ieee8021PbbPipRowStatus_active_c = 1,
	ieee8021PbbPipRowStatus_notInService_c = 2,
	ieee8021PbbPipRowStatus_notReady_c = 3,
	ieee8021PbbPipRowStatus_createAndGo_c = 4,
	ieee8021PbbPipRowStatus_createAndWait_c = 5,
	ieee8021PbbPipRowStatus_destroy_c = 6,
};

/* table ieee8021PbbPipTable row entry data structure */
typedef struct ieee8021PbbPipEntry_t
{
	/* Index values */
	uint32_t u32IfIndex;
	
	/* Column values */
	uint8_t au8BMACAddress[6];
	size_t u16BMACAddress_len;	/* # of uint8_t elements */
	uint8_t au8Name[32];
	size_t u16Name_len;	/* # of uint8_t elements */
	uint32_t u32IComponentId;
	uint8_t au8VipMap[512];
	size_t u16VipMap_len;	/* # of uint8_t elements */
	uint8_t au8VipMap1[0];
	size_t u16VipMap1_len;	/* # of uint8_t elements */
	uint8_t au8VipMap2[0];
	size_t u16VipMap2_len;	/* # of uint8_t elements */
	uint8_t au8VipMap3[0];
	size_t u16VipMap3_len;	/* # of uint8_t elements */
	uint8_t au8VipMap4[0];
	size_t u16VipMap4_len;	/* # of uint8_t elements */
	uint8_t u8RowStatus;
	
	bool bExternal;
	uint32_t u32ChassisId;
	uint32_t u32PipPort;
	uint16_t u16NumVipPorts;
	
	xBTree_Node_t oBTreeNode;
	xBTree_Node_t oComp_BTreeNode;
} ieee8021PbbPipEntry_t;

extern xBTree_t oIeee8021PbbPipTable_BTree;
extern xBTree_t oIeee8021PbbPipTable_Comp_BTree;

/* ieee8021PbbPipTable table mapper */
void ieee8021PbbPipTable_init (void);
ieee8021PbbPipEntry_t * ieee8021PbbPipTable_createEntry (
	uint32_t u32IfIndex);
ieee8021PbbPipEntry_t * ieee8021PbbPipTable_getByIndex (
	uint32_t u32IfIndex);
ieee8021PbbPipEntry_t * ieee8021PbbPipTable_getNextIndex (
	uint32_t u32IfIndex);
ieee8021PbbPipEntry_t * ieee8021PbbPipTable_Comp_getNextIndex (
	uint32_t u32IComponentId,
	uint32_t u32IfIndex);
void ieee8021PbbPipTable_removeEntry (ieee8021PbbPipEntry_t *poEntry);
ieee8021PbbPipEntry_t * ieee8021PbbPipTable_createExt (
	uint32_t u32IfIndex);
bool ieee8021PbbPipTable_removeExt (ieee8021PbbPipEntry_t *poEntry);
bool ieee8021PbbPipTable_createHier (ieee8021PbbPipEntry_t *poEntry, bool bIfReserved);
bool ieee8021PbbPipTable_removeHier (ieee8021PbbPipEntry_t *poEntry);
bool ieee8021PbbPipRowStatus_handler (
	ieee8021PbbPipEntry_t *poEntry, uint8_t u8RowStatus);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021PbbPipTable_getFirst;
Netsnmp_Next_Data_Point ieee8021PbbPipTable_getNext;
Netsnmp_Get_Data_Point ieee8021PbbPipTable_get;
Netsnmp_Node_Handler ieee8021PbbPipTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021PbbPipPriorityTable definitions
 */
#define IEEE8021PBBPIPPRIORITYCODEPOINTSELECTION 1
#define IEEE8021PBBPIPUSEDEI 2
#define IEEE8021PBBPIPREQUIREDROPENCODING 3

enum
{
	/* enums for column ieee8021PbbPipPriorityCodePointSelection */
	ieee8021PbbPipPriorityCodePointSelection_codePoint8p0d_c = 1,
	ieee8021PbbPipPriorityCodePointSelection_codePoint7p1d_c = 2,
	ieee8021PbbPipPriorityCodePointSelection_codePoint6p2d_c = 3,
	ieee8021PbbPipPriorityCodePointSelection_codePoint5p3d_c = 4,

	/* enums for column ieee8021PbbPipUseDEI */
	ieee8021PbbPipUseDEI_true_c = 1,
	ieee8021PbbPipUseDEI_false_c = 2,

	/* enums for column ieee8021PbbPipRequireDropEncoding */
	ieee8021PbbPipRequireDropEncoding_true_c = 1,
	ieee8021PbbPipRequireDropEncoding_false_c = 2,
};

/* table ieee8021PbbPipPriorityTable row entry data structure */
typedef struct ieee8021PbbPipPriorityEntry_t
{
	/* Index values */
	uint32_t u32IfIndex;
	
	/* Column values */
	int32_t i32CodePointSelection;
	int32_t i32UseDEI;
	int32_t i32RequireDropEncoding;
	
	xBTree_Node_t oBTreeNode;
} ieee8021PbbPipPriorityEntry_t;

extern xBTree_t oIeee8021PbbPipPriorityTable_BTree;

/* ieee8021PbbPipPriorityTable table mapper */
void ieee8021PbbPipPriorityTable_init (void);
ieee8021PbbPipPriorityEntry_t * ieee8021PbbPipPriorityTable_createEntry (
	uint32_t u32IfIndex);
ieee8021PbbPipPriorityEntry_t * ieee8021PbbPipPriorityTable_getByIndex (
	uint32_t u32IfIndex);
ieee8021PbbPipPriorityEntry_t * ieee8021PbbPipPriorityTable_getNextIndex (
	uint32_t u32IfIndex);
void ieee8021PbbPipPriorityTable_removeEntry (ieee8021PbbPipPriorityEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021PbbPipPriorityTable_getFirst;
Netsnmp_Next_Data_Point ieee8021PbbPipPriorityTable_getNext;
Netsnmp_Get_Data_Point ieee8021PbbPipPriorityTable_get;
Netsnmp_Node_Handler ieee8021PbbPipPriorityTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021PbbPipDecodingTable definitions
 */
#define IEEE8021PBBPIPDECODINGPRIORITYCODEPOINTROW 1
#define IEEE8021PBBPIPDECODINGPRIORITYCODEPOINT 2
#define IEEE8021PBBPIPDECODINGPRIORITY 3
#define IEEE8021PBBPIPDECODINGDROPELIGIBLE 4

enum
{
	/* enums for column ieee8021PbbPipDecodingPriorityCodePointRow */
	ieee8021PbbPipDecodingPriorityCodePointRow_codePoint8p0d_c = 1,
	ieee8021PbbPipDecodingPriorityCodePointRow_codePoint7p1d_c = 2,
	ieee8021PbbPipDecodingPriorityCodePointRow_codePoint6p2d_c = 3,
	ieee8021PbbPipDecodingPriorityCodePointRow_codePoint5p3d_c = 4,

	/* enums for column ieee8021PbbPipDecodingDropEligible */
	ieee8021PbbPipDecodingDropEligible_true_c = 1,
	ieee8021PbbPipDecodingDropEligible_false_c = 2,
};

/* table ieee8021PbbPipDecodingTable row entry data structure */
typedef struct ieee8021PbbPipDecodingEntry_t
{
	/* Index values */
	uint32_t u32IfIndex;
	int32_t i32PriorityCodePointRow;
	int32_t i32PriorityCodePoint;
	
	/* Column values */
	uint32_t u32Priority;
	int32_t i32DropEligible;
	
	xBTree_Node_t oBTreeNode;
} ieee8021PbbPipDecodingEntry_t;

extern xBTree_t oIeee8021PbbPipDecodingTable_BTree;

/* ieee8021PbbPipDecodingTable table mapper */
void ieee8021PbbPipDecodingTable_init (void);
ieee8021PbbPipDecodingEntry_t * ieee8021PbbPipDecodingTable_createEntry (
	uint32_t u32IfIndex,
	int32_t i32PriorityCodePointRow,
	int32_t i32PriorityCodePoint);
ieee8021PbbPipDecodingEntry_t * ieee8021PbbPipDecodingTable_getByIndex (
	uint32_t u32IfIndex,
	int32_t i32PriorityCodePointRow,
	int32_t i32PriorityCodePoint);
ieee8021PbbPipDecodingEntry_t * ieee8021PbbPipDecodingTable_getNextIndex (
	uint32_t u32IfIndex,
	int32_t i32PriorityCodePointRow,
	int32_t i32PriorityCodePoint);
void ieee8021PbbPipDecodingTable_removeEntry (ieee8021PbbPipDecodingEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021PbbPipDecodingTable_getFirst;
Netsnmp_Next_Data_Point ieee8021PbbPipDecodingTable_getNext;
Netsnmp_Get_Data_Point ieee8021PbbPipDecodingTable_get;
Netsnmp_Node_Handler ieee8021PbbPipDecodingTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021PbbPipEncodingTable definitions
 */
#define IEEE8021PBBPIPENCODINGPRIORITYCODEPOINTROW 1
#define IEEE8021PBBPIPENCODINGPRIORITYCODEPOINT 2
#define IEEE8021PBBPIPENCODINGDROPELIGIBLE 3
#define IEEE8021PBBPIPENCODINGPRIORITY 4

enum
{
	/* enums for column ieee8021PbbPipEncodingPriorityCodePointRow */
	ieee8021PbbPipEncodingPriorityCodePointRow_codePoint8p0d_c = 1,
	ieee8021PbbPipEncodingPriorityCodePointRow_codePoint7p1d_c = 2,
	ieee8021PbbPipEncodingPriorityCodePointRow_codePoint6p2d_c = 3,
	ieee8021PbbPipEncodingPriorityCodePointRow_codePoint5p3d_c = 4,

	/* enums for column ieee8021PbbPipEncodingDropEligible */
	ieee8021PbbPipEncodingDropEligible_true_c = 1,
	ieee8021PbbPipEncodingDropEligible_false_c = 2,
};

/* table ieee8021PbbPipEncodingTable row entry data structure */
typedef struct ieee8021PbbPipEncodingEntry_t
{
	/* Index values */
	uint32_t u32IfIndex;
	int32_t i32PriorityCodePointRow;
	int32_t i32PriorityCodePoint;
	int32_t i32DropEligible;
	
	/* Column values */
	uint32_t u32Priority;
	
	xBTree_Node_t oBTreeNode;
} ieee8021PbbPipEncodingEntry_t;

extern xBTree_t oIeee8021PbbPipEncodingTable_BTree;

/* ieee8021PbbPipEncodingTable table mapper */
void ieee8021PbbPipEncodingTable_init (void);
ieee8021PbbPipEncodingEntry_t * ieee8021PbbPipEncodingTable_createEntry (
	uint32_t u32IfIndex,
	int32_t i32PriorityCodePointRow,
	int32_t i32PriorityCodePoint,
	int32_t i32DropEligible);
ieee8021PbbPipEncodingEntry_t * ieee8021PbbPipEncodingTable_getByIndex (
	uint32_t u32IfIndex,
	int32_t i32PriorityCodePointRow,
	int32_t i32PriorityCodePoint,
	int32_t i32DropEligible);
ieee8021PbbPipEncodingEntry_t * ieee8021PbbPipEncodingTable_getNextIndex (
	uint32_t u32IfIndex,
	int32_t i32PriorityCodePointRow,
	int32_t i32PriorityCodePoint,
	int32_t i32DropEligible);
void ieee8021PbbPipEncodingTable_removeEntry (ieee8021PbbPipEncodingEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021PbbPipEncodingTable_getFirst;
Netsnmp_Next_Data_Point ieee8021PbbPipEncodingTable_getNext;
Netsnmp_Get_Data_Point ieee8021PbbPipEncodingTable_get;
Netsnmp_Node_Handler ieee8021PbbPipEncodingTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021PbbVipToPipMappingTable definitions
 */
#define IEEE8021PBBVIPTOPIPMAPPINGPIPIFINDEX 1
#define IEEE8021PBBVIPTOPIPMAPPINGSTORAGETYPE 2
#define IEEE8021PBBVIPTOPIPMAPPINGROWSTATUS 3

enum
{
	/* enums for column ieee8021PbbVipToPipMappingStorageType */
	ieee8021PbbVipToPipMappingStorageType_other_c = 1,
	ieee8021PbbVipToPipMappingStorageType_volatile_c = 2,
	ieee8021PbbVipToPipMappingStorageType_nonVolatile_c = 3,
	ieee8021PbbVipToPipMappingStorageType_permanent_c = 4,
	ieee8021PbbVipToPipMappingStorageType_readOnly_c = 5,

	/* enums for column ieee8021PbbVipToPipMappingRowStatus */
	ieee8021PbbVipToPipMappingRowStatus_active_c = 1,
	ieee8021PbbVipToPipMappingRowStatus_notInService_c = 2,
	ieee8021PbbVipToPipMappingRowStatus_notReady_c = 3,
	ieee8021PbbVipToPipMappingRowStatus_createAndGo_c = 4,
	ieee8021PbbVipToPipMappingRowStatus_createAndWait_c = 5,
	ieee8021PbbVipToPipMappingRowStatus_destroy_c = 6,
};

/* table ieee8021PbbVipToPipMappingTable row entry data structure */
typedef struct ieee8021PbbVipToPipMappingEntry_t
{
	/* Index values */
	uint32_t u32BridgeBasePortComponentId;
	uint32_t u32BridgeBasePort;
	
	/* Column values */
	uint32_t u32PipIfIndex;
	uint8_t u8StorageType;
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} ieee8021PbbVipToPipMappingEntry_t;

extern xBTree_t oIeee8021PbbVipToPipMappingTable_BTree;

/* ieee8021PbbVipToPipMappingTable table mapper */
void ieee8021PbbVipToPipMappingTable_init (void);
ieee8021PbbVipToPipMappingEntry_t * ieee8021PbbVipToPipMappingTable_createEntry (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort);
ieee8021PbbVipToPipMappingEntry_t * ieee8021PbbVipToPipMappingTable_getByIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort);
ieee8021PbbVipToPipMappingEntry_t * ieee8021PbbVipToPipMappingTable_getNextIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort);
void ieee8021PbbVipToPipMappingTable_removeEntry (ieee8021PbbVipToPipMappingEntry_t *poEntry);
ieee8021PbbVipToPipMappingEntry_t * ieee8021PbbVipToPipMappingTable_createExt (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort);
bool ieee8021PbbVipToPipMappingTable_removeExt (ieee8021PbbVipToPipMappingEntry_t *poEntry);
bool ieee8021PbbVipToPipMappingTable_createHier (ieee8021PbbVipToPipMappingEntry_t *poEntry);
bool ieee8021PbbVipToPipMappingTable_removeHier (ieee8021PbbVipToPipMappingEntry_t *poEntry);
bool ieee8021PbbVipToPipMappingRowStatus_handler (
	ieee8021PbbVipToPipMappingEntry_t *poEntry, uint8_t u8RowStatus);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021PbbVipToPipMappingTable_getFirst;
Netsnmp_Next_Data_Point ieee8021PbbVipToPipMappingTable_getNext;
Netsnmp_Get_Data_Point ieee8021PbbVipToPipMappingTable_get;
Netsnmp_Node_Handler ieee8021PbbVipToPipMappingTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021PbbCbpServiceMappingTable definitions
 */
#define IEEE8021PBBCBPSERVICEMAPPINGBACKBONESID 1
#define IEEE8021PBBCBPSERVICEMAPPINGBVID 2
#define IEEE8021PBBCBPSERVICEMAPPINGDEFAULTBACKBONEDEST 3
#define IEEE8021PBBCBPSERVICEMAPPINGTYPE 4
#define IEEE8021PBBCBPSERVICEMAPPINGLOCALSID 5
#define IEEE8021PBBCBPSERVICEMAPPINGROWSTATUS 6

enum
{
	/* enums for column ieee8021PbbCbpServiceMappingType */
	ieee8021PbbCbpServiceMappingType_ingress_c = 0,
	ieee8021PbbCbpServiceMappingType_egress_c = 1,

	/* enums for column ieee8021PbbCbpServiceMappingRowStatus */
	ieee8021PbbCbpServiceMappingRowStatus_active_c = 1,
	ieee8021PbbCbpServiceMappingRowStatus_notInService_c = 2,
	ieee8021PbbCbpServiceMappingRowStatus_notReady_c = 3,
	ieee8021PbbCbpServiceMappingRowStatus_createAndGo_c = 4,
	ieee8021PbbCbpServiceMappingRowStatus_createAndWait_c = 5,
	ieee8021PbbCbpServiceMappingRowStatus_destroy_c = 6,
};

/* table ieee8021PbbCbpServiceMappingTable row entry data structure */
typedef struct ieee8021PbbCbpServiceMappingEntry_t
{
	/* Index values */
	uint32_t u32BridgeBasePortComponentId;
	uint32_t u32BridgeBasePort;
	uint32_t u32BackboneSid;
	
	/* Column values */
	uint32_t u32BVid;
	uint8_t au8DefaultBackboneDest[6];
	size_t u16DefaultBackboneDest_len;	/* # of uint8_t elements */
	uint8_t au8Type[1];
	size_t u16Type_len;	/* # of uint8_t elements */
	uint32_t u32LocalSid;
	uint8_t u8RowStatus;
	
	struct ieee8021PbbCbpServiceMappingEntry_t *pOldEntry;
	
	xBTree_Node_t oBTreeNode;
} ieee8021PbbCbpServiceMappingEntry_t;

extern xBTree_t oIeee8021PbbCbpServiceMappingTable_BTree;

/* ieee8021PbbCbpServiceMappingTable table mapper */
void ieee8021PbbCbpServiceMappingTable_init (void);
ieee8021PbbCbpServiceMappingEntry_t * ieee8021PbbCbpServiceMappingTable_createEntry (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	uint32_t u32BackboneSid);
ieee8021PbbCbpServiceMappingEntry_t * ieee8021PbbCbpServiceMappingTable_getByIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	uint32_t u32BackboneSid);
ieee8021PbbCbpServiceMappingEntry_t * ieee8021PbbCbpServiceMappingTable_getNextIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	uint32_t u32BackboneSid);
void ieee8021PbbCbpServiceMappingTable_removeEntry (ieee8021PbbCbpServiceMappingEntry_t *poEntry);
ieee8021PbbCbpServiceMappingEntry_t * ieee8021PbbCbpServiceMappingTable_createExt (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	uint32_t u32BackboneSid);
bool ieee8021PbbCbpServiceMappingTable_removeExt (ieee8021PbbCbpServiceMappingEntry_t *poEntry);
bool ieee8021PbbCbpServiceMappingTable_createHier (ieee8021PbbCbpServiceMappingEntry_t *poEntry);
bool ieee8021PbbCbpServiceMappingTable_removeHier (ieee8021PbbCbpServiceMappingEntry_t *poEntry);
bool ieee8021PbbCbpServiceMappingRowStatus_handler (
	ieee8021PbbCbpServiceMappingEntry_t *poEntry, uint8_t u8RowStatus);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021PbbCbpServiceMappingTable_getFirst;
Netsnmp_Next_Data_Point ieee8021PbbCbpServiceMappingTable_getNext;
Netsnmp_Get_Data_Point ieee8021PbbCbpServiceMappingTable_get;
Netsnmp_Node_Handler ieee8021PbbCbpServiceMappingTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021PbbCbpTable definitions
 */
#define IEEE8021PBBCBPROWSTATUS 1

enum
{
	/* enums for column ieee8021PbbCbpRowStatus */
	ieee8021PbbCbpRowStatus_active_c = 1,
	ieee8021PbbCbpRowStatus_notInService_c = 2,
	ieee8021PbbCbpRowStatus_notReady_c = 3,
	ieee8021PbbCbpRowStatus_createAndGo_c = 4,
	ieee8021PbbCbpRowStatus_createAndWait_c = 5,
	ieee8021PbbCbpRowStatus_destroy_c = 6,
};

/* table ieee8021PbbCbpTable row entry data structure */
typedef struct ieee8021PbbCbpEntry_t
{
	/* Index values */
	uint32_t u32BridgeBasePortComponentId;
	uint32_t u32BridgeBasePort;
	
	/* Column values */
	uint8_t u8RowStatus;
	
	bool bExternal;
	uint32_t u32ChassisId;
	
	xBTree_Node_t oBTreeNode;
} ieee8021PbbCbpEntry_t;

extern xBTree_t oIeee8021PbbCbpTable_BTree;

/* ieee8021PbbCbpTable table mapper */
void ieee8021PbbCbpTable_init (void);
ieee8021PbbCbpEntry_t * ieee8021PbbCbpTable_createEntry (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort);
ieee8021PbbCbpEntry_t * ieee8021PbbCbpTable_getByIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort);
ieee8021PbbCbpEntry_t * ieee8021PbbCbpTable_getNextIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort);
void ieee8021PbbCbpTable_removeEntry (ieee8021PbbCbpEntry_t *poEntry);
ieee8021PbbCbpEntry_t * ieee8021PbbCbpTable_createExt (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort);
bool ieee8021PbbCbpTable_removeExt (ieee8021PbbCbpEntry_t *poEntry);
bool ieee8021PbbCbpTable_createHier (ieee8021PbbCbpEntry_t *poEntry);
bool ieee8021PbbCbpTable_removeHier (ieee8021PbbCbpEntry_t *poEntry);
bool ieee8021PbbCbpRowStatus_handler (
	ieee8021PbbCbpEntry_t *poEntry, uint8_t u8RowStatus);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021PbbCbpTable_getFirst;
Netsnmp_Next_Data_Point ieee8021PbbCbpTable_getNext;
Netsnmp_Get_Data_Point ieee8021PbbCbpTable_get;
Netsnmp_Node_Handler ieee8021PbbCbpTable_mapper;
#endif	/* SNMP_SRC */



#	ifdef __cplusplus
}
#	endif

#endif /* __IEEE8021PBBMIB_H__ */
