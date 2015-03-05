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

#ifndef __IEEE8021QBRIDGEMIB_H__
#	define __IEEE8021QBRIDGEMIB_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include "neIeee8021BridgeMIB.h"
#include "ethernet_ext.h"

#include "lib/binaryTree.h"
#include "lib/sync.h"
#include "lib/snmp.h"

#include <stdbool.h>

#define TOBE_REPLACED 1


/**
 *	agent MIB function
 */
void ieee8021QBridgeMib_init (void);


/**
 *	scalar mapper(s)
 */
/** definitions for scalar(s) of ieee8021QBridgeVlan **/
#define IEEE8021QBRIDGEVLANNUMDELETES 1

typedef struct ieee8021QBridgeVlan_t
{
	uint64_t u64NumDeletes;
} ieee8021QBridgeVlan_t;

extern ieee8021QBridgeVlan_t oIeee8021QBridgeVlan;

#ifdef SNMP_SRC
Netsnmp_Node_Handler ieee8021QBridgeVlan_mapper;
#endif	/* SNMP_SRC */



/**
 *	table mapper(s)
 */
/**
 *	table ieee8021QBridgeTable definitions
 */
#define IEEE8021QBRIDGECOMPONENTID 1
#define IEEE8021QBRIDGEVLANVERSIONNUMBER 2
#define IEEE8021QBRIDGEMAXVLANID 3
#define IEEE8021QBRIDGEMAXSUPPORTEDVLANS 4
#define IEEE8021QBRIDGENUMVLANS 5
#define IEEE8021QBRIDGEMVRPENABLEDSTATUS 6

enum
{
	ieee8021QBridgeVlanIndex_all_c = 0xFFFFFFFF,
	
	/* enums for column ieee8021QBridgeVlanVersionNumber */
	ieee8021QBridgeVlanVersionNumber_version1_c = 1,
	ieee8021QBridgeVlanVersionNumber_version2_c = 2,

	/* enums for column ieee8021QBridgeMvrpEnabledStatus */
	ieee8021QBridgeMvrpEnabledStatus_true_c = 1,
	ieee8021QBridgeMvrpEnabledStatus_false_c = 2,
};

/* table ieee8021QBridgeTable row entry data structure */
typedef struct ieee8021QBridgeEntry_t
{
	/* Index values */
// 	uint32_t u32ComponentId;
	
	/* Column values */
	int32_t i32VlanVersionNumber;
	uint32_t u32MaxVlanId;
	uint32_t u32MaxSupportedVlans;
	uint32_t u32NumVlans;
	uint8_t u8MvrpEnabledStatus;
	
// 	xBTree_Node_t oBTreeNode;
} ieee8021QBridgeEntry_t;

// extern xBTree_t oIeee8021QBridgeTable_BTree;

/* ieee8021QBridgeTable table mapper */
void ieee8021QBridgeTable_init (void);
ieee8021QBridgeEntry_t * ieee8021QBridgeTable_createEntry (
	uint32_t u32ComponentId);
ieee8021QBridgeEntry_t * ieee8021QBridgeTable_getByIndex (
	uint32_t u32ComponentId);
ieee8021QBridgeEntry_t * ieee8021QBridgeTable_getNextIndex (
	uint32_t u32ComponentId);
void ieee8021QBridgeTable_removeEntry (ieee8021QBridgeEntry_t *poEntry);
ieee8021QBridgeEntry_t * ieee8021QBridgeTable_createExt (
	uint32_t u32ComponentId);
bool ieee8021QBridgeTable_removeExt (ieee8021QBridgeEntry_t *poEntry);
bool ieee8021QBridgeTable_createHier (ieee8021QBridgeEntry_t *poEntry);
bool ieee8021QBridgeTable_removeHier (ieee8021QBridgeEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021QBridgeTable_getFirst;
Netsnmp_Next_Data_Point ieee8021QBridgeTable_getNext;
Netsnmp_Get_Data_Point ieee8021QBridgeTable_get;
Netsnmp_Node_Handler ieee8021QBridgeTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021QBridgeCVlanPortTable definitions
 */
#define IEEE8021QBRIDGECVLANPORTCOMPONENTID 1
#define IEEE8021QBRIDGECVLANPORTNUMBER 2
#define IEEE8021QBRIDGECVLANPORTROWSTATUS 3

enum
{
	/* enums for column ieee8021QBridgeCVlanPortRowStatus */
	ieee8021QBridgeCVlanPortRowStatus_active_c = 1,
	ieee8021QBridgeCVlanPortRowStatus_notInService_c = 2,
	ieee8021QBridgeCVlanPortRowStatus_notReady_c = 3,
	ieee8021QBridgeCVlanPortRowStatus_createAndGo_c = 4,
	ieee8021QBridgeCVlanPortRowStatus_createAndWait_c = 5,
	ieee8021QBridgeCVlanPortRowStatus_destroy_c = 6,
};

/* table ieee8021QBridgeCVlanPortTable row entry data structure */
typedef struct ieee8021QBridgeCVlanPortEntry_t
{
	/* Index values */
	uint32_t u32ComponentId;
	uint32_t u32Number;
	
	/* Column values */
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} ieee8021QBridgeCVlanPortEntry_t;

extern xBTree_t oIeee8021QBridgeCVlanPortTable_BTree;

/* ieee8021QBridgeCVlanPortTable table mapper */
void ieee8021QBridgeCVlanPortTable_init (void);
ieee8021QBridgeCVlanPortEntry_t * ieee8021QBridgeCVlanPortTable_createEntry (
	uint32_t u32ComponentId,
	uint32_t u32Number);
ieee8021QBridgeCVlanPortEntry_t * ieee8021QBridgeCVlanPortTable_getByIndex (
	uint32_t u32ComponentId,
	uint32_t u32Number);
ieee8021QBridgeCVlanPortEntry_t * ieee8021QBridgeCVlanPortTable_getNextIndex (
	uint32_t u32ComponentId,
	uint32_t u32Number);
void ieee8021QBridgeCVlanPortTable_removeEntry (ieee8021QBridgeCVlanPortEntry_t *poEntry);
ieee8021QBridgeCVlanPortEntry_t * ieee8021QBridgeCVlanPortTable_createExt (
	uint32_t u32ComponentId,
	uint32_t u32Number);
bool ieee8021QBridgeCVlanPortTable_removeExt (ieee8021QBridgeCVlanPortEntry_t *poEntry);
bool ieee8021QBridgeCVlanPortTable_createHier (ieee8021QBridgeCVlanPortEntry_t *poEntry);
bool ieee8021QBridgeCVlanPortTable_removeHier (ieee8021QBridgeCVlanPortEntry_t *poEntry);
bool ieee8021QBridgeCVlanPortRowStatus_handler (
	ieee8021QBridgeCVlanPortEntry_t *poEntry, uint8_t u8RowStatus);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021QBridgeCVlanPortTable_getFirst;
Netsnmp_Next_Data_Point ieee8021QBridgeCVlanPortTable_getNext;
Netsnmp_Get_Data_Point ieee8021QBridgeCVlanPortTable_get;
Netsnmp_Node_Handler ieee8021QBridgeCVlanPortTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021QBridgeFdbTable definitions
 */
#define IEEE8021QBRIDGEFDBCOMPONENTID 1
#define IEEE8021QBRIDGEFDBID 2
#define IEEE8021QBRIDGEFDBDYNAMICCOUNT 3
#define IEEE8021QBRIDGEFDBLEARNEDENTRYDISCARDS 4
#define IEEE8021QBRIDGEFDBAGINGTIME 5

enum
{
	ieee8021QBridgeFdbId_zero_c = 0,
	ieee8021QBridgeFdbId_start_c = 1,
	ieee8021QBridgeFdbId_end_c = 0xFFFF,
	ieee8021QBridgeFdbId_default_c = ieee8021QBridgeFdbId_start_c,
};

/* table ieee8021QBridgeFdbTable row entry data structure */
typedef struct ieee8021QBridgeFdbEntry_t
{
	/* Index values */
	uint32_t u32ComponentId;
	uint32_t u32Id;
	
	/* Column values */
	uint32_t u32DynamicCount;
	uint64_t u64LearnedEntryDiscards;
	int32_t i32AgingTime;
	
	uint32_t u32NumVlans;
	
	xBTree_Node_t oBTreeNode;
} ieee8021QBridgeFdbEntry_t;

extern xBTree_t oIeee8021QBridgeFdbTable_BTree;

/* ieee8021QBridgeFdbTable table mapper */
void ieee8021QBridgeFdbTable_init (void);
ieee8021QBridgeFdbEntry_t * ieee8021QBridgeFdbTable_createEntry (
	uint32_t u32ComponentId,
	uint32_t u32Id);
ieee8021QBridgeFdbEntry_t * ieee8021QBridgeFdbTable_getByIndex (
	uint32_t u32ComponentId,
	uint32_t u32Id);
ieee8021QBridgeFdbEntry_t * ieee8021QBridgeFdbTable_getNextIndex (
	uint32_t u32ComponentId,
	uint32_t u32Id);
void ieee8021QBridgeFdbTable_removeEntry (ieee8021QBridgeFdbEntry_t *poEntry);
ieee8021QBridgeFdbEntry_t *ieee8021QBridgeFdbTable_createExt (
	uint32_t u32ComponentId,
	uint32_t u32Id);
bool ieee8021QBridgeFdbTable_removeExt (ieee8021QBridgeFdbEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021QBridgeFdbTable_getFirst;
Netsnmp_Next_Data_Point ieee8021QBridgeFdbTable_getNext;
Netsnmp_Get_Data_Point ieee8021QBridgeFdbTable_get;
Netsnmp_Node_Handler ieee8021QBridgeFdbTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021QBridgeTpFdbTable definitions
 */
#define IEEE8021QBRIDGETPFDBADDRESS 1
#define IEEE8021QBRIDGETPFDBPORT 2
#define IEEE8021QBRIDGETPFDBSTATUS 3

enum
{
	/* enums for column ieee8021QBridgeTpFdbStatus */
	ieee8021QBridgeTpFdbStatus_other_c = 1,
	ieee8021QBridgeTpFdbStatus_invalid_c = 2,
	ieee8021QBridgeTpFdbStatus_learned_c = 3,
	ieee8021QBridgeTpFdbStatus_self_c = 4,
	ieee8021QBridgeTpFdbStatus_mgmt_c = 5,
};

/* table ieee8021QBridgeTpFdbTable row entry data structure */
typedef struct ieee8021QBridgeTpFdbEntry_t
{
	/* Index values */
	uint32_t u32FdbComponentId;
	uint32_t u32FdbId;
	uint8_t au8Address[6];
	size_t u16Address_len;	/* # of uint8_t elements */
	
	/* Column values */
	uint32_t u32Port;
	int32_t i32Status;
	
	xBTree_Node_t oBTreeNode;
} ieee8021QBridgeTpFdbEntry_t;

extern xBTree_t oIeee8021QBridgeTpFdbTable_BTree;

/* ieee8021QBridgeTpFdbTable table mapper */
void ieee8021QBridgeTpFdbTable_init (void);
ieee8021QBridgeTpFdbEntry_t * ieee8021QBridgeTpFdbTable_createEntry (
	uint32_t u32FdbComponentId,
	uint32_t u32FdbId,
	uint8_t *pau8Address, size_t u16Address_len);
ieee8021QBridgeTpFdbEntry_t * ieee8021QBridgeTpFdbTable_getByIndex (
	uint32_t u32FdbComponentId,
	uint32_t u32FdbId,
	uint8_t *pau8Address, size_t u16Address_len);
ieee8021QBridgeTpFdbEntry_t * ieee8021QBridgeTpFdbTable_getNextIndex (
	uint32_t u32FdbComponentId,
	uint32_t u32FdbId,
	uint8_t *pau8Address, size_t u16Address_len);
void ieee8021QBridgeTpFdbTable_removeEntry (ieee8021QBridgeTpFdbEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021QBridgeTpFdbTable_getFirst;
Netsnmp_Next_Data_Point ieee8021QBridgeTpFdbTable_getNext;
Netsnmp_Get_Data_Point ieee8021QBridgeTpFdbTable_get;
Netsnmp_Node_Handler ieee8021QBridgeTpFdbTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021QBridgeTpGroupTable definitions
 */
#define IEEE8021QBRIDGETPGROUPADDRESS 1
#define IEEE8021QBRIDGETPGROUPEGRESSPORTS 2
#define IEEE8021QBRIDGETPGROUPLEARNT 3

/* table ieee8021QBridgeTpGroupTable row entry data structure */
typedef struct ieee8021QBridgeTpGroupEntry_t
{
	/* Index values */
	uint32_t u32VlanCurrentComponentId;
	uint32_t u32VlanIndex;
	uint8_t au8Address[6];
	size_t u16Address_len;	/* # of uint8_t elements */
	
	/* Column values */
	uint8_t *pu8EgressPorts;
	size_t u16EgressPorts_len;	/* # of uint8_t elements */
	uint8_t *pu8Learnt;
	size_t u16Learnt_len;	/* # of uint8_t elements */
	
	xBTree_Node_t oBTreeNode;
} ieee8021QBridgeTpGroupEntry_t;

extern xBTree_t oIeee8021QBridgeTpGroupTable_BTree;

/* ieee8021QBridgeTpGroupTable table mapper */
void ieee8021QBridgeTpGroupTable_init (void);
ieee8021QBridgeTpGroupEntry_t * ieee8021QBridgeTpGroupTable_createEntry (
	uint32_t u32VlanCurrentComponentId,
	uint32_t u32VlanIndex,
	uint8_t *pau8Address, size_t u16Address_len,
	uint16_t u16Ports_len);
ieee8021QBridgeTpGroupEntry_t * ieee8021QBridgeTpGroupTable_getByIndex (
	uint32_t u32VlanCurrentComponentId,
	uint32_t u32VlanIndex,
	uint8_t *pau8Address, size_t u16Address_len);
ieee8021QBridgeTpGroupEntry_t * ieee8021QBridgeTpGroupTable_getNextIndex (
	uint32_t u32VlanCurrentComponentId,
	uint32_t u32VlanIndex,
	uint8_t *pau8Address, size_t u16Address_len);
void ieee8021QBridgeTpGroupTable_removeEntry (ieee8021QBridgeTpGroupEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021QBridgeTpGroupTable_getFirst;
Netsnmp_Next_Data_Point ieee8021QBridgeTpGroupTable_getNext;
Netsnmp_Get_Data_Point ieee8021QBridgeTpGroupTable_get;
Netsnmp_Node_Handler ieee8021QBridgeTpGroupTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021QBridgeForwardAllTable definitions
 */
#define IEEE8021QBRIDGEFORWARDALLVLANINDEX 1
#define IEEE8021QBRIDGEFORWARDALLPORTS 2
#define IEEE8021QBRIDGEFORWARDALLSTATICPORTS 3
#define IEEE8021QBRIDGEFORWARDALLFORBIDDENPORTS 4

/* table ieee8021QBridgeForwardAllTable row entry data structure */
typedef struct ieee8021QBridgeForwardAllEntry_t
{
	/* Index values */
	uint32_t u32VlanCurrentComponentId;
	uint32_t u32VlanIndex;
	
	/* Column values */
	uint8_t au8Ports[ETHERNET_PORT_MAP_SIZE];
	size_t u16Ports_len;	/* # of uint8_t elements */
	uint8_t au8StaticPorts[ETHERNET_PORT_MAP_SIZE];
	size_t u16StaticPorts_len;	/* # of uint8_t elements */
	uint8_t au8ForbiddenPorts[ETHERNET_PORT_MAP_SIZE];
	size_t u16ForbiddenPorts_len;	/* # of uint8_t elements */
	
	xBTree_Node_t oBTreeNode;
} ieee8021QBridgeForwardAllEntry_t;

extern xBTree_t oIeee8021QBridgeForwardAllTable_BTree;

/* ieee8021QBridgeForwardAllTable table mapper */
void ieee8021QBridgeForwardAllTable_init (void);
ieee8021QBridgeForwardAllEntry_t * ieee8021QBridgeForwardAllTable_createEntry (
	uint32_t u32VlanCurrentComponentId,
	uint32_t u32VlanIndex);
ieee8021QBridgeForwardAllEntry_t * ieee8021QBridgeForwardAllTable_getByIndex (
	uint32_t u32VlanCurrentComponentId,
	uint32_t u32VlanIndex);
ieee8021QBridgeForwardAllEntry_t * ieee8021QBridgeForwardAllTable_getNextIndex (
	uint32_t u32VlanCurrentComponentId,
	uint32_t u32VlanIndex);
void ieee8021QBridgeForwardAllTable_removeEntry (ieee8021QBridgeForwardAllEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021QBridgeForwardAllTable_getFirst;
Netsnmp_Next_Data_Point ieee8021QBridgeForwardAllTable_getNext;
Netsnmp_Get_Data_Point ieee8021QBridgeForwardAllTable_get;
Netsnmp_Node_Handler ieee8021QBridgeForwardAllTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021QBridgeForwardUnregisteredTable definitions
 */
#define IEEE8021QBRIDGEFORWARDUNREGISTEREDVLANINDEX 1
#define IEEE8021QBRIDGEFORWARDUNREGISTEREDPORTS 2
#define IEEE8021QBRIDGEFORWARDUNREGISTEREDSTATICPORTS 3
#define IEEE8021QBRIDGEFORWARDUNREGISTEREDFORBIDDENPORTS 4

/* table ieee8021QBridgeForwardUnregisteredTable row entry data structure */
typedef struct ieee8021QBridgeForwardUnregisteredEntry_t
{
	/* Index values */
	uint32_t u32VlanCurrentComponentId;
	uint32_t u32VlanIndex;
	
	/* Column values */
	uint8_t au8Ports[ETHERNET_PORT_MAP_SIZE];
	size_t u16Ports_len;	/* # of uint8_t elements */
	uint8_t au8StaticPorts[ETHERNET_PORT_MAP_SIZE];
	size_t u16StaticPorts_len;	/* # of uint8_t elements */
	uint8_t au8ForbiddenPorts[ETHERNET_PORT_MAP_SIZE];
	size_t u16ForbiddenPorts_len;	/* # of uint8_t elements */
	
	xBTree_Node_t oBTreeNode;
} ieee8021QBridgeForwardUnregisteredEntry_t;

extern xBTree_t oIeee8021QBridgeForwardUnregisteredTable_BTree;

/* ieee8021QBridgeForwardUnregisteredTable table mapper */
void ieee8021QBridgeForwardUnregisteredTable_init (void);
ieee8021QBridgeForwardUnregisteredEntry_t * ieee8021QBridgeForwardUnregisteredTable_createEntry (
	uint32_t u32VlanCurrentComponentId,
	uint32_t u32VlanIndex);
ieee8021QBridgeForwardUnregisteredEntry_t * ieee8021QBridgeForwardUnregisteredTable_getByIndex (
	uint32_t u32VlanCurrentComponentId,
	uint32_t u32VlanIndex);
ieee8021QBridgeForwardUnregisteredEntry_t * ieee8021QBridgeForwardUnregisteredTable_getNextIndex (
	uint32_t u32VlanCurrentComponentId,
	uint32_t u32VlanIndex);
void ieee8021QBridgeForwardUnregisteredTable_removeEntry (ieee8021QBridgeForwardUnregisteredEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021QBridgeForwardUnregisteredTable_getFirst;
Netsnmp_Next_Data_Point ieee8021QBridgeForwardUnregisteredTable_getNext;
Netsnmp_Get_Data_Point ieee8021QBridgeForwardUnregisteredTable_get;
Netsnmp_Node_Handler ieee8021QBridgeForwardUnregisteredTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021QBridgeStaticUnicastTable definitions
 */
#define IEEE8021QBRIDGESTATICUNICASTCOMPONENTID 1
#define IEEE8021QBRIDGESTATICUNICASTVLANINDEX 2
#define IEEE8021QBRIDGESTATICUNICASTADDRESS 3
#define IEEE8021QBRIDGESTATICUNICASTRECEIVEPORT 4
#define IEEE8021QBRIDGESTATICUNICASTSTATICEGRESSPORTS 5
#define IEEE8021QBRIDGESTATICUNICASTFORBIDDENEGRESSPORTS 6
#define IEEE8021QBRIDGESTATICUNICASTSTORAGETYPE 7
#define IEEE8021QBRIDGESTATICUNICASTROWSTATUS 8

enum
{
	/* enums for column ieee8021QBridgeStaticUnicastStorageType */
	ieee8021QBridgeStaticUnicastStorageType_other_c = 1,
	ieee8021QBridgeStaticUnicastStorageType_volatile_c = 2,
	ieee8021QBridgeStaticUnicastStorageType_nonVolatile_c = 3,
	ieee8021QBridgeStaticUnicastStorageType_permanent_c = 4,
	ieee8021QBridgeStaticUnicastStorageType_readOnly_c = 5,

	/* enums for column ieee8021QBridgeStaticUnicastRowStatus */
	ieee8021QBridgeStaticUnicastRowStatus_active_c = 1,
	ieee8021QBridgeStaticUnicastRowStatus_notInService_c = 2,
	ieee8021QBridgeStaticUnicastRowStatus_notReady_c = 3,
	ieee8021QBridgeStaticUnicastRowStatus_createAndGo_c = 4,
	ieee8021QBridgeStaticUnicastRowStatus_createAndWait_c = 5,
	ieee8021QBridgeStaticUnicastRowStatus_destroy_c = 6,
};

/* table ieee8021QBridgeStaticUnicastTable row entry data structure */
typedef struct ieee8021QBridgeStaticUnicastEntry_t
{
	/* Index values */
	uint32_t u32ComponentId;
	uint32_t u32VlanIndex;
	uint8_t au8Address[6];
	size_t u16Address_len;	/* # of uint8_t elements */
	uint32_t u32ReceivePort;
	
	/* Column values */
	uint8_t au8StaticEgressPorts[ETHERNET_PORT_MAP_SIZE];
	size_t u16StaticEgressPorts_len;	/* # of uint8_t elements */
	uint8_t au8ForbiddenEgressPorts[ETHERNET_PORT_MAP_SIZE];
	size_t u16ForbiddenEgressPorts_len;	/* # of uint8_t elements */
	uint8_t u8StorageType;
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} ieee8021QBridgeStaticUnicastEntry_t;

extern xBTree_t oIeee8021QBridgeStaticUnicastTable_BTree;

/* ieee8021QBridgeStaticUnicastTable table mapper */
void ieee8021QBridgeStaticUnicastTable_init (void);
ieee8021QBridgeStaticUnicastEntry_t * ieee8021QBridgeStaticUnicastTable_createEntry (
	uint32_t u32ComponentId,
	uint32_t u32VlanIndex,
	uint8_t *pau8Address, size_t u16Address_len,
	uint32_t u32ReceivePort);
ieee8021QBridgeStaticUnicastEntry_t * ieee8021QBridgeStaticUnicastTable_getByIndex (
	uint32_t u32ComponentId,
	uint32_t u32VlanIndex,
	uint8_t *pau8Address, size_t u16Address_len,
	uint32_t u32ReceivePort);
ieee8021QBridgeStaticUnicastEntry_t * ieee8021QBridgeStaticUnicastTable_getNextIndex (
	uint32_t u32ComponentId,
	uint32_t u32VlanIndex,
	uint8_t *pau8Address, size_t u16Address_len,
	uint32_t u32ReceivePort);
void ieee8021QBridgeStaticUnicastTable_removeEntry (ieee8021QBridgeStaticUnicastEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021QBridgeStaticUnicastTable_getFirst;
Netsnmp_Next_Data_Point ieee8021QBridgeStaticUnicastTable_getNext;
Netsnmp_Get_Data_Point ieee8021QBridgeStaticUnicastTable_get;
Netsnmp_Node_Handler ieee8021QBridgeStaticUnicastTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021QBridgeStaticMulticastTable definitions
 */
#define IEEE8021QBRIDGESTATICMULTICASTADDRESS 1
#define IEEE8021QBRIDGESTATICMULTICASTRECEIVEPORT 2
#define IEEE8021QBRIDGESTATICMULTICASTSTATICEGRESSPORTS 3
#define IEEE8021QBRIDGESTATICMULTICASTFORBIDDENEGRESSPORTS 4
#define IEEE8021QBRIDGESTATICMULTICASTSTORAGETYPE 5
#define IEEE8021QBRIDGESTATICMULTICASTROWSTATUS 6

enum
{
	/* enums for column ieee8021QBridgeStaticMulticastStorageType */
	ieee8021QBridgeStaticMulticastStorageType_other_c = 1,
	ieee8021QBridgeStaticMulticastStorageType_volatile_c = 2,
	ieee8021QBridgeStaticMulticastStorageType_nonVolatile_c = 3,
	ieee8021QBridgeStaticMulticastStorageType_permanent_c = 4,
	ieee8021QBridgeStaticMulticastStorageType_readOnly_c = 5,

	/* enums for column ieee8021QBridgeStaticMulticastRowStatus */
	ieee8021QBridgeStaticMulticastRowStatus_active_c = 1,
	ieee8021QBridgeStaticMulticastRowStatus_notInService_c = 2,
	ieee8021QBridgeStaticMulticastRowStatus_notReady_c = 3,
	ieee8021QBridgeStaticMulticastRowStatus_createAndGo_c = 4,
	ieee8021QBridgeStaticMulticastRowStatus_createAndWait_c = 5,
	ieee8021QBridgeStaticMulticastRowStatus_destroy_c = 6,
};

/* table ieee8021QBridgeStaticMulticastTable row entry data structure */
typedef struct ieee8021QBridgeStaticMulticastEntry_t
{
	/* Index values */
	uint32_t u32VlanCurrentComponentId;
	uint32_t u32VlanIndex;
	uint8_t au8Address[6];
	size_t u16Address_len;	/* # of uint8_t elements */
	uint32_t u32ReceivePort;
	
	/* Column values */
	uint8_t au8StaticEgressPorts[ETHERNET_PORT_MAP_SIZE];
	size_t u16StaticEgressPorts_len;	/* # of uint8_t elements */
	uint8_t au8ForbiddenEgressPorts[ETHERNET_PORT_MAP_SIZE];
	size_t u16ForbiddenEgressPorts_len;	/* # of uint8_t elements */
	uint8_t u8StorageType;
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} ieee8021QBridgeStaticMulticastEntry_t;

extern xBTree_t oIeee8021QBridgeStaticMulticastTable_BTree;

/* ieee8021QBridgeStaticMulticastTable table mapper */
void ieee8021QBridgeStaticMulticastTable_init (void);
ieee8021QBridgeStaticMulticastEntry_t * ieee8021QBridgeStaticMulticastTable_createEntry (
	uint32_t u32VlanCurrentComponentId,
	uint32_t u32VlanIndex,
	uint8_t *pau8Address, size_t u16Address_len,
	uint32_t u32ReceivePort);
ieee8021QBridgeStaticMulticastEntry_t * ieee8021QBridgeStaticMulticastTable_getByIndex (
	uint32_t u32VlanCurrentComponentId,
	uint32_t u32VlanIndex,
	uint8_t *pau8Address, size_t u16Address_len,
	uint32_t u32ReceivePort);
ieee8021QBridgeStaticMulticastEntry_t * ieee8021QBridgeStaticMulticastTable_getNextIndex (
	uint32_t u32VlanCurrentComponentId,
	uint32_t u32VlanIndex,
	uint8_t *pau8Address, size_t u16Address_len,
	uint32_t u32ReceivePort);
void ieee8021QBridgeStaticMulticastTable_removeEntry (ieee8021QBridgeStaticMulticastEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021QBridgeStaticMulticastTable_getFirst;
Netsnmp_Next_Data_Point ieee8021QBridgeStaticMulticastTable_getNext;
Netsnmp_Get_Data_Point ieee8021QBridgeStaticMulticastTable_get;
Netsnmp_Node_Handler ieee8021QBridgeStaticMulticastTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021QBridgeVlanCurrentTable definitions
 */
#define IEEE8021QBRIDGEVLANTIMEMARK 1
#define IEEE8021QBRIDGEVLANCURRENTCOMPONENTID 2
#define IEEE8021QBRIDGEVLANINDEX 3
#define IEEE8021QBRIDGEVLANFDBID 4
#define IEEE8021QBRIDGEVLANCURRENTEGRESSPORTS 5
#define IEEE8021QBRIDGEVLANCURRENTUNTAGGEDPORTS 6
#define IEEE8021QBRIDGEVLANSTATUS 7
#define IEEE8021QBRIDGEVLANCREATIONTIME 8

enum
{
	/* enums for column ieee8021QBridgeVlanStatus */
	ieee8021QBridgeVlanStatus_other_c = 1,
	ieee8021QBridgeVlanStatus_permanent_c = 2,
	ieee8021QBridgeVlanStatus_dynamicMvrp_c = 3,
};

/* table ieee8021QBridgeVlanCurrentTable row entry data structure */
typedef struct ieee8021QBridgeVlanCurrentEntry_t
{
	/* Index values */
	uint32_t u32TimeMark;
	uint32_t u32ComponentId;
	uint32_t u32Index;
	
	/* Column values */
	uint32_t u32FdbId;
	uint8_t au8EgressPorts[ETHERNET_PORT_MAP_SIZE];
	size_t u16EgressPorts_len;	/* # of uint8_t elements */
	uint8_t au8UntaggedPorts[ETHERNET_PORT_MAP_SIZE];
	size_t u16UntaggedPorts_len;	/* # of uint8_t elements */
	int32_t i32Status;
	uint32_t u32CreationTime;
	
	neIeee8021QBridgeVlanCurrentEntry_t oNe;
	
	uint8_t au8Learnt[ETHERNET_PORT_MAP_SIZE];
	size_t u16Learnt_len;	/* # of uint8_t elements */
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
	xBTree_Node_t oVlan_BTreeNode;
} ieee8021QBridgeVlanCurrentEntry_t;

extern xBTree_t oIeee8021QBridgeVlanCurrentTable_BTree;
extern xBTree_t oIeee8021QBridgeVlanCurrentTable_Vlan_BTree;

/* ieee8021QBridgeVlanCurrentTable table mapper */
void ieee8021QBridgeVlanCurrentTable_init (void);
ieee8021QBridgeVlanCurrentEntry_t * ieee8021QBridgeVlanCurrentTable_createEntry (
	uint32_t u32TimeMark,
	uint32_t u32ComponentId,
	uint32_t u32Index);
ieee8021QBridgeVlanCurrentEntry_t * ieee8021QBridgeVlanCurrentTable_getByIndex (
	uint32_t u32TimeMark,
	uint32_t u32ComponentId,
	uint32_t u32Index);
ieee8021QBridgeVlanCurrentEntry_t * ieee8021QBridgeVlanCurrentTable_getNextIndex (
	uint32_t u32TimeMark,
	uint32_t u32ComponentId,
	uint32_t u32Index);
ieee8021QBridgeVlanCurrentEntry_t * ieee8021QBridgeVlanCurrentTable_Vlan_getByIndex (
	uint32_t u32ComponentId,
	uint32_t u32Index);
ieee8021QBridgeVlanCurrentEntry_t * ieee8021QBridgeVlanCurrentTable_Vlan_getNextIndex (
	uint32_t u32ComponentId,
	uint32_t u32Index);
void ieee8021QBridgeVlanCurrentTable_removeEntry (ieee8021QBridgeVlanCurrentEntry_t *poEntry);
ieee8021QBridgeVlanCurrentEntry_t * ieee8021QBridgeVlanCurrentTable_createExt (
	uint32_t u32TimeMark,
	uint32_t u32ComponentId,
	uint32_t u32Index);
bool ieee8021QBridgeVlanCurrentTable_removeExt (ieee8021QBridgeVlanCurrentEntry_t *poEntry);
bool ieee8021QBridgeVlanCurrentTable_createHier (ieee8021QBridgeVlanCurrentEntry_t *poEntry);
bool ieee8021QBridgeVlanCurrentTable_removeHier (ieee8021QBridgeVlanCurrentEntry_t *poEntry);
bool ieee8021QBridgeVlanCurrentTable_vlanHandler (
	ieee8021BridgeBaseEntry_t *poComponent,
	ieee8021QBridgeVlanCurrentEntry_t *poEntry,
	uint8_t *pu8DisabledPorts, uint8_t *pu8TaggedPorts, uint8_t *pu8UntaggedPorts);
bool ieee8021QBridgeVlanCurrentRowStatus_handler (
	ieee8021BridgeBaseEntry_t *poComponent,
	ieee8021QBridgeVlanCurrentEntry_t *poEntry, uint8_t u8RowStatus);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021QBridgeVlanCurrentTable_getFirst;
Netsnmp_Next_Data_Point ieee8021QBridgeVlanCurrentTable_getNext;
Netsnmp_Get_Data_Point ieee8021QBridgeVlanCurrentTable_get;
Netsnmp_Node_Handler ieee8021QBridgeVlanCurrentTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021QBridgeVlanStaticTable definitions
 */
#define IEEE8021QBRIDGEVLANSTATICCOMPONENTID 1
#define IEEE8021QBRIDGEVLANSTATICVLANINDEX 2
#define IEEE8021QBRIDGEVLANSTATICNAME 3
#define IEEE8021QBRIDGEVLANSTATICEGRESSPORTS 4
#define IEEE8021QBRIDGEVLANFORBIDDENEGRESSPORTS 5
#define IEEE8021QBRIDGEVLANSTATICUNTAGGEDPORTS 6
#define IEEE8021QBRIDGEVLANSTATICROWSTATUS 7

enum
{
	/* enums for column ieee8021QBridgeVlanStaticRowStatus */
	ieee8021QBridgeVlanStaticRowStatus_active_c = 1,
	ieee8021QBridgeVlanStaticRowStatus_notInService_c = 2,
	ieee8021QBridgeVlanStaticRowStatus_notReady_c = 3,
	ieee8021QBridgeVlanStaticRowStatus_createAndGo_c = 4,
	ieee8021QBridgeVlanStaticRowStatus_createAndWait_c = 5,
	ieee8021QBridgeVlanStaticRowStatus_destroy_c = 6,
};

/* table ieee8021QBridgeVlanStaticTable row entry data structure */
typedef struct ieee8021QBridgeVlanStaticEntry_t
{
	/* Index values */
	uint32_t u32ComponentId;
	uint32_t u32VlanIndex;
	
	/* Column values */
	uint8_t au8Name[32];
	size_t u16Name_len;	/* # of uint8_t elements */
	uint8_t au8EgressPorts[ETHERNET_PORT_MAP_SIZE];
	size_t u16EgressPorts_len;	/* # of uint8_t elements */
	uint8_t au8ForbiddenEgressPorts[ETHERNET_PORT_MAP_SIZE];
	size_t u16ForbiddenEgressPorts_len;	/* # of uint8_t elements */
	uint8_t au8UntaggedPorts[ETHERNET_PORT_MAP_SIZE];
	size_t u16UntaggedPorts_len;	/* # of uint8_t elements */
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} ieee8021QBridgeVlanStaticEntry_t;

extern xBTree_t oIeee8021QBridgeVlanStaticTable_BTree;

/* ieee8021QBridgeVlanStaticTable table mapper */
void ieee8021QBridgeVlanStaticTable_init (void);
ieee8021QBridgeVlanStaticEntry_t * ieee8021QBridgeVlanStaticTable_createEntry (
	uint32_t u32ComponentId,
	uint32_t u32VlanIndex);
ieee8021QBridgeVlanStaticEntry_t * ieee8021QBridgeVlanStaticTable_getByIndex (
	uint32_t u32ComponentId,
	uint32_t u32VlanIndex);
ieee8021QBridgeVlanStaticEntry_t * ieee8021QBridgeVlanStaticTable_getNextIndex (
	uint32_t u32ComponentId,
	uint32_t u32VlanIndex);
void ieee8021QBridgeVlanStaticTable_removeEntry (ieee8021QBridgeVlanStaticEntry_t *poEntry);
ieee8021QBridgeVlanStaticEntry_t * ieee8021QBridgeVlanStaticTable_createExt (
	uint32_t u32ComponentId,
	uint32_t u32VlanIndex);
bool ieee8021QBridgeVlanStaticTable_removeExt (ieee8021QBridgeVlanStaticEntry_t *poEntry);
bool ieee8021QBridgeVlanStaticTable_createHier (ieee8021QBridgeVlanStaticEntry_t *poEntry);
bool ieee8021QBridgeVlanStaticTable_removeHier (ieee8021QBridgeVlanStaticEntry_t *poEntry);
bool ieee8021QBridgeVlanStaticTable_vlanUpdater (
	ieee8021BridgeBaseEntry_t *poComponent,
	ieee8021QBridgeVlanStaticEntry_t *poEntry,
	uint8_t *pu8EnabledPorts, uint8_t *pu8DisabledPorts, uint8_t *pu8UntaggedPorts);
bool ieee8021QBridgeVlanStaticTable_handler (
	ieee8021BridgeBaseEntry_t *poComponent,
	ieee8021QBridgeVlanStaticEntry_t *poEntry,
	uint8_t *pu8EgressPorts, uint8_t *pu8ForbiddenEgressPorts, uint8_t *pu8UntaggedPorts);
bool ieee8021QBridgeVlanStaticRowStatus_handler (
	ieee8021BridgeBaseEntry_t *poComponent,
	ieee8021QBridgeVlanStaticEntry_t *poEntry, uint8_t u8RowStatus);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021QBridgeVlanStaticTable_getFirst;
Netsnmp_Next_Data_Point ieee8021QBridgeVlanStaticTable_getNext;
Netsnmp_Get_Data_Point ieee8021QBridgeVlanStaticTable_get;
Netsnmp_Node_Handler ieee8021QBridgeVlanStaticTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021QBridgeNextFreeLocalVlanTable definitions
 */
#define IEEE8021QBRIDGENEXTFREELOCALVLANCOMPONENTID 1
#define IEEE8021QBRIDGENEXTFREELOCALVLANINDEX 2

/* table ieee8021QBridgeNextFreeLocalVlanTable row entry data structure */
typedef struct ieee8021QBridgeNextFreeLocalVlanEntry_t
{
	/* Index values */
	uint32_t u32ComponentId;
	
	/* Column values */
	uint32_t u32Index;
	
	xBTree_Node_t oBTreeNode;
} ieee8021QBridgeNextFreeLocalVlanEntry_t;

extern xBTree_t oIeee8021QBridgeNextFreeLocalVlanTable_BTree;

/* ieee8021QBridgeNextFreeLocalVlanTable table mapper */
void ieee8021QBridgeNextFreeLocalVlanTable_init (void);
ieee8021QBridgeNextFreeLocalVlanEntry_t * ieee8021QBridgeNextFreeLocalVlanTable_createEntry (
	uint32_t u32ComponentId);
ieee8021QBridgeNextFreeLocalVlanEntry_t * ieee8021QBridgeNextFreeLocalVlanTable_getByIndex (
	uint32_t u32ComponentId);
ieee8021QBridgeNextFreeLocalVlanEntry_t * ieee8021QBridgeNextFreeLocalVlanTable_getNextIndex (
	uint32_t u32ComponentId);
void ieee8021QBridgeNextFreeLocalVlanTable_removeEntry (ieee8021QBridgeNextFreeLocalVlanEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021QBridgeNextFreeLocalVlanTable_getFirst;
Netsnmp_Next_Data_Point ieee8021QBridgeNextFreeLocalVlanTable_getNext;
Netsnmp_Get_Data_Point ieee8021QBridgeNextFreeLocalVlanTable_get;
Netsnmp_Node_Handler ieee8021QBridgeNextFreeLocalVlanTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021QBridgePortTable definitions
 */
#define IEEE8021QBRIDGEPORTPVID 1
#define IEEE8021QBRIDGEPORTACCEPTABLEFRAMETYPES 2
#define IEEE8021QBRIDGEPORTINGRESSFILTERING 3
#define IEEE8021QBRIDGEPORTMVRPENABLEDSTATUS 4
#define IEEE8021QBRIDGEPORTMVRPFAILEDREGISTRATIONS 5
#define IEEE8021QBRIDGEPORTMVRPLASTPDUORIGIN 6
#define IEEE8021QBRIDGEPORTRESTRICTEDVLANREGISTRATION 7

enum
{
	/* enums for column ieee8021QBridgePortAcceptableFrameTypes */
	ieee8021QBridgePortAcceptableFrameTypes_admitAll_c = 1,
	ieee8021QBridgePortAcceptableFrameTypes_admitUntaggedAndPriority_c = 2,
	ieee8021QBridgePortAcceptableFrameTypes_admitTagged_c = 3,

	/* enums for column ieee8021QBridgePortIngressFiltering */
	ieee8021QBridgePortIngressFiltering_true_c = 1,
	ieee8021QBridgePortIngressFiltering_false_c = 2,

	/* enums for column ieee8021QBridgePortMvrpEnabledStatus */
	ieee8021QBridgePortMvrpEnabledStatus_true_c = 1,
	ieee8021QBridgePortMvrpEnabledStatus_false_c = 2,

	/* enums for column ieee8021QBridgePortRestrictedVlanRegistration */
	ieee8021QBridgePortRestrictedVlanRegistration_true_c = 1,
	ieee8021QBridgePortRestrictedVlanRegistration_false_c = 2,
};

/* table ieee8021QBridgePortTable row entry data structure */
typedef struct ieee8021QBridgePortEntry_t
{
	/* Index values */
	uint32_t u32BridgeBasePortComponentId;
	uint32_t u32BridgeBasePort;
	
	/* Column values */
	uint32_t u32PVid;
	int32_t i32AcceptableFrameTypes;
	uint8_t u8IngressFiltering;
	uint8_t u8MvrpEnabledStatus;
	uint64_t u64MvrpFailedRegistrations;
	uint8_t au8MvrpLastPduOrigin[6];
	size_t u16MvrpLastPduOrigin_len;	/* # of uint8_t elements */
	uint8_t u8RestrictedVlanRegistration;
	
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} ieee8021QBridgePortEntry_t;

extern xBTree_t oIeee8021QBridgePortTable_BTree;

/* ieee8021QBridgePortTable table mapper */
void ieee8021QBridgePortTable_init (void);
ieee8021QBridgePortEntry_t * ieee8021QBridgePortTable_createEntry (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort);
ieee8021QBridgePortEntry_t * ieee8021QBridgePortTable_getByIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort);
ieee8021QBridgePortEntry_t * ieee8021QBridgePortTable_getNextIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort);
void ieee8021QBridgePortTable_removeEntry (ieee8021QBridgePortEntry_t *poEntry);
ieee8021QBridgePortEntry_t * ieee8021QBridgePortTable_createExt (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort);
bool ieee8021QBridgePortTable_removeExt (ieee8021QBridgePortEntry_t *poEntry);
bool ieee8021QBridgePortRowStatus_handler (
	ieee8021BridgeBaseEntry_t *poComponent,
	ieee8021QBridgePortEntry_t *poEntry, uint8_t u8RowStatus);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021QBridgePortTable_getFirst;
Netsnmp_Next_Data_Point ieee8021QBridgePortTable_getNext;
Netsnmp_Get_Data_Point ieee8021QBridgePortTable_get;
Netsnmp_Node_Handler ieee8021QBridgePortTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021QBridgePortVlanStatisticsTable definitions
 */
#define IEEE8021QBRIDGETPVLANPORTINFRAMES 1
#define IEEE8021QBRIDGETPVLANPORTOUTFRAMES 2
#define IEEE8021QBRIDGETPVLANPORTINDISCARDS 3

/* table ieee8021QBridgePortVlanStatisticsTable row entry data structure */
typedef struct ieee8021QBridgePortVlanStatisticsEntry_t
{
	/* Index values */
	uint32_t u32BridgeBasePortComponentId;
	uint32_t u32BridgeBasePort;
	uint32_t u32VlanIndex;
	
	/* Column values */
	uint64_t u64InFrames;
	uint64_t u64OutFrames;
	uint64_t u64InDiscards;
	
	xBTree_Node_t oBTreeNode;
} ieee8021QBridgePortVlanStatisticsEntry_t;

extern xBTree_t oIeee8021QBridgePortVlanStatisticsTable_BTree;

/* ieee8021QBridgePortVlanStatisticsTable table mapper */
void ieee8021QBridgePortVlanStatisticsTable_init (void);
ieee8021QBridgePortVlanStatisticsEntry_t * ieee8021QBridgePortVlanStatisticsTable_createEntry (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	uint32_t u32VlanIndex);
ieee8021QBridgePortVlanStatisticsEntry_t * ieee8021QBridgePortVlanStatisticsTable_getByIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	uint32_t u32VlanIndex);
ieee8021QBridgePortVlanStatisticsEntry_t * ieee8021QBridgePortVlanStatisticsTable_getNextIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	uint32_t u32VlanIndex);
void ieee8021QBridgePortVlanStatisticsTable_removeEntry (ieee8021QBridgePortVlanStatisticsEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021QBridgePortVlanStatisticsTable_getFirst;
Netsnmp_Next_Data_Point ieee8021QBridgePortVlanStatisticsTable_getNext;
Netsnmp_Get_Data_Point ieee8021QBridgePortVlanStatisticsTable_get;
Netsnmp_Node_Handler ieee8021QBridgePortVlanStatisticsTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021QBridgeLearningConstraintsTable definitions
 */
#define IEEE8021QBRIDGELEARNINGCONSTRAINTSCOMPONENTID 1
#define IEEE8021QBRIDGELEARNINGCONSTRAINTSVLAN 2
#define IEEE8021QBRIDGELEARNINGCONSTRAINTSSET 3
#define IEEE8021QBRIDGELEARNINGCONSTRAINTSTYPE 4
#define IEEE8021QBRIDGELEARNINGCONSTRAINTSSTATUS 5

enum
{
	/* enums for column ieee8021QBridgeLearningConstraintsType */
	ieee8021QBridgeLearningConstraintsType_independent_c = 1,
	ieee8021QBridgeLearningConstraintsType_shared_c = 2,

	/* enums for column ieee8021QBridgeLearningConstraintsStatus */
	ieee8021QBridgeLearningConstraintsStatus_active_c = 1,
	ieee8021QBridgeLearningConstraintsStatus_notInService_c = 2,
	ieee8021QBridgeLearningConstraintsStatus_notReady_c = 3,
	ieee8021QBridgeLearningConstraintsStatus_createAndGo_c = 4,
	ieee8021QBridgeLearningConstraintsStatus_createAndWait_c = 5,
	ieee8021QBridgeLearningConstraintsStatus_destroy_c = 6,
};

/* table ieee8021QBridgeLearningConstraintsTable row entry data structure */
typedef struct ieee8021QBridgeLearningConstraintsEntry_t
{
	/* Index values */
	uint32_t u32ComponentId;
	uint32_t u32Vlan;
	int32_t i32Set;
	
	/* Column values */
	int32_t i32Type;
	uint8_t u8Status;
	
	xBTree_Node_t oBTreeNode;
} ieee8021QBridgeLearningConstraintsEntry_t;

extern xBTree_t oIeee8021QBridgeLearningConstraintsTable_BTree;

/* ieee8021QBridgeLearningConstraintsTable table mapper */
void ieee8021QBridgeLearningConstraintsTable_init (void);
ieee8021QBridgeLearningConstraintsEntry_t * ieee8021QBridgeLearningConstraintsTable_createEntry (
	uint32_t u32ComponentId,
	uint32_t u32Vlan,
	int32_t i32Set);
ieee8021QBridgeLearningConstraintsEntry_t * ieee8021QBridgeLearningConstraintsTable_getByIndex (
	uint32_t u32ComponentId,
	uint32_t u32Vlan,
	int32_t i32Set);
ieee8021QBridgeLearningConstraintsEntry_t * ieee8021QBridgeLearningConstraintsTable_getNextIndex (
	uint32_t u32ComponentId,
	uint32_t u32Vlan,
	int32_t i32Set);
void ieee8021QBridgeLearningConstraintsTable_removeEntry (ieee8021QBridgeLearningConstraintsEntry_t *poEntry);
ieee8021QBridgeLearningConstraintsEntry_t *ieee8021QBridgeLearningConstraintsTable_createExt (
	uint32_t u32ComponentId,
	uint32_t u32Vlan,
	int32_t i32Set);
bool ieee8021QBridgeLearningConstraintsTable_removeExt (ieee8021QBridgeLearningConstraintsEntry_t *poEntry);
bool ieee8021QBridgeLearningConstraintsTable_createHier (ieee8021QBridgeLearningConstraintsEntry_t *poEntry);
bool ieee8021QBridgeLearningConstraintsTable_removeHier (ieee8021QBridgeLearningConstraintsEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021QBridgeLearningConstraintsTable_getFirst;
Netsnmp_Next_Data_Point ieee8021QBridgeLearningConstraintsTable_getNext;
Netsnmp_Get_Data_Point ieee8021QBridgeLearningConstraintsTable_get;
Netsnmp_Node_Handler ieee8021QBridgeLearningConstraintsTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021QBridgeLearningConstraintDefaultsTable definitions
 */
#define IEEE8021QBRIDGELEARNINGCONSTRAINTDEFAULTSCOMPONENTID 1
#define IEEE8021QBRIDGELEARNINGCONSTRAINTDEFAULTSSET 2
#define IEEE8021QBRIDGELEARNINGCONSTRAINTDEFAULTSTYPE 3

enum
{
	/* enums for column ieee8021QBridgeLearningConstraintDefaultsType */
	ieee8021QBridgeLearningConstraintDefaultsType_independent_c = 1,
	ieee8021QBridgeLearningConstraintDefaultsType_shared_c = 2,
};

/* table ieee8021QBridgeLearningConstraintDefaultsTable row entry data structure */
typedef struct ieee8021QBridgeLearningConstraintDefaultsEntry_t
{
	/* Index values */
	uint32_t u32ComponentId;
	
	/* Column values */
	int32_t i32Set;
	int32_t i32Type;
	
	xBTree_Node_t oBTreeNode;
} ieee8021QBridgeLearningConstraintDefaultsEntry_t;

extern xBTree_t oIeee8021QBridgeLearningConstraintDefaultsTable_BTree;

/* ieee8021QBridgeLearningConstraintDefaultsTable table mapper */
void ieee8021QBridgeLearningConstraintDefaultsTable_init (void);
ieee8021QBridgeLearningConstraintDefaultsEntry_t * ieee8021QBridgeLearningConstraintDefaultsTable_createEntry (
	uint32_t u32ComponentId);
ieee8021QBridgeLearningConstraintDefaultsEntry_t * ieee8021QBridgeLearningConstraintDefaultsTable_getByIndex (
	uint32_t u32ComponentId);
ieee8021QBridgeLearningConstraintDefaultsEntry_t * ieee8021QBridgeLearningConstraintDefaultsTable_getNextIndex (
	uint32_t u32ComponentId);
void ieee8021QBridgeLearningConstraintDefaultsTable_removeEntry (ieee8021QBridgeLearningConstraintDefaultsEntry_t *poEntry);
ieee8021QBridgeLearningConstraintDefaultsEntry_t *ieee8021QBridgeLearningConstraintDefaultsTable_createExt (
	uint32_t u32ComponentId);
bool ieee8021QBridgeLearningConstraintDefaultsTable_removeExt (ieee8021QBridgeLearningConstraintDefaultsEntry_t *poEntry);
bool ieee8021QBridgeLearningConstraintDefaultsTable_createHier (ieee8021QBridgeLearningConstraintDefaultsEntry_t *poEntry);
bool ieee8021QBridgeLearningConstraintDefaultsTable_removeHier (ieee8021QBridgeLearningConstraintDefaultsEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021QBridgeLearningConstraintDefaultsTable_getFirst;
Netsnmp_Next_Data_Point ieee8021QBridgeLearningConstraintDefaultsTable_getNext;
Netsnmp_Get_Data_Point ieee8021QBridgeLearningConstraintDefaultsTable_get;
Netsnmp_Node_Handler ieee8021QBridgeLearningConstraintDefaultsTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021QBridgeProtocolGroupTable definitions
 */
#define IEEE8021QBRIDGEPROTOCOLGROUPCOMPONENTID 1
#define IEEE8021QBRIDGEPROTOCOLTEMPLATEFRAMETYPE 2
#define IEEE8021QBRIDGEPROTOCOLTEMPLATEPROTOCOLVALUE 3
#define IEEE8021QBRIDGEPROTOCOLGROUPID 4
#define IEEE8021QBRIDGEPROTOCOLGROUPROWSTATUS 5

enum
{
	/* enums for column ieee8021QBridgeProtocolTemplateFrameType */
	ieee8021QBridgeProtocolTemplateFrameType_ethernet_c = 1,
	ieee8021QBridgeProtocolTemplateFrameType_rfc1042_c = 2,
	ieee8021QBridgeProtocolTemplateFrameType_snap8021H_c = 3,
	ieee8021QBridgeProtocolTemplateFrameType_snapOther_c = 4,
	ieee8021QBridgeProtocolTemplateFrameType_llcOther_c = 5,

	/* enums for column ieee8021QBridgeProtocolGroupRowStatus */
	ieee8021QBridgeProtocolGroupRowStatus_active_c = 1,
	ieee8021QBridgeProtocolGroupRowStatus_notInService_c = 2,
	ieee8021QBridgeProtocolGroupRowStatus_notReady_c = 3,
	ieee8021QBridgeProtocolGroupRowStatus_createAndGo_c = 4,
	ieee8021QBridgeProtocolGroupRowStatus_createAndWait_c = 5,
	ieee8021QBridgeProtocolGroupRowStatus_destroy_c = 6,
};

/* table ieee8021QBridgeProtocolGroupTable row entry data structure */
typedef struct ieee8021QBridgeProtocolGroupEntry_t
{
	/* Index values */
	uint32_t u32ComponentId;
	int32_t i32TemplateFrameType;
	uint8_t au8TemplateProtocolValue[5];
	size_t u16TemplateProtocolValue_len;	/* # of uint8_t elements */
	
	/* Column values */
	int32_t i32Id;
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} ieee8021QBridgeProtocolGroupEntry_t;

extern xBTree_t oIeee8021QBridgeProtocolGroupTable_BTree;

/* ieee8021QBridgeProtocolGroupTable table mapper */
void ieee8021QBridgeProtocolGroupTable_init (void);
ieee8021QBridgeProtocolGroupEntry_t * ieee8021QBridgeProtocolGroupTable_createEntry (
	uint32_t u32ComponentId,
	int32_t i32TemplateFrameType,
	uint8_t *pau8TemplateProtocolValue, size_t u16TemplateProtocolValue_len);
ieee8021QBridgeProtocolGroupEntry_t * ieee8021QBridgeProtocolGroupTable_getByIndex (
	uint32_t u32ComponentId,
	int32_t i32TemplateFrameType,
	uint8_t *pau8TemplateProtocolValue, size_t u16TemplateProtocolValue_len);
ieee8021QBridgeProtocolGroupEntry_t * ieee8021QBridgeProtocolGroupTable_getNextIndex (
	uint32_t u32ComponentId,
	int32_t i32TemplateFrameType,
	uint8_t *pau8TemplateProtocolValue, size_t u16TemplateProtocolValue_len);
void ieee8021QBridgeProtocolGroupTable_removeEntry (ieee8021QBridgeProtocolGroupEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021QBridgeProtocolGroupTable_getFirst;
Netsnmp_Next_Data_Point ieee8021QBridgeProtocolGroupTable_getNext;
Netsnmp_Get_Data_Point ieee8021QBridgeProtocolGroupTable_get;
Netsnmp_Node_Handler ieee8021QBridgeProtocolGroupTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021QBridgeProtocolPortTable definitions
 */
#define IEEE8021QBRIDGEPROTOCOLPORTGROUPID 1
#define IEEE8021QBRIDGEPROTOCOLPORTGROUPVID 2
#define IEEE8021QBRIDGEPROTOCOLPORTROWSTATUS 3

enum
{
	/* enums for column ieee8021QBridgeProtocolPortRowStatus */
	ieee8021QBridgeProtocolPortRowStatus_active_c = 1,
	ieee8021QBridgeProtocolPortRowStatus_notInService_c = 2,
	ieee8021QBridgeProtocolPortRowStatus_notReady_c = 3,
	ieee8021QBridgeProtocolPortRowStatus_createAndGo_c = 4,
	ieee8021QBridgeProtocolPortRowStatus_createAndWait_c = 5,
	ieee8021QBridgeProtocolPortRowStatus_destroy_c = 6,
};

/* table ieee8021QBridgeProtocolPortTable row entry data structure */
typedef struct ieee8021QBridgeProtocolPortEntry_t
{
	/* Index values */
	uint32_t u32BridgeBasePortComponentId;
	uint32_t u32BridgeBasePort;
	int32_t i32GroupId;
	
	/* Column values */
	uint32_t u32GroupVid;
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} ieee8021QBridgeProtocolPortEntry_t;

extern xBTree_t oIeee8021QBridgeProtocolPortTable_BTree;

/* ieee8021QBridgeProtocolPortTable table mapper */
void ieee8021QBridgeProtocolPortTable_init (void);
ieee8021QBridgeProtocolPortEntry_t * ieee8021QBridgeProtocolPortTable_createEntry (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	int32_t i32GroupId);
ieee8021QBridgeProtocolPortEntry_t * ieee8021QBridgeProtocolPortTable_getByIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	int32_t i32GroupId);
ieee8021QBridgeProtocolPortEntry_t * ieee8021QBridgeProtocolPortTable_getNextIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	int32_t i32GroupId);
void ieee8021QBridgeProtocolPortTable_removeEntry (ieee8021QBridgeProtocolPortEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021QBridgeProtocolPortTable_getFirst;
Netsnmp_Next_Data_Point ieee8021QBridgeProtocolPortTable_getNext;
Netsnmp_Get_Data_Point ieee8021QBridgeProtocolPortTable_get;
Netsnmp_Node_Handler ieee8021QBridgeProtocolPortTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021QBridgeIngressVidXTable definitions
 */
#define IEEE8021QBRIDGEINGRESSVIDXLOCALVID 1
#define IEEE8021QBRIDGEINGRESSVIDXRELAYVID 2
#define IEEE8021QBRIDGEINGRESSVIDXROWSTATUS 3

enum
{
	/* enums for column ieee8021QBridgeIngressVidXRowStatus */
	ieee8021QBridgeIngressVidXRowStatus_active_c = 1,
	ieee8021QBridgeIngressVidXRowStatus_notInService_c = 2,
	ieee8021QBridgeIngressVidXRowStatus_notReady_c = 3,
	ieee8021QBridgeIngressVidXRowStatus_createAndGo_c = 4,
	ieee8021QBridgeIngressVidXRowStatus_createAndWait_c = 5,
	ieee8021QBridgeIngressVidXRowStatus_destroy_c = 6,
};

/* table ieee8021QBridgeIngressVidXTable row entry data structure */
typedef struct ieee8021QBridgeIngressVidXEntry_t
{
	/* Index values */
	uint32_t u32BridgeBasePortComponentId;
	uint32_t u32BridgeBasePort;
	uint32_t u32LocalVid;
	
	/* Column values */
	uint32_t u32RelayVid;
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} ieee8021QBridgeIngressVidXEntry_t;

extern xBTree_t oIeee8021QBridgeIngressVidXTable_BTree;

/* ieee8021QBridgeIngressVidXTable table mapper */
void ieee8021QBridgeIngressVidXTable_init (void);
ieee8021QBridgeIngressVidXEntry_t * ieee8021QBridgeIngressVidXTable_createEntry (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	uint32_t u32LocalVid);
ieee8021QBridgeIngressVidXEntry_t * ieee8021QBridgeIngressVidXTable_getByIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	uint32_t u32LocalVid);
ieee8021QBridgeIngressVidXEntry_t * ieee8021QBridgeIngressVidXTable_getNextIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	uint32_t u32LocalVid);
void ieee8021QBridgeIngressVidXTable_removeEntry (ieee8021QBridgeIngressVidXEntry_t *poEntry);
bool ieee8021QBridgeIngressVidXRowStatus_handler (
	ieee8021QBridgeIngressVidXEntry_t *poEntry, uint8_t u8RowStatus);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021QBridgeIngressVidXTable_getFirst;
Netsnmp_Next_Data_Point ieee8021QBridgeIngressVidXTable_getNext;
Netsnmp_Get_Data_Point ieee8021QBridgeIngressVidXTable_get;
Netsnmp_Node_Handler ieee8021QBridgeIngressVidXTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021QBridgeEgressVidXTable definitions
 */
#define IEEE8021QBRIDGEEGRESSVIDXRELAYVID 1
#define IEEE8021QBRIDGEEGRESSVIDXLOCALVID 2
#define IEEE8021QBRIDGEEGRESSVIDXROWSTATUS 3

enum
{
	/* enums for column ieee8021QBridgeEgressVidXRowStatus */
	ieee8021QBridgeEgressVidXRowStatus_active_c = 1,
	ieee8021QBridgeEgressVidXRowStatus_notInService_c = 2,
	ieee8021QBridgeEgressVidXRowStatus_notReady_c = 3,
	ieee8021QBridgeEgressVidXRowStatus_createAndGo_c = 4,
	ieee8021QBridgeEgressVidXRowStatus_createAndWait_c = 5,
	ieee8021QBridgeEgressVidXRowStatus_destroy_c = 6,
};

/* table ieee8021QBridgeEgressVidXTable row entry data structure */
typedef struct ieee8021QBridgeEgressVidXEntry_t
{
	/* Index values */
	uint32_t u32BridgeBaseComponentId;
	uint32_t u32BridgeBasePort;
	uint32_t u32RelayVid;
	
	/* Column values */
	uint32_t u32LocalVid;
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} ieee8021QBridgeEgressVidXEntry_t;

extern xBTree_t oIeee8021QBridgeEgressVidXTable_BTree;

/* ieee8021QBridgeEgressVidXTable table mapper */
void ieee8021QBridgeEgressVidXTable_init (void);
ieee8021QBridgeEgressVidXEntry_t * ieee8021QBridgeEgressVidXTable_createEntry (
	uint32_t u32BridgeBaseComponentId,
	uint32_t u32BridgeBasePort,
	uint32_t u32RelayVid);
ieee8021QBridgeEgressVidXEntry_t * ieee8021QBridgeEgressVidXTable_getByIndex (
	uint32_t u32BridgeBaseComponentId,
	uint32_t u32BridgeBasePort,
	uint32_t u32RelayVid);
ieee8021QBridgeEgressVidXEntry_t * ieee8021QBridgeEgressVidXTable_getNextIndex (
	uint32_t u32BridgeBaseComponentId,
	uint32_t u32BridgeBasePort,
	uint32_t u32RelayVid);
void ieee8021QBridgeEgressVidXTable_removeEntry (ieee8021QBridgeEgressVidXEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021QBridgeEgressVidXTable_getFirst;
Netsnmp_Next_Data_Point ieee8021QBridgeEgressVidXTable_getNext;
Netsnmp_Get_Data_Point ieee8021QBridgeEgressVidXTable_get;
Netsnmp_Node_Handler ieee8021QBridgeEgressVidXTable_mapper;
#endif	/* SNMP_SRC */



#	ifdef __cplusplus
}
#	endif

#endif /* __IEEE8021QBRIDGEMIB_H__ */
