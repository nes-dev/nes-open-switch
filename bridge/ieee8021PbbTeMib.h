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

#ifndef __IEEE8021PBBTEMIB_H__
#	define __IEEE8021PBBTEMIB_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include "lib/binaryTree.h"
#include "lib/snmp.h"

#define TOBE_REPLACED 1


/**
 *	agent MIB function
 */
void ieee8021PbbTeMib_init (void);


/**
 *	table mapper(s)
 */
/**
 *	table ieee8021PbbTeProtectionGroupListTable definitions
 */
#define IEEE8021PBBTEPROTECTIONGROUPLISTGROUPID 1
#define IEEE8021PBBTEPROTECTIONGROUPLISTMD 2
#define IEEE8021PBBTEPROTECTIONGROUPLISTWORKINGMA 3
#define IEEE8021PBBTEPROTECTIONGROUPLISTPROTECTIONMA 4
#define IEEE8021PBBTEPROTECTIONGROUPLISTSTORAGETYPE 5
#define IEEE8021PBBTEPROTECTIONGROUPLISTROWSTATUS 6

enum
{
	/* enums for column ieee8021PbbTeProtectionGroupListStorageType */
	ieee8021PbbTeProtectionGroupListStorageType_other_c = 1,
	ieee8021PbbTeProtectionGroupListStorageType_volatile_c = 2,
	ieee8021PbbTeProtectionGroupListStorageType_nonVolatile_c = 3,
	ieee8021PbbTeProtectionGroupListStorageType_permanent_c = 4,
	ieee8021PbbTeProtectionGroupListStorageType_readOnly_c = 5,

	/* enums for column ieee8021PbbTeProtectionGroupListRowStatus */
	ieee8021PbbTeProtectionGroupListRowStatus_active_c = 1,
	ieee8021PbbTeProtectionGroupListRowStatus_notInService_c = 2,
	ieee8021PbbTeProtectionGroupListRowStatus_notReady_c = 3,
	ieee8021PbbTeProtectionGroupListRowStatus_createAndGo_c = 4,
	ieee8021PbbTeProtectionGroupListRowStatus_createAndWait_c = 5,
	ieee8021PbbTeProtectionGroupListRowStatus_destroy_c = 6,
};

/* table ieee8021PbbTeProtectionGroupListTable row entry data structure */
typedef struct ieee8021PbbTeProtectionGroupListEntry_t
{
	/* Index values */
	uint32_t u32BridgeBaseComponentId;
	uint32_t u32GroupId;
	
	/* Column values */
	uint32_t u32MD;
	uint32_t u32WorkingMA;
	uint32_t u32ProtectionMA;
	uint8_t u8StorageType;
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} ieee8021PbbTeProtectionGroupListEntry_t;

extern xBTree_t oIeee8021PbbTeProtectionGroupListTable_BTree;

/* ieee8021PbbTeProtectionGroupListTable table mapper */
void ieee8021PbbTeProtectionGroupListTable_init (void);
ieee8021PbbTeProtectionGroupListEntry_t * ieee8021PbbTeProtectionGroupListTable_createEntry (
	uint32_t u32BridgeBaseComponentId,
	uint32_t u32GroupId);
ieee8021PbbTeProtectionGroupListEntry_t * ieee8021PbbTeProtectionGroupListTable_getByIndex (
	uint32_t u32BridgeBaseComponentId,
	uint32_t u32GroupId);
ieee8021PbbTeProtectionGroupListEntry_t * ieee8021PbbTeProtectionGroupListTable_getNextIndex (
	uint32_t u32BridgeBaseComponentId,
	uint32_t u32GroupId);
void ieee8021PbbTeProtectionGroupListTable_removeEntry (ieee8021PbbTeProtectionGroupListEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021PbbTeProtectionGroupListTable_getFirst;
Netsnmp_Next_Data_Point ieee8021PbbTeProtectionGroupListTable_getNext;
Netsnmp_Get_Data_Point ieee8021PbbTeProtectionGroupListTable_get;
Netsnmp_Node_Handler ieee8021PbbTeProtectionGroupListTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021PbbTeMASharedGroupTable definitions
 */
#define IEEE8021PBBTEMASHAREDGROUPSUBINDEX 1
#define IEEE8021PBBTEMASHAREDGROUPID 2

/* table ieee8021PbbTeMASharedGroupTable row entry data structure */
typedef struct ieee8021PbbTeMASharedGroupEntry_t
{
	/* Index values */
	uint32_t u32BridgeBaseComponentId;
	uint32_t u32PbbTeProtectionGroupListGroupId;
	uint32_t u32SubIndex;
	
	/* Column values */
	uint32_t u32Id;
	
	xBTree_Node_t oBTreeNode;
} ieee8021PbbTeMASharedGroupEntry_t;

extern xBTree_t oIeee8021PbbTeMASharedGroupTable_BTree;

/* ieee8021PbbTeMASharedGroupTable table mapper */
void ieee8021PbbTeMASharedGroupTable_init (void);
ieee8021PbbTeMASharedGroupEntry_t * ieee8021PbbTeMASharedGroupTable_createEntry (
	uint32_t u32BridgeBaseComponentId,
	uint32_t u32PbbTeProtectionGroupListGroupId,
	uint32_t u32SubIndex);
ieee8021PbbTeMASharedGroupEntry_t * ieee8021PbbTeMASharedGroupTable_getByIndex (
	uint32_t u32BridgeBaseComponentId,
	uint32_t u32PbbTeProtectionGroupListGroupId,
	uint32_t u32SubIndex);
ieee8021PbbTeMASharedGroupEntry_t * ieee8021PbbTeMASharedGroupTable_getNextIndex (
	uint32_t u32BridgeBaseComponentId,
	uint32_t u32PbbTeProtectionGroupListGroupId,
	uint32_t u32SubIndex);
void ieee8021PbbTeMASharedGroupTable_removeEntry (ieee8021PbbTeMASharedGroupEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021PbbTeMASharedGroupTable_getFirst;
Netsnmp_Next_Data_Point ieee8021PbbTeMASharedGroupTable_getNext;
Netsnmp_Get_Data_Point ieee8021PbbTeMASharedGroupTable_get;
Netsnmp_Node_Handler ieee8021PbbTeMASharedGroupTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021PbbTeTesiTable definitions
 */
#define IEEE8021PBBTETESIID 1
#define IEEE8021PBBTETESICOMPONENT 2
#define IEEE8021PBBTETESIBRIDGEPORT 3
#define IEEE8021PBBTETESISTORAGETYPE 4
#define IEEE8021PBBTETESIROWSTATUS 5

enum
{
	/* enums for column ieee8021PbbTeTesiStorageType */
	ieee8021PbbTeTesiStorageType_other_c = 1,
	ieee8021PbbTeTesiStorageType_volatile_c = 2,
	ieee8021PbbTeTesiStorageType_nonVolatile_c = 3,
	ieee8021PbbTeTesiStorageType_permanent_c = 4,
	ieee8021PbbTeTesiStorageType_readOnly_c = 5,

	/* enums for column ieee8021PbbTeTesiRowStatus */
	ieee8021PbbTeTesiRowStatus_active_c = 1,
	ieee8021PbbTeTesiRowStatus_notInService_c = 2,
	ieee8021PbbTeTesiRowStatus_notReady_c = 3,
	ieee8021PbbTeTesiRowStatus_createAndGo_c = 4,
	ieee8021PbbTeTesiRowStatus_createAndWait_c = 5,
	ieee8021PbbTeTesiRowStatus_destroy_c = 6,
};

/* table ieee8021PbbTeTesiTable row entry data structure */
typedef struct ieee8021PbbTeTesiEntry_t
{
	/* Index values */
	uint32_t u32Id;
	
	/* Column values */
	uint32_t u32Component;
	uint32_t u32BridgePort;
	uint8_t u8StorageType;
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} ieee8021PbbTeTesiEntry_t;

extern xBTree_t oIeee8021PbbTeTesiTable_BTree;

/* ieee8021PbbTeTesiTable table mapper */
void ieee8021PbbTeTesiTable_init (void);
ieee8021PbbTeTesiEntry_t * ieee8021PbbTeTesiTable_createEntry (
	uint32_t u32Id);
ieee8021PbbTeTesiEntry_t * ieee8021PbbTeTesiTable_getByIndex (
	uint32_t u32Id);
ieee8021PbbTeTesiEntry_t * ieee8021PbbTeTesiTable_getNextIndex (
	uint32_t u32Id);
void ieee8021PbbTeTesiTable_removeEntry (ieee8021PbbTeTesiEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021PbbTeTesiTable_getFirst;
Netsnmp_Next_Data_Point ieee8021PbbTeTesiTable_getNext;
Netsnmp_Get_Data_Point ieee8021PbbTeTesiTable_get;
Netsnmp_Node_Handler ieee8021PbbTeTesiTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021PbbTeTeSiEspTable definitions
 */
#define IEEE8021PBBTETESIESPESPINDEX 1
#define IEEE8021PBBTETESIESPESP 2
#define IEEE8021PBBTETESIESPSTORAGETYPE 3
#define IEEE8021PBBTETESIESPROWSTATUS 4

enum
{
	/* enums for column ieee8021PbbTeTeSiEspStorageType */
	ieee8021PbbTeTeSiEspStorageType_other_c = 1,
	ieee8021PbbTeTeSiEspStorageType_volatile_c = 2,
	ieee8021PbbTeTeSiEspStorageType_nonVolatile_c = 3,
	ieee8021PbbTeTeSiEspStorageType_permanent_c = 4,
	ieee8021PbbTeTeSiEspStorageType_readOnly_c = 5,

	/* enums for column ieee8021PbbTeTeSiEspRowStatus */
	ieee8021PbbTeTeSiEspRowStatus_active_c = 1,
	ieee8021PbbTeTeSiEspRowStatus_notInService_c = 2,
	ieee8021PbbTeTeSiEspRowStatus_notReady_c = 3,
	ieee8021PbbTeTeSiEspRowStatus_createAndGo_c = 4,
	ieee8021PbbTeTeSiEspRowStatus_createAndWait_c = 5,
	ieee8021PbbTeTeSiEspRowStatus_destroy_c = 6,
};

/* table ieee8021PbbTeTeSiEspTable row entry data structure */
typedef struct ieee8021PbbTeTeSiEspEntry_t
{
	/* Index values */
	uint32_t u32TesiId;
	uint32_t u32EspIndex;
	
	/* Column values */
	uint8_t au8Esp[14];
	size_t u16Esp_len;	/* # of uint8_t elements */
	uint8_t u8StorageType;
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} ieee8021PbbTeTeSiEspEntry_t;

extern xBTree_t oIeee8021PbbTeTeSiEspTable_BTree;

/* ieee8021PbbTeTeSiEspTable table mapper */
void ieee8021PbbTeTeSiEspTable_init (void);
ieee8021PbbTeTeSiEspEntry_t * ieee8021PbbTeTeSiEspTable_createEntry (
	uint32_t u32TesiId,
	uint32_t u32EspIndex);
ieee8021PbbTeTeSiEspEntry_t * ieee8021PbbTeTeSiEspTable_getByIndex (
	uint32_t u32TesiId,
	uint32_t u32EspIndex);
ieee8021PbbTeTeSiEspEntry_t * ieee8021PbbTeTeSiEspTable_getNextIndex (
	uint32_t u32TesiId,
	uint32_t u32EspIndex);
void ieee8021PbbTeTeSiEspTable_removeEntry (ieee8021PbbTeTeSiEspEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021PbbTeTeSiEspTable_getFirst;
Netsnmp_Next_Data_Point ieee8021PbbTeTeSiEspTable_getNext;
Netsnmp_Get_Data_Point ieee8021PbbTeTeSiEspTable_get;
Netsnmp_Node_Handler ieee8021PbbTeTeSiEspTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021PbbTeProtectionGroupConfigTable definitions
 */
#define IEEE8021PBBTEPROTECTIONGROUPCONFIGSTATE 1
#define IEEE8021PBBTEPROTECTIONGROUPCONFIGCOMMANDSTATUS 2
#define IEEE8021PBBTEPROTECTIONGROUPCONFIGCOMMANDLAST 3
#define IEEE8021PBBTEPROTECTIONGROUPCONFIGCOMMANDADMIN 4
#define IEEE8021PBBTEPROTECTIONGROUPCONFIGACTIVEREQUESTS 5
#define IEEE8021PBBTEPROTECTIONGROUPCONFIGWTR 6
#define IEEE8021PBBTEPROTECTIONGROUPCONFIGHOLDOFF 7
#define IEEE8021PBBTEPROTECTIONGROUPCONFIGNOTIFYENABLE 8
#define IEEE8021PBBTEPROTECTIONGROUPCONFIGSTORAGETYPE 9

enum
{
	/* enums for column ieee8021PbbTeProtectionGroupConfigState */
	ieee8021PbbTeProtectionGroupConfigState_workingPath_c = 1,
	ieee8021PbbTeProtectionGroupConfigState_protectionPat_c = 2,
	ieee8021PbbTeProtectionGroupConfigState_waitToRestore_c = 3,
	ieee8021PbbTeProtectionGroupConfigState_protAdmin_c = 4,

	/* enums for column ieee8021PbbTeProtectionGroupConfigCommandStatus */
	ieee8021PbbTeProtectionGroupConfigCommandStatus_clear_c = 1,
	ieee8021PbbTeProtectionGroupConfigCommandStatus_lockOutProtection_c = 2,
	ieee8021PbbTeProtectionGroupConfigCommandStatus_forceSwitch_c = 3,
	ieee8021PbbTeProtectionGroupConfigCommandStatus_manualSwitchToProtection_c = 4,
	ieee8021PbbTeProtectionGroupConfigCommandStatus_manualSwitchToWorking_c = 5,

	/* enums for column ieee8021PbbTeProtectionGroupConfigCommandLast */
	ieee8021PbbTeProtectionGroupConfigCommandLast_clear_c = 1,
	ieee8021PbbTeProtectionGroupConfigCommandLast_lockOutProtection_c = 2,
	ieee8021PbbTeProtectionGroupConfigCommandLast_forceSwitch_c = 3,
	ieee8021PbbTeProtectionGroupConfigCommandLast_manualSwitchToProtection_c = 4,
	ieee8021PbbTeProtectionGroupConfigCommandLast_manualSwitchToWorking_c = 5,

	/* enums for column ieee8021PbbTeProtectionGroupConfigCommandAdmin */
	ieee8021PbbTeProtectionGroupConfigCommandAdmin_clear_c = 1,
	ieee8021PbbTeProtectionGroupConfigCommandAdmin_lockOutProtection_c = 2,
	ieee8021PbbTeProtectionGroupConfigCommandAdmin_forceSwitch_c = 3,
	ieee8021PbbTeProtectionGroupConfigCommandAdmin_manualSwitchToProtection_c = 4,
	ieee8021PbbTeProtectionGroupConfigCommandAdmin_manualSwitchToWorking_c = 5,

	/* enums for column ieee8021PbbTeProtectionGroupConfigActiveRequests */
	ieee8021PbbTeProtectionGroupConfigActiveRequests_noRequest_c = 1,
	ieee8021PbbTeProtectionGroupConfigActiveRequests_loP_c = 2,
	ieee8021PbbTeProtectionGroupConfigActiveRequests_fs_c = 3,
	ieee8021PbbTeProtectionGroupConfigActiveRequests_pSFH_c = 4,
	ieee8021PbbTeProtectionGroupConfigActiveRequests_wSFH_c = 5,
	ieee8021PbbTeProtectionGroupConfigActiveRequests_manualSwitchToProtection_c = 6,
	ieee8021PbbTeProtectionGroupConfigActiveRequests_manualSwitchToWorking_c = 7,

	/* enums for column ieee8021PbbTeProtectionGroupConfigNotifyEnable */
	ieee8021PbbTeProtectionGroupConfigNotifyEnable_true_c = 1,
	ieee8021PbbTeProtectionGroupConfigNotifyEnable_false_c = 2,

	/* enums for column ieee8021PbbTeProtectionGroupConfigStorageType */
	ieee8021PbbTeProtectionGroupConfigStorageType_other_c = 1,
	ieee8021PbbTeProtectionGroupConfigStorageType_volatile_c = 2,
	ieee8021PbbTeProtectionGroupConfigStorageType_nonVolatile_c = 3,
	ieee8021PbbTeProtectionGroupConfigStorageType_permanent_c = 4,
	ieee8021PbbTeProtectionGroupConfigStorageType_readOnly_c = 5,
};

/* table ieee8021PbbTeProtectionGroupConfigTable row entry data structure */
typedef struct ieee8021PbbTeProtectionGroupConfigEntry_t
{
	/* Index values */
	uint32_t u32BridgeBaseComponentId;
	uint32_t u32PbbTeProtectionGroupListGroupId;
	
	/* Column values */
	int32_t i32State;
	int32_t i32CommandStatus;
	int32_t i32CommandLast;
	int32_t i32CommandAdmin;
	int32_t i32ActiveRequests;
	uint32_t u32WTR;
	uint32_t u32HoldOff;
	uint8_t u8NotifyEnable;
	uint8_t u8StorageType;
	
	xBTree_Node_t oBTreeNode;
} ieee8021PbbTeProtectionGroupConfigEntry_t;

extern xBTree_t oIeee8021PbbTeProtectionGroupConfigTable_BTree;

/* ieee8021PbbTeProtectionGroupConfigTable table mapper */
void ieee8021PbbTeProtectionGroupConfigTable_init (void);
ieee8021PbbTeProtectionGroupConfigEntry_t * ieee8021PbbTeProtectionGroupConfigTable_createEntry (
	uint32_t u32BridgeBaseComponentId,
	uint32_t u32PbbTeProtectionGroupListGroupId);
ieee8021PbbTeProtectionGroupConfigEntry_t * ieee8021PbbTeProtectionGroupConfigTable_getByIndex (
	uint32_t u32BridgeBaseComponentId,
	uint32_t u32PbbTeProtectionGroupListGroupId);
ieee8021PbbTeProtectionGroupConfigEntry_t * ieee8021PbbTeProtectionGroupConfigTable_getNextIndex (
	uint32_t u32BridgeBaseComponentId,
	uint32_t u32PbbTeProtectionGroupListGroupId);
void ieee8021PbbTeProtectionGroupConfigTable_removeEntry (ieee8021PbbTeProtectionGroupConfigEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021PbbTeProtectionGroupConfigTable_getFirst;
Netsnmp_Next_Data_Point ieee8021PbbTeProtectionGroupConfigTable_getNext;
Netsnmp_Get_Data_Point ieee8021PbbTeProtectionGroupConfigTable_get;
Netsnmp_Node_Handler ieee8021PbbTeProtectionGroupConfigTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021PbbTeProtectionGroupISidTable definitions
 */
#define IEEE8021PBBTEPROTECTIONGROUPISIDINDEX 1
#define IEEE8021PBBTEPROTECTIONGROUPISIDCOMPONENTID 2
#define IEEE8021PBBTEPROTECTIONGROUPISIDGROUPID 3
#define IEEE8021PBBTEPROTECTIONGROUPISIDSTORAGETYPE 4
#define IEEE8021PBBTEPROTECTIONGROUPISIDROWSTATUS 5

enum
{
	/* enums for column ieee8021PbbTeProtectionGroupISidStorageType */
	ieee8021PbbTeProtectionGroupISidStorageType_other_c = 1,
	ieee8021PbbTeProtectionGroupISidStorageType_volatile_c = 2,
	ieee8021PbbTeProtectionGroupISidStorageType_nonVolatile_c = 3,
	ieee8021PbbTeProtectionGroupISidStorageType_permanent_c = 4,
	ieee8021PbbTeProtectionGroupISidStorageType_readOnly_c = 5,

	/* enums for column ieee8021PbbTeProtectionGroupISidRowStatus */
	ieee8021PbbTeProtectionGroupISidRowStatus_active_c = 1,
	ieee8021PbbTeProtectionGroupISidRowStatus_notInService_c = 2,
	ieee8021PbbTeProtectionGroupISidRowStatus_notReady_c = 3,
	ieee8021PbbTeProtectionGroupISidRowStatus_createAndGo_c = 4,
	ieee8021PbbTeProtectionGroupISidRowStatus_createAndWait_c = 5,
	ieee8021PbbTeProtectionGroupISidRowStatus_destroy_c = 6,
};

/* table ieee8021PbbTeProtectionGroupISidTable row entry data structure */
typedef struct ieee8021PbbTeProtectionGroupISidEntry_t
{
	/* Index values */
	uint32_t u32Index;
	
	/* Column values */
	uint32_t u32ComponentId;
	uint32_t u32GroupId;
	uint8_t u8StorageType;
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} ieee8021PbbTeProtectionGroupISidEntry_t;

extern xBTree_t oIeee8021PbbTeProtectionGroupISidTable_BTree;

/* ieee8021PbbTeProtectionGroupISidTable table mapper */
void ieee8021PbbTeProtectionGroupISidTable_init (void);
ieee8021PbbTeProtectionGroupISidEntry_t * ieee8021PbbTeProtectionGroupISidTable_createEntry (
	uint32_t u32Index);
ieee8021PbbTeProtectionGroupISidEntry_t * ieee8021PbbTeProtectionGroupISidTable_getByIndex (
	uint32_t u32Index);
ieee8021PbbTeProtectionGroupISidEntry_t * ieee8021PbbTeProtectionGroupISidTable_getNextIndex (
	uint32_t u32Index);
void ieee8021PbbTeProtectionGroupISidTable_removeEntry (ieee8021PbbTeProtectionGroupISidEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021PbbTeProtectionGroupISidTable_getFirst;
Netsnmp_Next_Data_Point ieee8021PbbTeProtectionGroupISidTable_getNext;
Netsnmp_Get_Data_Point ieee8021PbbTeProtectionGroupISidTable_get;
Netsnmp_Node_Handler ieee8021PbbTeProtectionGroupISidTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021PbbTeBridgeStaticForwardAnyUnicastTable definitions
 */
#define IEEE8021PBBTEBRIDGESTATICFORWARDANYUNICASTVLANINDEX 1
#define IEEE8021PBBTEBRIDGESTATICFORWARDANYUNICASTEGRESSPORTS 2
#define IEEE8021PBBTEBRIDGESTATICFORWARDANYUNICASTFORBIDDENPORTS 3
#define IEEE8021PBBTEBRIDGESTATICFORWARDANYUNICASTSTORAGETYPE 4
#define IEEE8021PBBTEBRIDGESTATICFORWARDANYUNICASTROWSTATUS 5

enum
{
	/* enums for column ieee8021PbbTeBridgeStaticForwardAnyUnicastStorageType */
	ieee8021PbbTeBridgeStaticForwardAnyUnicastStorageType_other_c = 1,
	ieee8021PbbTeBridgeStaticForwardAnyUnicastStorageType_volatile_c = 2,
	ieee8021PbbTeBridgeStaticForwardAnyUnicastStorageType_nonVolatile_c = 3,
	ieee8021PbbTeBridgeStaticForwardAnyUnicastStorageType_permanent_c = 4,
	ieee8021PbbTeBridgeStaticForwardAnyUnicastStorageType_readOnly_c = 5,

	/* enums for column ieee8021PbbTeBridgeStaticForwardAnyUnicastRowStatus */
	ieee8021PbbTeBridgeStaticForwardAnyUnicastRowStatus_active_c = 1,
	ieee8021PbbTeBridgeStaticForwardAnyUnicastRowStatus_notInService_c = 2,
	ieee8021PbbTeBridgeStaticForwardAnyUnicastRowStatus_notReady_c = 3,
	ieee8021PbbTeBridgeStaticForwardAnyUnicastRowStatus_createAndGo_c = 4,
	ieee8021PbbTeBridgeStaticForwardAnyUnicastRowStatus_createAndWait_c = 5,
	ieee8021PbbTeBridgeStaticForwardAnyUnicastRowStatus_destroy_c = 6,
};

/* table ieee8021PbbTeBridgeStaticForwardAnyUnicastTable row entry data structure */
typedef struct ieee8021PbbTeBridgeStaticForwardAnyUnicastEntry_t
{
	/* Index values */
	uint32_t u32QBridgeVlanCurrentComponentId;
	uint32_t u32VlanIndex;
	
	/* Column values */
	uint8_t au8EgressPorts[/* TODO: PortList, PortList, "" */ TOBE_REPLACED];
	size_t u16EgressPorts_len;	/* # of uint8_t elements */
	uint8_t au8ForbiddenPorts[/* TODO: PortList, PortList, "" */ TOBE_REPLACED];
	size_t u16ForbiddenPorts_len;	/* # of uint8_t elements */
	uint8_t u8StorageType;
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} ieee8021PbbTeBridgeStaticForwardAnyUnicastEntry_t;

extern xBTree_t oIeee8021PbbTeBridgeStaticForwardAnyUnicastTable_BTree;

/* ieee8021PbbTeBridgeStaticForwardAnyUnicastTable table mapper */
void ieee8021PbbTeBridgeStaticForwardAnyUnicastTable_init (void);
ieee8021PbbTeBridgeStaticForwardAnyUnicastEntry_t * ieee8021PbbTeBridgeStaticForwardAnyUnicastTable_createEntry (
	uint32_t u32QBridgeVlanCurrentComponentId,
	uint32_t u32VlanIndex);
ieee8021PbbTeBridgeStaticForwardAnyUnicastEntry_t * ieee8021PbbTeBridgeStaticForwardAnyUnicastTable_getByIndex (
	uint32_t u32QBridgeVlanCurrentComponentId,
	uint32_t u32VlanIndex);
ieee8021PbbTeBridgeStaticForwardAnyUnicastEntry_t * ieee8021PbbTeBridgeStaticForwardAnyUnicastTable_getNextIndex (
	uint32_t u32QBridgeVlanCurrentComponentId,
	uint32_t u32VlanIndex);
void ieee8021PbbTeBridgeStaticForwardAnyUnicastTable_removeEntry (ieee8021PbbTeBridgeStaticForwardAnyUnicastEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021PbbTeBridgeStaticForwardAnyUnicastTable_getFirst;
Netsnmp_Next_Data_Point ieee8021PbbTeBridgeStaticForwardAnyUnicastTable_getNext;
Netsnmp_Get_Data_Point ieee8021PbbTeBridgeStaticForwardAnyUnicastTable_get;
Netsnmp_Node_Handler ieee8021PbbTeBridgeStaticForwardAnyUnicastTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	notification mapper(s)
 */
/* definitions for notification(s) of ieee8021PbbTeNotifications */
#	define IEEE8021PBBTEPROTECTIONGROUPADMINFAILURE 1

/* ieee8021PbbTeNotifications mapper(s) */
int ieee8021PbbTeProtectionGroupAdminFailure_trap (void);



#	ifdef __cplusplus
}
#	endif

#endif /* __IEEE8021PBBTEMIB_H__ */
