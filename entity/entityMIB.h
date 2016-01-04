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

#ifndef __ENTITYMIB_H__
#	define __ENTITYMIB_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include "lib/binaryTree.h"
#include "lib/sync.h"
#include "lib/snmp.h"

#include <stdbool.h>

#define TOBE_REPLACED 1


/**
 *	agent MIB function
 */
void entityMIB_init (void);


/**
 *	scalar mapper(s)
 */
/** definitions for scalar(s) of entityGeneral **/
#define ENTLASTCHANGETIME 1

typedef struct entityGeneral_t
{
	uint32_t u32LastChangeTime;
	
	xRwLock_t oLock;
} entityGeneral_t;

extern entityGeneral_t oEntityGeneral;

#ifdef SNMP_SRC
Netsnmp_Node_Handler entityGeneral_mapper;
#endif	/* SNMP_SRC */



/**
 *	table mapper(s)
 */
/**
 *	table entPhysicalTable definitions
 */
#define ENTPHYSICALINDEX 1
#define ENTPHYSICALDESCR 2
#define ENTPHYSICALVENDORTYPE 3
#define ENTPHYSICALCONTAINEDIN 4
#define ENTPHYSICALCLASS 5
#define ENTPHYSICALPARENTRELPOS 6
#define ENTPHYSICALNAME 7
#define ENTPHYSICALHARDWAREREV 8
#define ENTPHYSICALFIRMWAREREV 9
#define ENTPHYSICALSOFTWAREREV 10
#define ENTPHYSICALSERIALNUM 11
#define ENTPHYSICALMFGNAME 12
#define ENTPHYSICALMODELNAME 13
#define ENTPHYSICALALIAS 14
#define ENTPHYSICALASSETID 15
#define ENTPHYSICALISFRU 16
#define ENTPHYSICALMFGDATE 17
#define ENTPHYSICALURIS 18
#define ENTPHYSICALUUID 19

enum
{
	/* enums for column entPhysicalClass */
	entPhysicalClass_other_c = 1,
	entPhysicalClass_unknown_c = 2,
	entPhysicalClass_chassis_c = 3,
	entPhysicalClass_backplane_c = 4,
	entPhysicalClass_container_c = 5,
	entPhysicalClass_powerSupply_c = 6,
	entPhysicalClass_fan_c = 7,
	entPhysicalClass_sensor_c = 8,
	entPhysicalClass_module_c = 9,
	entPhysicalClass_port_c = 10,
	entPhysicalClass_stack_c = 11,
	entPhysicalClass_cpu_c = 12,
	entPhysicalClass_energyObject_c = 13,
	entPhysicalClass_battery_c = 14,

	/* enums for column entPhysicalIsFRU */
	entPhysicalIsFRU_true_c = 1,
	entPhysicalIsFRU_false_c = 2,
};

/* table entPhysicalTable row entry data structure */
typedef struct entPhysicalEntry_t
{
	/* Index values */
// 	uint32_t u32Index;
	
	/* Column values */
	uint8_t au8Descr[32];
	size_t u16Descr_len;	/* # of uint8_t elements */
	xOid_t aoVendorType[128];
	size_t u16VendorType_len;	/* # of xOid_t elements */
	uint32_t u32ContainedIn;
	int32_t i32Class;
	int32_t i32ParentRelPos;
	uint8_t au8Name[32];
	size_t u16Name_len;	/* # of uint8_t elements */
	uint8_t au8HardwareRev[32];
	size_t u16HardwareRev_len;	/* # of uint8_t elements */
	uint8_t au8FirmwareRev[32];
	size_t u16FirmwareRev_len;	/* # of uint8_t elements */
	uint8_t au8SoftwareRev[32];
	size_t u16SoftwareRev_len;	/* # of uint8_t elements */
	uint8_t au8SerialNum[32];
	size_t u16SerialNum_len;	/* # of uint8_t elements */
	uint8_t au8MfgName[32];
	size_t u16MfgName_len;	/* # of uint8_t elements */
	uint8_t au8ModelName[32];
	size_t u16ModelName_len;	/* # of uint8_t elements */
	uint8_t au8Alias[32];
	size_t u16Alias_len;	/* # of uint8_t elements */
	uint8_t au8AssetID[32];
	size_t u16AssetID_len;	/* # of uint8_t elements */
	uint8_t u8IsFRU;
	uint8_t au8MfgDate[11];
	size_t u16MfgDate_len;	/* # of uint8_t elements */
	uint8_t au8Uris[0];
	size_t u16Uris_len;	/* # of uint8_t elements */
	uint8_t au8UUID[16];
	size_t u16UUID_len;	/* # of uint8_t elements */
	
// 	xBTree_Node_t oBTreeNode;
} entPhysicalEntry_t;

// extern xBTree_t oEntPhysicalTable_BTree;

/* entPhysicalTable table mapper */
void entPhysicalTable_init (void);
entPhysicalEntry_t * entPhysicalTable_createEntry (
	uint32_t u32Index);
entPhysicalEntry_t * entPhysicalTable_getByIndex (
	uint32_t u32Index);
entPhysicalEntry_t * entPhysicalTable_getNextIndex (
	uint32_t u32Index);
void entPhysicalTable_removeEntry (entPhysicalEntry_t *poEntry);
bool entPhysicalTable_createEntity (
	uint32_t u32Index,
	entPhysicalEntry_t *poEntry);
bool entPhysicalTable_removeEntity (
	uint32_t u32Index);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point entPhysicalTable_getFirst;
Netsnmp_Next_Data_Point entPhysicalTable_getNext;
Netsnmp_Get_Data_Point entPhysicalTable_get;
Netsnmp_Node_Handler entPhysicalTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table entLogicalTable definitions
 */
#define ENTLOGICALINDEX 1
#define ENTLOGICALDESCR 2
#define ENTLOGICALTYPE 3
#define ENTLOGICALCOMMUNITY 4
#define ENTLOGICALTADDRESS 5
#define ENTLOGICALTDOMAIN 6
#define ENTLOGICALCONTEXTENGINEID 7
#define ENTLOGICALCONTEXTNAME 8

/* table entLogicalTable row entry data structure */
typedef struct entLogicalEntry_t
{
	/* Index values */
// 	uint32_t u32Index;
	
	/* Column values */
	uint8_t au8Descr[32];
	size_t u16Descr_len;	/* # of uint8_t elements */
	xOid_t aoType[128];
	size_t u16Type_len;	/* # of xOid_t elements */
	uint8_t au8Community[32];
	size_t u16Community_len;	/* # of uint8_t elements */
	uint8_t au8TAddress[32];
	size_t u16TAddress_len;	/* # of uint8_t elements */
	xOid_t aoTDomain[128];
	size_t u16TDomain_len;	/* # of xOid_t elements */
	uint8_t au8ContextEngineID[32];
	size_t u16ContextEngineID_len;	/* # of uint8_t elements */
	uint8_t au8ContextName[32];
	size_t u16ContextName_len;	/* # of uint8_t elements */
	
// 	xBTree_Node_t oBTreeNode;
} entLogicalEntry_t;

// extern xBTree_t oEntLogicalTable_BTree;

/* entLogicalTable table mapper */
void entLogicalTable_init (void);
entLogicalEntry_t * entLogicalTable_createEntry (
	uint32_t u32Index);
entLogicalEntry_t * entLogicalTable_getByIndex (
	uint32_t u32Index);
entLogicalEntry_t * entLogicalTable_getNextIndex (
	uint32_t u32Index);
void entLogicalTable_removeEntry (entLogicalEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point entLogicalTable_getFirst;
Netsnmp_Next_Data_Point entLogicalTable_getNext;
Netsnmp_Get_Data_Point entLogicalTable_get;
Netsnmp_Node_Handler entLogicalTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table entLPMappingTable definitions
 */
#define ENTLPPHYSICALINDEX 1

/* table entLPMappingTable row entry data structure */
typedef struct entLPMappingEntry_t
{
	/* Index values */
// 	uint32_t u32LogicalIndex;
// 	uint32_t u32PhysicalIndex;
	
	/* Column values */
	
// 	xBTree_Node_t oBTreeNode;
} entLPMappingEntry_t;

// extern xBTree_t oEntLPMappingTable_BTree;

/* entLPMappingTable table mapper */
void entLPMappingTable_init (void);
entLPMappingEntry_t * entLPMappingTable_createEntry (
	uint32_t u32LogicalIndex,
	uint32_t u32PhysicalIndex);
entLPMappingEntry_t * entLPMappingTable_getByIndex (
	uint32_t u32LogicalIndex,
	uint32_t u32PhysicalIndex);
entLPMappingEntry_t * entLPMappingTable_getNextIndex (
	uint32_t u32LogicalIndex,
	uint32_t u32PhysicalIndex);
void entLPMappingTable_removeEntry (entLPMappingEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point entLPMappingTable_getFirst;
Netsnmp_Next_Data_Point entLPMappingTable_getNext;
Netsnmp_Get_Data_Point entLPMappingTable_get;
Netsnmp_Node_Handler entLPMappingTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table entAliasMappingTable definitions
 */
#define ENTALIASLOGICALINDEXORZERO 1
#define ENTALIASMAPPINGIDENTIFIER 2

/* table entAliasMappingTable row entry data structure */
typedef struct entAliasMappingEntry_t
{
	/* Index values */
	uint32_t u32PhysicalIndex;
	uint32_t u32LogicalIndexOrZero;
	
	/* Column values */
	xOid_t aoIdentifier[128];
	size_t u16Identifier_len;	/* # of xOid_t elements */
	
	xBTree_Node_t oBTreeNode;
} entAliasMappingEntry_t;

extern xBTree_t oEntAliasMappingTable_BTree;

/* entAliasMappingTable table mapper */
void entAliasMappingTable_init (void);
entAliasMappingEntry_t * entAliasMappingTable_createEntry (
	uint32_t u32PhysicalIndex,
	uint32_t u32LogicalIndexOrZero);
entAliasMappingEntry_t * entAliasMappingTable_getByIndex (
	uint32_t u32PhysicalIndex,
	uint32_t u32LogicalIndexOrZero);
entAliasMappingEntry_t * entAliasMappingTable_getNextIndex (
	uint32_t u32PhysicalIndex,
	uint32_t u32LogicalIndexOrZero);
void entAliasMappingTable_removeEntry (entAliasMappingEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point entAliasMappingTable_getFirst;
Netsnmp_Next_Data_Point entAliasMappingTable_getNext;
Netsnmp_Get_Data_Point entAliasMappingTable_get;
Netsnmp_Node_Handler entAliasMappingTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table entPhysicalContainsTable definitions
 */
#define ENTPHYSICALCHILDINDEX 1

/* table entPhysicalContainsTable row entry data structure */
typedef struct entPhysicalContainsEntry_t
{
	/* Index values */
	uint32_t u32Index;
	uint32_t u32ChildIndex;
	
	/* Column values */
	
	xBTree_Node_t oBTreeNode;
} entPhysicalContainsEntry_t;

extern xBTree_t oEntPhysicalContainsTable_BTree;

/* entPhysicalContainsTable table mapper */
void entPhysicalContainsTable_init (void);
entPhysicalContainsEntry_t * entPhysicalContainsTable_createEntry (
	uint32_t u32Index,
	uint32_t u32ChildIndex);
entPhysicalContainsEntry_t * entPhysicalContainsTable_getByIndex (
	uint32_t u32Index,
	uint32_t u32ChildIndex);
entPhysicalContainsEntry_t * entPhysicalContainsTable_getNextIndex (
	uint32_t u32Index,
	uint32_t u32ChildIndex);
void entPhysicalContainsTable_removeEntry (entPhysicalContainsEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point entPhysicalContainsTable_getFirst;
Netsnmp_Next_Data_Point entPhysicalContainsTable_getNext;
Netsnmp_Get_Data_Point entPhysicalContainsTable_get;
Netsnmp_Node_Handler entPhysicalContainsTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table neEntPhysicalTable definitions
 */
#define NEENTPHYSICALCONTAINEDIN 1
#define NEENTPHYSICALCLASS 2
#define NEENTPHYSICALPARENTRELPOS 3
#define NEENTPHYSICALROWSTATUS 4
#define NEENTPHYSICALSTORAGETYPE 5

enum
{
	/* enums for column neEntPhysicalClass */
	neEntPhysicalClass_other_c = 1,
	neEntPhysicalClass_unknown_c = 2,
	neEntPhysicalClass_chassis_c = 3,
	neEntPhysicalClass_backplane_c = 4,
	neEntPhysicalClass_container_c = 5,
	neEntPhysicalClass_powerSupply_c = 6,
	neEntPhysicalClass_fan_c = 7,
	neEntPhysicalClass_sensor_c = 8,
	neEntPhysicalClass_module_c = 9,
	neEntPhysicalClass_port_c = 10,
	neEntPhysicalClass_stack_c = 11,
	neEntPhysicalClass_cpu_c = 12,
	neEntPhysicalClass_energyObject_c = 13,
	neEntPhysicalClass_battery_c = 14,

	/* enums for column neEntPhysicalRowStatus */
	neEntPhysicalRowStatus_active_c = 1,
	neEntPhysicalRowStatus_notInService_c = 2,
	neEntPhysicalRowStatus_notReady_c = 3,
	neEntPhysicalRowStatus_createAndGo_c = 4,
	neEntPhysicalRowStatus_createAndWait_c = 5,
	neEntPhysicalRowStatus_destroy_c = 6,

	/* enums for column neEntPhysicalStorageType */
	neEntPhysicalStorageType_other_c = 1,
	neEntPhysicalStorageType_volatile_c = 2,
	neEntPhysicalStorageType_nonVolatile_c = 3,
	neEntPhysicalStorageType_permanent_c = 4,
	neEntPhysicalStorageType_readOnly_c = 5,
};

/* table neEntPhysicalTable row entry data structure */
typedef struct neEntPhysicalEntry_t
{
	/* Index values */
	uint32_t u32Index;
	
	uint8_t au8MfgName[32];
	size_t u16MfgName_len;
	uint8_t au8SerialNum[32];
	size_t u16SerialNum_len;
	
	/* Column values */
	uint32_t u32ContainedIn;
	int32_t i32Class;
	int32_t i32ParentRelPos;
	uint8_t u8RowStatus;
	uint8_t u8StorageType;
	
	entPhysicalEntry_t oPhy;
	
	uint32_t u32ChassisIndex;
	struct neEntPhysicalEntry_t *pOldEntry;
	
	xBTree_Node_t oBTreeNode;
	xBTree_Node_t oSerialNum_BTreeNode;
} neEntPhysicalEntry_t;

extern xBTree_t oNeEntPhysicalTable_BTree;
extern xBTree_t oNeEntPhysicalTable_SerialNum_BTree;

/* neEntPhysicalTable table mapper */
void neEntPhysicalTable_init (void);
neEntPhysicalEntry_t * neEntPhysicalTable_createEntry (
	uint32_t u32Index);
bool neEntPhysicalTable_linkSerialNum (neEntPhysicalEntry_t *poEntry);
neEntPhysicalEntry_t * neEntPhysicalTable_getByIndex (
	uint32_t u32Index);
neEntPhysicalEntry_t * neEntPhysicalTable_getBySerialNum (
	uint8_t *pu8MfgName, size_t u16MfgName_len,
	uint8_t *pu8SerialNum, size_t u16SerialNum_len);
neEntPhysicalEntry_t * neEntPhysicalTable_getNextIndex (
	uint32_t u32Index);
void neEntPhysicalTable_removeEntry (neEntPhysicalEntry_t *poEntry);
neEntPhysicalEntry_t * neEntPhysicalTable_createExt (
	uint32_t u32Index);
bool neEntPhysicalTable_removeExt (neEntPhysicalEntry_t *poEntry);
bool neEntPhysicalTable_createHier (neEntPhysicalEntry_t *poEntry);
bool neEntPhysicalTable_removeHier (neEntPhysicalEntry_t *poEntry);
bool neEntPhysicalRowStatus_handler (
	neEntPhysicalEntry_t *poEntry,
	uint8_t u8RowStatus);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point neEntPhysicalTable_getFirst;
Netsnmp_Next_Data_Point neEntPhysicalTable_getNext;
Netsnmp_Get_Data_Point neEntPhysicalTable_get;
Netsnmp_Node_Handler neEntPhysicalTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table neEntLogicalTable definitions
 */
#define NEENTLOGICALROWSTATUS 1
#define NEENTLOGICALSTORAGETYPE 2

enum
{
	/* enums for column neEntLogicalRowStatus */
	neEntLogicalRowStatus_active_c = 1,
	neEntLogicalRowStatus_notInService_c = 2,
	neEntLogicalRowStatus_notReady_c = 3,
	neEntLogicalRowStatus_createAndGo_c = 4,
	neEntLogicalRowStatus_createAndWait_c = 5,
	neEntLogicalRowStatus_destroy_c = 6,

	/* enums for column neEntLogicalStorageType */
	neEntLogicalStorageType_other_c = 1,
	neEntLogicalStorageType_volatile_c = 2,
	neEntLogicalStorageType_nonVolatile_c = 3,
	neEntLogicalStorageType_permanent_c = 4,
	neEntLogicalStorageType_readOnly_c = 5,
};

/* table neEntLogicalTable row entry data structure */
typedef struct neEntLogicalEntry_t
{
	/* Index values */
	uint32_t u32Index;
	
	/* Column values */
	uint8_t u8RowStatus;
	uint8_t u8StorageType;
	
	entLogicalEntry_t oLog;
	
	xBTree_Node_t oBTreeNode;
} neEntLogicalEntry_t;

extern xBTree_t oNeEntLogicalTable_BTree;

/* neEntLogicalTable table mapper */
void neEntLogicalTable_init (void);
neEntLogicalEntry_t * neEntLogicalTable_createEntry (
	uint32_t u32Index);
neEntLogicalEntry_t * neEntLogicalTable_getByIndex (
	uint32_t u32Index);
neEntLogicalEntry_t * neEntLogicalTable_getNextIndex (
	uint32_t u32Index);
void neEntLogicalTable_removeEntry (neEntLogicalEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point neEntLogicalTable_getFirst;
Netsnmp_Next_Data_Point neEntLogicalTable_getNext;
Netsnmp_Get_Data_Point neEntLogicalTable_get;
Netsnmp_Node_Handler neEntLogicalTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table neEntLPMappingTable definitions
 */
#define NEENTLPMAPPINGROWSTATUS 1
#define NEENTLPMAPPINGSTORAGETYPE 2

enum
{
	/* enums for column neEntLPMappingRowStatus */
	neEntLPMappingRowStatus_active_c = 1,
	neEntLPMappingRowStatus_notInService_c = 2,
	neEntLPMappingRowStatus_notReady_c = 3,
	neEntLPMappingRowStatus_createAndGo_c = 4,
	neEntLPMappingRowStatus_createAndWait_c = 5,
	neEntLPMappingRowStatus_destroy_c = 6,

	/* enums for column neEntLPMappingStorageType */
	neEntLPMappingStorageType_other_c = 1,
	neEntLPMappingStorageType_volatile_c = 2,
	neEntLPMappingStorageType_nonVolatile_c = 3,
	neEntLPMappingStorageType_permanent_c = 4,
	neEntLPMappingStorageType_readOnly_c = 5,
};

/* table neEntLPMappingTable row entry data structure */
typedef struct neEntLPMappingEntry_t
{
	/* Index values */
	uint32_t u32LogicalIndex;
	uint32_t u32PhysicalIndex;
	
	/* Column values */
	uint8_t u8RowStatus;
	uint8_t u8StorageType;
	
	entLPMappingEntry_t oLp;
	
	xBTree_Node_t oBTreeNode;
} neEntLPMappingEntry_t;

extern xBTree_t oNeEntLPMappingTable_BTree;

/* neEntLPMappingTable table mapper */
void neEntLPMappingTable_init (void);
neEntLPMappingEntry_t * neEntLPMappingTable_createEntry (
	uint32_t u32LogicalIndex,
	uint32_t u32PhysicalIndex);
neEntLPMappingEntry_t * neEntLPMappingTable_getByIndex (
	uint32_t u32LogicalIndex,
	uint32_t u32PhysicalIndex);
neEntLPMappingEntry_t * neEntLPMappingTable_getNextIndex (
	uint32_t u32LogicalIndex,
	uint32_t u32PhysicalIndex);
#define neEntLPMappingTable_getByLpEntry(poEntry) ((poEntry) == NULL ? NULL: xGetParentByMemberPtr ((poEntry), neEntLPMappingEntry_t, oLp))
void neEntLPMappingTable_removeEntry (neEntLPMappingEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point neEntLPMappingTable_getFirst;
Netsnmp_Next_Data_Point neEntLPMappingTable_getNext;
Netsnmp_Get_Data_Point neEntLPMappingTable_get;
Netsnmp_Node_Handler neEntLPMappingTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table neEntChassisTable definitions
 */
#define NEENTCHASSISNUMPORTS 1
#define NEENTCHASSISPORTTYPES 2

enum
{
	/* enums for column neEntChassisPortTypes */
	neEntChassisPortTypes_bEthernet_c = 0,
	neEntChassisPortTypes_bSonet_c = 1,
	neEntChassisPortTypes_bSdh_c = 2,
	neEntChassisPortTypes_bOtn_c = 3,
};

/* table neEntChassisTable row entry data structure */
typedef struct neEntChassisEntry_t
{
	/* Index values */
	uint32_t u32PhysicalIndex;
	
	/* Column values */
	uint32_t u32NumPorts;
	uint8_t au8PortTypes[1];
	size_t u16PortTypes_len;	/* # of uint8_t elements */
	
	uint8_t u8RowStatus;
	struct neEntChassisEntry_t *pOldEntry;
	
	xBTree_Node_t oBTreeNode;
} neEntChassisEntry_t;

extern xBTree_t oNeEntChassisTable_BTree;

/* neEntChassisTable table mapper */
void neEntChassisTable_init (void);
neEntChassisEntry_t * neEntChassisTable_createEntry (
	uint32_t u32PhysicalIndex);
neEntChassisEntry_t * neEntChassisTable_getByIndex (
	uint32_t u32PhysicalIndex);
neEntChassisEntry_t * neEntChassisTable_getNextIndex (
	uint32_t u32PhysicalIndex);
void neEntChassisTable_removeEntry (neEntChassisEntry_t *poEntry);
bool neEntChassisRowStatus_handler (
	neEntPhysicalEntry_t *poPhysical,
	neEntChassisEntry_t *poEntry, uint8_t u8RowStatus);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point neEntChassisTable_getFirst;
Netsnmp_Next_Data_Point neEntChassisTable_getNext;
Netsnmp_Get_Data_Point neEntChassisTable_get;
Netsnmp_Node_Handler neEntChassisTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table neEntPortTable definitions
 */
#define NEENTPORTIFINDEX 1
#define NEENTPORTIFTYPE 2
#define NEENTPORTCHASSISINDEX 3
#define NEENTPORTHINDEX 4
#define NEENTPORTROWSTATUS 5

enum
{
	/* enums for column neEntPortIfType */
	neEntPortIfType_other_c = 1,
	neEntPortIfType_regular1822_c = 2,
	neEntPortIfType_hdh1822_c = 3,
	neEntPortIfType_ddnX25_c = 4,
	neEntPortIfType_rfc877x25_c = 5,
	neEntPortIfType_ethernetCsmacd_c = 6,
	neEntPortIfType_iso88023Csmacd_c = 7,
	neEntPortIfType_iso88024TokenBus_c = 8,
	neEntPortIfType_iso88025TokenRing_c = 9,
	neEntPortIfType_iso88026Man_c = 10,
	neEntPortIfType_starLan_c = 11,
	neEntPortIfType_proteon10Mbit_c = 12,
	neEntPortIfType_proteon80Mbit_c = 13,
	neEntPortIfType_hyperchannel_c = 14,
	neEntPortIfType_fddi_c = 15,
	neEntPortIfType_lapb_c = 16,
	neEntPortIfType_sdlc_c = 17,
	neEntPortIfType_ds1_c = 18,
	neEntPortIfType_e1_c = 19,
	neEntPortIfType_basicISDN_c = 20,
	neEntPortIfType_primaryISDN_c = 21,
	neEntPortIfType_propPointToPointSerial_c = 22,
	neEntPortIfType_ppp_c = 23,
	neEntPortIfType_softwareLoopback_c = 24,
	neEntPortIfType_eon_c = 25,
	neEntPortIfType_ethernet3Mbit_c = 26,
	neEntPortIfType_nsip_c = 27,
	neEntPortIfType_slip_c = 28,
	neEntPortIfType_ultra_c = 29,
	neEntPortIfType_ds3_c = 30,
	neEntPortIfType_sip_c = 31,
	neEntPortIfType_frameRelay_c = 32,
	neEntPortIfType_rs232_c = 33,
	neEntPortIfType_para_c = 34,
	neEntPortIfType_arcnet_c = 35,
	neEntPortIfType_arcnetPlus_c = 36,
	neEntPortIfType_atm_c = 37,
	neEntPortIfType_miox25_c = 38,
	neEntPortIfType_sonet_c = 39,
	neEntPortIfType_x25ple_c = 40,
	neEntPortIfType_iso88022llc_c = 41,
	neEntPortIfType_localTalk_c = 42,
	neEntPortIfType_smdsDxi_c = 43,
	neEntPortIfType_frameRelayService_c = 44,
	neEntPortIfType_v35_c = 45,
	neEntPortIfType_hssi_c = 46,
	neEntPortIfType_hippi_c = 47,
	neEntPortIfType_modem_c = 48,
	neEntPortIfType_aal5_c = 49,
	neEntPortIfType_sonetPath_c = 50,
	neEntPortIfType_sonetVT_c = 51,
	neEntPortIfType_smdsIcip_c = 52,
	neEntPortIfType_propVirtual_c = 53,
	neEntPortIfType_propMultiplexor_c = 54,
	neEntPortIfType_ieee80212_c = 55,
	neEntPortIfType_fibreChannel_c = 56,
	neEntPortIfType_hippiInterface_c = 57,
	neEntPortIfType_frameRelayInterconnect_c = 58,
	neEntPortIfType_aflane8023_c = 59,
	neEntPortIfType_aflane8025_c = 60,
	neEntPortIfType_cctEmul_c = 61,
	neEntPortIfType_fastEther_c = 62,
	neEntPortIfType_isdn_c = 63,
	neEntPortIfType_v11_c = 64,
	neEntPortIfType_v36_c = 65,
	neEntPortIfType_g703at64k_c = 66,
	neEntPortIfType_g703at2mb_c = 67,
	neEntPortIfType_qllc_c = 68,
	neEntPortIfType_fastEtherFX_c = 69,
	neEntPortIfType_channel_c = 70,
	neEntPortIfType_ieee80211_c = 71,
	neEntPortIfType_ibm370parChan_c = 72,
	neEntPortIfType_escon_c = 73,
	neEntPortIfType_dlsw_c = 74,
	neEntPortIfType_isdns_c = 75,
	neEntPortIfType_isdnu_c = 76,
	neEntPortIfType_lapd_c = 77,
	neEntPortIfType_ipSwitch_c = 78,
	neEntPortIfType_rsrb_c = 79,
	neEntPortIfType_atmLogical_c = 80,
	neEntPortIfType_ds0_c = 81,
	neEntPortIfType_ds0Bundle_c = 82,
	neEntPortIfType_bsc_c = 83,
	neEntPortIfType_async_c = 84,
	neEntPortIfType_cnr_c = 85,
	neEntPortIfType_iso88025Dtr_c = 86,
	neEntPortIfType_eplrs_c = 87,
	neEntPortIfType_arap_c = 88,
	neEntPortIfType_propCnls_c = 89,
	neEntPortIfType_hostPad_c = 90,
	neEntPortIfType_termPad_c = 91,
	neEntPortIfType_frameRelayMPI_c = 92,
	neEntPortIfType_x213_c = 93,
	neEntPortIfType_adsl_c = 94,
	neEntPortIfType_radsl_c = 95,
	neEntPortIfType_sdsl_c = 96,
	neEntPortIfType_vdsl_c = 97,
	neEntPortIfType_iso88025CRFPInt_c = 98,
	neEntPortIfType_myrinet_c = 99,
	neEntPortIfType_voiceEM_c = 100,
	neEntPortIfType_voiceFXO_c = 101,
	neEntPortIfType_voiceFXS_c = 102,
	neEntPortIfType_voiceEncap_c = 103,
	neEntPortIfType_voiceOverIp_c = 104,
	neEntPortIfType_atmDxi_c = 105,
	neEntPortIfType_atmFuni_c = 106,
	neEntPortIfType_atmIma_c = 107,
	neEntPortIfType_pppMultilinkBundle_c = 108,
	neEntPortIfType_ipOverCdlc_c = 109,
	neEntPortIfType_ipOverClaw_c = 110,
	neEntPortIfType_stackToStack_c = 111,
	neEntPortIfType_virtualIpAddress_c = 112,
	neEntPortIfType_mpc_c = 113,
	neEntPortIfType_ipOverAtm_c = 114,
	neEntPortIfType_iso88025Fiber_c = 115,
	neEntPortIfType_tdlc_c = 116,
	neEntPortIfType_gigabitEthernet_c = 117,
	neEntPortIfType_hdlc_c = 118,
	neEntPortIfType_lapf_c = 119,
	neEntPortIfType_v37_c = 120,
	neEntPortIfType_x25mlp_c = 121,
	neEntPortIfType_x25huntGroup_c = 122,
	neEntPortIfType_transpHdlc_c = 123,
	neEntPortIfType_interleave_c = 124,
	neEntPortIfType_fast_c = 125,
	neEntPortIfType_ip_c = 126,
	neEntPortIfType_docsCableMaclayer_c = 127,
	neEntPortIfType_docsCableDownstream_c = 128,
	neEntPortIfType_docsCableUpstream_c = 129,
	neEntPortIfType_a12MppSwitch_c = 130,
	neEntPortIfType_tunnel_c = 131,
	neEntPortIfType_coffee_c = 132,
	neEntPortIfType_ces_c = 133,
	neEntPortIfType_atmSubInterface_c = 134,
	neEntPortIfType_l2vlan_c = 135,
	neEntPortIfType_l3ipvlan_c = 136,
	neEntPortIfType_l3ipxvlan_c = 137,
	neEntPortIfType_digitalPowerline_c = 138,
	neEntPortIfType_mediaMailOverIp_c = 139,
	neEntPortIfType_dtm_c = 140,
	neEntPortIfType_dcn_c = 141,
	neEntPortIfType_ipForward_c = 142,
	neEntPortIfType_msdsl_c = 143,
	neEntPortIfType_ieee1394_c = 144,
	neEntPortIfType_if_gsn_c = 145,
	neEntPortIfType_dvbRccMacLayer_c = 146,
	neEntPortIfType_dvbRccDownstream_c = 147,
	neEntPortIfType_dvbRccUpstream_c = 148,
	neEntPortIfType_atmVirtual_c = 149,
	neEntPortIfType_mplsTunnel_c = 150,
	neEntPortIfType_srp_c = 151,
	neEntPortIfType_voiceOverAtm_c = 152,
	neEntPortIfType_voiceOverFrameRelay_c = 153,
	neEntPortIfType_idsl_c = 154,
	neEntPortIfType_compositeLink_c = 155,
	neEntPortIfType_ss7SigLink_c = 156,
	neEntPortIfType_propWirelessP2P_c = 157,
	neEntPortIfType_frForward_c = 158,
	neEntPortIfType_rfc1483_c = 159,
	neEntPortIfType_usb_c = 160,
	neEntPortIfType_ieee8023adLag_c = 161,
	neEntPortIfType_bgppolicyaccounting_c = 162,
	neEntPortIfType_frf16MfrBundle_c = 163,
	neEntPortIfType_h323Gatekeeper_c = 164,
	neEntPortIfType_h323Proxy_c = 165,
	neEntPortIfType_mpls_c = 166,
	neEntPortIfType_mfSigLink_c = 167,
	neEntPortIfType_hdsl2_c = 168,
	neEntPortIfType_shdsl_c = 169,
	neEntPortIfType_ds1FDL_c = 170,
	neEntPortIfType_pos_c = 171,
	neEntPortIfType_dvbAsiIn_c = 172,
	neEntPortIfType_dvbAsiOut_c = 173,
	neEntPortIfType_plc_c = 174,
	neEntPortIfType_nfas_c = 175,
	neEntPortIfType_tr008_c = 176,
	neEntPortIfType_gr303RDT_c = 177,
	neEntPortIfType_gr303IDT_c = 178,
	neEntPortIfType_isup_c = 179,
	neEntPortIfType_propDocsWirelessMaclayer_c = 180,
	neEntPortIfType_propDocsWirelessDownstream_c = 181,
	neEntPortIfType_propDocsWirelessUpstream_c = 182,
	neEntPortIfType_hiperlan2_c = 183,
	neEntPortIfType_propBWAp2Mp_c = 184,
	neEntPortIfType_sonetOverheadChannel_c = 185,
	neEntPortIfType_digitalWrapperOverheadChannel_c = 186,
	neEntPortIfType_aal2_c = 187,
	neEntPortIfType_radioMAC_c = 188,
	neEntPortIfType_atmRadio_c = 189,
	neEntPortIfType_imt_c = 190,
	neEntPortIfType_mvl_c = 191,
	neEntPortIfType_reachDSL_c = 192,
	neEntPortIfType_frDlciEndPt_c = 193,
	neEntPortIfType_atmVciEndPt_c = 194,
	neEntPortIfType_opticalChannel_c = 195,
	neEntPortIfType_opticalTransport_c = 196,
	neEntPortIfType_propAtm_c = 197,
	neEntPortIfType_voiceOverCable_c = 198,
	neEntPortIfType_infiniband_c = 199,
	neEntPortIfType_teLink_c = 200,
	neEntPortIfType_q2931_c = 201,
	neEntPortIfType_virtualTg_c = 202,
	neEntPortIfType_sipTg_c = 203,
	neEntPortIfType_sipSig_c = 204,
	neEntPortIfType_docsCableUpstreamChannel_c = 205,
	neEntPortIfType_econet_c = 206,
	neEntPortIfType_pon155_c = 207,
	neEntPortIfType_pon622_c = 208,
	neEntPortIfType_bridge_c = 209,
	neEntPortIfType_linegroup_c = 210,
	neEntPortIfType_voiceEMFGD_c = 211,
	neEntPortIfType_voiceFGDEANA_c = 212,
	neEntPortIfType_voiceDID_c = 213,
	neEntPortIfType_mpegTransport_c = 214,
	neEntPortIfType_sixToFour_c = 215,
	neEntPortIfType_gtp_c = 216,
	neEntPortIfType_pdnEtherLoop1_c = 217,
	neEntPortIfType_pdnEtherLoop2_c = 218,
	neEntPortIfType_opticalChannelGroup_c = 219,
	neEntPortIfType_homepna_c = 220,
	neEntPortIfType_gfp_c = 221,
	neEntPortIfType_ciscoISLvlan_c = 222,
	neEntPortIfType_actelisMetaLOOP_c = 223,
	neEntPortIfType_fcipLink_c = 224,
	neEntPortIfType_rpr_c = 225,
	neEntPortIfType_qam_c = 226,
	neEntPortIfType_lmp_c = 227,
	neEntPortIfType_cblVectaStar_c = 228,
	neEntPortIfType_docsCableMCmtsDownstream_c = 229,
	neEntPortIfType_adsl2_c = 230,
	neEntPortIfType_macSecControlledIF_c = 231,
	neEntPortIfType_macSecUncontrolledIF_c = 232,
	neEntPortIfType_aviciOpticalEther_c = 233,
	neEntPortIfType_atmbond_c = 234,
	neEntPortIfType_voiceFGDOS_c = 235,
	neEntPortIfType_mocaVersion1_c = 236,
	neEntPortIfType_ieee80216WMAN_c = 237,
	neEntPortIfType_adsl2plus_c = 238,
	neEntPortIfType_dvbRcsMacLayer_c = 239,
	neEntPortIfType_dvbTdm_c = 240,
	neEntPortIfType_dvbRcsTdma_c = 241,
	neEntPortIfType_x86Laps_c = 242,
	neEntPortIfType_wwanPP_c = 243,
	neEntPortIfType_wwanPP2_c = 244,
	neEntPortIfType_voiceEBS_c = 245,
	neEntPortIfType_ifPwType_c = 246,
	neEntPortIfType_ilan_c = 247,
	neEntPortIfType_pip_c = 248,
	neEntPortIfType_aluELP_c = 249,
	neEntPortIfType_gpon_c = 250,
	neEntPortIfType_vdsl2_c = 251,
	neEntPortIfType_capwapDot11Profile_c = 252,
	neEntPortIfType_capwapDot11Bss_c = 253,
	neEntPortIfType_capwapWtpVirtualRadio_c = 254,
	neEntPortIfType_bits_c = 255,
	neEntPortIfType_docsCableUpstreamRfPort_c = 256,
	neEntPortIfType_cableDownstreamRfPort_c = 257,
	neEntPortIfType_vmwareVirtualNic_c = 258,
	neEntPortIfType_ieee802154_c = 259,
	neEntPortIfType_otnOdu_c = 260,
	neEntPortIfType_otnOtu_c = 261,
	neEntPortIfType_ifVfiType_c = 262,
	neEntPortIfType_g9981_c = 263,
	neEntPortIfType_g9982_c = 264,
	neEntPortIfType_g9983_c = 265,
	neEntPortIfType_aluEpon_c = 266,
	neEntPortIfType_aluEponOnu_c = 267,
	neEntPortIfType_aluEponPhysicalUni_c = 268,
	neEntPortIfType_aluEponLogicalLink_c = 269,
	neEntPortIfType_aluGponOnu_c = 270,
	neEntPortIfType_aluGponPhysicalUni_c = 271,
	neEntPortIfType_vmwareNicTeam_c = 272,

	/* enums for column neEntPortRowStatus */
	neEntPortRowStatus_active_c = 1,
	neEntPortRowStatus_notInService_c = 2,
	neEntPortRowStatus_notReady_c = 3,
	neEntPortRowStatus_createAndGo_c = 4,
	neEntPortRowStatus_createAndWait_c = 5,
	neEntPortRowStatus_destroy_c = 6,
};

/* table neEntPortTable row entry data structure */
typedef struct neEntPortEntry_t
{
	/* Index values */
	uint32_t u32PhysicalIndex;
	
	struct {
		uint32_t u32IfIndex;
		int32_t i32IfType;
		uint32_t u32ChassisIndex;
		uint32_t u32HIndex;
	} oK;
	
	/* Column values */
	uint32_t u32IfIndex;
	int32_t i32IfType;
	uint32_t u32ChassisIndex;
	uint32_t u32HIndex;
	uint8_t u8RowStatus;
	
	int32_t i32Type;
	struct neEntPortEntry_t *pOldEntry;
	
	xBTree_Node_t oBTreeNode;
	xBTree_Node_t oIf_BTreeNode;
	xBTree_Node_t oHMap_BTreeNode;
} neEntPortEntry_t;

extern xBTree_t oNeEntPortTable_BTree;
extern xBTree_t oNeEntPortTable_If_BTree;
extern xBTree_t oNeEntPortTable_HMap_BTree;

/* neEntPortTable table mapper */
void neEntPortTable_init (void);
neEntPortEntry_t * neEntPortTable_createEntry (
	uint32_t u32PhysicalIndex);
neEntPortEntry_t * neEntPortTable_getByIndex (
	uint32_t u32PhysicalIndex);
neEntPortEntry_t * neEntPortTable_getNextIndex (
	uint32_t u32PhysicalIndex);
neEntPortEntry_t * neEntPortTable_HMap_getByIndex (
	uint32_t u32ChassisIndex,
	uint32_t u32HIndex);
neEntPortEntry_t * neEntPortTable_HMap_getNextIndex (
	uint32_t u32ChassisIndex,
	uint32_t u32HIndex);
void neEntPortTable_removeEntry (neEntPortEntry_t *poEntry);
bool neEntPortRowStatus_handler (
	neEntPortEntry_t *poEntry,
	uint8_t u8RowStatus);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point neEntPortTable_getFirst;
Netsnmp_Next_Data_Point neEntPortTable_getNext;
Netsnmp_Get_Data_Point neEntPortTable_get;
Netsnmp_Node_Handler neEntPortTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table neEntChassisPortTable definitions
 */
#define NEENTCHASSISPORTCHASSISINDEX 1
#define NEENTCHASSISPORTHINDEX 2
#define NEENTCHASSISPORTENTINDEX 3

/* table neEntChassisPortTable row entry data structure */
typedef struct neEntChassisPortEntry_t
{
	/* Index values */
// 	uint32_t u32ChassisIndex;
// 	uint32_t u32HIndex;
	
	/* Column values */
// 	uint32_t u32EntIndex;
	
// 	xBTree_Node_t oBTreeNode;
} neEntChassisPortEntry_t;

// extern xBTree_t oNeEntChassisPortTable_BTree;

/* neEntChassisPortTable table mapper */
void neEntChassisPortTable_init (void);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point neEntChassisPortTable_getFirst;
Netsnmp_Next_Data_Point neEntChassisPortTable_getNext;
Netsnmp_Get_Data_Point neEntChassisPortTable_get;
Netsnmp_Node_Handler neEntChassisPortTable_mapper;
#endif	/* SNMP_SRC */


enum
{
	neEntPortFlags_portCreated_c = 0,
	neEntPortFlags_mapCreated_c = 1,
	neEntPortFlags_count_c,
};

typedef struct neEntPortData_t
{
	uint32_t u32PhysicalIndex;
	uint32_t u32ChassisIndex;
	uint32_t u32HIndex;
	uint32_t u32IfIndex;
	
	neEntPortEntry_t oPort;
	neEntChassisPortEntry_t oMap;
	
	uint8_t au8Flags[1];
	
	xBTree_Node_t oBTreeNode;
	xBTree_Node_t oIf_BTreeNode;
	xBTree_Node_t oMap_BTreeNode;
} neEntPortData_t;

// extern xBTree_t oNeEntPortData_BTree;
// extern xBTree_t oNeEntPortData_If_BTree;
// extern xBTree_t oNeEntPortData_Map_BTree;

neEntPortData_t * neEntPortData_createEntry (
	uint32_t u32PhysicalIndex);
neEntPortData_t * neEntPortData_getByIndex (
	uint32_t u32PhysicalIndex);
neEntPortData_t * neEntPortData_getNextIndex (
	uint32_t u32PhysicalIndex);
#define neEntPortData_getByPortEntry(poEntry) ((poEntry) == NULL ? NULL: xGetParentByMemberPtr ((poEntry), neEntPortData_t, oPort))
#define neEntPortData_getByMapEntry(poEntry) ((poEntry) == NULL ? NULL: xGetParentByMemberPtr ((poEntry), neEntPortData_t, oMap))
void neEntPortData_removeEntry (neEntPortData_t *poEntry);


/**
 *	notification mapper(s)
 */
/* definitions for notification(s) of entityMIBTrapPrefix */
#	define ENTCONFIGCHANGE 1

/* entityMIBTrapPrefix mapper(s) */
int entConfigChange_trap (void);



#	ifdef __cplusplus
}
#	endif

#endif /* __ENTITYMIB_H__ */
