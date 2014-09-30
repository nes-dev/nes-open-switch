/*
 *  Copyright (c) 2013, 2014
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
	uint8_t au8Descr[255];
	size_t u16Descr_len;	/* # of uint8_t elements */
	xOid_t aoVendorType[128];
	size_t u16VendorType_len;	/* # of xOid_t elements */
	uint32_t u32ContainedIn;
	int32_t i32Class;
	int32_t i32ParentRelPos;
	uint8_t au8Name[255];
	size_t u16Name_len;	/* # of uint8_t elements */
	uint8_t au8HardwareRev[255];
	size_t u16HardwareRev_len;	/* # of uint8_t elements */
	uint8_t au8FirmwareRev[255];
	size_t u16FirmwareRev_len;	/* # of uint8_t elements */
	uint8_t au8SoftwareRev[255];
	size_t u16SoftwareRev_len;	/* # of uint8_t elements */
	uint8_t au8SerialNum[32];
	size_t u16SerialNum_len;	/* # of uint8_t elements */
	uint8_t au8MfgName[255];
	size_t u16MfgName_len;	/* # of uint8_t elements */
	uint8_t au8ModelName[255];
	size_t u16ModelName_len;	/* # of uint8_t elements */
	uint8_t au8Alias[32];
	size_t u16Alias_len;	/* # of uint8_t elements */
	uint8_t au8AssetID[32];
	size_t u16AssetID_len;	/* # of uint8_t elements */
	int32_t i32IsFRU;
	uint8_t au8MfgDate[11];
	size_t u16MfgDate_len;	/* # of uint8_t elements */
	uint8_t au8Uris[/* TODO: , OCTETSTR, "" */ TOBE_REPLACED];
	size_t u16Uris_len;	/* # of uint8_t elements */
	
// 	xBTree_Node_t oBTreeNode;
} entPhysicalEntry_t;

extern xBTree_t oEntPhysicalTable_BTree;
extern xBTree_t oEntPhysicalTable_SerialNum_BTree;

/* entPhysicalTable table mapper */
void entPhysicalTable_init (void);
entPhysicalEntry_t * entPhysicalTable_createEntry (
	uint32_t u32Index);
entPhysicalEntry_t * entPhysicalTable_getByIndex (
	uint32_t u32Index);
entPhysicalEntry_t * entPhysicalTable_getBySerialNum (
	uint8_t pu8SerialNum, size_t u16SerialNum_len);
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
	uint8_t au8Descr[255];
	size_t u16Descr_len;	/* # of uint8_t elements */
	xOid_t aoType[128];
	size_t u16Type_len;	/* # of xOid_t elements */
	uint8_t au8Community[255];
	size_t u16Community_len;	/* # of uint8_t elements */
	uint8_t au8TAddress[255];
	size_t u16TAddress_len;	/* # of uint8_t elements */
	xOid_t aoTDomain[128];
	size_t u16TDomain_len;	/* # of xOid_t elements */
	uint8_t au8ContextEngineID[32];
	size_t u16ContextEngineID_len;	/* # of uint8_t elements */
	uint8_t au8ContextName[255];
	size_t u16ContextName_len;	/* # of uint8_t elements */
	
// 	xBTree_Node_t oBTreeNode;
} entLogicalEntry_t;

extern xBTree_t oEntLogicalTable_BTree;

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
// 	uint32_t u32LPPhysicalIndex;
	
	/* Column values */
	
// 	xBTree_Node_t oBTreeNode;
} entLPMappingEntry_t;

extern xBTree_t oEntLPMappingTable_BTree;

/* entLPMappingTable table mapper */
void entLPMappingTable_init (void);
entLPMappingEntry_t * entLPMappingTable_createEntry (
	uint32_t u32LogicalIndex,
	uint32_t u32LPPhysicalIndex);
entLPMappingEntry_t * entLPMappingTable_getByIndex (
	uint32_t u32LogicalIndex,
	uint32_t u32LPPhysicalIndex);
entLPMappingEntry_t * entLPMappingTable_getNextIndex (
	uint32_t u32LogicalIndex,
	uint32_t u32LPPhysicalIndex);
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
	uint32_t u32AliasLogicalIndexOrZero;
	
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
	uint32_t u32AliasLogicalIndexOrZero);
entAliasMappingEntry_t * entAliasMappingTable_getByIndex (
	uint32_t u32PhysicalIndex,
	uint32_t u32AliasLogicalIndexOrZero);
entAliasMappingEntry_t * entAliasMappingTable_getNextIndex (
	uint32_t u32PhysicalIndex,
	uint32_t u32AliasLogicalIndexOrZero);
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
#define NEENTPHYSICALROWSTATUS 3
#define NEENTPHYSICALSTORAGETYPE 4

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
// 	uint32_t u32EntPhysicalIndex;
	
	/* Column values */
	uint32_t u32ContainedIn;
	int32_t i32Class;
	int32_t i32ParentRelPos;
	uint8_t u8RowStatus;
	uint8_t u8StorageType;
	
	uint32_t u32ChassisIndex;
	struct neEntPhysicalEntry_t *pOldEntry;
	
// 	xBTree_Node_t oBTreeNode;
} neEntPhysicalEntry_t;

extern xBTree_t oNeEntPhysicalTable_BTree;

/* neEntPhysicalTable table mapper */
void neEntPhysicalTable_init (void);
neEntPhysicalEntry_t * neEntPhysicalTable_createEntry (
	uint32_t u32EntPhysicalIndex);
neEntPhysicalEntry_t * neEntPhysicalTable_getByIndex (
	uint32_t u32EntPhysicalIndex);
neEntPhysicalEntry_t * neEntPhysicalTable_getNextIndex (
	uint32_t u32EntPhysicalIndex);
void neEntPhysicalTable_removeEntry (neEntPhysicalEntry_t *poEntry);
neEntPhysicalEntry_t * neEntPhysicalTable_createExt (
	uint32_t u32EntPhysicalIndex);
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


enum
{
	entPhysicalFlags_neCreated_c = 0,
	entPhysicalFlags_phyCreated_c = 1,
	entPhysicalFlags_count_c,
};

typedef struct entPhysicalData_t
{
	uint32_t u32Index;
	uint8_t au8SerialNum[32];
	size_t u16SerialNum_len;
	
	neEntPhysicalEntry_t oNe;
	entPhysicalEntry_t oPhy;
	
	uint8_t au8Flags[1];
	
	xBTree_Node_t oBTreeNode;
	xBTree_Node_t oSerialNum_BTreeNode;
} entPhysicalData_t;

// extern xBTree_t oEntPhysicalData_BTree;
// extern xBTree_t oEntPhysicalData_SerialNum_BTree;

entPhysicalData_t * entPhysicalData_createEntry (
	uint32_t u32Index);
bool entPhysicalData_linkSerialNum (entPhysicalData_t *poEntry);
entPhysicalData_t * entPhysicalData_getByIndex (
	uint32_t u32Index);
entPhysicalData_t * entPhysicalData_getBySerialNum (
	uint8_t *pu8SerialNum,
	size_t u16SerialNum_len);
entPhysicalData_t * entPhysicalData_getNextIndex (
	uint32_t u32Index);
#define entPhysicalData_getByNeEntry(poEntry) ((poEntry) == NULL ? NULL: xGetParentByMemberPtr ((poEntry), entPhysicalData_t, oNe))
#define entPhysicalData_getByPhyEntry(poEntry) ((poEntry) == NULL ? NULL: xGetParentByMemberPtr ((poEntry), entPhysicalData_t, oPhy))
void entPhysicalData_removeEntry (entPhysicalData_t *poEntry);


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
// 	uint32_t u32EntLogicalIndex;
	
	/* Column values */
	uint8_t u8RowStatus;
	uint8_t u8StorageType;
	
// 	xBTree_Node_t oBTreeNode;
} neEntLogicalEntry_t;

extern xBTree_t oNeEntLogicalTable_BTree;

/* neEntLogicalTable table mapper */
void neEntLogicalTable_init (void);
neEntLogicalEntry_t * neEntLogicalTable_createEntry (
	uint32_t u32EntLogicalIndex);
neEntLogicalEntry_t * neEntLogicalTable_getByIndex (
	uint32_t u32EntLogicalIndex);
neEntLogicalEntry_t * neEntLogicalTable_getNextIndex (
	uint32_t u32EntLogicalIndex);
void neEntLogicalTable_removeEntry (neEntLogicalEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point neEntLogicalTable_getFirst;
Netsnmp_Next_Data_Point neEntLogicalTable_getNext;
Netsnmp_Get_Data_Point neEntLogicalTable_get;
Netsnmp_Node_Handler neEntLogicalTable_mapper;
#endif	/* SNMP_SRC */


enum
{
	entLogicalFlags_neCreated_c = 0,
	entLogicalFlags_logCreated_c = 1,
	entLogicalFlags_count_c,
};

typedef struct entLogicalData_t
{
	uint32_t u32Index;
	
	neEntLogicalEntry_t oNe;
	entLogicalEntry_t oLog;
	
	uint8_t au8Flags[1];
	
	xBTree_Node_t oBTreeNode;
} entLogicalData_t;

// extern xBTree_t oEntLogicalData_BTree;

entLogicalData_t * entLogicalData_createEntry (
	uint32_t u32Index);
entLogicalData_t * entLogicalData_getByIndex (
	uint32_t u32Index);
entLogicalData_t * entLogicalData_getNextIndex (
	uint32_t u32Index);
#define entLogicalData_getByNeEntry(poEntry) ((poEntry) == NULL ? NULL: xGetParentByMemberPtr ((poEntry), entLogicalData_t, oNe))
#define entLogicalData_getByLogEntry(poEntry) ((poEntry) == NULL ? NULL: xGetParentByMemberPtr ((poEntry), entLogicalData_t, oLog))
void entLogicalData_removeEntry (entLogicalData_t *poEntry);


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
// 	uint32_t u32EntLogicalIndex;
// 	uint32_t u32EntLPPhysicalIndex;
	
	/* Column values */
	uint8_t u8RowStatus;
	uint8_t u8StorageType;
	
// 	xBTree_Node_t oBTreeNode;
} neEntLPMappingEntry_t;

extern xBTree_t oNeEntLPMappingTable_BTree;

/* neEntLPMappingTable table mapper */
void neEntLPMappingTable_init (void);
neEntLPMappingEntry_t * neEntLPMappingTable_createEntry (
	uint32_t u32EntLogicalIndex,
	uint32_t u32EntLPPhysicalIndex);
neEntLPMappingEntry_t * neEntLPMappingTable_getByIndex (
	uint32_t u32EntLogicalIndex,
	uint32_t u32EntLPPhysicalIndex);
neEntLPMappingEntry_t * neEntLPMappingTable_getNextIndex (
	uint32_t u32EntLogicalIndex,
	uint32_t u32EntLPPhysicalIndex);
void neEntLPMappingTable_removeEntry (neEntLPMappingEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point neEntLPMappingTable_getFirst;
Netsnmp_Next_Data_Point neEntLPMappingTable_getNext;
Netsnmp_Get_Data_Point neEntLPMappingTable_get;
Netsnmp_Node_Handler neEntLPMappingTable_mapper;
#endif	/* SNMP_SRC */


enum
{
	entLPMappingFlags_neCreated_c = 0,
	entLPMappingFlags_lpCreated_c = 1,
	entLPMappingFlags_count_c,
};

typedef struct entLPMappingData_t
{
	uint32_t u32LogicalIndex;
	uint32_t u32LPPhysicalIndex;
	
	neEntLPMappingEntry_t oNe;
	entLPMappingEntry_t oLp;
	
	uint8_t au8Flags[1];
	
	xBTree_Node_t oBTreeNode;
} entLPMappingData_t;

// extern xBTree_t oEntLPMappingData_BTree;

entLPMappingData_t * entLPMappingData_createEntry (
	uint32_t u32LogicalIndex,
	uint32_t u32LPPhysicalIndex);
entLPMappingData_t * entLPMappingData_getByIndex (
	uint32_t u32LogicalIndex,
	uint32_t u32LPPhysicalIndex);
entLPMappingData_t * entLPMappingData_getNextIndex (
	uint32_t u32LogicalIndex,
	uint32_t u32LPPhysicalIndex);
#define entLPMappingData_getByNeEntry(poEntry) ((poEntry) == NULL ? NULL: xGetParentByMemberPtr ((poEntry), entLPMappingData_t, oNe))
#define entLPMappingData_getByLpEntry(poEntry) ((poEntry) == NULL ? NULL: xGetParentByMemberPtr ((poEntry), entLPMappingData_t, oLp))
void entLPMappingData_removeEntry (entLPMappingData_t *poEntry);


/**
 *	table neEntPortTable definitions
 */
#define NEENTPORTCHASSISINDEX 1
#define NEENTPORTPORTINDEX 2
#define NEENTPORTIFINDEX 3
#define NEENTPORTROWSTATUS 4

enum
{
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
	uint32_t u32EntPhysicalIndex;
	
	/* Column values */
	uint32_t u32ChassisIndex;
	uint32_t u32PortIndex;
	uint32_t u32IfIndex;
	uint8_t u8RowStatus;
	
	int32_t i32Type;
	struct neEntPortEntry_t *pOldEntry;
	
	xBTree_Node_t oBTreeNode;
	xBTree_Node_t oIf_BTreeNode;
	xBTree_Node_t oId_BTreeNode;
} neEntPortEntry_t;

extern xBTree_t oNeEntPortTable_BTree;
extern xBTree_t oNeEntPortTable_If_BTree;
extern xBTree_t oNeEntPortTable_Id_BTree;

/* neEntPortTable table mapper */
void neEntPortTable_init (void);
neEntPortEntry_t * neEntPortTable_createEntry (
	uint32_t u32EntPhysicalIndex);
neEntPortEntry_t * neEntPortTable_getByIndex (
	uint32_t u32EntPhysicalIndex);
neEntPortEntry_t * neEntPortTable_getNextIndex (
	uint32_t u32EntPhysicalIndex);
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
#define NEENTCHASSISPORTINDEX 2
#define NEENTCHASSISPORTENTINDEX 3

/* table neEntChassisPortTable row entry data structure */
typedef struct neEntChassisPortEntry_t
{
	/* Index values */
	uint32_t u32ChassisIndex;
	uint32_t u32Index;
	
	/* Column values */
 	uint32_t u32EntIndex;
	
	xBTree_Node_t oBTreeNode;
} neEntChassisPortEntry_t;

extern xBTree_t oNeEntChassisPortTable_BTree;

/* neEntChassisPortTable table mapper */
void neEntChassisPortTable_init (void);
neEntChassisPortEntry_t * neEntChassisPortTable_createEntry (
	uint32_t u32ChassisIndex,
	uint32_t u32Index);
neEntChassisPortEntry_t * neEntChassisPortTable_getByIndex (
	uint32_t u32ChassisIndex,
	uint32_t u32Index);
neEntChassisPortEntry_t * neEntChassisPortTable_getNextIndex (
	uint32_t u32ChassisIndex,
	uint32_t u32Index);
void neEntChassisPortTable_removeEntry (neEntChassisPortEntry_t *poEntry);
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
	uint32_t u32EntPhysicalIndex;
	uint32_t u32ChassisIndex;
	uint32_t u32PortIndex;
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
	uint32_t u32EntPhysicalIndex);
neEntPortData_t * neEntPortData_getByIndex (
	uint32_t u32EntPhysicalIndex);
neEntPortData_t * neEntPortData_getNextIndex (
	uint32_t u32EntPhysicalIndex);
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
