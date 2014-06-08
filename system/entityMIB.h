/*
 *  Copyright (c) 2013, 2014
 *      NES <nes.open.switch@gmail.com>
 *
 *  All rights reserved. This source file is the sole property of NES, and
 *  contain proprietary and confidential information related to NES.
 *
 *  Licensed under the NES PROF License, Version 1.0 (the "License"); you may
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
#include "lib/snmp.h"

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
	int32_t i32Index;
	
	/* Column values */
	uint8_t au8Descr[255];
	size_t u16Descr_len;	/* # of uint8_t elements */
	xOid_t aoVendorType[128];
	size_t u16VendorType_len;	/* # of xOid_t elements */
	int32_t i32ContainedIn;
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
	
	xBTree_Node_t oBTreeNode;
} entPhysicalEntry_t;

extern xBTree_t oEntPhysicalTable_BTree;

/* entPhysicalTable table mapper */
void entPhysicalTable_init (void);
entPhysicalEntry_t * entPhysicalTable_createEntry (
	int32_t i32Index);
entPhysicalEntry_t * entPhysicalTable_getByIndex (
	int32_t i32Index);
entPhysicalEntry_t * entPhysicalTable_getNextIndex (
	int32_t i32Index);
void entPhysicalTable_removeEntry (entPhysicalEntry_t *poEntry);
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
	int32_t i32Index;
	
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
	
	xBTree_Node_t oBTreeNode;
} entLogicalEntry_t;

extern xBTree_t oEntLogicalTable_BTree;

/* entLogicalTable table mapper */
void entLogicalTable_init (void);
entLogicalEntry_t * entLogicalTable_createEntry (
	int32_t i32Index);
entLogicalEntry_t * entLogicalTable_getByIndex (
	int32_t i32Index);
entLogicalEntry_t * entLogicalTable_getNextIndex (
	int32_t i32Index);
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
	int32_t i32LogicalIndex;
	int32_t i32LPPhysicalIndex;
	
	/* Column values */
	
	xBTree_Node_t oBTreeNode;
} entLPMappingEntry_t;

extern xBTree_t oEntLPMappingTable_BTree;

/* entLPMappingTable table mapper */
void entLPMappingTable_init (void);
entLPMappingEntry_t * entLPMappingTable_createEntry (
	int32_t i32LogicalIndex,
	int32_t i32LPPhysicalIndex);
entLPMappingEntry_t * entLPMappingTable_getByIndex (
	int32_t i32LogicalIndex,
	int32_t i32LPPhysicalIndex);
entLPMappingEntry_t * entLPMappingTable_getNextIndex (
	int32_t i32LogicalIndex,
	int32_t i32LPPhysicalIndex);
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
	int32_t i32PhysicalIndex;
	int32_t i32AliasLogicalIndexOrZero;
	
	/* Column values */
	xOid_t aoIdentifier[128];
	size_t u16Identifier_len;	/* # of xOid_t elements */
	
	xBTree_Node_t oBTreeNode;
} entAliasMappingEntry_t;

extern xBTree_t oEntAliasMappingTable_BTree;

/* entAliasMappingTable table mapper */
void entAliasMappingTable_init (void);
entAliasMappingEntry_t * entAliasMappingTable_createEntry (
	int32_t i32PhysicalIndex,
	int32_t i32AliasLogicalIndexOrZero);
entAliasMappingEntry_t * entAliasMappingTable_getByIndex (
	int32_t i32PhysicalIndex,
	int32_t i32AliasLogicalIndexOrZero);
entAliasMappingEntry_t * entAliasMappingTable_getNextIndex (
	int32_t i32PhysicalIndex,
	int32_t i32AliasLogicalIndexOrZero);
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
	int32_t i32Index;
	int32_t i32ChildIndex;
	
	/* Column values */
	
	xBTree_Node_t oBTreeNode;
} entPhysicalContainsEntry_t;

extern xBTree_t oEntPhysicalContainsTable_BTree;

/* entPhysicalContainsTable table mapper */
void entPhysicalContainsTable_init (void);
entPhysicalContainsEntry_t * entPhysicalContainsTable_createEntry (
	int32_t i32Index,
	int32_t i32ChildIndex);
entPhysicalContainsEntry_t * entPhysicalContainsTable_getByIndex (
	int32_t i32Index,
	int32_t i32ChildIndex);
entPhysicalContainsEntry_t * entPhysicalContainsTable_getNextIndex (
	int32_t i32Index,
	int32_t i32ChildIndex);
void entPhysicalContainsTable_removeEntry (entPhysicalContainsEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point entPhysicalContainsTable_getFirst;
Netsnmp_Next_Data_Point entPhysicalContainsTable_getNext;
Netsnmp_Get_Data_Point entPhysicalContainsTable_get;
Netsnmp_Node_Handler entPhysicalContainsTable_mapper;
#endif	/* SNMP_SRC */


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
