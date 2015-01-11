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

#ifndef __MEFENNIOVCMIB_H__
#	define __MEFENNIOVCMIB_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include "lib/binaryTree.h"
#include "lib/snmp.h"

#define TOBE_REPLACED 1


/**
 *	agent MIB function
 */
void mefEnniOvcMib_init (void);


/**
 *	scalar mapper(s)
 */
/** definitions for scalar(s) of mefServiceOvcAttributes **/
#define MEFSERVICEOVCNEXTINDEX 1

typedef struct mefServiceOvcAttributes_t
{
	uint32_t u32NextIndex;
} mefServiceOvcAttributes_t;

extern mefServiceOvcAttributes_t oMefServiceOvcAttributes;

#ifdef SNMP_SRC
Netsnmp_Node_Handler mefServiceOvcAttributes_mapper;
#endif	/* SNMP_SRC */



/**
 *	table mapper(s)
 */
/**
 *	table mefServiceEnniCfgTable definitions
 */
#define MEFSERVICEENNICFGIDENTIFIER 1
#define MEFSERVICEENNICFGNUMBERLINKS 2
#define MEFSERVICEENNICFGPROTECTION 3
#define MEFSERVICEENNICFGMAXNUMBEROVCENDPTS 4
#define MEFSERVICEENNICFGVUNINEXTINDEX 5

enum
{
	/* enums for column mefServiceEnniCfgProtection */
	mefServiceEnniCfgProtection_none_c = 1,
	mefServiceEnniCfgProtection_linkAggregation_c = 2,
	mefServiceEnniCfgProtection_other_c = 3,
};

/* table mefServiceEnniCfgTable row entry data structure */
typedef struct mefServiceEnniCfgEntry_t
{
	/* Index values */
	uint32_t u32IfIndex;
	
	/* Column values */
	uint8_t au8Identifier[45];
	size_t u16Identifier_len;	/* # of uint8_t elements */
	uint32_t u32NumberLinks;
	int32_t i32Protection;
	uint32_t u32MaxNumberOvcEndPts;
	uint32_t u32VuniNextIndex;
	
	xBTree_Node_t oBTreeNode;
} mefServiceEnniCfgEntry_t;

extern xBTree_t oMefServiceEnniCfgTable_BTree;

/* mefServiceEnniCfgTable table mapper */
void mefServiceEnniCfgTable_init (void);
mefServiceEnniCfgEntry_t * mefServiceEnniCfgTable_createEntry (
	uint32_t u32IfIndex);
mefServiceEnniCfgEntry_t * mefServiceEnniCfgTable_getByIndex (
	uint32_t u32IfIndex);
mefServiceEnniCfgEntry_t * mefServiceEnniCfgTable_getNextIndex (
	uint32_t u32IfIndex);
void mefServiceEnniCfgTable_removeEntry (mefServiceEnniCfgEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point mefServiceEnniCfgTable_getFirst;
Netsnmp_Next_Data_Point mefServiceEnniCfgTable_getNext;
Netsnmp_Get_Data_Point mefServiceEnniCfgTable_get;
Netsnmp_Node_Handler mefServiceEnniCfgTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table mefServiceVuniCfgTable definitions
 */
#define MEFSERVICEVUNICFGINDEX 1
#define MEFSERVICEVUNICFGIDENTIFIER 2
#define MEFSERVICEVUNICFGCEVIDUNTAGGED 3
#define MEFSERVICEVUNICFGCEPRIORITYUNTAGGED 4
#define MEFSERVICEVUNICFGSVLANMAP 5
#define MEFSERVICEVUNICFGMAXNUMBEROVCENDPOINTS 6
#define MEFSERVICEVUNICFGINGRESSBWPGRPINDEX 7
#define MEFSERVICEVUNICFGEGRESSBWPGRPINDEX 8
#define MEFSERVICEVUNICFGL2CPGRPINDEX 9
#define MEFSERVICEVUNICFGROWSTATUS 10

enum
{
	/* enums for column mefServiceVuniCfgRowStatus */
	mefServiceVuniCfgRowStatus_active_c = 1,
	mefServiceVuniCfgRowStatus_notInService_c = 2,
	mefServiceVuniCfgRowStatus_notReady_c = 3,
	mefServiceVuniCfgRowStatus_createAndGo_c = 4,
	mefServiceVuniCfgRowStatus_createAndWait_c = 5,
	mefServiceVuniCfgRowStatus_destroy_c = 6,
};

/* table mefServiceVuniCfgTable row entry data structure */
typedef struct mefServiceVuniCfgEntry_t
{
	/* Index values */
	uint32_t u32IfIndex;
	uint32_t u32Index;
	
	/* Column values */
	uint8_t au8Identifier[45];
	size_t u16Identifier_len;	/* # of uint8_t elements */
	uint32_t u32CeVidUntagged;
	uint32_t u32CePriorityUntagged;
	uint8_t au8SVlanMap[255];
	size_t u16SVlanMap_len;	/* # of uint8_t elements */
	uint32_t u32MaxNumberOvcEndPoints;
	uint32_t u32IngressBwpGrpIndex;
	uint32_t u32EgressBwpGrpIndex;
	uint32_t u32L2cpGrpIndex;
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} mefServiceVuniCfgEntry_t;

extern xBTree_t oMefServiceVuniCfgTable_BTree;

/* mefServiceVuniCfgTable table mapper */
void mefServiceVuniCfgTable_init (void);
mefServiceVuniCfgEntry_t * mefServiceVuniCfgTable_createEntry (
	uint32_t u32IfIndex,
	uint32_t u32Index);
mefServiceVuniCfgEntry_t * mefServiceVuniCfgTable_getByIndex (
	uint32_t u32IfIndex,
	uint32_t u32Index);
mefServiceVuniCfgEntry_t * mefServiceVuniCfgTable_getNextIndex (
	uint32_t u32IfIndex,
	uint32_t u32Index);
void mefServiceVuniCfgTable_removeEntry (mefServiceVuniCfgEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point mefServiceVuniCfgTable_getFirst;
Netsnmp_Next_Data_Point mefServiceVuniCfgTable_getNext;
Netsnmp_Get_Data_Point mefServiceVuniCfgTable_get;
Netsnmp_Node_Handler mefServiceVuniCfgTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table mefServiceOvcCfgTable definitions
 */
#define MEFSERVICEOVCCFGINDEX 1
#define MEFSERVICEOVCCFGIDENTIFIER 2
#define MEFSERVICEOVCCFGSERVICETYPE 3
#define MEFSERVICEOVCCFGMTUSIZE 4
#define MEFSERVICEOVCCFGCEVLANIDPRESERVATION 5
#define MEFSERVICEOVCCFGCEVLANCOSPRESERVATION 6
#define MEFSERVICEOVCCFGSVLANIDPRESERVATION 7
#define MEFSERVICEOVCCFGSVLANCOSPRESERVATION 8
#define MEFSERVICEOVCCFGCOLORFORWARDING 9
#define MEFSERVICEOVCCFGCOLORINDICATOR 10
#define MEFSERVICEOVCCFGUNICASTDELIVERY 11
#define MEFSERVICEOVCCFGMULTICASTDELIVERY 12
#define MEFSERVICEOVCCFGBROADCASTDELIVERY 13
#define MEFSERVICEOVCCFGL2CPGRPINDEX 14
#define MEFSERVICEOVCCFGADMINSTATE 15
#define MEFSERVICEOVCCFGROWSTATUS 16

enum
{
	/* enums for column mefServiceOvcCfgServiceType */
	mefServiceOvcCfgServiceType_pointToPoint_c = 1,
	mefServiceOvcCfgServiceType_multipointToMultipoint_c = 2,
	mefServiceOvcCfgServiceType_rootedMultipoint_c = 3,

	/* enums for column mefServiceOvcCfgCeVlanIdPreservation */
	mefServiceOvcCfgCeVlanIdPreservation_preserve_c = 1,
	mefServiceOvcCfgCeVlanIdPreservation_noPreserve_c = 2,

	/* enums for column mefServiceOvcCfgCeVlanCosPreservation */
	mefServiceOvcCfgCeVlanCosPreservation_preserve_c = 1,
	mefServiceOvcCfgCeVlanCosPreservation_noPreserve_c = 2,

	/* enums for column mefServiceOvcCfgSVlanIdPreservation */
	mefServiceOvcCfgSVlanIdPreservation_preserve_c = 1,
	mefServiceOvcCfgSVlanIdPreservation_noPreserve_c = 2,

	/* enums for column mefServiceOvcCfgSVlanCosPreservation */
	mefServiceOvcCfgSVlanCosPreservation_preserve_c = 1,
	mefServiceOvcCfgSVlanCosPreservation_noPreserve_c = 2,

	/* enums for column mefServiceOvcCfgColorForwarding */
	mefServiceOvcCfgColorForwarding_colorFwdYes_c = 1,
	mefServiceOvcCfgColorForwarding_colorFwdNo_c = 2,

	/* enums for column mefServiceOvcCfgColorIndicator */
	mefServiceOvcCfgColorIndicator_colorIndicatorPcp_c = 1,
	mefServiceOvcCfgColorIndicator_colorIndicatorDei_c = 2,

	/* enums for column mefServiceOvcCfgUnicastDelivery */
	mefServiceOvcCfgUnicastDelivery_discard_c = 1,
	mefServiceOvcCfgUnicastDelivery_unconditional_c = 2,
	mefServiceOvcCfgUnicastDelivery_conditional_c = 3,

	/* enums for column mefServiceOvcCfgMulticastDelivery */
	mefServiceOvcCfgMulticastDelivery_discard_c = 1,
	mefServiceOvcCfgMulticastDelivery_unconditional_c = 2,
	mefServiceOvcCfgMulticastDelivery_conditional_c = 3,

	/* enums for column mefServiceOvcCfgBroadcastDelivery */
	mefServiceOvcCfgBroadcastDelivery_discard_c = 1,
	mefServiceOvcCfgBroadcastDelivery_unconditional_c = 2,
	mefServiceOvcCfgBroadcastDelivery_conditional_c = 3,

	/* enums for column mefServiceOvcCfgAdminState */
	mefServiceOvcCfgAdminState_unknown_c = 1,
	mefServiceOvcCfgAdminState_locked_c = 2,
	mefServiceOvcCfgAdminState_shuttingDown_c = 3,
	mefServiceOvcCfgAdminState_unlocked_c = 4,

	/* enums for column mefServiceOvcCfgRowStatus */
	mefServiceOvcCfgRowStatus_active_c = 1,
	mefServiceOvcCfgRowStatus_notInService_c = 2,
	mefServiceOvcCfgRowStatus_notReady_c = 3,
	mefServiceOvcCfgRowStatus_createAndGo_c = 4,
	mefServiceOvcCfgRowStatus_createAndWait_c = 5,
	mefServiceOvcCfgRowStatus_destroy_c = 6,
};

/* table mefServiceOvcCfgTable row entry data structure */
typedef struct mefServiceOvcCfgEntry_t
{
	/* Index values */
	uint32_t u32Index;
	
	/* Column values */
	uint8_t au8Identifier[45];
	size_t u16Identifier_len;	/* # of uint8_t elements */
	int32_t i32ServiceType;
	uint32_t u32MtuSize;
	int32_t i32CeVlanIdPreservation;
	int32_t i32CeVlanCosPreservation;
	int32_t i32SVlanIdPreservation;
	int32_t i32SVlanCosPreservation;
	int32_t i32ColorForwarding;
	int32_t i32ColorIndicator;
	int32_t i32UnicastDelivery;
	int32_t i32MulticastDelivery;
	int32_t i32BroadcastDelivery;
	uint32_t u32L2cpGrpIndex;
	int32_t i32AdminState;
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} mefServiceOvcCfgEntry_t;

extern xBTree_t oMefServiceOvcCfgTable_BTree;

/* mefServiceOvcCfgTable table mapper */
void mefServiceOvcCfgTable_init (void);
mefServiceOvcCfgEntry_t * mefServiceOvcCfgTable_createEntry (
	uint32_t u32Index);
mefServiceOvcCfgEntry_t * mefServiceOvcCfgTable_getByIndex (
	uint32_t u32Index);
mefServiceOvcCfgEntry_t * mefServiceOvcCfgTable_getNextIndex (
	uint32_t u32Index);
void mefServiceOvcCfgTable_removeEntry (mefServiceOvcCfgEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point mefServiceOvcCfgTable_getFirst;
Netsnmp_Next_Data_Point mefServiceOvcCfgTable_getNext;
Netsnmp_Get_Data_Point mefServiceOvcCfgTable_get;
Netsnmp_Node_Handler mefServiceOvcCfgTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table mefServiceOvcStatusTable definitions
 */
#define MEFSERVICEOVCSTATUSMAXMTUSIZE 1
#define MEFSERVICEOVCSTATUSMAXNUMENNIOVCENDPT 2
#define MEFSERVICEOVCSTATUSMAXNUMVUNIOVCENDPT 3
#define MEFSERVICEOVCSTATUSOPERATIONALSTATE 4

enum
{
	/* enums for column mefServiceOvcStatusOperationalState */
	mefServiceOvcStatusOperationalState_unknown_c = 1,
	mefServiceOvcStatusOperationalState_disabled_c = 2,
	mefServiceOvcStatusOperationalState_enabled_c = 3,
	mefServiceOvcStatusOperationalState_testing_c = 4,
};

/* table mefServiceOvcStatusTable row entry data structure */
typedef struct mefServiceOvcStatusEntry_t
{
	/* Index values */
	uint32_t u32CfgIndex;
	
	/* Column values */
	uint32_t u32MaxMtuSize;
	uint32_t u32MaxNumEnniOvcEndPt;
	uint32_t u32MaxNumVuniOvcEndPt;
	int32_t i32OperationalState;
	
	xBTree_Node_t oBTreeNode;
} mefServiceOvcStatusEntry_t;

extern xBTree_t oMefServiceOvcStatusTable_BTree;

/* mefServiceOvcStatusTable table mapper */
void mefServiceOvcStatusTable_init (void);
mefServiceOvcStatusEntry_t * mefServiceOvcStatusTable_createEntry (
	uint32_t u32CfgIndex);
mefServiceOvcStatusEntry_t * mefServiceOvcStatusTable_getByIndex (
	uint32_t u32CfgIndex);
mefServiceOvcStatusEntry_t * mefServiceOvcStatusTable_getNextIndex (
	uint32_t u32CfgIndex);
void mefServiceOvcStatusTable_removeEntry (mefServiceOvcStatusEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point mefServiceOvcStatusTable_getFirst;
Netsnmp_Next_Data_Point mefServiceOvcStatusTable_getNext;
Netsnmp_Get_Data_Point mefServiceOvcStatusTable_get;
Netsnmp_Node_Handler mefServiceOvcStatusTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table mefServiceOvcEndPtPerEnniCfgTable definitions
 */
#define MEFSERVICEOVCENDPTPERENNICFGIDENTIFIER 1
#define MEFSERVICEOVCENDPTPERENNICFGROLE 2
#define MEFSERVICEOVCENDPTPERENNICFGROOTSVLANMAP 3
#define MEFSERVICEOVCENDPTPERENNICFGLEAFSVLANMAP 4
#define MEFSERVICEOVCENDPTPERENNICFGINGRESSBWPGRPINDEX 5
#define MEFSERVICEOVCENDPTPERENNICFGEGRESSBWPGRPINDEX 6
#define MEFSERVICEOVCENDPTPERENNICFGROWSTATUS 7

enum
{
	/* enums for column mefServiceOvcEndPtPerEnniCfgRole */
	mefServiceOvcEndPtPerEnniCfgRole_root_c = 1,
	mefServiceOvcEndPtPerEnniCfgRole_leaf_c = 2,
	mefServiceOvcEndPtPerEnniCfgRole_trunk_c = 3,
	mefServiceOvcEndPtPerEnniCfgRole_other_c = 4,

	/* enums for column mefServiceOvcEndPtPerEnniCfgRowStatus */
	mefServiceOvcEndPtPerEnniCfgRowStatus_active_c = 1,
	mefServiceOvcEndPtPerEnniCfgRowStatus_notInService_c = 2,
	mefServiceOvcEndPtPerEnniCfgRowStatus_notReady_c = 3,
	mefServiceOvcEndPtPerEnniCfgRowStatus_createAndGo_c = 4,
	mefServiceOvcEndPtPerEnniCfgRowStatus_createAndWait_c = 5,
	mefServiceOvcEndPtPerEnniCfgRowStatus_destroy_c = 6,
};

/* table mefServiceOvcEndPtPerEnniCfgTable row entry data structure */
typedef struct mefServiceOvcEndPtPerEnniCfgEntry_t
{
	/* Index values */
	uint32_t u32IfIndex;
	uint32_t u32CfgIndex;
	
	/* Column values */
	uint8_t au8Identifier[45];
	size_t u16Identifier_len;	/* # of uint8_t elements */
	int32_t i32Role;
	uint8_t au8RootSVlanMap[255];
	size_t u16RootSVlanMap_len;	/* # of uint8_t elements */
	uint8_t au8LeafSVlanMap[255];
	size_t u16LeafSVlanMap_len;	/* # of uint8_t elements */
	uint32_t u32IngressBwpGrpIndex;
	uint32_t u32EgressBwpGrpIndex;
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} mefServiceOvcEndPtPerEnniCfgEntry_t;

extern xBTree_t oMefServiceOvcEndPtPerEnniCfgTable_BTree;

/* mefServiceOvcEndPtPerEnniCfgTable table mapper */
void mefServiceOvcEndPtPerEnniCfgTable_init (void);
mefServiceOvcEndPtPerEnniCfgEntry_t * mefServiceOvcEndPtPerEnniCfgTable_createEntry (
	uint32_t u32IfIndex,
	uint32_t u32CfgIndex);
mefServiceOvcEndPtPerEnniCfgEntry_t * mefServiceOvcEndPtPerEnniCfgTable_getByIndex (
	uint32_t u32IfIndex,
	uint32_t u32CfgIndex);
mefServiceOvcEndPtPerEnniCfgEntry_t * mefServiceOvcEndPtPerEnniCfgTable_getNextIndex (
	uint32_t u32IfIndex,
	uint32_t u32CfgIndex);
void mefServiceOvcEndPtPerEnniCfgTable_removeEntry (mefServiceOvcEndPtPerEnniCfgEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point mefServiceOvcEndPtPerEnniCfgTable_getFirst;
Netsnmp_Next_Data_Point mefServiceOvcEndPtPerEnniCfgTable_getNext;
Netsnmp_Get_Data_Point mefServiceOvcEndPtPerEnniCfgTable_get;
Netsnmp_Node_Handler mefServiceOvcEndPtPerEnniCfgTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table mefServiceOvcEndPtPerUniCfgTable definitions
 */
#define MEFSERVICEOVCENDPTPERUNICFGIDENTIFIER 1
#define MEFSERVICEOVCENDPTPERUNICFGROLE 2
#define MEFSERVICEOVCENDPTPERUNICFGCEVLANMAP 3
#define MEFSERVICEOVCENDPTPERUNICFGINGRESSBWPGRPINDEX 4
#define MEFSERVICEOVCENDPTPERUNICFGEGRESSBWPGRPINDEX 5
#define MEFSERVICEOVCENDPTPERUNICFGROWSTATUS 6

enum
{
	/* enums for column mefServiceOvcEndPtPerUniCfgRole */
	mefServiceOvcEndPtPerUniCfgRole_root_c = 1,
	mefServiceOvcEndPtPerUniCfgRole_leaf_c = 2,
	mefServiceOvcEndPtPerUniCfgRole_trunk_c = 3,
	mefServiceOvcEndPtPerUniCfgRole_other_c = 4,

	/* enums for column mefServiceOvcEndPtPerUniCfgRowStatus */
	mefServiceOvcEndPtPerUniCfgRowStatus_active_c = 1,
	mefServiceOvcEndPtPerUniCfgRowStatus_notInService_c = 2,
	mefServiceOvcEndPtPerUniCfgRowStatus_notReady_c = 3,
	mefServiceOvcEndPtPerUniCfgRowStatus_createAndGo_c = 4,
	mefServiceOvcEndPtPerUniCfgRowStatus_createAndWait_c = 5,
	mefServiceOvcEndPtPerUniCfgRowStatus_destroy_c = 6,
};

/* table mefServiceOvcEndPtPerUniCfgTable row entry data structure */
typedef struct mefServiceOvcEndPtPerUniCfgEntry_t
{
	/* Index values */
	uint32_t u32IfIndex;
	uint32_t u32CfgIndex;
	
	/* Column values */
	uint8_t au8Identifier[90];
	size_t u16Identifier_len;	/* # of uint8_t elements */
	int32_t i32Role;
	uint8_t au8CeVlanMap[255];
	size_t u16CeVlanMap_len;	/* # of uint8_t elements */
	uint32_t u32IngressBwpGrpIndex;
	uint32_t u32EgressBwpGrpIndex;
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} mefServiceOvcEndPtPerUniCfgEntry_t;

extern xBTree_t oMefServiceOvcEndPtPerUniCfgTable_BTree;

/* mefServiceOvcEndPtPerUniCfgTable table mapper */
void mefServiceOvcEndPtPerUniCfgTable_init (void);
mefServiceOvcEndPtPerUniCfgEntry_t * mefServiceOvcEndPtPerUniCfgTable_createEntry (
	uint32_t u32IfIndex,
	uint32_t u32CfgIndex);
mefServiceOvcEndPtPerUniCfgEntry_t * mefServiceOvcEndPtPerUniCfgTable_getByIndex (
	uint32_t u32IfIndex,
	uint32_t u32CfgIndex);
mefServiceOvcEndPtPerUniCfgEntry_t * mefServiceOvcEndPtPerUniCfgTable_getNextIndex (
	uint32_t u32IfIndex,
	uint32_t u32CfgIndex);
void mefServiceOvcEndPtPerUniCfgTable_removeEntry (mefServiceOvcEndPtPerUniCfgEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point mefServiceOvcEndPtPerUniCfgTable_getFirst;
Netsnmp_Next_Data_Point mefServiceOvcEndPtPerUniCfgTable_getNext;
Netsnmp_Get_Data_Point mefServiceOvcEndPtPerUniCfgTable_get;
Netsnmp_Node_Handler mefServiceOvcEndPtPerUniCfgTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table mefServiceOvcEndPtPerVuniCfgTable definitions
 */
#define MEFSERVICEOVCENDPTPERVUNICFGIDENTIFIER 1
#define MEFSERVICEOVCENDPTPERVUNICFGROLE 2
#define MEFSERVICEOVCENDPTPERVUNICFGCEVLANMAP 3
#define MEFSERVICEOVCENDPTPERVUNICFGINGRESSBWPGRPINDEX 4
#define MEFSERVICEOVCENDPTPERVUNICFGEGRESSBWPGRPINDEX 5
#define MEFSERVICEOVCENDPTPERVUNICFGROWSTATUS 6

enum
{
	/* enums for column mefServiceOvcEndPtPerVuniCfgRole */
	mefServiceOvcEndPtPerVuniCfgRole_root_c = 1,
	mefServiceOvcEndPtPerVuniCfgRole_leaf_c = 2,
	mefServiceOvcEndPtPerVuniCfgRole_trunk_c = 3,
	mefServiceOvcEndPtPerVuniCfgRole_other_c = 4,

	/* enums for column mefServiceOvcEndPtPerVuniCfgRowStatus */
	mefServiceOvcEndPtPerVuniCfgRowStatus_active_c = 1,
	mefServiceOvcEndPtPerVuniCfgRowStatus_notInService_c = 2,
	mefServiceOvcEndPtPerVuniCfgRowStatus_notReady_c = 3,
	mefServiceOvcEndPtPerVuniCfgRowStatus_createAndGo_c = 4,
	mefServiceOvcEndPtPerVuniCfgRowStatus_createAndWait_c = 5,
	mefServiceOvcEndPtPerVuniCfgRowStatus_destroy_c = 6,
};

/* table mefServiceOvcEndPtPerVuniCfgTable row entry data structure */
typedef struct mefServiceOvcEndPtPerVuniCfgEntry_t
{
	/* Index values */
	uint32_t u32IfIndex;
	uint32_t u32VuniCfgIndex;
	uint32_t u32OvcCfgIndex;
	
	/* Column values */
	uint8_t au8Identifier[90];
	size_t u16Identifier_len;	/* # of uint8_t elements */
	int32_t i32Role;
	uint8_t au8CeVlanMap[255];
	size_t u16CeVlanMap_len;	/* # of uint8_t elements */
	uint32_t u32IngressBwpGrpIndex;
	uint32_t u32EgressBwpGrpIndex;
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} mefServiceOvcEndPtPerVuniCfgEntry_t;

extern xBTree_t oMefServiceOvcEndPtPerVuniCfgTable_BTree;

/* mefServiceOvcEndPtPerVuniCfgTable table mapper */
void mefServiceOvcEndPtPerVuniCfgTable_init (void);
mefServiceOvcEndPtPerVuniCfgEntry_t * mefServiceOvcEndPtPerVuniCfgTable_createEntry (
	uint32_t u32IfIndex,
	uint32_t u32VuniCfgIndex,
	uint32_t u32OvcCfgIndex);
mefServiceOvcEndPtPerVuniCfgEntry_t * mefServiceOvcEndPtPerVuniCfgTable_getByIndex (
	uint32_t u32IfIndex,
	uint32_t u32VuniCfgIndex,
	uint32_t u32OvcCfgIndex);
mefServiceOvcEndPtPerVuniCfgEntry_t * mefServiceOvcEndPtPerVuniCfgTable_getNextIndex (
	uint32_t u32IfIndex,
	uint32_t u32VuniCfgIndex,
	uint32_t u32OvcCfgIndex);
void mefServiceOvcEndPtPerVuniCfgTable_removeEntry (mefServiceOvcEndPtPerVuniCfgEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point mefServiceOvcEndPtPerVuniCfgTable_getFirst;
Netsnmp_Next_Data_Point mefServiceOvcEndPtPerVuniCfgTable_getNext;
Netsnmp_Get_Data_Point mefServiceOvcEndPtPerVuniCfgTable_get;
Netsnmp_Node_Handler mefServiceOvcEndPtPerVuniCfgTable_mapper;
#endif	/* SNMP_SRC */



#	ifdef __cplusplus
}
#	endif

#endif /* __MEFENNIOVCMIB_H__ */
