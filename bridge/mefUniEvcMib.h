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

#ifndef __MEFUNIEVCMIB_H__
#	define __MEFUNIEVCMIB_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include "lib/binaryTree.h"
#include "lib/snmp.h"

#define TOBE_REPLACED 1


/**
 *	agent MIB function
 */
void mefUniEvcMib_init (void);


/**
 *	scalar mapper(s)
 */
/** definitions for scalar(s) of mefServiceEvcAttributes **/
#define MEFSERVICEEVCNEXTINDEX 1

typedef struct mefServiceEvcAttributes_t
{
	uint32_t u32NextIndex;
} mefServiceEvcAttributes_t;

extern mefServiceEvcAttributes_t oMefServiceEvcAttributes;

#ifdef SNMP_SRC
Netsnmp_Node_Handler mefServiceEvcAttributes_mapper;
#endif	/* SNMP_SRC */

/** definitions for scalar(s) of mefServiceBwpAttributes **/
#define MEFSERVICEBWPGRPNEXTINDEX 1

typedef struct mefServiceBwpAttributes_t
{
	uint32_t u32GrpNextIndex;
} mefServiceBwpAttributes_t;

extern mefServiceBwpAttributes_t oMefServiceBwpAttributes;

#ifdef SNMP_SRC
Netsnmp_Node_Handler mefServiceBwpAttributes_mapper;
#endif	/* SNMP_SRC */

/** definitions for scalar(s) of mefServiceCosAttributes **/
#define MEFSERVICECOSNEXTINDEX 1

typedef struct mefServiceCosAttributes_t
{
	uint32_t u32NextIndex;
} mefServiceCosAttributes_t;

extern mefServiceCosAttributes_t oMefServiceCosAttributes;

#ifdef SNMP_SRC
Netsnmp_Node_Handler mefServiceCosAttributes_mapper;
#endif	/* SNMP_SRC */

/** definitions for scalar(s) of mefServiceL2cpAttributes **/
#define MEFSERVICEL2CPGRPNEXTINDEX 1

typedef struct mefServiceL2cpAttributes_t
{
	uint32_t u32GrpNextIndex;
} mefServiceL2cpAttributes_t;

extern mefServiceL2cpAttributes_t oMefServiceL2cpAttributes;

#ifdef SNMP_SRC
Netsnmp_Node_Handler mefServiceL2cpAttributes_mapper;
#endif	/* SNMP_SRC */

/** definitions for scalar(s) of mefServiceNotificationCfg **/
#define MEFSERVICENOTIFICATIONCFGALARMENABLE 1

enum
{
	/* enums for scalar mefServiceNotificationCfgAlarmEnable */
	mefServiceNotificationCfgAlarmEnable_bServiceConfigurationAlarm_c = 0,
};

typedef struct mefServiceNotificationCfg_t
{
	uint8_t au8AlarmEnable[1];
	size_t u16AlarmEnable_len;	/* # of uint8_t elements */
} mefServiceNotificationCfg_t;

extern mefServiceNotificationCfg_t oMefServiceNotificationCfg;

#ifdef SNMP_SRC
Netsnmp_Node_Handler mefServiceNotificationCfg_mapper;
#endif	/* SNMP_SRC */



/**
 *	table mapper(s)
 */
/**
 *	table mefServiceInterfaceCfgTable definitions
 */
#define MEFSERVICEINTERFACECFGTYPE 1
#define MEFSERVICEINTERFACECFGIDENTIFIER 2
#define MEFSERVICEINTERFACECFGFRAMEFORMAT 3
#define MEFSERVICEINTERFACECFGINGRESSBWPGRPINDEX 4
#define MEFSERVICEINTERFACECFGEGRESSBWPGRPINDEX 5
#define MEFSERVICEINTERFACECFGL2CPGRPINDEX 9

enum
{
	/* enums for column mefServiceInterfaceCfgType */
	mefServiceInterfaceCfgType_bUni1d1_c = 0,
	mefServiceInterfaceCfgType_bUni1d2_c = 1,
	mefServiceInterfaceCfgType_bUni2d1_c = 2,
	mefServiceInterfaceCfgType_bUni2d2_c = 3,
	mefServiceInterfaceCfgType_bEnni_c = 4,
	mefServiceInterfaceCfgType_bEnniVuni_c = 5,

	/* enums for column mefServiceInterfaceCfgFrameFormat */
	mefServiceInterfaceCfgFrameFormat_noTag_c = 1,
	mefServiceInterfaceCfgFrameFormat_ctag_c = 2,
	mefServiceInterfaceCfgFrameFormat_stag_c = 3,
	mefServiceInterfaceCfgFrameFormat_stagCtag_c = 4,
};

/* table mefServiceInterfaceCfgTable row entry data structure */
typedef struct mefServiceInterfaceCfgEntry_t
{
	/* Index values */
	uint32_t u32IfIndex;
	
	/* Column values */
	uint8_t au8Type[1];
	size_t u16Type_len;	/* # of uint8_t elements */
	uint8_t au8Identifier[255];
	size_t u16Identifier_len;	/* # of uint8_t elements */
	int32_t i32FrameFormat;
	uint32_t u32IngressBwpGrpIndex;
	uint32_t u32EgressBwpGrpIndex;
	uint32_t u32L2cpGrpIndex;
	
	xBTree_Node_t oBTreeNode;
} mefServiceInterfaceCfgEntry_t;

extern xBTree_t oMefServiceInterfaceCfgTable_BTree;

/* mefServiceInterfaceCfgTable table mapper */
void mefServiceInterfaceCfgTable_init (void);
mefServiceInterfaceCfgEntry_t * mefServiceInterfaceCfgTable_createEntry (
	uint32_t u32IfIndex);
mefServiceInterfaceCfgEntry_t * mefServiceInterfaceCfgTable_getByIndex (
	uint32_t u32IfIndex);
mefServiceInterfaceCfgEntry_t * mefServiceInterfaceCfgTable_getNextIndex (
	uint32_t u32IfIndex);
void mefServiceInterfaceCfgTable_removeEntry (mefServiceInterfaceCfgEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point mefServiceInterfaceCfgTable_getFirst;
Netsnmp_Next_Data_Point mefServiceInterfaceCfgTable_getNext;
Netsnmp_Get_Data_Point mefServiceInterfaceCfgTable_get;
Netsnmp_Node_Handler mefServiceInterfaceCfgTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table mefServiceInterfaceStatusTable definitions
 */
#define MEFSERVICEINTERFACESTATUSTYPE 1
#define MEFSERVICEINTERFACESTATUSMAXVC 2
#define MEFSERVICEINTERFACESTATUSMAXENDPOINTPERVC 3

enum
{
	/* enums for column mefServiceInterfaceStatusType */
	mefServiceInterfaceStatusType_bUni1d1_c = 0,
	mefServiceInterfaceStatusType_bUni1d2_c = 1,
	mefServiceInterfaceStatusType_bUni2d1_c = 2,
	mefServiceInterfaceStatusType_bUni2d2_c = 3,
	mefServiceInterfaceStatusType_bEnni_c = 4,
	mefServiceInterfaceStatusType_bEnniVuni_c = 5,
};

/* table mefServiceInterfaceStatusTable row entry data structure */
typedef struct mefServiceInterfaceStatusEntry_t
{
	/* Index values */
	uint32_t u32IfIndex;
	
	/* Column values */
	uint8_t au8Type[1];
	size_t u16Type_len;	/* # of uint8_t elements */
	uint32_t u32MaxVc;
	uint32_t u32MaxEndPointPerVc;
	
	xBTree_Node_t oBTreeNode;
} mefServiceInterfaceStatusEntry_t;

extern xBTree_t oMefServiceInterfaceStatusTable_BTree;

/* mefServiceInterfaceStatusTable table mapper */
void mefServiceInterfaceStatusTable_init (void);
mefServiceInterfaceStatusEntry_t * mefServiceInterfaceStatusTable_createEntry (
	uint32_t u32IfIndex);
mefServiceInterfaceStatusEntry_t * mefServiceInterfaceStatusTable_getByIndex (
	uint32_t u32IfIndex);
mefServiceInterfaceStatusEntry_t * mefServiceInterfaceStatusTable_getNextIndex (
	uint32_t u32IfIndex);
void mefServiceInterfaceStatusTable_removeEntry (mefServiceInterfaceStatusEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point mefServiceInterfaceStatusTable_getFirst;
Netsnmp_Next_Data_Point mefServiceInterfaceStatusTable_getNext;
Netsnmp_Get_Data_Point mefServiceInterfaceStatusTable_get;
Netsnmp_Node_Handler mefServiceInterfaceStatusTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table mefServiceInterfaceStatisticsTable definitions
 */
#define MEFSERVICEINTERFACESTATISTICSINGRESSUNDERSIZED 1
#define MEFSERVICEINTERFACESTATISTICSINGRESSOVERSIZED 2
#define MEFSERVICEINTERFACESTATISTICSINGRESSFRAGMENTS 3
#define MEFSERVICEINTERFACESTATISTICSINGRESSCRCALIGNMENT 4
#define MEFSERVICEINTERFACESTATISTICSINGRESSINVALIDVID 5
#define MEFSERVICEINTERFACESTATISTICSINGRESSOCTETS 6
#define MEFSERVICEINTERFACESTATISTICSINGRESSUNICAST 7
#define MEFSERVICEINTERFACESTATISTICSINGRESSMULTICAST 8
#define MEFSERVICEINTERFACESTATISTICSINGRESSBROADCAST 9
#define MEFSERVICEINTERFACESTATISTICSEGRESSOCTETS 10
#define MEFSERVICEINTERFACESTATISTICSEGRESSUNICAST 11
#define MEFSERVICEINTERFACESTATISTICSEGRESSMULTICAST 12
#define MEFSERVICEINTERFACESTATISTICSEGRESSBROADCAST 13

/* table mefServiceInterfaceStatisticsTable row entry data structure */
typedef struct mefServiceInterfaceStatisticsEntry_t
{
	/* Index values */
	uint32_t u32IfIndex;
	
	/* Column values */
	uint32_t u32IngressUndersized;
	uint32_t u32IngressOversized;
	uint32_t u32IngressFragments;
	uint32_t u32IngressCrcAlignment;
	uint32_t u32IngressInvalidVid;
	uint64_t u64IngressOctets;
	uint64_t u64IngressUnicast;
	uint64_t u64IngressMulticast;
	uint64_t u64IngressBroadcast;
	uint64_t u64EgressOctets;
	uint64_t u64EgressUnicast;
	uint64_t u64EgressMulticast;
	uint64_t u64EgressBroadcast;
	
	xBTree_Node_t oBTreeNode;
} mefServiceInterfaceStatisticsEntry_t;

extern xBTree_t oMefServiceInterfaceStatisticsTable_BTree;

/* mefServiceInterfaceStatisticsTable table mapper */
void mefServiceInterfaceStatisticsTable_init (void);
mefServiceInterfaceStatisticsEntry_t * mefServiceInterfaceStatisticsTable_createEntry (
	uint32_t u32IfIndex);
mefServiceInterfaceStatisticsEntry_t * mefServiceInterfaceStatisticsTable_getByIndex (
	uint32_t u32IfIndex);
mefServiceInterfaceStatisticsEntry_t * mefServiceInterfaceStatisticsTable_getNextIndex (
	uint32_t u32IfIndex);
void mefServiceInterfaceStatisticsTable_removeEntry (mefServiceInterfaceStatisticsEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point mefServiceInterfaceStatisticsTable_getFirst;
Netsnmp_Next_Data_Point mefServiceInterfaceStatisticsTable_getNext;
Netsnmp_Get_Data_Point mefServiceInterfaceStatisticsTable_get;
Netsnmp_Node_Handler mefServiceInterfaceStatisticsTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table mefServiceUniCfgTable definitions
 */
#define MEFSERVICEUNICFGIDENTIFIER 1
#define MEFSERVICEUNICFGBUNDLINGMULTIPLEX 2
#define MEFSERVICEUNICFGCEVIDUNTAGGED 3
#define MEFSERVICEUNICFGCEPRIORITYUNTAGGED 4

enum
{
	/* enums for column mefServiceUniCfgBundlingMultiplex */
	mefServiceUniCfgBundlingMultiplex_allToOne_c = 1,
	mefServiceUniCfgBundlingMultiplex_bundling_c = 2,
	mefServiceUniCfgBundlingMultiplex_multiplex_c = 3,
	mefServiceUniCfgBundlingMultiplex_bundlingMultiplex_c = 4,
};

/* table mefServiceUniCfgTable row entry data structure */
typedef struct mefServiceUniCfgEntry_t
{
	/* Index values */
	uint32_t u32IfIndex;
	
	/* Column values */
	uint8_t au8Identifier[255];
	size_t u16Identifier_len;	/* # of uint8_t elements */
	int32_t i32BundlingMultiplex;
	uint32_t u32CeVidUntagged;
	uint32_t u32CePriorityUntagged;
	
	xBTree_Node_t oBTreeNode;
} mefServiceUniCfgEntry_t;

extern xBTree_t oMefServiceUniCfgTable_BTree;

/* mefServiceUniCfgTable table mapper */
void mefServiceUniCfgTable_init (void);
mefServiceUniCfgEntry_t * mefServiceUniCfgTable_createEntry (
	uint32_t u32IfIndex);
mefServiceUniCfgEntry_t * mefServiceUniCfgTable_getByIndex (
	uint32_t u32IfIndex);
mefServiceUniCfgEntry_t * mefServiceUniCfgTable_getNextIndex (
	uint32_t u32IfIndex);
void mefServiceUniCfgTable_removeEntry (mefServiceUniCfgEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point mefServiceUniCfgTable_getFirst;
Netsnmp_Next_Data_Point mefServiceUniCfgTable_getNext;
Netsnmp_Get_Data_Point mefServiceUniCfgTable_get;
Netsnmp_Node_Handler mefServiceUniCfgTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table mefServiceEvcPerUniCfgTable definitions
 */
#define MEFSERVICEEVCPERUNICFGSERVICETYPE 1
#define MEFSERVICEEVCPERUNICFGIDENTIFIER 2
#define MEFSERVICEEVCPERUNICFGCEVLANMAP 3
#define MEFSERVICEEVCPERUNICFGINGRESSBWPGRPINDEX 4
#define MEFSERVICEEVCPERUNICFGEGRESSBWPGRPINDEX 5

enum
{
	/* enums for column mefServiceEvcPerUniCfgServiceType */
	mefServiceEvcPerUniCfgServiceType_epl_c = 1,
	mefServiceEvcPerUniCfgServiceType_evpl_c = 2,
	mefServiceEvcPerUniCfgServiceType_eplan_c = 3,
	mefServiceEvcPerUniCfgServiceType_evplan_c = 4,
	mefServiceEvcPerUniCfgServiceType_eptree_c = 5,
	mefServiceEvcPerUniCfgServiceType_evptree_c = 6,
};

/* table mefServiceEvcPerUniCfgTable row entry data structure */
typedef struct mefServiceEvcPerUniCfgEntry_t
{
	/* Index values */
	uint32_t u32IfIndex;
	uint32_t u32CfgIndex;
	
	/* Column values */
	int32_t i32ServiceType;
	uint8_t au8Identifier[90];
	size_t u16Identifier_len;	/* # of uint8_t elements */
	uint8_t au8CeVlanMap[255];
	size_t u16CeVlanMap_len;	/* # of uint8_t elements */
	uint32_t u32IngressBwpGrpIndex;
	uint32_t u32EgressBwpGrpIndex;
	
	xBTree_Node_t oBTreeNode;
} mefServiceEvcPerUniCfgEntry_t;

extern xBTree_t oMefServiceEvcPerUniCfgTable_BTree;

/* mefServiceEvcPerUniCfgTable table mapper */
void mefServiceEvcPerUniCfgTable_init (void);
mefServiceEvcPerUniCfgEntry_t * mefServiceEvcPerUniCfgTable_createEntry (
	uint32_t u32IfIndex,
	uint32_t u32CfgIndex);
mefServiceEvcPerUniCfgEntry_t * mefServiceEvcPerUniCfgTable_getByIndex (
	uint32_t u32IfIndex,
	uint32_t u32CfgIndex);
mefServiceEvcPerUniCfgEntry_t * mefServiceEvcPerUniCfgTable_getNextIndex (
	uint32_t u32IfIndex,
	uint32_t u32CfgIndex);
void mefServiceEvcPerUniCfgTable_removeEntry (mefServiceEvcPerUniCfgEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point mefServiceEvcPerUniCfgTable_getFirst;
Netsnmp_Next_Data_Point mefServiceEvcPerUniCfgTable_getNext;
Netsnmp_Get_Data_Point mefServiceEvcPerUniCfgTable_get;
Netsnmp_Node_Handler mefServiceEvcPerUniCfgTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table mefServiceEvcCfgTable definitions
 */
#define MEFSERVICEEVCCFGINDEX 1
#define MEFSERVICEEVCCFGIDENTIFIER 2
#define MEFSERVICEEVCCFGSERVICETYPE 3
#define MEFSERVICEEVCCFGMTUSIZE 4
#define MEFSERVICEEVCCFGCEVLANIDPRESERVATION 5
#define MEFSERVICEEVCCFGCEVLANCOSPRESERVATION 6
#define MEFSERVICEEVCCFGUNICASTDELIVERY 7
#define MEFSERVICEEVCCFGMULTICASTDELIVERY 8
#define MEFSERVICEEVCCFGBROADCASTDELIVERY 9
#define MEFSERVICEEVCCFGL2CPGRPINDEX 10
#define MEFSERVICEEVCCFGADMINSTATE 11
#define MEFSERVICEEVCCFGROWSTATUS 12

enum
{
	/* enums for column mefServiceEvcCfgServiceType */
	mefServiceEvcCfgServiceType_pointToPoint_c = 1,
	mefServiceEvcCfgServiceType_multipointToMultipoint_c = 2,
	mefServiceEvcCfgServiceType_rootedMultipoint_c = 3,

	/* enums for column mefServiceEvcCfgCeVlanIdPreservation */
	mefServiceEvcCfgCeVlanIdPreservation_preserve_c = 1,
	mefServiceEvcCfgCeVlanIdPreservation_noPreserve_c = 2,

	/* enums for column mefServiceEvcCfgCeVlanCosPreservation */
	mefServiceEvcCfgCeVlanCosPreservation_preserve_c = 1,
	mefServiceEvcCfgCeVlanCosPreservation_noPreserve_c = 2,

	/* enums for column mefServiceEvcCfgUnicastDelivery */
	mefServiceEvcCfgUnicastDelivery_discard_c = 1,
	mefServiceEvcCfgUnicastDelivery_unconditional_c = 2,
	mefServiceEvcCfgUnicastDelivery_conditional_c = 3,

	/* enums for column mefServiceEvcCfgMulticastDelivery */
	mefServiceEvcCfgMulticastDelivery_discard_c = 1,
	mefServiceEvcCfgMulticastDelivery_unconditional_c = 2,
	mefServiceEvcCfgMulticastDelivery_conditional_c = 3,

	/* enums for column mefServiceEvcCfgBroadcastDelivery */
	mefServiceEvcCfgBroadcastDelivery_discard_c = 1,
	mefServiceEvcCfgBroadcastDelivery_unconditional_c = 2,
	mefServiceEvcCfgBroadcastDelivery_conditional_c = 3,

	/* enums for column mefServiceEvcCfgAdminState */
	mefServiceEvcCfgAdminState_unknown_c = 1,
	mefServiceEvcCfgAdminState_locked_c = 2,
	mefServiceEvcCfgAdminState_shuttingDown_c = 3,
	mefServiceEvcCfgAdminState_unlocked_c = 4,

	/* enums for column mefServiceEvcCfgRowStatus */
	mefServiceEvcCfgRowStatus_active_c = 1,
	mefServiceEvcCfgRowStatus_notInService_c = 2,
	mefServiceEvcCfgRowStatus_notReady_c = 3,
	mefServiceEvcCfgRowStatus_createAndGo_c = 4,
	mefServiceEvcCfgRowStatus_createAndWait_c = 5,
	mefServiceEvcCfgRowStatus_destroy_c = 6,
};

/* table mefServiceEvcCfgTable row entry data structure */
typedef struct mefServiceEvcCfgEntry_t
{
	/* Index values */
	uint32_t u32Index;
	
	/* Column values */
	uint8_t au8Identifier[255];
	size_t u16Identifier_len;	/* # of uint8_t elements */
	int32_t i32ServiceType;
	uint32_t u32MtuSize;
	int32_t i32CeVlanIdPreservation;
	int32_t i32CeVlanCosPreservation;
	int32_t i32UnicastDelivery;
	int32_t i32MulticastDelivery;
	int32_t i32BroadcastDelivery;
	uint32_t u32L2cpGrpIndex;
	int32_t i32AdminState;
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} mefServiceEvcCfgEntry_t;

extern xBTree_t oMefServiceEvcCfgTable_BTree;

/* mefServiceEvcCfgTable table mapper */
void mefServiceEvcCfgTable_init (void);
mefServiceEvcCfgEntry_t * mefServiceEvcCfgTable_createEntry (
	uint32_t u32Index);
mefServiceEvcCfgEntry_t * mefServiceEvcCfgTable_getByIndex (
	uint32_t u32Index);
mefServiceEvcCfgEntry_t * mefServiceEvcCfgTable_getNextIndex (
	uint32_t u32Index);
void mefServiceEvcCfgTable_removeEntry (mefServiceEvcCfgEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point mefServiceEvcCfgTable_getFirst;
Netsnmp_Next_Data_Point mefServiceEvcCfgTable_getNext;
Netsnmp_Get_Data_Point mefServiceEvcCfgTable_get;
Netsnmp_Node_Handler mefServiceEvcCfgTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table mefServiceEvcUniCfgTable definitions
 */
#define MEFSERVICEEVCUNICFGTYPE 1
#define MEFSERVICEEVCUNICFGROWSTATUS 2

enum
{
	/* enums for column mefServiceEvcUniCfgType */
	mefServiceEvcUniCfgType_root_c = 1,
	mefServiceEvcUniCfgType_leaf_c = 2,
	mefServiceEvcUniCfgType_unknown_c = 3,

	/* enums for column mefServiceEvcUniCfgRowStatus */
	mefServiceEvcUniCfgRowStatus_active_c = 1,
	mefServiceEvcUniCfgRowStatus_notInService_c = 2,
	mefServiceEvcUniCfgRowStatus_notReady_c = 3,
	mefServiceEvcUniCfgRowStatus_createAndGo_c = 4,
	mefServiceEvcUniCfgRowStatus_createAndWait_c = 5,
	mefServiceEvcUniCfgRowStatus_destroy_c = 6,
};

/* table mefServiceEvcUniCfgTable row entry data structure */
typedef struct mefServiceEvcUniCfgEntry_t
{
	/* Index values */
	uint32_t u32CfgIndex;
	uint32_t u32IfIndex;
	
	/* Column values */
	int32_t i32Type;
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} mefServiceEvcUniCfgEntry_t;

extern xBTree_t oMefServiceEvcUniCfgTable_BTree;

/* mefServiceEvcUniCfgTable table mapper */
void mefServiceEvcUniCfgTable_init (void);
mefServiceEvcUniCfgEntry_t * mefServiceEvcUniCfgTable_createEntry (
	uint32_t u32CfgIndex,
	uint32_t u32IfIndex);
mefServiceEvcUniCfgEntry_t * mefServiceEvcUniCfgTable_getByIndex (
	uint32_t u32CfgIndex,
	uint32_t u32IfIndex);
mefServiceEvcUniCfgEntry_t * mefServiceEvcUniCfgTable_getNextIndex (
	uint32_t u32CfgIndex,
	uint32_t u32IfIndex);
void mefServiceEvcUniCfgTable_removeEntry (mefServiceEvcUniCfgEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point mefServiceEvcUniCfgTable_getFirst;
Netsnmp_Next_Data_Point mefServiceEvcUniCfgTable_getNext;
Netsnmp_Get_Data_Point mefServiceEvcUniCfgTable_get;
Netsnmp_Node_Handler mefServiceEvcUniCfgTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table mefServiceEvcStatusTable definitions
 */
#define MEFSERVICEEVCSTATUSMAXMTUSIZE 1
#define MEFSERVICEEVCSTATUSMAXNUMUNI 2
#define MEFSERVICEEVCSTATUSOPERATIONALSTATE 3

enum
{
	/* enums for column mefServiceEvcStatusOperationalState */
	mefServiceEvcStatusOperationalState_unknown_c = 1,
	mefServiceEvcStatusOperationalState_disabled_c = 2,
	mefServiceEvcStatusOperationalState_enabled_c = 3,
	mefServiceEvcStatusOperationalState_testing_c = 4,
};

/* table mefServiceEvcStatusTable row entry data structure */
typedef struct mefServiceEvcStatusEntry_t
{
	/* Index values */
	uint32_t u32CfgIndex;
	
	/* Column values */
	uint32_t u32MaxMtuSize;
	uint32_t u32MaxNumUni;
	int32_t i32OperationalState;
	
	xBTree_Node_t oBTreeNode;
} mefServiceEvcStatusEntry_t;

extern xBTree_t oMefServiceEvcStatusTable_BTree;

/* mefServiceEvcStatusTable table mapper */
void mefServiceEvcStatusTable_init (void);
mefServiceEvcStatusEntry_t * mefServiceEvcStatusTable_createEntry (
	uint32_t u32CfgIndex);
mefServiceEvcStatusEntry_t * mefServiceEvcStatusTable_getByIndex (
	uint32_t u32CfgIndex);
mefServiceEvcStatusEntry_t * mefServiceEvcStatusTable_getNextIndex (
	uint32_t u32CfgIndex);
void mefServiceEvcStatusTable_removeEntry (mefServiceEvcStatusEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point mefServiceEvcStatusTable_getFirst;
Netsnmp_Next_Data_Point mefServiceEvcStatusTable_getNext;
Netsnmp_Get_Data_Point mefServiceEvcStatusTable_get;
Netsnmp_Node_Handler mefServiceEvcStatusTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table mefServiceBwpGrpCfgTable definitions
 */
#define MEFSERVICEBWPGRPCFGINDEX 1
#define MEFSERVICEBWPCFGNEXTINDEX 2
#define MEFSERVICEBWPGRPCFGROWSTATUS 3

enum
{
	/* enums for column mefServiceBwpGrpCfgRowStatus */
	mefServiceBwpGrpCfgRowStatus_active_c = 1,
	mefServiceBwpGrpCfgRowStatus_notInService_c = 2,
	mefServiceBwpGrpCfgRowStatus_notReady_c = 3,
	mefServiceBwpGrpCfgRowStatus_createAndGo_c = 4,
	mefServiceBwpGrpCfgRowStatus_createAndWait_c = 5,
	mefServiceBwpGrpCfgRowStatus_destroy_c = 6,
};

/* table mefServiceBwpGrpCfgTable row entry data structure */
typedef struct mefServiceBwpGrpCfgEntry_t
{
	/* Index values */
	uint32_t u32Index;
	
	/* Column values */
	uint32_t u32CfgNextIndex;
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} mefServiceBwpGrpCfgEntry_t;

extern xBTree_t oMefServiceBwpGrpCfgTable_BTree;

/* mefServiceBwpGrpCfgTable table mapper */
void mefServiceBwpGrpCfgTable_init (void);
mefServiceBwpGrpCfgEntry_t * mefServiceBwpGrpCfgTable_createEntry (
	uint32_t u32Index);
mefServiceBwpGrpCfgEntry_t * mefServiceBwpGrpCfgTable_getByIndex (
	uint32_t u32Index);
mefServiceBwpGrpCfgEntry_t * mefServiceBwpGrpCfgTable_getNextIndex (
	uint32_t u32Index);
void mefServiceBwpGrpCfgTable_removeEntry (mefServiceBwpGrpCfgEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point mefServiceBwpGrpCfgTable_getFirst;
Netsnmp_Next_Data_Point mefServiceBwpGrpCfgTable_getNext;
Netsnmp_Get_Data_Point mefServiceBwpGrpCfgTable_get;
Netsnmp_Node_Handler mefServiceBwpGrpCfgTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table mefServiceBwpCfgTable definitions
 */
#define MEFSERVICEBWPCFGINDEX 1
#define MEFSERVICEBWPCFGIDENTIFIER 2
#define MEFSERVICEBWPCFGCIR 3
#define MEFSERVICEBWPCFGCBS 4
#define MEFSERVICEBWPCFGEIR 5
#define MEFSERVICEBWPCFGEBS 6
#define MEFSERVICEBWPCFGCM 7
#define MEFSERVICEBWPCFGCF 8
#define MEFSERVICEBWPCFGCOSINDEX 9
#define MEFSERVICEBWPCFGPERFORMANCEENABLE 10
#define MEFSERVICEBWPCFGROWSTATUS 11

enum
{
	/* enums for column mefServiceBwpCfgCm */
	mefServiceBwpCfgCm_colorBlind_c = 1,
	mefServiceBwpCfgCm_colorAware_c = 2,

	/* enums for column mefServiceBwpCfgCf */
	mefServiceBwpCfgCf_couplingYellowEirOnly_c = 0,
	mefServiceBwpCfgCf_couplingYellowEirPlusCir_c = 1,

	/* enums for column mefServiceBwpCfgPerformanceEnable */
	mefServiceBwpCfgPerformanceEnable_disablePerformanceDataSet_c = 1,
	mefServiceBwpCfgPerformanceEnable_enablePerformanceDataSet_c = 2,

	/* enums for column mefServiceBwpCfgRowStatus */
	mefServiceBwpCfgRowStatus_active_c = 1,
	mefServiceBwpCfgRowStatus_notInService_c = 2,
	mefServiceBwpCfgRowStatus_notReady_c = 3,
	mefServiceBwpCfgRowStatus_createAndGo_c = 4,
	mefServiceBwpCfgRowStatus_createAndWait_c = 5,
	mefServiceBwpCfgRowStatus_destroy_c = 6,
};

/* table mefServiceBwpCfgTable row entry data structure */
typedef struct mefServiceBwpCfgEntry_t
{
	/* Index values */
	uint32_t u32GrpCfgIndex;
	uint32_t u32Index;
	
	/* Column values */
	uint8_t au8Identifier[255];
	size_t u16Identifier_len;	/* # of uint8_t elements */
	uint32_t u32Cir;
	uint32_t u32Cbs;
	uint32_t u32Eir;
	uint32_t u32Ebs;
	int32_t i32Cm;
	int32_t i32Cf;
	uint32_t u32CosIndex;
	int32_t i32PerformanceEnable;
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} mefServiceBwpCfgEntry_t;

extern xBTree_t oMefServiceBwpCfgTable_BTree;

/* mefServiceBwpCfgTable table mapper */
void mefServiceBwpCfgTable_init (void);
mefServiceBwpCfgEntry_t * mefServiceBwpCfgTable_createEntry (
	uint32_t u32GrpCfgIndex,
	uint32_t u32Index);
mefServiceBwpCfgEntry_t * mefServiceBwpCfgTable_getByIndex (
	uint32_t u32GrpCfgIndex,
	uint32_t u32Index);
mefServiceBwpCfgEntry_t * mefServiceBwpCfgTable_getNextIndex (
	uint32_t u32GrpCfgIndex,
	uint32_t u32Index);
void mefServiceBwpCfgTable_removeEntry (mefServiceBwpCfgEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point mefServiceBwpCfgTable_getFirst;
Netsnmp_Next_Data_Point mefServiceBwpCfgTable_getNext;
Netsnmp_Get_Data_Point mefServiceBwpCfgTable_get;
Netsnmp_Node_Handler mefServiceBwpCfgTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table mefServicePerformanceTable definitions
 */
#define MEFSERVICEPERFORMANCEINGRESSGREENFRAMECOUNT 1
#define MEFSERVICEPERFORMANCEINGRESSYELLOWFRAMECOUNT 2
#define MEFSERVICEPERFORMANCEINGRESSREDFRAMECOUNT 3
#define MEFSERVICEPERFORMANCEINGRESSGREENOCTETS 4
#define MEFSERVICEPERFORMANCEINGRESSYELLOWOCTETS 5
#define MEFSERVICEPERFORMANCEINGRESSREDOCTETS 6
#define MEFSERVICEPERFORMANCEINGRESSGREENFRAMEDISCARDS 7
#define MEFSERVICEPERFORMANCEINGRESSYELLOWFRAMEDISCARDS 8
#define MEFSERVICEPERFORMANCEINGRESSGREENOCTETSDISCARDS 9
#define MEFSERVICEPERFORMANCEINGRESSYELLOWOCTETSDISCARDS 10
#define MEFSERVICEPERFORMANCEEGRESSGREENFRAMECOUNT 11
#define MEFSERVICEPERFORMANCEEGRESSYELLOWFRAMECOUNT 12
#define MEFSERVICEPERFORMANCEEGRESSGREENOCTETS 13
#define MEFSERVICEPERFORMANCEEGRESSYELLOWOCTETS 14

/* table mefServicePerformanceTable row entry data structure */
typedef struct mefServicePerformanceEntry_t
{
	/* Index values */
	uint32_t u32BwpGrpCfgIndex;
	uint32_t u32BwpCfgIndex;
	
	/* Column values */
	uint64_t u64IngressGreenFrameCount;
	uint64_t u64IngressYellowFrameCount;
	uint64_t u64IngressRedFrameCount;
	uint64_t u64IngressGreenOctets;
	uint64_t u64IngressYellowOctets;
	uint64_t u64IngressRedOctets;
	uint64_t u64IngressGreenFrameDiscards;
	uint64_t u64IngressYellowFrameDiscards;
	uint64_t u64IngressGreenOctetsDiscards;
	uint64_t u64IngressYellowOctetsDiscards;
	uint64_t u64EgressGreenFrameCount;
	uint64_t u64EgressYellowFrameCount;
	uint64_t u64EgressGreenOctets;
	uint64_t u64EgressYellowOctets;
	
	xBTree_Node_t oBTreeNode;
} mefServicePerformanceEntry_t;

extern xBTree_t oMefServicePerformanceTable_BTree;

/* mefServicePerformanceTable table mapper */
void mefServicePerformanceTable_init (void);
mefServicePerformanceEntry_t * mefServicePerformanceTable_createEntry (
	uint32_t u32BwpGrpCfgIndex,
	uint32_t u32BwpCfgIndex);
mefServicePerformanceEntry_t * mefServicePerformanceTable_getByIndex (
	uint32_t u32BwpGrpCfgIndex,
	uint32_t u32BwpCfgIndex);
mefServicePerformanceEntry_t * mefServicePerformanceTable_getNextIndex (
	uint32_t u32BwpGrpCfgIndex,
	uint32_t u32BwpCfgIndex);
void mefServicePerformanceTable_removeEntry (mefServicePerformanceEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point mefServicePerformanceTable_getFirst;
Netsnmp_Next_Data_Point mefServicePerformanceTable_getNext;
Netsnmp_Get_Data_Point mefServicePerformanceTable_get;
Netsnmp_Node_Handler mefServicePerformanceTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table mefServiceCosCfgTable definitions
 */
#define MEFSERVICECOSCFGINDEX 1
#define MEFSERVICECOSCFGIDENTIFIER 2
#define MEFSERVICECOSCFGTYPE 3
#define MEFSERVICECOSCFGIDENTIFIERLIST 4
#define MEFSERVICECOSCFGMACADDRESS 5
#define MEFSERVICECOSCFGPROTOCOL 6
#define MEFSERVICECOSCFGSUBTYPE 7
#define MEFSERVICECOSCFGROWSTATUS 8

enum
{
	/* enums for column mefServiceCosCfgType */
	mefServiceCosCfgType_interface_c = 1,
	mefServiceCosCfgType_evc_c = 2,
	mefServiceCosCfgType_pcp_c = 3,
	mefServiceCosCfgType_dscp_c = 4,
	mefServiceCosCfgType_l2cp_c = 5,

	/* enums for column mefServiceCosCfgRowStatus */
	mefServiceCosCfgRowStatus_active_c = 1,
	mefServiceCosCfgRowStatus_notInService_c = 2,
	mefServiceCosCfgRowStatus_notReady_c = 3,
	mefServiceCosCfgRowStatus_createAndGo_c = 4,
	mefServiceCosCfgRowStatus_createAndWait_c = 5,
	mefServiceCosCfgRowStatus_destroy_c = 6,
};

/* table mefServiceCosCfgTable row entry data structure */
typedef struct mefServiceCosCfgEntry_t
{
	/* Index values */
	uint32_t u32Index;
	
	/* Column values */
	uint8_t au8Identifier[255];
	size_t u16Identifier_len;	/* # of uint8_t elements */
	int32_t i32Type;
	uint8_t au8IdentifierList[255];
	size_t u16IdentifierList_len;	/* # of uint8_t elements */
	uint8_t au8MacAddress[6];
	size_t u16MacAddress_len;	/* # of uint8_t elements */
	uint32_t u32Protocol;
	uint32_t u32SubType;
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} mefServiceCosCfgEntry_t;

extern xBTree_t oMefServiceCosCfgTable_BTree;

/* mefServiceCosCfgTable table mapper */
void mefServiceCosCfgTable_init (void);
mefServiceCosCfgEntry_t * mefServiceCosCfgTable_createEntry (
	uint32_t u32Index);
mefServiceCosCfgEntry_t * mefServiceCosCfgTable_getByIndex (
	uint32_t u32Index);
mefServiceCosCfgEntry_t * mefServiceCosCfgTable_getNextIndex (
	uint32_t u32Index);
void mefServiceCosCfgTable_removeEntry (mefServiceCosCfgEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point mefServiceCosCfgTable_getFirst;
Netsnmp_Next_Data_Point mefServiceCosCfgTable_getNext;
Netsnmp_Get_Data_Point mefServiceCosCfgTable_get;
Netsnmp_Node_Handler mefServiceCosCfgTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table mefServiceL2cpGrpCfgTable definitions
 */
#define MEFSERVICEL2CPGRPCFGINDEX 1
#define MEFSERVICEL2CPCFGNEXTINDEX 2
#define MEFSERVICEL2CPGRPCFGROWSTATUS 3

enum
{
	/* enums for column mefServiceL2cpGrpCfgRowStatus */
	mefServiceL2cpGrpCfgRowStatus_active_c = 1,
	mefServiceL2cpGrpCfgRowStatus_notInService_c = 2,
	mefServiceL2cpGrpCfgRowStatus_notReady_c = 3,
	mefServiceL2cpGrpCfgRowStatus_createAndGo_c = 4,
	mefServiceL2cpGrpCfgRowStatus_createAndWait_c = 5,
	mefServiceL2cpGrpCfgRowStatus_destroy_c = 6,
};

/* table mefServiceL2cpGrpCfgTable row entry data structure */
typedef struct mefServiceL2cpGrpCfgEntry_t
{
	/* Index values */
	uint32_t u32Index;
	
	/* Column values */
	uint32_t u32CfgNextIndex;
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} mefServiceL2cpGrpCfgEntry_t;

extern xBTree_t oMefServiceL2cpGrpCfgTable_BTree;

/* mefServiceL2cpGrpCfgTable table mapper */
void mefServiceL2cpGrpCfgTable_init (void);
mefServiceL2cpGrpCfgEntry_t * mefServiceL2cpGrpCfgTable_createEntry (
	uint32_t u32Index);
mefServiceL2cpGrpCfgEntry_t * mefServiceL2cpGrpCfgTable_getByIndex (
	uint32_t u32Index);
mefServiceL2cpGrpCfgEntry_t * mefServiceL2cpGrpCfgTable_getNextIndex (
	uint32_t u32Index);
void mefServiceL2cpGrpCfgTable_removeEntry (mefServiceL2cpGrpCfgEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point mefServiceL2cpGrpCfgTable_getFirst;
Netsnmp_Next_Data_Point mefServiceL2cpGrpCfgTable_getNext;
Netsnmp_Get_Data_Point mefServiceL2cpGrpCfgTable_get;
Netsnmp_Node_Handler mefServiceL2cpGrpCfgTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table mefServiceL2cpCfgTable definitions
 */
#define MEFSERVICEL2CPCFGINDEX 1
#define MEFSERVICEL2CPCFGTYPE 2
#define MEFSERVICEL2CPCFGMATCHSCOPE 3
#define MEFSERVICEL2CPCFGMACADDRESS 4
#define MEFSERVICEL2CPCFGPROTOCOL 5
#define MEFSERVICEL2CPCFGSUBTYPE 6
#define MEFSERVICEL2CPCFGROWSTATUS 7

enum
{
	/* enums for column mefServiceL2cpCfgType */
	mefServiceL2cpCfgType_discard_c = 1,
	mefServiceL2cpCfgType_tunnel_c = 2,
	mefServiceL2cpCfgType_peer_c = 3,
	mefServiceL2cpCfgType_passToEvc_c = 4,

	/* enums for column mefServiceL2cpCfgMatchScope */
	mefServiceL2cpCfgMatchScope_destinationAddressOnly_c = 1,
	mefServiceL2cpCfgMatchScope_daPlusProtocol_c = 2,
	mefServiceL2cpCfgMatchScope_daPlusProtocolPlusSubtype_c = 3,

	/* enums for column mefServiceL2cpCfgRowStatus */
	mefServiceL2cpCfgRowStatus_active_c = 1,
	mefServiceL2cpCfgRowStatus_notInService_c = 2,
	mefServiceL2cpCfgRowStatus_notReady_c = 3,
	mefServiceL2cpCfgRowStatus_createAndGo_c = 4,
	mefServiceL2cpCfgRowStatus_createAndWait_c = 5,
	mefServiceL2cpCfgRowStatus_destroy_c = 6,
};

/* table mefServiceL2cpCfgTable row entry data structure */
typedef struct mefServiceL2cpCfgEntry_t
{
	/* Index values */
	uint32_t u32GrpCfgIndex;
	uint32_t u32Index;
	
	/* Column values */
	int32_t i32Type;
	int32_t i32MatchScope;
	uint8_t au8MacAddress[6];
	size_t u16MacAddress_len;	/* # of uint8_t elements */
	uint32_t u32Protocol;
	uint32_t u32SubType;
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} mefServiceL2cpCfgEntry_t;

extern xBTree_t oMefServiceL2cpCfgTable_BTree;

/* mefServiceL2cpCfgTable table mapper */
void mefServiceL2cpCfgTable_init (void);
mefServiceL2cpCfgEntry_t * mefServiceL2cpCfgTable_createEntry (
	uint32_t u32GrpCfgIndex,
	uint32_t u32Index);
mefServiceL2cpCfgEntry_t * mefServiceL2cpCfgTable_getByIndex (
	uint32_t u32GrpCfgIndex,
	uint32_t u32Index);
mefServiceL2cpCfgEntry_t * mefServiceL2cpCfgTable_getNextIndex (
	uint32_t u32GrpCfgIndex,
	uint32_t u32Index);
void mefServiceL2cpCfgTable_removeEntry (mefServiceL2cpCfgEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point mefServiceL2cpCfgTable_getFirst;
Netsnmp_Next_Data_Point mefServiceL2cpCfgTable_getNext;
Netsnmp_Get_Data_Point mefServiceL2cpCfgTable_get;
Netsnmp_Node_Handler mefServiceL2cpCfgTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	notification mapper(s)
 */
/* definitions for notification(s) of mefServiceNotifications */
#	define MEFSERVICECONFIGURATIONALARM 1

/* mefServiceNotifications mapper(s) */
int mefServiceConfigurationAlarm_trap (void);



#	ifdef __cplusplus
}
#	endif

#endif /* __MEFUNIEVCMIB_H__ */
