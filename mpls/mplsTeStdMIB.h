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

#ifndef __MPLSTESTDMIB_H__
#	define __MPLSTESTDMIB_H__

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
void mplsTeStdMIB_init (void);


/**
 *	scalar mapper(s)
 */
/** definitions for scalar(s) of mplsTeScalars **/
#define MPLSTUNNELCONFIGURED 1
#define MPLSTUNNELACTIVE 2
#define MPLSTUNNELTEDISTPROTO 3
#define MPLSTUNNELMAXHOPS 4
#define MPLSTUNNELNOTIFICATIONMAXRATE 5

enum
{
	/* enums for scalar mplsTunnelTEDistProto */
	mplsTunnelTEDistProto_other_c = 0,
	mplsTunnelTEDistProto_ospf_c = 1,
	mplsTunnelTEDistProto_isis_c = 2,
};

typedef struct mplsTeScalars_t
{
	uint32_t u32Configured;
	uint32_t u32Active;
	uint8_t au8TEDistProto[1];
	size_t u16TEDistProto_len;	/* # of uint8_t elements */
	uint32_t u32MaxHops;
	uint32_t u32NotificationMaxRate;
} mplsTeScalars_t;

extern mplsTeScalars_t oMplsTeScalars;

#ifdef SNMP_SRC
Netsnmp_Node_Handler mplsTeScalars_mapper;
#endif	/* SNMP_SRC */

/** definitions for scalar(s) of mplsTeObjects **/
#define MPLSTUNNELINDEXNEXT 1
#define MPLSTUNNELHOPLISTINDEXNEXT 3
#define MPLSTUNNELRESOURCEINDEXNEXT 5
#define MPLSTUNNELNOTIFICATIONENABLE 11

enum
{
	/* enums for scalar mplsTunnelNotificationEnable */
	mplsTunnelNotificationEnable_true_c = 1,
	mplsTunnelNotificationEnable_false_c = 2,
};

typedef struct mplsTeObjects_t
{
	uint32_t u32IndexNext;
	uint32_t u32HopListIndexNext;
	uint32_t u32ResourceIndexNext;
	uint8_t u8NotificationEnable;
} mplsTeObjects_t;

extern mplsTeObjects_t oMplsTeObjects;

#ifdef SNMP_SRC
Netsnmp_Node_Handler mplsTeObjects_mapper;
#endif	/* SNMP_SRC */



/**
 *	table mapper(s)
 */
/**
 *	table mplsTunnelResourceTable definitions
 */
#define MPLSTUNNELRESOURCEINDEX 1
#define MPLSTUNNELRESOURCEMAXRATE 2
#define MPLSTUNNELRESOURCEMEANRATE 3
#define MPLSTUNNELRESOURCEMAXBURSTSIZE 4
#define MPLSTUNNELRESOURCEMEANBURSTSIZE 5
#define MPLSTUNNELRESOURCEEXBURSTSIZE 6
#define MPLSTUNNELRESOURCEFREQUENCY 7
#define MPLSTUNNELRESOURCEWEIGHT 8
#define MPLSTUNNELRESOURCEROWSTATUS 9
#define MPLSTUNNELRESOURCESTORAGETYPE 10

enum
{
	/* enums for column mplsTunnelResourceFrequency */
	mplsTunnelResourceFrequency_unspecified_c = 1,
	mplsTunnelResourceFrequency_frequent_c = 2,
	mplsTunnelResourceFrequency_veryFrequent_c = 3,

	/* enums for column mplsTunnelResourceRowStatus */
	mplsTunnelResourceRowStatus_active_c = 1,
	mplsTunnelResourceRowStatus_notInService_c = 2,
	mplsTunnelResourceRowStatus_notReady_c = 3,
	mplsTunnelResourceRowStatus_createAndGo_c = 4,
	mplsTunnelResourceRowStatus_createAndWait_c = 5,
	mplsTunnelResourceRowStatus_destroy_c = 6,

	/* enums for column mplsTunnelResourceStorageType */
	mplsTunnelResourceStorageType_other_c = 1,
	mplsTunnelResourceStorageType_volatile_c = 2,
	mplsTunnelResourceStorageType_nonVolatile_c = 3,
	mplsTunnelResourceStorageType_permanent_c = 4,
	mplsTunnelResourceStorageType_readOnly_c = 5,
};

/* table mplsTunnelResourceTable row entry data structure */
typedef struct mplsTunnelResourceEntry_t
{
	/* Index values */
	uint32_t u32Index;
	
	/* Column values */
	uint32_t u32MaxRate;
	uint32_t u32MeanRate;
	uint32_t u32MaxBurstSize;
	uint32_t u32MeanBurstSize;
	uint32_t u32ExBurstSize;
	int32_t i32Frequency;
	uint32_t u32Weight;
	uint8_t u8RowStatus;
	uint8_t u8StorageType;
	
	xBTree_Node_t oBTreeNode;
} mplsTunnelResourceEntry_t;

extern xBTree_t oMplsTunnelResourceTable_BTree;

/* mplsTunnelResourceTable table mapper */
void mplsTunnelResourceTable_init (void);
mplsTunnelResourceEntry_t * mplsTunnelResourceTable_createEntry (
	uint32_t u32Index);
mplsTunnelResourceEntry_t * mplsTunnelResourceTable_getByIndex (
	uint32_t u32Index);
mplsTunnelResourceEntry_t * mplsTunnelResourceTable_getNextIndex (
	uint32_t u32Index);
void mplsTunnelResourceTable_removeEntry (mplsTunnelResourceEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point mplsTunnelResourceTable_getFirst;
Netsnmp_Next_Data_Point mplsTunnelResourceTable_getNext;
Netsnmp_Get_Data_Point mplsTunnelResourceTable_get;
Netsnmp_Node_Handler mplsTunnelResourceTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table mplsTunnelPerfTable definitions
 */
#define MPLSTUNNELPERFPACKETS 1
#define MPLSTUNNELPERFHCPACKETS 2
#define MPLSTUNNELPERFERRORS 3
#define MPLSTUNNELPERFBYTES 4
#define MPLSTUNNELPERFHCBYTES 5

/* table mplsTunnelPerfTable row entry data structure */
typedef struct mplsTunnelPerfEntry_t
{
	/* Index values */
	uint32_t u32Index;
	uint32_t u32Instance;
	uint32_t u32IngressLSRId;
	uint32_t u32EgressLSRId;
	
	/* Column values */
	uint32_t u32Packets;
	uint64_t u64HCPackets;
	uint32_t u32Errors;
	uint32_t u32Bytes;
	uint64_t u64HCBytes;
	
	xBTree_Node_t oBTreeNode;
} mplsTunnelPerfEntry_t;

extern xBTree_t oMplsTunnelPerfTable_BTree;

/* mplsTunnelPerfTable table mapper */
void mplsTunnelPerfTable_init (void);
mplsTunnelPerfEntry_t * mplsTunnelPerfTable_createEntry (
	uint32_t u32Index,
	uint32_t u32Instance,
	uint32_t u32IngressLSRId,
	uint32_t u32EgressLSRId);
mplsTunnelPerfEntry_t * mplsTunnelPerfTable_getByIndex (
	uint32_t u32Index,
	uint32_t u32Instance,
	uint32_t u32IngressLSRId,
	uint32_t u32EgressLSRId);
mplsTunnelPerfEntry_t * mplsTunnelPerfTable_getNextIndex (
	uint32_t u32Index,
	uint32_t u32Instance,
	uint32_t u32IngressLSRId,
	uint32_t u32EgressLSRId);
void mplsTunnelPerfTable_removeEntry (mplsTunnelPerfEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point mplsTunnelPerfTable_getFirst;
Netsnmp_Next_Data_Point mplsTunnelPerfTable_getNext;
Netsnmp_Get_Data_Point mplsTunnelPerfTable_get;
Netsnmp_Node_Handler mplsTunnelPerfTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table mplsTunnelCRLDPResTable definitions
 */
#define MPLSTUNNELCRLDPRESMEANBURSTSIZE 1
#define MPLSTUNNELCRLDPRESEXBURSTSIZE 2
#define MPLSTUNNELCRLDPRESFREQUENCY 3
#define MPLSTUNNELCRLDPRESWEIGHT 4
#define MPLSTUNNELCRLDPRESFLAGS 5
#define MPLSTUNNELCRLDPRESROWSTATUS 6
#define MPLSTUNNELCRLDPRESSTORAGETYPE 7

enum
{
	/* enums for column mplsTunnelCRLDPResFrequency */
	mplsTunnelCRLDPResFrequency_unspecified_c = 1,
	mplsTunnelCRLDPResFrequency_frequent_c = 2,
	mplsTunnelCRLDPResFrequency_veryFrequent_c = 3,

	/* enums for column mplsTunnelCRLDPResRowStatus */
	mplsTunnelCRLDPResRowStatus_active_c = 1,
	mplsTunnelCRLDPResRowStatus_notInService_c = 2,
	mplsTunnelCRLDPResRowStatus_notReady_c = 3,
	mplsTunnelCRLDPResRowStatus_createAndGo_c = 4,
	mplsTunnelCRLDPResRowStatus_createAndWait_c = 5,
	mplsTunnelCRLDPResRowStatus_destroy_c = 6,

	/* enums for column mplsTunnelCRLDPResStorageType */
	mplsTunnelCRLDPResStorageType_other_c = 1,
	mplsTunnelCRLDPResStorageType_volatile_c = 2,
	mplsTunnelCRLDPResStorageType_nonVolatile_c = 3,
	mplsTunnelCRLDPResStorageType_permanent_c = 4,
	mplsTunnelCRLDPResStorageType_readOnly_c = 5,
};

/* table mplsTunnelCRLDPResTable row entry data structure */
typedef struct mplsTunnelCRLDPResEntry_t
{
	/* Index values */
	uint32_t u32ResourceIndex;
	
	/* Column values */
	uint32_t u32MeanBurstSize;
	uint32_t u32ExBurstSize;
	int32_t i32Frequency;
	uint32_t u32Weight;
	uint32_t u32Flags;
	uint8_t u8RowStatus;
	uint8_t u8StorageType;
	
	xBTree_Node_t oBTreeNode;
} mplsTunnelCRLDPResEntry_t;

extern xBTree_t oMplsTunnelCRLDPResTable_BTree;

/* mplsTunnelCRLDPResTable table mapper */
void mplsTunnelCRLDPResTable_init (void);
mplsTunnelCRLDPResEntry_t * mplsTunnelCRLDPResTable_createEntry (
	uint32_t u32ResourceIndex);
mplsTunnelCRLDPResEntry_t * mplsTunnelCRLDPResTable_getByIndex (
	uint32_t u32ResourceIndex);
mplsTunnelCRLDPResEntry_t * mplsTunnelCRLDPResTable_getNextIndex (
	uint32_t u32ResourceIndex);
void mplsTunnelCRLDPResTable_removeEntry (mplsTunnelCRLDPResEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point mplsTunnelCRLDPResTable_getFirst;
Netsnmp_Next_Data_Point mplsTunnelCRLDPResTable_getNext;
Netsnmp_Get_Data_Point mplsTunnelCRLDPResTable_get;
Netsnmp_Node_Handler mplsTunnelCRLDPResTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table mplsTunnelTable definitions
 */
#define MPLSTUNNELINDEX 1
#define MPLSTUNNELINSTANCE 2
#define MPLSTUNNELINGRESSLSRID 3
#define MPLSTUNNELEGRESSLSRID 4
#define MPLSTUNNELNAME 5
#define MPLSTUNNELDESCR 6
#define MPLSTUNNELISIF 7
#define MPLSTUNNELIFINDEX 8
#define MPLSTUNNELOWNER 9
#define MPLSTUNNELROLE 10
#define MPLSTUNNELXCPOINTER 11
#define MPLSTUNNELSIGNALLINGPROTO 12
#define MPLSTUNNELSETUPPRIO 13
#define MPLSTUNNELHOLDINGPRIO 14
#define MPLSTUNNELSESSIONATTRIBUTES 15
#define MPLSTUNNELLOCALPROTECTINUSE 16
#define MPLSTUNNELRESOURCEPOINTER 17
#define MPLSTUNNELPRIMARYINSTANCE 18
#define MPLSTUNNELINSTANCEPRIORITY 19
#define MPLSTUNNELHOPTABLEINDEX 20
#define MPLSTUNNELPATHINUSE 21
#define MPLSTUNNELARHOPTABLEINDEX 22
#define MPLSTUNNELCHOPTABLEINDEX 23
#define MPLSTUNNELINCLUDEANYAFFINITY 24
#define MPLSTUNNELINCLUDEALLAFFINITY 25
#define MPLSTUNNELEXCLUDEANYAFFINITY 26
#define MPLSTUNNELTOTALUPTIME 27
#define MPLSTUNNELINSTANCEUPTIME 28
#define MPLSTUNNELPRIMARYUPTIME 29
#define MPLSTUNNELPATHCHANGES 30
#define MPLSTUNNELLASTPATHCHANGE 31
#define MPLSTUNNELCREATIONTIME 32
#define MPLSTUNNELSTATETRANSITIONS 33
#define MPLSTUNNELADMINSTATUS 34
#define MPLSTUNNELOPERSTATUS 35
#define MPLSTUNNELROWSTATUS 36
#define MPLSTUNNELSTORAGETYPE 37

enum
{
	/* enums for column mplsTunnelIsIf */
	mplsTunnelIsIf_true_c = 1,
	mplsTunnelIsIf_false_c = 2,

	/* enums for column mplsTunnelOwner */
	mplsTunnelOwner_unknown_c = 1,
	mplsTunnelOwner_other_c = 2,
	mplsTunnelOwner_snmp_c = 3,
	mplsTunnelOwner_ldp_c = 4,
	mplsTunnelOwner_crldp_c = 5,
	mplsTunnelOwner_rsvpTe_c = 6,
	mplsTunnelOwner_policyAgent_c = 7,

	/* enums for column mplsTunnelRole */
	mplsTunnelRole_head_c = 1,
	mplsTunnelRole_transit_c = 2,
	mplsTunnelRole_tail_c = 3,
	mplsTunnelRole_headTail_c = 4,

	/* enums for column mplsTunnelSignallingProto */
	mplsTunnelSignallingProto_none_c = 1,
	mplsTunnelSignallingProto_rsvp_c = 2,
	mplsTunnelSignallingProto_crldp_c = 3,
	mplsTunnelSignallingProto_other_c = 4,

	/* enums for column mplsTunnelSessionAttributes */
	mplsTunnelSessionAttributes_fastReroute_c = 0,
	mplsTunnelSessionAttributes_mergingPermitted_c = 1,
	mplsTunnelSessionAttributes_isPersistent_c = 2,
	mplsTunnelSessionAttributes_isPinned_c = 3,
	mplsTunnelSessionAttributes_recordRoute_c = 4,

	/* enums for column mplsTunnelLocalProtectInUse */
	mplsTunnelLocalProtectInUse_true_c = 1,
	mplsTunnelLocalProtectInUse_false_c = 2,

	/* enums for column mplsTunnelAdminStatus */
	mplsTunnelAdminStatus_up_c = 1,
	mplsTunnelAdminStatus_down_c = 2,
	mplsTunnelAdminStatus_testing_c = 3,

	/* enums for column mplsTunnelOperStatus */
	mplsTunnelOperStatus_up_c = 1,
	mplsTunnelOperStatus_down_c = 2,
	mplsTunnelOperStatus_testing_c = 3,
	mplsTunnelOperStatus_unknown_c = 4,
	mplsTunnelOperStatus_dormant_c = 5,
	mplsTunnelOperStatus_notPresent_c = 6,
	mplsTunnelOperStatus_lowerLayerDown_c = 7,

	/* enums for column mplsTunnelRowStatus */
	mplsTunnelRowStatus_active_c = 1,
	mplsTunnelRowStatus_notInService_c = 2,
	mplsTunnelRowStatus_notReady_c = 3,
	mplsTunnelRowStatus_createAndGo_c = 4,
	mplsTunnelRowStatus_createAndWait_c = 5,
	mplsTunnelRowStatus_destroy_c = 6,

	/* enums for column mplsTunnelStorageType */
	mplsTunnelStorageType_other_c = 1,
	mplsTunnelStorageType_volatile_c = 2,
	mplsTunnelStorageType_nonVolatile_c = 3,
	mplsTunnelStorageType_permanent_c = 4,
	mplsTunnelStorageType_readOnly_c = 5,
};

/* table mplsTunnelTable row entry data structure */
typedef struct mplsTunnelEntry_t
{
	/* Index values */
	uint32_t u32Index;
	uint32_t u32Instance;
	uint32_t u32IngressLSRId;
	uint32_t u32EgressLSRId;
	
	/* Column values */
	uint8_t au8Name[255];
	size_t u16Name_len;	/* # of uint8_t elements */
	uint8_t au8Descr[255];
	size_t u16Descr_len;	/* # of uint8_t elements */
	uint8_t u8IsIf;
	uint32_t u32IfIndex;
	int32_t i32Owner;
	int32_t i32Role;
	xOid_t aoXCPointer[128];
	size_t u16XCPointer_len;	/* # of xOid_t elements */
	int32_t i32SignallingProto;
	int32_t i32SetupPrio;
	int32_t i32HoldingPrio;
	uint8_t au8SessionAttributes[1];
	size_t u16SessionAttributes_len;	/* # of uint8_t elements */
	uint8_t u8LocalProtectInUse;
	xOid_t aoResourcePointer[128];
	size_t u16ResourcePointer_len;	/* # of xOid_t elements */
	uint32_t u32PrimaryInstance;
	uint32_t u32InstancePriority;
	uint32_t u32HopTableIndex;
	uint32_t u32PathInUse;
	uint32_t u32ARHopTableIndex;
	uint32_t u32CHopTableIndex;
	uint32_t u32IncludeAnyAffinity;
	uint32_t u32IncludeAllAffinity;
	uint32_t u32ExcludeAnyAffinity;
	uint32_t u32TotalUpTime;
	uint32_t u32InstanceUpTime;
	uint32_t u32PrimaryUpTime;
	uint32_t u32PathChanges;
	uint32_t u32LastPathChange;
	uint32_t u32CreationTime;
	uint32_t u32StateTransitions;
	int32_t i32AdminStatus;
	int32_t i32OperStatus;
	uint8_t u8RowStatus;
	uint8_t u8StorageType;
	
	xBTree_Node_t oBTreeNode;
} mplsTunnelEntry_t;

extern xBTree_t oMplsTunnelTable_BTree;

/* mplsTunnelTable table mapper */
void mplsTunnelTable_init (void);
mplsTunnelEntry_t * mplsTunnelTable_createEntry (
	uint32_t u32Index,
	uint32_t u32Instance,
	uint32_t u32IngressLSRId,
	uint32_t u32EgressLSRId);
mplsTunnelEntry_t * mplsTunnelTable_getByIndex (
	uint32_t u32Index,
	uint32_t u32Instance,
	uint32_t u32IngressLSRId,
	uint32_t u32EgressLSRId);
mplsTunnelEntry_t * mplsTunnelTable_getNextIndex (
	uint32_t u32Index,
	uint32_t u32Instance,
	uint32_t u32IngressLSRId,
	uint32_t u32EgressLSRId);
void mplsTunnelTable_removeEntry (mplsTunnelEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point mplsTunnelTable_getFirst;
Netsnmp_Next_Data_Point mplsTunnelTable_getNext;
Netsnmp_Get_Data_Point mplsTunnelTable_get;
Netsnmp_Node_Handler mplsTunnelTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table mplsTunnelHopTable definitions
 */
#define MPLSTUNNELHOPLISTINDEX 1
#define MPLSTUNNELHOPPATHOPTIONINDEX 2
#define MPLSTUNNELHOPINDEX 3
#define MPLSTUNNELHOPADDRTYPE 4
#define MPLSTUNNELHOPIPADDR 5
#define MPLSTUNNELHOPIPPREFIXLEN 6
#define MPLSTUNNELHOPASNUMBER 7
#define MPLSTUNNELHOPADDRUNNUM 8
#define MPLSTUNNELHOPLSPID 9
#define MPLSTUNNELHOPTYPE 10
#define MPLSTUNNELHOPINCLUDE 11
#define MPLSTUNNELHOPPATHOPTIONNAME 12
#define MPLSTUNNELHOPENTRYPATHCOMP 13
#define MPLSTUNNELHOPROWSTATUS 14
#define MPLSTUNNELHOPSTORAGETYPE 15

enum
{
	/* enums for column mplsTunnelHopAddrType */
	mplsTunnelHopAddrType_unknown_c = 0,
	mplsTunnelHopAddrType_ipv4_c = 1,
	mplsTunnelHopAddrType_ipv6_c = 2,
	mplsTunnelHopAddrType_asnumber_c = 3,
	mplsTunnelHopAddrType_unnum_c = 4,
	mplsTunnelHopAddrType_lspid_c = 5,

	/* enums for column mplsTunnelHopType */
	mplsTunnelHopType_strict_c = 1,
	mplsTunnelHopType_loose_c = 2,

	/* enums for column mplsTunnelHopInclude */
	mplsTunnelHopInclude_true_c = 1,
	mplsTunnelHopInclude_false_c = 2,

	/* enums for column mplsTunnelHopEntryPathComp */
	mplsTunnelHopEntryPathComp_dynamic_c = 1,
	mplsTunnelHopEntryPathComp_explicit_c = 2,

	/* enums for column mplsTunnelHopRowStatus */
	mplsTunnelHopRowStatus_active_c = 1,
	mplsTunnelHopRowStatus_notInService_c = 2,
	mplsTunnelHopRowStatus_notReady_c = 3,
	mplsTunnelHopRowStatus_createAndGo_c = 4,
	mplsTunnelHopRowStatus_createAndWait_c = 5,
	mplsTunnelHopRowStatus_destroy_c = 6,

	/* enums for column mplsTunnelHopStorageType */
	mplsTunnelHopStorageType_other_c = 1,
	mplsTunnelHopStorageType_volatile_c = 2,
	mplsTunnelHopStorageType_nonVolatile_c = 3,
	mplsTunnelHopStorageType_permanent_c = 4,
	mplsTunnelHopStorageType_readOnly_c = 5,
};

/* table mplsTunnelHopTable row entry data structure */
typedef struct mplsTunnelHopEntry_t
{
	/* Index values */
	uint32_t u32ListIndex;
	uint32_t u32PathOptionIndex;
	uint32_t u32Index;
	
	/* Column values */
	int32_t i32AddrType;
	uint8_t au8IpAddr[32];
	size_t u16IpAddr_len;	/* # of uint8_t elements */
	uint32_t u32IpPrefixLen;
	uint8_t au8AsNumber[4];
	size_t u16AsNumber_len;	/* # of uint8_t elements */
	uint8_t au8AddrUnnum[4];
	size_t u16AddrUnnum_len;	/* # of uint8_t elements */
	uint8_t au8LspId[6];
	size_t u16LspId_len;	/* # of uint8_t elements */
	int32_t i32Type;
	uint8_t u8Include;
	uint8_t au8PathOptionName[255];
	size_t u16PathOptionName_len;	/* # of uint8_t elements */
	int32_t i32EntryPathComp;
	uint8_t u8RowStatus;
	uint8_t u8StorageType;
	
	xBTree_Node_t oBTreeNode;
} mplsTunnelHopEntry_t;

extern xBTree_t oMplsTunnelHopTable_BTree;

/* mplsTunnelHopTable table mapper */
void mplsTunnelHopTable_init (void);
mplsTunnelHopEntry_t * mplsTunnelHopTable_createEntry (
	uint32_t u32ListIndex,
	uint32_t u32PathOptionIndex,
	uint32_t u32Index);
mplsTunnelHopEntry_t * mplsTunnelHopTable_getByIndex (
	uint32_t u32ListIndex,
	uint32_t u32PathOptionIndex,
	uint32_t u32Index);
mplsTunnelHopEntry_t * mplsTunnelHopTable_getNextIndex (
	uint32_t u32ListIndex,
	uint32_t u32PathOptionIndex,
	uint32_t u32Index);
void mplsTunnelHopTable_removeEntry (mplsTunnelHopEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point mplsTunnelHopTable_getFirst;
Netsnmp_Next_Data_Point mplsTunnelHopTable_getNext;
Netsnmp_Get_Data_Point mplsTunnelHopTable_get;
Netsnmp_Node_Handler mplsTunnelHopTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table mplsTunnelARHopTable definitions
 */
#define MPLSTUNNELARHOPLISTINDEX 1
#define MPLSTUNNELARHOPINDEX 2
#define MPLSTUNNELARHOPADDRTYPE 3
#define MPLSTUNNELARHOPIPADDR 4
#define MPLSTUNNELARHOPADDRUNNUM 5
#define MPLSTUNNELARHOPLSPID 6

enum
{
	/* enums for column mplsTunnelARHopAddrType */
	mplsTunnelARHopAddrType_unknown_c = 0,
	mplsTunnelARHopAddrType_ipv4_c = 1,
	mplsTunnelARHopAddrType_ipv6_c = 2,
	mplsTunnelARHopAddrType_asnumber_c = 3,
	mplsTunnelARHopAddrType_unnum_c = 4,
	mplsTunnelARHopAddrType_lspid_c = 5,
};

/* table mplsTunnelARHopTable row entry data structure */
typedef struct mplsTunnelARHopEntry_t
{
	/* Index values */
	uint32_t u32ListIndex;
	uint32_t u32Index;
	
	/* Column values */
	int32_t i32AddrType;
	uint8_t au8IpAddr[32];
	size_t u16IpAddr_len;	/* # of uint8_t elements */
	uint8_t au8AddrUnnum[4];
	size_t u16AddrUnnum_len;	/* # of uint8_t elements */
	uint8_t au8LspId[6];
	size_t u16LspId_len;	/* # of uint8_t elements */
	
	xBTree_Node_t oBTreeNode;
} mplsTunnelARHopEntry_t;

extern xBTree_t oMplsTunnelARHopTable_BTree;

/* mplsTunnelARHopTable table mapper */
void mplsTunnelARHopTable_init (void);
mplsTunnelARHopEntry_t * mplsTunnelARHopTable_createEntry (
	uint32_t u32ListIndex,
	uint32_t u32Index);
mplsTunnelARHopEntry_t * mplsTunnelARHopTable_getByIndex (
	uint32_t u32ListIndex,
	uint32_t u32Index);
mplsTunnelARHopEntry_t * mplsTunnelARHopTable_getNextIndex (
	uint32_t u32ListIndex,
	uint32_t u32Index);
void mplsTunnelARHopTable_removeEntry (mplsTunnelARHopEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point mplsTunnelARHopTable_getFirst;
Netsnmp_Next_Data_Point mplsTunnelARHopTable_getNext;
Netsnmp_Get_Data_Point mplsTunnelARHopTable_get;
Netsnmp_Node_Handler mplsTunnelARHopTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table mplsTunnelCHopTable definitions
 */
#define MPLSTUNNELCHOPLISTINDEX 1
#define MPLSTUNNELCHOPINDEX 2
#define MPLSTUNNELCHOPADDRTYPE 3
#define MPLSTUNNELCHOPIPADDR 4
#define MPLSTUNNELCHOPIPPREFIXLEN 5
#define MPLSTUNNELCHOPASNUMBER 6
#define MPLSTUNNELCHOPADDRUNNUM 7
#define MPLSTUNNELCHOPLSPID 8
#define MPLSTUNNELCHOPTYPE 9

enum
{
	/* enums for column mplsTunnelCHopAddrType */
	mplsTunnelCHopAddrType_unknown_c = 0,
	mplsTunnelCHopAddrType_ipv4_c = 1,
	mplsTunnelCHopAddrType_ipv6_c = 2,
	mplsTunnelCHopAddrType_asnumber_c = 3,
	mplsTunnelCHopAddrType_unnum_c = 4,
	mplsTunnelCHopAddrType_lspid_c = 5,

	/* enums for column mplsTunnelCHopType */
	mplsTunnelCHopType_strict_c = 1,
	mplsTunnelCHopType_loose_c = 2,
};

/* table mplsTunnelCHopTable row entry data structure */
typedef struct mplsTunnelCHopEntry_t
{
	/* Index values */
	uint32_t u32ListIndex;
	uint32_t u32Index;
	
	/* Column values */
	int32_t i32AddrType;
	uint8_t au8IpAddr[32];
	size_t u16IpAddr_len;	/* # of uint8_t elements */
	uint32_t u32IpPrefixLen;
	uint8_t au8AsNumber[4];
	size_t u16AsNumber_len;	/* # of uint8_t elements */
	uint8_t au8AddrUnnum[4];
	size_t u16AddrUnnum_len;	/* # of uint8_t elements */
	uint8_t au8LspId[6];
	size_t u16LspId_len;	/* # of uint8_t elements */
	int32_t i32Type;
	
	xBTree_Node_t oBTreeNode;
} mplsTunnelCHopEntry_t;

extern xBTree_t oMplsTunnelCHopTable_BTree;

/* mplsTunnelCHopTable table mapper */
void mplsTunnelCHopTable_init (void);
mplsTunnelCHopEntry_t * mplsTunnelCHopTable_createEntry (
	uint32_t u32ListIndex,
	uint32_t u32Index);
mplsTunnelCHopEntry_t * mplsTunnelCHopTable_getByIndex (
	uint32_t u32ListIndex,
	uint32_t u32Index);
mplsTunnelCHopEntry_t * mplsTunnelCHopTable_getNextIndex (
	uint32_t u32ListIndex,
	uint32_t u32Index);
void mplsTunnelCHopTable_removeEntry (mplsTunnelCHopEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point mplsTunnelCHopTable_getFirst;
Netsnmp_Next_Data_Point mplsTunnelCHopTable_getNext;
Netsnmp_Get_Data_Point mplsTunnelCHopTable_get;
Netsnmp_Node_Handler mplsTunnelCHopTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	notification mapper(s)
 */
/* definitions for notification(s) of mplsTeNotifications */
#	define MPLSTUNNELUP 1
#	define MPLSTUNNELDOWN 2
#	define MPLSTUNNELREROUTED 3
#	define MPLSTUNNELREOPTIMIZED 4

/* mplsTeNotifications mapper(s) */
int mplsTunnelUp_trap (void);
int mplsTunnelDown_trap (void);
int mplsTunnelRerouted_trap (void);
int mplsTunnelReoptimized_trap (void);



#	ifdef __cplusplus
}
#	endif

#endif /* __MPLSTESTDMIB_H__ */
