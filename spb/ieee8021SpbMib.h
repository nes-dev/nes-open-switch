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

#ifndef __IEEE8021SPBMIB_H__
#	define __IEEE8021SPBMIB_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include "lib/binaryTree.h"
#include "lib/snmp.h"

#define TOBE_REPLACED 1


/**
 *	agent MIB function
 */
void ieee8021SpbMib_init (void);


/**
 *	scalar mapper(s)
 */
/** definitions for scalar(s) of ieee8021SpbSys **/
#define IEEE8021SPBSYSAREAADDRESS 1
#define IEEE8021SPBSYSID 2
#define IEEE8021SPBSYSCONTROLADDR 3
#define IEEE8021SPBSYSNAME 4
#define IEEE8021SPBSYSBRIDGEPRIORITY 5
#define IEEE8021SPBMSYSSPSOURCEID 6
#define IEEE8021SPBVSYSMODE 7
#define IEEE8021SPBMSYSMODE 8
#define IEEE8021SPBSYSDIGESTCONVENTION 9

enum
{
	/* enums for scalar ieee8021SpbvSysMode */
	ieee8021SpbvSysMode_auto_c = 1,
	ieee8021SpbvSysMode_manual_c = 2,

	/* enums for scalar ieee8021SpbmSysMode */
	ieee8021SpbmSysMode_auto_c = 1,
	ieee8021SpbmSysMode_manual_c = 2,

	/* enums for scalar ieee8021SpbSysDigestConvention */
	ieee8021SpbSysDigestConvention_off_c = 1,
	ieee8021SpbSysDigestConvention_loopFreeBoth_c = 2,
	ieee8021SpbSysDigestConvention_loopFreeMcastOnly_c = 3,
};

typedef struct ieee8021SpbSys_t
{
	uint8_t au8AreaAddress[3];
	size_t u16AreaAddress_len;	/* # of uint8_t elements */
	uint8_t au8Id[6];
	size_t u16Id_len;	/* # of uint8_t elements */
	uint8_t au8ControlAddr[6];
	size_t u16ControlAddr_len;	/* # of uint8_t elements */
	uint8_t au8Name[32];
	size_t u16Name_len;	/* # of uint8_t elements */
	uint8_t au8BridgePriority[2];
	size_t u16BridgePriority_len;	/* # of uint8_t elements */
	uint8_t au8SpbmSysSPSourceId[3];
	size_t u16SpbmSysSPSourceId_len;	/* # of uint8_t elements */
	int32_t i32SpbvSysMode;
	int32_t i32SpbmSysMode;
	int32_t i32DigestConvention;
} ieee8021SpbSys_t;

extern ieee8021SpbSys_t oIeee8021SpbSys;

#ifdef SNMP_SRC
Netsnmp_Node_Handler ieee8021SpbSys_mapper;
#endif	/* SNMP_SRC */



/**
 *	table mapper(s)
 */
/**
 *	table ieee8021SpbMtidStaticTable definitions
 */
#define IEEE8021SPBMTIDSTATICENTRYMTID 1
#define IEEE8021SPBMTIDSTATICENTRYMTIDOVERLOAD 2
#define IEEE8021SPBMTIDSTATICENTRYROWSTATUS 3
#define IEEE8021SPBTOPIX 4

enum
{
	/* enums for column ieee8021SpbMTidStaticEntryMtidOverload */
	ieee8021SpbMTidStaticEntryMtidOverload_true_c = 1,
	ieee8021SpbMTidStaticEntryMtidOverload_false_c = 2,

	/* enums for column ieee8021SpbMtidStaticEntryRowStatus */
	ieee8021SpbMtidStaticEntryRowStatus_active_c = 1,
	ieee8021SpbMtidStaticEntryRowStatus_notInService_c = 2,
	ieee8021SpbMtidStaticEntryRowStatus_notReady_c = 3,
	ieee8021SpbMtidStaticEntryRowStatus_createAndGo_c = 4,
	ieee8021SpbMtidStaticEntryRowStatus_createAndWait_c = 5,
	ieee8021SpbMtidStaticEntryRowStatus_destroy_c = 6,
};

/* table ieee8021SpbMtidStaticTable row entry data structure */
typedef struct ieee8021SpbMtidStaticEntry_t
{
	/* Index values */
	uint32_t u32EntryMtid;
	uint32_t u32TopIx;
	
	/* Column values */
	int32_t i32MTidStaticEntryMtidOverload;
	uint8_t u8EntryRowStatus;
	
	xBTree_Node_t oBTreeNode;
} ieee8021SpbMtidStaticEntry_t;

extern xBTree_t oIeee8021SpbMtidStaticTable_BTree;

/* ieee8021SpbMtidStaticTable table mapper */
void ieee8021SpbMtidStaticTable_init (void);
ieee8021SpbMtidStaticEntry_t * ieee8021SpbMtidStaticTable_createEntry (
	uint32_t u32EntryMtid,
	uint32_t u32TopIx);
ieee8021SpbMtidStaticEntry_t * ieee8021SpbMtidStaticTable_getByIndex (
	uint32_t u32EntryMtid,
	uint32_t u32TopIx);
ieee8021SpbMtidStaticEntry_t * ieee8021SpbMtidStaticTable_getNextIndex (
	uint32_t u32EntryMtid,
	uint32_t u32TopIx);
void ieee8021SpbMtidStaticTable_removeEntry (ieee8021SpbMtidStaticEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021SpbMtidStaticTable_getFirst;
Netsnmp_Next_Data_Point ieee8021SpbMtidStaticTable_getNext;
Netsnmp_Get_Data_Point ieee8021SpbMtidStaticTable_get;
Netsnmp_Node_Handler ieee8021SpbMtidStaticTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021SpbTopIxDynamicTable definitions
 */
#define IEEE8021SPBTOPIXDYNAMICENTRYTOPIX 1
#define IEEE8021SPBTOPIXDYNAMICENTRYAGREEDIGEST 2
#define IEEE8021SPBTOPIXDYNAMICENTRYMCID 3
#define IEEE8021SPBTOPIXDYNAMICENTRYAUXMCID 4

/* table ieee8021SpbTopIxDynamicTable row entry data structure */
typedef struct ieee8021SpbTopIxDynamicEntry_t
{
	/* Index values */
	uint32_t u32EntryTopIx;
	
	/* Column values */
	uint8_t au8EntryAgreeDigest[32];
	size_t u16EntryAgreeDigest_len;	/* # of uint8_t elements */
	uint8_t au8EntryMCID[51];
	size_t u16EntryMCID_len;	/* # of uint8_t elements */
	uint8_t au8EntryAuxMCID[51];
	size_t u16EntryAuxMCID_len;	/* # of uint8_t elements */
	
	xBTree_Node_t oBTreeNode;
} ieee8021SpbTopIxDynamicEntry_t;

extern xBTree_t oIeee8021SpbTopIxDynamicTable_BTree;

/* ieee8021SpbTopIxDynamicTable table mapper */
void ieee8021SpbTopIxDynamicTable_init (void);
ieee8021SpbTopIxDynamicEntry_t * ieee8021SpbTopIxDynamicTable_createEntry (
	uint32_t u32EntryTopIx);
ieee8021SpbTopIxDynamicEntry_t * ieee8021SpbTopIxDynamicTable_getByIndex (
	uint32_t u32EntryTopIx);
ieee8021SpbTopIxDynamicEntry_t * ieee8021SpbTopIxDynamicTable_getNextIndex (
	uint32_t u32EntryTopIx);
void ieee8021SpbTopIxDynamicTable_removeEntry (ieee8021SpbTopIxDynamicEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021SpbTopIxDynamicTable_getFirst;
Netsnmp_Next_Data_Point ieee8021SpbTopIxDynamicTable_getNext;
Netsnmp_Get_Data_Point ieee8021SpbTopIxDynamicTable_get;
Netsnmp_Node_Handler ieee8021SpbTopIxDynamicTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021SpbEctStaticTable definitions
 */
#define IEEE8021SPBECTSTATICENTRYTOPIX 1
#define IEEE8021SPBECTSTATICENTRYBASEVID 2
#define IEEE8021SPBECTSTATICENTRYECTALGORITHM 3
#define IEEE8021SPBVECTSTATICENTRYSPVID 4
#define IEEE8021SPBECTSTATICENTRYROWSTATUS 5

enum
{
	/* enums for column ieee8021SpbEctStaticEntryRowStatus */
	ieee8021SpbEctStaticEntryRowStatus_active_c = 1,
	ieee8021SpbEctStaticEntryRowStatus_notInService_c = 2,
	ieee8021SpbEctStaticEntryRowStatus_notReady_c = 3,
	ieee8021SpbEctStaticEntryRowStatus_createAndGo_c = 4,
	ieee8021SpbEctStaticEntryRowStatus_createAndWait_c = 5,
	ieee8021SpbEctStaticEntryRowStatus_destroy_c = 6,
};

/* table ieee8021SpbEctStaticTable row entry data structure */
typedef struct ieee8021SpbEctStaticEntry_t
{
	/* Index values */
	uint32_t u32EntryTopIx;
	int32_t i32EntryBaseVid;
	
	/* Column values */
	uint8_t au8EntryEctAlgorithm[4];
	size_t u16EntryEctAlgorithm_len;	/* # of uint8_t elements */
	int32_t i32SpbvEctStaticEntrySpvid;
	uint8_t u8EntryRowStatus;
	
	xBTree_Node_t oBTreeNode;
} ieee8021SpbEctStaticEntry_t;

extern xBTree_t oIeee8021SpbEctStaticTable_BTree;

/* ieee8021SpbEctStaticTable table mapper */
void ieee8021SpbEctStaticTable_init (void);
ieee8021SpbEctStaticEntry_t * ieee8021SpbEctStaticTable_createEntry (
	uint32_t u32EntryTopIx,
	int32_t i32EntryBaseVid);
ieee8021SpbEctStaticEntry_t * ieee8021SpbEctStaticTable_getByIndex (
	uint32_t u32EntryTopIx,
	int32_t i32EntryBaseVid);
ieee8021SpbEctStaticEntry_t * ieee8021SpbEctStaticTable_getNextIndex (
	uint32_t u32EntryTopIx,
	int32_t i32EntryBaseVid);
void ieee8021SpbEctStaticTable_removeEntry (ieee8021SpbEctStaticEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021SpbEctStaticTable_getFirst;
Netsnmp_Next_Data_Point ieee8021SpbEctStaticTable_getNext;
Netsnmp_Get_Data_Point ieee8021SpbEctStaticTable_get;
Netsnmp_Node_Handler ieee8021SpbEctStaticTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021SpbEctDynamicTable definitions
 */
#define IEEE8021SPBECTDYNAMICENTRYTOPIX 1
#define IEEE8021SPBECTDYNAMICENTRYBASEVID 2
#define IEEE8021SPBECTDYNAMICENTRYMODE 3
#define IEEE8021SPBECTDYNAMICENTRYLOCALUSE 4
#define IEEE8021SPBECTDYNAMICENTRYREMOTEUSE 5
#define IEEE8021SPBECTDYNAMICENTRYINGRESSCHECKDISCARDS 6

enum
{
	/* enums for column ieee8021SpbEctDynamicEntryMode */
	ieee8021SpbEctDynamicEntryMode_disabled_c = 1,
	ieee8021SpbEctDynamicEntryMode_spbm_c = 2,
	ieee8021SpbEctDynamicEntryMode_spbv_c = 3,

	/* enums for column ieee8021SpbEctDynamicEntryLocalUse */
	ieee8021SpbEctDynamicEntryLocalUse_true_c = 1,
	ieee8021SpbEctDynamicEntryLocalUse_false_c = 2,

	/* enums for column ieee8021SpbEctDynamicEntryRemoteUse */
	ieee8021SpbEctDynamicEntryRemoteUse_true_c = 1,
	ieee8021SpbEctDynamicEntryRemoteUse_false_c = 2,
};

/* table ieee8021SpbEctDynamicTable row entry data structure */
typedef struct ieee8021SpbEctDynamicEntry_t
{
	/* Index values */
	uint32_t u32EntryTopIx;
	int32_t i32EntryBaseVid;
	
	/* Column values */
	int32_t i32EntryMode;
	int32_t i32EntryLocalUse;
	int32_t i32EntryRemoteUse;
	uint32_t u32EntryIngressCheckDiscards;
	
	xBTree_Node_t oBTreeNode;
} ieee8021SpbEctDynamicEntry_t;

extern xBTree_t oIeee8021SpbEctDynamicTable_BTree;

/* ieee8021SpbEctDynamicTable table mapper */
void ieee8021SpbEctDynamicTable_init (void);
ieee8021SpbEctDynamicEntry_t * ieee8021SpbEctDynamicTable_createEntry (
	uint32_t u32EntryTopIx,
	int32_t i32EntryBaseVid);
ieee8021SpbEctDynamicEntry_t * ieee8021SpbEctDynamicTable_getByIndex (
	uint32_t u32EntryTopIx,
	int32_t i32EntryBaseVid);
ieee8021SpbEctDynamicEntry_t * ieee8021SpbEctDynamicTable_getNextIndex (
	uint32_t u32EntryTopIx,
	int32_t i32EntryBaseVid);
void ieee8021SpbEctDynamicTable_removeEntry (ieee8021SpbEctDynamicEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021SpbEctDynamicTable_getFirst;
Netsnmp_Next_Data_Point ieee8021SpbEctDynamicTable_getNext;
Netsnmp_Get_Data_Point ieee8021SpbEctDynamicTable_get;
Netsnmp_Node_Handler ieee8021SpbEctDynamicTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021SpbAdjStaticTable definitions
 */
#define IEEE8021SPBADJSTATICENTRYTOPIX 1
#define IEEE8021SPBADJSTATICENTRYIFINDEX 2
#define IEEE8021SPBADJSTATICENTRYMETRIC 3
#define IEEE8021SPBADJSTATICENTRYIFADMINSTATE 4
#define IEEE8021SPBADJSTATICENTRYROWSTATUS 5

enum
{
	/* enums for column ieee8021SpbAdjStaticEntryIfAdminState */
	ieee8021SpbAdjStaticEntryIfAdminState_up_c = 1,
	ieee8021SpbAdjStaticEntryIfAdminState_down_c = 2,
	ieee8021SpbAdjStaticEntryIfAdminState_testing_c = 3,

	/* enums for column ieee8021SpbAdjStaticEntryRowStatus */
	ieee8021SpbAdjStaticEntryRowStatus_active_c = 1,
	ieee8021SpbAdjStaticEntryRowStatus_notInService_c = 2,
	ieee8021SpbAdjStaticEntryRowStatus_notReady_c = 3,
	ieee8021SpbAdjStaticEntryRowStatus_createAndGo_c = 4,
	ieee8021SpbAdjStaticEntryRowStatus_createAndWait_c = 5,
	ieee8021SpbAdjStaticEntryRowStatus_destroy_c = 6,
};

/* table ieee8021SpbAdjStaticTable row entry data structure */
typedef struct ieee8021SpbAdjStaticEntry_t
{
	/* Index values */
	uint32_t u32EntryTopIx;
	uint32_t u32EntryIfIndex;
	
	/* Column values */
	int32_t i32EntryMetric;
	int32_t i32EntryIfAdminState;
	uint8_t u8EntryRowStatus;
	
	xBTree_Node_t oBTreeNode;
} ieee8021SpbAdjStaticEntry_t;

extern xBTree_t oIeee8021SpbAdjStaticTable_BTree;

/* ieee8021SpbAdjStaticTable table mapper */
void ieee8021SpbAdjStaticTable_init (void);
ieee8021SpbAdjStaticEntry_t * ieee8021SpbAdjStaticTable_createEntry (
	uint32_t u32EntryTopIx,
	uint32_t u32EntryIfIndex);
ieee8021SpbAdjStaticEntry_t * ieee8021SpbAdjStaticTable_getByIndex (
	uint32_t u32EntryTopIx,
	uint32_t u32EntryIfIndex);
ieee8021SpbAdjStaticEntry_t * ieee8021SpbAdjStaticTable_getNextIndex (
	uint32_t u32EntryTopIx,
	uint32_t u32EntryIfIndex);
void ieee8021SpbAdjStaticTable_removeEntry (ieee8021SpbAdjStaticEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021SpbAdjStaticTable_getFirst;
Netsnmp_Next_Data_Point ieee8021SpbAdjStaticTable_getNext;
Netsnmp_Get_Data_Point ieee8021SpbAdjStaticTable_get;
Netsnmp_Node_Handler ieee8021SpbAdjStaticTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021SpbAdjDynamicTable definitions
 */
#define IEEE8021SPBADJDYNAMICENTRYTOPIX 1
#define IEEE8021SPBADJDYNAMICENTRYIFINDEX 2
#define IEEE8021SPBADJDYNAMICENTRYPEERSYSID 3
#define IEEE8021SPBADJDYNAMICENTRYPORT 4
#define IEEE8021SPBADJDYNAMICENTRYIFOPERSTATE 5
#define IEEE8021SPBADJDYNAMICENTRYPEERSYSNAME 6
#define IEEE8021SPBADJDYNAMICENTRYPEERAGREEDIGEST 7
#define IEEE8021SPBADJDYNAMICENTRYPEERMCID 8
#define IEEE8021SPBADJDYNAMICENTRYPEERAUXMCID 9
#define IEEE8021SPBADJDYNAMICENTRYLOCALCIRCUITID 10
#define IEEE8021SPBADJDYNAMICENTRYPEERLOCALCIRCUITID 11
#define IEEE8021SPBADJDYNAMICENTRYPORTIDENTIFIER 12
#define IEEE8021SPBADJDYNAMICENTRYPEERPORTIDENTIFIER 13
#define IEEE8021SPBADJDYNAMICENTRYISISCIRCINDEX 14

enum
{
	/* enums for column ieee8021SpbAdjDynamicEntryIfOperState */
	ieee8021SpbAdjDynamicEntryIfOperState_up_c = 1,
	ieee8021SpbAdjDynamicEntryIfOperState_down_c = 2,
	ieee8021SpbAdjDynamicEntryIfOperState_testing_c = 3,
};

/* table ieee8021SpbAdjDynamicTable row entry data structure */
typedef struct ieee8021SpbAdjDynamicEntry_t
{
	/* Index values */
	uint32_t u32EntryTopIx;
	uint32_t u32EntryIfIndex;
	uint8_t au8EntryPeerSysId[6];
	size_t u16EntryPeerSysId_len;	/* # of uint8_t elements */
	
	/* Column values */
	uint32_t u32EntryPort;
	int32_t i32EntryIfOperState;
	uint8_t au8EntryPeerSysName[32];
	size_t u16EntryPeerSysName_len;	/* # of uint8_t elements */
	uint8_t au8EntryPeerAgreeDigest[32];
	size_t u16EntryPeerAgreeDigest_len;	/* # of uint8_t elements */
	uint8_t au8EntryPeerMCID[51];
	size_t u16EntryPeerMCID_len;	/* # of uint8_t elements */
	uint8_t au8EntryPeerAuxMCID[51];
	size_t u16EntryPeerAuxMCID_len;	/* # of uint8_t elements */
	uint32_t u32EntryLocalCircuitID;
	uint32_t u32EntryPeerLocalCircuitID;
	uint32_t u32EntryPortIdentifier;
	uint32_t u32EntryPeerPortIdentifier;
	uint32_t u32EntryIsisCircIndex;
	
	xBTree_Node_t oBTreeNode;
} ieee8021SpbAdjDynamicEntry_t;

extern xBTree_t oIeee8021SpbAdjDynamicTable_BTree;

/* ieee8021SpbAdjDynamicTable table mapper */
void ieee8021SpbAdjDynamicTable_init (void);
ieee8021SpbAdjDynamicEntry_t * ieee8021SpbAdjDynamicTable_createEntry (
	uint32_t u32EntryTopIx,
	uint32_t u32EntryIfIndex,
	uint8_t *pau8EntryPeerSysId, size_t u16EntryPeerSysId_len);
ieee8021SpbAdjDynamicEntry_t * ieee8021SpbAdjDynamicTable_getByIndex (
	uint32_t u32EntryTopIx,
	uint32_t u32EntryIfIndex,
	uint8_t *pau8EntryPeerSysId, size_t u16EntryPeerSysId_len);
ieee8021SpbAdjDynamicEntry_t * ieee8021SpbAdjDynamicTable_getNextIndex (
	uint32_t u32EntryTopIx,
	uint32_t u32EntryIfIndex,
	uint8_t *pau8EntryPeerSysId, size_t u16EntryPeerSysId_len);
void ieee8021SpbAdjDynamicTable_removeEntry (ieee8021SpbAdjDynamicEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021SpbAdjDynamicTable_getFirst;
Netsnmp_Next_Data_Point ieee8021SpbAdjDynamicTable_getNext;
Netsnmp_Get_Data_Point ieee8021SpbAdjDynamicTable_get;
Netsnmp_Node_Handler ieee8021SpbAdjDynamicTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021SpbTopNodeTable definitions
 */
#define IEEE8021SPBTOPNODEENTRYTOPIX 1
#define IEEE8021SPBTOPNODEENTRYSYSID 2
#define IEEE8021SPBTOPNODEENTRYBRIDGEPRIORITY 3
#define IEEE8021SPBMTOPNODEENTRYSPSOURCEID 4
#define IEEE8021SPBTOPNODEENTRYSYSNAME 5

/* table ieee8021SpbTopNodeTable row entry data structure */
typedef struct ieee8021SpbTopNodeEntry_t
{
	/* Index values */
	uint32_t u32EntryTopIx;
	uint8_t au8EntrySysId[6];
	size_t u16EntrySysId_len;	/* # of uint8_t elements */
	
	/* Column values */
	uint8_t au8EntryBridgePriority[2];
	size_t u16EntryBridgePriority_len;	/* # of uint8_t elements */
	uint8_t au8SpbmTopNodeEntrySPsourceID[3];
	size_t u16SpbmTopNodeEntrySPsourceID_len;	/* # of uint8_t elements */
	uint8_t au8EntrySysName[32];
	size_t u16EntrySysName_len;	/* # of uint8_t elements */
	
	xBTree_Node_t oBTreeNode;
} ieee8021SpbTopNodeEntry_t;

extern xBTree_t oIeee8021SpbTopNodeTable_BTree;

/* ieee8021SpbTopNodeTable table mapper */
void ieee8021SpbTopNodeTable_init (void);
ieee8021SpbTopNodeEntry_t * ieee8021SpbTopNodeTable_createEntry (
	uint32_t u32EntryTopIx,
	uint8_t *pau8EntrySysId, size_t u16EntrySysId_len);
ieee8021SpbTopNodeEntry_t * ieee8021SpbTopNodeTable_getByIndex (
	uint32_t u32EntryTopIx,
	uint8_t *pau8EntrySysId, size_t u16EntrySysId_len);
ieee8021SpbTopNodeEntry_t * ieee8021SpbTopNodeTable_getNextIndex (
	uint32_t u32EntryTopIx,
	uint8_t *pau8EntrySysId, size_t u16EntrySysId_len);
void ieee8021SpbTopNodeTable_removeEntry (ieee8021SpbTopNodeEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021SpbTopNodeTable_getFirst;
Netsnmp_Next_Data_Point ieee8021SpbTopNodeTable_getNext;
Netsnmp_Get_Data_Point ieee8021SpbTopNodeTable_get;
Netsnmp_Node_Handler ieee8021SpbTopNodeTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021SpbTopEctTable definitions
 */
#define IEEE8021SPBTOPECTENTRYTOPIX 1
#define IEEE8021SPBTOPECTENTRYSYSID 2
#define IEEE8021SPBTOPECTENTRYBASEVID 3
#define IEEE8021SPBTOPECTENTRYECTALGORITHM 4
#define IEEE8021SPBTOPECTENTRYMODE 5
#define IEEE8021SPBVTOPECTSYSMODE 6
#define IEEE8021SPBVTOPECTENTRYSPVID 7
#define IEEE8021SPBTOPECTENTRYLOCALUSE 8

enum
{
	/* enums for column ieee8021SpbTopEctEntryMode */
	ieee8021SpbTopEctEntryMode_disabled_c = 1,
	ieee8021SpbTopEctEntryMode_spbm_c = 2,
	ieee8021SpbTopEctEntryMode_spbv_c = 3,

	/* enums for column ieee8021SpbvTopEctSysMode */
	ieee8021SpbvTopEctSysMode_auto_c = 1,
	ieee8021SpbvTopEctSysMode_manual_c = 2,

	/* enums for column ieee8021SpbTopEctEntryLocalUse */
	ieee8021SpbTopEctEntryLocalUse_true_c = 1,
	ieee8021SpbTopEctEntryLocalUse_false_c = 2,
};

/* table ieee8021SpbTopEctTable row entry data structure */
typedef struct ieee8021SpbTopEctEntry_t
{
	/* Index values */
	uint32_t u32EntryTopIx;
	uint8_t au8EntrySysId[6];
	size_t u16EntrySysId_len;	/* # of uint8_t elements */
	int32_t i32EntryBaseVid;
	
	/* Column values */
	uint8_t au8EntryEctAlgorithm[4];
	size_t u16EntryEctAlgorithm_len;	/* # of uint8_t elements */
	int32_t i32EntryMode;
	int32_t i32SpbvTopEctSysMode;
	int32_t i32SpbvTopEctEntrySpvid;
	int32_t i32EntryLocalUse;
	
	xBTree_Node_t oBTreeNode;
} ieee8021SpbTopEctEntry_t;

extern xBTree_t oIeee8021SpbTopEctTable_BTree;

/* ieee8021SpbTopEctTable table mapper */
void ieee8021SpbTopEctTable_init (void);
ieee8021SpbTopEctEntry_t * ieee8021SpbTopEctTable_createEntry (
	uint32_t u32EntryTopIx,
	uint8_t *pau8EntrySysId, size_t u16EntrySysId_len,
	int32_t i32EntryBaseVid);
ieee8021SpbTopEctEntry_t * ieee8021SpbTopEctTable_getByIndex (
	uint32_t u32EntryTopIx,
	uint8_t *pau8EntrySysId, size_t u16EntrySysId_len,
	int32_t i32EntryBaseVid);
ieee8021SpbTopEctEntry_t * ieee8021SpbTopEctTable_getNextIndex (
	uint32_t u32EntryTopIx,
	uint8_t *pau8EntrySysId, size_t u16EntrySysId_len,
	int32_t i32EntryBaseVid);
void ieee8021SpbTopEctTable_removeEntry (ieee8021SpbTopEctEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021SpbTopEctTable_getFirst;
Netsnmp_Next_Data_Point ieee8021SpbTopEctTable_getNext;
Netsnmp_Get_Data_Point ieee8021SpbTopEctTable_get;
Netsnmp_Node_Handler ieee8021SpbTopEctTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021SpbTopEdgeTable definitions
 */
#define IEEE8021SPBTOPEDGEENTRYTOPIX 1
#define IEEE8021SPBTOPEDGEENTRYSYSIDNEAR 2
#define IEEE8021SPBTOPEDGEENTRYSYSIDFAR 3
#define IEEE8021SPBTOPEDGEENTRYMETRICNEAR2FAR 4
#define IEEE8021SPBTOPEDGEENTRYMETRICFAR2NEAR 5

/* table ieee8021SpbTopEdgeTable row entry data structure */
typedef struct ieee8021SpbTopEdgeEntry_t
{
	/* Index values */
	uint32_t u32EntryTopIx;
	uint8_t au8EntrySysIdNear[6];
	size_t u16EntrySysIdNear_len;	/* # of uint8_t elements */
	uint8_t au8EntrySysIdFar[6];
	size_t u16EntrySysIdFar_len;	/* # of uint8_t elements */
	
	/* Column values */
	int32_t i32EntryMetricNear2Far;
	int32_t i32EntryMetricFar2Near;
	
	xBTree_Node_t oBTreeNode;
} ieee8021SpbTopEdgeEntry_t;

extern xBTree_t oIeee8021SpbTopEdgeTable_BTree;

/* ieee8021SpbTopEdgeTable table mapper */
void ieee8021SpbTopEdgeTable_init (void);
ieee8021SpbTopEdgeEntry_t * ieee8021SpbTopEdgeTable_createEntry (
	uint32_t u32EntryTopIx,
	uint8_t *pau8EntrySysIdNear, size_t u16EntrySysIdNear_len,
	uint8_t *pau8EntrySysIdFar, size_t u16EntrySysIdFar_len);
ieee8021SpbTopEdgeEntry_t * ieee8021SpbTopEdgeTable_getByIndex (
	uint32_t u32EntryTopIx,
	uint8_t *pau8EntrySysIdNear, size_t u16EntrySysIdNear_len,
	uint8_t *pau8EntrySysIdFar, size_t u16EntrySysIdFar_len);
ieee8021SpbTopEdgeEntry_t * ieee8021SpbTopEdgeTable_getNextIndex (
	uint32_t u32EntryTopIx,
	uint8_t *pau8EntrySysIdNear, size_t u16EntrySysIdNear_len,
	uint8_t *pau8EntrySysIdFar, size_t u16EntrySysIdFar_len);
void ieee8021SpbTopEdgeTable_removeEntry (ieee8021SpbTopEdgeEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021SpbTopEdgeTable_getFirst;
Netsnmp_Next_Data_Point ieee8021SpbTopEdgeTable_getNext;
Netsnmp_Get_Data_Point ieee8021SpbTopEdgeTable_get;
Netsnmp_Node_Handler ieee8021SpbTopEdgeTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021SpbmTopSrvTable definitions
 */
#define IEEE8021SPBMTOPSRVENTRYTOPIX 1
#define IEEE8021SPBMTOPSRVENTRYSYSID 2
#define IEEE8021SPBMTOPSRVENTRYISID 3
#define IEEE8021SPBMTOPSRVENTRYBASEVID 4
#define IEEE8021SPBMTOPSRVENTRYMAC 5
#define IEEE8021SPBMTOPSRVENTRYISIDFLAGS 6

enum
{
	/* enums for column ieee8021SpbmTopSrvEntryIsidFlags */
	ieee8021SpbmTopSrvEntryIsidFlags_ingress_c = 0,
	ieee8021SpbmTopSrvEntryIsidFlags_egress_c = 1,
};

/* table ieee8021SpbmTopSrvTable row entry data structure */
typedef struct ieee8021SpbmTopSrvEntry_t
{
	/* Index values */
	uint32_t u32EntryTopIx;
	uint8_t au8EntrySysId[6];
	size_t u16EntrySysId_len;	/* # of uint8_t elements */
	uint32_t u32EntryIsid;
	int32_t i32EntryBaseVid;
	uint8_t au8EntryMac[6];
	size_t u16EntryMac_len;	/* # of uint8_t elements */
	
	/* Column values */
	uint8_t au8EntryIsidFlags[1];
	size_t u16EntryIsidFlags_len;	/* # of uint8_t elements */
	
	xBTree_Node_t oBTreeNode;
} ieee8021SpbmTopSrvEntry_t;

extern xBTree_t oIeee8021SpbmTopSrvTable_BTree;

/* ieee8021SpbmTopSrvTable table mapper */
void ieee8021SpbmTopSrvTable_init (void);
ieee8021SpbmTopSrvEntry_t * ieee8021SpbmTopSrvTable_createEntry (
	uint32_t u32EntryTopIx,
	uint8_t *pau8EntrySysId, size_t u16EntrySysId_len,
	uint32_t u32EntryIsid,
	int32_t i32EntryBaseVid,
	uint8_t *pau8EntryMac, size_t u16EntryMac_len);
ieee8021SpbmTopSrvEntry_t * ieee8021SpbmTopSrvTable_getByIndex (
	uint32_t u32EntryTopIx,
	uint8_t *pau8EntrySysId, size_t u16EntrySysId_len,
	uint32_t u32EntryIsid,
	int32_t i32EntryBaseVid,
	uint8_t *pau8EntryMac, size_t u16EntryMac_len);
ieee8021SpbmTopSrvEntry_t * ieee8021SpbmTopSrvTable_getNextIndex (
	uint32_t u32EntryTopIx,
	uint8_t *pau8EntrySysId, size_t u16EntrySysId_len,
	uint32_t u32EntryIsid,
	int32_t i32EntryBaseVid,
	uint8_t *pau8EntryMac, size_t u16EntryMac_len);
void ieee8021SpbmTopSrvTable_removeEntry (ieee8021SpbmTopSrvEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021SpbmTopSrvTable_getFirst;
Netsnmp_Next_Data_Point ieee8021SpbmTopSrvTable_getNext;
Netsnmp_Get_Data_Point ieee8021SpbmTopSrvTable_get;
Netsnmp_Node_Handler ieee8021SpbmTopSrvTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021SpbvTopSrvTable definitions
 */
#define IEEE8021SPBVTOPSRVENTRYTOPIX 1
#define IEEE8021SPBVTOPSRVENTRYSYSID 2
#define IEEE8021SPBVTOPSRVENTRYMMAC 3
#define IEEE8021SPBVTOPSRVENTRYBASEVID 4
#define IEEE8021SPBVTOPSRVENTRYMMACFLAGS 5

enum
{
	/* enums for column ieee8021SpbvTopSrvEntryMMacFlags */
	ieee8021SpbvTopSrvEntryMMacFlags_ingress_c = 0,
	ieee8021SpbvTopSrvEntryMMacFlags_egress_c = 1,
};

/* table ieee8021SpbvTopSrvTable row entry data structure */
typedef struct ieee8021SpbvTopSrvEntry_t
{
	/* Index values */
	uint32_t u32EntryTopIx;
	uint8_t au8EntrySysId[6];
	size_t u16EntrySysId_len;	/* # of uint8_t elements */
	uint8_t au8EntryMMac[6];
	size_t u16EntryMMac_len;	/* # of uint8_t elements */
	
	/* Column values */
	int32_t i32EntryBaseVid;
	uint8_t au8EntryMMacFlags[1];
	size_t u16EntryMMacFlags_len;	/* # of uint8_t elements */
	
	xBTree_Node_t oBTreeNode;
} ieee8021SpbvTopSrvEntry_t;

extern xBTree_t oIeee8021SpbvTopSrvTable_BTree;

/* ieee8021SpbvTopSrvTable table mapper */
void ieee8021SpbvTopSrvTable_init (void);
ieee8021SpbvTopSrvEntry_t * ieee8021SpbvTopSrvTable_createEntry (
	uint32_t u32EntryTopIx,
	uint8_t *pau8EntrySysId, size_t u16EntrySysId_len,
	uint8_t *pau8EntryMMac, size_t u16EntryMMac_len);
ieee8021SpbvTopSrvEntry_t * ieee8021SpbvTopSrvTable_getByIndex (
	uint32_t u32EntryTopIx,
	uint8_t *pau8EntrySysId, size_t u16EntrySysId_len,
	uint8_t *pau8EntryMMac, size_t u16EntryMMac_len);
ieee8021SpbvTopSrvEntry_t * ieee8021SpbvTopSrvTable_getNextIndex (
	uint32_t u32EntryTopIx,
	uint8_t *pau8EntrySysId, size_t u16EntrySysId_len,
	uint8_t *pau8EntryMMac, size_t u16EntryMMac_len);
void ieee8021SpbvTopSrvTable_removeEntry (ieee8021SpbvTopSrvEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021SpbvTopSrvTable_getFirst;
Netsnmp_Next_Data_Point ieee8021SpbvTopSrvTable_getNext;
Netsnmp_Get_Data_Point ieee8021SpbvTopSrvTable_get;
Netsnmp_Node_Handler ieee8021SpbvTopSrvTable_mapper;
#endif	/* SNMP_SRC */



#	ifdef __cplusplus
}
#	endif

#endif /* __IEEE8021SPBMIB_H__ */
