/*
 *  Copyright (c) 2008-2015
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

#ifndef __NEMPLSTEMIB_H__
#	define __NEMPLSTEMIB_H__

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
void neMplsTeMIB_init (void);


/**
 *	scalar mapper(s)
 */
/** definitions for scalar(s) of neMplsTeScalars **/
#define NEMPLSTEUNDERLAYENABLE 1
#define NEMPLSTELOOSEHOPEXPANDENABLE 2
#define NEMPLSTESETUPRETRYPERIOD 3
#define NEMPLSTESOFTPREEMPTIONPERIOD 4
#define NEMPLSTEREOPTIMIZATIONPERIOD 5
#define NEMPLSTEFRRPROTECTIONMETHOD 6
#define NEMPLSTEFRRREVERTIVEMODE 7
#define NEMPLSTECRANKBACKMODE 8
#define NEMPLSTEREROUTEUPSTREAMHOLDPERIOD 9
#define NEMPLSTEHLSPHOPMERGEENABLE 10

enum
{
	/* enums for scalar neMplsTeUnderlayEnable */
	neMplsTeUnderlayEnable_true_c = 1,
	neMplsTeUnderlayEnable_false_c = 2,

	/* enums for scalar neMplsTeLooseHopExpandEnable */
	neMplsTeLooseHopExpandEnable_true_c = 1,
	neMplsTeLooseHopExpandEnable_false_c = 2,

	/* enums for scalar neMplsTeFrrProtectionMethod */
	neMplsTeFrrProtectionMethod_oneToOneBackup_c = 0,
	neMplsTeFrrProtectionMethod_facilityBackup_c = 1,

	/* enums for scalar neMplsTeFrrRevertiveMode */
	neMplsTeFrrRevertiveMode_local_c = 0,
	neMplsTeFrrRevertiveMode_global_c = 1,

	/* enums for scalar neMplsTeCrankbackMode */
	neMplsTeCrankbackMode_forward_c = 1,
	neMplsTeCrankbackMode_reroute_c = 2,

	/* enums for scalar neMplsTeHlspHopMergeEnable */
	neMplsTeHlspHopMergeEnable_true_c = 1,
	neMplsTeHlspHopMergeEnable_false_c = 2,
};

typedef struct neMplsTeScalars_t
{
	uint8_t u8UnderlayEnable;
	uint8_t u8LooseHopExpandEnable;
	uint32_t u32SetupRetryPeriod;
	uint32_t u32SoftPreemptionPeriod;
	uint32_t u32ReoptimizationPeriod;
	uint8_t au8FrrProtectionMethod[1];
	size_t u16FrrProtectionMethod_len;	/* # of uint8_t elements */
	uint8_t au8FrrRevertiveMode[1];
	size_t u16FrrRevertiveMode_len;	/* # of uint8_t elements */
	int32_t i32CrankbackMode;
	uint32_t u32RerouteUpstreamHoldPeriod;
	uint8_t u8HlspHopMergeEnable;
} neMplsTeScalars_t;

extern neMplsTeScalars_t oNeMplsTeScalars;

#ifdef SNMP_SRC
Netsnmp_Node_Handler neMplsTeScalars_mapper;
#endif	/* SNMP_SRC */



/**
 *	table mapper(s)
 */
/**
 *	table neMplsTunnelTable definitions
 */
#define NEMPLSTUNNELCALLID 1
#define NEMPLSTUNNELTYPE 2
#define NEMPLSTUNNELXCINDEX 3
#define NEMPLSTUNNELRESOURCEINDEX 4
#define NEMPLSTUNNELREVERSERESOURCEINDEX 5
#define NEMPLSTUNNELPATHCOMPMODEL 6
#define NEMPLSTUNNELPEERIFINDEX 7
#define NEMPLSTUNNELLASTACTION 8
#define NEMPLSTUNNELREOPTIMIZATIONENABLE 9
#define NEMPLSTUNNELREOPTIMIZATIONSTATUS 10
#define NEMPLSTUNNELACTIVEINSTANCE 11
#define NEMPLSTUNNELSHAREDPARENTINSTANCE 12
#define NEMPLSTUNNELPROTECTIONSTATUS 13
#define NEMPLSTUNNELDIFFSERVTYPE 14

enum
{
	/* enums for column neMplsTunnelType */
	neMplsTunnelType_bP2p_c = 0,
	neMplsTunnelType_bP2mp_c = 1,
	neMplsTunnelType_bSLsp_c = 2,
	neMplsTunnelType_bHLsp_c = 3,

	/* enums for column neMplsTunnelPathCompModel */
	neMplsTunnelPathCompModel_bContiguous_c = 0,
	neMplsTunnelPathCompModel_bNested_c = 1,
	neMplsTunnelPathCompModel_bStitched_c = 2,

	/* enums for column neMplsTunnelLastAction */
	neMplsTunnelLastAction_bSharedInstanceInitiated_c = 0,
	neMplsTunnelLastAction_bSharedInstanceUp_c = 1,
	neMplsTunnelLastAction_bSharedInstanceDown_c = 2,
	neMplsTunnelLastAction_bSharedInstanceComplete_c = 3,
	neMplsTunnelLastAction_bProtectionSwitchingInitiated_c = 4,
	neMplsTunnelLastAction_bProtectionSwitchingComplete_c = 5,
	neMplsTunnelLastAction_bOptimizationInitiated_c = 6,
	neMplsTunnelLastAction_bOptimizationComplete_c = 7,
	neMplsTunnelLastAction_bRerouteUpstreamRequested_c = 8,
	neMplsTunnelLastAction_bAdminStatusRequested_c = 9,
	neMplsTunnelLastAction_bAdminStatusReflected_c = 10,

	/* enums for column neMplsTunnelReoptimizationEnable */
	neMplsTunnelReoptimizationEnable_enabled_c = 1,
	neMplsTunnelReoptimizationEnable_disabled_c = 2,
	neMplsTunnelReoptimizationEnable_auto_c = 3,

	/* enums for column neMplsTunnelReoptimizationStatus */
	neMplsTunnelReoptimizationStatus_true_c = 1,
	neMplsTunnelReoptimizationStatus_false_c = 2,

	/* enums for column neMplsTunnelProtectionStatus */
	neMplsTunnelProtectionStatus_bPrimary_c = 0,
	neMplsTunnelProtectionStatus_bSecondary_c = 1,
	neMplsTunnelProtectionStatus_bWorking_c = 2,
	neMplsTunnelProtectionStatus_bProtected_c = 3,
	neMplsTunnelProtectionStatus_bProtecting_c = 4,

	/* enums for column neMplsTunnelDiffServType */
	neMplsTunnelDiffServType_uniform_c = 1,
	neMplsTunnelDiffServType_pipe_c = 2,
	neMplsTunnelDiffServType_shortPipe_c = 3,
};

/* table neMplsTunnelTable row entry data structure */
typedef struct neMplsTunnelEntry_t
{
	/* Index values */
// 	uint32_t u32Index;
// 	uint32_t u32Instance;
// 	uint32_t u32IngressLSRId;
// 	uint32_t u32EgressLSRId;
	
	/* Column values */
	uint32_t u32CallId;
	uint8_t au8Type[1];
	size_t u16Type_len;	/* # of uint8_t elements */
	uint8_t au8XCIndex[24];
	size_t u16XCIndex_len;	/* # of uint8_t elements */
	uint32_t u32ResourceIndex;
	uint32_t u32ReverseResourceIndex;
	uint8_t au8PathCompModel[1];
	size_t u16PathCompModel_len;	/* # of uint8_t elements */
	uint32_t u32PeerIfIndex;
	uint8_t au8LastAction[2];
	size_t u16LastAction_len;	/* # of uint8_t elements */
	int32_t i32ReoptimizationEnable;
	uint8_t u8ReoptimizationStatus;
	uint32_t u32ActiveInstance;
	uint32_t u32SharedParentInstance;
	uint8_t au8ProtectionStatus[1];
	size_t u16ProtectionStatus_len;	/* # of uint8_t elements */
	int32_t i32DiffServType;
	
// 	xBTree_Node_t oBTreeNode;
} neMplsTunnelEntry_t;

// extern xBTree_t oNeMplsTunnelTable_BTree;

/* neMplsTunnelTable table mapper */
void neMplsTunnelTable_init (void);
neMplsTunnelEntry_t * neMplsTunnelTable_createEntry (
	uint32_t u32Index,
	uint32_t u32Instance,
	uint32_t u32IngressLSRId,
	uint32_t u32EgressLSRId);
neMplsTunnelEntry_t * neMplsTunnelTable_getByIndex (
	uint32_t u32Index,
	uint32_t u32Instance,
	uint32_t u32IngressLSRId,
	uint32_t u32EgressLSRId);
neMplsTunnelEntry_t * neMplsTunnelTable_getNextIndex (
	uint32_t u32Index,
	uint32_t u32Instance,
	uint32_t u32IngressLSRId,
	uint32_t u32EgressLSRId);
void neMplsTunnelTable_removeEntry (neMplsTunnelEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point neMplsTunnelTable_getFirst;
Netsnmp_Next_Data_Point neMplsTunnelTable_getNext;
Netsnmp_Get_Data_Point neMplsTunnelTable_get;
Netsnmp_Node_Handler neMplsTunnelTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table neMplsTunnelX1Table definitions
 */
#define NEMPLSTUNNELRESOURCEUPSTREAMINDEX 1
#define NEMPLSTUNNELREROUTEUPSTREAMENABLE 2
#define NEMPLSTUNNELCRANKBACKMODEL 3
#define NEMPLSTUNNELCRANKBACKENABLE 4
#define NEMPLSTUNNELCRANKBACKSTATUS 5
#define NEMPLSTUNNELCRANKBACKLISTINDEX 6
#define NEMPLSTUNNELSOFTPREEMPTIONENABLE 7
#define NEMPLSTUNNELSOFTPREEMPTIONSTATUS 8
#define NEMPLSTUNNELOAMENABLE 9
#define NEMPLSTUNNELOAMMEGINDEX 10
#define NEMPLSTUNNELOAMMEINDEX 11

enum
{
	/* enums for column neMplsTunnelRerouteUpstreamEnable */
	neMplsTunnelRerouteUpstreamEnable_true_c = 1,
	neMplsTunnelRerouteUpstreamEnable_false_c = 2,

	/* enums for column neMplsTunnelCrankbackModel */
	neMplsTunnelCrankbackModel_bE2eRerouting_c = 0,
	neMplsTunnelCrankbackModel_bBoundaryRerouting_c = 1,
	neMplsTunnelCrankbackModel_bSegmentRerouting_c = 2,

	/* enums for column neMplsTunnelCrankbackEnable */
	neMplsTunnelCrankbackEnable_enabled_c = 1,
	neMplsTunnelCrankbackEnable_disabled_c = 2,
	neMplsTunnelCrankbackEnable_auto_c = 3,

	/* enums for column neMplsTunnelCrankbackStatus */
	neMplsTunnelCrankbackStatus_true_c = 1,
	neMplsTunnelCrankbackStatus_false_c = 2,

	/* enums for column neMplsTunnelSoftPreemptionEnable */
	neMplsTunnelSoftPreemptionEnable_enabled_c = 1,
	neMplsTunnelSoftPreemptionEnable_disabled_c = 2,
	neMplsTunnelSoftPreemptionEnable_auto_c = 3,

	/* enums for column neMplsTunnelSoftPreemptionStatus */
	neMplsTunnelSoftPreemptionStatus_true_c = 1,
	neMplsTunnelSoftPreemptionStatus_false_c = 2,

	/* enums for column neMplsTunnelOamEnable */
	neMplsTunnelOamEnable_true_c = 1,
	neMplsTunnelOamEnable_false_c = 2,
};

/* table neMplsTunnelX1Table row entry data structure */
typedef struct neMplsTunnelX1Entry_t
{
	/* Index values */
	uint32_t u32Index;
	uint32_t u32Instance;
	uint32_t u32IngressLSRId;
	uint32_t u32EgressLSRId;
	
	/* Column values */
	uint32_t u32ResourceUpstreamIndex;
	uint8_t u8RerouteUpstreamEnable;
	uint8_t au8CrankbackModel[1];
	size_t u16CrankbackModel_len;	/* # of uint8_t elements */
	int32_t i32CrankbackEnable;
	uint8_t u8CrankbackStatus;
	uint32_t u32CrankbackListIndex;
	int32_t i32SoftPreemptionEnable;
	uint8_t u8SoftPreemptionStatus;
	uint8_t u8OamEnable;
	uint32_t u32OamMegIndex;
	uint32_t u32OamMeIndex;
	
	xBTree_Node_t oBTreeNode;
} neMplsTunnelX1Entry_t;

extern xBTree_t oNeMplsTunnelX1Table_BTree;

/* neMplsTunnelX1Table table mapper */
void neMplsTunnelX1Table_init (void);
neMplsTunnelX1Entry_t * neMplsTunnelX1Table_createEntry (
	uint32_t u32Index,
	uint32_t u32Instance,
	uint32_t u32IngressLSRId,
	uint32_t u32EgressLSRId);
neMplsTunnelX1Entry_t * neMplsTunnelX1Table_getByIndex (
	uint32_t u32Index,
	uint32_t u32Instance,
	uint32_t u32IngressLSRId,
	uint32_t u32EgressLSRId);
neMplsTunnelX1Entry_t * neMplsTunnelX1Table_getNextIndex (
	uint32_t u32Index,
	uint32_t u32Instance,
	uint32_t u32IngressLSRId,
	uint32_t u32EgressLSRId);
void neMplsTunnelX1Table_removeEntry (neMplsTunnelX1Entry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point neMplsTunnelX1Table_getFirst;
Netsnmp_Next_Data_Point neMplsTunnelX1Table_getNext;
Netsnmp_Get_Data_Point neMplsTunnelX1Table_get;
Netsnmp_Node_Handler neMplsTunnelX1Table_mapper;
#endif	/* SNMP_SRC */


/**
 *	table neMplsTunnelHopTable definitions
 */
#define NEMPLSTUNNELHOPNODEID 1
#define NEMPLSTUNNELHOPLINKID 2
#define NEMPLSTUNNELHOPLABELTYPE 3
#define NEMPLSTUNNELHOPFORWARDLABEL 4
#define NEMPLSTUNNELHOPREVERSELABEL 5

enum
{
	/* enums for column neMplsTunnelHopLabelType */
	neMplsTunnelHopLabelType_ethernet_c = 1,
	neMplsTunnelHopLabelType_atm_c = 2,
	neMplsTunnelHopLabelType_frameRelay_c = 3,
	neMplsTunnelHopLabelType_evpl_c = 4,
	neMplsTunnelHopLabelType_pbbTe_c = 5,
	neMplsTunnelHopLabelType_l2sc_c = 6,
	neMplsTunnelHopLabelType_sonet_c = 7,
	neMplsTunnelHopLabelType_sdh_c = 8,
	neMplsTunnelHopLabelType_otn_c = 9,
	neMplsTunnelHopLabelType_dcsc_c = 10,
	neMplsTunnelHopLabelType_waveband_c = 11,
	neMplsTunnelHopLabelType_lambda_c = 12,
	neMplsTunnelHopLabelType_fiber_c = 13,
};

/* table neMplsTunnelHopTable row entry data structure */
typedef struct neMplsTunnelHopEntry_t
{
	/* Index values */
// 	uint32_t u32ListIndex;
// 	uint32_t u32PathOptionIndex;
// 	uint32_t u32Index;
	
	/* Column values */
	uint32_t u32NodeId;
	uint32_t u32LinkId;
	int32_t i32LabelType;
	uint8_t au8ForwardLabel[64];
	size_t u16ForwardLabel_len;	/* # of uint8_t elements */
	uint8_t au8ReverseLabel[64];
	size_t u16ReverseLabel_len;	/* # of uint8_t elements */
	
// 	xBTree_Node_t oBTreeNode;
} neMplsTunnelHopEntry_t;

// extern xBTree_t oNeMplsTunnelHopTable_BTree;

/* neMplsTunnelHopTable table mapper */
void neMplsTunnelHopTable_init (void);
neMplsTunnelHopEntry_t * neMplsTunnelHopTable_createEntry (
	uint32_t u32ListIndex,
	uint32_t u32PathOptionIndex,
	uint32_t u32Index);
neMplsTunnelHopEntry_t * neMplsTunnelHopTable_getByIndex (
	uint32_t u32ListIndex,
	uint32_t u32PathOptionIndex,
	uint32_t u32Index);
neMplsTunnelHopEntry_t * neMplsTunnelHopTable_getNextIndex (
	uint32_t u32ListIndex,
	uint32_t u32PathOptionIndex,
	uint32_t u32Index);
void neMplsTunnelHopTable_removeEntry (neMplsTunnelHopEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point neMplsTunnelHopTable_getFirst;
Netsnmp_Next_Data_Point neMplsTunnelHopTable_getNext;
Netsnmp_Get_Data_Point neMplsTunnelHopTable_get;
Netsnmp_Node_Handler neMplsTunnelHopTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table neMplsTunnelARHopTable definitions
 */
#define NEMPLSTUNNELARHOPNODEID 1
#define NEMPLSTUNNELARHOPLINKID 2
#define NEMPLSTUNNELARHOPLABELTYPE 3
#define NEMPLSTUNNELARHOPFORWARDLABEL 4
#define NEMPLSTUNNELARHOPREVERSELABEL 5

enum
{
	/* enums for column neMplsTunnelARHopLabelType */
	neMplsTunnelARHopLabelType_ethernet_c = 1,
	neMplsTunnelARHopLabelType_atm_c = 2,
	neMplsTunnelARHopLabelType_frameRelay_c = 3,
	neMplsTunnelARHopLabelType_evpl_c = 4,
	neMplsTunnelARHopLabelType_pbbTe_c = 5,
	neMplsTunnelARHopLabelType_l2sc_c = 6,
	neMplsTunnelARHopLabelType_sonet_c = 7,
	neMplsTunnelARHopLabelType_sdh_c = 8,
	neMplsTunnelARHopLabelType_otn_c = 9,
	neMplsTunnelARHopLabelType_dcsc_c = 10,
	neMplsTunnelARHopLabelType_waveband_c = 11,
	neMplsTunnelARHopLabelType_lambda_c = 12,
	neMplsTunnelARHopLabelType_fiber_c = 13,
};

/* table neMplsTunnelARHopTable row entry data structure */
typedef struct neMplsTunnelARHopEntry_t
{
	/* Index values */
// 	uint32_t u32ListIndex;
// 	uint32_t u32Index;
	
	/* Column values */
	uint32_t u32NodeId;
	uint32_t u32LinkId;
	int32_t i32LabelType;
	uint8_t au8ForwardLabel[64];
	size_t u16ForwardLabel_len;	/* # of uint8_t elements */
	uint8_t au8ReverseLabel[64];
	size_t u16ReverseLabel_len;	/* # of uint8_t elements */
	
// 	xBTree_Node_t oBTreeNode;
} neMplsTunnelARHopEntry_t;

// extern xBTree_t oNeMplsTunnelARHopTable_BTree;

/* neMplsTunnelARHopTable table mapper */
void neMplsTunnelARHopTable_init (void);
neMplsTunnelARHopEntry_t * neMplsTunnelARHopTable_createEntry (
	uint32_t u32ListIndex,
	uint32_t u32Index);
neMplsTunnelARHopEntry_t * neMplsTunnelARHopTable_getByIndex (
	uint32_t u32ListIndex,
	uint32_t u32Index);
neMplsTunnelARHopEntry_t * neMplsTunnelARHopTable_getNextIndex (
	uint32_t u32ListIndex,
	uint32_t u32Index);
void neMplsTunnelARHopTable_removeEntry (neMplsTunnelARHopEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point neMplsTunnelARHopTable_getFirst;
Netsnmp_Next_Data_Point neMplsTunnelARHopTable_getNext;
Netsnmp_Get_Data_Point neMplsTunnelARHopTable_get;
Netsnmp_Node_Handler neMplsTunnelARHopTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table neMplsTunnelCHopTable definitions
 */
#define NEMPLSTUNNELCHOPNODEID 1
#define NEMPLSTUNNELCHOPLINKID 2
#define NEMPLSTUNNELCHOPLABELTYPE 3
#define NEMPLSTUNNELCHOPFORWARDLABEL 4
#define NEMPLSTUNNELCHOPREVERSELABEL 5

enum
{
	/* enums for column neMplsTunnelCHopLabelType */
	neMplsTunnelCHopLabelType_ethernet_c = 1,
	neMplsTunnelCHopLabelType_atm_c = 2,
	neMplsTunnelCHopLabelType_frameRelay_c = 3,
	neMplsTunnelCHopLabelType_evpl_c = 4,
	neMplsTunnelCHopLabelType_pbbTe_c = 5,
	neMplsTunnelCHopLabelType_l2sc_c = 6,
	neMplsTunnelCHopLabelType_sonet_c = 7,
	neMplsTunnelCHopLabelType_sdh_c = 8,
	neMplsTunnelCHopLabelType_otn_c = 9,
	neMplsTunnelCHopLabelType_dcsc_c = 10,
	neMplsTunnelCHopLabelType_waveband_c = 11,
	neMplsTunnelCHopLabelType_lambda_c = 12,
	neMplsTunnelCHopLabelType_fiber_c = 13,
};

/* table neMplsTunnelCHopTable row entry data structure */
typedef struct neMplsTunnelCHopEntry_t
{
	/* Index values */
// 	uint32_t u32ListIndex;
// 	uint32_t u32Index;
	
	/* Column values */
	uint32_t u32NodeId;
	uint32_t u32LinkId;
	int32_t i32LabelType;
	uint8_t au8ForwardLabel[64];
	size_t u16ForwardLabel_len;	/* # of uint8_t elements */
	uint8_t au8ReverseLabel[64];
	size_t u16ReverseLabel_len;	/* # of uint8_t elements */
	
// 	xBTree_Node_t oBTreeNode;
} neMplsTunnelCHopEntry_t;

// extern xBTree_t oNeMplsTunnelCHopTable_BTree;

/* neMplsTunnelCHopTable table mapper */
void neMplsTunnelCHopTable_init (void);
neMplsTunnelCHopEntry_t * neMplsTunnelCHopTable_createEntry (
	uint32_t u32ListIndex,
	uint32_t u32Index);
neMplsTunnelCHopEntry_t * neMplsTunnelCHopTable_getByIndex (
	uint32_t u32ListIndex,
	uint32_t u32Index);
neMplsTunnelCHopEntry_t * neMplsTunnelCHopTable_getNextIndex (
	uint32_t u32ListIndex,
	uint32_t u32Index);
void neMplsTunnelCHopTable_removeEntry (neMplsTunnelCHopEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point neMplsTunnelCHopTable_getFirst;
Netsnmp_Next_Data_Point neMplsTunnelCHopTable_getNext;
Netsnmp_Get_Data_Point neMplsTunnelCHopTable_get;
Netsnmp_Node_Handler neMplsTunnelCHopTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table neMplsTunnelPathTable definitions
 */
#define NEMPLSTUNNELPATHOPTIONINDEX 1
#define NEMPLSTUNNELPATHTYPE 2
#define NEMPLSTUNNELPATHROWSTATUS 3
#define NEMPLSTUNNELPATHSTORAGETYPE 4

enum
{
	/* enums for column neMplsTunnelPathType */
	neMplsTunnelPathType_ehop_c = 1,
	neMplsTunnelPathType_ppro_c = 2,
	neMplsTunnelPathType_prro_c = 3,
	neMplsTunnelPathType_sero_c = 4,

	/* enums for column neMplsTunnelPathRowStatus */
	neMplsTunnelPathRowStatus_active_c = 1,
	neMplsTunnelPathRowStatus_notInService_c = 2,
	neMplsTunnelPathRowStatus_notReady_c = 3,
	neMplsTunnelPathRowStatus_createAndGo_c = 4,
	neMplsTunnelPathRowStatus_createAndWait_c = 5,
	neMplsTunnelPathRowStatus_destroy_c = 6,

	/* enums for column neMplsTunnelPathStorageType */
	neMplsTunnelPathStorageType_other_c = 1,
	neMplsTunnelPathStorageType_volatile_c = 2,
	neMplsTunnelPathStorageType_nonVolatile_c = 3,
	neMplsTunnelPathStorageType_permanent_c = 4,
	neMplsTunnelPathStorageType_readOnly_c = 5,
};

/* table neMplsTunnelPathTable row entry data structure */
typedef struct neMplsTunnelPathEntry_t
{
	/* Index values */
	uint32_t u32Index;
	uint32_t u32Instance;
	uint32_t u32IngressLSRId;
	uint32_t u32EgressLSRId;
	uint32_t u32OptionIndex;
	
	/* Column values */
	int32_t i32Type;
	uint8_t u8RowStatus;
	uint8_t u8StorageType;
	
	xBTree_Node_t oBTreeNode;
} neMplsTunnelPathEntry_t;

extern xBTree_t oNeMplsTunnelPathTable_BTree;

/* neMplsTunnelPathTable table mapper */
void neMplsTunnelPathTable_init (void);
neMplsTunnelPathEntry_t * neMplsTunnelPathTable_createEntry (
	uint32_t u32Index,
	uint32_t u32Instance,
	uint32_t u32IngressLSRId,
	uint32_t u32EgressLSRId,
	uint32_t u32OptionIndex);
neMplsTunnelPathEntry_t * neMplsTunnelPathTable_getByIndex (
	uint32_t u32Index,
	uint32_t u32Instance,
	uint32_t u32IngressLSRId,
	uint32_t u32EgressLSRId,
	uint32_t u32OptionIndex);
neMplsTunnelPathEntry_t * neMplsTunnelPathTable_getNextIndex (
	uint32_t u32Index,
	uint32_t u32Instance,
	uint32_t u32IngressLSRId,
	uint32_t u32EgressLSRId,
	uint32_t u32OptionIndex);
void neMplsTunnelPathTable_removeEntry (neMplsTunnelPathEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point neMplsTunnelPathTable_getFirst;
Netsnmp_Next_Data_Point neMplsTunnelPathTable_getNext;
Netsnmp_Get_Data_Point neMplsTunnelPathTable_get;
Netsnmp_Node_Handler neMplsTunnelPathTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table neMplsCallTable definitions
 */
#define NEMPLSCALLINGRESSLSRID 1
#define NEMPLSCALLEGRESSLSRID 2
#define NEMPLSCALLID 3
#define NEMPLSCALLLONGID 4
#define NEMPLSCALLROWSTATUS 5
#define NEMPLSCALLSTORAGETYPE 6

enum
{
	/* enums for column neMplsCallRowStatus */
	neMplsCallRowStatus_active_c = 1,
	neMplsCallRowStatus_notInService_c = 2,
	neMplsCallRowStatus_notReady_c = 3,
	neMplsCallRowStatus_createAndGo_c = 4,
	neMplsCallRowStatus_createAndWait_c = 5,
	neMplsCallRowStatus_destroy_c = 6,

	/* enums for column neMplsCallStorageType */
	neMplsCallStorageType_other_c = 1,
	neMplsCallStorageType_volatile_c = 2,
	neMplsCallStorageType_nonVolatile_c = 3,
	neMplsCallStorageType_permanent_c = 4,
	neMplsCallStorageType_readOnly_c = 5,
};

/* table neMplsCallTable row entry data structure */
typedef struct neMplsCallEntry_t
{
	/* Index values */
	uint32_t u32IngressLsrId;
	uint32_t u32EgressLsrId;
	uint32_t u32Id;
	
	/* Column values */
	uint8_t au8LongId[64];
	size_t u16LongId_len;	/* # of uint8_t elements */
	uint8_t u8RowStatus;
	uint8_t u8StorageType;
	
	xBTree_Node_t oBTreeNode;
} neMplsCallEntry_t;

extern xBTree_t oNeMplsCallTable_BTree;

/* neMplsCallTable table mapper */
void neMplsCallTable_init (void);
neMplsCallEntry_t * neMplsCallTable_createEntry (
	uint32_t u32IngressLsrId,
	uint32_t u32EgressLsrId,
	uint32_t u32Id);
neMplsCallEntry_t * neMplsCallTable_getByIndex (
	uint32_t u32IngressLsrId,
	uint32_t u32EgressLsrId,
	uint32_t u32Id);
neMplsCallEntry_t * neMplsCallTable_getNextIndex (
	uint32_t u32IngressLsrId,
	uint32_t u32EgressLsrId,
	uint32_t u32Id);
void neMplsCallTable_removeEntry (neMplsCallEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point neMplsCallTable_getFirst;
Netsnmp_Next_Data_Point neMplsCallTable_getNext;
Netsnmp_Get_Data_Point neMplsCallTable_get;
Netsnmp_Node_Handler neMplsCallTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table neMplsCallLinkTable definitions
 */
#define NEMPLSCALLLINKINDEX 1
#define NEMPLSCALLLINKTYPE 2
#define NEMPLSCALLLINKADDRESS 3
#define NEMPLSCALLLINKADDRESSUNNUMBERED 4
#define NEMPLSCALLLINKRESERVABLEBANDWIDTH 5
#define NEMPLSCALLLINKROWSTATUS 6
#define NEMPLSCALLLINKSTORAGETYPE 7

enum
{
	/* enums for column neMplsCallLinkType */
	neMplsCallLinkType_unknown_c = 0,
	neMplsCallLinkType_ipv4_c = 1,
	neMplsCallLinkType_ipv6_c = 2,
	neMplsCallLinkType_unnumbered_c = 4,

	/* enums for column neMplsCallLinkRowStatus */
	neMplsCallLinkRowStatus_active_c = 1,
	neMplsCallLinkRowStatus_notInService_c = 2,
	neMplsCallLinkRowStatus_notReady_c = 3,
	neMplsCallLinkRowStatus_createAndGo_c = 4,
	neMplsCallLinkRowStatus_createAndWait_c = 5,
	neMplsCallLinkRowStatus_destroy_c = 6,

	/* enums for column neMplsCallLinkStorageType */
	neMplsCallLinkStorageType_other_c = 1,
	neMplsCallLinkStorageType_volatile_c = 2,
	neMplsCallLinkStorageType_nonVolatile_c = 3,
	neMplsCallLinkStorageType_permanent_c = 4,
	neMplsCallLinkStorageType_readOnly_c = 5,
};

/* table neMplsCallLinkTable row entry data structure */
typedef struct neMplsCallLinkEntry_t
{
	/* Index values */
	uint32_t u32IngressLsrId;
	uint32_t u32EgressLsrId;
	uint32_t u32Id;
	uint32_t u32Index;
	
	/* Column values */
	int32_t i32Type;
	uint8_t au8Address[16];
	size_t u16Address_len;	/* # of uint8_t elements */
	uint32_t u32AddressUnnumbered;
	uint8_t au8ReservableBandwidth[8];
	size_t u16ReservableBandwidth_len;	/* # of uint8_t elements */
	uint8_t u8RowStatus;
	uint8_t u8StorageType;
	
	xBTree_Node_t oBTreeNode;
} neMplsCallLinkEntry_t;

extern xBTree_t oNeMplsCallLinkTable_BTree;

/* neMplsCallLinkTable table mapper */
void neMplsCallLinkTable_init (void);
neMplsCallLinkEntry_t * neMplsCallLinkTable_createEntry (
	uint32_t u32IngressLsrId,
	uint32_t u32EgressLsrId,
	uint32_t u32Id,
	uint32_t u32Index);
neMplsCallLinkEntry_t * neMplsCallLinkTable_getByIndex (
	uint32_t u32IngressLsrId,
	uint32_t u32EgressLsrId,
	uint32_t u32Id,
	uint32_t u32Index);
neMplsCallLinkEntry_t * neMplsCallLinkTable_getNextIndex (
	uint32_t u32IngressLsrId,
	uint32_t u32EgressLsrId,
	uint32_t u32Id,
	uint32_t u32Index);
void neMplsCallLinkTable_removeEntry (neMplsCallLinkEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point neMplsCallLinkTable_getFirst;
Netsnmp_Next_Data_Point neMplsCallLinkTable_getNext;
Netsnmp_Get_Data_Point neMplsCallLinkTable_get;
Netsnmp_Node_Handler neMplsCallLinkTable_mapper;
#endif	/* SNMP_SRC */



#	ifdef __cplusplus
}
#	endif

#endif /* __NEMPLSTEMIB_H__ */
