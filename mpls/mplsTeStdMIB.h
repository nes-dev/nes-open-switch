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

#ifndef __MPLSTESTDMIB_H__
#	define __MPLSTESTDMIB_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include "mplsTeExtStdMIB.h"
#include "neMplsTeMIB.h"

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

/** definitions for scalar(s) of gmplsTeScalars **/
#define GMPLSTUNNELSCONFIGURED 1
#define GMPLSTUNNELSACTIVE 2

typedef struct gmplsTeScalars_t
{
	uint32_t u32Configured;
	uint32_t u32Active;
} gmplsTeScalars_t;

extern gmplsTeScalars_t oGmplsTeScalars;

#ifdef SNMP_SRC
Netsnmp_Node_Handler gmplsTeScalars_mapper;
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
// 	uint32_t u32Index;
// 	uint32_t u32Instance;
// 	uint32_t u32IngressLSRId;
// 	uint32_t u32EgressLSRId;
	
	/* Column values */
	uint32_t u32Packets;
	uint64_t u64HCPackets;
	uint32_t u32Errors;
	uint32_t u32Bytes;
	uint64_t u64HCBytes;
	
// 	xBTree_Node_t oBTreeNode;
} mplsTunnelPerfEntry_t;

// extern xBTree_t oMplsTunnelPerfTable_BTree;

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
 *	table gmplsTunnelTable definitions
 */
#define GMPLSTUNNELUNNUMIF 1
#define GMPLSTUNNELATTRIBUTES 2
#define GMPLSTUNNELLSPENCODING 3
#define GMPLSTUNNELSWITCHINGTYPE 4
#define GMPLSTUNNELLINKPROTECTION 5
#define GMPLSTUNNELGPID 6
#define GMPLSTUNNELSECONDARY 7
#define GMPLSTUNNELDIRECTION 8
#define GMPLSTUNNELPATHCOMP 9
#define GMPLSTUNNELUPSTREAMNOTIFYRECIPIENTTYPE 10
#define GMPLSTUNNELUPSTREAMNOTIFYRECIPIENT 11
#define GMPLSTUNNELSENDRESVNOTIFYRECIPIENTTYPE 12
#define GMPLSTUNNELSENDRESVNOTIFYRECIPIENT 13
#define GMPLSTUNNELDOWNSTREAMNOTIFYRECIPIENTTYPE 14
#define GMPLSTUNNELDOWNSTREAMNOTIFYRECIPIENT 15
#define GMPLSTUNNELSENDPATHNOTIFYRECIPIENTTYPE 16
#define GMPLSTUNNELSENDPATHNOTIFYRECIPIENT 17
#define GMPLSTUNNELADMINSTATUSFLAGS 18

enum
{
	/* enums for column gmplsTunnelUnnumIf */
	gmplsTunnelUnnumIf_true_c = 1,
	gmplsTunnelUnnumIf_false_c = 2,

	/* enums for column gmplsTunnelAttributes */
	gmplsTunnelAttributes_labelRecordingDesired_c = 0,

	/* enums for column gmplsTunnelLSPEncoding */
	gmplsTunnelLSPEncoding_notGmpls_c = 0,
	gmplsTunnelLSPEncoding_packet_c = 1,
	gmplsTunnelLSPEncoding_ethernet_c = 2,
	gmplsTunnelLSPEncoding_ansiEtsiPdh_c = 3,
	gmplsTunnelLSPEncoding_sdhSonet_c = 5,
	gmplsTunnelLSPEncoding_digitalWrapper_c = 7,
	gmplsTunnelLSPEncoding_lambda_c = 8,
	gmplsTunnelLSPEncoding_fiber_c = 9,
	gmplsTunnelLSPEncoding_fiberChannel_c = 11,
	gmplsTunnelLSPEncoding_digitalPath_c = 12,
	gmplsTunnelLSPEncoding_opticalChannel_c = 13,
	gmplsTunnelLSPEncoding_line_c = 14,

	/* enums for column gmplsTunnelSwitchingType */
	gmplsTunnelSwitchingType_unknown_c = 0,
	gmplsTunnelSwitchingType_psc1_c = 1,
	gmplsTunnelSwitchingType_psc2_c = 2,
	gmplsTunnelSwitchingType_psc3_c = 3,
	gmplsTunnelSwitchingType_psc4_c = 4,
	gmplsTunnelSwitchingType_evpl_c = 30,
	gmplsTunnelSwitchingType_pbb_c = 40,
	gmplsTunnelSwitchingType_l2sc_c = 51,
	gmplsTunnelSwitchingType_tdm_c = 100,
	gmplsTunnelSwitchingType_otntdm_c = 110,
	gmplsTunnelSwitchingType_dcsc_c = 125,
	gmplsTunnelSwitchingType_lsc_c = 150,
	gmplsTunnelSwitchingType_fsc_c = 200,

	/* enums for column gmplsTunnelLinkProtection */
	gmplsTunnelLinkProtection_extraTraffic_c = 0,
	gmplsTunnelLinkProtection_unprotected_c = 1,
	gmplsTunnelLinkProtection_shared_c = 2,
	gmplsTunnelLinkProtection_dedicatedOneToOne_c = 3,
	gmplsTunnelLinkProtection_dedicatedOnePlusOne_c = 4,
	gmplsTunnelLinkProtection_enhanced_c = 5,

	/* enums for column gmplsTunnelGPid */
	gmplsTunnelGPid_unknown_c = 0,
	gmplsTunnelGPid_asynchE4_c = 5,
	gmplsTunnelGPid_asynchDS3T3_c = 6,
	gmplsTunnelGPid_asynchE3_c = 7,
	gmplsTunnelGPid_bitsynchE3_c = 8,
	gmplsTunnelGPid_bytesynchE3_c = 9,
	gmplsTunnelGPid_asynchDS2T2_c = 10,
	gmplsTunnelGPid_bitsynchDS2T2_c = 11,
	gmplsTunnelGPid_reservedByRFC3471first_c = 12,
	gmplsTunnelGPid_asynchE1_c = 13,
	gmplsTunnelGPid_bytesynchE1_c = 14,
	gmplsTunnelGPid_bytesynch31ByDS0_c = 15,
	gmplsTunnelGPid_asynchDS1T1_c = 16,
	gmplsTunnelGPid_bitsynchDS1T1_c = 17,
	gmplsTunnelGPid_bytesynchDS1T1_c = 18,
	gmplsTunnelGPid_vc1vc12_c = 19,
	gmplsTunnelGPid_reservedByRFC3471second_c = 20,
	gmplsTunnelGPid_reservedByRFC3471third_c = 21,
	gmplsTunnelGPid_ds1SFAsynch_c = 22,
	gmplsTunnelGPid_ds1ESFAsynch_c = 23,
	gmplsTunnelGPid_ds3M23Asynch_c = 24,
	gmplsTunnelGPid_ds3CBitParityAsynch_c = 25,
	gmplsTunnelGPid_vtLovc_c = 26,
	gmplsTunnelGPid_stsSpeHovc_c = 27,
	gmplsTunnelGPid_posNoScramble16BitCrc_c = 28,
	gmplsTunnelGPid_posNoScramble32BitCrc_c = 29,
	gmplsTunnelGPid_posScramble16BitCrc_c = 30,
	gmplsTunnelGPid_posScramble32BitCrc_c = 31,
	gmplsTunnelGPid_atm_c = 32,
	gmplsTunnelGPid_ethernet_c = 33,
	gmplsTunnelGPid_sdhSonet_c = 34,
	gmplsTunnelGPid_digitalwrapper_c = 36,
	gmplsTunnelGPid_lambda_c = 37,
	gmplsTunnelGPid_ansiEtsiPdh_c = 38,
	gmplsTunnelGPid_lapsSdh_c = 40,
	gmplsTunnelGPid_fddi_c = 41,
	gmplsTunnelGPid_dqdb_c = 42,
	gmplsTunnelGPid_fiberChannel3_c = 43,
	gmplsTunnelGPid_hdlc_c = 44,
	gmplsTunnelGPid_ethernetV2DixOnly_c = 45,
	gmplsTunnelGPid_ethernet802dot3Only_c = 46,
	gmplsTunnelGPid_g709ODUj_c = 47,
	gmplsTunnelGPid_g709OTUk_c = 48,
	gmplsTunnelGPid_g709CBRorCBRa_c = 49,
	gmplsTunnelGPid_g709CBRb_c = 50,
	gmplsTunnelGPid_g709BSOT_c = 51,
	gmplsTunnelGPid_g709BSNT_c = 52,
	gmplsTunnelGPid_gfpIPorPPP_c = 53,
	gmplsTunnelGPid_gfpEthernetMAC_c = 54,
	gmplsTunnelGPid_gfpEthernetPHY_c = 55,
	gmplsTunnelGPid_g709ESCON_c = 56,
	gmplsTunnelGPid_g709FICON_c = 57,
	gmplsTunnelGPid_g709FiberChannel_c = 58,
	gmplsTunnelGPid_framedGFP_c = 59,
	gmplsTunnelGPid_sTM1_c = 60,
	gmplsTunnelGPid_sTM4_c = 61,
	gmplsTunnelGPid_infiniBand_c = 62,
	gmplsTunnelGPid_sDI_c = 63,
	gmplsTunnelGPid_sDI1point001_c = 64,
	gmplsTunnelGPid_dVBASI_c = 65,
	gmplsTunnelGPid_g709ODU125G_c = 66,
	gmplsTunnelGPid_g709ODUAny_c = 67,
	gmplsTunnelGPid_nullTest_c = 68,
	gmplsTunnelGPid_randomTest_c = 69,
	gmplsTunnelGPid_sixtyfourB66BGFPFEthernet_c = 70,

	/* enums for column gmplsTunnelSecondary */
	gmplsTunnelSecondary_true_c = 1,
	gmplsTunnelSecondary_false_c = 2,

	/* enums for column gmplsTunnelDirection */
	gmplsTunnelDirection_forward_c = 0,
	gmplsTunnelDirection_bidirectional_c = 1,

	/* enums for column gmplsTunnelPathComp */
	gmplsTunnelPathComp_dynamicFull_c = 1,
	gmplsTunnelPathComp_explicit_c = 2,
	gmplsTunnelPathComp_dynamicPartial_c = 3,

	/* enums for column gmplsTunnelUpstreamNotifyRecipientType */
	gmplsTunnelUpstreamNotifyRecipientType_unknown_c = 0,
	gmplsTunnelUpstreamNotifyRecipientType_ipv4_c = 1,
	gmplsTunnelUpstreamNotifyRecipientType_ipv6_c = 2,
	gmplsTunnelUpstreamNotifyRecipientType_ipv4z_c = 3,
	gmplsTunnelUpstreamNotifyRecipientType_ipv6z_c = 4,
	gmplsTunnelUpstreamNotifyRecipientType_dns_c = 16,

	/* enums for column gmplsTunnelSendResvNotifyRecipientType */
	gmplsTunnelSendResvNotifyRecipientType_unknown_c = 0,
	gmplsTunnelSendResvNotifyRecipientType_ipv4_c = 1,
	gmplsTunnelSendResvNotifyRecipientType_ipv6_c = 2,
	gmplsTunnelSendResvNotifyRecipientType_ipv4z_c = 3,
	gmplsTunnelSendResvNotifyRecipientType_ipv6z_c = 4,
	gmplsTunnelSendResvNotifyRecipientType_dns_c = 16,

	/* enums for column gmplsTunnelDownstreamNotifyRecipientType */
	gmplsTunnelDownstreamNotifyRecipientType_unknown_c = 0,
	gmplsTunnelDownstreamNotifyRecipientType_ipv4_c = 1,
	gmplsTunnelDownstreamNotifyRecipientType_ipv6_c = 2,
	gmplsTunnelDownstreamNotifyRecipientType_ipv4z_c = 3,
	gmplsTunnelDownstreamNotifyRecipientType_ipv6z_c = 4,
	gmplsTunnelDownstreamNotifyRecipientType_dns_c = 16,

	/* enums for column gmplsTunnelSendPathNotifyRecipientType */
	gmplsTunnelSendPathNotifyRecipientType_unknown_c = 0,
	gmplsTunnelSendPathNotifyRecipientType_ipv4_c = 1,
	gmplsTunnelSendPathNotifyRecipientType_ipv6_c = 2,
	gmplsTunnelSendPathNotifyRecipientType_ipv4z_c = 3,
	gmplsTunnelSendPathNotifyRecipientType_ipv6z_c = 4,
	gmplsTunnelSendPathNotifyRecipientType_dns_c = 16,

	/* enums for column gmplsTunnelAdminStatusFlags */
	gmplsTunnelAdminStatusFlags_reflect_c = 0,
	gmplsTunnelAdminStatusFlags_reserved1_c = 1,
	gmplsTunnelAdminStatusFlags_reserved2_c = 2,
	gmplsTunnelAdminStatusFlags_reserved3_c = 3,
	gmplsTunnelAdminStatusFlags_reserved4_c = 4,
	gmplsTunnelAdminStatusFlags_reserved5_c = 5,
	gmplsTunnelAdminStatusFlags_reserved6_c = 6,
	gmplsTunnelAdminStatusFlags_reserved7_c = 7,
	gmplsTunnelAdminStatusFlags_reserved8_c = 8,
	gmplsTunnelAdminStatusFlags_reserved9_c = 9,
	gmplsTunnelAdminStatusFlags_reserved10_c = 10,
	gmplsTunnelAdminStatusFlags_reserved11_c = 11,
	gmplsTunnelAdminStatusFlags_reserved12_c = 12,
	gmplsTunnelAdminStatusFlags_reserved13_c = 13,
	gmplsTunnelAdminStatusFlags_reserved14_c = 14,
	gmplsTunnelAdminStatusFlags_reserved15_c = 15,
	gmplsTunnelAdminStatusFlags_reserved16_c = 16,
	gmplsTunnelAdminStatusFlags_reserved17_c = 17,
	gmplsTunnelAdminStatusFlags_reserved18_c = 18,
	gmplsTunnelAdminStatusFlags_reserved19_c = 19,
	gmplsTunnelAdminStatusFlags_reserved20_c = 20,
	gmplsTunnelAdminStatusFlags_reserved21_c = 21,
	gmplsTunnelAdminStatusFlags_reserved22_c = 22,
	gmplsTunnelAdminStatusFlags_oamFlowsEnabled_c = 23,
	gmplsTunnelAdminStatusFlags_oamAlarmsEnabled_c = 24,
	gmplsTunnelAdminStatusFlags_handover_c = 25,
	gmplsTunnelAdminStatusFlags_lockout_c = 26,
	gmplsTunnelAdminStatusFlags_inhibitAlarmCommunication_c = 27,
	gmplsTunnelAdminStatusFlags_callControl_c = 28,
	gmplsTunnelAdminStatusFlags_testing_c = 29,
	gmplsTunnelAdminStatusFlags_administrativelyDown_c = 30,
	gmplsTunnelAdminStatusFlags_deleteInProgress_c = 31,
};

/* table gmplsTunnelTable row entry data structure */
typedef struct gmplsTunnelEntry_t
{
	/* Index values */
// 	uint32_t u32Index;
// 	uint32_t u32Instance;
// 	uint32_t u32IngressLSRId;
// 	uint32_t u32EgressLSRId;
	
	/* Column values */
	uint8_t u8UnnumIf;
	uint8_t au8Attributes[1];
	int32_t i32LSPEncoding;
	int32_t i32SwitchingType;
	uint8_t au8LinkProtection[1];
	int32_t i32GPid;
	uint8_t u8Secondary;
	int32_t i32Direction;
	int32_t i32PathComp;
	int32_t i32UpstreamNotifyRecipientType;
	uint8_t au8UpstreamNotifyRecipient[20];
	size_t u16UpstreamNotifyRecipient_len;	/* # of uint8_t elements */
	int32_t i32SendResvNotifyRecipientType;
	uint8_t au8SendResvNotifyRecipient[20];
	size_t u16SendResvNotifyRecipient_len;	/* # of uint8_t elements */
	int32_t i32DownstreamNotifyRecipientType;
	uint8_t au8DownstreamNotifyRecipient[20];
	size_t u16DownstreamNotifyRecipient_len;	/* # of uint8_t elements */
	int32_t i32SendPathNotifyRecipientType;
	uint8_t au8SendPathNotifyRecipient[20];
	size_t u16SendPathNotifyRecipient_len;	/* # of uint8_t elements */
	uint8_t au8AdminStatusFlags[4];
	
// 	xBTree_Node_t oBTreeNode;
} gmplsTunnelEntry_t;

// extern xBTree_t oGmplsTunnelTable_BTree;

/* gmplsTunnelTable table mapper */
void gmplsTunnelTable_init (void);
gmplsTunnelEntry_t * gmplsTunnelTable_createEntry (
	uint32_t u32Index,
	uint32_t u32Instance,
	uint32_t u32IngressLSRId,
	uint32_t u32EgressLSRId);
gmplsTunnelEntry_t * gmplsTunnelTable_getByIndex (
	uint32_t u32Index,
	uint32_t u32Instance,
	uint32_t u32IngressLSRId,
	uint32_t u32EgressLSRId);
gmplsTunnelEntry_t * gmplsTunnelTable_getNextIndex (
	uint32_t u32Index,
	uint32_t u32Instance,
	uint32_t u32IngressLSRId,
	uint32_t u32EgressLSRId);
void gmplsTunnelTable_removeEntry (gmplsTunnelEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point gmplsTunnelTable_getFirst;
Netsnmp_Next_Data_Point gmplsTunnelTable_getNext;
Netsnmp_Get_Data_Point gmplsTunnelTable_get;
Netsnmp_Node_Handler gmplsTunnelTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table gmplsTunnelHopTable definitions
 */
#define GMPLSTUNNELHOPLABELSTATUSES 1

enum
{
	/* enums for column gmplsTunnelHopLabelStatuses */
	gmplsTunnelHopLabelStatuses_forwardPresent_c = 0,
	gmplsTunnelHopLabelStatuses_reversePresent_c = 1,
};

/* table gmplsTunnelHopTable row entry data structure */
typedef struct gmplsTunnelHopEntry_t
{
	/* Index values */
// 	uint32_t u32ListIndex;
// 	uint32_t u32PathOptionIndex;
// 	uint32_t u32Index;
	
	/* Column values */
	uint8_t au8LabelStatuses[1];
	
// 	xBTree_Node_t oBTreeNode;
} gmplsTunnelHopEntry_t;

// extern xBTree_t oGmplsTunnelHopTable_BTree;

/* gmplsTunnelHopTable table mapper */
void gmplsTunnelHopTable_init (void);
gmplsTunnelHopEntry_t * gmplsTunnelHopTable_createEntry (
	uint32_t u32ListIndex,
	uint32_t u32PathOptionIndex,
	uint32_t u32Index);
gmplsTunnelHopEntry_t * gmplsTunnelHopTable_getByIndex (
	uint32_t u32ListIndex,
	uint32_t u32PathOptionIndex,
	uint32_t u32Index);
gmplsTunnelHopEntry_t * gmplsTunnelHopTable_getNextIndex (
	uint32_t u32ListIndex,
	uint32_t u32PathOptionIndex,
	uint32_t u32Index);
void gmplsTunnelHopTable_removeEntry (gmplsTunnelHopEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point gmplsTunnelHopTable_getFirst;
Netsnmp_Next_Data_Point gmplsTunnelHopTable_getNext;
Netsnmp_Get_Data_Point gmplsTunnelHopTable_get;
Netsnmp_Node_Handler gmplsTunnelHopTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table gmplsTunnelARHopTable definitions
 */
#define GMPLSTUNNELARHOPLABELSTATUSES 1
#define GMPLSTUNNELARHOPPROTECTION 6

enum
{
	/* enums for column gmplsTunnelARHopLabelStatuses */
	gmplsTunnelARHopLabelStatuses_forwardPresent_c = 0,
	gmplsTunnelARHopLabelStatuses_reversePresent_c = 1,
	gmplsTunnelARHopLabelStatuses_forwardGlobal_c = 2,
	gmplsTunnelARHopLabelStatuses_reverseGlobal_c = 3,

	/* enums for column gmplsTunnelARHopProtection */
	gmplsTunnelARHopProtection_localAvailable_c = 0,
	gmplsTunnelARHopProtection_localInUse_c = 1,
};

/* table gmplsTunnelARHopTable row entry data structure */
typedef struct gmplsTunnelARHopEntry_t
{
	/* Index values */
// 	uint32_t u32ListIndex;
// 	uint32_t u32Index;
	
	/* Column values */
	uint8_t au8LabelStatuses[1];
	uint8_t au8Protection[1];
	
// 	xBTree_Node_t oBTreeNode;
} gmplsTunnelARHopEntry_t;

// extern xBTree_t oGmplsTunnelARHopTable_BTree;

/* gmplsTunnelARHopTable table mapper */
void gmplsTunnelARHopTable_init (void);
gmplsTunnelARHopEntry_t * gmplsTunnelARHopTable_createEntry (
	uint32_t u32ListIndex,
	uint32_t u32Index);
gmplsTunnelARHopEntry_t * gmplsTunnelARHopTable_getByIndex (
	uint32_t u32ListIndex,
	uint32_t u32Index);
gmplsTunnelARHopEntry_t * gmplsTunnelARHopTable_getNextIndex (
	uint32_t u32ListIndex,
	uint32_t u32Index);
void gmplsTunnelARHopTable_removeEntry (gmplsTunnelARHopEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point gmplsTunnelARHopTable_getFirst;
Netsnmp_Next_Data_Point gmplsTunnelARHopTable_getNext;
Netsnmp_Get_Data_Point gmplsTunnelARHopTable_get;
Netsnmp_Node_Handler gmplsTunnelARHopTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table gmplsTunnelCHopTable definitions
 */
#define GMPLSTUNNELCHOPLABELSTATUSES 1

enum
{
	/* enums for column gmplsTunnelCHopLabelStatuses */
	gmplsTunnelCHopLabelStatuses_forwardPresent_c = 0,
	gmplsTunnelCHopLabelStatuses_reversePresent_c = 1,
};

/* table gmplsTunnelCHopTable row entry data structure */
typedef struct gmplsTunnelCHopEntry_t
{
	/* Index values */
// 	uint32_t u32ListIndex;
// 	uint32_t u32Index;
	
	/* Column values */
	uint8_t au8LabelStatuses[1];
	
// 	xBTree_Node_t oBTreeNode;
} gmplsTunnelCHopEntry_t;

// extern xBTree_t oGmplsTunnelCHopTable_BTree;

/* gmplsTunnelCHopTable table mapper */
void gmplsTunnelCHopTable_init (void);
gmplsTunnelCHopEntry_t * gmplsTunnelCHopTable_createEntry (
	uint32_t u32ListIndex,
	uint32_t u32Index);
gmplsTunnelCHopEntry_t * gmplsTunnelCHopTable_getByIndex (
	uint32_t u32ListIndex,
	uint32_t u32Index);
gmplsTunnelCHopEntry_t * gmplsTunnelCHopTable_getNextIndex (
	uint32_t u32ListIndex,
	uint32_t u32Index);
void gmplsTunnelCHopTable_removeEntry (gmplsTunnelCHopEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point gmplsTunnelCHopTable_getFirst;
Netsnmp_Next_Data_Point gmplsTunnelCHopTable_getNext;
Netsnmp_Get_Data_Point gmplsTunnelCHopTable_get;
Netsnmp_Node_Handler gmplsTunnelCHopTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table gmplsTunnelReversePerfTable definitions
 */
#define GMPLSTUNNELREVERSEPERFPACKETS 1
#define GMPLSTUNNELREVERSEPERFHCPACKETS 2
#define GMPLSTUNNELREVERSEPERFERRORS 3
#define GMPLSTUNNELREVERSEPERFBYTES 4
#define GMPLSTUNNELREVERSEPERFHCBYTES 5

/* table gmplsTunnelReversePerfTable row entry data structure */
typedef struct gmplsTunnelReversePerfEntry_t
{
	/* Index values */
// 	uint32_t u32Index;
// 	uint32_t u32Instance;
// 	uint32_t u32IngressLSRId;
// 	uint32_t u32EgressLSRId;
	
	/* Column values */
	uint32_t u32Packets;
	uint64_t u64HCPackets;
	uint32_t u32Errors;
	uint32_t u32Bytes;
	uint64_t u64HCBytes;
	
// 	xBTree_Node_t oBTreeNode;
} gmplsTunnelReversePerfEntry_t;

// extern xBTree_t oGmplsTunnelReversePerfTable_BTree;

/* gmplsTunnelReversePerfTable table mapper */
void gmplsTunnelReversePerfTable_init (void);
gmplsTunnelReversePerfEntry_t * gmplsTunnelReversePerfTable_createEntry (
	uint32_t u32Index,
	uint32_t u32Instance,
	uint32_t u32IngressLSRId,
	uint32_t u32EgressLSRId);
gmplsTunnelReversePerfEntry_t * gmplsTunnelReversePerfTable_getByIndex (
	uint32_t u32Index,
	uint32_t u32Instance,
	uint32_t u32IngressLSRId,
	uint32_t u32EgressLSRId);
gmplsTunnelReversePerfEntry_t * gmplsTunnelReversePerfTable_getNextIndex (
	uint32_t u32Index,
	uint32_t u32Instance,
	uint32_t u32IngressLSRId,
	uint32_t u32EgressLSRId);
void gmplsTunnelReversePerfTable_removeEntry (gmplsTunnelReversePerfEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point gmplsTunnelReversePerfTable_getFirst;
Netsnmp_Next_Data_Point gmplsTunnelReversePerfTable_getNext;
Netsnmp_Get_Data_Point gmplsTunnelReversePerfTable_get;
Netsnmp_Node_Handler gmplsTunnelReversePerfTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table gmplsTunnelErrorTable definitions
 */
#define GMPLSTUNNELERRORLASTERRORTYPE 1
#define GMPLSTUNNELERRORLASTTIME 2
#define GMPLSTUNNELERRORREPORTERTYPE 3
#define GMPLSTUNNELERRORREPORTER 4
#define GMPLSTUNNELERRORCODE 5
#define GMPLSTUNNELERRORSUBCODE 6
#define GMPLSTUNNELERRORTLVS 7
#define GMPLSTUNNELERRORHELPSTRING 8

enum
{
	/* enums for column gmplsTunnelErrorLastErrorType */
	gmplsTunnelErrorLastErrorType_noError_c = 0,
	gmplsTunnelErrorLastErrorType_unknown_c = 1,
	gmplsTunnelErrorLastErrorType_protocol_c = 2,
	gmplsTunnelErrorLastErrorType_pathComputation_c = 3,
	gmplsTunnelErrorLastErrorType_localConfiguration_c = 4,
	gmplsTunnelErrorLastErrorType_localResources_c = 5,
	gmplsTunnelErrorLastErrorType_localOther_c = 6,

	/* enums for column gmplsTunnelErrorReporterType */
	gmplsTunnelErrorReporterType_unknown_c = 0,
	gmplsTunnelErrorReporterType_ipv4_c = 1,
	gmplsTunnelErrorReporterType_ipv6_c = 2,
	gmplsTunnelErrorReporterType_ipv4z_c = 3,
	gmplsTunnelErrorReporterType_ipv6z_c = 4,
	gmplsTunnelErrorReporterType_dns_c = 16,
};

/* table gmplsTunnelErrorTable row entry data structure */
typedef struct gmplsTunnelErrorEntry_t
{
	/* Index values */
	uint32_t u32Index;
	uint32_t u32Instance;
	uint32_t u32IngressLSRId;
	uint32_t u32EgressLSRId;
	
	/* Column values */
	int32_t i32LastErrorType;
	uint32_t u32LastTime;
	int32_t i32ReporterType;
	uint8_t au8Reporter[255];
	size_t u16Reporter_len;	/* # of uint8_t elements */
	uint32_t u32Code;
	uint32_t u32Subcode;
	uint8_t au8TLVs[65535];
	size_t u16TLVs_len;	/* # of uint8_t elements */
	uint8_t au8HelpString[255];
	size_t u16HelpString_len;	/* # of uint8_t elements */
	
	xBTree_Node_t oBTreeNode;
} gmplsTunnelErrorEntry_t;

extern xBTree_t oGmplsTunnelErrorTable_BTree;

/* gmplsTunnelErrorTable table mapper */
void gmplsTunnelErrorTable_init (void);
gmplsTunnelErrorEntry_t * gmplsTunnelErrorTable_createEntry (
	uint32_t u32Index,
	uint32_t u32Instance,
	uint32_t u32IngressLSRId,
	uint32_t u32EgressLSRId);
gmplsTunnelErrorEntry_t * gmplsTunnelErrorTable_getByIndex (
	uint32_t u32Index,
	uint32_t u32Instance,
	uint32_t u32IngressLSRId,
	uint32_t u32EgressLSRId);
gmplsTunnelErrorEntry_t * gmplsTunnelErrorTable_getNextIndex (
	uint32_t u32Index,
	uint32_t u32Instance,
	uint32_t u32IngressLSRId,
	uint32_t u32EgressLSRId);
void gmplsTunnelErrorTable_removeEntry (gmplsTunnelErrorEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point gmplsTunnelErrorTable_getFirst;
Netsnmp_Next_Data_Point gmplsTunnelErrorTable_getNext;
Netsnmp_Get_Data_Point gmplsTunnelErrorTable_get;
Netsnmp_Node_Handler gmplsTunnelErrorTable_mapper;
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
#define MPLSTUNNELSIGNALLINGPROTO 12
#define MPLSTUNNELSETUPPRIO 13
#define MPLSTUNNELHOLDINGPRIO 14
#define MPLSTUNNELSESSIONATTRIBUTES 15
#define MPLSTUNNELLOCALPROTECTINUSE 16
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
	
	struct {
		uint8_t au8XCIndex[24];
		size_t u16XCIndex_len;
	} oK;
	
	/* Column values */
	uint8_t au8Name[32];
	size_t u16Name_len;	/* # of uint8_t elements */
	uint8_t au8Descr[64];
	size_t u16Descr_len;	/* # of uint8_t elements */
	uint8_t u8IsIf;
	uint32_t u32IfIndex;
	int32_t i32Owner;
	int32_t i32Role;
	int32_t i32SignallingProto;
	int32_t i32SetupPrio;
	int32_t i32HoldingPrio;
	uint8_t au8SessionAttributes[1];
	uint8_t u8LocalProtectInUse;
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
	
	mplsTunnelPerfEntry_t oPerf;
	mplsTunnelExtEntry_t oX;
	gmplsTunnelEntry_t oG;
	gmplsTunnelReversePerfEntry_t oReversePerf;
	gmplsTunnelErrorEntry_t oError;
	neMplsTunnelEntry_t oNe;
	
	xBTree_Node_t oBTreeNode;
	xBTree_Node_t oXC_BTreeNode;
} mplsTunnelEntry_t;

extern xBTree_t oMplsTunnelTable_BTree;
extern xBTree_t oMplsTunnelTable_XC_BTree;

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
mplsTunnelEntry_t * mplsTunnelTable_XC_getByIndex (
	uint8_t *pau8XCIndex, size_t u16XCIndex_len);
mplsTunnelEntry_t * mplsTunnelTable_getNextIndex (
	uint32_t u32Index,
	uint32_t u32Instance,
	uint32_t u32IngressLSRId,
	uint32_t u32EgressLSRId);
void mplsTunnelTable_removeEntry (mplsTunnelEntry_t *poEntry);
mplsTunnelEntry_t * mplsTunnelTable_createExt (
	uint32_t u32Index,
	uint32_t u32Instance,
	uint32_t u32IngressLSRId,
	uint32_t u32EgressLSRId);
bool mplsTunnelTable_removeExt (mplsTunnelEntry_t *poEntry);
bool mplsTunnelTable_createHier (mplsTunnelEntry_t *poEntry);
bool mplsTunnelTable_removeHier (mplsTunnelEntry_t *poEntry);
bool mplsTunnelRowStatus_handler (
	mplsTunnelEntry_t *poEntry, uint8_t u8RowStatus);
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
#define MPLSTUNNELHOPADDRESS 5
#define MPLSTUNNELHOPPREFIX 6
#define MPLSTUNNELHOPADDRUNNUM 8
#define MPLSTUNNELHOPTYPE 10
#define MPLSTUNNELHOPINCLUDE 11
#define MPLSTUNNELHOPPATHOPTIONNAME 12
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
	uint8_t au8Address[32];
	size_t u16Address_len;	/* # of uint8_t elements */
	uint32_t u32Prefix;
	uint8_t au8Unnum[4];
	size_t u16Unnum_len;	/* # of uint8_t elements */
	int32_t i32Type;
	uint8_t u8Include;
	uint8_t au8PathOptionName[255];
	size_t u16PathOptionName_len;	/* # of uint8_t elements */
	uint8_t u8RowStatus;
	uint8_t u8StorageType;
	
	gmplsTunnelHopEntry_t oG;
	neMplsTunnelHopEntry_t oNe;
	
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
#define MPLSTUNNELARHOPADDRESS 4
#define MPLSTUNNELARHOPADDRUNNUM 5

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
	uint8_t au8Address[32];
	size_t u16Address_len;	/* # of uint8_t elements */
	uint8_t au8Unnum[4];
	size_t u16Unnum_len;	/* # of uint8_t elements */
	
	gmplsTunnelARHopEntry_t oG;
	neMplsTunnelARHopEntry_t oNe;
	
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
#define MPLSTUNNELCHOPADDRESS 4
#define MPLSTUNNELCHOPPREFIX 5
#define MPLSTUNNELCHOPADDRUNNUM 7
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
	uint8_t au8Address[32];
	size_t u16Address_len;	/* # of uint8_t elements */
	uint32_t u32Prefix;
	uint8_t au8Unnum[4];
	size_t u16Unnum_len;	/* # of uint8_t elements */
	int32_t i32Type;
	
	gmplsTunnelCHopEntry_t oG;
	neMplsTunnelCHopEntry_t oNe;
	
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


/* definitions for notification(s) of gmplsTeNotifications */
#	define GMPLSTUNNELDOWN 1

/* gmplsTeNotifications mapper(s) */
int gmplsTunnelDown_trap (void);



#	ifdef __cplusplus
}
#	endif

#endif /* __MPLSTESTDMIB_H__ */
