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

#ifndef __MPLSLSRSTDMIB_H__
#	define __MPLSLSRSTDMIB_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include "mplsLsrExtStdMIB.h"
#include "neMplsLsrMIB.h"

#include "lib/binaryTree.h"
#include "lib/snmp.h"

#include <stdbool.h>
#include <stdint.h>

#define TOBE_REPLACED 1


/**
 *	agent MIB function
 */
void mplsLsrStdMIB_init (void);


/**
 *	scalar mapper(s)
 */
/** definitions for scalar(s) of mplsLsrObjects **/
#define MPLSINSEGMENTINDEXNEXT 3
#define MPLSOUTSEGMENTINDEXNEXT 6
#define MPLSXCINDEXNEXT 9
#define MPLSMAXLABELSTACKDEPTH 11
#define MPLSLABELSTACKINDEXNEXT 12
#define MPLSXCNOTIFICATIONSENABLE 15

enum
{
	/* enums for scalar mplsXCNotificationsEnable */
	mplsXCNotificationsEnable_true_c = 1,
	mplsXCNotificationsEnable_false_c = 2,
};

typedef struct mplsLsrObjects_t
{
	uint8_t au8InSegmentIndexNext[24];
	size_t u16InSegmentIndexNext_len;	/* # of uint8_t elements */
	uint8_t au8OutSegmentIndexNext[24];
	size_t u16OutSegmentIndexNext_len;	/* # of uint8_t elements */
	uint8_t au8XCIndexNext[24];
	size_t u16XCIndexNext_len;	/* # of uint8_t elements */
	uint32_t u32MaxLabelStackDepth;
	uint8_t au8LabelStackIndexNext[24];
	size_t u16LabelStackIndexNext_len;	/* # of uint8_t elements */
	uint8_t u8XCNotificationsEnable;
} mplsLsrObjects_t;

extern mplsLsrObjects_t oMplsLsrObjects;

#ifdef SNMP_SRC
Netsnmp_Node_Handler mplsLsrObjects_mapper;
#endif	/* SNMP_SRC */



/**
 *	table mapper(s)
 */
/**
 *	table mplsInterfacePerfTable definitions
 */
#define MPLSINTERFACEPERFINLABELSINUSE 1
#define MPLSINTERFACEPERFINLABELLOOKUPFAILURES 2
#define MPLSINTERFACEPERFOUTLABELSINUSE 3
#define MPLSINTERFACEPERFOUTFRAGMENTEDPKTS 4

/* table mplsInterfacePerfTable row entry data structure */
typedef struct mplsInterfacePerfEntry_t
{
	/* Index values */
// 	uint32_t u32Index;
	
	/* Column values */
	uint32_t u32InLabelsInUse;
	uint32_t u32InLabelLookupFailures;
	uint32_t u32OutLabelsInUse;
	uint32_t u32OutFragmentedPkts;
	
// 	xBTree_Node_t oBTreeNode;
} mplsInterfacePerfEntry_t;

// extern xBTree_t oMplsInterfacePerfTable_BTree;

/* mplsInterfacePerfTable table mapper */
void mplsInterfacePerfTable_init (void);
mplsInterfacePerfEntry_t * mplsInterfacePerfTable_createEntry (
	uint32_t u32Index);
mplsInterfacePerfEntry_t * mplsInterfacePerfTable_getByIndex (
	uint32_t u32Index);
mplsInterfacePerfEntry_t * mplsInterfacePerfTable_getNextIndex (
	uint32_t u32Index);
void mplsInterfacePerfTable_removeEntry (mplsInterfacePerfEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point mplsInterfacePerfTable_getFirst;
Netsnmp_Next_Data_Point mplsInterfacePerfTable_getNext;
Netsnmp_Get_Data_Point mplsInterfacePerfTable_get;
Netsnmp_Node_Handler mplsInterfacePerfTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table mplsInSegmentPerfTable definitions
 */
#define MPLSINSEGMENTPERFOCTETS 1
#define MPLSINSEGMENTPERFPACKETS 2
#define MPLSINSEGMENTPERFERRORS 3
#define MPLSINSEGMENTPERFDISCARDS 4
#define MPLSINSEGMENTPERFHCOCTETS 5
#define MPLSINSEGMENTPERFDISCONTINUITYTIME 6

/* table mplsInSegmentPerfTable row entry data structure */
typedef struct mplsInSegmentPerfEntry_t
{
	/* Index values */
// 	uint8_t au8Index[24];
// 	size_t u16Index_len;	/* # of uint8_t elements */
	
	/* Column values */
	uint32_t u32Octets;
	uint32_t u32Packets;
	uint32_t u32Errors;
	uint32_t u32Discards;
	uint64_t u64HCOctets;
	uint32_t u32DiscontinuityTime;
	
// 	xBTree_Node_t oBTreeNode;
} mplsInSegmentPerfEntry_t;

// extern xBTree_t oMplsInSegmentPerfTable_BTree;

/* mplsInSegmentPerfTable table mapper */
void mplsInSegmentPerfTable_init (void);
mplsInSegmentPerfEntry_t * mplsInSegmentPerfTable_createEntry (
	uint8_t *pau8Index, size_t u16Index_len);
mplsInSegmentPerfEntry_t * mplsInSegmentPerfTable_getByIndex (
	uint8_t *pau8Index, size_t u16Index_len);
mplsInSegmentPerfEntry_t * mplsInSegmentPerfTable_getNextIndex (
	uint8_t *pau8Index, size_t u16Index_len);
void mplsInSegmentPerfTable_removeEntry (mplsInSegmentPerfEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point mplsInSegmentPerfTable_getFirst;
Netsnmp_Next_Data_Point mplsInSegmentPerfTable_getNext;
Netsnmp_Get_Data_Point mplsInSegmentPerfTable_get;
Netsnmp_Node_Handler mplsInSegmentPerfTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table mplsOutSegmentPerfTable definitions
 */
#define MPLSOUTSEGMENTPERFOCTETS 1
#define MPLSOUTSEGMENTPERFPACKETS 2
#define MPLSOUTSEGMENTPERFERRORS 3
#define MPLSOUTSEGMENTPERFDISCARDS 4
#define MPLSOUTSEGMENTPERFHCOCTETS 5
#define MPLSOUTSEGMENTPERFDISCONTINUITYTIME 6

/* table mplsOutSegmentPerfTable row entry data structure */
typedef struct mplsOutSegmentPerfEntry_t
{
	/* Index values */
	uint8_t au8Index[24];
	size_t u16Index_len;	/* # of uint8_t elements */
	
	/* Column values */
	uint32_t u32Octets;
	uint32_t u32Packets;
	uint32_t u32Errors;
	uint32_t u32Discards;
	uint64_t u64HCOctets;
	uint32_t u32DiscontinuityTime;
	
	xBTree_Node_t oBTreeNode;
} mplsOutSegmentPerfEntry_t;

extern xBTree_t oMplsOutSegmentPerfTable_BTree;

/* mplsOutSegmentPerfTable table mapper */
void mplsOutSegmentPerfTable_init (void);
mplsOutSegmentPerfEntry_t * mplsOutSegmentPerfTable_createEntry (
	uint8_t *pau8Index, size_t u16Index_len);
mplsOutSegmentPerfEntry_t * mplsOutSegmentPerfTable_getByIndex (
	uint8_t *pau8Index, size_t u16Index_len);
mplsOutSegmentPerfEntry_t * mplsOutSegmentPerfTable_getNextIndex (
	uint8_t *pau8Index, size_t u16Index_len);
void mplsOutSegmentPerfTable_removeEntry (mplsOutSegmentPerfEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point mplsOutSegmentPerfTable_getFirst;
Netsnmp_Next_Data_Point mplsOutSegmentPerfTable_getNext;
Netsnmp_Get_Data_Point mplsOutSegmentPerfTable_get;
Netsnmp_Node_Handler mplsOutSegmentPerfTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table mplsLabelStackTable definitions
 */
#define MPLSLABELSTACKINDEX 1
#define MPLSLABELSTACKLABELINDEX 2
#define MPLSLABELSTACKLABEL 3
#define MPLSLABELSTACKLABELPTR 4
#define MPLSLABELSTACKROWSTATUS 5
#define MPLSLABELSTACKSTORAGETYPE 6

enum
{
	/* enums for column mplsLabelStackRowStatus */
	mplsLabelStackRowStatus_active_c = 1,
	mplsLabelStackRowStatus_notInService_c = 2,
	mplsLabelStackRowStatus_notReady_c = 3,
	mplsLabelStackRowStatus_createAndGo_c = 4,
	mplsLabelStackRowStatus_createAndWait_c = 5,
	mplsLabelStackRowStatus_destroy_c = 6,

	/* enums for column mplsLabelStackStorageType */
	mplsLabelStackStorageType_other_c = 1,
	mplsLabelStackStorageType_volatile_c = 2,
	mplsLabelStackStorageType_nonVolatile_c = 3,
	mplsLabelStackStorageType_permanent_c = 4,
	mplsLabelStackStorageType_readOnly_c = 5,
};

/* table mplsLabelStackTable row entry data structure */
typedef struct mplsLabelStackEntry_t
{
	/* Index values */
	uint8_t au8Index[24];
	size_t u16Index_len;	/* # of uint8_t elements */
	uint32_t u32LabelIndex;
	
	/* Column values */
	uint32_t u32Label;
	xOid_t aoLabelPtr[128];
	size_t u16LabelPtr_len;	/* # of xOid_t elements */
	uint8_t u8RowStatus;
	uint8_t u8StorageType;
	
	neMplsLabelStackEntry_t oNe;
	
	xBTree_Node_t oBTreeNode;
} mplsLabelStackEntry_t;

extern xBTree_t oMplsLabelStackTable_BTree;

/* mplsLabelStackTable table mapper */
void mplsLabelStackTable_init (void);
mplsLabelStackEntry_t * mplsLabelStackTable_createEntry (
	uint8_t *pau8Index, size_t u16Index_len,
	uint32_t u32LabelIndex);
mplsLabelStackEntry_t * mplsLabelStackTable_getByIndex (
	uint8_t *pau8Index, size_t u16Index_len,
	uint32_t u32LabelIndex);
mplsLabelStackEntry_t * mplsLabelStackTable_getNextIndex (
	uint8_t *pau8Index, size_t u16Index_len,
	uint32_t u32LabelIndex);
void mplsLabelStackTable_removeEntry (mplsLabelStackEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point mplsLabelStackTable_getFirst;
Netsnmp_Next_Data_Point mplsLabelStackTable_getNext;
Netsnmp_Get_Data_Point mplsLabelStackTable_get;
Netsnmp_Node_Handler mplsLabelStackTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table gmplsInterfaceTable definitions
 */
#define GMPLSINTERFACESIGNALINGCAPS 1
#define GMPLSINTERFACERSVPHELLOPERIOD 2

enum
{
	/* enums for column gmplsInterfaceSignalingCaps */
	gmplsInterfaceSignalingCaps_unknown_c = 0,
	gmplsInterfaceSignalingCaps_rsvpGmpls_c = 1,
	gmplsInterfaceSignalingCaps_crldpGmpls_c = 2,
	gmplsInterfaceSignalingCaps_otherGmpls_c = 3,
};

/* table gmplsInterfaceTable row entry data structure */
typedef struct gmplsInterfaceEntry_t
{
	/* Index values */
	uint32_t u32Index;
	
	/* Column values */
	uint8_t au8SignalingCaps[1];
	size_t u16SignalingCaps_len;	/* # of uint8_t elements */
	uint32_t u32RsvpHelloPeriod;
	
	xBTree_Node_t oBTreeNode;
} gmplsInterfaceEntry_t;

extern xBTree_t oGmplsInterfaceTable_BTree;

/* gmplsInterfaceTable table mapper */
void gmplsInterfaceTable_init (void);
gmplsInterfaceEntry_t * gmplsInterfaceTable_createEntry (
	uint32_t u32Index);
gmplsInterfaceEntry_t * gmplsInterfaceTable_getByIndex (
	uint32_t u32Index);
gmplsInterfaceEntry_t * gmplsInterfaceTable_getNextIndex (
	uint32_t u32Index);
void gmplsInterfaceTable_removeEntry (gmplsInterfaceEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point gmplsInterfaceTable_getFirst;
Netsnmp_Next_Data_Point gmplsInterfaceTable_getNext;
Netsnmp_Get_Data_Point gmplsInterfaceTable_get;
Netsnmp_Node_Handler gmplsInterfaceTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table gmplsInSegmentTable definitions
 */
#define GMPLSINSEGMENTDIRECTION 1
#define GMPLSINSEGMENTEXTRAPARAMSPTR 2

enum
{
	/* enums for column gmplsInSegmentDirection */
	gmplsInSegmentDirection_forward_c = 1,
	gmplsInSegmentDirection_reverse_c = 2,
};

/* table gmplsInSegmentTable row entry data structure */
typedef struct gmplsInSegmentEntry_t
{
	/* Index values */
// 	uint8_t au8Index[24];
// 	size_t u16Index_len;	/* # of uint8_t elements */
	
	/* Column values */
	int32_t i32Direction;
	xOid_t aoExtraParamsPtr[128];
	size_t u16ExtraParamsPtr_len;	/* # of xOid_t elements */
	
// 	xBTree_Node_t oBTreeNode;
} gmplsInSegmentEntry_t;

// extern xBTree_t oGmplsInSegmentTable_BTree;

/* gmplsInSegmentTable table mapper */
void gmplsInSegmentTable_init (void);
gmplsInSegmentEntry_t * gmplsInSegmentTable_createEntry (
	uint8_t *pau8Index, size_t u16Index_len);
gmplsInSegmentEntry_t * gmplsInSegmentTable_getByIndex (
	uint8_t *pau8Index, size_t u16Index_len);
gmplsInSegmentEntry_t * gmplsInSegmentTable_getNextIndex (
	uint8_t *pau8Index, size_t u16Index_len);
void gmplsInSegmentTable_removeEntry (gmplsInSegmentEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point gmplsInSegmentTable_getFirst;
Netsnmp_Next_Data_Point gmplsInSegmentTable_getNext;
Netsnmp_Get_Data_Point gmplsInSegmentTable_get;
Netsnmp_Node_Handler gmplsInSegmentTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table gmplsOutSegmentTable definitions
 */
#define GMPLSOUTSEGMENTDIRECTION 1
#define GMPLSOUTSEGMENTTTLDECREMENT 2
#define GMPLSOUTSEGMENTEXTRAPARAMSPTR 3

enum
{
	/* enums for column gmplsOutSegmentDirection */
	gmplsOutSegmentDirection_forward_c = 1,
	gmplsOutSegmentDirection_reverse_c = 2,
};

/* table gmplsOutSegmentTable row entry data structure */
typedef struct gmplsOutSegmentEntry_t
{
	/* Index values */
	uint8_t au8Index[24];
	size_t u16Index_len;	/* # of uint8_t elements */
	
	/* Column values */
	int32_t i32Direction;
	uint32_t u32TTLDecrement;
	xOid_t aoExtraParamsPtr[128];
	size_t u16ExtraParamsPtr_len;	/* # of xOid_t elements */
	
	xBTree_Node_t oBTreeNode;
} gmplsOutSegmentEntry_t;

extern xBTree_t oGmplsOutSegmentTable_BTree;

/* gmplsOutSegmentTable table mapper */
void gmplsOutSegmentTable_init (void);
gmplsOutSegmentEntry_t * gmplsOutSegmentTable_createEntry (
	uint8_t *pau8Index, size_t u16Index_len);
gmplsOutSegmentEntry_t * gmplsOutSegmentTable_getByIndex (
	uint8_t *pau8Index, size_t u16Index_len);
gmplsOutSegmentEntry_t * gmplsOutSegmentTable_getNextIndex (
	uint8_t *pau8Index, size_t u16Index_len);
void gmplsOutSegmentTable_removeEntry (gmplsOutSegmentEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point gmplsOutSegmentTable_getFirst;
Netsnmp_Next_Data_Point gmplsOutSegmentTable_getNext;
Netsnmp_Get_Data_Point gmplsOutSegmentTable_get;
Netsnmp_Node_Handler gmplsOutSegmentTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table mplsInterfaceTable definitions
 */
#define MPLSINTERFACEINDEX 1
#define MPLSINTERFACELABELMININ 2
#define MPLSINTERFACELABELMAXIN 3
#define MPLSINTERFACELABELMINOUT 4
#define MPLSINTERFACELABELMAXOUT 5
#define MPLSINTERFACETOTALBANDWIDTH 6
#define MPLSINTERFACEAVAILABLEBANDWIDTH 7
#define MPLSINTERFACELABELPARTICIPATIONTYPE 8

enum
{
	/* enums for column mplsInterfaceLabelParticipationType */
	mplsInterfaceLabelParticipationType_perPlatform_c = 0,
	mplsInterfaceLabelParticipationType_perInterface_c = 1,
};

/* table mplsInterfaceTable row entry data structure */
typedef struct mplsInterfaceEntry_t
{
	/* Index values */
	uint32_t u32Index;
	
	/* Column values */
	uint32_t u32LabelMinIn;
	uint32_t u32LabelMaxIn;
	uint32_t u32LabelMinOut;
	uint32_t u32LabelMaxOut;
	uint32_t u32TotalBandwidth;
	uint32_t u32AvailableBandwidth;
	uint8_t au8LabelParticipationType[1];
	size_t u16LabelParticipationType_len;	/* # of uint8_t elements */
	
	mplsInterfacePerfEntry_t oPerf;
	gmplsInterfaceEntry_t oG;
	
	int32_t i32Mtu;
	uint8_t u8AdminStatus;
	uint8_t u8OperStatus;
	uint8_t au8AdminFlags[3];
	uint8_t au8OperFlags[3];
	uint8_t au8Speed[8];
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} mplsInterfaceEntry_t;

extern xBTree_t oMplsInterfaceTable_BTree;

/* mplsInterfaceTable table mapper */
void mplsInterfaceTable_init (void);
mplsInterfaceEntry_t * mplsInterfaceTable_createEntry (
	uint32_t u32Index);
mplsInterfaceEntry_t * mplsInterfaceTable_getByIndex (
	uint32_t u32Index);
mplsInterfaceEntry_t * mplsInterfaceTable_getNextIndex (
	uint32_t u32Index);
void mplsInterfaceTable_removeEntry (mplsInterfaceEntry_t *poEntry);
mplsInterfaceEntry_t * mplsInterfaceTable_createExt (
	uint32_t u32Index);
bool mplsInterfaceTable_removeExt (mplsInterfaceEntry_t *poEntry);
bool mplsInterfaceTable_createHier (mplsInterfaceEntry_t *poEntry);
bool mplsInterfaceTable_removeHier (mplsInterfaceEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point mplsInterfaceTable_getFirst;
Netsnmp_Next_Data_Point mplsInterfaceTable_getNext;
Netsnmp_Get_Data_Point mplsInterfaceTable_get;
Netsnmp_Node_Handler mplsInterfaceTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table mplsInSegmentTable definitions
 */
#define MPLSINSEGMENTINDEX 1
#define MPLSINSEGMENTINTERFACE 2
#define MPLSINSEGMENTLABEL 3
#define MPLSINSEGMENTLABELPTR 4
#define MPLSINSEGMENTNPOP 5
#define MPLSINSEGMENTADDRFAMILY 6
#define MPLSINSEGMENTXCINDEX 7
#define MPLSINSEGMENTOWNER 8
#define MPLSINSEGMENTTRAFFICPARAMPTR 9
#define MPLSINSEGMENTROWSTATUS 10
#define MPLSINSEGMENTSTORAGETYPE 11

enum
{
	/* enums for column mplsInSegmentAddrFamily */
	mplsInSegmentAddrFamily_other_c = 0,
	mplsInSegmentAddrFamily_ipV4_c = 1,
	mplsInSegmentAddrFamily_ipV6_c = 2,
	mplsInSegmentAddrFamily_nsap_c = 3,
	mplsInSegmentAddrFamily_hdlc_c = 4,
	mplsInSegmentAddrFamily_bbn1822_c = 5,
	mplsInSegmentAddrFamily_all802_c = 6,
	mplsInSegmentAddrFamily_e163_c = 7,
	mplsInSegmentAddrFamily_e164_c = 8,
	mplsInSegmentAddrFamily_f69_c = 9,
	mplsInSegmentAddrFamily_x121_c = 10,
	mplsInSegmentAddrFamily_ipx_c = 11,
	mplsInSegmentAddrFamily_appleTalk_c = 12,
	mplsInSegmentAddrFamily_decnetIV_c = 13,
	mplsInSegmentAddrFamily_banyanVines_c = 14,
	mplsInSegmentAddrFamily_e164withNsap_c = 15,
	mplsInSegmentAddrFamily_dns_c = 16,
	mplsInSegmentAddrFamily_distinguishedName_c = 17,
	mplsInSegmentAddrFamily_asNumber_c = 18,
	mplsInSegmentAddrFamily_xtpOverIpv4_c = 19,
	mplsInSegmentAddrFamily_xtpOverIpv6_c = 20,
	mplsInSegmentAddrFamily_xtpNativeModeXTP_c = 21,
	mplsInSegmentAddrFamily_fibreChannelWWPN_c = 22,
	mplsInSegmentAddrFamily_fibreChannelWWNN_c = 23,
	mplsInSegmentAddrFamily_gwid_c = 24,
	mplsInSegmentAddrFamily_afi_c = 25,
	mplsInSegmentAddrFamily_mplsTpSectionEndpointIdentifier_c = 26,
	mplsInSegmentAddrFamily_mplsTpLspEndpointIdentifier_c = 27,
	mplsInSegmentAddrFamily_mplsTpPseudowireEndpointIdentifier_c = 28,
	mplsInSegmentAddrFamily_eigrpCommonServiceFamily_c = 16384,
	mplsInSegmentAddrFamily_eigrpIpv4ServiceFamily_c = 16385,
	mplsInSegmentAddrFamily_eigrpIpv6ServiceFamily_c = 16386,
	mplsInSegmentAddrFamily_lispCanonicalAddressFormat_c = 16387,
	mplsInSegmentAddrFamily_bgpLs_c = 16388,
	mplsInSegmentAddrFamily_fortyeightBitMac_c = 16389,
	mplsInSegmentAddrFamily_sixtyfourBitMac_c = 16390,
	mplsInSegmentAddrFamily_oui_c = 16391,
	mplsInSegmentAddrFamily_mac24_c = 16392,
	mplsInSegmentAddrFamily_mac40_c = 16393,
	mplsInSegmentAddrFamily_ipv664_c = 16394,
	mplsInSegmentAddrFamily_rBridgePortID_c = 16395,
	mplsInSegmentAddrFamily_reserved_c = 65535,

	/* enums for column mplsInSegmentOwner */
	mplsInSegmentOwner_unknown_c = 1,
	mplsInSegmentOwner_other_c = 2,
	mplsInSegmentOwner_snmp_c = 3,
	mplsInSegmentOwner_ldp_c = 4,
	mplsInSegmentOwner_crldp_c = 5,
	mplsInSegmentOwner_rsvpTe_c = 6,
	mplsInSegmentOwner_policyAgent_c = 7,

	/* enums for column mplsInSegmentRowStatus */
	mplsInSegmentRowStatus_active_c = 1,
	mplsInSegmentRowStatus_notInService_c = 2,
	mplsInSegmentRowStatus_notReady_c = 3,
	mplsInSegmentRowStatus_createAndGo_c = 4,
	mplsInSegmentRowStatus_createAndWait_c = 5,
	mplsInSegmentRowStatus_destroy_c = 6,

	/* enums for column mplsInSegmentStorageType */
	mplsInSegmentStorageType_other_c = 1,
	mplsInSegmentStorageType_volatile_c = 2,
	mplsInSegmentStorageType_nonVolatile_c = 3,
	mplsInSegmentStorageType_permanent_c = 4,
	mplsInSegmentStorageType_readOnly_c = 5,
};

/* table mplsInSegmentTable row entry data structure */
typedef struct mplsInSegmentEntry_t
{
	/* Index values */
	uint8_t au8Index[24];
	size_t u16Index_len;	/* # of uint8_t elements */
	
	struct {
		uint32_t u32Interface;
	} oK;
	
	/* Column values */
	uint32_t u32Interface;
	uint32_t u32Label;
	xOid_t aoLabelPtr[128];
	size_t u16LabelPtr_len;	/* # of xOid_t elements */
	int32_t i32NPop;
	int32_t i32AddrFamily;
	uint8_t au8XCIndex[24];
	size_t u16XCIndex_len;	/* # of uint8_t elements */
	int32_t i32Owner;
	xOid_t aoTrafficParamPtr[128];
	size_t u16TrafficParamPtr_len;	/* # of xOid_t elements */
	uint8_t u8RowStatus;
	uint8_t u8StorageType;
	
	mplsInSegmentPerfEntry_t oPerf;
	gmplsInSegmentEntry_t oG;
	neMplsInSegmentEntry_t oNe;
	
	xBTree_Node_t oBTreeNode;
	xBTree_Node_t oIf_BTreeNode;
} mplsInSegmentEntry_t;

extern xBTree_t oMplsInSegmentTable_BTree;
extern xBTree_t oMplsInSegmentTable_If_BTree;

/* mplsInSegmentTable table mapper */
void mplsInSegmentTable_init (void);
mplsInSegmentEntry_t * mplsInSegmentTable_createEntry (
	uint8_t *pau8Index, size_t u16Index_len);
mplsInSegmentEntry_t * mplsInSegmentTable_getByIndex (
	uint8_t *pau8Index, size_t u16Index_len);
mplsInSegmentEntry_t * mplsInSegmentTable_getNextIndex (
	uint8_t *pau8Index, size_t u16Index_len);
mplsInSegmentEntry_t * mplsInSegmentTable_If_getNextIndex (
	uint32_t u32Interface,
	uint8_t *pau8Index, size_t u16Index_len);
void mplsInSegmentTable_removeEntry (mplsInSegmentEntry_t *poEntry);
mplsInSegmentEntry_t * mplsInSegmentTable_createExt (
	uint8_t *pau8Index, size_t u16Index_len);
bool mplsInSegmentTable_removeExt (mplsInSegmentEntry_t *poEntry);
bool mplsInSegmentTable_createHier (mplsInSegmentEntry_t *poEntry);
bool mplsInSegmentTable_removeHier (mplsInSegmentEntry_t *poEntry);
bool mplsInSegmentRowStatus_handler (
	mplsInSegmentEntry_t *poEntry, uint8_t u8RowStatus);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point mplsInSegmentTable_getFirst;
Netsnmp_Next_Data_Point mplsInSegmentTable_getNext;
Netsnmp_Get_Data_Point mplsInSegmentTable_get;
Netsnmp_Node_Handler mplsInSegmentTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table mplsOutSegmentTable definitions
 */
#define MPLSOUTSEGMENTINDEX 1
#define MPLSOUTSEGMENTINTERFACE 2
#define MPLSOUTSEGMENTPUSHTOPLABEL 3
#define MPLSOUTSEGMENTTOPLABEL 4
#define MPLSOUTSEGMENTTOPLABELPTR 5
#define MPLSOUTSEGMENTNEXTHOPADDRTYPE 6
#define MPLSOUTSEGMENTNEXTHOPADDR 7
#define MPLSOUTSEGMENTXCINDEX 8
#define MPLSOUTSEGMENTOWNER 9
#define MPLSOUTSEGMENTTRAFFICPARAMPTR 10
#define MPLSOUTSEGMENTROWSTATUS 11
#define MPLSOUTSEGMENTSTORAGETYPE 12

enum
{
	/* enums for column mplsOutSegmentPushTopLabel */
	mplsOutSegmentPushTopLabel_true_c = 1,
	mplsOutSegmentPushTopLabel_false_c = 2,

	/* enums for column mplsOutSegmentNextHopAddrType */
	mplsOutSegmentNextHopAddrType_unknown_c = 0,
	mplsOutSegmentNextHopAddrType_ipv4_c = 1,
	mplsOutSegmentNextHopAddrType_ipv6_c = 2,
	mplsOutSegmentNextHopAddrType_ipv4z_c = 3,
	mplsOutSegmentNextHopAddrType_ipv6z_c = 4,
	mplsOutSegmentNextHopAddrType_dns_c = 16,

	/* enums for column mplsOutSegmentOwner */
	mplsOutSegmentOwner_unknown_c = 1,
	mplsOutSegmentOwner_other_c = 2,
	mplsOutSegmentOwner_snmp_c = 3,
	mplsOutSegmentOwner_ldp_c = 4,
	mplsOutSegmentOwner_crldp_c = 5,
	mplsOutSegmentOwner_rsvpTe_c = 6,
	mplsOutSegmentOwner_policyAgent_c = 7,

	/* enums for column mplsOutSegmentRowStatus */
	mplsOutSegmentRowStatus_active_c = 1,
	mplsOutSegmentRowStatus_notInService_c = 2,
	mplsOutSegmentRowStatus_notReady_c = 3,
	mplsOutSegmentRowStatus_createAndGo_c = 4,
	mplsOutSegmentRowStatus_createAndWait_c = 5,
	mplsOutSegmentRowStatus_destroy_c = 6,

	/* enums for column mplsOutSegmentStorageType */
	mplsOutSegmentStorageType_other_c = 1,
	mplsOutSegmentStorageType_volatile_c = 2,
	mplsOutSegmentStorageType_nonVolatile_c = 3,
	mplsOutSegmentStorageType_permanent_c = 4,
	mplsOutSegmentStorageType_readOnly_c = 5,
};

/* table mplsOutSegmentTable row entry data structure */
typedef struct mplsOutSegmentEntry_t
{
	/* Index values */
	uint8_t au8Index[24];
	size_t u16Index_len;	/* # of uint8_t elements */
	
	struct {
		uint32_t u32Interface;
	} oK;
	
	/* Column values */
	uint32_t u32Interface;
	uint8_t u8PushTopLabel;
	uint32_t u32TopLabel;
	xOid_t aoTopLabelPtr[128];
	size_t u16TopLabelPtr_len;	/* # of xOid_t elements */
	int32_t i32NextHopAddrType;
	uint8_t au8NextHopAddr[255];
	size_t u16NextHopAddr_len;	/* # of uint8_t elements */
	uint8_t au8XCIndex[24];
	size_t u16XCIndex_len;	/* # of uint8_t elements */
	int32_t i32Owner;
	xOid_t aoTrafficParamPtr[128];
	size_t u16TrafficParamPtr_len;	/* # of xOid_t elements */
	uint8_t u8RowStatus;
	uint8_t u8StorageType;
	
	xBTree_Node_t oBTreeNode;
	xBTree_Node_t oIf_BTreeNode;
} mplsOutSegmentEntry_t;

extern xBTree_t oMplsOutSegmentTable_BTree;
extern xBTree_t oMplsOutSegmentTable_If_BTree;

/* mplsOutSegmentTable table mapper */
void mplsOutSegmentTable_init (void);
mplsOutSegmentEntry_t * mplsOutSegmentTable_createEntry (
	uint8_t *pau8Index, size_t u16Index_len);
mplsOutSegmentEntry_t * mplsOutSegmentTable_getByIndex (
	uint8_t *pau8Index, size_t u16Index_len);
mplsOutSegmentEntry_t * mplsOutSegmentTable_getNextIndex (
	uint8_t *pau8Index, size_t u16Index_len);
mplsOutSegmentEntry_t * mplsOutSegmentTable_If_getNextIndex (
	uint32_t u32Interface,
	uint8_t *pau8Index, size_t u16Index_len);
void mplsOutSegmentTable_removeEntry (mplsOutSegmentEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point mplsOutSegmentTable_getFirst;
Netsnmp_Next_Data_Point mplsOutSegmentTable_getNext;
Netsnmp_Get_Data_Point mplsOutSegmentTable_get;
Netsnmp_Node_Handler mplsOutSegmentTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table mplsXCTable definitions
 */
#define MPLSXCINDEX 1
#define MPLSXCINSEGMENTINDEX 2
#define MPLSXCOUTSEGMENTINDEX 3
#define MPLSXCLSPID 4
#define MPLSXCLABELSTACKINDEX 5
#define MPLSXCOWNER 6
#define MPLSXCROWSTATUS 7
#define MPLSXCSTORAGETYPE 8
#define MPLSXCADMINSTATUS 9
#define MPLSXCOPERSTATUS 10

enum
{
	/* enums for column mplsXCOwner */
	mplsXCOwner_unknown_c = 1,
	mplsXCOwner_other_c = 2,
	mplsXCOwner_snmp_c = 3,
	mplsXCOwner_ldp_c = 4,
	mplsXCOwner_crldp_c = 5,
	mplsXCOwner_rsvpTe_c = 6,
	mplsXCOwner_policyAgent_c = 7,

	/* enums for column mplsXCRowStatus */
	mplsXCRowStatus_active_c = 1,
	mplsXCRowStatus_notInService_c = 2,
	mplsXCRowStatus_notReady_c = 3,
	mplsXCRowStatus_createAndGo_c = 4,
	mplsXCRowStatus_createAndWait_c = 5,
	mplsXCRowStatus_destroy_c = 6,

	/* enums for column mplsXCStorageType */
	mplsXCStorageType_other_c = 1,
	mplsXCStorageType_volatile_c = 2,
	mplsXCStorageType_nonVolatile_c = 3,
	mplsXCStorageType_permanent_c = 4,
	mplsXCStorageType_readOnly_c = 5,

	/* enums for column mplsXCAdminStatus */
	mplsXCAdminStatus_up_c = 1,
	mplsXCAdminStatus_down_c = 2,
	mplsXCAdminStatus_testing_c = 3,

	/* enums for column mplsXCOperStatus */
	mplsXCOperStatus_up_c = 1,
	mplsXCOperStatus_down_c = 2,
	mplsXCOperStatus_testing_c = 3,
	mplsXCOperStatus_unknown_c = 4,
	mplsXCOperStatus_dormant_c = 5,
	mplsXCOperStatus_notPresent_c = 6,
	mplsXCOperStatus_lowerLayerDown_c = 7,
};

/* table mplsXCTable row entry data structure */
typedef struct mplsXCEntry_t
{
	/* Index values */
	uint8_t au8Index[24];
	size_t u16Index_len;	/* # of uint8_t elements */
	uint8_t au8InSegmentIndex[24];
	size_t u16InSegmentIndex_len;	/* # of uint8_t elements */
	uint8_t au8OutSegmentIndex[24];
	size_t u16OutSegmentIndex_len;	/* # of uint8_t elements */
	
	/* Column values */
	uint8_t au8LspId[6];
	size_t u16LspId_len;	/* # of uint8_t elements */
	uint8_t au8LabelStackIndex[24];
	size_t u16LabelStackIndex_len;	/* # of uint8_t elements */
	int32_t i32Owner;
	uint8_t u8RowStatus;
	uint8_t u8StorageType;
	int32_t i32AdminStatus;
	int32_t i32OperStatus;
	
	mplsXCExtEntry_t oX;
	
	xBTree_Node_t oBTreeNode;
} mplsXCEntry_t;

extern xBTree_t oMplsXCTable_BTree;

/* mplsXCTable table mapper */
void mplsXCTable_init (void);
mplsXCEntry_t * mplsXCTable_createEntry (
	uint8_t *pau8Index, size_t u16Index_len,
	uint8_t *pau8InSegmentIndex, size_t u16InSegmentIndex_len,
	uint8_t *pau8OutSegmentIndex, size_t u16OutSegmentIndex_len);
mplsXCEntry_t * mplsXCTable_getByIndex (
	uint8_t *pau8Index, size_t u16Index_len,
	uint8_t *pau8InSegmentIndex, size_t u16InSegmentIndex_len,
	uint8_t *pau8OutSegmentIndex, size_t u16OutSegmentIndex_len);
mplsXCEntry_t * mplsXCTable_getNextIndex (
	uint8_t *pau8Index, size_t u16Index_len,
	uint8_t *pau8InSegmentIndex, size_t u16InSegmentIndex_len,
	uint8_t *pau8OutSegmentIndex, size_t u16OutSegmentIndex_len);
void mplsXCTable_removeEntry (mplsXCEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point mplsXCTable_getFirst;
Netsnmp_Next_Data_Point mplsXCTable_getNext;
Netsnmp_Get_Data_Point mplsXCTable_get;
Netsnmp_Node_Handler mplsXCTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	notification mapper(s)
 */
/* definitions for notification(s) of mplsLsrNotifications */
#	define MPLSXCUP 1
#	define MPLSXCDOWN 2

/* mplsLsrNotifications mapper(s) */
int mplsXCUp_trap (void);
int mplsXCDown_trap (void);



#	ifdef __cplusplus
}
#	endif

#endif /* __MPLSLSRSTDMIB_H__ */
