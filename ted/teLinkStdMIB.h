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

#ifndef __TELINKSTDMIB_H__
#	define __TELINKSTDMIB_H__

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
void teLinkStdMIB_init (void);


/**
 *	table mapper(s)
 */
/**
 *	table teLinkSwCapTable definitions
 */
#define TELINKSWCAPID 1
#define TELINKSWCAPTYPE 2
#define TELINKSWCAPENCODING 3
#define TELINKSWCAPMINLSPBANDWIDTH 4
#define TELINKSWCAPMAXLSPBANDWIDTHPRIO0 5
#define TELINKSWCAPMAXLSPBANDWIDTHPRIO1 6
#define TELINKSWCAPMAXLSPBANDWIDTHPRIO2 7
#define TELINKSWCAPMAXLSPBANDWIDTHPRIO3 8
#define TELINKSWCAPMAXLSPBANDWIDTHPRIO4 9
#define TELINKSWCAPMAXLSPBANDWIDTHPRIO5 10
#define TELINKSWCAPMAXLSPBANDWIDTHPRIO6 11
#define TELINKSWCAPMAXLSPBANDWIDTHPRIO7 12
#define TELINKSWCAPINTERFACEMTU 13
#define TELINKSWCAPINDICATION 14
#define TELINKSWCAPROWSTATUS 15
#define TELINKSWCAPSTORAGETYPE 16

enum
{
	/* enums for column teLinkSwCapType */
	teLinkSwCapType_unknown_c = 0,
	teLinkSwCapType_psc1_c = 1,
	teLinkSwCapType_psc2_c = 2,
	teLinkSwCapType_psc3_c = 3,
	teLinkSwCapType_psc4_c = 4,
	teLinkSwCapType_evpl_c = 30,
	teLinkSwCapType_pbb_c = 40,
	teLinkSwCapType_l2sc_c = 51,
	teLinkSwCapType_tdm_c = 100,
	teLinkSwCapType_otntdm_c = 110,
	teLinkSwCapType_dcsc_c = 125,
	teLinkSwCapType_lsc_c = 150,
	teLinkSwCapType_fsc_c = 200,

	/* enums for column teLinkSwCapEncoding */
	teLinkSwCapEncoding_notGmpls_c = 0,
	teLinkSwCapEncoding_packet_c = 1,
	teLinkSwCapEncoding_ethernet_c = 2,
	teLinkSwCapEncoding_ansiEtsiPdh_c = 3,
	teLinkSwCapEncoding_sdhSonet_c = 5,
	teLinkSwCapEncoding_digitalWrapper_c = 7,
	teLinkSwCapEncoding_lambda_c = 8,
	teLinkSwCapEncoding_fiber_c = 9,
	teLinkSwCapEncoding_fiberChannel_c = 11,
	teLinkSwCapEncoding_digitalPath_c = 12,
	teLinkSwCapEncoding_opticalChannel_c = 13,
	teLinkSwCapEncoding_line_c = 14,

	/* enums for column teLinkSwCapIndication */
	teLinkSwCapIndication_standard_c = 0,
	teLinkSwCapIndication_arbitrary_c = 1,

	/* enums for column teLinkSwCapRowStatus */
	teLinkSwCapRowStatus_active_c = 1,
	teLinkSwCapRowStatus_notInService_c = 2,
	teLinkSwCapRowStatus_notReady_c = 3,
	teLinkSwCapRowStatus_createAndGo_c = 4,
	teLinkSwCapRowStatus_createAndWait_c = 5,
	teLinkSwCapRowStatus_destroy_c = 6,

	/* enums for column teLinkSwCapStorageType */
	teLinkSwCapStorageType_other_c = 1,
	teLinkSwCapStorageType_volatile_c = 2,
	teLinkSwCapStorageType_nonVolatile_c = 3,
	teLinkSwCapStorageType_permanent_c = 4,
	teLinkSwCapStorageType_readOnly_c = 5,
};

/* table teLinkSwCapTable row entry data structure */
typedef struct teLinkSwCapEntry_t
{
	/* Index values */
	uint32_t u32IfIndex;
	uint32_t u32Id;
	
	struct {
		int32_t i32Type;
		int32_t i32Encoding;
	} oK;
	
	/* Column values */
	int32_t i32Type;
	int32_t i32Encoding;
	uint8_t au8MinLspBandwidth[8];
	size_t u16MinLspBandwidth_len;	/* # of uint8_t elements */
	uint8_t au8MaxLspBandwidthPrio[8][8];
	uint32_t u32InterfaceMtu;
	int32_t i32Indication;
	uint8_t u8RowStatus;
	uint8_t u8StorageType;
	
	xBTree_Node_t oBTreeNode;
	xBTree_Node_t oSwCap_BTreeNode;
} teLinkSwCapEntry_t;

extern xBTree_t oTeLinkSwCapTable_BTree;
extern xBTree_t oTeLinkSwCapTable_SwCap_BTree;

/* teLinkSwCapTable table mapper */
void teLinkSwCapTable_init (void);
teLinkSwCapEntry_t * teLinkSwCapTable_createEntry (
	uint32_t u32IfIndex,
	uint32_t u32Id);
teLinkSwCapEntry_t * teLinkSwCapTable_getByIndex (
	uint32_t u32IfIndex,
	uint32_t u32Id);
teLinkSwCapEntry_t * teLinkSwCapTable_SwCap_getByIndex (
	uint32_t u32IfIndex,
	int32_t i32Type,
	int32_t i32Encoding);
teLinkSwCapEntry_t * teLinkSwCapTable_getNextIndex (
	uint32_t u32IfIndex,
	uint32_t u32Id);
void teLinkSwCapTable_removeEntry (teLinkSwCapEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point teLinkSwCapTable_getFirst;
Netsnmp_Next_Data_Point teLinkSwCapTable_getNext;
Netsnmp_Get_Data_Point teLinkSwCapTable_get;
Netsnmp_Node_Handler teLinkSwCapTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table teLinkSrlgTable definitions
 */
#define TELINKSRLG 1
#define TELINKSRLGROWSTATUS 2
#define TELINKSRLGSTORAGETYPE 3

enum
{
	/* enums for column teLinkSrlgRowStatus */
	teLinkSrlgRowStatus_active_c = 1,
	teLinkSrlgRowStatus_notInService_c = 2,
	teLinkSrlgRowStatus_notReady_c = 3,
	teLinkSrlgRowStatus_createAndGo_c = 4,
	teLinkSrlgRowStatus_createAndWait_c = 5,
	teLinkSrlgRowStatus_destroy_c = 6,

	/* enums for column teLinkSrlgStorageType */
	teLinkSrlgStorageType_other_c = 1,
	teLinkSrlgStorageType_volatile_c = 2,
	teLinkSrlgStorageType_nonVolatile_c = 3,
	teLinkSrlgStorageType_permanent_c = 4,
	teLinkSrlgStorageType_readOnly_c = 5,
};

/* table teLinkSrlgTable row entry data structure */
typedef struct teLinkSrlgEntry_t
{
	/* Index values */
	uint32_t u32IfIndex;
	uint32_t u32Srlg;
	
	/* Column values */
	uint8_t u8RowStatus;
	uint8_t u8StorageType;
	
	xBTree_Node_t oBTreeNode;
} teLinkSrlgEntry_t;

extern xBTree_t oTeLinkSrlgTable_BTree;

/* teLinkSrlgTable table mapper */
void teLinkSrlgTable_init (void);
teLinkSrlgEntry_t * teLinkSrlgTable_createEntry (
	uint32_t u32IfIndex,
	uint32_t u32Srlg);
teLinkSrlgEntry_t * teLinkSrlgTable_getByIndex (
	uint32_t u32IfIndex,
	uint32_t u32Srlg);
teLinkSrlgEntry_t * teLinkSrlgTable_getNextIndex (
	uint32_t u32IfIndex,
	uint32_t u32Srlg);
void teLinkSrlgTable_removeEntry (teLinkSrlgEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point teLinkSrlgTable_getFirst;
Netsnmp_Next_Data_Point teLinkSrlgTable_getNext;
Netsnmp_Get_Data_Point teLinkSrlgTable_get;
Netsnmp_Node_Handler teLinkSrlgTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table teLinkBandwidthTable definitions
 */
#define TELINKBANDWIDTHPRIORITY 1
#define TELINKBANDWIDTHUNRESERVED 2
#define TELINKBANDWIDTHROWSTATUS 3
#define TELINKBANDWIDTHSTORAGETYPE 4

enum
{
	/* enums for column teLinkBandwidthRowStatus */
	teLinkBandwidthRowStatus_active_c = 1,
	teLinkBandwidthRowStatus_notInService_c = 2,
	teLinkBandwidthRowStatus_notReady_c = 3,
	teLinkBandwidthRowStatus_createAndGo_c = 4,
	teLinkBandwidthRowStatus_createAndWait_c = 5,
	teLinkBandwidthRowStatus_destroy_c = 6,

	/* enums for column teLinkBandwidthStorageType */
	teLinkBandwidthStorageType_other_c = 1,
	teLinkBandwidthStorageType_volatile_c = 2,
	teLinkBandwidthStorageType_nonVolatile_c = 3,
	teLinkBandwidthStorageType_permanent_c = 4,
	teLinkBandwidthStorageType_readOnly_c = 5,
};

/* table teLinkBandwidthTable row entry data structure */
typedef struct teLinkBandwidthEntry_t
{
	/* Index values */
	uint32_t u32IfIndex;
	uint32_t u32Priority;
	
	/* Column values */
	uint8_t au8Unreserved[8];
	size_t u16Unreserved_len;	/* # of uint8_t elements */
	uint8_t u8RowStatus;
	uint8_t u8StorageType;
	
	xBTree_Node_t oBTreeNode;
} teLinkBandwidthEntry_t;

extern xBTree_t oTeLinkBandwidthTable_BTree;

/* teLinkBandwidthTable table mapper */
void teLinkBandwidthTable_init (void);
teLinkBandwidthEntry_t * teLinkBandwidthTable_createEntry (
	uint32_t u32IfIndex,
	uint32_t u32Priority);
teLinkBandwidthEntry_t * teLinkBandwidthTable_getByIndex (
	uint32_t u32IfIndex,
	uint32_t u32Priority);
teLinkBandwidthEntry_t * teLinkBandwidthTable_getNextIndex (
	uint32_t u32IfIndex,
	uint32_t u32Priority);
void teLinkBandwidthTable_removeEntry (teLinkBandwidthEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point teLinkBandwidthTable_getFirst;
Netsnmp_Next_Data_Point teLinkBandwidthTable_getNext;
Netsnmp_Get_Data_Point teLinkBandwidthTable_get;
Netsnmp_Node_Handler teLinkBandwidthTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table componentLinkSwCapTable definitions
 */
#define COMPONENTLINKSWCAPID 1
#define COMPONENTLINKSWCAPTYPE 2
#define COMPONENTLINKSWCAPENCODING 3
#define COMPONENTLINKSWCAPMINLSPBANDWIDTH 4
#define COMPONENTLINKSWCAPMAXLSPBANDWIDTHPRIO0 5
#define COMPONENTLINKSWCAPMAXLSPBANDWIDTHPRIO1 6
#define COMPONENTLINKSWCAPMAXLSPBANDWIDTHPRIO2 7
#define COMPONENTLINKSWCAPMAXLSPBANDWIDTHPRIO3 8
#define COMPONENTLINKSWCAPMAXLSPBANDWIDTHPRIO4 9
#define COMPONENTLINKSWCAPMAXLSPBANDWIDTHPRIO5 10
#define COMPONENTLINKSWCAPMAXLSPBANDWIDTHPRIO6 11
#define COMPONENTLINKSWCAPMAXLSPBANDWIDTHPRIO7 12
#define COMPONENTLINKSWCAPINTERFACEMTU 13
#define COMPONENTLINKSWCAPINDICATION 14
#define COMPONENTLINKSWCAPROWSTATUS 15
#define COMPONENTLINKSWCAPSTORAGETYPE 16

enum
{
	/* enums for column componentLinkSwCapType */
	componentLinkSwCapType_unknown_c = 0,
	componentLinkSwCapType_psc1_c = 1,
	componentLinkSwCapType_psc2_c = 2,
	componentLinkSwCapType_psc3_c = 3,
	componentLinkSwCapType_psc4_c = 4,
	componentLinkSwCapType_evpl_c = 30,
	componentLinkSwCapType_pbb_c = 40,
	componentLinkSwCapType_l2sc_c = 51,
	componentLinkSwCapType_tdm_c = 100,
	componentLinkSwCapType_otntdm_c = 110,
	componentLinkSwCapType_dcsc_c = 125,
	componentLinkSwCapType_lsc_c = 150,
	componentLinkSwCapType_fsc_c = 200,

	/* enums for column componentLinkSwCapEncoding */
	componentLinkSwCapEncoding_notGmpls_c = 0,
	componentLinkSwCapEncoding_packet_c = 1,
	componentLinkSwCapEncoding_ethernet_c = 2,
	componentLinkSwCapEncoding_ansiEtsiPdh_c = 3,
	componentLinkSwCapEncoding_sdhSonet_c = 5,
	componentLinkSwCapEncoding_digitalWrapper_c = 7,
	componentLinkSwCapEncoding_lambda_c = 8,
	componentLinkSwCapEncoding_fiber_c = 9,
	componentLinkSwCapEncoding_fiberChannel_c = 11,
	componentLinkSwCapEncoding_digitalPath_c = 12,
	componentLinkSwCapEncoding_opticalChannel_c = 13,
	componentLinkSwCapEncoding_line_c = 14,

	/* enums for column componentLinkSwCapIndication */
	componentLinkSwCapIndication_standard_c = 0,
	componentLinkSwCapIndication_arbitrary_c = 1,

	/* enums for column componentLinkSwCapRowStatus */
	componentLinkSwCapRowStatus_active_c = 1,
	componentLinkSwCapRowStatus_notInService_c = 2,
	componentLinkSwCapRowStatus_notReady_c = 3,
	componentLinkSwCapRowStatus_createAndGo_c = 4,
	componentLinkSwCapRowStatus_createAndWait_c = 5,
	componentLinkSwCapRowStatus_destroy_c = 6,

	/* enums for column componentLinkSwCapStorageType */
	componentLinkSwCapStorageType_other_c = 1,
	componentLinkSwCapStorageType_volatile_c = 2,
	componentLinkSwCapStorageType_nonVolatile_c = 3,
	componentLinkSwCapStorageType_permanent_c = 4,
	componentLinkSwCapStorageType_readOnly_c = 5,
};

/* table componentLinkSwCapTable row entry data structure */
typedef struct componentLinkSwCapEntry_t
{
	/* Index values */
	uint32_t u32IfIndex;
	uint32_t u32Id;
	
	/* Column values */
	int32_t i32Type;
	int32_t i32Encoding;
	uint8_t au8MinLspBandwidth[8];
	size_t u16MinLspBandwidth_len;	/* # of uint8_t elements */
	uint8_t au8MaxLspBandwidthPrio[8][8];
	uint32_t u32InterfaceMtu;
	int32_t i32Indication;
	uint8_t u8RowStatus;
	uint8_t u8StorageType;
	
	xBTree_Node_t oBTreeNode;
} componentLinkSwCapEntry_t;

extern xBTree_t oComponentLinkSwCapTable_BTree;

/* componentLinkSwCapTable table mapper */
void componentLinkSwCapTable_init (void);
componentLinkSwCapEntry_t * componentLinkSwCapTable_createEntry (
	uint32_t u32IfIndex,
	uint32_t u32Id);
componentLinkSwCapEntry_t * componentLinkSwCapTable_getByIndex (
	uint32_t u32IfIndex,
	uint32_t u32Id);
componentLinkSwCapEntry_t * componentLinkSwCapTable_getNextIndex (
	uint32_t u32IfIndex,
	uint32_t u32Id);
void componentLinkSwCapTable_removeEntry (componentLinkSwCapEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point componentLinkSwCapTable_getFirst;
Netsnmp_Next_Data_Point componentLinkSwCapTable_getNext;
Netsnmp_Get_Data_Point componentLinkSwCapTable_get;
Netsnmp_Node_Handler componentLinkSwCapTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table componentLinkBandwidthTable definitions
 */
#define COMPONENTLINKBANDWIDTHPRIORITY 1
#define COMPONENTLINKBANDWIDTHUNRESERVED 2
#define COMPONENTLINKBANDWIDTHROWSTATUS 3
#define COMPONENTLINKBANDWIDTHSTORAGETYPE 4

enum
{
	/* enums for column componentLinkBandwidthRowStatus */
	componentLinkBandwidthRowStatus_active_c = 1,
	componentLinkBandwidthRowStatus_notInService_c = 2,
	componentLinkBandwidthRowStatus_notReady_c = 3,
	componentLinkBandwidthRowStatus_createAndGo_c = 4,
	componentLinkBandwidthRowStatus_createAndWait_c = 5,
	componentLinkBandwidthRowStatus_destroy_c = 6,

	/* enums for column componentLinkBandwidthStorageType */
	componentLinkBandwidthStorageType_other_c = 1,
	componentLinkBandwidthStorageType_volatile_c = 2,
	componentLinkBandwidthStorageType_nonVolatile_c = 3,
	componentLinkBandwidthStorageType_permanent_c = 4,
	componentLinkBandwidthStorageType_readOnly_c = 5,
};

/* table componentLinkBandwidthTable row entry data structure */
typedef struct componentLinkBandwidthEntry_t
{
	/* Index values */
	uint32_t u32IfIndex;
	uint32_t u32Priority;
	
	/* Column values */
	uint8_t au8Unreserved[8];
	uint8_t u8RowStatus;
	uint8_t u8StorageType;
	
	xBTree_Node_t oBTreeNode;
} componentLinkBandwidthEntry_t;

extern xBTree_t oComponentLinkBandwidthTable_BTree;

/* componentLinkBandwidthTable table mapper */
void componentLinkBandwidthTable_init (void);
componentLinkBandwidthEntry_t * componentLinkBandwidthTable_createEntry (
	uint32_t u32IfIndex,
	uint32_t u32Priority);
componentLinkBandwidthEntry_t * componentLinkBandwidthTable_getByIndex (
	uint32_t u32IfIndex,
	uint32_t u32Priority);
componentLinkBandwidthEntry_t * componentLinkBandwidthTable_getNextIndex (
	uint32_t u32IfIndex,
	uint32_t u32Priority);
void componentLinkBandwidthTable_removeEntry (componentLinkBandwidthEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point componentLinkBandwidthTable_getFirst;
Netsnmp_Next_Data_Point componentLinkBandwidthTable_getNext;
Netsnmp_Get_Data_Point componentLinkBandwidthTable_get;
Netsnmp_Node_Handler componentLinkBandwidthTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table teAdminGroupTable definitions
 */
#define TEADMINGROUPNUMBER 1
#define TEADMINGROUPNAME 2
#define TEADMINGROUPROWSTATUS 3

enum
{
	/* enums for column teAdminGroupRowStatus */
	teAdminGroupRowStatus_active_c = 1,
	teAdminGroupRowStatus_notInService_c = 2,
	teAdminGroupRowStatus_notReady_c = 3,
	teAdminGroupRowStatus_createAndGo_c = 4,
	teAdminGroupRowStatus_createAndWait_c = 5,
	teAdminGroupRowStatus_destroy_c = 6,
};

/* table teAdminGroupTable row entry data structure */
typedef struct teAdminGroupEntry_t
{
	/* Index values */
	int32_t i32Number;
	
	/* Column values */
	uint8_t au8Name[32];
	size_t u16Name_len;	/* # of uint8_t elements */
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} teAdminGroupEntry_t;

extern xBTree_t oTeAdminGroupTable_BTree;

/* teAdminGroupTable table mapper */
void teAdminGroupTable_init (void);
teAdminGroupEntry_t * teAdminGroupTable_createEntry (
	int32_t i32Number);
teAdminGroupEntry_t * teAdminGroupTable_getByIndex (
	int32_t i32Number);
teAdminGroupEntry_t * teAdminGroupTable_getNextIndex (
	int32_t i32Number);
void teAdminGroupTable_removeEntry (teAdminGroupEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point teAdminGroupTable_getFirst;
Netsnmp_Next_Data_Point teAdminGroupTable_getNext;
Netsnmp_Get_Data_Point teAdminGroupTable_get;
Netsnmp_Node_Handler teAdminGroupTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table teLinkTable definitions
 */
#define TELINKADDRESSTYPE 1
#define TELINKLOCALIPADDR 2
#define TELINKREMOTEIPADDR 3
#define TELINKMETRIC 4
#define TELINKMAXRESBANDWIDTH 5
#define TELINKPROTECTIONTYPE 6
#define TELINKWORKINGPRIORITY 7
#define TELINKRESOURCECLASS 8
#define TELINKREMOTEID 9
#define TELINKLOCALID 10
#define TELINKROWSTATUS 11
#define TELINKSTORAGETYPE 12

enum
{
	/* enums for column teLinkAddressType */
	teLinkAddressType_unknown_c = 0,
	teLinkAddressType_ipv4_c = 1,
	teLinkAddressType_ipv6_c = 2,
	teLinkAddressType_ipv4z_c = 3,
	teLinkAddressType_ipv6z_c = 4,
	teLinkAddressType_dns_c = 16,

	/* enums for column teLinkProtectionType */
	teLinkProtectionType_extraTraffic_c = 1,
	teLinkProtectionType_unprotected_c = 2,
	teLinkProtectionType_shared_c = 3,
	teLinkProtectionType_dedicated1For1_c = 4,
	teLinkProtectionType_dedicated1Plus1_c = 5,
	teLinkProtectionType_enhanced_c = 6,

	/* enums for column teLinkRowStatus */
	teLinkRowStatus_active_c = 1,
	teLinkRowStatus_notInService_c = 2,
	teLinkRowStatus_notReady_c = 3,
	teLinkRowStatus_createAndGo_c = 4,
	teLinkRowStatus_createAndWait_c = 5,
	teLinkRowStatus_destroy_c = 6,

	/* enums for column teLinkStorageType */
	teLinkStorageType_other_c = 1,
	teLinkStorageType_volatile_c = 2,
	teLinkStorageType_nonVolatile_c = 3,
	teLinkStorageType_permanent_c = 4,
	teLinkStorageType_readOnly_c = 5,
};

/* table teLinkTable row entry data structure */
typedef struct teLinkEntry_t
{
	/* Index values */
	uint32_t u32IfIndex;
	
	struct {
		int32_t i32AddrType;
		uint8_t au8LocalAddr[20];
		size_t u16LocalAddr_len;
		uint32_t u32LocalId;
		uint8_t au8RemoteAddr[20];
		size_t u16RemoteAddr_len;
		uint32_t u32RemoteId;
	} oK;
	
	/* Column values */
	int32_t i32AddressType;
	uint8_t au8LocalIpAddr[20];
	size_t u16LocalIpAddr_len;	/* # of uint8_t elements */
	uint8_t au8RemoteIpAddr[20];
	size_t u16RemoteIpAddr_len;	/* # of uint8_t elements */
	uint32_t u32Metric;
	uint8_t au8MaxResBandwidth[8];
	size_t u16MaxResBandwidth_len;	/* # of uint8_t elements */
	int32_t i32ProtectionType;
	uint32_t u32WorkingPriority;
	uint32_t u32ResourceClass;
	uint32_t u32RemoteId;
	uint32_t u32LocalId;
	uint8_t u8RowStatus;
	uint8_t u8StorageType;
	
	xBTree_Node_t oBTreeNode;
	xBTree_Node_t oAddrLocal_BTreeNode;
	xBTree_Node_t oAddrRemote_BTreeNode;
} teLinkEntry_t;

extern xBTree_t oTeLinkTable_BTree;
extern xBTree_t oTeLinkTable_AddrLocal_BTree;
extern xBTree_t oTeLinkTable_AddrRemote_BTree;

/* teLinkTable table mapper */
void teLinkTable_init (void);
teLinkEntry_t * teLinkTable_createEntry (
	uint32_t u32IfIndex);
teLinkEntry_t * teLinkTable_getByIndex (
	uint32_t u32IfIndex);
teLinkEntry_t * teLinkTable_getNextIndex (
	uint32_t u32IfIndex);
teLinkEntry_t * teLinkTable_AddrLocal_getNextIndex (
	int32_t i32AddressType,
	uint8_t *pau8LocalIpAddr, size_t u16LocalIpAddr_len,
	uint32_t u32LocalId);
teLinkEntry_t * teLinkTable_AddrRemote_getNextIndex (
	int32_t i32AddressType,
	uint8_t *pau8RemoteIpAddr, size_t u16RemoteIpAddr_len,
	uint32_t u32RemoteId);
void teLinkTable_removeEntry (teLinkEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point teLinkTable_getFirst;
Netsnmp_Next_Data_Point teLinkTable_getNext;
Netsnmp_Get_Data_Point teLinkTable_get;
Netsnmp_Node_Handler teLinkTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table componentLinkTable definitions
 */
#define COMPONENTLINKMAXRESBANDWIDTH 1
#define COMPONENTLINKPREFERREDPROTECTION 2
#define COMPONENTLINKCURRENTPROTECTION 3
#define COMPONENTLINKROWSTATUS 4
#define COMPONENTLINKSTORAGETYPE 5

enum
{
	/* enums for column componentLinkPreferredProtection */
	componentLinkPreferredProtection_primary_c = 1,
	componentLinkPreferredProtection_secondary_c = 2,

	/* enums for column componentLinkCurrentProtection */
	componentLinkCurrentProtection_primary_c = 1,
	componentLinkCurrentProtection_secondary_c = 2,

	/* enums for column componentLinkRowStatus */
	componentLinkRowStatus_active_c = 1,
	componentLinkRowStatus_notInService_c = 2,
	componentLinkRowStatus_notReady_c = 3,
	componentLinkRowStatus_createAndGo_c = 4,
	componentLinkRowStatus_createAndWait_c = 5,
	componentLinkRowStatus_destroy_c = 6,

	/* enums for column componentLinkStorageType */
	componentLinkStorageType_other_c = 1,
	componentLinkStorageType_volatile_c = 2,
	componentLinkStorageType_nonVolatile_c = 3,
	componentLinkStorageType_permanent_c = 4,
	componentLinkStorageType_readOnly_c = 5,
};

/* table componentLinkTable row entry data structure */
typedef struct componentLinkEntry_t
{
	/* Index values */
	uint32_t u32IfIndex;
	
	/* Column values */
	uint8_t au8MaxResBandwidth[8];
	int32_t i32PreferredProtection;
	int32_t i32CurrentProtection;
	uint8_t u8RowStatus;
	uint8_t u8StorageType;
	
	xBTree_Node_t oBTreeNode;
} componentLinkEntry_t;

extern xBTree_t oComponentLinkTable_BTree;

/* componentLinkTable table mapper */
void componentLinkTable_init (void);
componentLinkEntry_t * componentLinkTable_createEntry (
	uint32_t u32IfIndex);
componentLinkEntry_t * componentLinkTable_getByIndex (
	uint32_t u32IfIndex);
componentLinkEntry_t * componentLinkTable_getNextIndex (
	uint32_t u32IfIndex);
void componentLinkTable_removeEntry (componentLinkEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point componentLinkTable_getFirst;
Netsnmp_Next_Data_Point componentLinkTable_getNext;
Netsnmp_Get_Data_Point componentLinkTable_get;
Netsnmp_Node_Handler componentLinkTable_mapper;
#endif	/* SNMP_SRC */



#	ifdef __cplusplus
}
#	endif

#endif /* __TELINKSTDMIB_H__ */
