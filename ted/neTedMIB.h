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

#ifndef __NETEDMIB_H__
#	define __NETEDMIB_H__

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
void neTedMIB_init (void);


/**
 *	scalar mapper(s)
 */
/** definitions for scalar(s) of mplsIdObjects **/
#define MPLSIDGLOBALID 1
#define MPLSIDNODEID 2
#define MPLSIDCC 3
#define MPLSIDICC 4

typedef struct mplsIdObjects_t
{
	uint8_t au8GlobalId[4];
	size_t u16GlobalId_len;	/* # of uint8_t elements */
	uint32_t u32NodeId;
	uint8_t au8Cc[2];
	size_t u16Cc_len;	/* # of uint8_t elements */
	uint8_t au8Icc[6];
	size_t u16Icc_len;	/* # of uint8_t elements */
} mplsIdObjects_t;

extern mplsIdObjects_t oMplsIdObjects;

#ifdef SNMP_SRC
Netsnmp_Node_Handler mplsIdObjects_mapper;
#endif	/* SNMP_SRC */

/** definitions for scalar(s) of mplsTeExtObjects **/
#define MPLSTENODECONFIGLOCALIDNEXT 1

typedef struct mplsTeExtObjects_t
{
	uint32_t u32NodeConfigLocalIdNext;
} mplsTeExtObjects_t;

extern mplsTeExtObjects_t oMplsTeExtObjects;

#ifdef SNMP_SRC
Netsnmp_Node_Handler mplsTeExtObjects_mapper;
#endif	/* SNMP_SRC */

/** definitions for scalar(s) of neTedScalars **/
#define NETEDNODECONFIGURED 1
#define NETEDNODEACTIVE 2
#define NETEDLINKCONFIGURED 3
#define NETEDLINKACTIVE 4
#define NETEDADDRESSCONFIGURED 5
#define NETEDADDRESSACTIVE 6
#define NETEDNEIGHBORCONFIGURED 7
#define NETEDNEIGHBORACTIVE 8

typedef struct neTedScalars_t
{
	uint32_t u32NodeConfigured;
	uint32_t u32NodeActive;
	uint32_t u32LinkConfigured;
	uint32_t u32LinkActive;
	uint32_t u32AddressConfigured;
	uint32_t u32AddressActive;
	uint32_t u32NeighborConfigured;
	uint32_t u32NeighborActive;
} neTedScalars_t;

extern neTedScalars_t oNeTedScalars;

#ifdef SNMP_SRC
Netsnmp_Node_Handler neTedScalars_mapper;
#endif	/* SNMP_SRC */



/**
 *	table mapper(s)
 */
/**
 *	table mplsTeNodeConfigTable definitions
 */
#define MPLSTENODECONFIGLOCALID 1
#define MPLSTENODECONFIGGLOBALID 2
#define MPLSTENODECONFIGCCID 3
#define MPLSTENODECONFIGICCID 4
#define MPLSTENODECONFIGNODEID 5
#define MPLSTENODECONFIGICCVALID 6
#define MPLSTENODECONFIGSTORAGETYPE 7
#define MPLSTENODECONFIGROWSTATUS 8

enum
{
	/* enums for column mplsTeNodeConfigIccValid */
	mplsTeNodeConfigIccValid_true_c = 1,
	mplsTeNodeConfigIccValid_false_c = 2,

	/* enums for column mplsTeNodeConfigStorageType */
	mplsTeNodeConfigStorageType_other_c = 1,
	mplsTeNodeConfigStorageType_volatile_c = 2,
	mplsTeNodeConfigStorageType_nonVolatile_c = 3,
	mplsTeNodeConfigStorageType_permanent_c = 4,
	mplsTeNodeConfigStorageType_readOnly_c = 5,

	/* enums for column mplsTeNodeConfigRowStatus */
	mplsTeNodeConfigRowStatus_active_c = 1,
	mplsTeNodeConfigRowStatus_notInService_c = 2,
	mplsTeNodeConfigRowStatus_notReady_c = 3,
	mplsTeNodeConfigRowStatus_createAndGo_c = 4,
	mplsTeNodeConfigRowStatus_createAndWait_c = 5,
	mplsTeNodeConfigRowStatus_destroy_c = 6,
};

/* table mplsTeNodeConfigTable row entry data structure */
typedef struct mplsTeNodeConfigEntry_t
{
	/* Index values */
	uint32_t u32LocalId;
	
	/* Column values */
	uint8_t au8GlobalId[4];
	size_t u16GlobalId_len;	/* # of uint8_t elements */
	uint8_t au8CcId[2];
	size_t u16CcId_len;	/* # of uint8_t elements */
	uint8_t au8IccId[6];
	size_t u16IccId_len;	/* # of uint8_t elements */
	uint32_t u32NodeId;
	uint8_t u8IccValid;
	uint8_t u8StorageType;
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} mplsTeNodeConfigEntry_t;

extern xBTree_t oMplsTeNodeConfigTable_BTree;

/* mplsTeNodeConfigTable table mapper */
void mplsTeNodeConfigTable_init (void);
mplsTeNodeConfigEntry_t * mplsTeNodeConfigTable_createEntry (
	uint32_t u32LocalId);
mplsTeNodeConfigEntry_t * mplsTeNodeConfigTable_getByIndex (
	uint32_t u32LocalId);
mplsTeNodeConfigEntry_t * mplsTeNodeConfigTable_getNextIndex (
	uint32_t u32LocalId);
void mplsTeNodeConfigTable_removeEntry (mplsTeNodeConfigEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point mplsTeNodeConfigTable_getFirst;
Netsnmp_Next_Data_Point mplsTeNodeConfigTable_getNext;
Netsnmp_Get_Data_Point mplsTeNodeConfigTable_get;
Netsnmp_Node_Handler mplsTeNodeConfigTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table neTedNodeTable definitions
 */
#define NETEDNODEINDEX 1
#define NETEDNODEADDRTYPE 2
#define NETEDNODEADDRESS 3
#define NETEDNODEDATAPATHID 4

enum
{
	/* enums for column neTedNodeAddrType */
	neTedNodeAddrType_ipv4_c = 1,
	neTedNodeAddrType_ipv6_c = 2,
	neTedNodeAddrType_ipv4z_c = 3,
	neTedNodeAddrType_ipv6z_c = 4,
};

/* table neTedNodeTable row entry data structure */
typedef struct neTedNodeEntry_t
{
	/* Index values */
	uint32_t u32Index;
	
	/* Column values */
	int32_t i32AddrType;
	uint8_t au8Address[20];
	size_t u16Address_len;	/* # of uint8_t elements */
	uint8_t au8DataPathId[8];
	size_t u16DataPathId_len;	/* # of uint8_t elements */
	
	xBTree_Node_t oBTreeNode;
} neTedNodeEntry_t;

extern xBTree_t oNeTedNodeTable_BTree;

/* neTedNodeTable table mapper */
void neTedNodeTable_init (void);
neTedNodeEntry_t * neTedNodeTable_createEntry (
	uint32_t u32Index);
neTedNodeEntry_t * neTedNodeTable_getByIndex (
	uint32_t u32Index);
neTedNodeEntry_t * neTedNodeTable_getNextIndex (
	uint32_t u32Index);
void neTedNodeTable_removeEntry (neTedNodeEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point neTedNodeTable_getFirst;
Netsnmp_Next_Data_Point neTedNodeTable_getNext;
Netsnmp_Get_Data_Point neTedNodeTable_get;
Netsnmp_Node_Handler neTedNodeTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table neTedLinkTable definitions
 */
#define NETEDLINKINDEX 1
#define NETEDLINKDISTRIBUTEENABLE 2
#define NETEDLINKADJACENCYENABLE 3
#define NETEDLINKDISTRIBUTIONSCOPE 4
#define NETEDLINKLOCALASN 5
#define NETEDLINKIGPINSTANCE 6
#define NETEDLINKAREA 7
#define NETEDLINKREMOTEASN 8
#define NETEDLINKSWCAPTYPES 9
#define NETEDLINKSWCAPENCODINGS 10
#define NETEDLINKADJCAPTYPES 11
#define NETEDLINKADJCAPENCODINGS 12
#define NETEDLINKROWSTATUS 13
#define NETEDLINKSTORAGETYPE 14

enum
{
	/* enums for column neTedLinkDistributeEnable */
	neTedLinkDistributeEnable_true_c = 1,
	neTedLinkDistributeEnable_false_c = 2,

	/* enums for column neTedLinkAdjacencyEnable */
	neTedLinkAdjacencyEnable_true_c = 1,
	neTedLinkAdjacencyEnable_false_c = 2,

	/* enums for column neTedLinkDistributionScope */
	neTedLinkDistributionScope_area_c = 0,
	neTedLinkDistributionScope_as_c = 1,
	neTedLinkDistributionScope_interAs_c = 2,

	/* enums for column neTedLinkSwCapTypes */
	neTedLinkSwCapTypes_bUnknown_c = 0,
	neTedLinkSwCapTypes_bPsc1_c = 1,
	neTedLinkSwCapTypes_bPsc2_c = 2,
	neTedLinkSwCapTypes_bPsc3_c = 3,
	neTedLinkSwCapTypes_bPsc4_c = 4,
	neTedLinkSwCapTypes_bEvpl_c = 7,
	neTedLinkSwCapTypes_bPbb_c = 10,
	neTedLinkSwCapTypes_bL2sc_c = 13,
	neTedLinkSwCapTypes_bTdm_c = 16,
	neTedLinkSwCapTypes_bOtntdm_c = 19,
	neTedLinkSwCapTypes_bDcsc_c = 22,
	neTedLinkSwCapTypes_bLsc_c = 25,
	neTedLinkSwCapTypes_bFsc_c = 28,

	/* enums for column neTedLinkSwCapEncodings */
	neTedLinkSwCapEncodings_bNotGmpls_c = 0,
	neTedLinkSwCapEncodings_bPacket_c = 1,
	neTedLinkSwCapEncodings_bEthernet_c = 2,
	neTedLinkSwCapEncodings_bAnsiEtsiPdh_c = 3,
	neTedLinkSwCapEncodings_bSdhSonet_c = 5,
	neTedLinkSwCapEncodings_bDigitalWrapper_c = 7,
	neTedLinkSwCapEncodings_bLambda_c = 8,
	neTedLinkSwCapEncodings_bFiber_c = 9,
	neTedLinkSwCapEncodings_bFiberChannel_c = 11,
	neTedLinkSwCapEncodings_bDigitalPath_c = 12,
	neTedLinkSwCapEncodings_bOpticalChannel_c = 13,
	neTedLinkSwCapEncodings_bLine_c = 14,

	/* enums for column neTedLinkAdjCapTypes */
	neTedLinkAdjCapTypes_bUnknown_c = 0,
	neTedLinkAdjCapTypes_bPsc1_c = 1,
	neTedLinkAdjCapTypes_bPsc2_c = 2,
	neTedLinkAdjCapTypes_bPsc3_c = 3,
	neTedLinkAdjCapTypes_bPsc4_c = 4,
	neTedLinkAdjCapTypes_bEvpl_c = 7,
	neTedLinkAdjCapTypes_bPbb_c = 10,
	neTedLinkAdjCapTypes_bL2sc_c = 13,
	neTedLinkAdjCapTypes_bTdm_c = 16,
	neTedLinkAdjCapTypes_bOtntdm_c = 19,
	neTedLinkAdjCapTypes_bDcsc_c = 22,
	neTedLinkAdjCapTypes_bLsc_c = 25,
	neTedLinkAdjCapTypes_bFsc_c = 28,

	/* enums for column neTedLinkAdjCapEncodings */
	neTedLinkAdjCapEncodings_bNotGmpls_c = 0,
	neTedLinkAdjCapEncodings_bPacket_c = 1,
	neTedLinkAdjCapEncodings_bEthernet_c = 2,
	neTedLinkAdjCapEncodings_bAnsiEtsiPdh_c = 3,
	neTedLinkAdjCapEncodings_bSdhSonet_c = 5,
	neTedLinkAdjCapEncodings_bDigitalWrapper_c = 7,
	neTedLinkAdjCapEncodings_bLambda_c = 8,
	neTedLinkAdjCapEncodings_bFiber_c = 9,
	neTedLinkAdjCapEncodings_bFiberChannel_c = 11,
	neTedLinkAdjCapEncodings_bDigitalPath_c = 12,
	neTedLinkAdjCapEncodings_bOpticalChannel_c = 13,
	neTedLinkAdjCapEncodings_bLine_c = 14,

	/* enums for column neTedLinkRowStatus */
	neTedLinkRowStatus_active_c = 1,
	neTedLinkRowStatus_notInService_c = 2,
	neTedLinkRowStatus_notReady_c = 3,
	neTedLinkRowStatus_createAndGo_c = 4,
	neTedLinkRowStatus_createAndWait_c = 5,
	neTedLinkRowStatus_destroy_c = 6,

	/* enums for column neTedLinkStorageType */
	neTedLinkStorageType_other_c = 1,
	neTedLinkStorageType_volatile_c = 2,
	neTedLinkStorageType_nonVolatile_c = 3,
	neTedLinkStorageType_permanent_c = 4,
	neTedLinkStorageType_readOnly_c = 5,
};

/* table neTedLinkTable row entry data structure */
typedef struct neTedLinkEntry_t
{
	/* Index values */
	uint32_t u32NodeIndex;
	uint32_t u32Index;
	
	/* Column values */
	uint8_t u8DistributeEnable;
	uint8_t u8AdjacencyEnable;
	uint8_t au8DistributionScope[1];
	size_t u16DistributionScope_len;	/* # of uint8_t elements */
	uint32_t u32LocalAsn;
	uint32_t u32IgpInstance;
	uint32_t u32Area;
	uint32_t u32RemoteAsn;
	uint8_t au8SwCapTypes[4];
	size_t u16SwCapTypes_len;	/* # of uint8_t elements */
	uint8_t au8SwCapEncodings[2];
	size_t u16SwCapEncodings_len;	/* # of uint8_t elements */
	uint8_t au8AdjCapTypes[4];
	size_t u16AdjCapTypes_len;	/* # of uint8_t elements */
	uint8_t au8AdjCapEncodings[2];
	size_t u16AdjCapEncodings_len;	/* # of uint8_t elements */
	uint8_t u8RowStatus;
	uint8_t u8StorageType;
	
	xBTree_Node_t oBTreeNode;
} neTedLinkEntry_t;

extern xBTree_t oNeTedLinkTable_BTree;

/* neTedLinkTable table mapper */
void neTedLinkTable_init (void);
neTedLinkEntry_t * neTedLinkTable_createEntry (
	uint32_t u32NodeIndex,
	uint32_t u32Index);
neTedLinkEntry_t * neTedLinkTable_getByIndex (
	uint32_t u32NodeIndex,
	uint32_t u32Index);
neTedLinkEntry_t * neTedLinkTable_getNextIndex (
	uint32_t u32NodeIndex,
	uint32_t u32Index);
void neTedLinkTable_removeEntry (neTedLinkEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point neTedLinkTable_getFirst;
Netsnmp_Next_Data_Point neTedLinkTable_getNext;
Netsnmp_Get_Data_Point neTedLinkTable_get;
Netsnmp_Node_Handler neTedLinkTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table neTedAddressTable definitions
 */
#define NETEDADDRESSTYPE 1
#define NETEDADDRESS 2
#define NETEDADDRESSLENGTH 3
#define NETEDADDRESSROWSTATUS 4
#define NETEDADDRESSSTORAGETYPE 5

enum
{
	/* enums for column neTedAddressType */
	neTedAddressType_ipv4_c = 1,
	neTedAddressType_ipv6_c = 2,
	neTedAddressType_ipv4z_c = 3,
	neTedAddressType_ipv6z_c = 4,
	neTedAddressType_nsap_c = 16385,

	/* enums for column neTedAddressRowStatus */
	neTedAddressRowStatus_active_c = 1,
	neTedAddressRowStatus_notInService_c = 2,
	neTedAddressRowStatus_notReady_c = 3,
	neTedAddressRowStatus_createAndGo_c = 4,
	neTedAddressRowStatus_createAndWait_c = 5,
	neTedAddressRowStatus_destroy_c = 6,

	/* enums for column neTedAddressStorageType */
	neTedAddressStorageType_other_c = 1,
	neTedAddressStorageType_volatile_c = 2,
	neTedAddressStorageType_nonVolatile_c = 3,
	neTedAddressStorageType_permanent_c = 4,
	neTedAddressStorageType_readOnly_c = 5,
};

/* table neTedAddressTable row entry data structure */
typedef struct neTedAddressEntry_t
{
	/* Index values */
	uint32_t u32NodeIndex;
	uint32_t u32LinkIndex;
	int32_t i32Type;
	uint8_t au8Address[20];
	size_t u16Address_len;	/* # of uint8_t elements */
	uint32_t u32Length;
	
	/* Column values */
	uint8_t u8RowStatus;
	uint8_t u8StorageType;
	
	xBTree_Node_t oBTreeNode;
} neTedAddressEntry_t;

extern xBTree_t oNeTedAddressTable_BTree;

/* neTedAddressTable table mapper */
void neTedAddressTable_init (void);
neTedAddressEntry_t * neTedAddressTable_createEntry (
	uint32_t u32NodeIndex,
	uint32_t u32LinkIndex,
	int32_t i32Type,
	uint8_t *pau8Address, size_t u16Address_len,
	uint32_t u32Length);
neTedAddressEntry_t * neTedAddressTable_getByIndex (
	uint32_t u32NodeIndex,
	uint32_t u32LinkIndex,
	int32_t i32Type,
	uint8_t *pau8Address, size_t u16Address_len,
	uint32_t u32Length);
neTedAddressEntry_t * neTedAddressTable_getNextIndex (
	uint32_t u32NodeIndex,
	uint32_t u32LinkIndex,
	int32_t i32Type,
	uint8_t *pau8Address, size_t u16Address_len,
	uint32_t u32Length);
void neTedAddressTable_removeEntry (neTedAddressEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point neTedAddressTable_getFirst;
Netsnmp_Next_Data_Point neTedAddressTable_getNext;
Netsnmp_Get_Data_Point neTedAddressTable_get;
Netsnmp_Node_Handler neTedAddressTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table neTedNeighborTable definitions
 */
#define NETEDNEIGHBORINDEX 1
#define NETEDNEIGHBORLINK 2
#define NETEDNEIGHBORROWSTATUS 3
#define NETEDNEIGHBORSTORAGETYPE 4

enum
{
	/* enums for column neTedNeighborRowStatus */
	neTedNeighborRowStatus_active_c = 1,
	neTedNeighborRowStatus_notInService_c = 2,
	neTedNeighborRowStatus_notReady_c = 3,
	neTedNeighborRowStatus_createAndGo_c = 4,
	neTedNeighborRowStatus_createAndWait_c = 5,
	neTedNeighborRowStatus_destroy_c = 6,

	/* enums for column neTedNeighborStorageType */
	neTedNeighborStorageType_other_c = 1,
	neTedNeighborStorageType_volatile_c = 2,
	neTedNeighborStorageType_nonVolatile_c = 3,
	neTedNeighborStorageType_permanent_c = 4,
	neTedNeighborStorageType_readOnly_c = 5,
};

/* table neTedNeighborTable row entry data structure */
typedef struct neTedNeighborEntry_t
{
	/* Index values */
	uint32_t u32NodeIndex;
	uint32_t u32LinkIndex;
	uint32_t u32Index;
	
	/* Column values */
	uint32_t u32Link;
	uint8_t u8RowStatus;
	uint8_t u8StorageType;
	
	xBTree_Node_t oBTreeNode;
} neTedNeighborEntry_t;

extern xBTree_t oNeTedNeighborTable_BTree;

/* neTedNeighborTable table mapper */
void neTedNeighborTable_init (void);
neTedNeighborEntry_t * neTedNeighborTable_createEntry (
	uint32_t u32NodeIndex,
	uint32_t u32LinkIndex,
	uint32_t u32Index);
neTedNeighborEntry_t * neTedNeighborTable_getByIndex (
	uint32_t u32NodeIndex,
	uint32_t u32LinkIndex,
	uint32_t u32Index);
neTedNeighborEntry_t * neTedNeighborTable_getNextIndex (
	uint32_t u32NodeIndex,
	uint32_t u32LinkIndex,
	uint32_t u32Index);
void neTedNeighborTable_removeEntry (neTedNeighborEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point neTedNeighborTable_getFirst;
Netsnmp_Next_Data_Point neTedNeighborTable_getNext;
Netsnmp_Get_Data_Point neTedNeighborTable_get;
Netsnmp_Node_Handler neTedNeighborTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table neTeLinkAdjCapTable definitions
 */
#define NETELINKADJCAPID 1
#define NETELINKADJCAPLOWERTYPE 2
#define NETELINKADJCAPLOWERENCODING 3
#define NETELINKADJCAPUPPERTYPE 4
#define NETELINKADJCAPUPPERENCODING 5
#define NETELINKADJCAPMAXLSPBANDWIDTHPRIO0 6
#define NETELINKADJCAPMAXLSPBANDWIDTHPRIO1 7
#define NETELINKADJCAPMAXLSPBANDWIDTHPRIO2 8
#define NETELINKADJCAPMAXLSPBANDWIDTHPRIO3 9
#define NETELINKADJCAPMAXLSPBANDWIDTHPRIO4 10
#define NETELINKADJCAPMAXLSPBANDWIDTHPRIO5 11
#define NETELINKADJCAPMAXLSPBANDWIDTHPRIO6 12
#define NETELINKADJCAPMAXLSPBANDWIDTHPRIO7 13
#define NETELINKADJCAPROWSTATUS 14
#define NETELINKADJCAPSTORAGETYPE 15

enum
{
	/* enums for column neTeLinkAdjCapLowerType */
	neTeLinkAdjCapLowerType_unknown_c = 0,
	neTeLinkAdjCapLowerType_psc1_c = 1,
	neTeLinkAdjCapLowerType_psc2_c = 2,
	neTeLinkAdjCapLowerType_psc3_c = 3,
	neTeLinkAdjCapLowerType_psc4_c = 4,
	neTeLinkAdjCapLowerType_evpl_c = 30,
	neTeLinkAdjCapLowerType_pbb_c = 40,
	neTeLinkAdjCapLowerType_l2sc_c = 51,
	neTeLinkAdjCapLowerType_tdm_c = 100,
	neTeLinkAdjCapLowerType_otntdm_c = 110,
	neTeLinkAdjCapLowerType_dcsc_c = 125,
	neTeLinkAdjCapLowerType_lsc_c = 150,
	neTeLinkAdjCapLowerType_fsc_c = 200,

	/* enums for column neTeLinkAdjCapLowerEncoding */
	neTeLinkAdjCapLowerEncoding_notGmpls_c = 0,
	neTeLinkAdjCapLowerEncoding_packet_c = 1,
	neTeLinkAdjCapLowerEncoding_ethernet_c = 2,
	neTeLinkAdjCapLowerEncoding_ansiEtsiPdh_c = 3,
	neTeLinkAdjCapLowerEncoding_sdhSonet_c = 5,
	neTeLinkAdjCapLowerEncoding_digitalWrapper_c = 7,
	neTeLinkAdjCapLowerEncoding_lambda_c = 8,
	neTeLinkAdjCapLowerEncoding_fiber_c = 9,
	neTeLinkAdjCapLowerEncoding_fiberChannel_c = 11,
	neTeLinkAdjCapLowerEncoding_digitalPath_c = 12,
	neTeLinkAdjCapLowerEncoding_opticalChannel_c = 13,
	neTeLinkAdjCapLowerEncoding_line_c = 14,

	/* enums for column neTeLinkAdjCapUpperType */
	neTeLinkAdjCapUpperType_unknown_c = 0,
	neTeLinkAdjCapUpperType_psc1_c = 1,
	neTeLinkAdjCapUpperType_psc2_c = 2,
	neTeLinkAdjCapUpperType_psc3_c = 3,
	neTeLinkAdjCapUpperType_psc4_c = 4,
	neTeLinkAdjCapUpperType_evpl_c = 30,
	neTeLinkAdjCapUpperType_pbb_c = 40,
	neTeLinkAdjCapUpperType_l2sc_c = 51,
	neTeLinkAdjCapUpperType_tdm_c = 100,
	neTeLinkAdjCapUpperType_otntdm_c = 110,
	neTeLinkAdjCapUpperType_dcsc_c = 125,
	neTeLinkAdjCapUpperType_lsc_c = 150,
	neTeLinkAdjCapUpperType_fsc_c = 200,

	/* enums for column neTeLinkAdjCapUpperEncoding */
	neTeLinkAdjCapUpperEncoding_notGmpls_c = 0,
	neTeLinkAdjCapUpperEncoding_packet_c = 1,
	neTeLinkAdjCapUpperEncoding_ethernet_c = 2,
	neTeLinkAdjCapUpperEncoding_ansiEtsiPdh_c = 3,
	neTeLinkAdjCapUpperEncoding_sdhSonet_c = 5,
	neTeLinkAdjCapUpperEncoding_digitalWrapper_c = 7,
	neTeLinkAdjCapUpperEncoding_lambda_c = 8,
	neTeLinkAdjCapUpperEncoding_fiber_c = 9,
	neTeLinkAdjCapUpperEncoding_fiberChannel_c = 11,
	neTeLinkAdjCapUpperEncoding_digitalPath_c = 12,
	neTeLinkAdjCapUpperEncoding_opticalChannel_c = 13,
	neTeLinkAdjCapUpperEncoding_line_c = 14,

	/* enums for column neTeLinkAdjCapRowStatus */
	neTeLinkAdjCapRowStatus_active_c = 1,
	neTeLinkAdjCapRowStatus_notInService_c = 2,
	neTeLinkAdjCapRowStatus_notReady_c = 3,
	neTeLinkAdjCapRowStatus_createAndGo_c = 4,
	neTeLinkAdjCapRowStatus_createAndWait_c = 5,
	neTeLinkAdjCapRowStatus_destroy_c = 6,

	/* enums for column neTeLinkAdjCapStorageType */
	neTeLinkAdjCapStorageType_other_c = 1,
	neTeLinkAdjCapStorageType_volatile_c = 2,
	neTeLinkAdjCapStorageType_nonVolatile_c = 3,
	neTeLinkAdjCapStorageType_permanent_c = 4,
	neTeLinkAdjCapStorageType_readOnly_c = 5,
};

/* table neTeLinkAdjCapTable row entry data structure */
typedef struct neTeLinkAdjCapEntry_t
{
	/* Index values */
	uint32_t u32IfIndex;
	uint32_t u32Id;
	
	/* Column values */
	int32_t i32LowerType;
	int32_t i32LowerEncoding;
	int32_t i32UpperType;
	int32_t i32UpperEncoding;
	uint8_t au8MaxLspBandwidthPrio0[8];
	size_t u16MaxLspBandwidthPrio0_len;	/* # of uint8_t elements */
	uint8_t au8MaxLspBandwidthPrio1[8];
	size_t u16MaxLspBandwidthPrio1_len;	/* # of uint8_t elements */
	uint8_t au8MaxLspBandwidthPrio2[8];
	size_t u16MaxLspBandwidthPrio2_len;	/* # of uint8_t elements */
	uint8_t au8MaxLspBandwidthPrio3[8];
	size_t u16MaxLspBandwidthPrio3_len;	/* # of uint8_t elements */
	uint8_t au8MaxLspBandwidthPrio4[8];
	size_t u16MaxLspBandwidthPrio4_len;	/* # of uint8_t elements */
	uint8_t au8MaxLspBandwidthPrio5[8];
	size_t u16MaxLspBandwidthPrio5_len;	/* # of uint8_t elements */
	uint8_t au8MaxLspBandwidthPrio6[8];
	size_t u16MaxLspBandwidthPrio6_len;	/* # of uint8_t elements */
	uint8_t au8MaxLspBandwidthPrio7[8];
	size_t u16MaxLspBandwidthPrio7_len;	/* # of uint8_t elements */
	uint8_t u8RowStatus;
	uint8_t u8StorageType;
	
	xBTree_Node_t oBTreeNode;
} neTeLinkAdjCapEntry_t;

extern xBTree_t oNeTeLinkAdjCapTable_BTree;

/* neTeLinkAdjCapTable table mapper */
void neTeLinkAdjCapTable_init (void);
neTeLinkAdjCapEntry_t * neTeLinkAdjCapTable_createEntry (
	uint32_t u32IfIndex,
	uint32_t u32Id);
neTeLinkAdjCapEntry_t * neTeLinkAdjCapTable_getByIndex (
	uint32_t u32IfIndex,
	uint32_t u32Id);
neTeLinkAdjCapEntry_t * neTeLinkAdjCapTable_getNextIndex (
	uint32_t u32IfIndex,
	uint32_t u32Id);
void neTeLinkAdjCapTable_removeEntry (neTeLinkAdjCapEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point neTeLinkAdjCapTable_getFirst;
Netsnmp_Next_Data_Point neTeLinkAdjCapTable_getNext;
Netsnmp_Get_Data_Point neTeLinkAdjCapTable_get;
Netsnmp_Node_Handler neTeLinkAdjCapTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table neTeCompLinkAdjCapTable definitions
 */
#define NETECOMPLINKADJCAPID 1
#define NETECOMPLINKADJCAPLOWERTYPE 2
#define NETECOMPLINKADJCAPLOWERENCODING 3
#define NETECOMPLINKADJCAPUPPERTYPE 4
#define NETECOMPLINKADJCAPUPPERENCODING 5
#define NETECOMPLINKADJCAPMAXLSPBANDWIDTHPRIO0 6
#define NETECOMPLINKADJCAPMAXLSPBANDWIDTHPRIO1 7
#define NETECOMPLINKADJCAPMAXLSPBANDWIDTHPRIO2 8
#define NETECOMPLINKADJCAPMAXLSPBANDWIDTHPRIO3 9
#define NETECOMPLINKADJCAPMAXLSPBANDWIDTHPRIO4 10
#define NETECOMPLINKADJCAPMAXLSPBANDWIDTHPRIO5 11
#define NETECOMPLINKADJCAPMAXLSPBANDWIDTHPRIO6 12
#define NETECOMPLINKADJCAPMAXLSPBANDWIDTHPRIO7 13
#define NETECOMPLINKADJCAPROWSTATUS 14
#define NETECOMPLINKADJCAPSTORAGETYPE 15

enum
{
	/* enums for column neTeCompLinkAdjCapLowerType */
	neTeCompLinkAdjCapLowerType_unknown_c = 0,
	neTeCompLinkAdjCapLowerType_psc1_c = 1,
	neTeCompLinkAdjCapLowerType_psc2_c = 2,
	neTeCompLinkAdjCapLowerType_psc3_c = 3,
	neTeCompLinkAdjCapLowerType_psc4_c = 4,
	neTeCompLinkAdjCapLowerType_evpl_c = 30,
	neTeCompLinkAdjCapLowerType_pbb_c = 40,
	neTeCompLinkAdjCapLowerType_l2sc_c = 51,
	neTeCompLinkAdjCapLowerType_tdm_c = 100,
	neTeCompLinkAdjCapLowerType_otntdm_c = 110,
	neTeCompLinkAdjCapLowerType_dcsc_c = 125,
	neTeCompLinkAdjCapLowerType_lsc_c = 150,
	neTeCompLinkAdjCapLowerType_fsc_c = 200,

	/* enums for column neTeCompLinkAdjCapLowerEncoding */
	neTeCompLinkAdjCapLowerEncoding_notGmpls_c = 0,
	neTeCompLinkAdjCapLowerEncoding_packet_c = 1,
	neTeCompLinkAdjCapLowerEncoding_ethernet_c = 2,
	neTeCompLinkAdjCapLowerEncoding_ansiEtsiPdh_c = 3,
	neTeCompLinkAdjCapLowerEncoding_sdhSonet_c = 5,
	neTeCompLinkAdjCapLowerEncoding_digitalWrapper_c = 7,
	neTeCompLinkAdjCapLowerEncoding_lambda_c = 8,
	neTeCompLinkAdjCapLowerEncoding_fiber_c = 9,
	neTeCompLinkAdjCapLowerEncoding_fiberChannel_c = 11,
	neTeCompLinkAdjCapLowerEncoding_digitalPath_c = 12,
	neTeCompLinkAdjCapLowerEncoding_opticalChannel_c = 13,
	neTeCompLinkAdjCapLowerEncoding_line_c = 14,

	/* enums for column neTeCompLinkAdjCapUpperType */
	neTeCompLinkAdjCapUpperType_unknown_c = 0,
	neTeCompLinkAdjCapUpperType_psc1_c = 1,
	neTeCompLinkAdjCapUpperType_psc2_c = 2,
	neTeCompLinkAdjCapUpperType_psc3_c = 3,
	neTeCompLinkAdjCapUpperType_psc4_c = 4,
	neTeCompLinkAdjCapUpperType_evpl_c = 30,
	neTeCompLinkAdjCapUpperType_pbb_c = 40,
	neTeCompLinkAdjCapUpperType_l2sc_c = 51,
	neTeCompLinkAdjCapUpperType_tdm_c = 100,
	neTeCompLinkAdjCapUpperType_otntdm_c = 110,
	neTeCompLinkAdjCapUpperType_dcsc_c = 125,
	neTeCompLinkAdjCapUpperType_lsc_c = 150,
	neTeCompLinkAdjCapUpperType_fsc_c = 200,

	/* enums for column neTeCompLinkAdjCapUpperEncoding */
	neTeCompLinkAdjCapUpperEncoding_notGmpls_c = 0,
	neTeCompLinkAdjCapUpperEncoding_packet_c = 1,
	neTeCompLinkAdjCapUpperEncoding_ethernet_c = 2,
	neTeCompLinkAdjCapUpperEncoding_ansiEtsiPdh_c = 3,
	neTeCompLinkAdjCapUpperEncoding_sdhSonet_c = 5,
	neTeCompLinkAdjCapUpperEncoding_digitalWrapper_c = 7,
	neTeCompLinkAdjCapUpperEncoding_lambda_c = 8,
	neTeCompLinkAdjCapUpperEncoding_fiber_c = 9,
	neTeCompLinkAdjCapUpperEncoding_fiberChannel_c = 11,
	neTeCompLinkAdjCapUpperEncoding_digitalPath_c = 12,
	neTeCompLinkAdjCapUpperEncoding_opticalChannel_c = 13,
	neTeCompLinkAdjCapUpperEncoding_line_c = 14,

	/* enums for column neTeCompLinkAdjCapRowStatus */
	neTeCompLinkAdjCapRowStatus_active_c = 1,
	neTeCompLinkAdjCapRowStatus_notInService_c = 2,
	neTeCompLinkAdjCapRowStatus_notReady_c = 3,
	neTeCompLinkAdjCapRowStatus_createAndGo_c = 4,
	neTeCompLinkAdjCapRowStatus_createAndWait_c = 5,
	neTeCompLinkAdjCapRowStatus_destroy_c = 6,

	/* enums for column neTeCompLinkAdjCapStorageType */
	neTeCompLinkAdjCapStorageType_other_c = 1,
	neTeCompLinkAdjCapStorageType_volatile_c = 2,
	neTeCompLinkAdjCapStorageType_nonVolatile_c = 3,
	neTeCompLinkAdjCapStorageType_permanent_c = 4,
	neTeCompLinkAdjCapStorageType_readOnly_c = 5,
};

/* table neTeCompLinkAdjCapTable row entry data structure */
typedef struct neTeCompLinkAdjCapEntry_t
{
	/* Index values */
	uint32_t u32IfIndex;
	uint32_t u32Id;
	
	/* Column values */
	int32_t i32LowerType;
	int32_t i32LowerEncoding;
	int32_t i32UpperType;
	int32_t i32UpperEncoding;
	uint8_t au8MaxLspBandwidthPrio0[8];
	size_t u16MaxLspBandwidthPrio0_len;	/* # of uint8_t elements */
	uint8_t au8MaxLspBandwidthPrio1[8];
	size_t u16MaxLspBandwidthPrio1_len;	/* # of uint8_t elements */
	uint8_t au8MaxLspBandwidthPrio2[8];
	size_t u16MaxLspBandwidthPrio2_len;	/* # of uint8_t elements */
	uint8_t au8MaxLspBandwidthPrio3[8];
	size_t u16MaxLspBandwidthPrio3_len;	/* # of uint8_t elements */
	uint8_t au8MaxLspBandwidthPrio4[8];
	size_t u16MaxLspBandwidthPrio4_len;	/* # of uint8_t elements */
	uint8_t au8MaxLspBandwidthPrio5[8];
	size_t u16MaxLspBandwidthPrio5_len;	/* # of uint8_t elements */
	uint8_t au8MaxLspBandwidthPrio6[8];
	size_t u16MaxLspBandwidthPrio6_len;	/* # of uint8_t elements */
	uint8_t au8MaxLspBandwidthPrio7[8];
	size_t u16MaxLspBandwidthPrio7_len;	/* # of uint8_t elements */
	uint8_t u8RowStatus;
	uint8_t u8StorageType;
	
	xBTree_Node_t oBTreeNode;
} neTeCompLinkAdjCapEntry_t;

extern xBTree_t oNeTeCompLinkAdjCapTable_BTree;

/* neTeCompLinkAdjCapTable table mapper */
void neTeCompLinkAdjCapTable_init (void);
neTeCompLinkAdjCapEntry_t * neTeCompLinkAdjCapTable_createEntry (
	uint32_t u32IfIndex,
	uint32_t u32Id);
neTeCompLinkAdjCapEntry_t * neTeCompLinkAdjCapTable_getByIndex (
	uint32_t u32IfIndex,
	uint32_t u32Id);
neTeCompLinkAdjCapEntry_t * neTeCompLinkAdjCapTable_getNextIndex (
	uint32_t u32IfIndex,
	uint32_t u32Id);
void neTeCompLinkAdjCapTable_removeEntry (neTeCompLinkAdjCapEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point neTeCompLinkAdjCapTable_getFirst;
Netsnmp_Next_Data_Point neTeCompLinkAdjCapTable_getNext;
Netsnmp_Get_Data_Point neTeCompLinkAdjCapTable_get;
Netsnmp_Node_Handler neTeCompLinkAdjCapTable_mapper;
#endif	/* SNMP_SRC */



#	ifdef __cplusplus
}
#	endif

#endif /* __NETEDMIB_H__ */
