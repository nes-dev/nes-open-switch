/*
 *  Copyright (c) 2013, 2014
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

#ifndef __NEINETMIB_H__
#	define __NEINETMIB_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include "lib/ieee802.h"
#include "lib/binaryTree.h"
#include "lib/snmp.h"
#include "lib/ip.h"

#include <stdbool.h>

#define TOBE_REPLACED 1


/**
 *	agent MIB function
 */
void neInetMIB_init (void);


/**
 *	scalar mapper(s)
 */
/** definitions for scalar(s) of neInetScalars **/
#define NEINETFORWARDINGENABLE 1

enum
{
	/* enums for scalar neInetForwardingEnable */
	neInetForwardingEnable_ipv4_c = 0,
	neInetForwardingEnable_ipv6_c = 1,
	neInetForwardingEnable_clnp_c = 2,
};

typedef struct neInetScalars_t
{
	uint8_t au8ForwardingEnable[1];
	size_t u16ForwardingEnable_len;	/* # of uint8_t elements */
} neInetScalars_t;

extern neInetScalars_t oNeInetScalars;

#ifdef SNMP_SRC
Netsnmp_Node_Handler neInetScalars_mapper;
#endif	/* SNMP_SRC */

/** definitions for scalar(s) of neIpScalars **/
#define NEIPASN 1
#define NEIPROUTERID 2

typedef struct neIpScalars_t
{
	uint32_t u32Asn;
	uint32_t u32RouterId;
} neIpScalars_t;

extern neIpScalars_t oNeIpScalars;

#ifdef SNMP_SRC
Netsnmp_Node_Handler neIpScalars_mapper;
#endif	/* SNMP_SRC */



/**
 *	table mapper(s)
 */
/**
 *	table neInetInterfaceTable definitions
 */
#define NEINETINTERFACETRAFFICENABLE 1
#define NEINETINTERFACEFORWARDINGENABLE 2

enum
{
	/* enums for column neInetInterfaceTrafficEnable */
	neInetInterfaceTrafficEnable_true_c = 1,
	neInetInterfaceTrafficEnable_false_c = 2,

	/* enums for column neInetInterfaceForwardingEnable */
	neInetInterfaceForwardingEnable_ipv4_c = 0,
	neInetInterfaceForwardingEnable_ipv6_c = 1,
	neInetInterfaceForwardingEnable_clnp_c = 2,
};

/* table neInetInterfaceTable row entry data structure */
typedef struct neInetInterfaceEntry_t
{
	/* Index values */
	uint32_t u32IfIndex;
	
	/* Column values */
	int32_t i32TrafficEnable;
	uint8_t au8ForwardingEnable[1];
	size_t u16ForwardingEnable_len;	/* # of uint8_t elements */
	
	uint32_t u32NumIpv4Addresses;
	uint32_t u32NumIpv6Addresses;
	uint32_t u32NumIpv4zAddresses;
	uint32_t u32NumIpv6zAddresses;
	uint32_t u32NumIpv4UnNumAddresses;
	uint32_t u32NumIpv6UnNumAddresses;
	uint32_t u32NumIpv4zUnNumAddresses;
	uint32_t u32NumIpv6zUnNumAddresses;
	
	xBTree_Node_t oBTreeNode;
} neInetInterfaceEntry_t;

extern xBTree_t oNeInetInterfaceTable_BTree;

/* neInetInterfaceTable table mapper */
void neInetInterfaceTable_init (void);
neInetInterfaceEntry_t * neInetInterfaceTable_createEntry (
	uint32_t u32IfIndex);
neInetInterfaceEntry_t * neInetInterfaceTable_getByIndex (
	uint32_t u32IfIndex);
neInetInterfaceEntry_t * neInetInterfaceTable_getNextIndex (
	uint32_t u32IfIndex);
void neInetInterfaceTable_removeEntry (neInetInterfaceEntry_t *poEntry);
neInetInterfaceEntry_t *neInetInterfaceTable_createExt (
	uint32_t u32IfIndex,
	int32_t i32AddrType,
	uint8_t *pau8Addr, size_t u16Addr_len,
	bool bUnNumAddr);
bool neInetInterfaceTable_removeExt (
	neInetInterfaceEntry_t *poEntry,
	int32_t i32AddrType,
	uint8_t *pau8Addr, size_t u16Addr_len,
	bool bUnNumAddr);
bool neInetInterfaceTable_createHier (
	neInetInterfaceEntry_t *poEntry,
	int32_t i32AddrType,
	uint8_t *pau8Addr, size_t u16Addr_len);
bool neInetInterfaceTable_removeHier (
	neInetInterfaceEntry_t *poEntry,
	int32_t i32AddrType,
	uint8_t *pau8Addr, size_t u16Addr_len);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point neInetInterfaceTable_getFirst;
Netsnmp_Next_Data_Point neInetInterfaceTable_getNext;
Netsnmp_Get_Data_Point neInetInterfaceTable_get;
Netsnmp_Node_Handler neInetInterfaceTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table neInetIntRouteTable definitions
 */
#define NEINETINTROUTEDEST 1
#define NEINETINTROUTEDESTPREFIXLEN 2
#define NEINETINTROUTEINDEX 3
#define NEINETINTROUTENEXTHOP 4
#define NEINETINTROUTEIFINDEX 5
#define NEINETINTROUTEPROTO 6
#define NEINETINTROUTEPOLICY 7
#define NEINETINTROUTESTATE 8

enum
{
	/* enums for column neInetIntRouteProto */
	neInetIntRouteProto_other_c = 1,
	neInetIntRouteProto_local_c = 2,
	neInetIntRouteProto_netmgmt_c = 3,
	neInetIntRouteProto_icmp_c = 4,
	neInetIntRouteProto_egp_c = 5,
	neInetIntRouteProto_ggp_c = 6,
	neInetIntRouteProto_hello_c = 7,
	neInetIntRouteProto_rip_c = 8,
	neInetIntRouteProto_isIs_c = 9,
	neInetIntRouteProto_esIs_c = 10,
	neInetIntRouteProto_ciscoIgrp_c = 11,
	neInetIntRouteProto_bbnSpfIgp_c = 12,
	neInetIntRouteProto_ospf_c = 13,
	neInetIntRouteProto_bgp_c = 14,
	neInetIntRouteProto_idpr_c = 15,
	neInetIntRouteProto_ciscoEigrp_c = 16,
	neInetIntRouteProto_dvmrp_c = 17,

	/* enums for column neInetIntRouteState */
	neInetIntRouteState_enabled_c = 0,
	neInetIntRouteState_ecmp_c = 1,
};

/* table neInetIntRouteTable row entry data structure */
typedef struct neInetIntRouteEntry_t
{
	/* Index values */
	uint8_t au8Dest[20];
	size_t u16Dest_len;	/* # of uint8_t elements */
	uint32_t u32DestPrefixLen;
	uint32_t u32Index;
	uint8_t au8NextHop[20];
	size_t u16NextHop_len;	/* # of uint8_t elements */
	uint32_t u32IfIndex;
	int32_t i32Proto;
	
	/* Column values */
	xOid_t aoPolicy[128];
	size_t u16Policy_len;	/* # of xOid_t elements */
	uint8_t au8State[1];
	size_t u16State_len;	/* # of uint8_t elements */
	
	xBTree_Node_t oBTreeNode;
} neInetIntRouteEntry_t;

extern xBTree_t oNeInetIntRouteTable_BTree;

/* neInetIntRouteTable table mapper */
void neInetIntRouteTable_init (void);
neInetIntRouteEntry_t * neInetIntRouteTable_createEntry (
	uint8_t *pau8Dest, size_t u16Dest_len,
	uint32_t u32DestPrefixLen,
	uint32_t u32Index,
	uint8_t *pau8NextHop, size_t u16NextHop_len,
	uint32_t u32IfIndex,
	int32_t i32Proto);
neInetIntRouteEntry_t * neInetIntRouteTable_getByIndex (
	uint8_t *pau8Dest, size_t u16Dest_len,
	uint32_t u32DestPrefixLen,
	uint32_t u32Index,
	uint8_t *pau8NextHop, size_t u16NextHop_len,
	uint32_t u32IfIndex,
	int32_t i32Proto);
neInetIntRouteEntry_t * neInetIntRouteTable_getNextIndex (
	uint8_t *pau8Dest, size_t u16Dest_len,
	uint32_t u32DestPrefixLen,
	uint32_t u32Index,
	uint8_t *pau8NextHop, size_t u16NextHop_len,
	uint32_t u32IfIndex,
	int32_t i32Proto);
void neInetIntRouteTable_removeEntry (neInetIntRouteEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point neInetIntRouteTable_getFirst;
Netsnmp_Next_Data_Point neInetIntRouteTable_getNext;
Netsnmp_Get_Data_Point neInetIntRouteTable_get;
Netsnmp_Node_Handler neInetIntRouteTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table neInetRouteTable definitions
 */
#define NEINETROUTEDEST 1
#define NEINETROUTEDESTPREFIXLEN 2
#define NEINETROUTEINDEX 3
#define NEINETROUTENEXTHOP 4
#define NEINETROUTEIFINDEX 5
#define NEINETROUTEPROTO 6
#define NEINETROUTEPOLICY 7
#define NEINETROUTESTATE 8

enum
{
	/* enums for column neInetRouteProto */
	neInetRouteProto_other_c = 1,
	neInetRouteProto_local_c = 2,
	neInetRouteProto_netmgmt_c = 3,
	neInetRouteProto_icmp_c = 4,
	neInetRouteProto_egp_c = 5,
	neInetRouteProto_ggp_c = 6,
	neInetRouteProto_hello_c = 7,
	neInetRouteProto_rip_c = 8,
	neInetRouteProto_isIs_c = 9,
	neInetRouteProto_esIs_c = 10,
	neInetRouteProto_ciscoIgrp_c = 11,
	neInetRouteProto_bbnSpfIgp_c = 12,
	neInetRouteProto_ospf_c = 13,
	neInetRouteProto_bgp_c = 14,
	neInetRouteProto_idpr_c = 15,
	neInetRouteProto_ciscoEigrp_c = 16,
	neInetRouteProto_dvmrp_c = 17,

	/* enums for column neInetRouteState */
	neInetRouteState_enabled_c = 0,
	neInetRouteState_ecmp_c = 1,
};

/* table neInetRouteTable row entry data structure */
typedef struct neInetRouteEntry_t
{
	/* Index values */
	uint8_t au8Dest[20];
	size_t u16Dest_len;	/* # of uint8_t elements */
	uint32_t u32DestPrefixLen;
	uint32_t u32Index;
	uint8_t au8NextHop[20];
	size_t u16NextHop_len;	/* # of uint8_t elements */
	uint32_t u32IfIndex;
	
	/* Column values */
	xOid_t aoPolicy[128];
	size_t u16Policy_len;	/* # of xOid_t elements */
	uint8_t au8State[1];
	size_t u16State_len;	/* # of uint8_t elements */
	
	xBTree_Node_t oBTreeNode;
} neInetRouteEntry_t;

extern xBTree_t oNeInetRouteTable_BTree;

/* neInetRouteTable table mapper */
void neInetRouteTable_init (void);
neInetRouteEntry_t * neInetRouteTable_createEntry (
	uint8_t *pau8Dest, size_t u16Dest_len,
	uint32_t u32DestPrefixLen,
	uint32_t u32Index,
	uint8_t *pau8NextHop, size_t u16NextHop_len,
	uint32_t u32IfIndex);
neInetRouteEntry_t * neInetRouteTable_getByIndex (
	uint8_t *pau8Dest, size_t u16Dest_len,
	uint32_t u32DestPrefixLen,
	uint32_t u32Index,
	uint8_t *pau8NextHop, size_t u16NextHop_len,
	uint32_t u32IfIndex);
neInetRouteEntry_t * neInetRouteTable_getNextIndex (
	uint8_t *pau8Dest, size_t u16Dest_len,
	uint32_t u32DestPrefixLen,
	uint32_t u32Index,
	uint8_t *pau8NextHop, size_t u16NextHop_len,
	uint32_t u32IfIndex);
void neInetRouteTable_removeEntry (neInetRouteEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point neInetRouteTable_getFirst;
Netsnmp_Next_Data_Point neInetRouteTable_getNext;
Netsnmp_Get_Data_Point neInetRouteTable_get;
Netsnmp_Node_Handler neInetRouteTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table neIpAddressTable definitions
 */
#define NEIPADDRESSPREFIXLENGTH 1

/* table neIpAddressTable row entry data structure */
typedef struct neIpAddressEntry_t
{
	/* Index values */
// 	int32_t i32IpAddressAddrType;
// 	uint8_t au8IpAddressAddr[20];
// 	size_t u16IpAddressAddr_len;	/* # of uint8_t elements */
	
	/* Column values */
	uint32_t u32PrefixLength;
	
// 	xBTree_Node_t oBTreeNode;
} neIpAddressEntry_t;

// extern xBTree_t oNeIpAddressTable_BTree;

/* neIpAddressTable table mapper */
void neIpAddressTable_init (void);
neIpAddressEntry_t * neIpAddressTable_createEntry (
	int32_t i32IpAddressAddrType,
	uint8_t *pau8IpAddressAddr, size_t u16IpAddressAddr_len);
neIpAddressEntry_t * neIpAddressTable_getByIndex (
	int32_t i32IpAddressAddrType,
	uint8_t *pau8IpAddressAddr, size_t u16IpAddressAddr_len);
neIpAddressEntry_t * neIpAddressTable_getNextIndex (
	int32_t i32IpAddressAddrType,
	uint8_t *pau8IpAddressAddr, size_t u16IpAddressAddr_len);
void neIpAddressTable_removeEntry (neIpAddressEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point neIpAddressTable_getFirst;
Netsnmp_Next_Data_Point neIpAddressTable_getNext;
Netsnmp_Get_Data_Point neIpAddressTable_get;
Netsnmp_Node_Handler neIpAddressTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table neIpUnNumTable definitions
 */
#define NEIPUNNUMADDRESSTYPE 1
#define NEIPUNNUMNUMBEREDIFINDEX 2
#define NEIPUNNUMLOCALADDRESS 3
#define NEIPUNNUMREMOTEADDRESS 4
#define NEIPUNNUMLOCALID 5
#define NEIPUNNUMREMOTEID 6
#define NEIPUNNUMDESTPHYSADDRESS 7
#define NEIPUNNUMROWSTATUS 8
#define NEIPUNNUMSTORAGETYPE 9

enum
{
	/* enums for column neIpUnNumAddressType */
	neIpUnNumAddressType_unknown_c = 0,
	neIpUnNumAddressType_ipv4_c = 1,
	neIpUnNumAddressType_ipv6_c = 2,
	neIpUnNumAddressType_ipv4z_c = 3,
	neIpUnNumAddressType_ipv6z_c = 4,
	neIpUnNumAddressType_dns_c = 16,

	/* enums for column neIpUnNumRowStatus */
	neIpUnNumRowStatus_active_c = 1,
	neIpUnNumRowStatus_notInService_c = 2,
	neIpUnNumRowStatus_notReady_c = 3,
	neIpUnNumRowStatus_createAndGo_c = 4,
	neIpUnNumRowStatus_createAndWait_c = 5,
	neIpUnNumRowStatus_destroy_c = 6,

	/* enums for column neIpUnNumStorageType */
	neIpUnNumStorageType_other_c = 1,
	neIpUnNumStorageType_volatile_c = 2,
	neIpUnNumStorageType_nonVolatile_c = 3,
	neIpUnNumStorageType_permanent_c = 4,
	neIpUnNumStorageType_readOnly_c = 5,
};

/* table neIpUnNumTable row entry data structure */
typedef struct neIpUnNumEntry_t
{
	/* Index values */
	uint32_t u32IfIndex;
	
	/* Column values */
	int32_t i32AddressType;
	uint32_t u32NumberedIfIndex;
	uint8_t au8LocalAddress[20];
	size_t u16LocalAddress_len;	/* # of uint8_t elements */
	uint8_t au8RemoteAddress[20];
	size_t u16RemoteAddress_len;	/* # of uint8_t elements */
	uint32_t u32LocalId;
	uint32_t u32RemoteId;
	uint8_t au8DestPhysAddress[IeeeEui64_size_c];
	size_t u16DestPhysAddress_len;	/* # of uint8_t elements */
	uint8_t u8RowStatus;
	uint8_t u8StorageType;
	
	xBTree_Node_t oBTreeNode;
	xBTree_Node_t oLocalId_BTreeNode;
	xBTree_Node_t oRemoteId_BTreeNode;
} neIpUnNumEntry_t;

extern xBTree_t oNeIpUnNumTable_BTree;
extern xBTree_t oNeIpUnNumTable_LocalId_BTree;
extern xBTree_t oNeIpUnNumTable_RemoteId_BTree;

/* neIpUnNumTable table mapper */
void neIpUnNumTable_init (void);
neIpUnNumEntry_t * neIpUnNumTable_createEntry (
	uint32_t u32IfIndex);
neIpUnNumEntry_t * neIpUnNumTable_getByIndex (
	uint32_t u32IfIndex);
neIpUnNumEntry_t * neIpUnNumTable_getNextIndex (
	uint32_t u32IfIndex);
neIpUnNumEntry_t * neIpUnNumTable_LocalId_getByIndex (
	uint32_t u32LocalId);
neIpUnNumEntry_t * neIpUnNumTable_LocalId_getNextIndex (
	uint32_t u32LocalId);
neIpUnNumEntry_t * neIpUnNumTable_RemoteId_getByIndex (
	uint32_t u32RemoteId,
	int32_t i32AddressType,
	uint8_t *pau8RemoteAddress, size_t u16RemoteAddress_len);
neIpUnNumEntry_t * neIpUnNumTable_RemoteId_getNextIndex (
	uint32_t u32RemoteId,
	int32_t i32AddressType,
	uint8_t *pau8RemoteAddress, size_t u16RemoteAddress_len);
void neIpUnNumTable_removeEntry (neIpUnNumEntry_t *poEntry);
neIpUnNumEntry_t * neIpUnNumTable_createExt (
	uint32_t u32IfIndex);
bool neIpUnNumTable_removeExt (neIpUnNumEntry_t *poEntry);
bool neIpUnNumTable_createHier (neIpUnNumEntry_t *poEntry);
bool neIpUnNumTable_removeHier (neIpUnNumEntry_t *poEntry);
bool neIpUnNumRowStatus_handler (
	neIpUnNumEntry_t *poEntry,
	int32_t i32RowStatus);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point neIpUnNumTable_getFirst;
Netsnmp_Next_Data_Point neIpUnNumTable_getNext;
Netsnmp_Get_Data_Point neIpUnNumTable_get;
Netsnmp_Node_Handler neIpUnNumTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table neIpAsNodeTable definitions
 */
#define NEIPASNODEASN 1
#define NEIPASNODEADDRTYPE 2
#define NEIPASNODEADDR 3
#define NEIPASNODEADDRPREFIXLEN 4
#define NEIPASNODEROUTERID 5
#define NEIPASNODEINFO 6
#define NEIPASNODEROWSTATUS 7
#define NEIPASNODESTORAGETYPE 8

enum
{
	/* enums for column neIpAsNodeAddrType */
	neIpAsNodeAddrType_unknown_c = 0,
	neIpAsNodeAddrType_ipv4_c = 1,
	neIpAsNodeAddrType_ipv6_c = 2,
	neIpAsNodeAddrType_ipv4z_c = 3,
	neIpAsNodeAddrType_ipv6z_c = 4,
	neIpAsNodeAddrType_dns_c = 16,

	/* enums for column neIpAsNodeInfo */
	neIpAsNodeInfo_teAddress_c = 0,
	neIpAsNodeInfo_ospf_c = 1,
	neIpAsNodeInfo_isis_c = 2,
	neIpAsNodeInfo_bgp_c = 3,
	neIpAsNodeInfo_ldp_c = 4,
	neIpAsNodeInfo_rsvp_c = 5,

	/* enums for column neIpAsNodeRowStatus */
	neIpAsNodeRowStatus_active_c = 1,
	neIpAsNodeRowStatus_notInService_c = 2,
	neIpAsNodeRowStatus_notReady_c = 3,
	neIpAsNodeRowStatus_createAndGo_c = 4,
	neIpAsNodeRowStatus_createAndWait_c = 5,
	neIpAsNodeRowStatus_destroy_c = 6,

	/* enums for column neIpAsNodeStorageType */
	neIpAsNodeStorageType_other_c = 1,
	neIpAsNodeStorageType_volatile_c = 2,
	neIpAsNodeStorageType_nonVolatile_c = 3,
	neIpAsNodeStorageType_permanent_c = 4,
	neIpAsNodeStorageType_readOnly_c = 5,
};

/* table neIpAsNodeTable row entry data structure */
typedef struct neIpAsNodeEntry_t
{
	/* Index values */
	uint32_t u32Asn;
	int32_t i32AddrType;
	uint8_t au8Addr[20];
	size_t u16Addr_len;	/* # of uint8_t elements */
	uint32_t u32AddrPrefixLen;
	
	/* Column values */
	uint32_t u32RouterId;
	uint8_t au8Info[1];
	size_t u16Info_len;	/* # of uint8_t elements */
	uint8_t u8RowStatus;
	uint8_t u8StorageType;
	
	xBTree_Node_t oBTreeNode;
} neIpAsNodeEntry_t;

extern xBTree_t oNeIpAsNodeTable_BTree;

/* neIpAsNodeTable table mapper */
void neIpAsNodeTable_init (void);
neIpAsNodeEntry_t * neIpAsNodeTable_createEntry (
	uint32_t u32Asn,
	int32_t i32AddrType,
	uint8_t *pau8Addr, size_t u16Addr_len,
	uint32_t u32AddrPrefixLen);
neIpAsNodeEntry_t * neIpAsNodeTable_getByIndex (
	uint32_t u32Asn,
	int32_t i32AddrType,
	uint8_t *pau8Addr, size_t u16Addr_len,
	uint32_t u32AddrPrefixLen);
neIpAsNodeEntry_t * neIpAsNodeTable_getNextIndex (
	uint32_t u32Asn,
	int32_t i32AddrType,
	uint8_t *pau8Addr, size_t u16Addr_len,
	uint32_t u32AddrPrefixLen);
void neIpAsNodeTable_removeEntry (neIpAsNodeEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point neIpAsNodeTable_getFirst;
Netsnmp_Next_Data_Point neIpAsNodeTable_getNext;
Netsnmp_Get_Data_Point neIpAsNodeTable_get;
Netsnmp_Node_Handler neIpAsNodeTable_mapper;
#endif	/* SNMP_SRC */



#	ifdef __cplusplus
}
#	endif

#endif /* __NEINETMIB_H__ */
