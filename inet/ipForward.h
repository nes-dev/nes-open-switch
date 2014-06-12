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

#ifndef __IPFORWARD_H__
#	define __IPFORWARD_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include "lib/binaryTree.h"
#include "lib/snmp.h"
#include "lib/ip.h"

#define TOBE_REPLACED 1


/**
 *	agent MIB function
 */
void ipForward_init (void);


/**
 *	scalar mapper(s)
 */
/** definitions for scalar(s) of ipForward **/
#define INETCIDRROUTENUMBER 6
#define INETCIDRROUTEDISCARDS 8

typedef struct ipForward_t
{
	uint32_t u32InetCidrRouteNumber;
	uint32_t u32InetCidrRouteDiscards;
} ipForward_t;

extern ipForward_t oIpForward;

#ifdef SNMP_SRC
Netsnmp_Node_Handler ipForward_mapper;
#endif	/* SNMP_SRC */



/**
 *	table mapper(s)
 */
/**
 *	table inetCidrRouteTable definitions
 */
#define INETCIDRROUTEDESTTYPE 1
#define INETCIDRROUTEDEST 2
#define INETCIDRROUTEPFXLEN 3
#define INETCIDRROUTEPOLICY 4
#define INETCIDRROUTENEXTHOPTYPE 5
#define INETCIDRROUTENEXTHOP 6
#define INETCIDRROUTEIFINDEX 7
#define INETCIDRROUTETYPE 8
#define INETCIDRROUTEPROTO 9
#define INETCIDRROUTEAGE 10
#define INETCIDRROUTENEXTHOPAS 11
#define INETCIDRROUTEMETRIC1 12
#define INETCIDRROUTEMETRIC2 13
#define INETCIDRROUTEMETRIC3 14
#define INETCIDRROUTEMETRIC4 15
#define INETCIDRROUTEMETRIC5 16
#define INETCIDRROUTESTATUS 17

enum
{
	/* enums for column inetCidrRouteDestType */
	inetCidrRouteDestType_unknown_c = 0,
	inetCidrRouteDestType_ipv4_c = 1,
	inetCidrRouteDestType_ipv6_c = 2,
	inetCidrRouteDestType_ipv4z_c = 3,
	inetCidrRouteDestType_ipv6z_c = 4,
	inetCidrRouteDestType_dns_c = 16,

	/* enums for column inetCidrRouteNextHopType */
	inetCidrRouteNextHopType_unknown_c = 0,
	inetCidrRouteNextHopType_ipv4_c = 1,
	inetCidrRouteNextHopType_ipv6_c = 2,
	inetCidrRouteNextHopType_ipv4z_c = 3,
	inetCidrRouteNextHopType_ipv6z_c = 4,
	inetCidrRouteNextHopType_dns_c = 16,

	/* enums for column inetCidrRouteType */
	inetCidrRouteType_other_c = 1,
	inetCidrRouteType_reject_c = 2,
	inetCidrRouteType_local_c = 3,
	inetCidrRouteType_remote_c = 4,
	inetCidrRouteType_blackhole_c = 5,

	/* enums for column inetCidrRouteProto */
	inetCidrRouteProto_other_c = 1,
	inetCidrRouteProto_local_c = 2,
	inetCidrRouteProto_netmgmt_c = 3,
	inetCidrRouteProto_icmp_c = 4,
	inetCidrRouteProto_egp_c = 5,
	inetCidrRouteProto_ggp_c = 6,
	inetCidrRouteProto_hello_c = 7,
	inetCidrRouteProto_rip_c = 8,
	inetCidrRouteProto_isIs_c = 9,
	inetCidrRouteProto_esIs_c = 10,
	inetCidrRouteProto_ciscoIgrp_c = 11,
	inetCidrRouteProto_bbnSpfIgp_c = 12,
	inetCidrRouteProto_ospf_c = 13,
	inetCidrRouteProto_bgp_c = 14,
	inetCidrRouteProto_idpr_c = 15,
	inetCidrRouteProto_ciscoEigrp_c = 16,
	inetCidrRouteProto_dvmrp_c = 17,

	/* enums for column inetCidrRouteStatus */
	inetCidrRouteStatus_active_c = 1,
	inetCidrRouteStatus_notInService_c = 2,
	inetCidrRouteStatus_notReady_c = 3,
	inetCidrRouteStatus_createAndGo_c = 4,
	inetCidrRouteStatus_createAndWait_c = 5,
	inetCidrRouteStatus_destroy_c = 6,
};

/* table inetCidrRouteTable row entry data structure */
typedef struct inetCidrRouteEntry_t
{
	/* Index values */
	int32_t i32DestType;
	uint8_t au8Dest[16];
	size_t u16Dest_len;	/* # of uint8_t elements */
	uint32_t u32PfxLen;
	xOid_t aoPolicy[128];
	size_t u16Policy_len;	/* # of xOid_t elements */
	int32_t i32NextHopType;
	uint8_t au8NextHop[16];
	size_t u16NextHop_len;	/* # of uint8_t elements */
	
	/* Column values */
	uint32_t u32IfIndex;
	int32_t i32Type;
	int32_t i32Proto;
	uint32_t u32Age;
	uint32_t u32NextHopAS;
	int32_t i32Metric1;
	int32_t i32Metric2;
	int32_t i32Metric3;
	int32_t i32Metric4;
	int32_t i32Metric5;
	int32_t i32Status;
	
	xBTree_Node_t oBTreeNode;
} inetCidrRouteEntry_t;

extern xBTree_t oInetCidrRouteTable_BTree;

/* inetCidrRouteTable table mapper */
void inetCidrRouteTable_init (void);
inetCidrRouteEntry_t * inetCidrRouteTable_createEntry (
	int32_t i32DestType,
	uint8_t *pau8Dest, size_t u16Dest_len,
	uint32_t u32PfxLen,
	xOid_t *paoPolicy, size_t u16Policy_len,
	int32_t i32NextHopType,
	uint8_t *pau8NextHop, size_t u16NextHop_len);
inetCidrRouteEntry_t * inetCidrRouteTable_getByIndex (
	int32_t i32DestType,
	uint8_t *pau8Dest, size_t u16Dest_len,
	uint32_t u32PfxLen,
	xOid_t *paoPolicy, size_t u16Policy_len,
	int32_t i32NextHopType,
	uint8_t *pau8NextHop, size_t u16NextHop_len);
inetCidrRouteEntry_t * inetCidrRouteTable_getNextIndex (
	int32_t i32DestType,
	uint8_t *pau8Dest, size_t u16Dest_len,
	uint32_t u32PfxLen,
	xOid_t *paoPolicy, size_t u16Policy_len,
	int32_t i32NextHopType,
	uint8_t *pau8NextHop, size_t u16NextHop_len);
void inetCidrRouteTable_removeEntry (inetCidrRouteEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point inetCidrRouteTable_getFirst;
Netsnmp_Next_Data_Point inetCidrRouteTable_getNext;
Netsnmp_Get_Data_Point inetCidrRouteTable_get;
Netsnmp_Node_Handler inetCidrRouteTable_mapper;
#endif	/* SNMP_SRC */



#	ifdef __cplusplus
}
#	endif

#endif /* __IPFORWARD_H__ */
