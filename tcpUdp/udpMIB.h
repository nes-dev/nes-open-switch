/*
 *  Copyright (c) 2008-2016
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

#ifndef __UDPMIB_H__
#	define __UDPMIB_H__

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
void udpMIB_init (void);


/**
 *	scalar mapper(s)
 */
/** definitions for scalar(s) of udp **/
#define UDPINDATAGRAMS 1
#define UDPNOPORTS 2
#define UDPINERRORS 3
#define UDPOUTDATAGRAMS 4
#define UDPHCINDATAGRAMS 8
#define UDPHCOUTDATAGRAMS 9

typedef struct udp_t
{
	uint32_t u32InDatagrams;
	uint32_t u32NoPorts;
	uint32_t u32InErrors;
	uint32_t u32OutDatagrams;
	uint64_t u64HCInDatagrams;
	uint64_t u64HCOutDatagrams;
} udp_t;

extern udp_t oUdp;

#ifdef SNMP_SRC
Netsnmp_Node_Handler udp_mapper;
#endif	/* SNMP_SRC */



/**
 *	table mapper(s)
 */
/**
 *	table udpEndpointTable definitions
 */
#define UDPENDPOINTLOCALADDRESSTYPE 1
#define UDPENDPOINTLOCALADDRESS 2
#define UDPENDPOINTLOCALPORT 3
#define UDPENDPOINTREMOTEADDRESSTYPE 4
#define UDPENDPOINTREMOTEADDRESS 5
#define UDPENDPOINTREMOTEPORT 6
#define UDPENDPOINTINSTANCE 7
#define UDPENDPOINTPROCESS 8

enum
{
	/* enums for column udpEndpointLocalAddressType */
	udpEndpointLocalAddressType_unknown_c = 0,
	udpEndpointLocalAddressType_ipv4_c = 1,
	udpEndpointLocalAddressType_ipv6_c = 2,
	udpEndpointLocalAddressType_ipv4z_c = 3,
	udpEndpointLocalAddressType_ipv6z_c = 4,
	udpEndpointLocalAddressType_dns_c = 16,

	/* enums for column udpEndpointRemoteAddressType */
	udpEndpointRemoteAddressType_unknown_c = 0,
	udpEndpointRemoteAddressType_ipv4_c = 1,
	udpEndpointRemoteAddressType_ipv6_c = 2,
	udpEndpointRemoteAddressType_ipv4z_c = 3,
	udpEndpointRemoteAddressType_ipv6z_c = 4,
	udpEndpointRemoteAddressType_dns_c = 16,
};

/* table udpEndpointTable row entry data structure */
typedef struct udpEndpointEntry_t
{
	/* Index values */
	int32_t i32LocalAddressType;
	uint8_t au8LocalAddress[255];
	size_t u16LocalAddress_len;	/* # of uint8_t elements */
	uint32_t u32LocalPort;
	int32_t i32RemoteAddressType;
	uint8_t au8RemoteAddress[255];
	size_t u16RemoteAddress_len;	/* # of uint8_t elements */
	uint32_t u32RemotePort;
	uint32_t u32Instance;
	
	/* Column values */
	uint32_t u32Process;
	
	xBTree_Node_t oBTreeNode;
} udpEndpointEntry_t;

extern xBTree_t oUdpEndpointTable_BTree;

/* udpEndpointTable table mapper */
void udpEndpointTable_init (void);
udpEndpointEntry_t * udpEndpointTable_createEntry (
	int32_t i32LocalAddressType,
	uint8_t *pau8LocalAddress, size_t u16LocalAddress_len,
	uint32_t u32LocalPort,
	int32_t i32RemoteAddressType,
	uint8_t *pau8RemoteAddress, size_t u16RemoteAddress_len,
	uint32_t u32RemotePort,
	uint32_t u32Instance);
udpEndpointEntry_t * udpEndpointTable_getByIndex (
	int32_t i32LocalAddressType,
	uint8_t *pau8LocalAddress, size_t u16LocalAddress_len,
	uint32_t u32LocalPort,
	int32_t i32RemoteAddressType,
	uint8_t *pau8RemoteAddress, size_t u16RemoteAddress_len,
	uint32_t u32RemotePort,
	uint32_t u32Instance);
udpEndpointEntry_t * udpEndpointTable_getNextIndex (
	int32_t i32LocalAddressType,
	uint8_t *pau8LocalAddress, size_t u16LocalAddress_len,
	uint32_t u32LocalPort,
	int32_t i32RemoteAddressType,
	uint8_t *pau8RemoteAddress, size_t u16RemoteAddress_len,
	uint32_t u32RemotePort,
	uint32_t u32Instance);
void udpEndpointTable_removeEntry (udpEndpointEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point udpEndpointTable_getFirst;
Netsnmp_Next_Data_Point udpEndpointTable_getNext;
Netsnmp_Get_Data_Point udpEndpointTable_get;
Netsnmp_Node_Handler udpEndpointTable_mapper;
#endif	/* SNMP_SRC */



#	ifdef __cplusplus
}
#	endif

#endif /* __UDPMIB_H__ */
