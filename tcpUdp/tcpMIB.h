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

#ifndef __TCPMIB_H__
#	define __TCPMIB_H__

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
void tcpMIB_init (void);


/**
 *	scalar mapper(s)
 */
/** definitions for scalar(s) of tcp **/
#define TCPRTOALGORITHM 1
#define TCPRTOMIN 2
#define TCPRTOMAX 3
#define TCPMAXCONN 4
#define TCPACTIVEOPENS 5
#define TCPPASSIVEOPENS 6
#define TCPATTEMPTFAILS 7
#define TCPESTABRESETS 8
#define TCPCURRESTAB 9
#define TCPINSEGS 10
#define TCPOUTSEGS 11
#define TCPRETRANSSEGS 12
#define TCPINERRS 14
#define TCPOUTRSTS 15
#define TCPHCINSEGS 17
#define TCPHCOUTSEGS 18

enum
{
	/* enums for scalar tcpRtoAlgorithm */
	tcpRtoAlgorithm_other_c = 1,
	tcpRtoAlgorithm_constant_c = 2,
	tcpRtoAlgorithm_rsre_c = 3,
	tcpRtoAlgorithm_vanj_c = 4,
	tcpRtoAlgorithm_rfc2988_c = 5,
};

typedef struct tcp_t
{
	int32_t i32RtoAlgorithm;
	int32_t i32RtoMin;
	int32_t i32RtoMax;
	int32_t i32MaxConn;
	uint32_t u32ActiveOpens;
	uint32_t u32PassiveOpens;
	uint32_t u32AttemptFails;
	uint32_t u32EstabResets;
	uint32_t u32CurrEstab;
	uint32_t u32InSegs;
	uint32_t u32OutSegs;
	uint32_t u32RetransSegs;
	uint32_t u32InErrs;
	uint32_t u32OutRsts;
	uint64_t u64HCInSegs;
	uint64_t u64HCOutSegs;
} tcp_t;

extern tcp_t oTcp;

#ifdef SNMP_SRC
Netsnmp_Node_Handler tcp_mapper;
#endif	/* SNMP_SRC */



/**
 *	table mapper(s)
 */
/**
 *	table tcpConnectionTable definitions
 */
#define TCPCONNECTIONLOCALADDRESSTYPE 1
#define TCPCONNECTIONLOCALADDRESS 2
#define TCPCONNECTIONLOCALPORT 3
#define TCPCONNECTIONREMADDRESSTYPE 4
#define TCPCONNECTIONREMADDRESS 5
#define TCPCONNECTIONREMPORT 6
#define TCPCONNECTIONSTATE 7
#define TCPCONNECTIONPROCESS 8

enum
{
	/* enums for column tcpConnectionLocalAddressType */
	tcpConnectionLocalAddressType_unknown_c = 0,
	tcpConnectionLocalAddressType_ipv4_c = 1,
	tcpConnectionLocalAddressType_ipv6_c = 2,
	tcpConnectionLocalAddressType_ipv4z_c = 3,
	tcpConnectionLocalAddressType_ipv6z_c = 4,
	tcpConnectionLocalAddressType_dns_c = 16,

	/* enums for column tcpConnectionRemAddressType */
	tcpConnectionRemAddressType_unknown_c = 0,
	tcpConnectionRemAddressType_ipv4_c = 1,
	tcpConnectionRemAddressType_ipv6_c = 2,
	tcpConnectionRemAddressType_ipv4z_c = 3,
	tcpConnectionRemAddressType_ipv6z_c = 4,
	tcpConnectionRemAddressType_dns_c = 16,

	/* enums for column tcpConnectionState */
	tcpConnectionState_closed_c = 1,
	tcpConnectionState_listen_c = 2,
	tcpConnectionState_synSent_c = 3,
	tcpConnectionState_synReceived_c = 4,
	tcpConnectionState_established_c = 5,
	tcpConnectionState_finWait1_c = 6,
	tcpConnectionState_finWait2_c = 7,
	tcpConnectionState_closeWait_c = 8,
	tcpConnectionState_lastAck_c = 9,
	tcpConnectionState_closing_c = 10,
	tcpConnectionState_timeWait_c = 11,
	tcpConnectionState_deleteTCB_c = 12,
};

/* table tcpConnectionTable row entry data structure */
typedef struct tcpConnectionEntry_t
{
	/* Index values */
	int32_t i32LocalAddressType;
	uint8_t au8LocalAddress[255];
	size_t u16LocalAddress_len;	/* # of uint8_t elements */
	uint32_t u32LocalPort;
	int32_t i32RemAddressType;
	uint8_t au8RemAddress[255];
	size_t u16RemAddress_len;	/* # of uint8_t elements */
	uint32_t u32RemPort;
	
	/* Column values */
	int32_t i32State;
	uint32_t u32Process;
	
	xBTree_Node_t oBTreeNode;
} tcpConnectionEntry_t;

extern xBTree_t oTcpConnectionTable_BTree;

/* tcpConnectionTable table mapper */
void tcpConnectionTable_init (void);
tcpConnectionEntry_t * tcpConnectionTable_createEntry (
	int32_t i32LocalAddressType,
	uint8_t *pau8LocalAddress, size_t u16LocalAddress_len,
	uint32_t u32LocalPort,
	int32_t i32RemAddressType,
	uint8_t *pau8RemAddress, size_t u16RemAddress_len,
	uint32_t u32RemPort);
tcpConnectionEntry_t * tcpConnectionTable_getByIndex (
	int32_t i32LocalAddressType,
	uint8_t *pau8LocalAddress, size_t u16LocalAddress_len,
	uint32_t u32LocalPort,
	int32_t i32RemAddressType,
	uint8_t *pau8RemAddress, size_t u16RemAddress_len,
	uint32_t u32RemPort);
tcpConnectionEntry_t * tcpConnectionTable_getNextIndex (
	int32_t i32LocalAddressType,
	uint8_t *pau8LocalAddress, size_t u16LocalAddress_len,
	uint32_t u32LocalPort,
	int32_t i32RemAddressType,
	uint8_t *pau8RemAddress, size_t u16RemAddress_len,
	uint32_t u32RemPort);
void tcpConnectionTable_removeEntry (tcpConnectionEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point tcpConnectionTable_getFirst;
Netsnmp_Next_Data_Point tcpConnectionTable_getNext;
Netsnmp_Get_Data_Point tcpConnectionTable_get;
Netsnmp_Node_Handler tcpConnectionTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table tcpListenerTable definitions
 */
#define TCPLISTENERLOCALADDRESSTYPE 1
#define TCPLISTENERLOCALADDRESS 2
#define TCPLISTENERLOCALPORT 3
#define TCPLISTENERPROCESS 4

enum
{
	/* enums for column tcpListenerLocalAddressType */
	tcpListenerLocalAddressType_unknown_c = 0,
	tcpListenerLocalAddressType_ipv4_c = 1,
	tcpListenerLocalAddressType_ipv6_c = 2,
	tcpListenerLocalAddressType_ipv4z_c = 3,
	tcpListenerLocalAddressType_ipv6z_c = 4,
	tcpListenerLocalAddressType_dns_c = 16,
};

/* table tcpListenerTable row entry data structure */
typedef struct tcpListenerEntry_t
{
	/* Index values */
	int32_t i32LocalAddressType;
	uint8_t au8LocalAddress[255];
	size_t u16LocalAddress_len;	/* # of uint8_t elements */
	uint32_t u32LocalPort;
	
	/* Column values */
	uint32_t u32Process;
	
	xBTree_Node_t oBTreeNode;
} tcpListenerEntry_t;

extern xBTree_t oTcpListenerTable_BTree;

/* tcpListenerTable table mapper */
void tcpListenerTable_init (void);
tcpListenerEntry_t * tcpListenerTable_createEntry (
	int32_t i32LocalAddressType,
	uint8_t *pau8LocalAddress, size_t u16LocalAddress_len,
	uint32_t u32LocalPort);
tcpListenerEntry_t * tcpListenerTable_getByIndex (
	int32_t i32LocalAddressType,
	uint8_t *pau8LocalAddress, size_t u16LocalAddress_len,
	uint32_t u32LocalPort);
tcpListenerEntry_t * tcpListenerTable_getNextIndex (
	int32_t i32LocalAddressType,
	uint8_t *pau8LocalAddress, size_t u16LocalAddress_len,
	uint32_t u32LocalPort);
void tcpListenerTable_removeEntry (tcpListenerEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point tcpListenerTable_getFirst;
Netsnmp_Next_Data_Point tcpListenerTable_getNext;
Netsnmp_Get_Data_Point tcpListenerTable_get;
Netsnmp_Node_Handler tcpListenerTable_mapper;
#endif	/* SNMP_SRC */



#	ifdef __cplusplus
}
#	endif

#endif /* __TCPMIB_H__ */
