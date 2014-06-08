/*
 *  Copyright (c) 2013, 2014
 *      NES <nes.open.switch@gmail.com>
 *
 *  All rights reserved. This source file is the sole property of NES, and
 *  contain proprietary and confidential information related to NES.
 *
 *  Licensed under the NES PROF License, Version 1.0 (the "License"); you may
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

#ifndef __CLNSMIB_H__
#	define __CLNSMIB_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include "lib/binaryTree.h"
#include "lib/snmp.h"

#define TOBE_REPLACED 1


/**
 *	agent MIB function
 */
void clnsMIB_init (void);


/**
 *	scalar mapper(s)
 */
/** definitions for scalar(s) of clnp **/
#define CLNPFORWARDING 1
#define CLNPDEFAULTLIFETIME 2
#define CLNPINRECEIVES 3
#define CLNPINHDRERRORS 4
#define CLNPINADDRERRORS 5
#define CLNPFORWPDUS 6
#define CLNPINUNKNOWNNLPS 7
#define CLNPINUNKNOWNULPS 8
#define CLNPINDISCARDS 9
#define CLNPINDELIVERS 10
#define CLNPOUTREQUESTS 11
#define CLNPOUTDISCARDS 12
#define CLNPOUTNOROUTES 13
#define CLNPREASMTIMEOUT 14
#define CLNPREASMREQDS 15
#define CLNPREASMOKS 16
#define CLNPREASMFAILS 17
#define CLNPSEGOKS 18
#define CLNPSEGFAILS 19
#define CLNPSEGCREATES 20
#define CLNPINOPTS 25
#define CLNPOUTOPTS 26
#define CLNPROUTINGDISCARDS 27

enum
{
	/* enums for scalar clnpForwarding */
	clnpForwarding_is_c = 1,
	clnpForwarding_es_c = 2,
};

typedef struct clnp_t
{
	int32_t i32Forwarding;
	int32_t i32DefaultLifeTime;
	uint32_t u32InReceives;
	uint32_t u32InHdrErrors;
	uint32_t u32InAddrErrors;
	uint32_t u32ForwPDUs;
	uint32_t u32InUnknownNLPs;
	uint32_t u32InUnknownULPs;
	uint32_t u32InDiscards;
	uint32_t u32InDelivers;
	uint32_t u32OutRequests;
	uint32_t u32OutDiscards;
	uint32_t u32OutNoRoutes;
	int32_t i32ReasmTimeout;
	uint32_t u32ReasmReqds;
	uint32_t u32ReasmOKs;
	uint32_t u32ReasmFails;
	uint32_t u32SegOKs;
	uint32_t u32SegFails;
	uint32_t u32SegCreates;
	uint32_t u32InOpts;
	uint32_t u32OutOpts;
	uint32_t u32RoutingDiscards;
} clnp_t;

extern clnp_t oClnp;

#ifdef SNMP_SRC
Netsnmp_Node_Handler clnp_mapper;
#endif	/* SNMP_SRC */

/** definitions for scalar(s) of error **/
#define CLNPINERRORS 1
#define CLNPOUTERRORS 2
#define CLNPINERRUNSPECS 3
#define CLNPINERRPROCS 4
#define CLNPINERRCKSUMS 5
#define CLNPINERRCONGESTS 6
#define CLNPINERRHDRS 7
#define CLNPINERRSEGS 8
#define CLNPINERRINCOMPS 9
#define CLNPINERRDUPS 10
#define CLNPINERRUNREACHDSTS 11
#define CLNPINERRUNKNOWNDSTS 12
#define CLNPINERRSRUNSPECS 13
#define CLNPINERRSRSYNTAXES 14
#define CLNPINERRSRUNKADDRS 15
#define CLNPINERRSRBADPATHS 16
#define CLNPINERRHOPS 17
#define CLNPINERRHOPREASSMS 18
#define CLNPINERRUNSOPTIONS 19
#define CLNPINERRUNSVERSIONS 20
#define CLNPINERRUNSSECURITIES 21
#define CLNPINERRUNSSRS 22
#define CLNPINERRUNSRRS 23
#define CLNPINERRINTERFERENCES 24
#define CLNPOUTERRUNSPECS 25
#define CLNPOUTERRPROCS 26
#define CLNPOUTERRCKSUMS 27
#define CLNPOUTERRCONGESTS 28
#define CLNPOUTERRHDRS 29
#define CLNPOUTERRSEGS 30
#define CLNPOUTERRINCOMPS 31
#define CLNPOUTERRDUPS 32
#define CLNPOUTERRUNREACHDSTS 33
#define CLNPOUTERRUNKNOWNDSTS 34
#define CLNPOUTERRSRUNSPECS 35
#define CLNPOUTERRSRSYNTAXES 36
#define CLNPOUTERRSRUNKADDRS 37
#define CLNPOUTERRSRBADPATHS 38
#define CLNPOUTERRHOPS 39
#define CLNPOUTERRHOPREASSMS 40
#define CLNPOUTERRUNSOPTIONS 41
#define CLNPOUTERRUNSVERSIONS 42
#define CLNPOUTERRUNSSECURITIES 43
#define CLNPOUTERRUNSSRS 44
#define CLNPOUTERRUNSRRS 45
#define CLNPOUTERRINTERFERENCES 46

typedef struct error_t
{
	uint32_t u32ClnpInErrors;
	uint32_t u32ClnpOutErrors;
	uint32_t u32ClnpInErrUnspecs;
	uint32_t u32ClnpInErrProcs;
	uint32_t u32ClnpInErrCksums;
	uint32_t u32ClnpInErrCongests;
	uint32_t u32ClnpInErrHdrs;
	uint32_t u32ClnpInErrSegs;
	uint32_t u32ClnpInErrIncomps;
	uint32_t u32ClnpInErrDups;
	uint32_t u32ClnpInErrUnreachDsts;
	uint32_t u32ClnpInErrUnknownDsts;
	uint32_t u32ClnpInErrSRUnspecs;
	uint32_t u32ClnpInErrSRSyntaxes;
	uint32_t u32ClnpInErrSRUnkAddrs;
	uint32_t u32ClnpInErrSRBadPaths;
	uint32_t u32ClnpInErrHops;
	uint32_t u32ClnpInErrHopReassms;
	uint32_t u32ClnpInErrUnsOptions;
	uint32_t u32ClnpInErrUnsVersions;
	uint32_t u32ClnpInErrUnsSecurities;
	uint32_t u32ClnpInErrUnsSRs;
	uint32_t u32ClnpInErrUnsRRs;
	uint32_t u32ClnpInErrInterferences;
	uint32_t u32ClnpOutErrUnspecs;
	uint32_t u32ClnpOutErrProcs;
	uint32_t u32ClnpOutErrCksums;
	uint32_t u32ClnpOutErrCongests;
	uint32_t u32ClnpOutErrHdrs;
	uint32_t u32ClnpOutErrSegs;
	uint32_t u32ClnpOutErrIncomps;
	uint32_t u32ClnpOutErrDups;
	uint32_t u32ClnpOutErrUnreachDsts;
	uint32_t u32ClnpOutErrUnknownDsts;
	uint32_t u32ClnpOutErrSRUnspecs;
	uint32_t u32ClnpOutErrSRSyntaxes;
	uint32_t u32ClnpOutErrSRUnkAddrs;
	uint32_t u32ClnpOutErrSRBadPaths;
	uint32_t u32ClnpOutErrHops;
	uint32_t u32ClnpOutErrHopReassms;
	uint32_t u32ClnpOutErrUnsOptions;
	uint32_t u32ClnpOutErrUnsVersions;
	uint32_t u32ClnpOutErrUnsSecurities;
	uint32_t u32ClnpOutErrUnsSRs;
	uint32_t u32ClnpOutErrUnsRRs;
	uint32_t u32ClnpOutErrInterferences;
} error_t;

extern error_t oError;

#ifdef SNMP_SRC
Netsnmp_Node_Handler error_mapper;
#endif	/* SNMP_SRC */

/** definitions for scalar(s) of esis **/
#define ESISESHINS 1
#define ESISESHOUTS 2
#define ESISISHINS 3
#define ESISISHOUTS 4
#define ESISRDUINS 5
#define ESISRDUOUTS 6

typedef struct esis_t
{
	uint32_t u32ESHins;
	uint32_t u32ESHouts;
	uint32_t u32ISHins;
	uint32_t u32ISHouts;
	uint32_t u32RDUins;
	uint32_t u32RDUouts;
} esis_t;

extern esis_t oEsis;

#ifdef SNMP_SRC
Netsnmp_Node_Handler esis_mapper;
#endif	/* SNMP_SRC */



/**
 *	table mapper(s)
 */
/**
 *	table clnpAddrTable definitions
 */
#define CLNPADENTADDR 1
#define CLNPADENTIFINDEX 2
#define CLNPADENTREASMMAXSIZE 3

/* table clnpAddrTable row entry data structure */
typedef struct clnpAddrEntry_t
{
	/* Index values */
	uint8_t au8EntAddr[21];
	size_t u16EntAddr_len;	/* # of uint8_t elements */
	
	/* Column values */
	int32_t i32EntIfIndex;
	int32_t i32EntReasmMaxSize;
	
	xBTree_Node_t oBTreeNode;
} clnpAddrEntry_t;

extern xBTree_t oClnpAddrTable_BTree;

/* clnpAddrTable table mapper */
void clnpAddrTable_init (void);
clnpAddrEntry_t * clnpAddrTable_createEntry (
	uint8_t *pau8EntAddr, size_t u16EntAddr_len);
clnpAddrEntry_t * clnpAddrTable_getByIndex (
	uint8_t *pau8EntAddr, size_t u16EntAddr_len);
clnpAddrEntry_t * clnpAddrTable_getNextIndex (
	uint8_t *pau8EntAddr, size_t u16EntAddr_len);
void clnpAddrTable_removeEntry (clnpAddrEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point clnpAddrTable_getFirst;
Netsnmp_Next_Data_Point clnpAddrTable_getNext;
Netsnmp_Get_Data_Point clnpAddrTable_get;
Netsnmp_Node_Handler clnpAddrTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table clnpRoutingTable definitions
 */
#define CLNPROUTEDEST 1
#define CLNPROUTEIFINDEX 2
#define CLNPROUTEMETRIC1 3
#define CLNPROUTEMETRIC2 4
#define CLNPROUTEMETRIC3 5
#define CLNPROUTEMETRIC4 6
#define CLNPROUTENEXTHOP 7
#define CLNPROUTETYPE 8
#define CLNPROUTEPROTO 9
#define CLNPROUTEAGE 10
#define CLNPROUTEMETRIC5 11
#define CLNPROUTEINFO 12

enum
{
	/* enums for column clnpRouteType */
	clnpRouteType_other_c = 1,
	clnpRouteType_invalid_c = 2,
	clnpRouteType_direct_c = 3,
	clnpRouteType_remote_c = 4,

	/* enums for column clnpRouteProto */
	clnpRouteProto_other_c = 1,
	clnpRouteProto_local_c = 2,
	clnpRouteProto_netmgmt_c = 3,
	clnpRouteProto_is_is_c = 9,
	clnpRouteProto_ciscoIgrp_c = 11,
	clnpRouteProto_bbnSpfIgp_c = 12,
	clnpRouteProto_ospf_c = 13,
	clnpRouteProto_bgp_c = 14,
};

/* table clnpRoutingTable row entry data structure */
typedef struct clnpRoutingEntry_t
{
	/* Index values */
	uint8_t au8RouteDest[21];
	size_t u16RouteDest_len;	/* # of uint8_t elements */
	
	/* Column values */
	int32_t i32RouteIfIndex;
	int32_t i32RouteMetric1;
	int32_t i32RouteMetric2;
	int32_t i32RouteMetric3;
	int32_t i32RouteMetric4;
	uint8_t au8RouteNextHop[21];
	size_t u16RouteNextHop_len;	/* # of uint8_t elements */
	int32_t i32RouteType;
	int32_t i32RouteProto;
	int32_t i32RouteAge;
	int32_t i32RouteMetric5;
	xOid_t aoRouteInfo[128];
	size_t u16RouteInfo_len;	/* # of xOid_t elements */
	
	xBTree_Node_t oBTreeNode;
} clnpRoutingEntry_t;

extern xBTree_t oClnpRoutingTable_BTree;

/* clnpRoutingTable table mapper */
void clnpRoutingTable_init (void);
clnpRoutingEntry_t * clnpRoutingTable_createEntry (
	uint8_t *pau8RouteDest, size_t u16RouteDest_len);
clnpRoutingEntry_t * clnpRoutingTable_getByIndex (
	uint8_t *pau8RouteDest, size_t u16RouteDest_len);
clnpRoutingEntry_t * clnpRoutingTable_getNextIndex (
	uint8_t *pau8RouteDest, size_t u16RouteDest_len);
void clnpRoutingTable_removeEntry (clnpRoutingEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point clnpRoutingTable_getFirst;
Netsnmp_Next_Data_Point clnpRoutingTable_getNext;
Netsnmp_Get_Data_Point clnpRoutingTable_get;
Netsnmp_Node_Handler clnpRoutingTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table clnpNetToMediaTable definitions
 */
#define CLNPNETTOMEDIAIFINDEX 1
#define CLNPNETTOMEDIAPHYSADDRESS 2
#define CLNPNETTOMEDIANETADDRESS 3
#define CLNPNETTOMEDIATYPE 4
#define CLNPNETTOMEDIAAGE 5
#define CLNPNETTOMEDIAHOLDTIME 6

enum
{
	/* enums for column clnpNetToMediaType */
	clnpNetToMediaType_other_c = 1,
	clnpNetToMediaType_invalid_c = 2,
	clnpNetToMediaType_dynamic_c = 3,
	clnpNetToMediaType_static_c = 4,
};

/* table clnpNetToMediaTable row entry data structure */
typedef struct clnpNetToMediaEntry_t
{
	/* Index values */
	int32_t i32IfIndex;
	uint8_t au8NetAddress[21];
	size_t u16NetAddress_len;	/* # of uint8_t elements */
	
	/* Column values */
	uint8_t au8PhysAddress[/* TODO: PhysAddress, PhysAddress, "" */ TOBE_REPLACED];
	size_t u16PhysAddress_len;	/* # of uint8_t elements */
	int32_t i32Type;
	int32_t i32Age;
	int32_t i32HoldTime;
	
	xBTree_Node_t oBTreeNode;
} clnpNetToMediaEntry_t;

extern xBTree_t oClnpNetToMediaTable_BTree;

/* clnpNetToMediaTable table mapper */
void clnpNetToMediaTable_init (void);
clnpNetToMediaEntry_t * clnpNetToMediaTable_createEntry (
	int32_t i32IfIndex,
	uint8_t *pau8NetAddress, size_t u16NetAddress_len);
clnpNetToMediaEntry_t * clnpNetToMediaTable_getByIndex (
	int32_t i32IfIndex,
	uint8_t *pau8NetAddress, size_t u16NetAddress_len);
clnpNetToMediaEntry_t * clnpNetToMediaTable_getNextIndex (
	int32_t i32IfIndex,
	uint8_t *pau8NetAddress, size_t u16NetAddress_len);
void clnpNetToMediaTable_removeEntry (clnpNetToMediaEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point clnpNetToMediaTable_getFirst;
Netsnmp_Next_Data_Point clnpNetToMediaTable_getNext;
Netsnmp_Get_Data_Point clnpNetToMediaTable_get;
Netsnmp_Node_Handler clnpNetToMediaTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table clnpMediaToNetTable definitions
 */
#define CLNPMEDIATONETIFINDEX 1
#define CLNPMEDIATONETADDRESS 2
#define CLNPMEDIATONETPHYSADDRESS 3
#define CLNPMEDIATONETTYPE 4
#define CLNPMEDIATONETAGE 5
#define CLNPMEDIATONETHOLDTIME 6

enum
{
	/* enums for column clnpMediaToNetType */
	clnpMediaToNetType_other_c = 1,
	clnpMediaToNetType_invalid_c = 2,
	clnpMediaToNetType_dynamic_c = 3,
	clnpMediaToNetType_static_c = 4,
};

/* table clnpMediaToNetTable row entry data structure */
typedef struct clnpMediaToNetEntry_t
{
	/* Index values */
	int32_t i32IfIndex;
	uint8_t au8PhysAddress[/* TODO: PhysAddress, PhysAddress, "" */ TOBE_REPLACED];
	size_t u16PhysAddress_len;	/* # of uint8_t elements */
	
	/* Column values */
	uint8_t au8Address[21];
	size_t u16Address_len;	/* # of uint8_t elements */
	int32_t i32Type;
	int32_t i32Age;
	int32_t i32HoldTime;
	
	xBTree_Node_t oBTreeNode;
} clnpMediaToNetEntry_t;

extern xBTree_t oClnpMediaToNetTable_BTree;

/* clnpMediaToNetTable table mapper */
void clnpMediaToNetTable_init (void);
clnpMediaToNetEntry_t * clnpMediaToNetTable_createEntry (
	int32_t i32IfIndex,
	uint8_t *pau8PhysAddress, size_t u16PhysAddress_len);
clnpMediaToNetEntry_t * clnpMediaToNetTable_getByIndex (
	int32_t i32IfIndex,
	uint8_t *pau8PhysAddress, size_t u16PhysAddress_len);
clnpMediaToNetEntry_t * clnpMediaToNetTable_getNextIndex (
	int32_t i32IfIndex,
	uint8_t *pau8PhysAddress, size_t u16PhysAddress_len);
void clnpMediaToNetTable_removeEntry (clnpMediaToNetEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point clnpMediaToNetTable_getFirst;
Netsnmp_Next_Data_Point clnpMediaToNetTable_getNext;
Netsnmp_Get_Data_Point clnpMediaToNetTable_get;
Netsnmp_Node_Handler clnpMediaToNetTable_mapper;
#endif	/* SNMP_SRC */



#	ifdef __cplusplus
}
#	endif

#endif /* __CLNSMIB_H__ */
