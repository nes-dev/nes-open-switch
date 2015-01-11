/*
 *  Copyright (c) 2008-2015
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

#ifndef __IPMIB_H__
#	define __IPMIB_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include "lib/lib.h"
#include "lib/ieee802.h"
#include "lib/binaryTree.h"
#include "lib/snmp.h"
#include "lib/ip.h"
#include "neInetMIB.h"

#include <stdbool.h>

#define TOBE_REPLACED 1


/**
 *	agent MIB function
 */
void ipMIB_init (void);


/**
 *	scalar mapper(s)
 */
/** definitions for scalar(s) of ip **/
#define IPFORWARDING 1
#define IPDEFAULTTTL 2
#define IPREASMTIMEOUT 13
#define IPV6IPFORWARDING 25
#define IPV6IPDEFAULTHOPLIMIT 26
#define IPV4INTERFACETABLELASTCHANGE 27
#define IPV6INTERFACETABLELASTCHANGE 29
#define IPADDRESSSPINLOCK 33
#define IPV6ROUTERADVERTSPINLOCK 38

enum
{
	/* enums for scalar ipForwarding */
	ipForwarding_forwarding_c = 1,
	ipForwarding_notForwarding_c = 2,

	/* enums for scalar ipv6IpForwarding */
	ipv6IpForwarding_forwarding_c = 1,
	ipv6IpForwarding_notForwarding_c = 2,
};

typedef struct ip_t
{
	int32_t i32Forwarding;
	int32_t i32DefaultTTL;
	int32_t i32ReasmTimeout;
	int32_t i32Ipv6IpForwarding;
	int32_t i32Ipv6IpDefaultHopLimit;
	uint32_t u32Ipv4InterfaceTableLastChange;
	uint32_t u32Ipv6InterfaceTableLastChange;
	int32_t i32AddressSpinLock;
	int32_t i32Ipv6RouterAdvertSpinLock;
	
	uint32_t u32NumIpv4Addresses;
	uint32_t u32NumIpv6Addresses;
	uint32_t u32NumIpv4zAddresses;
	uint32_t u32NumIpv6zAddresses;
	uint32_t u32NumIpv4UnNumAddresses;
	uint32_t u32NumIpv6UnNumAddresses;
	uint32_t u32NumIpv4zUnNumAddresses;
	uint32_t u32NumIpv6zUnNumAddresses;
} ip_t;

extern ip_t oIp;

#ifdef SNMP_SRC
Netsnmp_Node_Handler ip_mapper;
#endif	/* SNMP_SRC */

/** definitions for scalar(s) of ipTrafficStats **/
#define IPIFSTATSTABLELASTCHANGE 2

typedef struct ipTrafficStats_t
{
	uint32_t u32IfStatsTableLastChange;
} ipTrafficStats_t;

extern ipTrafficStats_t oIpTrafficStats;

#ifdef SNMP_SRC
Netsnmp_Node_Handler ipTrafficStats_mapper;
#endif	/* SNMP_SRC */



/**
 *	table mapper(s)
 */
/**
 *	table ipv4InterfaceTable definitions
 */
#define IPV4INTERFACEIFINDEX 1
#define IPV4INTERFACEREASMMAXSIZE 2
#define IPV4INTERFACEENABLESTATUS 3
#define IPV4INTERFACERETRANSMITTIME 4

enum
{
	/* enums for column ipv4InterfaceEnableStatus */
	ipv4InterfaceEnableStatus_up_c = 1,
	ipv4InterfaceEnableStatus_down_c = 2,
};

/* table ipv4InterfaceTable row entry data structure */
typedef struct ipv4InterfaceEntry_t
{
	/* Index values */
	uint32_t u32IfIndex;
	
	/* Column values */
	int32_t i32ReasmMaxSize;
	int32_t i32EnableStatus;
	uint32_t u32RetransmitTime;
	
	xBTree_Node_t oBTreeNode;
} ipv4InterfaceEntry_t;

extern xBTree_t oIpv4InterfaceTable_BTree;

/* ipv4InterfaceTable table mapper */
void ipv4InterfaceTable_init (void);
ipv4InterfaceEntry_t * ipv4InterfaceTable_createEntry (
	uint32_t u32IfIndex);
ipv4InterfaceEntry_t * ipv4InterfaceTable_getByIndex (
	uint32_t u32IfIndex);
ipv4InterfaceEntry_t * ipv4InterfaceTable_getNextIndex (
	uint32_t u32IfIndex);
void ipv4InterfaceTable_removeEntry (ipv4InterfaceEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ipv4InterfaceTable_getFirst;
Netsnmp_Next_Data_Point ipv4InterfaceTable_getNext;
Netsnmp_Get_Data_Point ipv4InterfaceTable_get;
Netsnmp_Node_Handler ipv4InterfaceTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ipv6InterfaceTable definitions
 */
#define IPV6INTERFACEIFINDEX 1
#define IPV6INTERFACEREASMMAXSIZE 2
#define IPV6INTERFACEIDENTIFIER 3
#define IPV6INTERFACEENABLESTATUS 5
#define IPV6INTERFACEREACHABLETIME 6
#define IPV6INTERFACERETRANSMITTIME 7
#define IPV6INTERFACEFORWARDING 8

enum
{
	/* enums for column ipv6InterfaceEnableStatus */
	ipv6InterfaceEnableStatus_up_c = 1,
	ipv6InterfaceEnableStatus_down_c = 2,

	/* enums for column ipv6InterfaceForwarding */
	ipv6InterfaceForwarding_forwarding_c = 1,
	ipv6InterfaceForwarding_notForwarding_c = 2,
};

/* table ipv6InterfaceTable row entry data structure */
typedef struct ipv6InterfaceEntry_t
{
	/* Index values */
	uint32_t u32IfIndex;
	
	/* Column values */
	uint32_t u32ReasmMaxSize;
	uint8_t au8Identifier[8];
	size_t u16Identifier_len;	/* # of uint8_t elements */
	int32_t i32EnableStatus;
	uint32_t u32ReachableTime;
	uint32_t u32RetransmitTime;
	int32_t i32Forwarding;
	
	xBTree_Node_t oBTreeNode;
} ipv6InterfaceEntry_t;

extern xBTree_t oIpv6InterfaceTable_BTree;

/* ipv6InterfaceTable table mapper */
void ipv6InterfaceTable_init (void);
ipv6InterfaceEntry_t * ipv6InterfaceTable_createEntry (
	uint32_t u32IfIndex);
ipv6InterfaceEntry_t * ipv6InterfaceTable_getByIndex (
	uint32_t u32IfIndex);
ipv6InterfaceEntry_t * ipv6InterfaceTable_getNextIndex (
	uint32_t u32IfIndex);
void ipv6InterfaceTable_removeEntry (ipv6InterfaceEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ipv6InterfaceTable_getFirst;
Netsnmp_Next_Data_Point ipv6InterfaceTable_getNext;
Netsnmp_Get_Data_Point ipv6InterfaceTable_get;
Netsnmp_Node_Handler ipv6InterfaceTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ipSystemStatsTable definitions
 */
#define IPSYSTEMSTATSIPVERSION 1
#define IPSYSTEMSTATSINRECEIVES 3
#define IPSYSTEMSTATSHCINRECEIVES 4
#define IPSYSTEMSTATSINOCTETS 5
#define IPSYSTEMSTATSHCINOCTETS 6
#define IPSYSTEMSTATSINHDRERRORS 7
#define IPSYSTEMSTATSINNOROUTES 8
#define IPSYSTEMSTATSINADDRERRORS 9
#define IPSYSTEMSTATSINUNKNOWNPROTOS 10
#define IPSYSTEMSTATSINTRUNCATEDPKTS 11
#define IPSYSTEMSTATSINFORWDATAGRAMS 12
#define IPSYSTEMSTATSHCINFORWDATAGRAMS 13
#define IPSYSTEMSTATSREASMREQDS 14
#define IPSYSTEMSTATSREASMOKS 15
#define IPSYSTEMSTATSREASMFAILS 16
#define IPSYSTEMSTATSINDISCARDS 17
#define IPSYSTEMSTATSINDELIVERS 18
#define IPSYSTEMSTATSHCINDELIVERS 19
#define IPSYSTEMSTATSOUTREQUESTS 20
#define IPSYSTEMSTATSHCOUTREQUESTS 21
#define IPSYSTEMSTATSOUTNOROUTES 22
#define IPSYSTEMSTATSOUTFORWDATAGRAMS 23
#define IPSYSTEMSTATSHCOUTFORWDATAGRAMS 24
#define IPSYSTEMSTATSOUTDISCARDS 25
#define IPSYSTEMSTATSOUTFRAGREQDS 26
#define IPSYSTEMSTATSOUTFRAGOKS 27
#define IPSYSTEMSTATSOUTFRAGFAILS 28
#define IPSYSTEMSTATSOUTFRAGCREATES 29
#define IPSYSTEMSTATSOUTTRANSMITS 30
#define IPSYSTEMSTATSHCOUTTRANSMITS 31
#define IPSYSTEMSTATSOUTOCTETS 32
#define IPSYSTEMSTATSHCOUTOCTETS 33
#define IPSYSTEMSTATSINMCASTPKTS 34
#define IPSYSTEMSTATSHCINMCASTPKTS 35
#define IPSYSTEMSTATSINMCASTOCTETS 36
#define IPSYSTEMSTATSHCINMCASTOCTETS 37
#define IPSYSTEMSTATSOUTMCASTPKTS 38
#define IPSYSTEMSTATSHCOUTMCASTPKTS 39
#define IPSYSTEMSTATSOUTMCASTOCTETS 40
#define IPSYSTEMSTATSHCOUTMCASTOCTETS 41
#define IPSYSTEMSTATSINBCASTPKTS 42
#define IPSYSTEMSTATSHCINBCASTPKTS 43
#define IPSYSTEMSTATSOUTBCASTPKTS 44
#define IPSYSTEMSTATSHCOUTBCASTPKTS 45
#define IPSYSTEMSTATSDISCONTINUITYTIME 46
#define IPSYSTEMSTATSREFRESHRATE 47

enum
{
	/* enums for column ipSystemStatsIPVersion */
	ipSystemStatsIPVersion_unknown_c = 0,
	ipSystemStatsIPVersion_ipv4_c = 1,
	ipSystemStatsIPVersion_ipv6_c = 2,
};

/* table ipSystemStatsTable row entry data structure */
typedef struct ipSystemStatsEntry_t
{
	/* Index values */
	int32_t i32IPVersion;
	
	/* Column values */
	uint32_t u32InReceives;
	uint64_t u64HCInReceives;
	uint32_t u32InOctets;
	uint64_t u64HCInOctets;
	uint32_t u32InHdrErrors;
	uint32_t u32InNoRoutes;
	uint32_t u32InAddrErrors;
	uint32_t u32InUnknownProtos;
	uint32_t u32InTruncatedPkts;
	uint32_t u32InForwDatagrams;
	uint64_t u64HCInForwDatagrams;
	uint32_t u32ReasmReqds;
	uint32_t u32ReasmOKs;
	uint32_t u32ReasmFails;
	uint32_t u32InDiscards;
	uint32_t u32InDelivers;
	uint64_t u64HCInDelivers;
	uint32_t u32OutRequests;
	uint64_t u64HCOutRequests;
	uint32_t u32OutNoRoutes;
	uint32_t u32OutForwDatagrams;
	uint64_t u64HCOutForwDatagrams;
	uint32_t u32OutDiscards;
	uint32_t u32OutFragReqds;
	uint32_t u32OutFragOKs;
	uint32_t u32OutFragFails;
	uint32_t u32OutFragCreates;
	uint32_t u32OutTransmits;
	uint64_t u64HCOutTransmits;
	uint32_t u32OutOctets;
	uint64_t u64HCOutOctets;
	uint32_t u32InMcastPkts;
	uint64_t u64HCInMcastPkts;
	uint32_t u32InMcastOctets;
	uint64_t u64HCInMcastOctets;
	uint32_t u32OutMcastPkts;
	uint64_t u64HCOutMcastPkts;
	uint32_t u32OutMcastOctets;
	uint64_t u64HCOutMcastOctets;
	uint32_t u32InBcastPkts;
	uint64_t u64HCInBcastPkts;
	uint32_t u32OutBcastPkts;
	uint64_t u64HCOutBcastPkts;
	uint32_t u32DiscontinuityTime;
	uint32_t u32RefreshRate;
	
	xBTree_Node_t oBTreeNode;
} ipSystemStatsEntry_t;

extern xBTree_t oIpSystemStatsTable_BTree;

/* ipSystemStatsTable table mapper */
void ipSystemStatsTable_init (void);
ipSystemStatsEntry_t * ipSystemStatsTable_createEntry (
	int32_t i32IPVersion);
ipSystemStatsEntry_t * ipSystemStatsTable_getByIndex (
	int32_t i32IPVersion);
ipSystemStatsEntry_t * ipSystemStatsTable_getNextIndex (
	int32_t i32IPVersion);
void ipSystemStatsTable_removeEntry (ipSystemStatsEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ipSystemStatsTable_getFirst;
Netsnmp_Next_Data_Point ipSystemStatsTable_getNext;
Netsnmp_Get_Data_Point ipSystemStatsTable_get;
Netsnmp_Node_Handler ipSystemStatsTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ipIfStatsTable definitions
 */
#define IPIFSTATSIPVERSION 1
#define IPIFSTATSIFINDEX 2
#define IPIFSTATSINRECEIVES 3
#define IPIFSTATSHCINRECEIVES 4
#define IPIFSTATSINOCTETS 5
#define IPIFSTATSHCINOCTETS 6
#define IPIFSTATSINHDRERRORS 7
#define IPIFSTATSINNOROUTES 8
#define IPIFSTATSINADDRERRORS 9
#define IPIFSTATSINUNKNOWNPROTOS 10
#define IPIFSTATSINTRUNCATEDPKTS 11
#define IPIFSTATSINFORWDATAGRAMS 12
#define IPIFSTATSHCINFORWDATAGRAMS 13
#define IPIFSTATSREASMREQDS 14
#define IPIFSTATSREASMOKS 15
#define IPIFSTATSREASMFAILS 16
#define IPIFSTATSINDISCARDS 17
#define IPIFSTATSINDELIVERS 18
#define IPIFSTATSHCINDELIVERS 19
#define IPIFSTATSOUTREQUESTS 20
#define IPIFSTATSHCOUTREQUESTS 21
#define IPIFSTATSOUTFORWDATAGRAMS 23
#define IPIFSTATSHCOUTFORWDATAGRAMS 24
#define IPIFSTATSOUTDISCARDS 25
#define IPIFSTATSOUTFRAGREQDS 26
#define IPIFSTATSOUTFRAGOKS 27
#define IPIFSTATSOUTFRAGFAILS 28
#define IPIFSTATSOUTFRAGCREATES 29
#define IPIFSTATSOUTTRANSMITS 30
#define IPIFSTATSHCOUTTRANSMITS 31
#define IPIFSTATSOUTOCTETS 32
#define IPIFSTATSHCOUTOCTETS 33
#define IPIFSTATSINMCASTPKTS 34
#define IPIFSTATSHCINMCASTPKTS 35
#define IPIFSTATSINMCASTOCTETS 36
#define IPIFSTATSHCINMCASTOCTETS 37
#define IPIFSTATSOUTMCASTPKTS 38
#define IPIFSTATSHCOUTMCASTPKTS 39
#define IPIFSTATSOUTMCASTOCTETS 40
#define IPIFSTATSHCOUTMCASTOCTETS 41
#define IPIFSTATSINBCASTPKTS 42
#define IPIFSTATSHCINBCASTPKTS 43
#define IPIFSTATSOUTBCASTPKTS 44
#define IPIFSTATSHCOUTBCASTPKTS 45
#define IPIFSTATSDISCONTINUITYTIME 46
#define IPIFSTATSREFRESHRATE 47

enum
{
	/* enums for column ipIfStatsIPVersion */
	ipIfStatsIPVersion_unknown_c = 0,
	ipIfStatsIPVersion_ipv4_c = 1,
	ipIfStatsIPVersion_ipv6_c = 2,
};

/* table ipIfStatsTable row entry data structure */
typedef struct ipIfStatsEntry_t
{
	/* Index values */
	int32_t i32IPVersion;
	uint32_t u32IfIndex;
	
	/* Column values */
	uint32_t u32InReceives;
	uint64_t u64HCInReceives;
	uint32_t u32InOctets;
	uint64_t u64HCInOctets;
	uint32_t u32InHdrErrors;
	uint32_t u32InNoRoutes;
	uint32_t u32InAddrErrors;
	uint32_t u32InUnknownProtos;
	uint32_t u32InTruncatedPkts;
	uint32_t u32InForwDatagrams;
	uint64_t u64HCInForwDatagrams;
	uint32_t u32ReasmReqds;
	uint32_t u32ReasmOKs;
	uint32_t u32ReasmFails;
	uint32_t u32InDiscards;
	uint32_t u32InDelivers;
	uint64_t u64HCInDelivers;
	uint32_t u32OutRequests;
	uint64_t u64HCOutRequests;
	uint32_t u32OutForwDatagrams;
	uint64_t u64HCOutForwDatagrams;
	uint32_t u32OutDiscards;
	uint32_t u32OutFragReqds;
	uint32_t u32OutFragOKs;
	uint32_t u32OutFragFails;
	uint32_t u32OutFragCreates;
	uint32_t u32OutTransmits;
	uint64_t u64HCOutTransmits;
	uint32_t u32OutOctets;
	uint64_t u64HCOutOctets;
	uint32_t u32InMcastPkts;
	uint64_t u64HCInMcastPkts;
	uint32_t u32InMcastOctets;
	uint64_t u64HCInMcastOctets;
	uint32_t u32OutMcastPkts;
	uint64_t u64HCOutMcastPkts;
	uint32_t u32OutMcastOctets;
	uint64_t u64HCOutMcastOctets;
	uint32_t u32InBcastPkts;
	uint64_t u64HCInBcastPkts;
	uint32_t u32OutBcastPkts;
	uint64_t u64HCOutBcastPkts;
	uint32_t u32DiscontinuityTime;
	uint32_t u32RefreshRate;
	
	xBTree_Node_t oBTreeNode;
} ipIfStatsEntry_t;

extern xBTree_t oIpIfStatsTable_BTree;

/* ipIfStatsTable table mapper */
void ipIfStatsTable_init (void);
ipIfStatsEntry_t * ipIfStatsTable_createEntry (
	int32_t i32IPVersion,
	uint32_t u32IfIndex);
ipIfStatsEntry_t * ipIfStatsTable_getByIndex (
	int32_t i32IPVersion,
	uint32_t u32IfIndex);
ipIfStatsEntry_t * ipIfStatsTable_getNextIndex (
	int32_t i32IPVersion,
	uint32_t u32IfIndex);
void ipIfStatsTable_removeEntry (ipIfStatsEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ipIfStatsTable_getFirst;
Netsnmp_Next_Data_Point ipIfStatsTable_getNext;
Netsnmp_Get_Data_Point ipIfStatsTable_get;
Netsnmp_Node_Handler ipIfStatsTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ipAddressPrefixTable definitions
 */
#define IPADDRESSPREFIXIFINDEX 1
#define IPADDRESSPREFIXTYPE 2
#define IPADDRESSPREFIXPREFIX 3
#define IPADDRESSPREFIXLENGTH 4
#define IPADDRESSPREFIXORIGIN 5
#define IPADDRESSPREFIXONLINKFLAG 6
#define IPADDRESSPREFIXAUTONOMOUSFLAG 7
#define IPADDRESSPREFIXADVPREFERREDLIFETIME 8
#define IPADDRESSPREFIXADVVALIDLIFETIME 9

enum
{
	/* enums for column ipAddressPrefixType */
	ipAddressPrefixType_unknown_c = 0,
	ipAddressPrefixType_ipv4_c = 1,
	ipAddressPrefixType_ipv6_c = 2,
	ipAddressPrefixType_ipv4z_c = 3,
	ipAddressPrefixType_ipv6z_c = 4,
	ipAddressPrefixType_dns_c = 16,

	/* enums for column ipAddressPrefixOrigin */
	ipAddressPrefixOrigin_other_c = 1,
	ipAddressPrefixOrigin_manual_c = 2,
	ipAddressPrefixOrigin_wellknown_c = 3,
	ipAddressPrefixOrigin_dhcp_c = 4,
	ipAddressPrefixOrigin_routeradv_c = 5,

	/* enums for column ipAddressPrefixOnLinkFlag */
	ipAddressPrefixOnLinkFlag_true_c = 1,
	ipAddressPrefixOnLinkFlag_false_c = 2,

	/* enums for column ipAddressPrefixAutonomousFlag */
	ipAddressPrefixAutonomousFlag_true_c = 1,
	ipAddressPrefixAutonomousFlag_false_c = 2,
};

/* table ipAddressPrefixTable row entry data structure */
typedef struct ipAddressPrefixEntry_t
{
	/* Index values */
	uint32_t u32IfIndex;
	int32_t i32Type;
	uint8_t au8Prefix[20];
	size_t u16Prefix_len;	/* # of uint8_t elements */
	uint32_t u32Length;
	
	/* Column values */
	int32_t i32Origin;
	int32_t i32OnLinkFlag;
	int32_t i32AutonomousFlag;
	uint32_t u32AdvPreferredLifetime;
	uint32_t u32AdvValidLifetime;
	
	uint32_t u32NumAddresses;
	
	xBTree_Node_t oBTreeNode;
} ipAddressPrefixEntry_t;

extern xBTree_t oIpAddressPrefixTable_BTree;

/* ipAddressPrefixTable table mapper */
void ipAddressPrefixTable_init (void);
ipAddressPrefixEntry_t * ipAddressPrefixTable_createEntry (
	uint32_t u32IfIndex,
	int32_t i32Type,
	uint8_t *pau8Prefix, size_t u16Prefix_len,
	uint32_t u32Length);
ipAddressPrefixEntry_t * ipAddressPrefixTable_getByIndex (
	uint32_t u32IfIndex,
	int32_t i32Type,
	uint8_t *pau8Prefix, size_t u16Prefix_len,
	uint32_t u32Length);
ipAddressPrefixEntry_t * ipAddressPrefixTable_getNextIndex (
	uint32_t u32IfIndex,
	int32_t i32Type,
	uint8_t *pau8Prefix, size_t u16Prefix_len,
	uint32_t u32Length);
void ipAddressPrefixTable_removeEntry (ipAddressPrefixEntry_t *poEntry);
ipAddressPrefixEntry_t * ipAddressPrefixTable_handler (
	uint32_t u32IfIndex,
	int32_t i32Type,
	uint8_t *pau8Addr, size_t u16Addr_len,
	uint32_t u32PrefixLength,
	bool bAttach);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ipAddressPrefixTable_getFirst;
Netsnmp_Next_Data_Point ipAddressPrefixTable_getNext;
Netsnmp_Get_Data_Point ipAddressPrefixTable_get;
Netsnmp_Node_Handler ipAddressPrefixTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ipAddressTable definitions
 */
#define IPADDRESSADDRTYPE 1
#define IPADDRESSADDR 2
#define IPADDRESSIFINDEX 3
#define IPADDRESSTYPE 4
#define IPADDRESSPREFIX 5
#define IPADDRESSORIGIN 6
#define IPADDRESSSTATUS 7
#define IPADDRESSCREATED 8
#define IPADDRESSLASTCHANGED 9
#define IPADDRESSROWSTATUS 10
#define IPADDRESSSTORAGETYPE 11

enum
{
	/* enums for column ipAddressAddrType */
	ipAddressAddrType_unknown_c = 0,
	ipAddressAddrType_ipv4_c = 1,
	ipAddressAddrType_ipv6_c = 2,
	ipAddressAddrType_ipv4z_c = 3,
	ipAddressAddrType_ipv6z_c = 4,
	ipAddressAddrType_dns_c = 16,

	/* enums for column ipAddressType */
	ipAddressType_unicast_c = 1,
	ipAddressType_anycast_c = 2,
	ipAddressType_broadcast_c = 3,

	/* enums for column ipAddressOrigin */
	ipAddressOrigin_other_c = 1,
	ipAddressOrigin_manual_c = 2,
	ipAddressOrigin_dhcp_c = 4,
	ipAddressOrigin_linklayer_c = 5,
	ipAddressOrigin_random_c = 6,

	/* enums for column ipAddressStatus */
	ipAddressStatus_preferred_c = 1,
	ipAddressStatus_deprecated_c = 2,
	ipAddressStatus_invalid_c = 3,
	ipAddressStatus_inaccessible_c = 4,
	ipAddressStatus_unknown_c = 5,
	ipAddressStatus_tentative_c = 6,
	ipAddressStatus_duplicate_c = 7,
	ipAddressStatus_optimistic_c = 8,

	/* enums for column ipAddressRowStatus */
	ipAddressRowStatus_active_c = 1,
	ipAddressRowStatus_notInService_c = 2,
	ipAddressRowStatus_notReady_c = 3,
	ipAddressRowStatus_createAndGo_c = 4,
	ipAddressRowStatus_createAndWait_c = 5,
	ipAddressRowStatus_destroy_c = 6,

	/* enums for column ipAddressStorageType */
	ipAddressStorageType_other_c = 1,
	ipAddressStorageType_volatile_c = 2,
	ipAddressStorageType_nonVolatile_c = 3,
	ipAddressStorageType_permanent_c = 4,
	ipAddressStorageType_readOnly_c = 5,
};

/* table ipAddressTable row entry data structure */
typedef struct ipAddressEntry_t
{
	/* Index values */
// 	int32_t i32AddrType;
// 	uint8_t au8Addr[20];
// 	size_t u16Addr_len;	/* # of uint8_t elements */
	
	/* Column values */
	uint32_t u32IfIndex;
	int32_t i32Type;
	xOid_t aoPrefix[128];
	size_t u16Prefix_len;	/* # of xOid_t elements */
	int32_t i32Origin;
	int32_t i32Status;
	uint32_t u32Created;
	uint32_t u32LastChanged;
	uint8_t u8RowStatus;
	uint8_t u8StorageType;
	
// 	xBTree_Node_t oBTreeNode;
} ipAddressEntry_t;

// extern xBTree_t oIpAddressTable_BTree;

/* ipAddressTable table mapper */
void ipAddressTable_init (void);
ipAddressEntry_t * ipAddressTable_createEntry (
	int32_t i32AddrType,
	uint8_t *pau8Addr, size_t u16Addr_len);
ipAddressEntry_t * ipAddressTable_getByIndex (
	int32_t i32AddrType,
	uint8_t *pau8Addr, size_t u16Addr_len);
ipAddressEntry_t * ipAddressTable_getNextIndex (
	int32_t i32AddrType,
	uint8_t *pau8Addr, size_t u16Addr_len);
void ipAddressTable_removeEntry (ipAddressEntry_t *poEntry);
ipAddressEntry_t * ipAddressTable_createExt (
	int32_t i32AddrType,
	uint8_t *pau8Addr, size_t u16Addr_len);
bool ipAddressTable_removeExt (ipAddressEntry_t *poEntry);
bool ipAddressIfIndex_handler (
	ipAddressEntry_t *poEntry);
bool ipAddressRowStatus_handler (
	ipAddressEntry_t *poEntry,
	int32_t i32RowStatus);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ipAddressTable_getFirst;
Netsnmp_Next_Data_Point ipAddressTable_getNext;
Netsnmp_Get_Data_Point ipAddressTable_get;
Netsnmp_Node_Handler ipAddressTable_mapper;
#endif	/* SNMP_SRC */


enum
{
	ipAddressFlags_ipCreated_c = 0,
	ipAddressFlags_neCreated_c = 1,
	ipAddressFlags_count_c,
};

typedef struct ipAddressData_t
{
	int32_t i32AddrType;
	uint8_t au8Addr[20];
	size_t u16Addr_len;	/* # of uint8_t elements */
	uint32_t u32IfIndex;
	uint32_t u32PrefixLength;
	
	ipAddressEntry_t oIp;
	neIpAddressEntry_t oNe;
	
	uint8_t au8Flags[1];
	uint32_t u32NumUnNumAddresses;
	
	xBTree_Node_t oBTreeNode;
	xBTree_Node_t oIf_BTreeNode;
} ipAddressData_t;

extern xBTree_t oIpAddressData_BTree;
// extern xBTree_t oIpAddressData_If_BTree;

ipAddressData_t * ipAddressData_createEntry (
	int32_t i32AddrType,
	uint8_t *pau8Addr, size_t u16Addr_len);
ipAddressData_t * ipAddressData_getByIndex (
	int32_t i32AddrType,
	uint8_t *pau8Addr, size_t u16Addr_len);
ipAddressData_t * ipAddressData_getNextIndex (
	int32_t i32AddrType,
	uint8_t *pau8Addr, size_t u16Addr_len);
ipAddressData_t * ipAddressData_If_getByIndex (
	uint32_t u32IfIndex,
	int32_t i32AddrType,
	uint8_t *pau8Addr, size_t u16Addr_len);
ipAddressData_t * ipAddressData_If_getNextIndex (
	uint32_t u32IfIndex,
	int32_t i32AddrType,
	uint8_t *pau8Addr, size_t u16Addr_len);
#define ipAddressData_getByIpEntry(poEntry) ((poEntry) == NULL ? NULL: xGetParentByMemberPtr ((poEntry), ipAddressData_t, oIp))
#define ipAddressData_getByNeEntry(poEntry) ((poEntry) == NULL ? NULL: xGetParentByMemberPtr ((poEntry), ipAddressData_t, oNe))
void ipAddressData_removeEntry (ipAddressData_t *poEntry);


/**
 *	table ipNetToPhysicalTable definitions
 */
#define IPNETTOPHYSICALIFINDEX 1
#define IPNETTOPHYSICALNETADDRESSTYPE 2
#define IPNETTOPHYSICALNETADDRESS 3
#define IPNETTOPHYSICALPHYSADDRESS 4
#define IPNETTOPHYSICALLASTUPDATED 5
#define IPNETTOPHYSICALTYPE 6
#define IPNETTOPHYSICALSTATE 7
#define IPNETTOPHYSICALROWSTATUS 8

enum
{
	/* enums for column ipNetToPhysicalNetAddressType */
	ipNetToPhysicalNetAddressType_unknown_c = 0,
	ipNetToPhysicalNetAddressType_ipv4_c = 1,
	ipNetToPhysicalNetAddressType_ipv6_c = 2,
	ipNetToPhysicalNetAddressType_ipv4z_c = 3,
	ipNetToPhysicalNetAddressType_ipv6z_c = 4,
	ipNetToPhysicalNetAddressType_dns_c = 16,

	/* enums for column ipNetToPhysicalType */
	ipNetToPhysicalType_other_c = 1,
	ipNetToPhysicalType_invalid_c = 2,
	ipNetToPhysicalType_dynamic_c = 3,
	ipNetToPhysicalType_static_c = 4,
	ipNetToPhysicalType_local_c = 5,

	/* enums for column ipNetToPhysicalState */
	ipNetToPhysicalState_reachable_c = 1,
	ipNetToPhysicalState_stale_c = 2,
	ipNetToPhysicalState_delay_c = 3,
	ipNetToPhysicalState_probe_c = 4,
	ipNetToPhysicalState_invalid_c = 5,
	ipNetToPhysicalState_unknown_c = 6,
	ipNetToPhysicalState_incomplete_c = 7,

	/* enums for column ipNetToPhysicalRowStatus */
	ipNetToPhysicalRowStatus_active_c = 1,
	ipNetToPhysicalRowStatus_notInService_c = 2,
	ipNetToPhysicalRowStatus_notReady_c = 3,
	ipNetToPhysicalRowStatus_createAndGo_c = 4,
	ipNetToPhysicalRowStatus_createAndWait_c = 5,
	ipNetToPhysicalRowStatus_destroy_c = 6,
};

/* table ipNetToPhysicalTable row entry data structure */
typedef struct ipNetToPhysicalEntry_t
{
	/* Index values */
	uint32_t u32IfIndex;
	int32_t i32NetAddressType;
	uint8_t au8NetAddress[20];
	size_t u16NetAddress_len;	/* # of uint8_t elements */
	
	/* Column values */
	uint8_t au8PhysAddress[IeeeEui64_size_c];
	size_t u16PhysAddress_len;	/* # of uint8_t elements */
	uint32_t u32LastUpdated;
	int32_t i32Type;
	int32_t i32State;
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} ipNetToPhysicalEntry_t;

extern xBTree_t oIpNetToPhysicalTable_BTree;

/* ipNetToPhysicalTable table mapper */
void ipNetToPhysicalTable_init (void);
ipNetToPhysicalEntry_t * ipNetToPhysicalTable_createEntry (
	uint32_t u32IfIndex,
	int32_t i32NetAddressType,
	uint8_t *pau8NetAddress, size_t u16NetAddress_len);
ipNetToPhysicalEntry_t * ipNetToPhysicalTable_getByIndex (
	uint32_t u32IfIndex,
	int32_t i32NetAddressType,
	uint8_t *pau8NetAddress, size_t u16NetAddress_len);
ipNetToPhysicalEntry_t * ipNetToPhysicalTable_getNextIndex (
	uint32_t u32IfIndex,
	int32_t i32NetAddressType,
	uint8_t *pau8NetAddress, size_t u16NetAddress_len);
void ipNetToPhysicalTable_removeEntry (ipNetToPhysicalEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ipNetToPhysicalTable_getFirst;
Netsnmp_Next_Data_Point ipNetToPhysicalTable_getNext;
Netsnmp_Get_Data_Point ipNetToPhysicalTable_get;
Netsnmp_Node_Handler ipNetToPhysicalTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ipv6ScopeZoneIndexTable definitions
 */
#define IPV6SCOPEZONEINDEXIFINDEX 1
#define IPV6SCOPEZONEINDEXLINKLOCAL 2
#define IPV6SCOPEZONEINDEX3 3
#define IPV6SCOPEZONEINDEXADMINLOCAL 4
#define IPV6SCOPEZONEINDEXSITELOCAL 5
#define IPV6SCOPEZONEINDEX6 6
#define IPV6SCOPEZONEINDEX7 7
#define IPV6SCOPEZONEINDEXORGANIZATIONLOCAL 8
#define IPV6SCOPEZONEINDEX9 9
#define IPV6SCOPEZONEINDEXA 10
#define IPV6SCOPEZONEINDEXB 11
#define IPV6SCOPEZONEINDEXC 12
#define IPV6SCOPEZONEINDEXD 13

/* table ipv6ScopeZoneIndexTable row entry data structure */
typedef struct ipv6ScopeZoneIndexEntry_t
{
	/* Index values */
	uint32_t u32IfIndex;
	
	/* Column values */
	uint32_t u32LinkLocal;
	uint32_t u32Index3;
	uint32_t u32AdminLocal;
	uint32_t u32SiteLocal;
	uint32_t u32Index6;
	uint32_t u32Index7;
	uint32_t u32OrganizationLocal;
	uint32_t u32Index9;
	uint32_t u32IndexA;
	uint32_t u32IndexB;
	uint32_t u32IndexC;
	uint32_t u32IndexD;
	
	xBTree_Node_t oBTreeNode;
} ipv6ScopeZoneIndexEntry_t;

extern xBTree_t oIpv6ScopeZoneIndexTable_BTree;

/* ipv6ScopeZoneIndexTable table mapper */
void ipv6ScopeZoneIndexTable_init (void);
ipv6ScopeZoneIndexEntry_t * ipv6ScopeZoneIndexTable_createEntry (
	uint32_t u32IfIndex);
ipv6ScopeZoneIndexEntry_t * ipv6ScopeZoneIndexTable_getByIndex (
	uint32_t u32IfIndex);
ipv6ScopeZoneIndexEntry_t * ipv6ScopeZoneIndexTable_getNextIndex (
	uint32_t u32IfIndex);
void ipv6ScopeZoneIndexTable_removeEntry (ipv6ScopeZoneIndexEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ipv6ScopeZoneIndexTable_getFirst;
Netsnmp_Next_Data_Point ipv6ScopeZoneIndexTable_getNext;
Netsnmp_Get_Data_Point ipv6ScopeZoneIndexTable_get;
Netsnmp_Node_Handler ipv6ScopeZoneIndexTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ipDefaultRouterTable definitions
 */
#define IPDEFAULTROUTERADDRESSTYPE 1
#define IPDEFAULTROUTERADDRESS 2
#define IPDEFAULTROUTERIFINDEX 3
#define IPDEFAULTROUTERLIFETIME 4
#define IPDEFAULTROUTERPREFERENCE 5

enum
{
	/* enums for column ipDefaultRouterAddressType */
	ipDefaultRouterAddressType_unknown_c = 0,
	ipDefaultRouterAddressType_ipv4_c = 1,
	ipDefaultRouterAddressType_ipv6_c = 2,
	ipDefaultRouterAddressType_ipv4z_c = 3,
	ipDefaultRouterAddressType_ipv6z_c = 4,
	ipDefaultRouterAddressType_dns_c = 16,

	/* enums for column ipDefaultRouterPreference */
	ipDefaultRouterPreference_reserved_c = -2,
	ipDefaultRouterPreference_low_c = -1,
	ipDefaultRouterPreference_medium_c = 0,
	ipDefaultRouterPreference_high_c = 1,
};

/* table ipDefaultRouterTable row entry data structure */
typedef struct ipDefaultRouterEntry_t
{
	/* Index values */
	int32_t i32AddressType;
	uint8_t au8Address[20];
	size_t u16Address_len;	/* # of uint8_t elements */
	uint32_t u32IfIndex;
	
	/* Column values */
	uint32_t u32Lifetime;
	int32_t i32Preference;
	
	xBTree_Node_t oBTreeNode;
} ipDefaultRouterEntry_t;

extern xBTree_t oIpDefaultRouterTable_BTree;

/* ipDefaultRouterTable table mapper */
void ipDefaultRouterTable_init (void);
ipDefaultRouterEntry_t * ipDefaultRouterTable_createEntry (
	int32_t i32AddressType,
	uint8_t *pau8Address, size_t u16Address_len,
	uint32_t u32IfIndex);
ipDefaultRouterEntry_t * ipDefaultRouterTable_getByIndex (
	int32_t i32AddressType,
	uint8_t *pau8Address, size_t u16Address_len,
	uint32_t u32IfIndex);
ipDefaultRouterEntry_t * ipDefaultRouterTable_getNextIndex (
	int32_t i32AddressType,
	uint8_t *pau8Address, size_t u16Address_len,
	uint32_t u32IfIndex);
void ipDefaultRouterTable_removeEntry (ipDefaultRouterEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ipDefaultRouterTable_getFirst;
Netsnmp_Next_Data_Point ipDefaultRouterTable_getNext;
Netsnmp_Get_Data_Point ipDefaultRouterTable_get;
Netsnmp_Node_Handler ipDefaultRouterTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ipv6RouterAdvertTable definitions
 */
#define IPV6ROUTERADVERTIFINDEX 1
#define IPV6ROUTERADVERTSENDADVERTS 2
#define IPV6ROUTERADVERTMAXINTERVAL 3
#define IPV6ROUTERADVERTMININTERVAL 4
#define IPV6ROUTERADVERTMANAGEDFLAG 5
#define IPV6ROUTERADVERTOTHERCONFIGFLAG 6
#define IPV6ROUTERADVERTLINKMTU 7
#define IPV6ROUTERADVERTREACHABLETIME 8
#define IPV6ROUTERADVERTRETRANSMITTIME 9
#define IPV6ROUTERADVERTCURHOPLIMIT 10
#define IPV6ROUTERADVERTDEFAULTLIFETIME 11
#define IPV6ROUTERADVERTROWSTATUS 12

enum
{
	/* enums for column ipv6RouterAdvertSendAdverts */
	ipv6RouterAdvertSendAdverts_true_c = 1,
	ipv6RouterAdvertSendAdverts_false_c = 2,

	/* enums for column ipv6RouterAdvertManagedFlag */
	ipv6RouterAdvertManagedFlag_true_c = 1,
	ipv6RouterAdvertManagedFlag_false_c = 2,

	/* enums for column ipv6RouterAdvertOtherConfigFlag */
	ipv6RouterAdvertOtherConfigFlag_true_c = 1,
	ipv6RouterAdvertOtherConfigFlag_false_c = 2,

	/* enums for column ipv6RouterAdvertRowStatus */
	ipv6RouterAdvertRowStatus_active_c = 1,
	ipv6RouterAdvertRowStatus_notInService_c = 2,
	ipv6RouterAdvertRowStatus_notReady_c = 3,
	ipv6RouterAdvertRowStatus_createAndGo_c = 4,
	ipv6RouterAdvertRowStatus_createAndWait_c = 5,
	ipv6RouterAdvertRowStatus_destroy_c = 6,
};

/* table ipv6RouterAdvertTable row entry data structure */
typedef struct ipv6RouterAdvertEntry_t
{
	/* Index values */
	uint32_t u32IfIndex;
	
	/* Column values */
	int32_t i32SendAdverts;
	uint32_t u32MaxInterval;
	uint32_t u32MinInterval;
	int32_t i32ManagedFlag;
	int32_t i32OtherConfigFlag;
	uint32_t u32LinkMTU;
	uint32_t u32ReachableTime;
	uint32_t u32RetransmitTime;
	uint32_t u32CurHopLimit;
	uint32_t u32DefaultLifetime;
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} ipv6RouterAdvertEntry_t;

extern xBTree_t oIpv6RouterAdvertTable_BTree;

/* ipv6RouterAdvertTable table mapper */
void ipv6RouterAdvertTable_init (void);
ipv6RouterAdvertEntry_t * ipv6RouterAdvertTable_createEntry (
	uint32_t u32IfIndex);
ipv6RouterAdvertEntry_t * ipv6RouterAdvertTable_getByIndex (
	uint32_t u32IfIndex);
ipv6RouterAdvertEntry_t * ipv6RouterAdvertTable_getNextIndex (
	uint32_t u32IfIndex);
void ipv6RouterAdvertTable_removeEntry (ipv6RouterAdvertEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ipv6RouterAdvertTable_getFirst;
Netsnmp_Next_Data_Point ipv6RouterAdvertTable_getNext;
Netsnmp_Get_Data_Point ipv6RouterAdvertTable_get;
Netsnmp_Node_Handler ipv6RouterAdvertTable_mapper;
#endif	/* SNMP_SRC */



#	ifdef __cplusplus
}
#	endif

#endif /* __IPMIB_H__ */
