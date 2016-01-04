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

#ifndef __ISISMIB_H__
#	define __ISISMIB_H__

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
void isisMIB_init (void);


/**
 *	scalar mapper(s)
 */
/** definitions for scalar(s) of isisSysObject **/
#define ISISSYSVERSION 1
#define ISISSYSLEVELTYPE 2
#define ISISSYSID 3
#define ISISSYSMAXPATHSPLITS 4
#define ISISSYSMAXLSPGENINT 5
#define ISISSYSPOLLESHELLORATE 6
#define ISISSYSWAITTIME 7
#define ISISSYSADMINSTATE 8
#define ISISSYSL2TOL1LEAKING 9
#define ISISSYSMAXAGE 10
#define ISISSYSRECEIVELSPBUFFERSIZE 11
#define ISISSYSPROTSUPPORTED 12
#define ISISSYSNOTIFICATIONENABLE 13

enum
{
	/* enums for scalar isisSysVersion */
	isisSysVersion_unknown_c = 0,
	isisSysVersion_one_c = 1,

	/* enums for scalar isisSysLevelType */
	isisSysLevelType_level1_c = 1,
	isisSysLevelType_level2_c = 2,
	isisSysLevelType_level1and2_c = 3,

	/* enums for scalar isisSysAdminState */
	isisSysAdminState_on_c = 1,
	isisSysAdminState_off_c = 2,

	/* enums for scalar isisSysL2toL1Leaking */
	isisSysL2toL1Leaking_true_c = 1,
	isisSysL2toL1Leaking_false_c = 2,

	/* enums for scalar isisSysProtSupported */
	isisSysProtSupported_iso8473_c = 0,
	isisSysProtSupported_ipv4_c = 1,
	isisSysProtSupported_ipv6_c = 2,

	/* enums for scalar isisSysNotificationEnable */
	isisSysNotificationEnable_true_c = 1,
	isisSysNotificationEnable_false_c = 2,
};

typedef struct isisSysObject_t
{
	int32_t i32Version;
	int32_t i32LevelType;
	uint8_t au8ID[6];
	uint32_t u32MaxPathSplits;
	uint32_t u32MaxLSPGenInt;
	uint32_t u32PollESHelloRate;
	uint32_t u32WaitTime;
	int32_t i32AdminState;
	uint8_t u8L2toL1Leaking;
	uint32_t u32MaxAge;
	uint32_t u32ReceiveLSPBufferSize;
	uint8_t au8ProtSupported[1];
	uint8_t u8NotificationEnable;
} isisSysObject_t;

extern isisSysObject_t oIsisSysObject;

#ifdef SNMP_SRC
Netsnmp_Node_Handler isisSysObject_mapper;
#endif	/* SNMP_SRC */

/** definitions for scalar(s) of isisCirc **/
#define ISISNEXTCIRCINDEX 1

typedef struct isisCirc_t
{
	uint32_t u32NextCircIndex;
} isisCirc_t;

extern isisCirc_t oIsisCirc;

#ifdef SNMP_SRC
Netsnmp_Node_Handler isisCirc_mapper;
#endif	/* SNMP_SRC */



/**
 *	table mapper(s)
 */
/**
 *	table isisManAreaAddrTable definitions
 */
#define ISISMANAREAADDR 1
#define ISISMANAREAADDREXISTSTATE 2

enum
{
	/* enums for column isisManAreaAddrExistState */
	isisManAreaAddrExistState_active_c = 1,
	isisManAreaAddrExistState_notInService_c = 2,
	isisManAreaAddrExistState_notReady_c = 3,
	isisManAreaAddrExistState_createAndGo_c = 4,
	isisManAreaAddrExistState_createAndWait_c = 5,
	isisManAreaAddrExistState_destroy_c = 6,
};

/* table isisManAreaAddrTable row entry data structure */
typedef struct isisManAreaAddrEntry_t
{
	/* Index values */
	uint8_t au8Addr[20];
	size_t u16Addr_len;	/* # of uint8_t elements */
	
	/* Column values */
	uint8_t u8ExistState;
	
	xBTree_Node_t oBTreeNode;
} isisManAreaAddrEntry_t;

extern xBTree_t oIsisManAreaAddrTable_BTree;

/* isisManAreaAddrTable table mapper */
void isisManAreaAddrTable_init (void);
isisManAreaAddrEntry_t * isisManAreaAddrTable_createEntry (
	uint8_t *pau8Addr, size_t u16Addr_len);
isisManAreaAddrEntry_t * isisManAreaAddrTable_getByIndex (
	uint8_t *pau8Addr, size_t u16Addr_len);
isisManAreaAddrEntry_t * isisManAreaAddrTable_getNextIndex (
	uint8_t *pau8Addr, size_t u16Addr_len);
void isisManAreaAddrTable_removeEntry (isisManAreaAddrEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point isisManAreaAddrTable_getFirst;
Netsnmp_Next_Data_Point isisManAreaAddrTable_getNext;
Netsnmp_Get_Data_Point isisManAreaAddrTable_get;
Netsnmp_Node_Handler isisManAreaAddrTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table isisAreaAddrTable definitions
 */
#define ISISAREAADDR 1

/* table isisAreaAddrTable row entry data structure */
typedef struct isisAreaAddrEntry_t
{
	/* Index values */
	uint8_t au8Addr[20];
	size_t u16Addr_len;	/* # of uint8_t elements */
	
	/* Column values */
	
	xBTree_Node_t oBTreeNode;
} isisAreaAddrEntry_t;

extern xBTree_t oIsisAreaAddrTable_BTree;

/* isisAreaAddrTable table mapper */
void isisAreaAddrTable_init (void);
isisAreaAddrEntry_t * isisAreaAddrTable_createEntry (
	uint8_t *pau8Addr, size_t u16Addr_len);
isisAreaAddrEntry_t * isisAreaAddrTable_getByIndex (
	uint8_t *pau8Addr, size_t u16Addr_len);
isisAreaAddrEntry_t * isisAreaAddrTable_getNextIndex (
	uint8_t *pau8Addr, size_t u16Addr_len);
void isisAreaAddrTable_removeEntry (isisAreaAddrEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point isisAreaAddrTable_getFirst;
Netsnmp_Next_Data_Point isisAreaAddrTable_getNext;
Netsnmp_Get_Data_Point isisAreaAddrTable_get;
Netsnmp_Node_Handler isisAreaAddrTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table isisSummAddrTable definitions
 */
#define ISISSUMMADDRESSTYPE 1
#define ISISSUMMADDRESS 2
#define ISISSUMMADDRPREFIXLEN 3
#define ISISSUMMADDREXISTSTATE 4
#define ISISSUMMADDRMETRIC 5
#define ISISSUMMADDRFULLMETRIC 6

enum
{
	/* enums for column isisSummAddressType */
	isisSummAddressType_unknown_c = 0,
	isisSummAddressType_ipv4_c = 1,
	isisSummAddressType_ipv6_c = 2,
	isisSummAddressType_ipv4z_c = 3,
	isisSummAddressType_ipv6z_c = 4,
	isisSummAddressType_dns_c = 16,

	/* enums for column isisSummAddrExistState */
	isisSummAddrExistState_active_c = 1,
	isisSummAddrExistState_notInService_c = 2,
	isisSummAddrExistState_notReady_c = 3,
	isisSummAddrExistState_createAndGo_c = 4,
	isisSummAddrExistState_createAndWait_c = 5,
	isisSummAddrExistState_destroy_c = 6,
};

/* table isisSummAddrTable row entry data structure */
typedef struct isisSummAddrEntry_t
{
	/* Index values */
	int32_t i32AddressType;
	uint8_t au8Address[255];
	size_t u16Address_len;	/* # of uint8_t elements */
	uint32_t u32PrefixLen;
	
	/* Column values */
	uint8_t u8ExistState;
	uint32_t u32Metric;
	uint32_t u32FullMetric;
	
	xBTree_Node_t oBTreeNode;
} isisSummAddrEntry_t;

extern xBTree_t oIsisSummAddrTable_BTree;

/* isisSummAddrTable table mapper */
void isisSummAddrTable_init (void);
isisSummAddrEntry_t * isisSummAddrTable_createEntry (
	int32_t i32AddressType,
	uint8_t *pau8Address, size_t u16Address_len,
	uint32_t u32PrefixLen);
isisSummAddrEntry_t * isisSummAddrTable_getByIndex (
	int32_t i32AddressType,
	uint8_t *pau8Address, size_t u16Address_len,
	uint32_t u32PrefixLen);
isisSummAddrEntry_t * isisSummAddrTable_getNextIndex (
	int32_t i32AddressType,
	uint8_t *pau8Address, size_t u16Address_len,
	uint32_t u32PrefixLen);
void isisSummAddrTable_removeEntry (isisSummAddrEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point isisSummAddrTable_getFirst;
Netsnmp_Next_Data_Point isisSummAddrTable_getNext;
Netsnmp_Get_Data_Point isisSummAddrTable_get;
Netsnmp_Node_Handler isisSummAddrTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table isisRedistributeAddrTable definitions
 */
#define ISISREDISTRIBUTEADDRTYPE 1
#define ISISREDISTRIBUTEADDRADDRESS 2
#define ISISREDISTRIBUTEADDRPREFIXLEN 3
#define ISISREDISTRIBUTEADDREXISTSTATE 4

enum
{
	/* enums for column isisRedistributeAddrType */
	isisRedistributeAddrType_unknown_c = 0,
	isisRedistributeAddrType_ipv4_c = 1,
	isisRedistributeAddrType_ipv6_c = 2,
	isisRedistributeAddrType_ipv4z_c = 3,
	isisRedistributeAddrType_ipv6z_c = 4,
	isisRedistributeAddrType_dns_c = 16,

	/* enums for column isisRedistributeAddrExistState */
	isisRedistributeAddrExistState_active_c = 1,
	isisRedistributeAddrExistState_notInService_c = 2,
	isisRedistributeAddrExistState_notReady_c = 3,
	isisRedistributeAddrExistState_createAndGo_c = 4,
	isisRedistributeAddrExistState_createAndWait_c = 5,
	isisRedistributeAddrExistState_destroy_c = 6,
};

/* table isisRedistributeAddrTable row entry data structure */
typedef struct isisRedistributeAddrEntry_t
{
	/* Index values */
	int32_t i32Type;
	uint8_t au8Address[255];
	size_t u16Address_len;	/* # of uint8_t elements */
	uint32_t u32PrefixLen;
	
	/* Column values */
	uint8_t u8ExistState;
	
	xBTree_Node_t oBTreeNode;
} isisRedistributeAddrEntry_t;

extern xBTree_t oIsisRedistributeAddrTable_BTree;

/* isisRedistributeAddrTable table mapper */
void isisRedistributeAddrTable_init (void);
isisRedistributeAddrEntry_t * isisRedistributeAddrTable_createEntry (
	int32_t i32Type,
	uint8_t *pau8Address, size_t u16Address_len,
	uint32_t u32PrefixLen);
isisRedistributeAddrEntry_t * isisRedistributeAddrTable_getByIndex (
	int32_t i32Type,
	uint8_t *pau8Address, size_t u16Address_len,
	uint32_t u32PrefixLen);
isisRedistributeAddrEntry_t * isisRedistributeAddrTable_getNextIndex (
	int32_t i32Type,
	uint8_t *pau8Address, size_t u16Address_len,
	uint32_t u32PrefixLen);
void isisRedistributeAddrTable_removeEntry (isisRedistributeAddrEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point isisRedistributeAddrTable_getFirst;
Netsnmp_Next_Data_Point isisRedistributeAddrTable_getNext;
Netsnmp_Get_Data_Point isisRedistributeAddrTable_get;
Netsnmp_Node_Handler isisRedistributeAddrTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table isisRouterTable definitions
 */
#define ISISROUTERSYSID 1
#define ISISROUTERLEVEL 2
#define ISISROUTERHOSTNAME 3
#define ISISROUTERID 4

enum
{
	/* enums for column isisRouterLevel */
	isisRouterLevel_area_c = 1,
	isisRouterLevel_domain_c = 2,
};

/* table isisRouterTable row entry data structure */
typedef struct isisRouterEntry_t
{
	/* Index values */
	uint8_t au8SysID[6];
	int32_t i32Level;
	
	/* Column values */
	uint8_t au8HostName[255];
	size_t u16HostName_len;	/* # of uint8_t elements */
	uint32_t u32ID;
	
	xBTree_Node_t oBTreeNode;
} isisRouterEntry_t;

extern xBTree_t oIsisRouterTable_BTree;

/* isisRouterTable table mapper */
void isisRouterTable_init (void);
isisRouterEntry_t * isisRouterTable_createEntry (
	uint8_t *pau8SysID, size_t u16SysID_len,
	int32_t i32Level);
isisRouterEntry_t * isisRouterTable_getByIndex (
	uint8_t *pau8SysID, size_t u16SysID_len,
	int32_t i32Level);
isisRouterEntry_t * isisRouterTable_getNextIndex (
	uint8_t *pau8SysID, size_t u16SysID_len,
	int32_t i32Level);
void isisRouterTable_removeEntry (isisRouterEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point isisRouterTable_getFirst;
Netsnmp_Next_Data_Point isisRouterTable_getNext;
Netsnmp_Get_Data_Point isisRouterTable_get;
Netsnmp_Node_Handler isisRouterTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table isisSysLevelTable definitions
 */
#define ISISSYSLEVELINDEX 1
#define ISISSYSLEVELORIGLSPBUFFSIZE 2
#define ISISSYSLEVELMINLSPGENINT 3
#define ISISSYSLEVELSTATE 4
#define ISISSYSLEVELSETOVERLOAD 5
#define ISISSYSLEVELSETOVERLOADUNTIL 6
#define ISISSYSLEVELMETRICSTYLE 7
#define ISISSYSLEVELSPFCONSIDERS 8
#define ISISSYSLEVELTEENABLED 9

enum
{
	/* enums for column isisSysLevelIndex */
	isisSysLevelIndex_area_c = 1,
	isisSysLevelIndex_domain_c = 2,

	/* enums for column isisSysLevelState */
	isisSysLevelState_off_c = 1,
	isisSysLevelState_on_c = 2,
	isisSysLevelState_waiting_c = 3,
	isisSysLevelState_overloaded_c = 4,

	/* enums for column isisSysLevelSetOverload */
	isisSysLevelSetOverload_true_c = 1,
	isisSysLevelSetOverload_false_c = 2,

	/* enums for column isisSysLevelMetricStyle */
	isisSysLevelMetricStyle_narrow_c = 1,
	isisSysLevelMetricStyle_wide_c = 2,
	isisSysLevelMetricStyle_both_c = 3,

	/* enums for column isisSysLevelSPFConsiders */
	isisSysLevelSPFConsiders_narrow_c = 1,
	isisSysLevelSPFConsiders_wide_c = 2,
	isisSysLevelSPFConsiders_both_c = 3,

	/* enums for column isisSysLevelTEEnabled */
	isisSysLevelTEEnabled_true_c = 1,
	isisSysLevelTEEnabled_false_c = 2,
};

/* table isisSysLevelTable row entry data structure */
typedef struct isisSysLevelEntry_t
{
	/* Index values */
	int32_t i32Index;
	
	/* Column values */
	uint32_t u32OrigLSPBuffSize;
	uint32_t u32MinLSPGenInt;
	int32_t i32State;
	uint8_t u8SetOverload;
	uint32_t u32SetOverloadUntil;
	int32_t i32MetricStyle;
	int32_t i32SPFConsiders;
	uint8_t u8TEEnabled;
	
	xBTree_Node_t oBTreeNode;
} isisSysLevelEntry_t;

extern xBTree_t oIsisSysLevelTable_BTree;

/* isisSysLevelTable table mapper */
void isisSysLevelTable_init (void);
isisSysLevelEntry_t * isisSysLevelTable_createEntry (
	int32_t i32Index);
isisSysLevelEntry_t * isisSysLevelTable_getByIndex (
	int32_t i32Index);
isisSysLevelEntry_t * isisSysLevelTable_getNextIndex (
	int32_t i32Index);
void isisSysLevelTable_removeEntry (isisSysLevelEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point isisSysLevelTable_getFirst;
Netsnmp_Next_Data_Point isisSysLevelTable_getNext;
Netsnmp_Get_Data_Point isisSysLevelTable_get;
Netsnmp_Node_Handler isisSysLevelTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table isisCircTable definitions
 */
#define ISISCIRCINDEX 1
#define ISISCIRCIFINDEX 2
#define ISISCIRCADMINSTATE 3
#define ISISCIRCEXISTSTATE 4
#define ISISCIRCTYPE 5
#define ISISCIRCEXTDOMAIN 6
#define ISISCIRCLEVELTYPE 7
#define ISISCIRCPASSIVECIRCUIT 8
#define ISISCIRCMESHGROUPENABLED 9
#define ISISCIRCMESHGROUP 10
#define ISISCIRCSMALLHELLOS 11
#define ISISCIRCLASTUPTIME 12
#define ISISCIRC3WAYENABLED 13
#define ISISCIRCEXTENDEDCIRCID 14

enum
{
	/* enums for column isisCircAdminState */
	isisCircAdminState_on_c = 1,
	isisCircAdminState_off_c = 2,

	/* enums for column isisCircExistState */
	isisCircExistState_active_c = 1,
	isisCircExistState_notInService_c = 2,
	isisCircExistState_notReady_c = 3,
	isisCircExistState_createAndGo_c = 4,
	isisCircExistState_createAndWait_c = 5,
	isisCircExistState_destroy_c = 6,

	/* enums for column isisCircType */
	isisCircType_broadcast_c = 1,
	isisCircType_ptToPt_c = 2,
	isisCircType_staticIn_c = 3,
	isisCircType_staticOut_c = 4,
	isisCircType_dA_c = 5,

	/* enums for column isisCircExtDomain */
	isisCircExtDomain_true_c = 1,
	isisCircExtDomain_false_c = 2,

	/* enums for column isisCircLevelType */
	isisCircLevelType_level1_c = 1,
	isisCircLevelType_level2_c = 2,
	isisCircLevelType_level1and2_c = 3,

	/* enums for column isisCircPassiveCircuit */
	isisCircPassiveCircuit_true_c = 1,
	isisCircPassiveCircuit_false_c = 2,

	/* enums for column isisCircMeshGroupEnabled */
	isisCircMeshGroupEnabled_inactive_c = 1,
	isisCircMeshGroupEnabled_blocked_c = 2,
	isisCircMeshGroupEnabled_set_c = 3,

	/* enums for column isisCircSmallHellos */
	isisCircSmallHellos_true_c = 1,
	isisCircSmallHellos_false_c = 2,

	/* enums for column isisCirc3WayEnabled */
	isisCirc3WayEnabled_true_c = 1,
	isisCirc3WayEnabled_false_c = 2,
};

/* table isisCircTable row entry data structure */
typedef struct isisCircEntry_t
{
	/* Index values */
	uint32_t u32Index;
	
	/* Column values */
	uint32_t u32IfIndex;
	int32_t i32AdminState;
	uint8_t u8ExistState;
	int32_t i32Type;
	uint8_t u8ExtDomain;
	int32_t i32LevelType;
	uint8_t u8PassiveCircuit;
	int32_t i32MeshGroupEnabled;
	uint32_t u32MeshGroup;
	uint8_t u8SmallHellos;
	uint32_t u32LastUpTime;
	uint8_t u83WayEnabled;
	uint32_t u32ExtendedCircID;
	
	xBTree_Node_t oBTreeNode;
} isisCircEntry_t;

extern xBTree_t oIsisCircTable_BTree;

/* isisCircTable table mapper */
void isisCircTable_init (void);
isisCircEntry_t * isisCircTable_createEntry (
	uint32_t u32Index);
isisCircEntry_t * isisCircTable_getByIndex (
	uint32_t u32Index);
isisCircEntry_t * isisCircTable_getNextIndex (
	uint32_t u32Index);
void isisCircTable_removeEntry (isisCircEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point isisCircTable_getFirst;
Netsnmp_Next_Data_Point isisCircTable_getNext;
Netsnmp_Get_Data_Point isisCircTable_get;
Netsnmp_Node_Handler isisCircTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table isisCircLevelTable definitions
 */
#define ISISCIRCLEVELINDEX 1
#define ISISCIRCLEVELMETRIC 2
#define ISISCIRCLEVELWIDEMETRIC 3
#define ISISCIRCLEVELISPRIORITY 4
#define ISISCIRCLEVELIDOCTET 5
#define ISISCIRCLEVELID 6
#define ISISCIRCLEVELDESIS 7
#define ISISCIRCLEVELHELLOMULTIPLIER 8
#define ISISCIRCLEVELHELLOTIMER 9
#define ISISCIRCLEVELDRHELLOTIMER 10
#define ISISCIRCLEVELLSPTHROTTLE 11
#define ISISCIRCLEVELMINLSPRETRANSINT 12
#define ISISCIRCLEVELCSNPINTERVAL 13
#define ISISCIRCLEVELPARTSNPINTERVAL 14

enum
{
	/* enums for column isisCircLevelIndex */
	isisCircLevelIndex_area_c = 1,
	isisCircLevelIndex_domain_c = 2,
};

/* table isisCircLevelTable row entry data structure */
typedef struct isisCircLevelEntry_t
{
	/* Index values */
	uint32_t u32Index;
	int32_t i32Index;
	
	/* Column values */
	uint32_t u32Metric;
	uint32_t u32WideMetric;
	uint32_t u32ISPriority;
	uint32_t u32IDOctet;
	uint8_t au8ID[7];
	size_t u16ID_len;	/* # of uint8_t elements */
	uint8_t au8DesIS[7];
	size_t u16DesIS_len;	/* # of uint8_t elements */
	uint32_t u32HelloMultiplier;
	uint32_t u32HelloTimer;
	uint32_t u32DRHelloTimer;
	uint32_t u32LSPThrottle;
	uint32_t u32MinLSPRetransInt;
	uint32_t u32CSNPInterval;
	uint32_t u32PartSNPInterval;
	
	xBTree_Node_t oBTreeNode;
} isisCircLevelEntry_t;

extern xBTree_t oIsisCircLevelTable_BTree;

/* isisCircLevelTable table mapper */
void isisCircLevelTable_init (void);
isisCircLevelEntry_t * isisCircLevelTable_createEntry (
	uint32_t u32Index,
	int32_t i32Index);
isisCircLevelEntry_t * isisCircLevelTable_getByIndex (
	uint32_t u32Index,
	int32_t i32Index);
isisCircLevelEntry_t * isisCircLevelTable_getNextIndex (
	uint32_t u32Index,
	int32_t i32Index);
void isisCircLevelTable_removeEntry (isisCircLevelEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point isisCircLevelTable_getFirst;
Netsnmp_Next_Data_Point isisCircLevelTable_getNext;
Netsnmp_Get_Data_Point isisCircLevelTable_get;
Netsnmp_Node_Handler isisCircLevelTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table isisSystemCounterTable definitions
 */
#define ISISSYSSTATLEVEL 1
#define ISISSYSSTATCORRLSPS 2
#define ISISSYSSTATAUTHTYPEFAILS 3
#define ISISSYSSTATAUTHFAILS 4
#define ISISSYSSTATLSPDBASEOLOADS 5
#define ISISSYSSTATMANADDRDROPFROMAREAS 6
#define ISISSYSSTATATTMPTTOEXMAXSEQNUMS 7
#define ISISSYSSTATSEQNUMSKIPS 8
#define ISISSYSSTATOWNLSPPURGES 9
#define ISISSYSSTATIDFIELDLENMISMATCHES 10
#define ISISSYSSTATPARTCHANGES 11
#define ISISSYSSTATSPFRUNS 12
#define ISISSYSSTATLSPERRORS 13

enum
{
	/* enums for column isisSysStatLevel */
	isisSysStatLevel_area_c = 1,
	isisSysStatLevel_domain_c = 2,
};

/* table isisSystemCounterTable row entry data structure */
typedef struct isisSystemCounterEntry_t
{
	/* Index values */
	int32_t i32Level;
	
	/* Column values */
	uint32_t u32CorrLSPs;
	uint32_t u32AuthTypeFails;
	uint32_t u32AuthFails;
	uint32_t u32LSPDbaseOloads;
	uint32_t u32ManAddrDropFromAreas;
	uint32_t u32AttmptToExMaxSeqNums;
	uint32_t u32SeqNumSkips;
	uint32_t u32OwnLSPPurges;
	uint32_t u32IDFieldLenMismatches;
	uint32_t u32PartChanges;
	uint32_t u32SPFRuns;
	uint32_t u32LSPErrors;
	
	xBTree_Node_t oBTreeNode;
} isisSystemCounterEntry_t;

extern xBTree_t oIsisSystemCounterTable_BTree;

/* isisSystemCounterTable table mapper */
void isisSystemCounterTable_init (void);
isisSystemCounterEntry_t * isisSystemCounterTable_createEntry (
	int32_t i32Level);
isisSystemCounterEntry_t * isisSystemCounterTable_getByIndex (
	int32_t i32Level);
isisSystemCounterEntry_t * isisSystemCounterTable_getNextIndex (
	int32_t i32Level);
void isisSystemCounterTable_removeEntry (isisSystemCounterEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point isisSystemCounterTable_getFirst;
Netsnmp_Next_Data_Point isisSystemCounterTable_getNext;
Netsnmp_Get_Data_Point isisSystemCounterTable_get;
Netsnmp_Node_Handler isisSystemCounterTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table isisCircuitCounterTable definitions
 */
#define ISISCIRCUITTYPE 1
#define ISISCIRCADJCHANGES 2
#define ISISCIRCNUMADJ 3
#define ISISCIRCINITFAILS 4
#define ISISCIRCREJADJS 5
#define ISISCIRCIDFIELDLENMISMATCHES 6
#define ISISCIRCMAXAREAADDRMISMATCHES 7
#define ISISCIRCAUTHTYPEFAILS 8
#define ISISCIRCAUTHFAILS 9
#define ISISCIRCLANDESISCHANGES 10

enum
{
	/* enums for column isisCircuitType */
	isisCircuitType_lanlevel1_c = 1,
	isisCircuitType_lanlevel2_c = 2,
	isisCircuitType_p2pcircuit_c = 3,
};

/* table isisCircuitCounterTable row entry data structure */
typedef struct isisCircuitCounterEntry_t
{
	/* Index values */
	uint32_t u32Index;
	int32_t i32CircuitType;
	
	/* Column values */
	uint32_t u32AdjChanges;
	uint32_t u32NumAdj;
	uint32_t u32InitFails;
	uint32_t u32RejAdjs;
	uint32_t u32IDFieldLenMismatches;
	uint32_t u32MaxAreaAddrMismatches;
	uint32_t u32AuthTypeFails;
	uint32_t u32AuthFails;
	uint32_t u32LANDesISChanges;
	
	xBTree_Node_t oBTreeNode;
} isisCircuitCounterEntry_t;

extern xBTree_t oIsisCircuitCounterTable_BTree;

/* isisCircuitCounterTable table mapper */
void isisCircuitCounterTable_init (void);
isisCircuitCounterEntry_t * isisCircuitCounterTable_createEntry (
	uint32_t u32Index,
	int32_t i32CircuitType);
isisCircuitCounterEntry_t * isisCircuitCounterTable_getByIndex (
	uint32_t u32Index,
	int32_t i32CircuitType);
isisCircuitCounterEntry_t * isisCircuitCounterTable_getNextIndex (
	uint32_t u32Index,
	int32_t i32CircuitType);
void isisCircuitCounterTable_removeEntry (isisCircuitCounterEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point isisCircuitCounterTable_getFirst;
Netsnmp_Next_Data_Point isisCircuitCounterTable_getNext;
Netsnmp_Get_Data_Point isisCircuitCounterTable_get;
Netsnmp_Node_Handler isisCircuitCounterTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table isisPacketCounterTable definitions
 */
#define ISISPACKETCOUNTLEVEL 1
#define ISISPACKETCOUNTDIRECTION 2
#define ISISPACKETCOUNTIIHELLO 3
#define ISISPACKETCOUNTISHELLO 4
#define ISISPACKETCOUNTESHELLO 5
#define ISISPACKETCOUNTLSP 6
#define ISISPACKETCOUNTCSNP 7
#define ISISPACKETCOUNTPSNP 8
#define ISISPACKETCOUNTUNKNOWN 9

enum
{
	/* enums for column isisPacketCountLevel */
	isisPacketCountLevel_area_c = 1,
	isisPacketCountLevel_domain_c = 2,

	/* enums for column isisPacketCountDirection */
	isisPacketCountDirection_sending_c = 1,
	isisPacketCountDirection_receiving_c = 2,
};

/* table isisPacketCounterTable row entry data structure */
typedef struct isisPacketCounterEntry_t
{
	/* Index values */
	uint32_t u32CircIndex;
	int32_t i32PacketCountLevel;
	int32_t i32PacketCountDirection;
	
	/* Column values */
	uint32_t u32PacketCountIIHello;
	uint32_t u32PacketCountISHello;
	uint32_t u32PacketCountESHello;
	uint32_t u32PacketCountLSP;
	uint32_t u32PacketCountCSNP;
	uint32_t u32PacketCountPSNP;
	uint32_t u32PacketCountUnknown;
	
	xBTree_Node_t oBTreeNode;
} isisPacketCounterEntry_t;

extern xBTree_t oIsisPacketCounterTable_BTree;

/* isisPacketCounterTable table mapper */
void isisPacketCounterTable_init (void);
isisPacketCounterEntry_t * isisPacketCounterTable_createEntry (
	uint32_t u32CircIndex,
	int32_t i32PacketCountLevel,
	int32_t i32PacketCountDirection);
isisPacketCounterEntry_t * isisPacketCounterTable_getByIndex (
	uint32_t u32CircIndex,
	int32_t i32PacketCountLevel,
	int32_t i32PacketCountDirection);
isisPacketCounterEntry_t * isisPacketCounterTable_getNextIndex (
	uint32_t u32CircIndex,
	int32_t i32PacketCountLevel,
	int32_t i32PacketCountDirection);
void isisPacketCounterTable_removeEntry (isisPacketCounterEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point isisPacketCounterTable_getFirst;
Netsnmp_Next_Data_Point isisPacketCounterTable_getNext;
Netsnmp_Get_Data_Point isisPacketCounterTable_get;
Netsnmp_Node_Handler isisPacketCounterTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table isisISAdjTable definitions
 */
#define ISISISADJINDEX 1
#define ISISISADJSTATE 2
#define ISISISADJ3WAYSTATE 3
#define ISISISADJNEIGHSNPAADDRESS 4
#define ISISISADJNEIGHSYSTYPE 5
#define ISISISADJNEIGHSYSID 6
#define ISISISADJNBREXTENDEDCIRCID 7
#define ISISISADJUSAGE 8
#define ISISISADJHOLDTIMER 9
#define ISISISADJNEIGHPRIORITY 10
#define ISISISADJLASTUPTIME 11

enum
{
	/* enums for column isisISAdjState */
	isisISAdjState_down_c = 1,
	isisISAdjState_initializing_c = 2,
	isisISAdjState_up_c = 3,
	isisISAdjState_failed_c = 4,

	/* enums for column isisISAdj3WayState */
	isisISAdj3WayState_up_c = 0,
	isisISAdj3WayState_initializing_c = 1,
	isisISAdj3WayState_down_c = 2,
	isisISAdj3WayState_failed_c = 3,

	/* enums for column isisISAdjNeighSysType */
	isisISAdjNeighSysType_l1IntermediateSystem_c = 1,
	isisISAdjNeighSysType_l2IntermediateSystem_c = 2,
	isisISAdjNeighSysType_l1L2IntermediateSystem_c = 3,
	isisISAdjNeighSysType_unknown_c = 4,

	/* enums for column isisISAdjUsage */
	isisISAdjUsage_level1_c = 1,
	isisISAdjUsage_level2_c = 2,
	isisISAdjUsage_level1and2_c = 3,
};

/* table isisISAdjTable row entry data structure */
typedef struct isisISAdjEntry_t
{
	/* Index values */
	uint32_t u32CircIndex;
	uint32_t u32Index;
	
	/* Column values */
	int32_t i32State;
	int32_t i32ISAdj3WayState;
	uint8_t au8NeighSNPAAddress[20];
	size_t u16NeighSNPAAddress_len;	/* # of uint8_t elements */
	int32_t i32NeighSysType;
	uint8_t au8NeighSysID[6];
	size_t u16NeighSysID_len;	/* # of uint8_t elements */
	uint32_t u32NbrExtendedCircID;
	int32_t i32Usage;
	uint32_t u32HoldTimer;
	uint32_t u32NeighPriority;
	uint32_t u32LastUpTime;
	
	xBTree_Node_t oBTreeNode;
} isisISAdjEntry_t;

extern xBTree_t oIsisISAdjTable_BTree;

/* isisISAdjTable table mapper */
void isisISAdjTable_init (void);
isisISAdjEntry_t * isisISAdjTable_createEntry (
	uint32_t u32CircIndex,
	uint32_t u32Index);
isisISAdjEntry_t * isisISAdjTable_getByIndex (
	uint32_t u32CircIndex,
	uint32_t u32Index);
isisISAdjEntry_t * isisISAdjTable_getNextIndex (
	uint32_t u32CircIndex,
	uint32_t u32Index);
void isisISAdjTable_removeEntry (isisISAdjEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point isisISAdjTable_getFirst;
Netsnmp_Next_Data_Point isisISAdjTable_getNext;
Netsnmp_Get_Data_Point isisISAdjTable_get;
Netsnmp_Node_Handler isisISAdjTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table isisISAdjAreaAddrTable definitions
 */
#define ISISISADJAREAADDRINDEX 1
#define ISISISADJAREAADDRESS 2

/* table isisISAdjAreaAddrTable row entry data structure */
typedef struct isisISAdjAreaAddrEntry_t
{
	/* Index values */
	uint32_t u32CircIndex;
	uint32_t u32ISAdjIndex;
	uint32_t u32Index;
	
	/* Column values */
	uint8_t au8ISAdjAreaAddress[20];
	size_t u16ISAdjAreaAddress_len;	/* # of uint8_t elements */
	
	xBTree_Node_t oBTreeNode;
} isisISAdjAreaAddrEntry_t;

extern xBTree_t oIsisISAdjAreaAddrTable_BTree;

/* isisISAdjAreaAddrTable table mapper */
void isisISAdjAreaAddrTable_init (void);
isisISAdjAreaAddrEntry_t * isisISAdjAreaAddrTable_createEntry (
	uint32_t u32CircIndex,
	uint32_t u32ISAdjIndex,
	uint32_t u32Index);
isisISAdjAreaAddrEntry_t * isisISAdjAreaAddrTable_getByIndex (
	uint32_t u32CircIndex,
	uint32_t u32ISAdjIndex,
	uint32_t u32Index);
isisISAdjAreaAddrEntry_t * isisISAdjAreaAddrTable_getNextIndex (
	uint32_t u32CircIndex,
	uint32_t u32ISAdjIndex,
	uint32_t u32Index);
void isisISAdjAreaAddrTable_removeEntry (isisISAdjAreaAddrEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point isisISAdjAreaAddrTable_getFirst;
Netsnmp_Next_Data_Point isisISAdjAreaAddrTable_getNext;
Netsnmp_Get_Data_Point isisISAdjAreaAddrTable_get;
Netsnmp_Node_Handler isisISAdjAreaAddrTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table isisISAdjIPAddrTable definitions
 */
#define ISISISADJIPADDRINDEX 1
#define ISISISADJIPADDRTYPE 2
#define ISISISADJIPADDRADDRESS 3

enum
{
	/* enums for column isisISAdjIPAddrType */
	isisISAdjIPAddrType_unknown_c = 0,
	isisISAdjIPAddrType_ipv4_c = 1,
	isisISAdjIPAddrType_ipv6_c = 2,
	isisISAdjIPAddrType_ipv4z_c = 3,
	isisISAdjIPAddrType_ipv6z_c = 4,
	isisISAdjIPAddrType_dns_c = 16,
};

/* table isisISAdjIPAddrTable row entry data structure */
typedef struct isisISAdjIPAddrEntry_t
{
	/* Index values */
	uint32_t u32CircIndex;
	uint32_t u32ISAdjIndex;
	uint32_t u32Index;
	
	/* Column values */
	int32_t i32Type;
	uint8_t au8Address[255];
	size_t u16Address_len;	/* # of uint8_t elements */
	
	xBTree_Node_t oBTreeNode;
} isisISAdjIPAddrEntry_t;

extern xBTree_t oIsisISAdjIPAddrTable_BTree;

/* isisISAdjIPAddrTable table mapper */
void isisISAdjIPAddrTable_init (void);
isisISAdjIPAddrEntry_t * isisISAdjIPAddrTable_createEntry (
	uint32_t u32CircIndex,
	uint32_t u32ISAdjIndex,
	uint32_t u32Index);
isisISAdjIPAddrEntry_t * isisISAdjIPAddrTable_getByIndex (
	uint32_t u32CircIndex,
	uint32_t u32ISAdjIndex,
	uint32_t u32Index);
isisISAdjIPAddrEntry_t * isisISAdjIPAddrTable_getNextIndex (
	uint32_t u32CircIndex,
	uint32_t u32ISAdjIndex,
	uint32_t u32Index);
void isisISAdjIPAddrTable_removeEntry (isisISAdjIPAddrEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point isisISAdjIPAddrTable_getFirst;
Netsnmp_Next_Data_Point isisISAdjIPAddrTable_getNext;
Netsnmp_Get_Data_Point isisISAdjIPAddrTable_get;
Netsnmp_Node_Handler isisISAdjIPAddrTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table isisISAdjProtSuppTable definitions
 */
#define ISISISADJPROTSUPPPROTOCOL 1

enum
{
	/* enums for column isisISAdjProtSuppProtocol */
	isisISAdjProtSuppProtocol_iso8473_c = 129,
	isisISAdjProtSuppProtocol_ipV6_c = 142,
	isisISAdjProtSuppProtocol_ip_c = 204,
};

/* table isisISAdjProtSuppTable row entry data structure */
typedef struct isisISAdjProtSuppEntry_t
{
	/* Index values */
	uint32_t u32CircIndex;
	uint32_t u32ISAdjIndex;
	int32_t i32Protocol;
	
	/* Column values */
	
	xBTree_Node_t oBTreeNode;
} isisISAdjProtSuppEntry_t;

extern xBTree_t oIsisISAdjProtSuppTable_BTree;

/* isisISAdjProtSuppTable table mapper */
void isisISAdjProtSuppTable_init (void);
isisISAdjProtSuppEntry_t * isisISAdjProtSuppTable_createEntry (
	uint32_t u32CircIndex,
	uint32_t u32ISAdjIndex,
	int32_t i32Protocol);
isisISAdjProtSuppEntry_t * isisISAdjProtSuppTable_getByIndex (
	uint32_t u32CircIndex,
	uint32_t u32ISAdjIndex,
	int32_t i32Protocol);
isisISAdjProtSuppEntry_t * isisISAdjProtSuppTable_getNextIndex (
	uint32_t u32CircIndex,
	uint32_t u32ISAdjIndex,
	int32_t i32Protocol);
void isisISAdjProtSuppTable_removeEntry (isisISAdjProtSuppEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point isisISAdjProtSuppTable_getFirst;
Netsnmp_Next_Data_Point isisISAdjProtSuppTable_getNext;
Netsnmp_Get_Data_Point isisISAdjProtSuppTable_get;
Netsnmp_Node_Handler isisISAdjProtSuppTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table isisRATable definitions
 */
#define ISISRAINDEX 1
#define ISISRAEXISTSTATE 2
#define ISISRAADMINSTATE 3
#define ISISRAADDRPREFIX 4
#define ISISRAMAPTYPE 5
#define ISISRAMETRIC 6
#define ISISRAMETRICTYPE 7
#define ISISRASNPAADDRESS 8
#define ISISRASNPAMASK 9
#define ISISRASNPAPREFIX 10
#define ISISRATYPE 11

enum
{
	/* enums for column isisRAExistState */
	isisRAExistState_active_c = 1,
	isisRAExistState_notInService_c = 2,
	isisRAExistState_notReady_c = 3,
	isisRAExistState_createAndGo_c = 4,
	isisRAExistState_createAndWait_c = 5,
	isisRAExistState_destroy_c = 6,

	/* enums for column isisRAAdminState */
	isisRAAdminState_on_c = 1,
	isisRAAdminState_off_c = 2,

	/* enums for column isisRAMapType */
	isisRAMapType_none_c = 1,
	isisRAMapType_explicit_c = 2,
	isisRAMapType_extractIDI_c = 3,
	isisRAMapType_extractDSP_c = 4,

	/* enums for column isisRAMetricType */
	isisRAMetricType_internal_c = 1,
	isisRAMetricType_external_c = 2,

	/* enums for column isisRAType */
	isisRAType_manual_c = 1,
	isisRAType_automatic_c = 2,
};

/* table isisRATable row entry data structure */
typedef struct isisRAEntry_t
{
	/* Index values */
	uint32_t u32CircIndex;
	uint32_t u32Index;
	
	/* Column values */
	uint8_t u8ExistState;
	int32_t i32AdminState;
	uint8_t au8AddrPrefix[20];
	size_t u16AddrPrefix_len;	/* # of uint8_t elements */
	int32_t i32MapType;
	uint32_t u32Metric;
	int32_t i32MetricType;
	uint8_t au8SNPAAddress[20];
	size_t u16SNPAAddress_len;	/* # of uint8_t elements */
	uint8_t au8SNPAMask[20];
	size_t u16SNPAMask_len;	/* # of uint8_t elements */
	uint8_t au8SNPAPrefix[20];
	size_t u16SNPAPrefix_len;	/* # of uint8_t elements */
	int32_t i32Type;
	
	xBTree_Node_t oBTreeNode;
} isisRAEntry_t;

extern xBTree_t oIsisRATable_BTree;

/* isisRATable table mapper */
void isisRATable_init (void);
isisRAEntry_t * isisRATable_createEntry (
	uint32_t u32CircIndex,
	uint32_t u32Index);
isisRAEntry_t * isisRATable_getByIndex (
	uint32_t u32CircIndex,
	uint32_t u32Index);
isisRAEntry_t * isisRATable_getNextIndex (
	uint32_t u32CircIndex,
	uint32_t u32Index);
void isisRATable_removeEntry (isisRAEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point isisRATable_getFirst;
Netsnmp_Next_Data_Point isisRATable_getNext;
Netsnmp_Get_Data_Point isisRATable_get;
Netsnmp_Node_Handler isisRATable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table isisIPRATable definitions
 */
#define ISISIPRADESTTYPE 1
#define ISISIPRADEST 2
#define ISISIPRADESTPREFIXLEN 3
#define ISISIPRANEXTHOPINDEX 4
#define ISISIPRANEXTHOPTYPE 5
#define ISISIPRANEXTHOP 6
#define ISISIPRATYPE 7
#define ISISIPRAEXISTSTATE 8
#define ISISIPRAADMINSTATE 9
#define ISISIPRAMETRIC 10
#define ISISIPRAMETRICTYPE 11
#define ISISIPRAFULLMETRIC 12
#define ISISIPRASNPAADDRESS 13
#define ISISIPRASOURCETYPE 14

enum
{
	/* enums for column isisIPRADestType */
	isisIPRADestType_unknown_c = 0,
	isisIPRADestType_ipv4_c = 1,
	isisIPRADestType_ipv6_c = 2,
	isisIPRADestType_ipv4z_c = 3,
	isisIPRADestType_ipv6z_c = 4,
	isisIPRADestType_dns_c = 16,

	/* enums for column isisIPRANextHopType */
	isisIPRANextHopType_unknown_c = 0,
	isisIPRANextHopType_ipv4_c = 1,
	isisIPRANextHopType_ipv6_c = 2,
	isisIPRANextHopType_ipv4z_c = 3,
	isisIPRANextHopType_ipv6z_c = 4,
	isisIPRANextHopType_dns_c = 16,

	/* enums for column isisIPRAType */
	isisIPRAType_manual_c = 1,
	isisIPRAType_automatic_c = 2,

	/* enums for column isisIPRAExistState */
	isisIPRAExistState_active_c = 1,
	isisIPRAExistState_notInService_c = 2,
	isisIPRAExistState_notReady_c = 3,
	isisIPRAExistState_createAndGo_c = 4,
	isisIPRAExistState_createAndWait_c = 5,
	isisIPRAExistState_destroy_c = 6,

	/* enums for column isisIPRAAdminState */
	isisIPRAAdminState_on_c = 1,
	isisIPRAAdminState_off_c = 2,

	/* enums for column isisIPRAMetricType */
	isisIPRAMetricType_internal_c = 1,
	isisIPRAMetricType_external_c = 2,

	/* enums for column isisIPRASourceType */
	isisIPRASourceType_static_c = 1,
	isisIPRASourceType_direct_c = 2,
	isisIPRASourceType_ospfv2_c = 3,
	isisIPRASourceType_ospfv3_c = 4,
	isisIPRASourceType_isis_c = 5,
	isisIPRASourceType_rip_c = 6,
	isisIPRASourceType_igrp_c = 7,
	isisIPRASourceType_eigrp_c = 8,
	isisIPRASourceType_bgp_c = 9,
	isisIPRASourceType_other_c = 10,
};

/* table isisIPRATable row entry data structure */
typedef struct isisIPRAEntry_t
{
	/* Index values */
	int32_t i32SysLevelIndex;
	int32_t i32DestType;
	uint8_t au8Dest[255];
	size_t u16Dest_len;	/* # of uint8_t elements */
	uint32_t u32DestPrefixLen;
	uint32_t u32NextHopIndex;
	
	/* Column values */
	int32_t i32NextHopType;
	uint8_t au8NextHop[255];
	size_t u16NextHop_len;	/* # of uint8_t elements */
	int32_t i32Type;
	uint8_t u8ExistState;
	int32_t i32AdminState;
	uint32_t u32Metric;
	int32_t i32MetricType;
	uint32_t u32FullMetric;
	uint8_t au8SNPAAddress[20];
	size_t u16SNPAAddress_len;	/* # of uint8_t elements */
	int32_t i32SourceType;
	
	xBTree_Node_t oBTreeNode;
} isisIPRAEntry_t;

extern xBTree_t oIsisIPRATable_BTree;

/* isisIPRATable table mapper */
void isisIPRATable_init (void);
isisIPRAEntry_t * isisIPRATable_createEntry (
	int32_t i32SysLevelIndex,
	int32_t i32DestType,
	uint8_t *pau8Dest, size_t u16Dest_len,
	uint32_t u32DestPrefixLen,
	uint32_t u32NextHopIndex);
isisIPRAEntry_t * isisIPRATable_getByIndex (
	int32_t i32SysLevelIndex,
	int32_t i32DestType,
	uint8_t *pau8Dest, size_t u16Dest_len,
	uint32_t u32DestPrefixLen,
	uint32_t u32NextHopIndex);
isisIPRAEntry_t * isisIPRATable_getNextIndex (
	int32_t i32SysLevelIndex,
	int32_t i32DestType,
	uint8_t *pau8Dest, size_t u16Dest_len,
	uint32_t u32DestPrefixLen,
	uint32_t u32NextHopIndex);
void isisIPRATable_removeEntry (isisIPRAEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point isisIPRATable_getFirst;
Netsnmp_Next_Data_Point isisIPRATable_getNext;
Netsnmp_Get_Data_Point isisIPRATable_get;
Netsnmp_Node_Handler isisIPRATable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table isisLSPSummaryTable definitions
 */
#define ISISLSPLEVEL 1
#define ISISLSPID 2
#define ISISLSPSEQ 3
#define ISISLSPZEROLIFE 4
#define ISISLSPCHECKSUM 5
#define ISISLSPLIFETIMEREMAIN 6
#define ISISLSPPDULENGTH 7
#define ISISLSPATTRIBUTES 8

enum
{
	/* enums for column isisLSPLevel */
	isisLSPLevel_area_c = 1,
	isisLSPLevel_domain_c = 2,

	/* enums for column isisLSPZeroLife */
	isisLSPZeroLife_true_c = 1,
	isisLSPZeroLife_false_c = 2,
};

/* table isisLSPSummaryTable row entry data structure */
typedef struct isisLSPSummaryEntry_t
{
	/* Index values */
	int32_t i32Level;
	uint8_t au8ID[8];
	size_t u16ID_len;	/* # of uint8_t elements */
	
	/* Column values */
	uint32_t u32Seq;
	int32_t i32ZeroLife;
	uint32_t u32Checksum;
	uint32_t u32LifetimeRemain;
	uint32_t u32PDULength;
	uint32_t u32Attributes;
	
	xBTree_Node_t oBTreeNode;
} isisLSPSummaryEntry_t;

extern xBTree_t oIsisLSPSummaryTable_BTree;

/* isisLSPSummaryTable table mapper */
void isisLSPSummaryTable_init (void);
isisLSPSummaryEntry_t * isisLSPSummaryTable_createEntry (
	int32_t i32Level,
	uint8_t *pau8ID, size_t u16ID_len);
isisLSPSummaryEntry_t * isisLSPSummaryTable_getByIndex (
	int32_t i32Level,
	uint8_t *pau8ID, size_t u16ID_len);
isisLSPSummaryEntry_t * isisLSPSummaryTable_getNextIndex (
	int32_t i32Level,
	uint8_t *pau8ID, size_t u16ID_len);
void isisLSPSummaryTable_removeEntry (isisLSPSummaryEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point isisLSPSummaryTable_getFirst;
Netsnmp_Next_Data_Point isisLSPSummaryTable_getNext;
Netsnmp_Get_Data_Point isisLSPSummaryTable_get;
Netsnmp_Node_Handler isisLSPSummaryTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table isisLSPTLVTable definitions
 */
#define ISISLSPTLVINDEX 1
#define ISISLSPTLVSEQ 2
#define ISISLSPTLVCHECKSUM 3
#define ISISLSPTLVTYPE 4
#define ISISLSPTLVLEN 5
#define ISISLSPTLVVALUE 6

/* table isisLSPTLVTable row entry data structure */
typedef struct isisLSPTLVEntry_t
{
	/* Index values */
	int32_t i32Level;
	uint8_t au8ID[8];
	size_t u16ID_len;	/* # of uint8_t elements */
	uint32_t u32Index;
	
	/* Column values */
	uint32_t u32Seq;
	uint32_t u32Checksum;
	uint32_t u32Type;
	uint32_t u32Len;
	uint8_t au8Value[255];
	size_t u16Value_len;	/* # of uint8_t elements */
	
	xBTree_Node_t oBTreeNode;
} isisLSPTLVEntry_t;

extern xBTree_t oIsisLSPTLVTable_BTree;

/* isisLSPTLVTable table mapper */
void isisLSPTLVTable_init (void);
isisLSPTLVEntry_t * isisLSPTLVTable_createEntry (
	int32_t i32Level,
	uint8_t *pau8ID, size_t u16ID_len,
	uint32_t u32Index);
isisLSPTLVEntry_t * isisLSPTLVTable_getByIndex (
	int32_t i32Level,
	uint8_t *pau8ID, size_t u16ID_len,
	uint32_t u32Index);
isisLSPTLVEntry_t * isisLSPTLVTable_getNextIndex (
	int32_t i32Level,
	uint8_t *pau8ID, size_t u16ID_len,
	uint32_t u32Index);
void isisLSPTLVTable_removeEntry (isisLSPTLVEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point isisLSPTLVTable_getFirst;
Netsnmp_Next_Data_Point isisLSPTLVTable_getNext;
Netsnmp_Get_Data_Point isisLSPTLVTable_get;
Netsnmp_Node_Handler isisLSPTLVTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	notification mapper(s)
 */
/* definitions for notification(s) of isisNotifications */
#	define ISISDATABASEOVERLOAD 1
#	define ISISMANUALADDRESSDROPS 2
#	define ISISCORRUPTEDLSPDETECTED 3
#	define ISISATTEMPTTOEXCEEDMAXSEQUENCE 4
#	define ISISIDLENMISMATCH 5
#	define ISISMAXAREAADDRESSESMISMATCH 6
#	define ISISOWNLSPPURGE 7
#	define ISISSEQUENCENUMBERSKIP 8
#	define ISISAUTHENTICATIONTYPEFAILURE 9
#	define ISISAUTHENTICATIONFAILURE 10
#	define ISISVERSIONSKEW 11
#	define ISISAREAMISMATCH 12
#	define ISISREJECTEDADJACENCY 13
#	define ISISLSPTOOLARGETOPROPAGATE 14
#	define ISISORIGLSPBUFFSIZEMISMATCH 15
#	define ISISPROTOCOLSSUPPORTEDMISMATCH 16
#	define ISISADJACENCYCHANGE 17
#	define ISISLSPERRORDETECTED 18

/* isisNotifications mapper(s) */
int isisDatabaseOverload_trap (void);
int isisManualAddressDrops_trap (void);
int isisCorruptedLSPDetected_trap (void);
int isisAttemptToExceedMaxSequence_trap (void);
int isisIDLenMismatch_trap (void);
int isisMaxAreaAddressesMismatch_trap (void);
int isisOwnLSPPurge_trap (void);
int isisSequenceNumberSkip_trap (void);
int isisAuthenticationTypeFailure_trap (void);
int isisAuthenticationFailure_trap (void);
int isisVersionSkew_trap (void);
int isisAreaMismatch_trap (void);
int isisRejectedAdjacency_trap (void);
int isisLSPTooLargeToPropagate_trap (void);
int isisOrigLSPBuffSizeMismatch_trap (void);
int isisProtocolsSupportedMismatch_trap (void);
int isisAdjacencyChange_trap (void);
int isisLSPErrorDetected_trap (void);



#	ifdef __cplusplus
}
#	endif

#endif /* __ISISMIB_H__ */
