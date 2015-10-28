/*
 *  Copyright (c) 2008-2015
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

#ifndef __SNMPMIB_H__
#	define __SNMPMIB_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include "lib/binaryTree.h"
#include "lib/snmp.h"

#define TOBE_REPLACED 1


/**
 *	agent MIB function
 */
void snmpMIB_init (void);


/**
 *	scalar mapper(s)
 */
/** definitions for scalar(s) of snmpSet **/
#define SNMPSETSERIALNO 1

typedef struct snmpSet_t
{
	int32_t i32SerialNo;
} snmpSet_t;

extern snmpSet_t oSnmpSet;

#ifdef SNMP_SRC
Netsnmp_Node_Handler snmpSet_mapper;
#endif	/* SNMP_SRC */

/** definitions for scalar(s) of snmpTargetObjects **/
#define SNMPTARGETSPINLOCK 1
#define SNMPUNAVAILABLECONTEXTS 4
#define SNMPUNKNOWNCONTEXTS 5

typedef struct snmpTargetObjects_t
{
	int32_t i32TargetSpinLock;
	uint32_t u32UnavailableContexts;
	uint32_t u32UnknownContexts;
} snmpTargetObjects_t;

extern snmpTargetObjects_t oSnmpTargetObjects;

#ifdef SNMP_SRC
Netsnmp_Node_Handler snmpTargetObjects_mapper;
#endif	/* SNMP_SRC */

/** definitions for scalar(s) of usmStats **/
#define USMSTATSUNSUPPORTEDSECLEVELS 1
#define USMSTATSNOTINTIMEWINDOWS 2
#define USMSTATSUNKNOWNUSERNAMES 3
#define USMSTATSUNKNOWNENGINEIDS 4
#define USMSTATSWRONGDIGESTS 5
#define USMSTATSDECRYPTIONERRORS 6

typedef struct usmStats_t
{
	uint32_t u32UnsupportedSecLevels;
	uint32_t u32NotInTimeWindows;
	uint32_t u32UnknownUserNames;
	uint32_t u32UnknownEngineIDs;
	uint32_t u32WrongDigests;
	uint32_t u32DecryptionErrors;
} usmStats_t;

extern usmStats_t oUsmStats;

#ifdef SNMP_SRC
Netsnmp_Node_Handler usmStats_mapper;
#endif	/* SNMP_SRC */

/** definitions for scalar(s) of usmUser **/
#define USMUSERSPINLOCK 1

typedef struct usmUser_t
{
	int32_t i32SpinLock;
} usmUser_t;

extern usmUser_t oUsmUser;

#ifdef SNMP_SRC
Netsnmp_Node_Handler usmUser_mapper;
#endif	/* SNMP_SRC */

/** definitions for scalar(s) of vacmMIBViews **/
#define VACMVIEWSPINLOCK 1

typedef struct vacmMIBViews_t
{
	int32_t i32ViewSpinLock;
} vacmMIBViews_t;

extern vacmMIBViews_t oVacmMIBViews;

#ifdef SNMP_SRC
Netsnmp_Node_Handler vacmMIBViews_mapper;
#endif	/* SNMP_SRC */



/**
 *	table mapper(s)
 */
/**
 *	table snmpTargetAddrTable definitions
 */
#define SNMPTARGETADDRNAME 1
#define SNMPTARGETADDRTDOMAIN 2
#define SNMPTARGETADDRTADDRESS 3
#define SNMPTARGETADDRTIMEOUT 4
#define SNMPTARGETADDRRETRYCOUNT 5
#define SNMPTARGETADDRTAGLIST 6
#define SNMPTARGETADDRPARAMS 7
#define SNMPTARGETADDRSTORAGETYPE 8
#define SNMPTARGETADDRROWSTATUS 9

enum
{
	/* enums for column snmpTargetAddrStorageType */
	snmpTargetAddrStorageType_other_c = 1,
	snmpTargetAddrStorageType_volatile_c = 2,
	snmpTargetAddrStorageType_nonVolatile_c = 3,
	snmpTargetAddrStorageType_permanent_c = 4,
	snmpTargetAddrStorageType_readOnly_c = 5,

	/* enums for column snmpTargetAddrRowStatus */
	snmpTargetAddrRowStatus_active_c = 1,
	snmpTargetAddrRowStatus_notInService_c = 2,
	snmpTargetAddrRowStatus_notReady_c = 3,
	snmpTargetAddrRowStatus_createAndGo_c = 4,
	snmpTargetAddrRowStatus_createAndWait_c = 5,
	snmpTargetAddrRowStatus_destroy_c = 6,
};

/* table snmpTargetAddrTable row entry data structure */
typedef struct snmpTargetAddrEntry_t
{
	/* Index values */
	uint8_t au8Name[32];
	size_t u16Name_len;	/* # of uint8_t elements */
	
	/* Column values */
	xOid_t aoTDomain[128];
	size_t u16TDomain_len;	/* # of xOid_t elements */
	uint8_t au8TAddress[255];
	size_t u16TAddress_len;	/* # of uint8_t elements */
	int32_t i32Timeout;
	int32_t i32RetryCount;
	uint8_t au8TagList[255];
	size_t u16TagList_len;	/* # of uint8_t elements */
	uint8_t au8Params[32];
	size_t u16Params_len;	/* # of uint8_t elements */
	uint8_t u8StorageType;
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} snmpTargetAddrEntry_t;

extern xBTree_t oSnmpTargetAddrTable_BTree;

/* snmpTargetAddrTable table mapper */
void snmpTargetAddrTable_init (void);
snmpTargetAddrEntry_t * snmpTargetAddrTable_createEntry (
	uint8_t *pau8Name, size_t u16Name_len);
snmpTargetAddrEntry_t * snmpTargetAddrTable_getByIndex (
	uint8_t *pau8Name, size_t u16Name_len);
snmpTargetAddrEntry_t * snmpTargetAddrTable_getNextIndex (
	uint8_t *pau8Name, size_t u16Name_len);
void snmpTargetAddrTable_removeEntry (snmpTargetAddrEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point snmpTargetAddrTable_getFirst;
Netsnmp_Next_Data_Point snmpTargetAddrTable_getNext;
Netsnmp_Get_Data_Point snmpTargetAddrTable_get;
Netsnmp_Node_Handler snmpTargetAddrTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table snmpTargetParamsTable definitions
 */
#define SNMPTARGETPARAMSNAME 1
#define SNMPTARGETPARAMSMPMODEL 2
#define SNMPTARGETPARAMSSECURITYMODEL 3
#define SNMPTARGETPARAMSSECURITYNAME 4
#define SNMPTARGETPARAMSSECURITYLEVEL 5
#define SNMPTARGETPARAMSSTORAGETYPE 6
#define SNMPTARGETPARAMSROWSTATUS 7

enum
{
	/* enums for column snmpTargetParamsSecurityLevel */
	snmpTargetParamsSecurityLevel_noAuthNoPriv_c = 1,
	snmpTargetParamsSecurityLevel_authNoPriv_c = 2,
	snmpTargetParamsSecurityLevel_authPriv_c = 3,

	/* enums for column snmpTargetParamsStorageType */
	snmpTargetParamsStorageType_other_c = 1,
	snmpTargetParamsStorageType_volatile_c = 2,
	snmpTargetParamsStorageType_nonVolatile_c = 3,
	snmpTargetParamsStorageType_permanent_c = 4,
	snmpTargetParamsStorageType_readOnly_c = 5,

	/* enums for column snmpTargetParamsRowStatus */
	snmpTargetParamsRowStatus_active_c = 1,
	snmpTargetParamsRowStatus_notInService_c = 2,
	snmpTargetParamsRowStatus_notReady_c = 3,
	snmpTargetParamsRowStatus_createAndGo_c = 4,
	snmpTargetParamsRowStatus_createAndWait_c = 5,
	snmpTargetParamsRowStatus_destroy_c = 6,
};

/* table snmpTargetParamsTable row entry data structure */
typedef struct snmpTargetParamsEntry_t
{
	/* Index values */
	uint8_t au8Name[32];
	size_t u16Name_len;	/* # of uint8_t elements */
	
	/* Column values */
	int32_t i32MPModel;
	int32_t i32SecurityModel;
	uint8_t au8SecurityName[255];
	size_t u16SecurityName_len;	/* # of uint8_t elements */
	int32_t i32SecurityLevel;
	uint8_t u8StorageType;
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} snmpTargetParamsEntry_t;

extern xBTree_t oSnmpTargetParamsTable_BTree;

/* snmpTargetParamsTable table mapper */
void snmpTargetParamsTable_init (void);
snmpTargetParamsEntry_t * snmpTargetParamsTable_createEntry (
	uint8_t *pau8Name, size_t u16Name_len);
snmpTargetParamsEntry_t * snmpTargetParamsTable_getByIndex (
	uint8_t *pau8Name, size_t u16Name_len);
snmpTargetParamsEntry_t * snmpTargetParamsTable_getNextIndex (
	uint8_t *pau8Name, size_t u16Name_len);
void snmpTargetParamsTable_removeEntry (snmpTargetParamsEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point snmpTargetParamsTable_getFirst;
Netsnmp_Next_Data_Point snmpTargetParamsTable_getNext;
Netsnmp_Get_Data_Point snmpTargetParamsTable_get;
Netsnmp_Node_Handler snmpTargetParamsTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table snmpNotifyTable definitions
 */
#define SNMPNOTIFYNAME 1
#define SNMPNOTIFYTAG 2
#define SNMPNOTIFYTYPE 3
#define SNMPNOTIFYSTORAGETYPE 4
#define SNMPNOTIFYROWSTATUS 5

enum
{
	/* enums for column snmpNotifyType */
	snmpNotifyType_trap_c = 1,
	snmpNotifyType_inform_c = 2,

	/* enums for column snmpNotifyStorageType */
	snmpNotifyStorageType_other_c = 1,
	snmpNotifyStorageType_volatile_c = 2,
	snmpNotifyStorageType_nonVolatile_c = 3,
	snmpNotifyStorageType_permanent_c = 4,
	snmpNotifyStorageType_readOnly_c = 5,

	/* enums for column snmpNotifyRowStatus */
	snmpNotifyRowStatus_active_c = 1,
	snmpNotifyRowStatus_notInService_c = 2,
	snmpNotifyRowStatus_notReady_c = 3,
	snmpNotifyRowStatus_createAndGo_c = 4,
	snmpNotifyRowStatus_createAndWait_c = 5,
	snmpNotifyRowStatus_destroy_c = 6,
};

/* table snmpNotifyTable row entry data structure */
typedef struct snmpNotifyEntry_t
{
	/* Index values */
	uint8_t au8Name[32];
	size_t u16Name_len;	/* # of uint8_t elements */
	
	/* Column values */
	uint8_t au8Tag[255];
	size_t u16Tag_len;	/* # of uint8_t elements */
	int32_t i32Type;
	uint8_t u8StorageType;
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} snmpNotifyEntry_t;

extern xBTree_t oSnmpNotifyTable_BTree;

/* snmpNotifyTable table mapper */
void snmpNotifyTable_init (void);
snmpNotifyEntry_t * snmpNotifyTable_createEntry (
	uint8_t *pau8Name, size_t u16Name_len);
snmpNotifyEntry_t * snmpNotifyTable_getByIndex (
	uint8_t *pau8Name, size_t u16Name_len);
snmpNotifyEntry_t * snmpNotifyTable_getNextIndex (
	uint8_t *pau8Name, size_t u16Name_len);
void snmpNotifyTable_removeEntry (snmpNotifyEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point snmpNotifyTable_getFirst;
Netsnmp_Next_Data_Point snmpNotifyTable_getNext;
Netsnmp_Get_Data_Point snmpNotifyTable_get;
Netsnmp_Node_Handler snmpNotifyTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table snmpNotifyFilterProfileTable definitions
 */
#define SNMPNOTIFYFILTERPROFILENAME 1
#define SNMPNOTIFYFILTERPROFILESTORTYPE 2
#define SNMPNOTIFYFILTERPROFILEROWSTATUS 3

enum
{
	/* enums for column snmpNotifyFilterProfileStorType */
	snmpNotifyFilterProfileStorType_other_c = 1,
	snmpNotifyFilterProfileStorType_volatile_c = 2,
	snmpNotifyFilterProfileStorType_nonVolatile_c = 3,
	snmpNotifyFilterProfileStorType_permanent_c = 4,
	snmpNotifyFilterProfileStorType_readOnly_c = 5,

	/* enums for column snmpNotifyFilterProfileRowStatus */
	snmpNotifyFilterProfileRowStatus_active_c = 1,
	snmpNotifyFilterProfileRowStatus_notInService_c = 2,
	snmpNotifyFilterProfileRowStatus_notReady_c = 3,
	snmpNotifyFilterProfileRowStatus_createAndGo_c = 4,
	snmpNotifyFilterProfileRowStatus_createAndWait_c = 5,
	snmpNotifyFilterProfileRowStatus_destroy_c = 6,
};

/* table snmpNotifyFilterProfileTable row entry data structure */
typedef struct snmpNotifyFilterProfileEntry_t
{
	/* Index values */
	uint8_t au8TargetParamsName[32];
	size_t u16TargetParamsName_len;	/* # of uint8_t elements */
	
	/* Column values */
	uint8_t au8Name[32];
	size_t u16Name_len;	/* # of uint8_t elements */
	uint8_t u8StorType;
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} snmpNotifyFilterProfileEntry_t;

extern xBTree_t oSnmpNotifyFilterProfileTable_BTree;

/* snmpNotifyFilterProfileTable table mapper */
void snmpNotifyFilterProfileTable_init (void);
snmpNotifyFilterProfileEntry_t * snmpNotifyFilterProfileTable_createEntry (
	uint8_t *pau8TargetParamsName, size_t u16TargetParamsName_len);
snmpNotifyFilterProfileEntry_t * snmpNotifyFilterProfileTable_getByIndex (
	uint8_t *pau8TargetParamsName, size_t u16TargetParamsName_len);
snmpNotifyFilterProfileEntry_t * snmpNotifyFilterProfileTable_getNextIndex (
	uint8_t *pau8TargetParamsName, size_t u16TargetParamsName_len);
void snmpNotifyFilterProfileTable_removeEntry (snmpNotifyFilterProfileEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point snmpNotifyFilterProfileTable_getFirst;
Netsnmp_Next_Data_Point snmpNotifyFilterProfileTable_getNext;
Netsnmp_Get_Data_Point snmpNotifyFilterProfileTable_get;
Netsnmp_Node_Handler snmpNotifyFilterProfileTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table snmpNotifyFilterTable definitions
 */
#define SNMPNOTIFYFILTERSUBTREE 1
#define SNMPNOTIFYFILTERMASK 2
#define SNMPNOTIFYFILTERTYPE 3
#define SNMPNOTIFYFILTERSTORAGETYPE 4
#define SNMPNOTIFYFILTERROWSTATUS 5

enum
{
	/* enums for column snmpNotifyFilterType */
	snmpNotifyFilterType_included_c = 1,
	snmpNotifyFilterType_excluded_c = 2,

	/* enums for column snmpNotifyFilterStorageType */
	snmpNotifyFilterStorageType_other_c = 1,
	snmpNotifyFilterStorageType_volatile_c = 2,
	snmpNotifyFilterStorageType_nonVolatile_c = 3,
	snmpNotifyFilterStorageType_permanent_c = 4,
	snmpNotifyFilterStorageType_readOnly_c = 5,

	/* enums for column snmpNotifyFilterRowStatus */
	snmpNotifyFilterRowStatus_active_c = 1,
	snmpNotifyFilterRowStatus_notInService_c = 2,
	snmpNotifyFilterRowStatus_notReady_c = 3,
	snmpNotifyFilterRowStatus_createAndGo_c = 4,
	snmpNotifyFilterRowStatus_createAndWait_c = 5,
	snmpNotifyFilterRowStatus_destroy_c = 6,
};

/* table snmpNotifyFilterTable row entry data structure */
typedef struct snmpNotifyFilterEntry_t
{
	/* Index values */
	uint8_t au8ProfileName[32];
	size_t u16ProfileName_len;	/* # of uint8_t elements */
	xOid_t aoSubtree[128];
	size_t u16Subtree_len;	/* # of xOid_t elements */
	
	/* Column values */
	uint8_t au8Mask[16];
	size_t u16Mask_len;	/* # of uint8_t elements */
	int32_t i32Type;
	uint8_t u8StorageType;
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} snmpNotifyFilterEntry_t;

extern xBTree_t oSnmpNotifyFilterTable_BTree;

/* snmpNotifyFilterTable table mapper */
void snmpNotifyFilterTable_init (void);
snmpNotifyFilterEntry_t * snmpNotifyFilterTable_createEntry (
	uint8_t *pau8ProfileName, size_t u16ProfileName_len,
	xOid_t *paoSubtree, size_t u16Subtree_len);
snmpNotifyFilterEntry_t * snmpNotifyFilterTable_getByIndex (
	uint8_t *pau8ProfileName, size_t u16ProfileName_len,
	xOid_t *paoSubtree, size_t u16Subtree_len);
snmpNotifyFilterEntry_t * snmpNotifyFilterTable_getNextIndex (
	uint8_t *pau8ProfileName, size_t u16ProfileName_len,
	xOid_t *paoSubtree, size_t u16Subtree_len);
void snmpNotifyFilterTable_removeEntry (snmpNotifyFilterEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point snmpNotifyFilterTable_getFirst;
Netsnmp_Next_Data_Point snmpNotifyFilterTable_getNext;
Netsnmp_Get_Data_Point snmpNotifyFilterTable_get;
Netsnmp_Node_Handler snmpNotifyFilterTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table usmUserTable definitions
 */
#define USMUSERENGINEID 1
#define USMUSERNAME 2
#define USMUSERSECURITYNAME 3
#define USMUSERCLONEFROM 4
#define USMUSERAUTHPROTOCOL 5
#define USMUSERAUTHKEYCHANGE 6
#define USMUSEROWNAUTHKEYCHANGE 7
#define USMUSERPRIVPROTOCOL 8
#define USMUSERPRIVKEYCHANGE 9
#define USMUSEROWNPRIVKEYCHANGE 10
#define USMUSERPUBLIC 11
#define USMUSERSTORAGETYPE 12
#define USMUSERSTATUS 13

enum
{
	/* enums for column usmUserStorageType */
	usmUserStorageType_other_c = 1,
	usmUserStorageType_volatile_c = 2,
	usmUserStorageType_nonVolatile_c = 3,
	usmUserStorageType_permanent_c = 4,
	usmUserStorageType_readOnly_c = 5,

	/* enums for column usmUserStatus */
	usmUserStatus_active_c = 1,
	usmUserStatus_notInService_c = 2,
	usmUserStatus_notReady_c = 3,
	usmUserStatus_createAndGo_c = 4,
	usmUserStatus_createAndWait_c = 5,
	usmUserStatus_destroy_c = 6,
};

/* table usmUserTable row entry data structure */
typedef struct usmUserEntry_t
{
	/* Index values */
	uint8_t au8EngineID[32];
	size_t u16EngineID_len;	/* # of uint8_t elements */
	uint8_t au8Name[32];
	size_t u16Name_len;	/* # of uint8_t elements */
	
	/* Column values */
	uint8_t au8SecurityName[255];
	size_t u16SecurityName_len;	/* # of uint8_t elements */
	xOid_t aoCloneFrom[128];
	size_t u16CloneFrom_len;	/* # of xOid_t elements */
	xOid_t aoAuthProtocol[128];
	size_t u16AuthProtocol_len;	/* # of xOid_t elements */
	uint8_t au8AuthKeyChange[/* TODO: KeyChange, KeyChange, "" */ TOBE_REPLACED];
	size_t u16AuthKeyChange_len;	/* # of uint8_t elements */
	uint8_t au8OwnAuthKeyChange[/* TODO: KeyChange, KeyChange, "" */ TOBE_REPLACED];
	size_t u16OwnAuthKeyChange_len;	/* # of uint8_t elements */
	xOid_t aoPrivProtocol[128];
	size_t u16PrivProtocol_len;	/* # of xOid_t elements */
	uint8_t au8PrivKeyChange[/* TODO: KeyChange, KeyChange, "" */ TOBE_REPLACED];
	size_t u16PrivKeyChange_len;	/* # of uint8_t elements */
	uint8_t au8OwnPrivKeyChange[/* TODO: KeyChange, KeyChange, "" */ TOBE_REPLACED];
	size_t u16OwnPrivKeyChange_len;	/* # of uint8_t elements */
	uint8_t au8Public[32];
	size_t u16Public_len;	/* # of uint8_t elements */
	uint8_t u8StorageType;
	uint8_t u8Status;
	
	xBTree_Node_t oBTreeNode;
} usmUserEntry_t;

extern xBTree_t oUsmUserTable_BTree;

/* usmUserTable table mapper */
void usmUserTable_init (void);
usmUserEntry_t * usmUserTable_createEntry (
	uint8_t *pau8EngineID, size_t u16EngineID_len,
	uint8_t *pau8Name, size_t u16Name_len);
usmUserEntry_t * usmUserTable_getByIndex (
	uint8_t *pau8EngineID, size_t u16EngineID_len,
	uint8_t *pau8Name, size_t u16Name_len);
usmUserEntry_t * usmUserTable_getNextIndex (
	uint8_t *pau8EngineID, size_t u16EngineID_len,
	uint8_t *pau8Name, size_t u16Name_len);
void usmUserTable_removeEntry (usmUserEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point usmUserTable_getFirst;
Netsnmp_Next_Data_Point usmUserTable_getNext;
Netsnmp_Get_Data_Point usmUserTable_get;
Netsnmp_Node_Handler usmUserTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table vacmContextTable definitions
 */
#define VACMCONTEXTNAME 1

/* table vacmContextTable row entry data structure */
typedef struct vacmContextEntry_t
{
	/* Index values */
	uint8_t au8Name[32];
	size_t u16Name_len;	/* # of uint8_t elements */
	
	/* Column values */
	
	xBTree_Node_t oBTreeNode;
} vacmContextEntry_t;

extern xBTree_t oVacmContextTable_BTree;

/* vacmContextTable table mapper */
void vacmContextTable_init (void);
vacmContextEntry_t * vacmContextTable_createEntry (
	uint8_t *pau8Name, size_t u16Name_len);
vacmContextEntry_t * vacmContextTable_getByIndex (
	uint8_t *pau8Name, size_t u16Name_len);
vacmContextEntry_t * vacmContextTable_getNextIndex (
	uint8_t *pau8Name, size_t u16Name_len);
void vacmContextTable_removeEntry (vacmContextEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point vacmContextTable_getFirst;
Netsnmp_Next_Data_Point vacmContextTable_getNext;
Netsnmp_Get_Data_Point vacmContextTable_get;
Netsnmp_Node_Handler vacmContextTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table vacmSecurityToGroupTable definitions
 */
#define VACMSECURITYMODEL 1
#define VACMSECURITYNAME 2
#define VACMGROUPNAME 3
#define VACMSECURITYTOGROUPSTORAGETYPE 4
#define VACMSECURITYTOGROUPSTATUS 5

enum
{
	/* enums for column vacmSecurityToGroupStorageType */
	vacmSecurityToGroupStorageType_other_c = 1,
	vacmSecurityToGroupStorageType_volatile_c = 2,
	vacmSecurityToGroupStorageType_nonVolatile_c = 3,
	vacmSecurityToGroupStorageType_permanent_c = 4,
	vacmSecurityToGroupStorageType_readOnly_c = 5,

	/* enums for column vacmSecurityToGroupStatus */
	vacmSecurityToGroupStatus_active_c = 1,
	vacmSecurityToGroupStatus_notInService_c = 2,
	vacmSecurityToGroupStatus_notReady_c = 3,
	vacmSecurityToGroupStatus_createAndGo_c = 4,
	vacmSecurityToGroupStatus_createAndWait_c = 5,
	vacmSecurityToGroupStatus_destroy_c = 6,
};

/* table vacmSecurityToGroupTable row entry data structure */
typedef struct vacmSecurityToGroupEntry_t
{
	/* Index values */
	int32_t i32SecurityModel;
	uint8_t au8SecurityName[32];
	size_t u16SecurityName_len;	/* # of uint8_t elements */
	
	/* Column values */
	uint8_t au8GroupName[32];
	size_t u16GroupName_len;	/* # of uint8_t elements */
	uint8_t u8StorageType;
	uint8_t u8Status;
	
	xBTree_Node_t oBTreeNode;
} vacmSecurityToGroupEntry_t;

extern xBTree_t oVacmSecurityToGroupTable_BTree;

/* vacmSecurityToGroupTable table mapper */
void vacmSecurityToGroupTable_init (void);
vacmSecurityToGroupEntry_t * vacmSecurityToGroupTable_createEntry (
	int32_t i32SecurityModel,
	uint8_t *pau8SecurityName, size_t u16SecurityName_len);
vacmSecurityToGroupEntry_t * vacmSecurityToGroupTable_getByIndex (
	int32_t i32SecurityModel,
	uint8_t *pau8SecurityName, size_t u16SecurityName_len);
vacmSecurityToGroupEntry_t * vacmSecurityToGroupTable_getNextIndex (
	int32_t i32SecurityModel,
	uint8_t *pau8SecurityName, size_t u16SecurityName_len);
void vacmSecurityToGroupTable_removeEntry (vacmSecurityToGroupEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point vacmSecurityToGroupTable_getFirst;
Netsnmp_Next_Data_Point vacmSecurityToGroupTable_getNext;
Netsnmp_Get_Data_Point vacmSecurityToGroupTable_get;
Netsnmp_Node_Handler vacmSecurityToGroupTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table vacmAccessTable definitions
 */
#define VACMACCESSCONTEXTPREFIX 1
#define VACMACCESSSECURITYMODEL 2
#define VACMACCESSSECURITYLEVEL 3
#define VACMACCESSCONTEXTMATCH 4
#define VACMACCESSREADVIEWNAME 5
#define VACMACCESSWRITEVIEWNAME 6
#define VACMACCESSNOTIFYVIEWNAME 7
#define VACMACCESSSTORAGETYPE 8
#define VACMACCESSSTATUS 9

enum
{
	/* enums for column vacmAccessSecurityLevel */
	vacmAccessSecurityLevel_noAuthNoPriv_c = 1,
	vacmAccessSecurityLevel_authNoPriv_c = 2,
	vacmAccessSecurityLevel_authPriv_c = 3,

	/* enums for column vacmAccessContextMatch */
	vacmAccessContextMatch_exact_c = 1,
	vacmAccessContextMatch_prefix_c = 2,

	/* enums for column vacmAccessStorageType */
	vacmAccessStorageType_other_c = 1,
	vacmAccessStorageType_volatile_c = 2,
	vacmAccessStorageType_nonVolatile_c = 3,
	vacmAccessStorageType_permanent_c = 4,
	vacmAccessStorageType_readOnly_c = 5,

	/* enums for column vacmAccessStatus */
	vacmAccessStatus_active_c = 1,
	vacmAccessStatus_notInService_c = 2,
	vacmAccessStatus_notReady_c = 3,
	vacmAccessStatus_createAndGo_c = 4,
	vacmAccessStatus_createAndWait_c = 5,
	vacmAccessStatus_destroy_c = 6,
};

/* table vacmAccessTable row entry data structure */
typedef struct vacmAccessEntry_t
{
	/* Index values */
	uint8_t au8GroupName[32];
	size_t u16GroupName_len;	/* # of uint8_t elements */
	uint8_t au8ContextPrefix[32];
	size_t u16ContextPrefix_len;	/* # of uint8_t elements */
	int32_t i32SecurityModel;
	int32_t i32SecurityLevel;
	
	/* Column values */
	int32_t i32ContextMatch;
	uint8_t au8ReadViewName[32];
	size_t u16ReadViewName_len;	/* # of uint8_t elements */
	uint8_t au8WriteViewName[32];
	size_t u16WriteViewName_len;	/* # of uint8_t elements */
	uint8_t au8NotifyViewName[32];
	size_t u16NotifyViewName_len;	/* # of uint8_t elements */
	uint8_t u8StorageType;
	uint8_t u8Status;
	
	xBTree_Node_t oBTreeNode;
} vacmAccessEntry_t;

extern xBTree_t oVacmAccessTable_BTree;

/* vacmAccessTable table mapper */
void vacmAccessTable_init (void);
vacmAccessEntry_t * vacmAccessTable_createEntry (
	uint8_t *pau8GroupName, size_t u16GroupName_len,
	uint8_t *pau8ContextPrefix, size_t u16ContextPrefix_len,
	int32_t i32SecurityModel,
	int32_t i32SecurityLevel);
vacmAccessEntry_t * vacmAccessTable_getByIndex (
	uint8_t *pau8GroupName, size_t u16GroupName_len,
	uint8_t *pau8ContextPrefix, size_t u16ContextPrefix_len,
	int32_t i32SecurityModel,
	int32_t i32SecurityLevel);
vacmAccessEntry_t * vacmAccessTable_getNextIndex (
	uint8_t *pau8GroupName, size_t u16GroupName_len,
	uint8_t *pau8ContextPrefix, size_t u16ContextPrefix_len,
	int32_t i32SecurityModel,
	int32_t i32SecurityLevel);
void vacmAccessTable_removeEntry (vacmAccessEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point vacmAccessTable_getFirst;
Netsnmp_Next_Data_Point vacmAccessTable_getNext;
Netsnmp_Get_Data_Point vacmAccessTable_get;
Netsnmp_Node_Handler vacmAccessTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table vacmViewTreeFamilyTable definitions
 */
#define VACMVIEWTREEFAMILYVIEWNAME 1
#define VACMVIEWTREEFAMILYSUBTREE 2
#define VACMVIEWTREEFAMILYMASK 3
#define VACMVIEWTREEFAMILYTYPE 4
#define VACMVIEWTREEFAMILYSTORAGETYPE 5
#define VACMVIEWTREEFAMILYSTATUS 6

enum
{
	/* enums for column vacmViewTreeFamilyType */
	vacmViewTreeFamilyType_included_c = 1,
	vacmViewTreeFamilyType_excluded_c = 2,

	/* enums for column vacmViewTreeFamilyStorageType */
	vacmViewTreeFamilyStorageType_other_c = 1,
	vacmViewTreeFamilyStorageType_volatile_c = 2,
	vacmViewTreeFamilyStorageType_nonVolatile_c = 3,
	vacmViewTreeFamilyStorageType_permanent_c = 4,
	vacmViewTreeFamilyStorageType_readOnly_c = 5,

	/* enums for column vacmViewTreeFamilyStatus */
	vacmViewTreeFamilyStatus_active_c = 1,
	vacmViewTreeFamilyStatus_notInService_c = 2,
	vacmViewTreeFamilyStatus_notReady_c = 3,
	vacmViewTreeFamilyStatus_createAndGo_c = 4,
	vacmViewTreeFamilyStatus_createAndWait_c = 5,
	vacmViewTreeFamilyStatus_destroy_c = 6,
};

/* table vacmViewTreeFamilyTable row entry data structure */
typedef struct vacmViewTreeFamilyEntry_t
{
	/* Index values */
	uint8_t au8ViewName[32];
	size_t u16ViewName_len;	/* # of uint8_t elements */
	xOid_t aoSubtree[128];
	size_t u16Subtree_len;	/* # of xOid_t elements */
	
	/* Column values */
	uint8_t au8Mask[16];
	size_t u16Mask_len;	/* # of uint8_t elements */
	int32_t i32Type;
	uint8_t u8StorageType;
	uint8_t u8Status;
	
	xBTree_Node_t oBTreeNode;
} vacmViewTreeFamilyEntry_t;

extern xBTree_t oVacmViewTreeFamilyTable_BTree;

/* vacmViewTreeFamilyTable table mapper */
void vacmViewTreeFamilyTable_init (void);
vacmViewTreeFamilyEntry_t * vacmViewTreeFamilyTable_createEntry (
	uint8_t *pau8ViewName, size_t u16ViewName_len,
	xOid_t *paoSubtree, size_t u16Subtree_len);
vacmViewTreeFamilyEntry_t * vacmViewTreeFamilyTable_getByIndex (
	uint8_t *pau8ViewName, size_t u16ViewName_len,
	xOid_t *paoSubtree, size_t u16Subtree_len);
vacmViewTreeFamilyEntry_t * vacmViewTreeFamilyTable_getNextIndex (
	uint8_t *pau8ViewName, size_t u16ViewName_len,
	xOid_t *paoSubtree, size_t u16Subtree_len);
void vacmViewTreeFamilyTable_removeEntry (vacmViewTreeFamilyEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point vacmViewTreeFamilyTable_getFirst;
Netsnmp_Next_Data_Point vacmViewTreeFamilyTable_getNext;
Netsnmp_Get_Data_Point vacmViewTreeFamilyTable_get;
Netsnmp_Node_Handler vacmViewTreeFamilyTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table snmpCommunityTable definitions
 */
#define SNMPCOMMUNITYINDEX 1
#define SNMPCOMMUNITYNAME 2
#define SNMPCOMMUNITYSECURITYNAME 3
#define SNMPCOMMUNITYCONTEXTENGINEID 4
#define SNMPCOMMUNITYCONTEXTNAME 5
#define SNMPCOMMUNITYTRANSPORTTAG 6
#define SNMPCOMMUNITYSTORAGETYPE 7
#define SNMPCOMMUNITYSTATUS 8

enum
{
	/* enums for column snmpCommunityStorageType */
	snmpCommunityStorageType_other_c = 1,
	snmpCommunityStorageType_volatile_c = 2,
	snmpCommunityStorageType_nonVolatile_c = 3,
	snmpCommunityStorageType_permanent_c = 4,
	snmpCommunityStorageType_readOnly_c = 5,

	/* enums for column snmpCommunityStatus */
	snmpCommunityStatus_active_c = 1,
	snmpCommunityStatus_notInService_c = 2,
	snmpCommunityStatus_notReady_c = 3,
	snmpCommunityStatus_createAndGo_c = 4,
	snmpCommunityStatus_createAndWait_c = 5,
	snmpCommunityStatus_destroy_c = 6,
};

/* table snmpCommunityTable row entry data structure */
typedef struct snmpCommunityEntry_t
{
	/* Index values */
	uint8_t au8Index[32];
	size_t u16Index_len;	/* # of uint8_t elements */
	
	/* Column values */
	uint8_t au8Name[/* TODO: , OCTETSTR, "" */ TOBE_REPLACED];
	size_t u16Name_len;	/* # of uint8_t elements */
	uint8_t au8SecurityName[32];
	size_t u16SecurityName_len;	/* # of uint8_t elements */
	uint8_t au8ContextEngineID[32];
	size_t u16ContextEngineID_len;	/* # of uint8_t elements */
	uint8_t au8ContextName[32];
	size_t u16ContextName_len;	/* # of uint8_t elements */
	uint8_t au8TransportTag[255];
	size_t u16TransportTag_len;	/* # of uint8_t elements */
	uint8_t u8StorageType;
	uint8_t u8Status;
	
	xBTree_Node_t oBTreeNode;
} snmpCommunityEntry_t;

extern xBTree_t oSnmpCommunityTable_BTree;

/* snmpCommunityTable table mapper */
void snmpCommunityTable_init (void);
snmpCommunityEntry_t * snmpCommunityTable_createEntry (
	uint8_t *pau8Index, size_t u16Index_len);
snmpCommunityEntry_t * snmpCommunityTable_getByIndex (
	uint8_t *pau8Index, size_t u16Index_len);
snmpCommunityEntry_t * snmpCommunityTable_getNextIndex (
	uint8_t *pau8Index, size_t u16Index_len);
void snmpCommunityTable_removeEntry (snmpCommunityEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point snmpCommunityTable_getFirst;
Netsnmp_Next_Data_Point snmpCommunityTable_getNext;
Netsnmp_Get_Data_Point snmpCommunityTable_get;
Netsnmp_Node_Handler snmpCommunityTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table snmpTargetAddrExtTable definitions
 */
#define SNMPTARGETADDRTMASK 1
#define SNMPTARGETADDRMMS 2

/* table snmpTargetAddrExtTable row entry data structure */
typedef struct snmpTargetAddrExtEntry_t
{
	/* Index values */
	uint8_t au8Name[32];
	size_t u16Name_len;	/* # of uint8_t elements */
	
	/* Column values */
	uint8_t au8TMask[255];
	size_t u16TMask_len;	/* # of uint8_t elements */
	int32_t i32MMS;
	
	xBTree_Node_t oBTreeNode;
} snmpTargetAddrExtEntry_t;

extern xBTree_t oSnmpTargetAddrExtTable_BTree;

/* snmpTargetAddrExtTable table mapper */
void snmpTargetAddrExtTable_init (void);
snmpTargetAddrExtEntry_t * snmpTargetAddrExtTable_createEntry (
	uint8_t *pau8Name, size_t u16Name_len);
snmpTargetAddrExtEntry_t * snmpTargetAddrExtTable_getByIndex (
	uint8_t *pau8Name, size_t u16Name_len);
snmpTargetAddrExtEntry_t * snmpTargetAddrExtTable_getNextIndex (
	uint8_t *pau8Name, size_t u16Name_len);
void snmpTargetAddrExtTable_removeEntry (snmpTargetAddrExtEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point snmpTargetAddrExtTable_getFirst;
Netsnmp_Next_Data_Point snmpTargetAddrExtTable_getNext;
Netsnmp_Get_Data_Point snmpTargetAddrExtTable_get;
Netsnmp_Node_Handler snmpTargetAddrExtTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	notification mapper(s)
 */
/* definitions for notification(s) of snmpTraps */
#	define COLDSTART 1
#	define WARMSTART 2
#	define LINKDOWN 3
#	define LINKUP 4
#	define AUTHENTICATIONFAILURE 5

/* snmpTraps mapper(s) */
int coldStart_trap (void);
int warmStart_trap (void);
int linkDown_trap (void);
int linkUp_trap (void);
int authenticationFailure_trap (void);



#	ifdef __cplusplus
}
#	endif

#endif /* __SNMPMIB_H__ */
