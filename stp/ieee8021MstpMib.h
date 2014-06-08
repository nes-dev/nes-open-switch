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

#ifndef __IEEE8021MSTPMIB_H__
#	define __IEEE8021MSTPMIB_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include "lib/binaryTree.h"
#include "lib/snmp.h"

#define TOBE_REPLACED 1


/**
 *	agent MIB function
 */
void ieee8021MstpMib_init (void);


/**
 *	table mapper(s)
 */
/**
 *	table ieee8021MstpCistTable definitions
 */
#define IEEE8021MSTPCISTCOMPONENTID 1
#define IEEE8021MSTPCISTBRIDGEIDENTIFIER 2
#define IEEE8021MSTPCISTTOPOLOGYCHANGE 3
#define IEEE8021MSTPCISTREGIONALROOTIDENTIFIER 4
#define IEEE8021MSTPCISTPATHCOST 5
#define IEEE8021MSTPCISTMAXHOPS 6

enum
{
	/* enums for column ieee8021MstpCistTopologyChange */
	ieee8021MstpCistTopologyChange_true_c = 1,
	ieee8021MstpCistTopologyChange_false_c = 2,
};

/* table ieee8021MstpCistTable row entry data structure */
typedef struct ieee8021MstpCistEntry_t
{
	/* Index values */
	uint32_t u32ComponentId;
	
	/* Column values */
	uint8_t au8BridgeIdentifier[8];
	size_t u16BridgeIdentifier_len;	/* # of uint8_t elements */
	int32_t i32TopologyChange;
	uint8_t au8RegionalRootIdentifier[8];
	size_t u16RegionalRootIdentifier_len;	/* # of uint8_t elements */
	uint32_t u32PathCost;
	int32_t i32MaxHops;
	
	xBTree_Node_t oBTreeNode;
} ieee8021MstpCistEntry_t;

extern xBTree_t oIeee8021MstpCistTable_BTree;

/* ieee8021MstpCistTable table mapper */
void ieee8021MstpCistTable_init (void);
ieee8021MstpCistEntry_t * ieee8021MstpCistTable_createEntry (
	uint32_t u32ComponentId);
ieee8021MstpCistEntry_t * ieee8021MstpCistTable_getByIndex (
	uint32_t u32ComponentId);
ieee8021MstpCistEntry_t * ieee8021MstpCistTable_getNextIndex (
	uint32_t u32ComponentId);
void ieee8021MstpCistTable_removeEntry (ieee8021MstpCistEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021MstpCistTable_getFirst;
Netsnmp_Next_Data_Point ieee8021MstpCistTable_getNext;
Netsnmp_Get_Data_Point ieee8021MstpCistTable_get;
Netsnmp_Node_Handler ieee8021MstpCistTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021MstpTable definitions
 */
#define IEEE8021MSTPCOMPONENTID 1
#define IEEE8021MSTPID 2
#define IEEE8021MSTPBRIDGEID 3
#define IEEE8021MSTPTIMESINCETOPOLOGYCHANGE 4
#define IEEE8021MSTPTOPOLOGYCHANGES 5
#define IEEE8021MSTPTOPOLOGYCHANGE 6
#define IEEE8021MSTPDESIGNATEDROOT 7
#define IEEE8021MSTPROOTPATHCOST 8
#define IEEE8021MSTPROOTPORT 9
#define IEEE8021MSTPBRIDGEPRIORITY 10
#define IEEE8021MSTPVIDS0 11
#define IEEE8021MSTPVIDS1 12
#define IEEE8021MSTPVIDS2 13
#define IEEE8021MSTPVIDS3 14
#define IEEE8021MSTPROWSTATUS 15

enum
{
	/* enums for column ieee8021MstpTopologyChange */
	ieee8021MstpTopologyChange_true_c = 1,
	ieee8021MstpTopologyChange_false_c = 2,

	/* enums for column ieee8021MstpRowStatus */
	ieee8021MstpRowStatus_active_c = 1,
	ieee8021MstpRowStatus_notInService_c = 2,
	ieee8021MstpRowStatus_notReady_c = 3,
	ieee8021MstpRowStatus_createAndGo_c = 4,
	ieee8021MstpRowStatus_createAndWait_c = 5,
	ieee8021MstpRowStatus_destroy_c = 6,
};

/* table ieee8021MstpTable row entry data structure */
typedef struct ieee8021MstpEntry_t
{
	/* Index values */
	uint32_t u32ComponentId;
	uint32_t u32Id;
	
	/* Column values */
	uint8_t au8BridgeId[8];
	size_t u16BridgeId_len;	/* # of uint8_t elements */
	uint32_t u32TimeSinceTopologyChange;
	uint64_t u64TopologyChanges;
	int32_t i32TopologyChange;
	uint8_t au8DesignatedRoot[8];
	size_t u16DesignatedRoot_len;	/* # of uint8_t elements */
	int32_t i32RootPathCost;
	uint32_t u32RootPort;
	int32_t i32BridgePriority;
	uint8_t au8Vids0[128];
	size_t u16Vids0_len;	/* # of uint8_t elements */
	uint8_t au8Vids1[128];
	size_t u16Vids1_len;	/* # of uint8_t elements */
	uint8_t au8Vids2[128];
	size_t u16Vids2_len;	/* # of uint8_t elements */
	uint8_t au8Vids3[128];
	size_t u16Vids3_len;	/* # of uint8_t elements */
	int32_t i32RowStatus;
	
	xBTree_Node_t oBTreeNode;
} ieee8021MstpEntry_t;

extern xBTree_t oIeee8021MstpTable_BTree;

/* ieee8021MstpTable table mapper */
void ieee8021MstpTable_init (void);
ieee8021MstpEntry_t * ieee8021MstpTable_createEntry (
	uint32_t u32ComponentId,
	uint32_t u32Id);
ieee8021MstpEntry_t * ieee8021MstpTable_getByIndex (
	uint32_t u32ComponentId,
	uint32_t u32Id);
ieee8021MstpEntry_t * ieee8021MstpTable_getNextIndex (
	uint32_t u32ComponentId,
	uint32_t u32Id);
void ieee8021MstpTable_removeEntry (ieee8021MstpEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021MstpTable_getFirst;
Netsnmp_Next_Data_Point ieee8021MstpTable_getNext;
Netsnmp_Get_Data_Point ieee8021MstpTable_get;
Netsnmp_Node_Handler ieee8021MstpTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021MstpCistPortTable definitions
 */
#define IEEE8021MSTPCISTPORTCOMPONENTID 1
#define IEEE8021MSTPCISTPORTNUM 2
#define IEEE8021MSTPCISTPORTUPTIME 3
#define IEEE8021MSTPCISTPORTADMINPATHCOST 4
#define IEEE8021MSTPCISTPORTDESIGNATEDROOT 5
#define IEEE8021MSTPCISTPORTTOPOLOGYCHANGEACK 6
#define IEEE8021MSTPCISTPORTHELLOTIME 7
#define IEEE8021MSTPCISTPORTADMINEDGEPORT 8
#define IEEE8021MSTPCISTPORTOPEREDGEPORT 9
#define IEEE8021MSTPCISTPORTMACENABLED 10
#define IEEE8021MSTPCISTPORTMACOPERATIONAL 11
#define IEEE8021MSTPCISTPORTRESTRICTEDROLE 12
#define IEEE8021MSTPCISTPORTRESTRICTEDTCN 13
#define IEEE8021MSTPCISTPORTROLE 14
#define IEEE8021MSTPCISTPORTDISPUTED 15
#define IEEE8021MSTPCISTPORTCISTREGIONALROOTID 16
#define IEEE8021MSTPCISTPORTCISTPATHCOST 17
#define IEEE8021MSTPCISTPORTPROTOCOLMIGRATION 18
#define IEEE8021MSTPCISTPORTENABLEBPDURX 19
#define IEEE8021MSTPCISTPORTENABLEBPDUTX 20
#define IEEE8021MSTPCISTPORTPSEUDOROOTID 21
#define IEEE8021MSTPCISTPORTISL2GP 22

enum
{
	/* enums for column ieee8021MstpCistPortTopologyChangeAck */
	ieee8021MstpCistPortTopologyChangeAck_true_c = 1,
	ieee8021MstpCistPortTopologyChangeAck_false_c = 2,

	/* enums for column ieee8021MstpCistPortAdminEdgePort */
	ieee8021MstpCistPortAdminEdgePort_true_c = 1,
	ieee8021MstpCistPortAdminEdgePort_false_c = 2,

	/* enums for column ieee8021MstpCistPortOperEdgePort */
	ieee8021MstpCistPortOperEdgePort_true_c = 1,
	ieee8021MstpCistPortOperEdgePort_false_c = 2,

	/* enums for column ieee8021MstpCistPortMacEnabled */
	ieee8021MstpCistPortMacEnabled_true_c = 1,
	ieee8021MstpCistPortMacEnabled_false_c = 2,

	/* enums for column ieee8021MstpCistPortMacOperational */
	ieee8021MstpCistPortMacOperational_true_c = 1,
	ieee8021MstpCistPortMacOperational_false_c = 2,

	/* enums for column ieee8021MstpCistPortRestrictedRole */
	ieee8021MstpCistPortRestrictedRole_true_c = 1,
	ieee8021MstpCistPortRestrictedRole_false_c = 2,

	/* enums for column ieee8021MstpCistPortRestrictedTcn */
	ieee8021MstpCistPortRestrictedTcn_true_c = 1,
	ieee8021MstpCistPortRestrictedTcn_false_c = 2,

	/* enums for column ieee8021MstpCistPortRole */
	ieee8021MstpCistPortRole_root_c = 1,
	ieee8021MstpCistPortRole_alternate_c = 2,
	ieee8021MstpCistPortRole_designated_c = 3,
	ieee8021MstpCistPortRole_backup_c = 4,

	/* enums for column ieee8021MstpCistPortDisputed */
	ieee8021MstpCistPortDisputed_true_c = 1,
	ieee8021MstpCistPortDisputed_false_c = 2,

	/* enums for column ieee8021MstpCistPortProtocolMigration */
	ieee8021MstpCistPortProtocolMigration_true_c = 1,
	ieee8021MstpCistPortProtocolMigration_false_c = 2,

	/* enums for column ieee8021MstpCistPortEnableBPDURx */
	ieee8021MstpCistPortEnableBPDURx_true_c = 1,
	ieee8021MstpCistPortEnableBPDURx_false_c = 2,

	/* enums for column ieee8021MstpCistPortEnableBPDUTx */
	ieee8021MstpCistPortEnableBPDUTx_true_c = 1,
	ieee8021MstpCistPortEnableBPDUTx_false_c = 2,

	/* enums for column ieee8021MstpCistPortIsL2Gp */
	ieee8021MstpCistPortIsL2Gp_true_c = 1,
	ieee8021MstpCistPortIsL2Gp_false_c = 2,
};

/* table ieee8021MstpCistPortTable row entry data structure */
typedef struct ieee8021MstpCistPortEntry_t
{
	/* Index values */
	uint32_t u32ComponentId;
	uint32_t u32Num;
	
	/* Column values */
	uint32_t u32Uptime;
	int32_t i32AdminPathCost;
	uint8_t au8DesignatedRoot[8];
	size_t u16DesignatedRoot_len;	/* # of uint8_t elements */
	int32_t i32TopologyChangeAck;
	int32_t i32HelloTime;
	int32_t i32AdminEdgePort;
	int32_t i32OperEdgePort;
	int32_t i32MacEnabled;
	int32_t i32MacOperational;
	int32_t i32RestrictedRole;
	int32_t i32RestrictedTcn;
	int32_t i32Role;
	int32_t i32Disputed;
	uint8_t au8CistRegionalRootId[8];
	size_t u16CistRegionalRootId_len;	/* # of uint8_t elements */
	uint32_t u32CistPathCost;
	int32_t i32ProtocolMigration;
	int32_t i32EnableBPDURx;
	int32_t i32EnableBPDUTx;
	uint8_t au8PseudoRootId[8];
	size_t u16PseudoRootId_len;	/* # of uint8_t elements */
	int32_t i32IsL2Gp;
	
	xBTree_Node_t oBTreeNode;
} ieee8021MstpCistPortEntry_t;

extern xBTree_t oIeee8021MstpCistPortTable_BTree;

/* ieee8021MstpCistPortTable table mapper */
void ieee8021MstpCistPortTable_init (void);
ieee8021MstpCistPortEntry_t * ieee8021MstpCistPortTable_createEntry (
	uint32_t u32ComponentId,
	uint32_t u32Num);
ieee8021MstpCistPortEntry_t * ieee8021MstpCistPortTable_getByIndex (
	uint32_t u32ComponentId,
	uint32_t u32Num);
ieee8021MstpCistPortEntry_t * ieee8021MstpCistPortTable_getNextIndex (
	uint32_t u32ComponentId,
	uint32_t u32Num);
void ieee8021MstpCistPortTable_removeEntry (ieee8021MstpCistPortEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021MstpCistPortTable_getFirst;
Netsnmp_Next_Data_Point ieee8021MstpCistPortTable_getNext;
Netsnmp_Get_Data_Point ieee8021MstpCistPortTable_get;
Netsnmp_Node_Handler ieee8021MstpCistPortTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021MstpPortTable definitions
 */
#define IEEE8021MSTPPORTCOMPONENTID 1
#define IEEE8021MSTPPORTMSTID 2
#define IEEE8021MSTPPORTNUM 3
#define IEEE8021MSTPPORTUPTIME 4
#define IEEE8021MSTPPORTSTATE 5
#define IEEE8021MSTPPORTPRIORITY 6
#define IEEE8021MSTPPORTPATHCOST 7
#define IEEE8021MSTPPORTDESIGNATEDROOT 8
#define IEEE8021MSTPPORTDESIGNATEDCOST 9
#define IEEE8021MSTPPORTDESIGNATEDBRIDGE 10
#define IEEE8021MSTPPORTDESIGNATEDPORT 11
#define IEEE8021MSTPPORTROLE 12
#define IEEE8021MSTPPORTDISPUTED 13

enum
{
	/* enums for column ieee8021MstpPortState */
	ieee8021MstpPortState_disabled_c = 1,
	ieee8021MstpPortState_listening_c = 2,
	ieee8021MstpPortState_learning_c = 3,
	ieee8021MstpPortState_forwarding_c = 4,
	ieee8021MstpPortState_blocking_c = 5,

	/* enums for column ieee8021MstpPortRole */
	ieee8021MstpPortRole_root_c = 1,
	ieee8021MstpPortRole_alternate_c = 2,
	ieee8021MstpPortRole_designated_c = 3,
	ieee8021MstpPortRole_backup_c = 4,

	/* enums for column ieee8021MstpPortDisputed */
	ieee8021MstpPortDisputed_true_c = 1,
	ieee8021MstpPortDisputed_false_c = 2,
};

/* table ieee8021MstpPortTable row entry data structure */
typedef struct ieee8021MstpPortEntry_t
{
	/* Index values */
	uint32_t u32ComponentId;
	uint32_t u32MstId;
	uint32_t u32Num;
	
	/* Column values */
	uint32_t u32Uptime;
	int32_t i32State;
	int32_t i32Priority;
	int32_t i32PathCost;
	uint8_t au8DesignatedRoot[8];
	size_t u16DesignatedRoot_len;	/* # of uint8_t elements */
	int32_t i32DesignatedCost;
	uint8_t au8DesignatedBridge[8];
	size_t u16DesignatedBridge_len;	/* # of uint8_t elements */
	uint32_t u32DesignatedPort;
	int32_t i32Role;
	int32_t i32Disputed;
	
	xBTree_Node_t oBTreeNode;
} ieee8021MstpPortEntry_t;

extern xBTree_t oIeee8021MstpPortTable_BTree;

/* ieee8021MstpPortTable table mapper */
void ieee8021MstpPortTable_init (void);
ieee8021MstpPortEntry_t * ieee8021MstpPortTable_createEntry (
	uint32_t u32ComponentId,
	uint32_t u32MstId,
	uint32_t u32Num);
ieee8021MstpPortEntry_t * ieee8021MstpPortTable_getByIndex (
	uint32_t u32ComponentId,
	uint32_t u32MstId,
	uint32_t u32Num);
ieee8021MstpPortEntry_t * ieee8021MstpPortTable_getNextIndex (
	uint32_t u32ComponentId,
	uint32_t u32MstId,
	uint32_t u32Num);
void ieee8021MstpPortTable_removeEntry (ieee8021MstpPortEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021MstpPortTable_getFirst;
Netsnmp_Next_Data_Point ieee8021MstpPortTable_getNext;
Netsnmp_Get_Data_Point ieee8021MstpPortTable_get;
Netsnmp_Node_Handler ieee8021MstpPortTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021MstpConfigIdTable definitions
 */
#define IEEE8021MSTPCONFIGIDCOMPONENTID 1
#define IEEE8021MSTPCONFIGIDFORMATSELECTOR 2
#define IEEE8021MSTPCONFIGURATIONNAME 3
#define IEEE8021MSTPREVISIONLEVEL 4
#define IEEE8021MSTPCONFIGURATIONDIGEST 5

/* table ieee8021MstpConfigIdTable row entry data structure */
typedef struct ieee8021MstpConfigIdEntry_t
{
	/* Index values */
	uint32_t u32ComponentId;
	
	/* Column values */
	int32_t i32FormatSelector;
	uint8_t au8ConfigurationName[32];
	size_t u16ConfigurationName_len;	/* # of uint8_t elements */
	uint32_t u32RevisionLevel;
	uint8_t au8ConfigurationDigest[16];
	size_t u16ConfigurationDigest_len;	/* # of uint8_t elements */
	
	xBTree_Node_t oBTreeNode;
} ieee8021MstpConfigIdEntry_t;

extern xBTree_t oIeee8021MstpConfigIdTable_BTree;

/* ieee8021MstpConfigIdTable table mapper */
void ieee8021MstpConfigIdTable_init (void);
ieee8021MstpConfigIdEntry_t * ieee8021MstpConfigIdTable_createEntry (
	uint32_t u32ComponentId);
ieee8021MstpConfigIdEntry_t * ieee8021MstpConfigIdTable_getByIndex (
	uint32_t u32ComponentId);
ieee8021MstpConfigIdEntry_t * ieee8021MstpConfigIdTable_getNextIndex (
	uint32_t u32ComponentId);
void ieee8021MstpConfigIdTable_removeEntry (ieee8021MstpConfigIdEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021MstpConfigIdTable_getFirst;
Netsnmp_Next_Data_Point ieee8021MstpConfigIdTable_getNext;
Netsnmp_Get_Data_Point ieee8021MstpConfigIdTable_get;
Netsnmp_Node_Handler ieee8021MstpConfigIdTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021MstpCistPortExtensionTable definitions
 */
#define IEEE8021MSTPCISTPORTAUTOEDGEPORT 1
#define IEEE8021MSTPCISTPORTAUTOISOLATEPORT 2

enum
{
	/* enums for column ieee8021MstpCistPortAutoEdgePort */
	ieee8021MstpCistPortAutoEdgePort_true_c = 1,
	ieee8021MstpCistPortAutoEdgePort_false_c = 2,

	/* enums for column ieee8021MstpCistPortAutoIsolatePort */
	ieee8021MstpCistPortAutoIsolatePort_true_c = 1,
	ieee8021MstpCistPortAutoIsolatePort_false_c = 2,
};

/* table ieee8021MstpCistPortExtensionTable row entry data structure */
typedef struct ieee8021MstpCistPortExtensionEntry_t
{
	/* Index values */
	uint32_t u32ComponentId;
	uint32_t u32Num;
	
	/* Column values */
	int32_t i32AutoEdgePort;
	int32_t i32AutoIsolatePort;
	
	xBTree_Node_t oBTreeNode;
} ieee8021MstpCistPortExtensionEntry_t;

extern xBTree_t oIeee8021MstpCistPortExtensionTable_BTree;

/* ieee8021MstpCistPortExtensionTable table mapper */
void ieee8021MstpCistPortExtensionTable_init (void);
ieee8021MstpCistPortExtensionEntry_t * ieee8021MstpCistPortExtensionTable_createEntry (
	uint32_t u32ComponentId,
	uint32_t u32Num);
ieee8021MstpCistPortExtensionEntry_t * ieee8021MstpCistPortExtensionTable_getByIndex (
	uint32_t u32ComponentId,
	uint32_t u32Num);
ieee8021MstpCistPortExtensionEntry_t * ieee8021MstpCistPortExtensionTable_getNextIndex (
	uint32_t u32ComponentId,
	uint32_t u32Num);
void ieee8021MstpCistPortExtensionTable_removeEntry (ieee8021MstpCistPortExtensionEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021MstpCistPortExtensionTable_getFirst;
Netsnmp_Next_Data_Point ieee8021MstpCistPortExtensionTable_getNext;
Netsnmp_Get_Data_Point ieee8021MstpCistPortExtensionTable_get;
Netsnmp_Node_Handler ieee8021MstpCistPortExtensionTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021MstpFidToMstiV2Table definitions
 */
#define IEEE8021MSTPFIDTOMSTIV2COMPONENTID 1
#define IEEE8021MSTPFIDTOMSTIV2FID 2
#define IEEE8021MSTPFIDTOMSTIV2MSTID 3

/* table ieee8021MstpFidToMstiV2Table row entry data structure */
typedef struct ieee8021MstpFidToMstiV2Entry_t
{
	/* Index values */
	uint32_t u32ComponentId;
	uint32_t u32Fid;
	
	/* Column values */
	uint32_t u32MstId;
	
	xBTree_Node_t oBTreeNode;
} ieee8021MstpFidToMstiV2Entry_t;

extern xBTree_t oIeee8021MstpFidToMstiV2Table_BTree;

/* ieee8021MstpFidToMstiV2Table table mapper */
void ieee8021MstpFidToMstiV2Table_init (void);
ieee8021MstpFidToMstiV2Entry_t * ieee8021MstpFidToMstiV2Table_createEntry (
	uint32_t u32ComponentId,
	uint32_t u32Fid);
ieee8021MstpFidToMstiV2Entry_t * ieee8021MstpFidToMstiV2Table_getByIndex (
	uint32_t u32ComponentId,
	uint32_t u32Fid);
ieee8021MstpFidToMstiV2Entry_t * ieee8021MstpFidToMstiV2Table_getNextIndex (
	uint32_t u32ComponentId,
	uint32_t u32Fid);
void ieee8021MstpFidToMstiV2Table_removeEntry (ieee8021MstpFidToMstiV2Entry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021MstpFidToMstiV2Table_getFirst;
Netsnmp_Next_Data_Point ieee8021MstpFidToMstiV2Table_getNext;
Netsnmp_Get_Data_Point ieee8021MstpFidToMstiV2Table_get;
Netsnmp_Node_Handler ieee8021MstpFidToMstiV2Table_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021MstpVlanV2Table definitions
 */
#define IEEE8021MSTPVLANV2COMPONENTID 1
#define IEEE8021MSTPVLANV2ID 2
#define IEEE8021MSTPVLANV2MSTID 3

/* table ieee8021MstpVlanV2Table row entry data structure */
typedef struct ieee8021MstpVlanV2Entry_t
{
	/* Index values */
	uint32_t u32ComponentId;
	uint32_t u32Id;
	
	/* Column values */
	uint32_t u32MstId;
	
	xBTree_Node_t oBTreeNode;
} ieee8021MstpVlanV2Entry_t;

extern xBTree_t oIeee8021MstpVlanV2Table_BTree;

/* ieee8021MstpVlanV2Table table mapper */
void ieee8021MstpVlanV2Table_init (void);
ieee8021MstpVlanV2Entry_t * ieee8021MstpVlanV2Table_createEntry (
	uint32_t u32ComponentId,
	uint32_t u32Id);
ieee8021MstpVlanV2Entry_t * ieee8021MstpVlanV2Table_getByIndex (
	uint32_t u32ComponentId,
	uint32_t u32Id);
ieee8021MstpVlanV2Entry_t * ieee8021MstpVlanV2Table_getNextIndex (
	uint32_t u32ComponentId,
	uint32_t u32Id);
void ieee8021MstpVlanV2Table_removeEntry (ieee8021MstpVlanV2Entry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021MstpVlanV2Table_getFirst;
Netsnmp_Next_Data_Point ieee8021MstpVlanV2Table_getNext;
Netsnmp_Get_Data_Point ieee8021MstpVlanV2Table_get;
Netsnmp_Node_Handler ieee8021MstpVlanV2Table_mapper;
#endif	/* SNMP_SRC */



#	ifdef __cplusplus
}
#	endif

#endif /* __IEEE8021MSTPMIB_H__ */
