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

#ifndef __IEEE8021SPANNINGTREEMIB_H__
#	define __IEEE8021SPANNINGTREEMIB_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include "ieee8021MstpMib.h"
#include "neIeee8021StpMIB.h"

#include "lib/binaryTree.h"
#include "lib/snmp.h"

#include <stdbool.h>
#include <stdint.h>

#define TOBE_REPLACED 1


/**
 *	agent MIB function
 */
void ieee8021SpanningTreeMib_init (void);


/**
 *	table mapper(s)
 */
/**
 *	table ieee8021SpanningTreeTable definitions
 */
#define IEEE8021SPANNINGTREECOMPONENTID 1
#define IEEE8021SPANNINGTREEPROTOCOLSPECIFICATION 2
#define IEEE8021SPANNINGTREEPRIORITY 3
#define IEEE8021SPANNINGTREETIMESINCETOPOLOGYCHANGE 4
#define IEEE8021SPANNINGTREETOPCHANGES 5
#define IEEE8021SPANNINGTREEDESIGNATEDROOT 6
#define IEEE8021SPANNINGTREEROOTCOST 7
#define IEEE8021SPANNINGTREEROOTPORT 8
#define IEEE8021SPANNINGTREEMAXAGE 9
#define IEEE8021SPANNINGTREEHELLOTIME 10
#define IEEE8021SPANNINGTREEHOLDTIME 11
#define IEEE8021SPANNINGTREEFORWARDDELAY 12
#define IEEE8021SPANNINGTREEBRIDGEMAXAGE 13
#define IEEE8021SPANNINGTREEBRIDGEHELLOTIME 14
#define IEEE8021SPANNINGTREEBRIDGEFORWARDDELAY 15
#define IEEE8021SPANNINGTREEVERSION 16
#define IEEE8021SPANNINGTREERSTPTXHOLDCOUNT 17

enum
{
	/* enums for column ieee8021SpanningTreeProtocolSpecification */
	ieee8021SpanningTreeProtocolSpecification_unknown_c = 1,
	ieee8021SpanningTreeProtocolSpecification_decLb100_c = 2,
	ieee8021SpanningTreeProtocolSpecification_ieee8021d_c = 3,
	ieee8021SpanningTreeProtocolSpecification_ieee8021q_c = 4,

	/* enums for column ieee8021SpanningTreeVersion */
	ieee8021SpanningTreeVersion_stp_c = 0,
	ieee8021SpanningTreeVersion_rstp_c = 2,
	ieee8021SpanningTreeVersion_mstp_c = 3,
	ieee8021SpanningTreeVersion_spb_c = 4,
};

/* table ieee8021SpanningTreeTable row entry data structure */
typedef struct ieee8021SpanningTreeEntry_t
{
	/* Index values */
	uint32_t u32ComponentId;
	
	/* Column values */
	int32_t i32ProtocolSpecification;
	int32_t i32Priority;
	uint32_t u32TimeSinceTopologyChange;
	uint64_t u64TopChanges;
	uint8_t au8DesignatedRoot[8];
	size_t u16DesignatedRoot_len;	/* # of uint8_t elements */
	int32_t i32RootCost;
	uint32_t u32RootPort;
	int32_t i32MaxAge;
	int32_t i32HelloTime;
	int32_t i32HoldTime;
	int32_t i32ForwardDelay;
	int32_t i32BridgeMaxAge;
	int32_t i32BridgeHelloTime;
	int32_t i32BridgeForwardDelay;
	int32_t i32Version;
	int32_t i32RstpTxHoldCount;
	
	uint8_t u8RowStatus;
	struct ieee8021SpanningTreeEntry_t *pOldEntry;
	
	xBTree_Node_t oBTreeNode;
} ieee8021SpanningTreeEntry_t;

extern xBTree_t oIeee8021SpanningTreeTable_BTree;

/* ieee8021SpanningTreeTable table mapper */
void ieee8021SpanningTreeTable_init (void);
ieee8021SpanningTreeEntry_t * ieee8021SpanningTreeTable_createEntry (
	uint32_t u32ComponentId);
ieee8021SpanningTreeEntry_t * ieee8021SpanningTreeTable_getByIndex (
	uint32_t u32ComponentId);
ieee8021SpanningTreeEntry_t * ieee8021SpanningTreeTable_getNextIndex (
	uint32_t u32ComponentId);
void ieee8021SpanningTreeTable_removeEntry (ieee8021SpanningTreeEntry_t *poEntry);
bool ieee8021StpRowStatus_handler (
	ieee8021SpanningTreeEntry_t *poEntry, uint8_t u8RowStatus);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021SpanningTreeTable_getFirst;
Netsnmp_Next_Data_Point ieee8021SpanningTreeTable_getNext;
Netsnmp_Get_Data_Point ieee8021SpanningTreeTable_get;
Netsnmp_Node_Handler ieee8021SpanningTreeTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021SpanningTreePortExtensionTable definitions
 */
#define IEEE8021SPANNINGTREEPORTRSTPAUTOEDGEPORT 1
#define IEEE8021SPANNINGTREEPORTRSTPAUTOISOLATEPORT 2
#define IEEE8021SPANNINGTREEPORTRSTPISOLATEPORT 3

enum
{
	/* enums for column ieee8021SpanningTreePortRstpAutoEdgePort */
	ieee8021SpanningTreePortRstpAutoEdgePort_true_c = 1,
	ieee8021SpanningTreePortRstpAutoEdgePort_false_c = 2,

	/* enums for column ieee8021SpanningTreePortRstpAutoIsolatePort */
	ieee8021SpanningTreePortRstpAutoIsolatePort_true_c = 1,
	ieee8021SpanningTreePortRstpAutoIsolatePort_false_c = 2,

	/* enums for column ieee8021SpanningTreePortRstpIsolatePort */
	ieee8021SpanningTreePortRstpIsolatePort_true_c = 1,
	ieee8021SpanningTreePortRstpIsolatePort_false_c = 2,
};

/* table ieee8021SpanningTreePortExtensionTable row entry data structure */
typedef struct ieee8021SpanningTreePortExtensionEntry_t
{
	/* Index values */
	uint32_t u32ComponentId;
	uint32_t u32Port;
	
	/* Column values */
	uint8_t u8AutoEdgePort;
	uint8_t u8AutoIsolatePort;
	uint8_t u8IsolatePort;
	
	xBTree_Node_t oBTreeNode;
} ieee8021SpanningTreePortExtensionEntry_t;

extern xBTree_t oIeee8021SpanningTreePortExtensionTable_BTree;

/* ieee8021SpanningTreePortExtensionTable table mapper */
void ieee8021SpanningTreePortExtensionTable_init (void);
ieee8021SpanningTreePortExtensionEntry_t * ieee8021SpanningTreePortExtensionTable_createEntry (
	uint32_t u32ComponentId,
	uint32_t u32Port);
ieee8021SpanningTreePortExtensionEntry_t * ieee8021SpanningTreePortExtensionTable_getByIndex (
	uint32_t u32ComponentId,
	uint32_t u32Port);
ieee8021SpanningTreePortExtensionEntry_t * ieee8021SpanningTreePortExtensionTable_getNextIndex (
	uint32_t u32ComponentId,
	uint32_t u32Port);
void ieee8021SpanningTreePortExtensionTable_removeEntry (ieee8021SpanningTreePortExtensionEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021SpanningTreePortExtensionTable_getFirst;
Netsnmp_Next_Data_Point ieee8021SpanningTreePortExtensionTable_getNext;
Netsnmp_Get_Data_Point ieee8021SpanningTreePortExtensionTable_get;
Netsnmp_Node_Handler ieee8021SpanningTreePortExtensionTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021SpanningTreePortTable definitions
 */
#define IEEE8021SPANNINGTREEPORTCOMPONENTID 1
#define IEEE8021SPANNINGTREEPORT 2
#define IEEE8021SPANNINGTREEPORTPRIORITY 3
#define IEEE8021SPANNINGTREEPORTSTATE 4
#define IEEE8021SPANNINGTREEPORTENABLED 5
#define IEEE8021SPANNINGTREEPORTPATHCOST 6
#define IEEE8021SPANNINGTREEPORTDESIGNATEDROOT 7
#define IEEE8021SPANNINGTREEPORTDESIGNATEDCOST 8
#define IEEE8021SPANNINGTREEPORTDESIGNATEDBRIDGE 9
#define IEEE8021SPANNINGTREEPORTDESIGNATEDPORT 10
#define IEEE8021SPANNINGTREEPORTFORWARDTRANSITIONS 11
#define IEEE8021SPANNINGTREEPORTRSTPPROTOCOLMIGRATION 12
#define IEEE8021SPANNINGTREEPORTRSTPADMINEDGEPORT 13
#define IEEE8021SPANNINGTREEPORTRSTPOPEREDGEPORT 14
#define IEEE8021SPANNINGTREEPORTRSTPADMINPATHCOST 15

enum
{
	/* enums for column ieee8021SpanningTreePortState */
	ieee8021SpanningTreePortState_disabled_c = 1,
	ieee8021SpanningTreePortState_blocking_c = 2,
	ieee8021SpanningTreePortState_listening_c = 3,
	ieee8021SpanningTreePortState_learning_c = 4,
	ieee8021SpanningTreePortState_forwarding_c = 5,
	ieee8021SpanningTreePortState_broken_c = 6,

	/* enums for column ieee8021SpanningTreePortEnabled */
	ieee8021SpanningTreePortEnabled_true_c = 1,
	ieee8021SpanningTreePortEnabled_false_c = 2,

	/* enums for column ieee8021SpanningTreePortRstpProtocolMigration */
	ieee8021SpanningTreePortRstpProtocolMigration_true_c = 1,
	ieee8021SpanningTreePortRstpProtocolMigration_false_c = 2,

	/* enums for column ieee8021SpanningTreePortRstpAdminEdgePort */
	ieee8021SpanningTreePortRstpAdminEdgePort_true_c = 1,
	ieee8021SpanningTreePortRstpAdminEdgePort_false_c = 2,

	/* enums for column ieee8021SpanningTreePortRstpOperEdgePort */
	ieee8021SpanningTreePortRstpOperEdgePort_true_c = 1,
	ieee8021SpanningTreePortRstpOperEdgePort_false_c = 2,
};

/* table ieee8021SpanningTreePortTable row entry data structure */
typedef struct ieee8021SpanningTreePortEntry_t
{
	/* Index values */
	uint32_t u32ComponentId;
	uint32_t u32Port;
	
	/* Column values */
	int32_t i32Priority;
	int32_t i32State;
	uint8_t u8Enabled;
	int32_t i32PathCost;
	uint8_t au8DesignatedRoot[8];
	size_t u16DesignatedRoot_len;	/* # of uint8_t elements */
	int32_t i32DesignatedCost;
	uint8_t au8DesignatedBridge[8];
	size_t u16DesignatedBridge_len;	/* # of uint8_t elements */
	uint8_t au8DesignatedPort[2];
	size_t u16DesignatedPort_len;	/* # of uint8_t elements */
	uint64_t u64ForwardTransitions;
	uint8_t u8RstpProtocolMigration;
	uint8_t u8RstpAdminEdgePort;
	uint8_t u8RstpOperEdgePort;
	int32_t i32RstpAdminPathCost;
	
	ieee8021SpanningTreePortExtensionEntry_t oExtension;
	ieee8021MstpCistPortEntry_t oCist;
	
	uint8_t u8AdminStatus;
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} ieee8021SpanningTreePortEntry_t;

extern xBTree_t oIeee8021SpanningTreePortTable_BTree;

/* ieee8021SpanningTreePortTable table mapper */
void ieee8021SpanningTreePortTable_init (void);
ieee8021SpanningTreePortEntry_t * ieee8021SpanningTreePortTable_createEntry (
	uint32_t u32ComponentId,
	uint32_t u32Port);
ieee8021SpanningTreePortEntry_t * ieee8021SpanningTreePortTable_getByIndex (
	uint32_t u32ComponentId,
	uint32_t u32Port);
ieee8021SpanningTreePortEntry_t * ieee8021SpanningTreePortTable_getNextIndex (
	uint32_t u32ComponentId,
	uint32_t u32Port);
void ieee8021SpanningTreePortTable_removeEntry (ieee8021SpanningTreePortEntry_t *poEntry);
bool ieee8021StpPortRowStatus_handler (
	ieee8021SpanningTreePortEntry_t *poEntry, uint8_t u8RowStatus);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021SpanningTreePortTable_getFirst;
Netsnmp_Next_Data_Point ieee8021SpanningTreePortTable_getNext;
Netsnmp_Get_Data_Point ieee8021SpanningTreePortTable_get;
Netsnmp_Node_Handler ieee8021SpanningTreePortTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	notification mapper(s)
 */
/* definitions for notification(s) of ieee8021SpanningTreeNotifications */
#	define IEEE8021SPANNINGTREENEWROOT 1
#	define IEEE8021SPANNINGTREETOPOLOGYCHANGE 2

/* ieee8021SpanningTreeNotifications mapper(s) */
int ieee8021SpanningTreeNewRoot_trap (void);
int ieee8021SpanningTreeTopologyChange_trap (void);



#	ifdef __cplusplus
}
#	endif

#endif /* __IEEE8021SPANNINGTREEMIB_H__ */
