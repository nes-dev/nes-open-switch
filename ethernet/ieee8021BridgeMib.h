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

#ifndef __IEEE8021BRIDGEMIB_H__
#	define __IEEE8021BRIDGEMIB_H__

#	ifdef __cplusplus
extern "C" {
#	endif



struct ieee8021BridgeBaseEntry_t;
typedef struct ieee8021BridgeBaseEntry_t ieee8021BridgeBaseEntry_t;

struct ieee8021BridgeBasePortEntry_t;
typedef struct ieee8021BridgeBasePortEntry_t ieee8021BridgeBasePortEntry_t;

#include "neIeee8021BridgeMIB.h"
#include "ieee8021QBridgeMib.h"
#include "ethernet_ext.h"

#include "lib/freeRange.h"
#include "lib/binaryTree.h"
#include "lib/sync.h"
#include "lib/snmp.h"

#include <stdbool.h>

#define TOBE_REPLACED 1


/**
 *	agent MIB function
 */
void ieee8021BridgeMib_init (void);


typedef struct ieee8021Bridge_t
{
	xFreeRange_t oComponent_FreeRange;
	
	xRwLock_t oComponentLock;
	xRwLock_t oPhyPortLock;
} ieee8021Bridge_t;

extern ieee8021Bridge_t oBridge;

#define ieee8021Bridge_wrLock() (xRwLock_wrLock (&oBridge.oComponentLock))
#define ieee8021Bridge_rdLock() (xRwLock_rdLock (&oBridge.oComponentLock))
#define ieee8021Bridge_unLock() (xRwLock_unlock (&oBridge.oComponentLock))


/**
 *	table mapper(s)
 */
/**
 *	table ieee8021BridgeBaseTable definitions
 */
#define IEEE8021BRIDGEBASECOMPONENTID 1
#define IEEE8021BRIDGEBASEBRIDGEADDRESS 2
#define IEEE8021BRIDGEBASENUMPORTS 3
#define IEEE8021BRIDGEBASECOMPONENTTYPE 4
#define IEEE8021BRIDGEBASEDEVICECAPABILITIES 5
#define IEEE8021BRIDGEBASETRAFFICCLASSESENABLED 6
#define IEEE8021BRIDGEBASEMMRPENABLEDSTATUS 7
#define IEEE8021BRIDGEBASEROWSTATUS 8

enum
{
	ieee8021BridgeBaseComponent_zero_c = 0,
	ieee8021BridgeBaseComponent_start_c = 1,
	ieee8021BridgeBaseComponent_end_c = 0xFFFFFFFF,

	/* enums for column ieee8021BridgeBaseComponentType */
	ieee8021BridgeBaseComponentType_iComponent_c = 1,
	ieee8021BridgeBaseComponentType_bComponent_c = 2,
	ieee8021BridgeBaseComponentType_cVlanComponent_c = 3,
	ieee8021BridgeBaseComponentType_sVlanComponent_c = 4,
	ieee8021BridgeBaseComponentType_dBridgeComponent_c = 5,
	ieee8021BridgeBaseComponentType_erComponent_c = 6,
	ieee8021BridgeBaseComponentType_tComponent_c = 7,

	/* enums for column ieee8021BridgeBaseDeviceCapabilities */
	ieee8021BridgeBaseDeviceCapabilities_dot1dExtendedFilteringServices_c = 0,
	ieee8021BridgeBaseDeviceCapabilities_dot1dTrafficClasses_c = 1,
	ieee8021BridgeBaseDeviceCapabilities_dot1qStaticEntryIndividualPort_c = 2,
	ieee8021BridgeBaseDeviceCapabilities_dot1qIVLCapable_c = 3,
	ieee8021BridgeBaseDeviceCapabilities_dot1qSVLCapable_c = 4,
	ieee8021BridgeBaseDeviceCapabilities_dot1qHybridCapable_c = 5,
	ieee8021BridgeBaseDeviceCapabilities_dot1qConfigurablePvidTagging_c = 6,
	ieee8021BridgeBaseDeviceCapabilities_dot1dLocalVlanCapable_c = 7,

	/* enums for column ieee8021BridgeBaseTrafficClassesEnabled */
	ieee8021BridgeBaseTrafficClassesEnabled_true_c = 1,
	ieee8021BridgeBaseTrafficClassesEnabled_false_c = 2,

	/* enums for column ieee8021BridgeBaseMmrpEnabledStatus */
	ieee8021BridgeBaseMmrpEnabledStatus_true_c = 1,
	ieee8021BridgeBaseMmrpEnabledStatus_false_c = 2,

	/* enums for column ieee8021BridgeBaseRowStatus */
	ieee8021BridgeBaseRowStatus_active_c = 1,
	ieee8021BridgeBaseRowStatus_notInService_c = 2,
	ieee8021BridgeBaseRowStatus_notReady_c = 3,
	ieee8021BridgeBaseRowStatus_createAndGo_c = 4,
	ieee8021BridgeBaseRowStatus_createAndWait_c = 5,
	ieee8021BridgeBaseRowStatus_destroy_c = 6,
};

/* table ieee8021BridgeBaseTable row entry data structure */
/*typedef*/ struct ieee8021BridgeBaseEntry_t
{
	/* Index values */
	uint32_t u32ComponentId;
	
	/* Column values */
	uint8_t au8BridgeAddress[6];
	size_t u16BridgeAddress_len;	/* # of uint8_t elements */
	int32_t i32NumPorts;
	int32_t i32ComponentType;
	uint8_t au8DeviceCapabilities[1];
	size_t u16DeviceCapabilities_len;	/* # of uint8_t elements */
	uint8_t u8TrafficClassesEnabled;
	uint8_t u8MmrpEnabledStatus;
	uint8_t u8RowStatus;
	
	neIeee8021BridgeBaseEntry_t oNe;
	ieee8021QBridgeEntry_t oQ;
	ieee8021QBridgeNextFreeLocalVlanEntry_t oNextFreeLocalVlan;
	ieee8021QBridgeLearningConstraintDefaultsEntry_t oLearningConstraintDefaults;
	
	uint32_t u32ChassisId;
	uint32_t u32NumTpPorts;
	xFreeRange_t oPort_FreeRange;
	
	xBTree_Node_t oBTreeNode;
	xBTree_Node_t oChassis_BTreeNode;
	xRwLock_t oLock;
} /*ieee8021BridgeBaseEntry_t*/;

extern xBTree_t oIeee8021BridgeBaseTable_BTree;
extern xBTree_t oIeee8021BridgeBaseTable_Chassis_BTree;

#define ieee8021BridgeBase_wrLock(poEntry) (xRwLock_wrLock (&(poEntry)->oLock))
#define ieee8021BridgeBase_rdLock(poEntry) (xRwLock_rdLock (&(poEntry)->oLock))
#define ieee8021BridgeBase_unLock(poEntry) (xRwLock_unlock (&(poEntry)->oLock))

/* ieee8021BridgeBaseTable table mapper */
void ieee8021BridgeBaseTable_init (void);
ieee8021BridgeBaseEntry_t * ieee8021BridgeBaseTable_createEntry (
	uint32_t u32ComponentId);
ieee8021BridgeBaseEntry_t * ieee8021BridgeBaseTable_getByIndex (
	uint32_t u32ComponentId);
ieee8021BridgeBaseEntry_t * ieee8021BridgeBaseTable_getNextIndex (
	uint32_t u32ComponentId);
ieee8021BridgeBaseEntry_t * ieee8021BridgeBaseTable_Chassis_getNextIndex (
	uint32_t u32ChassisId,
	uint32_t u32ComponentId);
#define ieee8021BridgeBaseTable_getByNeEntry(poEntry) ((poEntry) == NULL ? NULL: xGetParentByMemberPtr ((poEntry), ieee8021BridgeBaseEntry_t, oNe))
#define ieee8021BridgeBaseTable_getByQEntry(poEntry) ((poEntry) == NULL ? NULL: xGetParentByMemberPtr ((poEntry), ieee8021BridgeBaseEntry_t, oQ))
#define ieee8021BridgeBaseTable_getByNextFreeLocalVlanEntry(poEntry) ((poEntry) == NULL ? NULL: xGetParentByMemberPtr ((poEntry), ieee8021BridgeBaseEntry_t, oNextFreeLocalVlan))
#define ieee8021BridgeBaseTable_getByLearningConstraintDefaultsEntry(poEntry) ((poEntry) == NULL ? NULL: xGetParentByMemberPtr ((poEntry), ieee8021BridgeBaseEntry_t, oLearningConstraintDefaults))
void ieee8021BridgeBaseTable_removeEntry (ieee8021BridgeBaseEntry_t *poEntry);
ieee8021BridgeBaseEntry_t * ieee8021BridgeBaseTable_createExt (
	uint32_t u32ComponentId);
bool ieee8021BridgeBaseTable_removeExt (ieee8021BridgeBaseEntry_t *poEntry);
bool ieee8021BridgeBaseTable_createHier (ieee8021BridgeBaseEntry_t *poEntry);
bool ieee8021BridgeBaseTable_removeHier (ieee8021BridgeBaseEntry_t *poEntry);
bool ieee8021BridgeBaseEntry_init (ieee8021BridgeBaseEntry_t *poEntry);
bool ieee8021BridgeBaseTrafficClassesEnabled_handler (
	ieee8021BridgeBaseEntry_t *poEntry, uint8_t u8TrafficClassesEnabled, bool bForce);
bool ieee8021BridgeBaseMmrpEnabledStatus_handler (
	ieee8021BridgeBaseEntry_t *poEntry, uint8_t u8MmrpEnabledStatus, bool bForce);
bool ieee8021BridgeBaseRowStatus_handler (
	ieee8021BridgeBaseEntry_t *poEntry, uint8_t u8RowStatus);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021BridgeBaseTable_getFirst;
Netsnmp_Next_Data_Point ieee8021BridgeBaseTable_getNext;
Netsnmp_Get_Data_Point ieee8021BridgeBaseTable_get;
Netsnmp_Node_Handler ieee8021BridgeBaseTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021BridgeBasePortTable definitions
 */
#define IEEE8021BRIDGEBASEPORTCOMPONENTID 1
#define IEEE8021BRIDGEBASEPORT 2
#define IEEE8021BRIDGEBASEPORTIFINDEX 3
#define IEEE8021BRIDGEBASEPORTDELAYEXCEEDEDDISCARDS 4
#define IEEE8021BRIDGEBASEPORTMTUEXCEEDEDDISCARDS 5
#define IEEE8021BRIDGEBASEPORTCAPABILITIES 6
#define IEEE8021BRIDGEBASEPORTTYPECAPABILITIES 7
#define IEEE8021BRIDGEBASEPORTTYPE 8
#define IEEE8021BRIDGEBASEPORTEXTERNAL 9
#define IEEE8021BRIDGEBASEPORTADMINPOINTTOPOINT 10
#define IEEE8021BRIDGEBASEPORTOPERPOINTTOPOINT 11
#define IEEE8021BRIDGEBASEPORTNAME 12

enum
{
	ieee8021BridgeBasePort_zero_c = 0,
	ieee8021BridgeBasePort_start_c = 1,
	ieee8021BridgeBasePort_end_c = 0xFFFFFFFF,
	
	/* enums for column ieee8021BridgeBasePortCapabilities */
	ieee8021BridgeBasePortCapabilities_dot1qDot1qTagging_c = 0,
	ieee8021BridgeBasePortCapabilities_dot1qConfigurableAcceptableFrameTypes_c = 1,
	ieee8021BridgeBasePortCapabilities_dot1qIngressFiltering_c = 2,

	/* enums for column ieee8021BridgeBasePortTypeCapabilities */
	ieee8021BridgeBasePortTypeCapabilities_customerVlanPort_c = 0,
	ieee8021BridgeBasePortTypeCapabilities_providerNetworkPort_c = 1,
	ieee8021BridgeBasePortTypeCapabilities_customerNetworkPort_c = 2,
	ieee8021BridgeBasePortTypeCapabilities_customerEdgePort_c = 3,
	ieee8021BridgeBasePortTypeCapabilities_customerBackbonePort_c = 4,
	ieee8021BridgeBasePortTypeCapabilities_virtualInstancePort_c = 5,
	ieee8021BridgeBasePortTypeCapabilities_dBridgePort_c = 6,
	ieee8021BridgeBasePortTypeCapabilities_remoteCustomerAccessPort_c = 7,
	ieee8021BridgeBasePortTypeCapabilities_stationFacingBridgePort_c = 8,
	ieee8021BridgeBasePortTypeCapabilities_uplinkAccessPort_c = 9,
	ieee8021BridgeBasePortTypeCapabilities_uplinkRelayPort_c = 10,
	ieee8021BridgeBasePortTypeCapabilities_providerEdgePort_c = 11,
	ieee8021BridgeBasePortTypeCapabilities_providerInstancePort_c = 12,

	/* enums for column ieee8021BridgeBasePortType */
	ieee8021BridgeBasePortType_none_c = 1,
	ieee8021BridgeBasePortType_customerVlanPort_c = 2,
	ieee8021BridgeBasePortType_providerNetworkPort_c = 3,
	ieee8021BridgeBasePortType_customerNetworkPort_c = 4,
	ieee8021BridgeBasePortType_customerEdgePort_c = 5,
	ieee8021BridgeBasePortType_customerBackbonePort_c = 6,
	ieee8021BridgeBasePortType_virtualInstancePort_c = 7,
	ieee8021BridgeBasePortType_dBridgePort_c = 8,
	ieee8021BridgeBasePortType_remoteCustomerAccessPort_c = 9,
	ieee8021BridgeBasePortType_stationFacingBridgePort_c = 10,
	ieee8021BridgeBasePortType_uplinkAccessPort_c = 11,
	ieee8021BridgeBasePortType_uplinkRelayPort_c = 12,
	ieee8021BridgeBasePortType_providerEdgePort_c = 13,
	ieee8021BridgeBasePortType_providerInstancePort_c = 14,
	ieee8021BridgeBasePortType_min_c = ieee8021BridgeBasePortType_customerVlanPort_c,
	ieee8021BridgeBasePortType_max_c = ieee8021BridgeBasePortType_providerInstancePort_c,

	/* enums for column ieee8021BridgeBasePortExternal */
	ieee8021BridgeBasePortExternal_true_c = 1,
	ieee8021BridgeBasePortExternal_false_c = 2,

	/* enums for column ieee8021BridgeBasePortAdminPointToPoint */
	ieee8021BridgeBasePortAdminPointToPoint_forceTrue_c = 1,
	ieee8021BridgeBasePortAdminPointToPoint_forceFalse_c = 2,
	ieee8021BridgeBasePortAdminPointToPoint_auto_c = 3,

	/* enums for column ieee8021BridgeBasePortOperPointToPoint */
	ieee8021BridgeBasePortOperPointToPoint_true_c = 1,
	ieee8021BridgeBasePortOperPointToPoint_false_c = 2,
};

extern xBTree_t oIeee8021BridgeBasePortTable_BTree;

/* ieee8021BridgeBasePortTable table mapper */
void ieee8021BridgeBasePortTable_init (void);
ieee8021BridgeBasePortEntry_t * ieee8021BridgeBasePortTable_createEntry (
	uint32_t u32ComponentId,
	uint32_t u32Port);
ieee8021BridgeBasePortEntry_t * ieee8021BridgeBasePortTable_getByIndex (
	uint32_t u32ComponentId,
	uint32_t u32Port);
ieee8021BridgeBasePortEntry_t * ieee8021BridgeBasePortTable_getNextIndex (
	uint32_t u32ComponentId,
	uint32_t u32Port);
#define ieee8021BridgeBasePortTable_getByNeEntry(poEntry) ((poEntry) == NULL ? NULL: xGetParentByMemberPtr ((poEntry), ieee8021BridgeBasePortEntry_t, oNe))
#define ieee8021BridgeBasePortTable_getByPriorityEntry(poEntry) ((poEntry) == NULL ? NULL: xGetParentByMemberPtr ((poEntry), ieee8021BridgeBasePortEntry_t, oPriority))
void ieee8021BridgeBasePortTable_removeEntry (ieee8021BridgeBasePortEntry_t *poEntry);
bool ieee8021BridgeBasePortTable_allocateIndex (
	ieee8021BridgeBaseEntry_t *poComponent,
	uint32_t *pu32Port);
bool ieee8021BridgeBasePortTable_removeIndex (
	ieee8021BridgeBaseEntry_t *poComponent,
	uint32_t u32Port);
ieee8021BridgeBasePortEntry_t *ieee8021BridgeBasePortTable_createExt (
	ieee8021BridgeBaseEntry_t *poComponent,
	uint32_t u32Port);
bool ieee8021BridgeBasePortTable_removeExt (ieee8021BridgeBaseEntry_t *poComponent, ieee8021BridgeBasePortEntry_t *poEntry);
bool ieee8021BridgeBasePortTable_createHier (ieee8021BridgeBaseEntry_t *poComponent, ieee8021BridgeBasePortEntry_t *poEntry);
bool ieee8021BridgeBasePortTable_removeHier (ieee8021BridgeBaseEntry_t *poComponent, ieee8021BridgeBasePortEntry_t *poEntry);
bool ieee8021BridgeBasePortIfIndex_handler (
	ieee8021BridgeBaseEntry_t *poComponent,
	ieee8021BridgeBasePortEntry_t *poEntry);
bool ieee8021BridgeBasePortRowStatus_handler (
	ieee8021BridgeBaseEntry_t *poComponent,
	ieee8021BridgeBasePortEntry_t *poEntry, uint8_t u8RowStatus);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021BridgeBasePortTable_getFirst;
Netsnmp_Next_Data_Point ieee8021BridgeBasePortTable_getNext;
Netsnmp_Get_Data_Point ieee8021BridgeBasePortTable_get;
Netsnmp_Node_Handler ieee8021BridgeBasePortTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021BridgeBaseIfToPortTable definitions
 */
#define IEEE8021BRIDGEBASEIFINDEXCOMPONENTID 1
#define IEEE8021BRIDGEBASEIFINDEXPORT 2

/* table ieee8021BridgeBaseIfToPortTable row entry data structure */
typedef struct ieee8021BridgeBaseIfToPortEntry_t
{
	/* Index values */
// 	uint32_t u32Index;
	
	/* Column values */
// 	uint32_t u32ComponentId;
// 	uint32_t u32Port;
	
// 	xBTree_Node_t oBTreeNode;
} ieee8021BridgeBaseIfToPortEntry_t;

// extern xBTree_t oIeee8021BridgeBaseIfToPortTable_BTree;

/* ieee8021BridgeBaseIfToPortTable table mapper */
void ieee8021BridgeBaseIfToPortTable_init (void);
ieee8021BridgeBaseIfToPortEntry_t * ieee8021BridgeBaseIfToPortTable_createEntry (
	uint32_t u32Index);
ieee8021BridgeBaseIfToPortEntry_t * ieee8021BridgeBaseIfToPortTable_getByIndex (
	uint32_t u32Index);
ieee8021BridgeBaseIfToPortEntry_t * ieee8021BridgeBaseIfToPortTable_getNextIndex (
	uint32_t u32Index);
void ieee8021BridgeBaseIfToPortTable_removeEntry (ieee8021BridgeBaseIfToPortEntry_t *poEntry);
ieee8021BridgeBaseIfToPortEntry_t *ieee8021BridgeBaseIfToPortTable_createExt (
	uint32_t u32Index);
bool ieee8021BridgeBaseIfToPortTable_removeExt (ieee8021BridgeBaseIfToPortEntry_t *poEntry);
bool ieee8021BridgeBaseIfToPortTable_createHier (ieee8021BridgeBaseIfToPortEntry_t *poEntry);
bool ieee8021BridgeBaseIfToPortTable_removeHier (ieee8021BridgeBaseIfToPortEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021BridgeBaseIfToPortTable_getFirst;
Netsnmp_Next_Data_Point ieee8021BridgeBaseIfToPortTable_getNext;
Netsnmp_Get_Data_Point ieee8021BridgeBaseIfToPortTable_get;
Netsnmp_Node_Handler ieee8021BridgeBaseIfToPortTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021BridgePhyPortTable definitions
 */
#define IEEE8021BRIDGEPHYPORT 1
#define IEEE8021BRIDGEPHYPORTIFINDEX 2
#define IEEE8021BRIDGEPHYMACADDRESS 3
#define IEEE8021BRIDGEPHYPORTTOCOMPONENTID 4
#define IEEE8021BRIDGEPHYPORTTOINTERNALPORT 5

/* table ieee8021BridgePhyPortTable row entry data structure */
typedef struct ieee8021BridgePhyPortEntry_t
{
	/* Index values */
// 	uint32_t u32Port;
	
	/* Column values */
// 	uint32_t u32IfIndex;
	uint8_t au8MacAddress[6];
	size_t u16MacAddress_len;	/* # of uint8_t elements */
// 	uint32_t u32ToComponentId;
// 	uint32_t u32ToInternalPort;
	
// 	xBTree_Node_t oBTreeNode;
} ieee8021BridgePhyPortEntry_t;

// extern xBTree_t oIeee8021BridgePhyPortTable_BTree;

/* ieee8021BridgePhyPortTable table mapper */
void ieee8021BridgePhyPortTable_init (void);
ieee8021BridgePhyPortEntry_t * ieee8021BridgePhyPortTable_createEntry (
	uint32_t u32Port);
ieee8021BridgePhyPortEntry_t * ieee8021BridgePhyPortTable_getByIndex (
	uint32_t u32Port);
ieee8021BridgePhyPortEntry_t * ieee8021BridgePhyPortTable_getNextIndex (
	uint32_t u32Port);
void ieee8021BridgePhyPortTable_removeEntry (ieee8021BridgePhyPortEntry_t *poEntry);
ieee8021BridgePhyPortEntry_t * ieee8021BridgePhyPortTable_createExt (
	uint32_t u32Port,
	uint32_t u32IfIndex);
bool ieee8021BridgePhyPortTable_removeExt (ieee8021BridgePhyPortEntry_t *poEntry);
bool ieee8021BridgePhyPortTable_createHier (ieee8021BridgePhyPortEntry_t *poEntry);
bool ieee8021BridgePhyPortTable_removeHier (ieee8021BridgePhyPortEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021BridgePhyPortTable_getFirst;
Netsnmp_Next_Data_Point ieee8021BridgePhyPortTable_getNext;
Netsnmp_Get_Data_Point ieee8021BridgePhyPortTable_get;
Netsnmp_Node_Handler ieee8021BridgePhyPortTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021BridgeChassisTable definitions
 */


/**
 *	table ieee8021BridgePhyTable definitions
 */
typedef struct ieee8021BridgePhyData_t
{
	uint32_t u32IfIndex;
	uint32_t u32PhyPort;
	
	ieee8021BridgeBaseIfToPortEntry_t oIf;
	ieee8021BridgePhyPortEntry_t oPhy;
	
	uint32_t u32ChassisId;
	uint32_t u32ComponentId;
	uint32_t u32Port;
	uint8_t au8TypeCapabilities[2];
	size_t u16TypeCapabilities_len;	/* # of uint8_t elements */
	uint8_t au8AdminFlags[3];
	
	xBTree_Node_t oIf_BTreeNode;
	xBTree_Node_t oPhy_BTreeNode;
} ieee8021BridgePhyData_t;

// extern xBTree_t oIeee8021BridgePhyData_If_BTree;
// extern xBTree_t oIeee8021BridgePhyData_Phy_BTree;

ieee8021BridgePhyData_t * ieee8021BridgePhyData_createEntry (
	uint32_t u32IfIndex,
	uint32_t u32PhyPort);
ieee8021BridgePhyData_t * ieee8021BridgePhyData_getByIndex (
	uint32_t u32IfIndex,
	uint32_t u32PhyPort);
ieee8021BridgePhyData_t * ieee8021BridgePhyData_getNextIndex (
	uint32_t u32IfIndex,
	uint32_t u32PhyPort);
#define ieee8021BridgePhyData_getByIfEntry(poEntry) ((poEntry) == NULL ? NULL: xGetParentByMemberPtr ((poEntry), ieee8021BridgePhyData_t, oIf))
#define ieee8021BridgePhyData_getByPhyEntry(poEntry) ((poEntry) == NULL ? NULL: xGetParentByMemberPtr ((poEntry), ieee8021BridgePhyData_t, oPhy))
void ieee8021BridgePhyData_removeEntry (ieee8021BridgePhyData_t *poEntry);
ieee8021BridgePhyData_t * ieee8021BridgePhyData_createExt (
	uint32_t u32IfIndex,
	uint32_t u32PhyPort);
bool ieee8021BridgePhyData_removeExt (ieee8021BridgePhyData_t *poEntry);
bool ieee8021BridgePhyData_createHier (ieee8021BridgePhyData_t *poEntry);
bool ieee8021BridgePhyData_removeHier (ieee8021BridgePhyData_t *poEntry);
bool ieee8021BridgePhyData_attachComponent (
	ieee8021BridgeBaseEntry_t *poComponent, ieee8021BridgeBasePortEntry_t *poPort,
	ieee8021BridgePhyData_t *poPhyData);
bool ieee8021BridgePhyData_detachComponent (
	ieee8021BridgeBasePortEntry_t *poPort,
	ieee8021BridgePhyData_t *poPhyData);
	
#define ieee8021BridgePhyData_wrLock() (xRwLock_wrLock (&oBridge.oPhyPortLock))
#define ieee8021BridgePhyData_rdLock() (xRwLock_rdLock (&oBridge.oPhyPortLock))
#define ieee8021BridgePhyData_unLock() (xRwLock_unlock (&oBridge.oPhyPortLock))


/**
 *	table ieee8021BridgeTpPortTable definitions
 */
#define IEEE8021BRIDGETPPORTCOMPONENTID 1
#define IEEE8021BRIDGETPPORT 2
#define IEEE8021BRIDGETPPORTMAXINFO 3
#define IEEE8021BRIDGETPPORTINFRAMES 4
#define IEEE8021BRIDGETPPORTOUTFRAMES 5
#define IEEE8021BRIDGETPPORTINDISCARDS 6

/* table ieee8021BridgeTpPortTable row entry data structure */
typedef struct ieee8021BridgeTpPortEntry_t
{
	/* Index values */
	uint32_t u32ComponentId;
	uint32_t u32Port;
	
	/* Column values */
	int32_t i32MaxInfo;
	uint64_t u64InFrames;
	uint64_t u64OutFrames;
	uint64_t u64InDiscards;
	
	xBTree_Node_t oBTreeNode;
} ieee8021BridgeTpPortEntry_t;

extern xBTree_t oIeee8021BridgeTpPortTable_BTree;

/* ieee8021BridgeTpPortTable table mapper */
void ieee8021BridgeTpPortTable_init (void);
ieee8021BridgeTpPortEntry_t * ieee8021BridgeTpPortTable_createEntry (
	uint32_t u32ComponentId,
	uint32_t u32Port);
ieee8021BridgeTpPortEntry_t * ieee8021BridgeTpPortTable_getByIndex (
	uint32_t u32ComponentId,
	uint32_t u32Port);
ieee8021BridgeTpPortEntry_t * ieee8021BridgeTpPortTable_getNextIndex (
	uint32_t u32ComponentId,
	uint32_t u32Port);
void ieee8021BridgeTpPortTable_removeEntry (ieee8021BridgeTpPortEntry_t *poEntry);
ieee8021BridgeTpPortEntry_t * ieee8021BridgeTpPortTable_createExt (
	uint32_t u32ComponentId,
	uint32_t u32Port);
bool ieee8021BridgeTpPortTable_removeExt (ieee8021BridgeTpPortEntry_t *poEntry);
bool ieee8021BridgeTpPortTable_createHier (ieee8021BridgeTpPortEntry_t *poEntry);
bool ieee8021BridgeTpPortTable_removeHier (ieee8021BridgeTpPortEntry_t *poEntry);
bool ieee8021BridgeTpPortTable_handler (
	ieee8021BridgeBaseEntry_t *poComponent,
	ieee8021BridgePhyData_t *poPhyData, bool bMacLearn, bool bMacFwd);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021BridgeTpPortTable_getFirst;
Netsnmp_Next_Data_Point ieee8021BridgeTpPortTable_getNext;
Netsnmp_Get_Data_Point ieee8021BridgeTpPortTable_get;
Netsnmp_Node_Handler ieee8021BridgeTpPortTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	ieee8021BridgePortPriority, ieee8021BridgePriorityCodePoint, ieee8021BridgeDEI & ieee8021BridgeTrafficClass definitions
 */
enum
{
	ieee8021BridgePriority_min_c = 0,
	ieee8021BridgePriority_max_c = 7,
	ieee8021BridgePriority_invalid_c = 8,
	ieee8021BridgePriority_count_c = 8,
	
	ieee8021BridgePriorityCodePoint_min_c = 1,
	ieee8021BridgePriorityCodePoint_max_c = 4,
	ieee8021BridgePriorityCodePoint_invalid_c = 5,
	ieee8021BridgePriorityCodePoint_count_c = 4,
	
	ieee8021BridgeDEI_min_c = 1,
	ieee8021BridgeDEI_max_c = 2,
	ieee8021BridgeDEI_count_c = 2,
};

#define ieee8021BridgePriority_getNext(_p) (ieee8021BridgePriority_min_c <= (_p) && (_p) < ieee8021BridgePriority_max_c ? (_p) + 1: ieee8021BridgePriority_min_c)
#define ieee8021BridgePriority_isLast(_p) ((_p) == ieee8021BridgePriority_max_c)
#define ieee8021BridgePriority_isValid(_p) (ieee8021BridgePriority_min_c <= (_p) && (_p) <= ieee8021BridgePriority_max_c)

#define ieee8021BridgeDEI_getNext(_p) (ieee8021BridgeDEI_min_c <= (_p) && (_p) < ieee8021BridgeDEI_max_c ? (_p) + 1: ieee8021BridgeDEI_min_c)
#define ieee8021BridgeDEI_isLast(_p) ((_p) == ieee8021BridgeDEI_max_c)
#define ieee8021BridgeDEI_isValid(_p) (ieee8021BridgeDEI_min_c <= (_p) && (_p) <= ieee8021BridgeDEI_max_c)

typedef struct ieee8021BridgePcp_t {
	uint8_t ubDei: 1;
	uint8_t ubPcp: 7;
} ieee8021BridgePcp_t;

extern const uint8_t ieee8021BridgePcpEncodingTable [ieee8021BridgePriorityCodePoint_count_c][ieee8021BridgePriority_count_c][ieee8021BridgeDEI_count_c];
extern const ieee8021BridgePcp_t ieee8021BridgePcpDecodingTable [ieee8021BridgePriorityCodePoint_count_c][ieee8021BridgePriority_count_c];


/**
 *	table ieee8021BridgePortPriorityTable definitions
 */
#define IEEE8021BRIDGEPORTDEFAULTUSERPRIORITY 1
#define IEEE8021BRIDGEPORTNUMTRAFFICCLASSES 2
#define IEEE8021BRIDGEPORTPRIORITYCODEPOINTSELECTION 3
#define IEEE8021BRIDGEPORTUSEDEI 4
#define IEEE8021BRIDGEPORTREQUIREDROPENCODING 5
#define IEEE8021BRIDGEPORTSERVICEACCESSPRIORITYSELECTION 6

enum
{
	/* enums for column ieee8021BridgePortPriorityCodePointSelection */
	ieee8021BridgePortPriorityCodePointSelection_codePoint8p0d_c = 1,
	ieee8021BridgePortPriorityCodePointSelection_codePoint7p1d_c = 2,
	ieee8021BridgePortPriorityCodePointSelection_codePoint6p2d_c = 3,
	ieee8021BridgePortPriorityCodePointSelection_codePoint5p3d_c = 4,

	/* enums for column ieee8021BridgePortUseDEI */
	ieee8021BridgePortUseDEI_true_c = 1,
	ieee8021BridgePortUseDEI_false_c = 2,

	/* enums for column ieee8021BridgePortRequireDropEncoding */
	ieee8021BridgePortRequireDropEncoding_true_c = 1,
	ieee8021BridgePortRequireDropEncoding_false_c = 2,

	/* enums for column ieee8021BridgePortServiceAccessPrioritySelection */
	ieee8021BridgePortServiceAccessPrioritySelection_true_c = 1,
	ieee8021BridgePortServiceAccessPrioritySelection_false_c = 2,
};

/* table ieee8021BridgePortPriorityTable row entry data structure */
typedef struct ieee8021BridgePortPriorityEntry_t
{
	/* Index values */
	uint32_t u32BasePortComponentId;
	uint32_t u32BasePort;
	
	/* Column values */
	uint32_t u32DefaultUserPriority;
	int32_t i32NumTrafficClasses;
	int32_t i32CodePointSelection;
	uint8_t u8UseDEI;
	uint8_t u8RequireDropEncoding;
	uint8_t u8ServiceAccessPrioritySelection;
	
	xBTree_Node_t oBTreeNode;
} ieee8021BridgePortPriorityEntry_t;

extern xBTree_t oIeee8021BridgePortPriorityTable_BTree;

/* ieee8021BridgePortPriorityTable table mapper */
void ieee8021BridgePortPriorityTable_init (void);
ieee8021BridgePortPriorityEntry_t * ieee8021BridgePortPriorityTable_createEntry (
	uint32_t u32BasePortComponentId,
	uint32_t u32BasePort);
ieee8021BridgePortPriorityEntry_t * ieee8021BridgePortPriorityTable_getByIndex (
	uint32_t u32BasePortComponentId,
	uint32_t u32BasePort);
ieee8021BridgePortPriorityEntry_t * ieee8021BridgePortPriorityTable_getNextIndex (
	uint32_t u32BasePortComponentId,
	uint32_t u32BasePort);
void ieee8021BridgePortPriorityTable_removeEntry (ieee8021BridgePortPriorityEntry_t *poEntry);
ieee8021BridgePortPriorityEntry_t * ieee8021BridgePortPriorityTable_createExt (
	uint32_t u32BasePortComponentId,
	uint32_t u32BasePort);
bool ieee8021BridgePortPriorityTable_removeExt (ieee8021BridgePortPriorityEntry_t *poEntry);
bool ieee8021BridgePortPriorityTable_createHier (ieee8021BridgePortPriorityEntry_t *poEntry);
bool ieee8021BridgePortPriorityTable_removeHier (ieee8021BridgePortPriorityEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021BridgePortPriorityTable_getFirst;
Netsnmp_Next_Data_Point ieee8021BridgePortPriorityTable_getNext;
Netsnmp_Get_Data_Point ieee8021BridgePortPriorityTable_get;
Netsnmp_Node_Handler ieee8021BridgePortPriorityTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021BridgeUserPriorityRegenTable definitions
 */
#define IEEE8021BRIDGEUSERPRIORITY 1
#define IEEE8021BRIDGEREGENUSERPRIORITY 2

/* table ieee8021BridgeUserPriorityRegenTable row entry data structure */
typedef struct ieee8021BridgeUserPriorityRegenEntry_t
{
	/* Index values */
	uint32_t u32BasePortComponentId;
	uint32_t u32BasePort;
// 	uint32_t u32UserPriority;
	
	/* Column values */
	uint8_t au8RegenUserPriority[ieee8021BridgePriority_count_c];
	
	xBTree_Node_t oBTreeNode;
} ieee8021BridgeUserPriorityRegenEntry_t;

extern xBTree_t oIeee8021BridgeUserPriorityRegenTable_BTree;

/* ieee8021BridgeUserPriorityRegenTable table mapper */
void ieee8021BridgeUserPriorityRegenTable_init (void);
ieee8021BridgeUserPriorityRegenEntry_t * ieee8021BridgeUserPriorityRegenTable_createEntry (
	uint32_t u32BasePortComponentId,
	uint32_t u32BasePort,
	uint32_t u32UserPriority);
ieee8021BridgeUserPriorityRegenEntry_t * ieee8021BridgeUserPriorityRegenTable_getByIndex (
	uint32_t u32BasePortComponentId,
	uint32_t u32BasePort,
	uint32_t u32UserPriority);
ieee8021BridgeUserPriorityRegenEntry_t * ieee8021BridgeUserPriorityRegenTable_getNextIndex (
	uint32_t u32BasePortComponentId,
	uint32_t u32BasePort,
	uint32_t u32UserPriority);
void ieee8021BridgeUserPriorityRegenTable_removeEntry (ieee8021BridgeUserPriorityRegenEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021BridgeUserPriorityRegenTable_getFirst;
Netsnmp_Next_Data_Point ieee8021BridgeUserPriorityRegenTable_getNext;
Netsnmp_Get_Data_Point ieee8021BridgeUserPriorityRegenTable_get;
Netsnmp_Node_Handler ieee8021BridgeUserPriorityRegenTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021BridgeTrafficClassTable definitions
 */
#define IEEE8021BRIDGETRAFFICCLASSPRIORITY 1
#define IEEE8021BRIDGETRAFFICCLASS 2

/* table ieee8021BridgeTrafficClassTable row entry data structure */
typedef struct ieee8021BridgeTrafficClassEntry_t
{
	/* Index values */
	uint32_t u32BasePortComponentId;
	uint32_t u32BasePort;
// 	uint32_t u32Priority;
	
	/* Column values */
	uint8_t au8Class[ieee8021BridgePriority_count_c];
	
	xBTree_Node_t oBTreeNode;
} ieee8021BridgeTrafficClassEntry_t;

extern xBTree_t oIeee8021BridgeTrafficClassTable_BTree;

/* ieee8021BridgeTrafficClassTable table mapper */
void ieee8021BridgeTrafficClassTable_init (void);
ieee8021BridgeTrafficClassEntry_t * ieee8021BridgeTrafficClassTable_createEntry (
	uint32_t u32BasePortComponentId,
	uint32_t u32BasePort,
	uint32_t u32Priority);
ieee8021BridgeTrafficClassEntry_t * ieee8021BridgeTrafficClassTable_getByIndex (
	uint32_t u32BasePortComponentId,
	uint32_t u32BasePort,
	uint32_t u32Priority);
ieee8021BridgeTrafficClassEntry_t * ieee8021BridgeTrafficClassTable_getNextIndex (
	uint32_t u32BasePortComponentId,
	uint32_t u32BasePort,
	uint32_t u32Priority);
void ieee8021BridgeTrafficClassTable_removeEntry (ieee8021BridgeTrafficClassEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021BridgeTrafficClassTable_getFirst;
Netsnmp_Next_Data_Point ieee8021BridgeTrafficClassTable_getNext;
Netsnmp_Get_Data_Point ieee8021BridgeTrafficClassTable_get;
Netsnmp_Node_Handler ieee8021BridgeTrafficClassTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021BridgePortOutboundAccessPriorityTable definitions
 */
#define IEEE8021BRIDGEPORTOUTBOUNDACCESSPRIORITY 1

/* table ieee8021BridgePortOutboundAccessPriorityTable row entry data structure */
typedef struct ieee8021BridgePortOutboundAccessPriorityEntry_t
{
	/* Index values */
	uint32_t u32BasePortComponentId;
	uint32_t u32BasePort;
// 	uint32_t u32RegenUserPriority;
	
	/* Column values */
	uint8_t au8Priority[ieee8021BridgePriority_count_c];
	
	xBTree_Node_t oBTreeNode;
} ieee8021BridgePortOutboundAccessPriorityEntry_t;

extern xBTree_t oIeee8021BridgePortOutboundAccessPriorityTable_BTree;

/* ieee8021BridgePortOutboundAccessPriorityTable table mapper */
void ieee8021BridgePortOutboundAccessPriorityTable_init (void);
ieee8021BridgePortOutboundAccessPriorityEntry_t * ieee8021BridgePortOutboundAccessPriorityTable_createEntry (
	uint32_t u32BasePortComponentId,
	uint32_t u32BasePort,
	uint32_t u32RegenUserPriority);
ieee8021BridgePortOutboundAccessPriorityEntry_t * ieee8021BridgePortOutboundAccessPriorityTable_getByIndex (
	uint32_t u32BasePortComponentId,
	uint32_t u32BasePort,
	uint32_t u32RegenUserPriority);
ieee8021BridgePortOutboundAccessPriorityEntry_t * ieee8021BridgePortOutboundAccessPriorityTable_getNextIndex (
	uint32_t u32BasePortComponentId,
	uint32_t u32BasePort,
	uint32_t u32RegenUserPriority);
void ieee8021BridgePortOutboundAccessPriorityTable_removeEntry (ieee8021BridgePortOutboundAccessPriorityEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021BridgePortOutboundAccessPriorityTable_getFirst;
Netsnmp_Next_Data_Point ieee8021BridgePortOutboundAccessPriorityTable_getNext;
Netsnmp_Get_Data_Point ieee8021BridgePortOutboundAccessPriorityTable_get;
Netsnmp_Node_Handler ieee8021BridgePortOutboundAccessPriorityTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021BridgePortDecodingTable definitions
 */
#define IEEE8021BRIDGEPORTDECODINGCOMPONENTID 1
#define IEEE8021BRIDGEPORTDECODINGPORTNUM 2
#define IEEE8021BRIDGEPORTDECODINGPRIORITYCODEPOINTROW 3
#define IEEE8021BRIDGEPORTDECODINGPRIORITYCODEPOINT 4
#define IEEE8021BRIDGEPORTDECODINGPRIORITY 5
#define IEEE8021BRIDGEPORTDECODINGDROPELIGIBLE 6

enum
{
	/* enums for column ieee8021BridgePortDecodingPriorityCodePointRow */
	ieee8021BridgePortDecodingPriorityCodePointRow_codePoint8p0d_c = 1,
	ieee8021BridgePortDecodingPriorityCodePointRow_codePoint7p1d_c = 2,
	ieee8021BridgePortDecodingPriorityCodePointRow_codePoint6p2d_c = 3,
	ieee8021BridgePortDecodingPriorityCodePointRow_codePoint5p3d_c = 4,

	/* enums for column ieee8021BridgePortDecodingDropEligible */
	ieee8021BridgePortDecodingDropEligible_true_c = 1,
	ieee8021BridgePortDecodingDropEligible_false_c = 2,
};

/* table ieee8021BridgePortDecodingTable row entry data structure */
typedef struct ieee8021BridgePortDecodingEntry_t
{
	/* Index values */
	uint32_t u32ComponentId;
	uint32_t u32PortNum;
	int32_t i32PriorityCodePointRow;
// 	int32_t i32PriorityCodePoint;
	
	/* Column values */
	uint8_t au8Priority[ieee8021BridgePriority_count_c];
	uint8_t au8DropEligible[ieee8021BridgePriority_count_c];
	
	xBTree_Node_t oBTreeNode;
} ieee8021BridgePortDecodingEntry_t;

extern xBTree_t oIeee8021BridgePortDecodingTable_BTree;

/* ieee8021BridgePortDecodingTable table mapper */
void ieee8021BridgePortDecodingTable_init (void);
ieee8021BridgePortDecodingEntry_t * ieee8021BridgePortDecodingTable_createEntry (
	uint32_t u32ComponentId,
	uint32_t u32PortNum,
	int32_t i32PriorityCodePointRow,
	int32_t i32PriorityCodePoint);
ieee8021BridgePortDecodingEntry_t * ieee8021BridgePortDecodingTable_getByIndex (
	uint32_t u32ComponentId,
	uint32_t u32PortNum,
	int32_t i32PriorityCodePointRow,
	int32_t i32PriorityCodePoint);
ieee8021BridgePortDecodingEntry_t * ieee8021BridgePortDecodingTable_getNextIndex (
	uint32_t u32ComponentId,
	uint32_t u32PortNum,
	int32_t i32PriorityCodePointRow,
	int32_t i32PriorityCodePoint);
void ieee8021BridgePortDecodingTable_removeEntry (ieee8021BridgePortDecodingEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021BridgePortDecodingTable_getFirst;
Netsnmp_Next_Data_Point ieee8021BridgePortDecodingTable_getNext;
Netsnmp_Get_Data_Point ieee8021BridgePortDecodingTable_get;
Netsnmp_Node_Handler ieee8021BridgePortDecodingTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021BridgePortEncodingTable definitions
 */
#define IEEE8021BRIDGEPORTENCODINGCOMPONENTID 1
#define IEEE8021BRIDGEPORTENCODINGPORTNUM 2
#define IEEE8021BRIDGEPORTENCODINGPRIORITYCODEPOINTROW 3
#define IEEE8021BRIDGEPORTENCODINGPRIORITYCODEPOINT 4
#define IEEE8021BRIDGEPORTENCODINGDROPELIGIBLE 5
#define IEEE8021BRIDGEPORTENCODINGPRIORITY 6

enum
{
	/* enums for column ieee8021BridgePortEncodingPriorityCodePointRow */
	ieee8021BridgePortEncodingPriorityCodePointRow_codePoint8p0d_c = 1,
	ieee8021BridgePortEncodingPriorityCodePointRow_codePoint7p1d_c = 2,
	ieee8021BridgePortEncodingPriorityCodePointRow_codePoint6p2d_c = 3,
	ieee8021BridgePortEncodingPriorityCodePointRow_codePoint5p3d_c = 4,

	/* enums for column ieee8021BridgePortEncodingDropEligible */
	ieee8021BridgePortEncodingDropEligible_true_c = 1,
	ieee8021BridgePortEncodingDropEligible_false_c = 2,
};

/* table ieee8021BridgePortEncodingTable row entry data structure */
typedef struct ieee8021BridgePortEncodingEntry_t
{
	/* Index values */
	uint32_t u32ComponentId;
	uint32_t u32PortNum;
	int32_t i32PriorityCodePointRow;
// 	int32_t i32PriorityCodePoint;
// 	uint8_t u8DropEligible;
	
	/* Column values */
	uint8_t au8Priority[ieee8021BridgePriority_count_c][ieee8021BridgeDEI_count_c];
	
	xBTree_Node_t oBTreeNode;
} ieee8021BridgePortEncodingEntry_t;

extern xBTree_t oIeee8021BridgePortEncodingTable_BTree;

/* ieee8021BridgePortEncodingTable table mapper */
void ieee8021BridgePortEncodingTable_init (void);
ieee8021BridgePortEncodingEntry_t * ieee8021BridgePortEncodingTable_createEntry (
	uint32_t u32ComponentId,
	uint32_t u32PortNum,
	int32_t i32PriorityCodePointRow,
	int32_t i32PriorityCodePoint,
	uint8_t u8DropEligible);
ieee8021BridgePortEncodingEntry_t * ieee8021BridgePortEncodingTable_getByIndex (
	uint32_t u32ComponentId,
	uint32_t u32PortNum,
	int32_t i32PriorityCodePointRow,
	int32_t i32PriorityCodePoint,
	uint8_t u8DropEligible);
ieee8021BridgePortEncodingEntry_t * ieee8021BridgePortEncodingTable_getNextIndex (
	uint32_t u32ComponentId,
	uint32_t u32PortNum,
	int32_t i32PriorityCodePointRow,
	int32_t i32PriorityCodePoint,
	uint8_t u8DropEligible);
void ieee8021BridgePortEncodingTable_removeEntry (ieee8021BridgePortEncodingEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021BridgePortEncodingTable_getFirst;
Netsnmp_Next_Data_Point ieee8021BridgePortEncodingTable_getNext;
Netsnmp_Get_Data_Point ieee8021BridgePortEncodingTable_get;
Netsnmp_Node_Handler ieee8021BridgePortEncodingTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021BridgeServiceAccessPriorityTable definitions
 */
#define IEEE8021BRIDGESERVICEACCESSPRIORITYCOMPONENTID 1
#define IEEE8021BRIDGESERVICEACCESSPRIORITYPORTNUM 2
#define IEEE8021BRIDGESERVICEACCESSPRIORITYRECEIVED 3
#define IEEE8021BRIDGESERVICEACCESSPRIORITYVALUE 4

/* table ieee8021BridgeServiceAccessPriorityTable row entry data structure */
typedef struct ieee8021BridgeServiceAccessPriorityEntry_t
{
	/* Index values */
	uint32_t u32ComponentId;
	uint32_t u32PortNum;
// 	uint32_t u32Received;
	
	/* Column values */
	uint8_t au8Value[ieee8021BridgePriority_count_c];
	
	xBTree_Node_t oBTreeNode;
} ieee8021BridgeServiceAccessPriorityEntry_t;

extern xBTree_t oIeee8021BridgeServiceAccessPriorityTable_BTree;

/* ieee8021BridgeServiceAccessPriorityTable table mapper */
void ieee8021BridgeServiceAccessPriorityTable_init (void);
ieee8021BridgeServiceAccessPriorityEntry_t * ieee8021BridgeServiceAccessPriorityTable_createEntry (
	uint32_t u32ComponentId,
	uint32_t u32PortNum,
	uint32_t u32Received);
ieee8021BridgeServiceAccessPriorityEntry_t * ieee8021BridgeServiceAccessPriorityTable_getByIndex (
	uint32_t u32ComponentId,
	uint32_t u32PortNum,
	uint32_t u32Received);
ieee8021BridgeServiceAccessPriorityEntry_t * ieee8021BridgeServiceAccessPriorityTable_getNextIndex (
	uint32_t u32ComponentId,
	uint32_t u32PortNum,
	uint32_t u32Received);
void ieee8021BridgeServiceAccessPriorityTable_removeEntry (ieee8021BridgeServiceAccessPriorityEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021BridgeServiceAccessPriorityTable_getFirst;
Netsnmp_Next_Data_Point ieee8021BridgeServiceAccessPriorityTable_getNext;
Netsnmp_Get_Data_Point ieee8021BridgeServiceAccessPriorityTable_get;
Netsnmp_Node_Handler ieee8021BridgeServiceAccessPriorityTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021BridgePortMrpTable definitions
 */
#define IEEE8021BRIDGEPORTMRPJOINTIME 1
#define IEEE8021BRIDGEPORTMRPLEAVETIME 2
#define IEEE8021BRIDGEPORTMRPLEAVEALLTIME 3

/* table ieee8021BridgePortMrpTable row entry data structure */
typedef struct ieee8021BridgePortMrpEntry_t
{
	/* Index values */
	uint32_t u32BasePortComponentId;
	uint32_t u32BasePort;
	
	/* Column values */
	int32_t i32JoinTime;
	int32_t i32LeaveTime;
	int32_t i32LeaveAllTime;
	
	xBTree_Node_t oBTreeNode;
} ieee8021BridgePortMrpEntry_t;

extern xBTree_t oIeee8021BridgePortMrpTable_BTree;

/* ieee8021BridgePortMrpTable table mapper */
void ieee8021BridgePortMrpTable_init (void);
ieee8021BridgePortMrpEntry_t * ieee8021BridgePortMrpTable_createEntry (
	uint32_t u32BasePortComponentId,
	uint32_t u32BasePort);
ieee8021BridgePortMrpEntry_t * ieee8021BridgePortMrpTable_getByIndex (
	uint32_t u32BasePortComponentId,
	uint32_t u32BasePort);
ieee8021BridgePortMrpEntry_t * ieee8021BridgePortMrpTable_getNextIndex (
	uint32_t u32BasePortComponentId,
	uint32_t u32BasePort);
void ieee8021BridgePortMrpTable_removeEntry (ieee8021BridgePortMrpEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021BridgePortMrpTable_getFirst;
Netsnmp_Next_Data_Point ieee8021BridgePortMrpTable_getNext;
Netsnmp_Get_Data_Point ieee8021BridgePortMrpTable_get;
Netsnmp_Node_Handler ieee8021BridgePortMrpTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021BridgePortMmrpTable definitions
 */
#define IEEE8021BRIDGEPORTMMRPENABLEDSTATUS 1
#define IEEE8021BRIDGEPORTMMRPFAILEDREGISTRATIONS 2
#define IEEE8021BRIDGEPORTMMRPLASTPDUORIGIN 3
#define IEEE8021BRIDGEPORTRESTRICTEDGROUPREGISTRATION 4

enum
{
	/* enums for column ieee8021BridgePortMmrpEnabledStatus */
	ieee8021BridgePortMmrpEnabledStatus_true_c = 1,
	ieee8021BridgePortMmrpEnabledStatus_false_c = 2,

	/* enums for column ieee8021BridgePortRestrictedGroupRegistration */
	ieee8021BridgePortRestrictedGroupRegistration_true_c = 1,
	ieee8021BridgePortRestrictedGroupRegistration_false_c = 2,
};

/* table ieee8021BridgePortMmrpTable row entry data structure */
typedef struct ieee8021BridgePortMmrpEntry_t
{
	/* Index values */
	uint32_t u32BasePortComponentId;
	uint32_t u32BasePort;
	
	/* Column values */
	uint8_t u8EnabledStatus;
	uint64_t u64FailedRegistrations;
	uint8_t au8LastPduOrigin[6];
	size_t u16LastPduOrigin_len;	/* # of uint8_t elements */
	uint8_t u8RestrictedGroupRegistration;
	
	xBTree_Node_t oBTreeNode;
} ieee8021BridgePortMmrpEntry_t;

extern xBTree_t oIeee8021BridgePortMmrpTable_BTree;

/* ieee8021BridgePortMmrpTable table mapper */
void ieee8021BridgePortMmrpTable_init (void);
ieee8021BridgePortMmrpEntry_t * ieee8021BridgePortMmrpTable_createEntry (
	uint32_t u32BasePortComponentId,
	uint32_t u32BasePort);
ieee8021BridgePortMmrpEntry_t * ieee8021BridgePortMmrpTable_getByIndex (
	uint32_t u32BasePortComponentId,
	uint32_t u32BasePort);
ieee8021BridgePortMmrpEntry_t * ieee8021BridgePortMmrpTable_getNextIndex (
	uint32_t u32BasePortComponentId,
	uint32_t u32BasePort);
void ieee8021BridgePortMmrpTable_removeEntry (ieee8021BridgePortMmrpEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021BridgePortMmrpTable_getFirst;
Netsnmp_Next_Data_Point ieee8021BridgePortMmrpTable_getNext;
Netsnmp_Get_Data_Point ieee8021BridgePortMmrpTable_get;
Netsnmp_Node_Handler ieee8021BridgePortMmrpTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021BridgeILanIfTable definitions
 */
#define IEEE8021BRIDGEILANIFROWSTATUS 1

enum
{
	/* enums for column ieee8021BridgeILanIfRowStatus */
	ieee8021BridgeILanIfRowStatus_active_c = 1,
	ieee8021BridgeILanIfRowStatus_notInService_c = 2,
	ieee8021BridgeILanIfRowStatus_notReady_c = 3,
	ieee8021BridgeILanIfRowStatus_createAndGo_c = 4,
	ieee8021BridgeILanIfRowStatus_createAndWait_c = 5,
	ieee8021BridgeILanIfRowStatus_destroy_c = 6,
};

/* table ieee8021BridgeILanIfTable row entry data structure */
typedef struct ieee8021BridgeILanIfEntry_t
{
	/* Index values */
	uint32_t u32Index;
	
	/* Column values */
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} ieee8021BridgeILanIfEntry_t;

extern xBTree_t oIeee8021BridgeILanIfTable_BTree;

/* ieee8021BridgeILanIfTable table mapper */
void ieee8021BridgeILanIfTable_init (void);
ieee8021BridgeILanIfEntry_t * ieee8021BridgeILanIfTable_createEntry (
	uint32_t u32Index);
ieee8021BridgeILanIfEntry_t * ieee8021BridgeILanIfTable_getByIndex (
	uint32_t u32Index);
ieee8021BridgeILanIfEntry_t * ieee8021BridgeILanIfTable_getNextIndex (
	uint32_t u32Index);
void ieee8021BridgeILanIfTable_removeEntry (ieee8021BridgeILanIfEntry_t *poEntry);
ieee8021BridgeILanIfEntry_t * ieee8021BridgeILanIfTable_createRegister (
	uint32_t u32Index);
bool ieee8021BridgeILanIfTable_removeRegister (
	uint32_t u32Index);
ieee8021BridgeILanIfEntry_t * ieee8021BridgeILanIfTable_createExt (
	uint32_t u32Index);
bool ieee8021BridgeILanIfTable_removeExt (ieee8021BridgeILanIfEntry_t *poEntry);
bool ieee8021BridgeILanIfTable_createHier (ieee8021BridgeILanIfEntry_t *poEntry);
bool ieee8021BridgeILanIfTable_removeHier (ieee8021BridgeILanIfEntry_t *poEntry);
bool ieee8021BridgeILanIfRowStatus_handler (
	ieee8021BridgeILanIfEntry_t *poEntry, uint8_t u8RowStatus);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021BridgeILanIfTable_getFirst;
Netsnmp_Next_Data_Point ieee8021BridgeILanIfTable_getNext;
Netsnmp_Get_Data_Point ieee8021BridgeILanIfTable_get;
Netsnmp_Node_Handler ieee8021BridgeILanIfTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021BridgeDot1dPortTable definitions
 */
#define IEEE8021BRIDGEDOT1DPORTROWSTATUS 1

enum
{
	/* enums for column ieee8021BridgeDot1dPortRowStatus */
	ieee8021BridgeDot1dPortRowStatus_active_c = 1,
	ieee8021BridgeDot1dPortRowStatus_notInService_c = 2,
	ieee8021BridgeDot1dPortRowStatus_notReady_c = 3,
	ieee8021BridgeDot1dPortRowStatus_createAndGo_c = 4,
	ieee8021BridgeDot1dPortRowStatus_createAndWait_c = 5,
	ieee8021BridgeDot1dPortRowStatus_destroy_c = 6,
};

/* table ieee8021BridgeDot1dPortTable row entry data structure */
typedef struct ieee8021BridgeDot1dPortEntry_t
{
	/* Index values */
	uint32_t u32BasePortComponentId;
	uint32_t u32BasePort;
	
	/* Column values */
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} ieee8021BridgeDot1dPortEntry_t;

extern xBTree_t oIeee8021BridgeDot1dPortTable_BTree;

/* ieee8021BridgeDot1dPortTable table mapper */
void ieee8021BridgeDot1dPortTable_init (void);
ieee8021BridgeDot1dPortEntry_t * ieee8021BridgeDot1dPortTable_createEntry (
	uint32_t u32BasePortComponentId,
	uint32_t u32BasePort);
ieee8021BridgeDot1dPortEntry_t * ieee8021BridgeDot1dPortTable_getByIndex (
	uint32_t u32BasePortComponentId,
	uint32_t u32BasePort);
ieee8021BridgeDot1dPortEntry_t * ieee8021BridgeDot1dPortTable_getNextIndex (
	uint32_t u32BasePortComponentId,
	uint32_t u32BasePort);
void ieee8021BridgeDot1dPortTable_removeEntry (ieee8021BridgeDot1dPortEntry_t *poEntry);
ieee8021BridgeDot1dPortEntry_t * ieee8021BridgeDot1dPortTable_createExt (
	uint32_t u32BasePortComponentId,
	uint32_t u32BasePort);
bool ieee8021BridgeDot1dPortTable_removeExt (ieee8021BridgeDot1dPortEntry_t *poEntry);
bool ieee8021BridgeDot1dPortTable_createHier (ieee8021BridgeDot1dPortEntry_t *poEntry);
bool ieee8021BridgeDot1dPortTable_removeHier (ieee8021BridgeDot1dPortEntry_t *poEntry);
bool ieee8021BridgeDot1dPortRowStatus_handler (
	ieee8021BridgeDot1dPortEntry_t *poEntry, uint8_t u8RowStatus);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021BridgeDot1dPortTable_getFirst;
Netsnmp_Next_Data_Point ieee8021BridgeDot1dPortTable_getNext;
Netsnmp_Get_Data_Point ieee8021BridgeDot1dPortTable_get;
Netsnmp_Node_Handler ieee8021BridgeDot1dPortTable_mapper;
#endif	/* SNMP_SRC */


/* table ieee8021BridgeBasePortTable row entry data structure */
/*typedef*/ struct ieee8021BridgeBasePortEntry_t
{
	/* Index values */
	uint32_t u32ComponentId;
	uint32_t u32Port;
	
	/* Column values */
	uint32_t u32IfIndex;
	uint64_t u64DelayExceededDiscards;
	uint64_t u64MtuExceededDiscards;
	uint8_t au8Capabilities[1];
	size_t u16Capabilities_len;	/* # of uint8_t elements */
	uint8_t au8TypeCapabilities[2];
	size_t u16TypeCapabilities_len;	/* # of uint8_t elements */
	int32_t i32Type;
	uint8_t u8External;
	int32_t i32AdminPointToPoint;
	uint8_t u8OperPointToPoint;
	uint8_t au8Name[32];
	size_t u16Name_len;	/* # of uint8_t elements */
	
	neIeee8021BridgeBasePortEntry_t oNe;
	ieee8021BridgePortPriorityEntry_t oPriority;
	
	uint8_t u8RowStatus;
	struct ieee8021BridgeBasePortEntry_t *pOldEntry;
	
	xBTree_Node_t oBTreeNode;
} /*ieee8021BridgeBasePortEntry_t*/;



#	ifdef __cplusplus
}
#	endif

#endif /* __IEEE8021BRIDGEMIB_H__ */
