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

#ifndef __IEEE8021PBMIB_H__
#	define __IEEE8021PBMIB_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include "lib/binaryTree.h"
#include "lib/snmp.h"

#define TOBE_REPLACED 1


/**
 *	agent MIB function
 */
void ieee8021PbMib_init (void);


/**
 *	table mapper(s)
 */
/**
 *	table ieee8021PbCVidRegistrationTable definitions
 */
#define IEEE8021PBCVIDREGISTRATIONCVID 1
#define IEEE8021PBCVIDREGISTRATIONSVID 2
#define IEEE8021PBCVIDREGISTRATIONUNTAGGEDPEP 3
#define IEEE8021PBCVIDREGISTRATIONUNTAGGEDCEP 4
#define IEEE8021PBCVIDREGISTRATIONROWSTATUS 5

enum
{
	/* enums for column ieee8021PbCVidRegistrationUntaggedPep */
	ieee8021PbCVidRegistrationUntaggedPep_true_c = 1,
	ieee8021PbCVidRegistrationUntaggedPep_false_c = 2,

	/* enums for column ieee8021PbCVidRegistrationUntaggedCep */
	ieee8021PbCVidRegistrationUntaggedCep_true_c = 1,
	ieee8021PbCVidRegistrationUntaggedCep_false_c = 2,

	/* enums for column ieee8021PbCVidRegistrationRowStatus */
	ieee8021PbCVidRegistrationRowStatus_active_c = 1,
	ieee8021PbCVidRegistrationRowStatus_notInService_c = 2,
	ieee8021PbCVidRegistrationRowStatus_notReady_c = 3,
	ieee8021PbCVidRegistrationRowStatus_createAndGo_c = 4,
	ieee8021PbCVidRegistrationRowStatus_createAndWait_c = 5,
	ieee8021PbCVidRegistrationRowStatus_destroy_c = 6,
};

/* table ieee8021PbCVidRegistrationTable row entry data structure */
typedef struct ieee8021PbCVidRegistrationEntry_t
{
	/* Index values */
	uint32_t u32BridgeBasePortComponentId;
	uint32_t u32BridgeBasePort;
	int32_t i32CVid;
	
	/* Column values */
	int32_t i32SVid;
	int32_t i32UntaggedPep;
	int32_t i32UntaggedCep;
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} ieee8021PbCVidRegistrationEntry_t;

extern xBTree_t oIeee8021PbCVidRegistrationTable_BTree;

/* ieee8021PbCVidRegistrationTable table mapper */
void ieee8021PbCVidRegistrationTable_init (void);
ieee8021PbCVidRegistrationEntry_t * ieee8021PbCVidRegistrationTable_createEntry (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	int32_t i32CVid);
ieee8021PbCVidRegistrationEntry_t * ieee8021PbCVidRegistrationTable_getByIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	int32_t i32CVid);
ieee8021PbCVidRegistrationEntry_t * ieee8021PbCVidRegistrationTable_getNextIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	int32_t i32CVid);
void ieee8021PbCVidRegistrationTable_removeEntry (ieee8021PbCVidRegistrationEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021PbCVidRegistrationTable_getFirst;
Netsnmp_Next_Data_Point ieee8021PbCVidRegistrationTable_getNext;
Netsnmp_Get_Data_Point ieee8021PbCVidRegistrationTable_get;
Netsnmp_Node_Handler ieee8021PbCVidRegistrationTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021PbEdgePortTable definitions
 */
#define IEEE8021PBEDGEPORTSVID 1
#define IEEE8021PBEDGEPORTPVID 2
#define IEEE8021PBEDGEPORTDEFAULTUSERPRIORITY 3
#define IEEE8021PBEDGEPORTACCEPTABLEFRAMETYPES 4
#define IEEE8021PBEDGEPORTENABLEINGRESSFILTERING 5

enum
{
	/* enums for column ieee8021PbEdgePortAcceptableFrameTypes */
	ieee8021PbEdgePortAcceptableFrameTypes_admitAll_c = 1,
	ieee8021PbEdgePortAcceptableFrameTypes_admitUntaggedAndPriority_c = 2,
	ieee8021PbEdgePortAcceptableFrameTypes_admitTagged_c = 3,

	/* enums for column ieee8021PbEdgePortEnableIngressFiltering */
	ieee8021PbEdgePortEnableIngressFiltering_true_c = 1,
	ieee8021PbEdgePortEnableIngressFiltering_false_c = 2,
};

/* table ieee8021PbEdgePortTable row entry data structure */
typedef struct ieee8021PbEdgePortEntry_t
{
	/* Index values */
	uint32_t u32BridgeBasePortComponentId;
	uint32_t u32BridgeBasePort;
	int32_t i32SVid;
	
	/* Column values */
	int32_t i32PVID;
	uint32_t u32DefaultUserPriority;
	int32_t i32AcceptableFrameTypes;
	int32_t i32EnableIngressFiltering;
	
	xBTree_Node_t oBTreeNode;
} ieee8021PbEdgePortEntry_t;

extern xBTree_t oIeee8021PbEdgePortTable_BTree;

/* ieee8021PbEdgePortTable table mapper */
void ieee8021PbEdgePortTable_init (void);
ieee8021PbEdgePortEntry_t * ieee8021PbEdgePortTable_createEntry (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	int32_t i32SVid);
ieee8021PbEdgePortEntry_t * ieee8021PbEdgePortTable_getByIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	int32_t i32SVid);
ieee8021PbEdgePortEntry_t * ieee8021PbEdgePortTable_getNextIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	int32_t i32SVid);
void ieee8021PbEdgePortTable_removeEntry (ieee8021PbEdgePortEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021PbEdgePortTable_getFirst;
Netsnmp_Next_Data_Point ieee8021PbEdgePortTable_getNext;
Netsnmp_Get_Data_Point ieee8021PbEdgePortTable_get;
Netsnmp_Node_Handler ieee8021PbEdgePortTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021PbServicePriorityRegenerationTable definitions
 */
#define IEEE8021PBSERVICEPRIORITYREGENERATIONSVID 1
#define IEEE8021PBSERVICEPRIORITYREGENERATIONRECEIVEDPRIORITY 2
#define IEEE8021PBSERVICEPRIORITYREGENERATIONREGENERATEDPRIORITY 3

/* table ieee8021PbServicePriorityRegenerationTable row entry data structure */
typedef struct ieee8021PbServicePriorityRegenerationEntry_t
{
	/* Index values */
	uint32_t u32BridgeBasePortComponentId;
	uint32_t u32BridgeBasePort;
	int32_t i32SVid;
	uint32_t u32ReceivedPriority;
	
	/* Column values */
	uint32_t u32RegeneratedPriority;
	
	xBTree_Node_t oBTreeNode;
} ieee8021PbServicePriorityRegenerationEntry_t;

extern xBTree_t oIeee8021PbServicePriorityRegenerationTable_BTree;

/* ieee8021PbServicePriorityRegenerationTable table mapper */
void ieee8021PbServicePriorityRegenerationTable_init (void);
ieee8021PbServicePriorityRegenerationEntry_t * ieee8021PbServicePriorityRegenerationTable_createEntry (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	int32_t i32SVid,
	uint32_t u32ReceivedPriority);
ieee8021PbServicePriorityRegenerationEntry_t * ieee8021PbServicePriorityRegenerationTable_getByIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	int32_t i32SVid,
	uint32_t u32ReceivedPriority);
ieee8021PbServicePriorityRegenerationEntry_t * ieee8021PbServicePriorityRegenerationTable_getNextIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	int32_t i32SVid,
	uint32_t u32ReceivedPriority);
void ieee8021PbServicePriorityRegenerationTable_removeEntry (ieee8021PbServicePriorityRegenerationEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021PbServicePriorityRegenerationTable_getFirst;
Netsnmp_Next_Data_Point ieee8021PbServicePriorityRegenerationTable_getNext;
Netsnmp_Get_Data_Point ieee8021PbServicePriorityRegenerationTable_get;
Netsnmp_Node_Handler ieee8021PbServicePriorityRegenerationTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021PbCnpTable definitions
 */
#define IEEE8021PBCNPCCOMPONENTID 1
#define IEEE8021PBCNPSVID 2
#define IEEE8021PBCNPROWSTATUS 3

enum
{
	/* enums for column ieee8021PbCnpRowStatus */
	ieee8021PbCnpRowStatus_active_c = 1,
	ieee8021PbCnpRowStatus_notInService_c = 2,
	ieee8021PbCnpRowStatus_notReady_c = 3,
	ieee8021PbCnpRowStatus_createAndGo_c = 4,
	ieee8021PbCnpRowStatus_createAndWait_c = 5,
	ieee8021PbCnpRowStatus_destroy_c = 6,
};

/* table ieee8021PbCnpTable row entry data structure */
typedef struct ieee8021PbCnpEntry_t
{
	/* Index values */
	uint32_t u32BridgeBasePortComponentId;
	uint32_t u32BridgeBasePort;
	
	/* Column values */
	uint32_t u32CComponentId;
	int32_t i32SVid;
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} ieee8021PbCnpEntry_t;

extern xBTree_t oIeee8021PbCnpTable_BTree;

/* ieee8021PbCnpTable table mapper */
void ieee8021PbCnpTable_init (void);
ieee8021PbCnpEntry_t * ieee8021PbCnpTable_createEntry (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort);
ieee8021PbCnpEntry_t * ieee8021PbCnpTable_getByIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort);
ieee8021PbCnpEntry_t * ieee8021PbCnpTable_getNextIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort);
void ieee8021PbCnpTable_removeEntry (ieee8021PbCnpEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021PbCnpTable_getFirst;
Netsnmp_Next_Data_Point ieee8021PbCnpTable_getNext;
Netsnmp_Get_Data_Point ieee8021PbCnpTable_get;
Netsnmp_Node_Handler ieee8021PbCnpTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021PbPnpTable definitions
 */
#define IEEE8021PBPNPROWSTATUS 1

enum
{
	/* enums for column ieee8021PbPnpRowStatus */
	ieee8021PbPnpRowStatus_active_c = 1,
	ieee8021PbPnpRowStatus_notInService_c = 2,
	ieee8021PbPnpRowStatus_notReady_c = 3,
	ieee8021PbPnpRowStatus_createAndGo_c = 4,
	ieee8021PbPnpRowStatus_createAndWait_c = 5,
	ieee8021PbPnpRowStatus_destroy_c = 6,
};

/* table ieee8021PbPnpTable row entry data structure */
typedef struct ieee8021PbPnpEntry_t
{
	/* Index values */
	uint32_t u32BridgeBasePortComponentId;
	uint32_t u32BridgeBasePort;
	
	/* Column values */
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} ieee8021PbPnpEntry_t;

extern xBTree_t oIeee8021PbPnpTable_BTree;

/* ieee8021PbPnpTable table mapper */
void ieee8021PbPnpTable_init (void);
ieee8021PbPnpEntry_t * ieee8021PbPnpTable_createEntry (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort);
ieee8021PbPnpEntry_t * ieee8021PbPnpTable_getByIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort);
ieee8021PbPnpEntry_t * ieee8021PbPnpTable_getNextIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort);
void ieee8021PbPnpTable_removeEntry (ieee8021PbPnpEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021PbPnpTable_getFirst;
Netsnmp_Next_Data_Point ieee8021PbPnpTable_getNext;
Netsnmp_Get_Data_Point ieee8021PbPnpTable_get;
Netsnmp_Node_Handler ieee8021PbPnpTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021PbCepTable definitions
 */
#define IEEE8021PBCEPCCOMPONENTID 1
#define IEEE8021PBCEPCEPPORTNUMBER 2
#define IEEE8021PBCEPROWSTATUS 3

enum
{
	/* enums for column ieee8021PbCepRowStatus */
	ieee8021PbCepRowStatus_active_c = 1,
	ieee8021PbCepRowStatus_notInService_c = 2,
	ieee8021PbCepRowStatus_notReady_c = 3,
	ieee8021PbCepRowStatus_createAndGo_c = 4,
	ieee8021PbCepRowStatus_createAndWait_c = 5,
	ieee8021PbCepRowStatus_destroy_c = 6,
};

/* table ieee8021PbCepTable row entry data structure */
typedef struct ieee8021PbCepEntry_t
{
	/* Index values */
	uint32_t u32BridgeBasePortComponentId;
	uint32_t u32BridgeBasePort;
	
	/* Column values */
	uint32_t u32CComponentId;
	uint32_t u32CepPortNumber;
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} ieee8021PbCepEntry_t;

extern xBTree_t oIeee8021PbCepTable_BTree;

/* ieee8021PbCepTable table mapper */
void ieee8021PbCepTable_init (void);
ieee8021PbCepEntry_t * ieee8021PbCepTable_createEntry (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort);
ieee8021PbCepEntry_t * ieee8021PbCepTable_getByIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort);
ieee8021PbCepEntry_t * ieee8021PbCepTable_getNextIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort);
void ieee8021PbCepTable_removeEntry (ieee8021PbCepEntry_t *poEntry);
ieee8021PbCepEntry_t * ieee8021PbCepTable_createExt (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort);
bool ieee8021PbCepTable_removeExt (ieee8021PbCepEntry_t *poEntry);
bool ieee8021PbCepTable_createHier (ieee8021PbCepEntry_t *poEntry);
bool ieee8021PbCepTable_removeHier (ieee8021PbCepEntry_t *poEntry);
bool ieee8021PbCepRowStatus_handler (
	ieee8021PbCepEntry_t *poEntry, uint8_t u8RowStatus);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021PbCepTable_getFirst;
Netsnmp_Next_Data_Point ieee8021PbCepTable_getNext;
Netsnmp_Get_Data_Point ieee8021PbCepTable_get;
Netsnmp_Node_Handler ieee8021PbCepTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021PbRcapTable definitions
 */
#define IEEE8021PBRCAPSCOMPONENTID 1
#define IEEE8021PBRCAPRCAPPORTNUMBER 2
#define IEEE8021PBRCAPROWSTATUS 3

enum
{
	/* enums for column ieee8021PbRcapRowStatus */
	ieee8021PbRcapRowStatus_active_c = 1,
	ieee8021PbRcapRowStatus_notInService_c = 2,
	ieee8021PbRcapRowStatus_notReady_c = 3,
	ieee8021PbRcapRowStatus_createAndGo_c = 4,
	ieee8021PbRcapRowStatus_createAndWait_c = 5,
	ieee8021PbRcapRowStatus_destroy_c = 6,
};

/* table ieee8021PbRcapTable row entry data structure */
typedef struct ieee8021PbRcapEntry_t
{
	/* Index values */
	uint32_t u32BridgeBasePortComponentId;
	uint32_t u32BridgeBasePort;
	
	/* Column values */
	uint32_t u32SComponentId;
	uint32_t u32RcapPortNumber;
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} ieee8021PbRcapEntry_t;

extern xBTree_t oIeee8021PbRcapTable_BTree;

/* ieee8021PbRcapTable table mapper */
void ieee8021PbRcapTable_init (void);
ieee8021PbRcapEntry_t * ieee8021PbRcapTable_createEntry (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort);
ieee8021PbRcapEntry_t * ieee8021PbRcapTable_getByIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort);
ieee8021PbRcapEntry_t * ieee8021PbRcapTable_getNextIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort);
void ieee8021PbRcapTable_removeEntry (ieee8021PbRcapEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021PbRcapTable_getFirst;
Netsnmp_Next_Data_Point ieee8021PbRcapTable_getNext;
Netsnmp_Get_Data_Point ieee8021PbRcapTable_get;
Netsnmp_Node_Handler ieee8021PbRcapTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021PbInternalInterfaceTable definitions
 */
#define IEEE8021PBIIEXTERNALSVID 1
#define IEEE8021PBIIINTERNALPORTNUMBER 2
#define IEEE8021PBIIINTERNALPORTTYPE 3
#define IEEE8021PBIIINTERNALSVID 4
#define IEEE8021PBIIROWSTATUS 5

enum
{
	/* enums for column ieee8021PbIiInternalPortType */
	ieee8021PbIiInternalPortType_none_c = 1,
	ieee8021PbIiInternalPortType_customerVlanPort_c = 2,
	ieee8021PbIiInternalPortType_providerNetworkPort_c = 3,
	ieee8021PbIiInternalPortType_customerNetworkPort_c = 4,
	ieee8021PbIiInternalPortType_customerEdgePort_c = 5,
	ieee8021PbIiInternalPortType_customerBackbonePort_c = 6,
	ieee8021PbIiInternalPortType_virtualInstancePort_c = 7,
	ieee8021PbIiInternalPortType_dBridgePort_c = 8,
	ieee8021PbIiInternalPortType_remoteCustomerAccessPort_c = 9,
	ieee8021PbIiInternalPortType_stationFacingBridgePort_c = 10,
	ieee8021PbIiInternalPortType_uplinkAccessPort_c = 11,
	ieee8021PbIiInternalPortType_uplinkRelayPort_c = 12,

	/* enums for column ieee8021PbIiRowStatus */
	ieee8021PbIiRowStatus_active_c = 1,
	ieee8021PbIiRowStatus_notInService_c = 2,
	ieee8021PbIiRowStatus_notReady_c = 3,
	ieee8021PbIiRowStatus_createAndGo_c = 4,
	ieee8021PbIiRowStatus_createAndWait_c = 5,
	ieee8021PbIiRowStatus_destroy_c = 6,
};

/* table ieee8021PbInternalInterfaceTable row entry data structure */
typedef struct ieee8021PbInternalInterfaceEntry_t
{
	/* Index values */
	uint32_t u32BridgeBasePortComponentId;
	uint32_t u32BridgeBasePort;
	int32_t i32PbIiExternalSVid;
	
	/* Column values */
	uint32_t u32PbIiInternalPortNumber;
	int32_t i32PbIiInternalPortType;
	int32_t i32PbIiInternalSVid;
	uint8_t u8PbIiRowStatus;
	
	xBTree_Node_t oBTreeNode;
} ieee8021PbInternalInterfaceEntry_t;

extern xBTree_t oIeee8021PbInternalInterfaceTable_BTree;

/* ieee8021PbInternalInterfaceTable table mapper */
void ieee8021PbInternalInterfaceTable_init (void);
ieee8021PbInternalInterfaceEntry_t * ieee8021PbInternalInterfaceTable_createEntry (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	int32_t i32PbIiExternalSVid);
ieee8021PbInternalInterfaceEntry_t * ieee8021PbInternalInterfaceTable_getByIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	int32_t i32PbIiExternalSVid);
ieee8021PbInternalInterfaceEntry_t * ieee8021PbInternalInterfaceTable_getNextIndex (
	uint32_t u32BridgeBasePortComponentId,
	uint32_t u32BridgeBasePort,
	int32_t i32PbIiExternalSVid);
void ieee8021PbInternalInterfaceTable_removeEntry (ieee8021PbInternalInterfaceEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021PbInternalInterfaceTable_getFirst;
Netsnmp_Next_Data_Point ieee8021PbInternalInterfaceTable_getNext;
Netsnmp_Get_Data_Point ieee8021PbInternalInterfaceTable_get;
Netsnmp_Node_Handler ieee8021PbInternalInterfaceTable_mapper;
#endif	/* SNMP_SRC */



#	ifdef __cplusplus
}
#	endif

#endif /* __IEEE8021PBMIB_H__ */
