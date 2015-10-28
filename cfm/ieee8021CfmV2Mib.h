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

#ifndef __IEEE8021CFMV2MIB_H__
#	define __IEEE8021CFMV2MIB_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include "lib/binaryTree.h"
#include "lib/snmp.h"

#define TOBE_REPLACED 1


/**
 *	agent MIB function
 */
void ieee8021CfmV2Mib_init (void);


/**
 *	table mapper(s)
 */
/**
 *	table ieee8021CfmStackTable definitions
 */
#define IEEE8021CFMSTACKIFINDEX 1
#define IEEE8021CFMSTACKSERVICESELECTORTYPE 2
#define IEEE8021CFMSTACKSERVICESELECTORORNONE 3
#define IEEE8021CFMSTACKMDLEVEL 4
#define IEEE8021CFMSTACKDIRECTION 5
#define IEEE8021CFMSTACKMDINDEX 6
#define IEEE8021CFMSTACKMAINDEX 7
#define IEEE8021CFMSTACKMEPID 8
#define IEEE8021CFMSTACKMACADDRESS 9

enum
{
	/* enums for column ieee8021CfmStackServiceSelectorType */
	ieee8021CfmStackServiceSelectorType_vlanId_c = 1,
	ieee8021CfmStackServiceSelectorType_isid_c = 2,
	ieee8021CfmStackServiceSelectorType_tesid_c = 3,
	ieee8021CfmStackServiceSelectorType_segid_c = 4,

	/* enums for column ieee8021CfmStackDirection */
	ieee8021CfmStackDirection_down_c = 1,
	ieee8021CfmStackDirection_up_c = 2,
};

/* table ieee8021CfmStackTable row entry data structure */
typedef struct ieee8021CfmStackEntry_t
{
	/* Index values */
	uint32_t u32IfIndex;
	int32_t i32ServiceSelectorType;
	uint32_t u32ServiceSelectorOrNone;
	int32_t i32MdLevel;
	int32_t i32Direction;
	
	/* Column values */
	uint32_t u32MdIndex;
	uint32_t u32MaIndex;
	uint32_t u32MepId;
	uint8_t au8MacAddress[6];
	size_t u16MacAddress_len;	/* # of uint8_t elements */
	
	xBTree_Node_t oBTreeNode;
} ieee8021CfmStackEntry_t;

extern xBTree_t oIeee8021CfmStackTable_BTree;

/* ieee8021CfmStackTable table mapper */
void ieee8021CfmStackTable_init (void);
ieee8021CfmStackEntry_t * ieee8021CfmStackTable_createEntry (
	uint32_t u32IfIndex,
	int32_t i32ServiceSelectorType,
	uint32_t u32ServiceSelectorOrNone,
	int32_t i32MdLevel,
	int32_t i32Direction);
ieee8021CfmStackEntry_t * ieee8021CfmStackTable_getByIndex (
	uint32_t u32IfIndex,
	int32_t i32ServiceSelectorType,
	uint32_t u32ServiceSelectorOrNone,
	int32_t i32MdLevel,
	int32_t i32Direction);
ieee8021CfmStackEntry_t * ieee8021CfmStackTable_getNextIndex (
	uint32_t u32IfIndex,
	int32_t i32ServiceSelectorType,
	uint32_t u32ServiceSelectorOrNone,
	int32_t i32MdLevel,
	int32_t i32Direction);
void ieee8021CfmStackTable_removeEntry (ieee8021CfmStackEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021CfmStackTable_getFirst;
Netsnmp_Next_Data_Point ieee8021CfmStackTable_getNext;
Netsnmp_Get_Data_Point ieee8021CfmStackTable_get;
Netsnmp_Node_Handler ieee8021CfmStackTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021CfmDefaultMdTable definitions
 */
#define IEEE8021CFMDEFAULTMDCOMPONENTID 1
#define IEEE8021CFMDEFAULTMDPRIMARYSELECTORTYPE 2
#define IEEE8021CFMDEFAULTMDPRIMARYSELECTOR 3
#define IEEE8021CFMDEFAULTMDSTATUS 4
#define IEEE8021CFMDEFAULTMDLEVEL 5
#define IEEE8021CFMDEFAULTMDMHFCREATION 6
#define IEEE8021CFMDEFAULTMDIDPERMISSION 7

enum
{
	/* enums for column ieee8021CfmDefaultMdPrimarySelectorType */
	ieee8021CfmDefaultMdPrimarySelectorType_vlanId_c = 1,
	ieee8021CfmDefaultMdPrimarySelectorType_isid_c = 2,
	ieee8021CfmDefaultMdPrimarySelectorType_tesid_c = 3,
	ieee8021CfmDefaultMdPrimarySelectorType_segid_c = 4,

	/* enums for column ieee8021CfmDefaultMdStatus */
	ieee8021CfmDefaultMdStatus_true_c = 1,
	ieee8021CfmDefaultMdStatus_false_c = 2,

	/* enums for column ieee8021CfmDefaultMdMhfCreation */
	ieee8021CfmDefaultMdMhfCreation_defMHFnone_c = 1,
	ieee8021CfmDefaultMdMhfCreation_defMHFdefault_c = 2,
	ieee8021CfmDefaultMdMhfCreation_defMHFexplicit_c = 3,
	ieee8021CfmDefaultMdMhfCreation_defMHFdefer_c = 4,

	/* enums for column ieee8021CfmDefaultMdIdPermission */
	ieee8021CfmDefaultMdIdPermission_sendIdNone_c = 1,
	ieee8021CfmDefaultMdIdPermission_sendIdChassis_c = 2,
	ieee8021CfmDefaultMdIdPermission_sendIdManage_c = 3,
	ieee8021CfmDefaultMdIdPermission_sendIdChassisManage_c = 4,
	ieee8021CfmDefaultMdIdPermission_sendIdDefer_c = 5,
};

/* table ieee8021CfmDefaultMdTable row entry data structure */
typedef struct ieee8021CfmDefaultMdEntry_t
{
	/* Index values */
	uint32_t u32ComponentId;
	int32_t i32PrimarySelectorType;
	uint32_t u32PrimarySelector;
	
	/* Column values */
	int32_t i32Status;
	int32_t i32Level;
	int32_t i32MhfCreation;
	int32_t i32IdPermission;
	
	xBTree_Node_t oBTreeNode;
} ieee8021CfmDefaultMdEntry_t;

extern xBTree_t oIeee8021CfmDefaultMdTable_BTree;

/* ieee8021CfmDefaultMdTable table mapper */
void ieee8021CfmDefaultMdTable_init (void);
ieee8021CfmDefaultMdEntry_t * ieee8021CfmDefaultMdTable_createEntry (
	uint32_t u32ComponentId,
	int32_t i32PrimarySelectorType,
	uint32_t u32PrimarySelector);
ieee8021CfmDefaultMdEntry_t * ieee8021CfmDefaultMdTable_getByIndex (
	uint32_t u32ComponentId,
	int32_t i32PrimarySelectorType,
	uint32_t u32PrimarySelector);
ieee8021CfmDefaultMdEntry_t * ieee8021CfmDefaultMdTable_getNextIndex (
	uint32_t u32ComponentId,
	int32_t i32PrimarySelectorType,
	uint32_t u32PrimarySelector);
void ieee8021CfmDefaultMdTable_removeEntry (ieee8021CfmDefaultMdEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021CfmDefaultMdTable_getFirst;
Netsnmp_Next_Data_Point ieee8021CfmDefaultMdTable_getNext;
Netsnmp_Get_Data_Point ieee8021CfmDefaultMdTable_get;
Netsnmp_Node_Handler ieee8021CfmDefaultMdTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021CfmVlanTable definitions
 */
#define IEEE8021CFMVLANCOMPONENTID 1
#define IEEE8021CFMVLANSELECTOR 3
#define IEEE8021CFMVLANPRIMARYSELECTOR 5
#define IEEE8021CFMVLANROWSTATUS 6

enum
{
	/* enums for column ieee8021CfmVlanRowStatus */
	ieee8021CfmVlanRowStatus_active_c = 1,
	ieee8021CfmVlanRowStatus_notInService_c = 2,
	ieee8021CfmVlanRowStatus_notReady_c = 3,
	ieee8021CfmVlanRowStatus_createAndGo_c = 4,
	ieee8021CfmVlanRowStatus_createAndWait_c = 5,
	ieee8021CfmVlanRowStatus_destroy_c = 6,
};

/* table ieee8021CfmVlanTable row entry data structure */
typedef struct ieee8021CfmVlanEntry_t
{
	/* Index values */
	uint32_t u32ComponentId;
	uint32_t u32Selector;
	
	/* Column values */
	uint32_t u32PrimarySelector;
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} ieee8021CfmVlanEntry_t;

extern xBTree_t oIeee8021CfmVlanTable_BTree;

/* ieee8021CfmVlanTable table mapper */
void ieee8021CfmVlanTable_init (void);
ieee8021CfmVlanEntry_t * ieee8021CfmVlanTable_createEntry (
	uint32_t u32ComponentId,
	uint32_t u32Selector);
ieee8021CfmVlanEntry_t * ieee8021CfmVlanTable_getByIndex (
	uint32_t u32ComponentId,
	uint32_t u32Selector);
ieee8021CfmVlanEntry_t * ieee8021CfmVlanTable_getNextIndex (
	uint32_t u32ComponentId,
	uint32_t u32Selector);
void ieee8021CfmVlanTable_removeEntry (ieee8021CfmVlanEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021CfmVlanTable_getFirst;
Netsnmp_Next_Data_Point ieee8021CfmVlanTable_getNext;
Netsnmp_Get_Data_Point ieee8021CfmVlanTable_get;
Netsnmp_Node_Handler ieee8021CfmVlanTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021CfmConfigErrorListTable definitions
 */
#define IEEE8021CFMCONFIGERRORLISTSELECTORTYPE 1
#define IEEE8021CFMCONFIGERRORLISTSELECTOR 2
#define IEEE8021CFMCONFIGERRORLISTIFINDEX 3
#define IEEE8021CFMCONFIGERRORLISTERRORTYPE 4

enum
{
	/* enums for column ieee8021CfmConfigErrorListSelectorType */
	ieee8021CfmConfigErrorListSelectorType_vlanId_c = 1,
	ieee8021CfmConfigErrorListSelectorType_isid_c = 2,
	ieee8021CfmConfigErrorListSelectorType_tesid_c = 3,
	ieee8021CfmConfigErrorListSelectorType_segid_c = 4,

	/* enums for column ieee8021CfmConfigErrorListErrorType */
	ieee8021CfmConfigErrorListErrorType_cfmLeak_c = 0,
	ieee8021CfmConfigErrorListErrorType_conflictingVids_c = 1,
	ieee8021CfmConfigErrorListErrorType_excessiveLevels_c = 2,
	ieee8021CfmConfigErrorListErrorType_overlappedLevels_c = 3,
};

/* table ieee8021CfmConfigErrorListTable row entry data structure */
typedef struct ieee8021CfmConfigErrorListEntry_t
{
	/* Index values */
	int32_t i32SelectorType;
	uint32_t u32Selector;
	uint32_t u32IfIndex;
	
	/* Column values */
	uint8_t au8ErrorType[1];
	size_t u16ErrorType_len;	/* # of uint8_t elements */
	
	xBTree_Node_t oBTreeNode;
} ieee8021CfmConfigErrorListEntry_t;

extern xBTree_t oIeee8021CfmConfigErrorListTable_BTree;

/* ieee8021CfmConfigErrorListTable table mapper */
void ieee8021CfmConfigErrorListTable_init (void);
ieee8021CfmConfigErrorListEntry_t * ieee8021CfmConfigErrorListTable_createEntry (
	int32_t i32SelectorType,
	uint32_t u32Selector,
	uint32_t u32IfIndex);
ieee8021CfmConfigErrorListEntry_t * ieee8021CfmConfigErrorListTable_getByIndex (
	int32_t i32SelectorType,
	uint32_t u32Selector,
	uint32_t u32IfIndex);
ieee8021CfmConfigErrorListEntry_t * ieee8021CfmConfigErrorListTable_getNextIndex (
	int32_t i32SelectorType,
	uint32_t u32Selector,
	uint32_t u32IfIndex);
void ieee8021CfmConfigErrorListTable_removeEntry (ieee8021CfmConfigErrorListEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021CfmConfigErrorListTable_getFirst;
Netsnmp_Next_Data_Point ieee8021CfmConfigErrorListTable_getNext;
Netsnmp_Get_Data_Point ieee8021CfmConfigErrorListTable_get;
Netsnmp_Node_Handler ieee8021CfmConfigErrorListTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table ieee8021CfmMaCompTable definitions
 */
#define IEEE8021CFMMACOMPONENTID 1
#define IEEE8021CFMMACOMPPRIMARYSELECTORTYPE 2
#define IEEE8021CFMMACOMPPRIMARYSELECTORORNONE 3
#define IEEE8021CFMMACOMPMHFCREATION 4
#define IEEE8021CFMMACOMPIDPERMISSION 5
#define IEEE8021CFMMACOMPNUMBEROFVIDS 6
#define IEEE8021CFMMACOMPROWSTATUS 7

enum
{
	/* enums for column ieee8021CfmMaCompPrimarySelectorType */
	ieee8021CfmMaCompPrimarySelectorType_vlanId_c = 1,
	ieee8021CfmMaCompPrimarySelectorType_isid_c = 2,
	ieee8021CfmMaCompPrimarySelectorType_tesid_c = 3,
	ieee8021CfmMaCompPrimarySelectorType_segid_c = 4,

	/* enums for column ieee8021CfmMaCompMhfCreation */
	ieee8021CfmMaCompMhfCreation_defMHFnone_c = 1,
	ieee8021CfmMaCompMhfCreation_defMHFdefault_c = 2,
	ieee8021CfmMaCompMhfCreation_defMHFexplicit_c = 3,
	ieee8021CfmMaCompMhfCreation_defMHFdefer_c = 4,

	/* enums for column ieee8021CfmMaCompIdPermission */
	ieee8021CfmMaCompIdPermission_sendIdNone_c = 1,
	ieee8021CfmMaCompIdPermission_sendIdChassis_c = 2,
	ieee8021CfmMaCompIdPermission_sendIdManage_c = 3,
	ieee8021CfmMaCompIdPermission_sendIdChassisManage_c = 4,
	ieee8021CfmMaCompIdPermission_sendIdDefer_c = 5,

	/* enums for column ieee8021CfmMaCompRowStatus */
	ieee8021CfmMaCompRowStatus_active_c = 1,
	ieee8021CfmMaCompRowStatus_notInService_c = 2,
	ieee8021CfmMaCompRowStatus_notReady_c = 3,
	ieee8021CfmMaCompRowStatus_createAndGo_c = 4,
	ieee8021CfmMaCompRowStatus_createAndWait_c = 5,
	ieee8021CfmMaCompRowStatus_destroy_c = 6,
};

/* table ieee8021CfmMaCompTable row entry data structure */
typedef struct ieee8021CfmMaCompEntry_t
{
	/* Index values */
	uint32_t u32ComponentId;
	uint32_t u32Dot1agCfmMdIndex;
	uint32_t u32Dot1agCfmMaIndex;
	
	/* Column values */
	int32_t i32PrimarySelectorType;
	uint32_t u32PrimarySelectorOrNone;
	int32_t i32MhfCreation;
	int32_t i32IdPermission;
	uint32_t u32NumberOfVids;
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} ieee8021CfmMaCompEntry_t;

extern xBTree_t oIeee8021CfmMaCompTable_BTree;

/* ieee8021CfmMaCompTable table mapper */
void ieee8021CfmMaCompTable_init (void);
ieee8021CfmMaCompEntry_t * ieee8021CfmMaCompTable_createEntry (
	uint32_t u32ComponentId,
	uint32_t u32Dot1agCfmMdIndex,
	uint32_t u32Dot1agCfmMaIndex);
ieee8021CfmMaCompEntry_t * ieee8021CfmMaCompTable_getByIndex (
	uint32_t u32ComponentId,
	uint32_t u32Dot1agCfmMdIndex,
	uint32_t u32Dot1agCfmMaIndex);
ieee8021CfmMaCompEntry_t * ieee8021CfmMaCompTable_getNextIndex (
	uint32_t u32ComponentId,
	uint32_t u32Dot1agCfmMdIndex,
	uint32_t u32Dot1agCfmMaIndex);
void ieee8021CfmMaCompTable_removeEntry (ieee8021CfmMaCompEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point ieee8021CfmMaCompTable_getFirst;
Netsnmp_Next_Data_Point ieee8021CfmMaCompTable_getNext;
Netsnmp_Get_Data_Point ieee8021CfmMaCompTable_get;
Netsnmp_Node_Handler ieee8021CfmMaCompTable_mapper;
#endif	/* SNMP_SRC */



#	ifdef __cplusplus
}
#	endif

#endif /* __IEEE8021CFMV2MIB_H__ */
