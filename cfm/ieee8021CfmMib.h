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

#ifndef __IEEE8021CFMMIB_H__
#	define __IEEE8021CFMMIB_H__

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
void ieee8021CfmMib_init (void);


/**
 *	scalar mapper(s)
 */
/** definitions for scalar(s) of dot1agCfmDefaultMd **/
#define DOT1AGCFMDEFAULTMDDEFLEVEL 1
#define DOT1AGCFMDEFAULTMDDEFMHFCREATION 2
#define DOT1AGCFMDEFAULTMDDEFIDPERMISSION 3

enum
{
	/* enums for scalar dot1agCfmDefaultMdDefMhfCreation */
	dot1agCfmDefaultMdDefMhfCreation_defMHFnone_c = 1,
	dot1agCfmDefaultMdDefMhfCreation_defMHFdefault_c = 2,
	dot1agCfmDefaultMdDefMhfCreation_defMHFexplicit_c = 3,

	/* enums for scalar dot1agCfmDefaultMdDefIdPermission */
	dot1agCfmDefaultMdDefIdPermission_sendIdNone_c = 1,
	dot1agCfmDefaultMdDefIdPermission_sendIdChassis_c = 2,
	dot1agCfmDefaultMdDefIdPermission_sendIdManage_c = 3,
	dot1agCfmDefaultMdDefIdPermission_sendIdChassisManage_c = 4,
};

typedef struct dot1agCfmDefaultMd_t
{
	int32_t i32DefLevel;
	int32_t i32DefMhfCreation;
	int32_t i32DefIdPermission;
} dot1agCfmDefaultMd_t;

extern dot1agCfmDefaultMd_t oDot1agCfmDefaultMd;

#ifdef SNMP_SRC
Netsnmp_Node_Handler dot1agCfmDefaultMd_mapper;
#endif	/* SNMP_SRC */

/** definitions for scalar(s) of dot1agCfmMd **/
#define DOT1AGCFMMDTABLENEXTINDEX 1

typedef struct dot1agCfmMd_t
{
	uint32_t u32TableNextIndex;
} dot1agCfmMd_t;

extern dot1agCfmMd_t oDot1agCfmMd;

#ifdef SNMP_SRC
Netsnmp_Node_Handler dot1agCfmMd_mapper;
#endif	/* SNMP_SRC */



/**
 *	table mapper(s)
 */
/**
 *	table dot1agCfmMdTable definitions
 */
#define DOT1AGCFMMDINDEX 1
#define DOT1AGCFMMDFORMAT 2
#define DOT1AGCFMMDNAME 3
#define DOT1AGCFMMDMDLEVEL 4
#define DOT1AGCFMMDMHFCREATION 5
#define DOT1AGCFMMDMHFIDPERMISSION 6
#define DOT1AGCFMMDMANEXTINDEX 7
#define DOT1AGCFMMDROWSTATUS 8

enum
{
	/* enums for column dot1agCfmMdFormat */
	dot1agCfmMdFormat_none_c = 1,
	dot1agCfmMdFormat_dnsLikeName_c = 2,
	dot1agCfmMdFormat_macAddressAndUint_c = 3,
	dot1agCfmMdFormat_charString_c = 4,

	/* enums for column dot1agCfmMdMhfCreation */
	dot1agCfmMdMhfCreation_defMHFnone_c = 1,
	dot1agCfmMdMhfCreation_defMHFdefault_c = 2,
	dot1agCfmMdMhfCreation_defMHFexplicit_c = 3,

	/* enums for column dot1agCfmMdMhfIdPermission */
	dot1agCfmMdMhfIdPermission_sendIdNone_c = 1,
	dot1agCfmMdMhfIdPermission_sendIdChassis_c = 2,
	dot1agCfmMdMhfIdPermission_sendIdManage_c = 3,
	dot1agCfmMdMhfIdPermission_sendIdChassisManage_c = 4,

	/* enums for column dot1agCfmMdRowStatus */
	dot1agCfmMdRowStatus_active_c = 1,
	dot1agCfmMdRowStatus_notInService_c = 2,
	dot1agCfmMdRowStatus_notReady_c = 3,
	dot1agCfmMdRowStatus_createAndGo_c = 4,
	dot1agCfmMdRowStatus_createAndWait_c = 5,
	dot1agCfmMdRowStatus_destroy_c = 6,
};

/* table dot1agCfmMdTable row entry data structure */
typedef struct dot1agCfmMdEntry_t
{
	/* Index values */
	uint32_t u32Index;
	
	/* Column values */
	int32_t i32Format;
	uint8_t au8Name[43];
	size_t u16Name_len;	/* # of uint8_t elements */
	int32_t i32MdLevel;
	int32_t i32MhfCreation;
	int32_t i32MhfIdPermission;
	uint32_t u32MaNextIndex;
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} dot1agCfmMdEntry_t;

extern xBTree_t oDot1agCfmMdTable_BTree;

/* dot1agCfmMdTable table mapper */
void dot1agCfmMdTable_init (void);
dot1agCfmMdEntry_t * dot1agCfmMdTable_createEntry (
	uint32_t u32Index);
dot1agCfmMdEntry_t * dot1agCfmMdTable_getByIndex (
	uint32_t u32Index);
dot1agCfmMdEntry_t * dot1agCfmMdTable_getNextIndex (
	uint32_t u32Index);
void dot1agCfmMdTable_removeEntry (dot1agCfmMdEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point dot1agCfmMdTable_getFirst;
Netsnmp_Next_Data_Point dot1agCfmMdTable_getNext;
Netsnmp_Get_Data_Point dot1agCfmMdTable_get;
Netsnmp_Node_Handler dot1agCfmMdTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table dot1agCfmMaNetTable definitions
 */
#define DOT1AGCFMMAINDEX 1
#define DOT1AGCFMMANETFORMAT 2
#define DOT1AGCFMMANETNAME 3
#define DOT1AGCFMMANETCCMINTERVAL 4
#define DOT1AGCFMMANETROWSTATUS 5

enum
{
	/* enums for column dot1agCfmMaNetFormat */
	dot1agCfmMaNetFormat_primaryVid_c = 1,
	dot1agCfmMaNetFormat_charString_c = 2,
	dot1agCfmMaNetFormat_unsignedInt16_c = 3,
	dot1agCfmMaNetFormat_rfc2865VpnId_c = 4,
	dot1agCfmMaNetFormat_ICCformat_c = 32,

	/* enums for column dot1agCfmMaNetCcmInterval */
	dot1agCfmMaNetCcmInterval_intervalInvalid_c = 0,
	dot1agCfmMaNetCcmInterval_interval300Hz_c = 1,
	dot1agCfmMaNetCcmInterval_interval10ms_c = 2,
	dot1agCfmMaNetCcmInterval_interval100ms_c = 3,
	dot1agCfmMaNetCcmInterval_interval1s_c = 4,
	dot1agCfmMaNetCcmInterval_interval10s_c = 5,
	dot1agCfmMaNetCcmInterval_interval1min_c = 6,
	dot1agCfmMaNetCcmInterval_interval10min_c = 7,

	/* enums for column dot1agCfmMaNetRowStatus */
	dot1agCfmMaNetRowStatus_active_c = 1,
	dot1agCfmMaNetRowStatus_notInService_c = 2,
	dot1agCfmMaNetRowStatus_notReady_c = 3,
	dot1agCfmMaNetRowStatus_createAndGo_c = 4,
	dot1agCfmMaNetRowStatus_createAndWait_c = 5,
	dot1agCfmMaNetRowStatus_destroy_c = 6,
};

/* table dot1agCfmMaNetTable row entry data structure */
typedef struct dot1agCfmMaNetEntry_t
{
	/* Index values */
	uint32_t u32MdIndex;
	uint32_t u32Index;
	
	/* Column values */
	int32_t i32Format;
	uint8_t au8Name[48];
	size_t u16Name_len;	/* # of uint8_t elements */
	int32_t i32CcmInterval;
	uint8_t u8RowStatus;
	
	uint8_t b3MdLevel: 3;
	uint8_t b2MhfCreation: 2;
	uint8_t b2MhfIdPermission: 2;
	
	xBTree_Node_t oBTreeNode;
	xBTree_Node_t oMeg_BTreeNode;
} dot1agCfmMaNetEntry_t;

extern xBTree_t oDot1agCfmMaNetTable_BTree;
extern xBTree_t oDot1agCfmMaNetTable_Meg_BTree;

/* dot1agCfmMaNetTable table mapper */
void dot1agCfmMaNetTable_init (void);
dot1agCfmMaNetEntry_t * dot1agCfmMaNetTable_createEntry (
	uint32_t u32MdIndex,
	uint32_t u32Index);
dot1agCfmMaNetEntry_t * dot1agCfmMaNetTable_getByIndex (
	uint32_t u32MdIndex,
	uint32_t u32Index);
dot1agCfmMaNetEntry_t * dot1agCfmMaNetTable_getNextIndex (
	uint32_t u32MdIndex,
	uint32_t u32Index);
void dot1agCfmMaNetTable_removeEntry (dot1agCfmMaNetEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point dot1agCfmMaNetTable_getFirst;
Netsnmp_Next_Data_Point dot1agCfmMaNetTable_getNext;
Netsnmp_Get_Data_Point dot1agCfmMaNetTable_get;
Netsnmp_Node_Handler dot1agCfmMaNetTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table dot1agCfmMaMepListTable definitions
 */
#define DOT1AGCFMMAMEPLISTIDENTIFIER 1
#define DOT1AGCFMMAMEPLISTROWSTATUS 2

enum
{
	/* enums for column dot1agCfmMaMepListRowStatus */
	dot1agCfmMaMepListRowStatus_active_c = 1,
	dot1agCfmMaMepListRowStatus_notInService_c = 2,
	dot1agCfmMaMepListRowStatus_notReady_c = 3,
	dot1agCfmMaMepListRowStatus_createAndGo_c = 4,
	dot1agCfmMaMepListRowStatus_createAndWait_c = 5,
	dot1agCfmMaMepListRowStatus_destroy_c = 6,
};

/* table dot1agCfmMaMepListTable row entry data structure */
typedef struct dot1agCfmMaMepListEntry_t
{
	/* Index values */
	uint32_t u32MdIndex;
	uint32_t u32MaIndex;
	uint32_t u32Identifier;
	
	/* Column values */
	uint8_t u8RowStatus;
	
	xBTree_Node_t oBTreeNode;
} dot1agCfmMaMepListEntry_t;

extern xBTree_t oDot1agCfmMaMepListTable_BTree;

/* dot1agCfmMaMepListTable table mapper */
void dot1agCfmMaMepListTable_init (void);
dot1agCfmMaMepListEntry_t * dot1agCfmMaMepListTable_createEntry (
	uint32_t u32MdIndex,
	uint32_t u32MaIndex,
	uint32_t u32Identifier);
dot1agCfmMaMepListEntry_t * dot1agCfmMaMepListTable_getByIndex (
	uint32_t u32MdIndex,
	uint32_t u32MaIndex,
	uint32_t u32Identifier);
dot1agCfmMaMepListEntry_t * dot1agCfmMaMepListTable_getNextIndex (
	uint32_t u32MdIndex,
	uint32_t u32MaIndex,
	uint32_t u32Identifier);
void dot1agCfmMaMepListTable_removeEntry (dot1agCfmMaMepListEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point dot1agCfmMaMepListTable_getFirst;
Netsnmp_Next_Data_Point dot1agCfmMaMepListTable_getNext;
Netsnmp_Get_Data_Point dot1agCfmMaMepListTable_get;
Netsnmp_Node_Handler dot1agCfmMaMepListTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table dot1agCfmMepTable definitions
 */
#define DOT1AGCFMMEPIDENTIFIER 1
#define DOT1AGCFMMEPIFINDEX 2
#define DOT1AGCFMMEPDIRECTION 3
#define DOT1AGCFMMEPPRIMARYVID 4
#define DOT1AGCFMMEPACTIVE 5
#define DOT1AGCFMMEPFNGSTATE 6
#define DOT1AGCFMMEPCCIENABLED 7
#define DOT1AGCFMMEPCCMLTMPRIORITY 8
#define DOT1AGCFMMEPMACADDRESS 9
#define DOT1AGCFMMEPLOWPRDEF 10
#define DOT1AGCFMMEPFNGALARMTIME 11
#define DOT1AGCFMMEPFNGRESETTIME 12
#define DOT1AGCFMMEPHIGHESTPRDEFECT 13
#define DOT1AGCFMMEPDEFECTS 14
#define DOT1AGCFMMEPERRORCCMLASTFAILURE 15
#define DOT1AGCFMMEPXCONCCMLASTFAILURE 16
#define DOT1AGCFMMEPCCMSEQUENCEERRORS 17
#define DOT1AGCFMMEPCCISENTCCMS 18
#define DOT1AGCFMMEPNEXTLBMTRANSID 19
#define DOT1AGCFMMEPLBRIN 20
#define DOT1AGCFMMEPLBRINOUTOFORDER 21
#define DOT1AGCFMMEPLBRBADMSDU 22
#define DOT1AGCFMMEPLTMNEXTSEQNUMBER 23
#define DOT1AGCFMMEPUNEXPLTRIN 24
#define DOT1AGCFMMEPLBROUT 25
#define DOT1AGCFMMEPTRANSMITLBMSTATUS 26
#define DOT1AGCFMMEPTRANSMITLBMDESTMACADDRESS 27
#define DOT1AGCFMMEPTRANSMITLBMDESTMEPID 28
#define DOT1AGCFMMEPTRANSMITLBMDESTISMEPID 29
#define DOT1AGCFMMEPTRANSMITLBMMESSAGES 30
#define DOT1AGCFMMEPTRANSMITLBMDATATLV 31
#define DOT1AGCFMMEPTRANSMITLBMVLANPRIORITY 32
#define DOT1AGCFMMEPTRANSMITLBMVLANDROPENABLE 33
#define DOT1AGCFMMEPTRANSMITLBMRESULTOK 34
#define DOT1AGCFMMEPTRANSMITLBMSEQNUMBER 35
#define DOT1AGCFMMEPTRANSMITLTMSTATUS 36
#define DOT1AGCFMMEPTRANSMITLTMFLAGS 37
#define DOT1AGCFMMEPTRANSMITLTMTARGETMACADDRESS 38
#define DOT1AGCFMMEPTRANSMITLTMTARGETMEPID 39
#define DOT1AGCFMMEPTRANSMITLTMTARGETISMEPID 40
#define DOT1AGCFMMEPTRANSMITLTMTTL 41
#define DOT1AGCFMMEPTRANSMITLTMRESULT 42
#define DOT1AGCFMMEPTRANSMITLTMSEQNUMBER 43
#define DOT1AGCFMMEPTRANSMITLTMEGRESSIDENTIFIER 44
#define DOT1AGCFMMEPROWSTATUS 45
#define DOT1AGCFMMEPPBBTECANREPORTPBBTEPRESENCE 46
#define DOT1AGCFMMEPPBBTETRAFFICMISMATCHDEFECT 47
#define DOT1AGCFMMEPPBBTRANSMITLBMLTMREVERSEVID 48
#define DOT1AGCFMMEPPBBTEMISMATCHALARM 49
#define DOT1AGCFMMEPPBBTELOCALMISMATCHDEFECT 50
#define DOT1AGCFMMEPPBBTEMISMATCHSINCERESET 51

enum
{
	/* enums for column dot1agCfmMepDirection */
	dot1agCfmMepDirection_down_c = 1,
	dot1agCfmMepDirection_up_c = 2,

	/* enums for column dot1agCfmMepActive */
	dot1agCfmMepActive_true_c = 1,
	dot1agCfmMepActive_false_c = 2,

	/* enums for column dot1agCfmMepFngState */
	dot1agCfmMepFngState_fngReset_c = 1,
	dot1agCfmMepFngState_fngDefect_c = 2,
	dot1agCfmMepFngState_fngReportDefect_c = 3,
	dot1agCfmMepFngState_fngDefectReported_c = 4,
	dot1agCfmMepFngState_fngDefectClearing_c = 5,

	/* enums for column dot1agCfmMepCciEnabled */
	dot1agCfmMepCciEnabled_true_c = 1,
	dot1agCfmMepCciEnabled_false_c = 2,

	/* enums for column dot1agCfmMepLowPrDef */
	dot1agCfmMepLowPrDef_allDef_c = 1,
	dot1agCfmMepLowPrDef_macRemErrXcon_c = 2,
	dot1agCfmMepLowPrDef_remErrXcon_c = 3,
	dot1agCfmMepLowPrDef_errXcon_c = 4,
	dot1agCfmMepLowPrDef_xcon_c = 5,
	dot1agCfmMepLowPrDef_noXcon_c = 6,

	/* enums for column dot1agCfmMepHighestPrDefect */
	dot1agCfmMepHighestPrDefect_none_c = 0,
	dot1agCfmMepHighestPrDefect_defRDICCM_c = 1,
	dot1agCfmMepHighestPrDefect_defMACstatus_c = 2,
	dot1agCfmMepHighestPrDefect_defRemoteCCM_c = 3,
	dot1agCfmMepHighestPrDefect_defErrorCCM_c = 4,
	dot1agCfmMepHighestPrDefect_defXconCCM_c = 5,

	/* enums for column dot1agCfmMepDefects */
	dot1agCfmMepDefects_bDefRDICCM_c = 0,
	dot1agCfmMepDefects_bDefMACstatus_c = 1,
	dot1agCfmMepDefects_bDefRemoteCCM_c = 2,
	dot1agCfmMepDefects_bDefErrorCCM_c = 3,
	dot1agCfmMepDefects_bDefXconCCM_c = 4,

	/* enums for column dot1agCfmMepTransmitLbmStatus */
	dot1agCfmMepTransmitLbmStatus_true_c = 1,
	dot1agCfmMepTransmitLbmStatus_false_c = 2,

	/* enums for column dot1agCfmMepTransmitLbmDestIsMepId */
	dot1agCfmMepTransmitLbmDestIsMepId_true_c = 1,
	dot1agCfmMepTransmitLbmDestIsMepId_false_c = 2,

	/* enums for column dot1agCfmMepTransmitLbmVlanDropEnable */
	dot1agCfmMepTransmitLbmVlanDropEnable_true_c = 1,
	dot1agCfmMepTransmitLbmVlanDropEnable_false_c = 2,

	/* enums for column dot1agCfmMepTransmitLbmResultOK */
	dot1agCfmMepTransmitLbmResultOK_true_c = 1,
	dot1agCfmMepTransmitLbmResultOK_false_c = 2,

	/* enums for column dot1agCfmMepTransmitLtmStatus */
	dot1agCfmMepTransmitLtmStatus_true_c = 1,
	dot1agCfmMepTransmitLtmStatus_false_c = 2,

	/* enums for column dot1agCfmMepTransmitLtmFlags */
	dot1agCfmMepTransmitLtmFlags_useFDBonly_c = 0,

	/* enums for column dot1agCfmMepTransmitLtmTargetIsMepId */
	dot1agCfmMepTransmitLtmTargetIsMepId_true_c = 1,
	dot1agCfmMepTransmitLtmTargetIsMepId_false_c = 2,

	/* enums for column dot1agCfmMepTransmitLtmResult */
	dot1agCfmMepTransmitLtmResult_true_c = 1,
	dot1agCfmMepTransmitLtmResult_false_c = 2,

	/* enums for column dot1agCfmMepRowStatus */
	dot1agCfmMepRowStatus_active_c = 1,
	dot1agCfmMepRowStatus_notInService_c = 2,
	dot1agCfmMepRowStatus_notReady_c = 3,
	dot1agCfmMepRowStatus_createAndGo_c = 4,
	dot1agCfmMepRowStatus_createAndWait_c = 5,
	dot1agCfmMepRowStatus_destroy_c = 6,

	/* enums for column dot1agCfmMepPbbTeCanReportPbbTePresence */
	dot1agCfmMepPbbTeCanReportPbbTePresence_true_c = 1,
	dot1agCfmMepPbbTeCanReportPbbTePresence_false_c = 2,

	/* enums for column dot1agCfmMepPbbTeTrafficMismatchDefect */
	dot1agCfmMepPbbTeTrafficMismatchDefect_true_c = 1,
	dot1agCfmMepPbbTeTrafficMismatchDefect_false_c = 2,

	/* enums for column dot1agCfmMepPbbTeMismatchAlarm */
	dot1agCfmMepPbbTeMismatchAlarm_true_c = 1,
	dot1agCfmMepPbbTeMismatchAlarm_false_c = 2,

	/* enums for column dot1agCfmMepPbbTeLocalMismatchDefect */
	dot1agCfmMepPbbTeLocalMismatchDefect_true_c = 1,
	dot1agCfmMepPbbTeLocalMismatchDefect_false_c = 2,

	/* enums for column dot1agCfmMepPbbTeMismatchSinceReset */
	dot1agCfmMepPbbTeMismatchSinceReset_true_c = 1,
	dot1agCfmMepPbbTeMismatchSinceReset_false_c = 2,
};

/* table dot1agCfmMepTable row entry data structure */
typedef struct dot1agCfmMepEntry_t
{
	/* Index values */
	uint32_t u32MdIndex;
	uint32_t u32MaIndex;
	uint32_t u32Identifier;
	
	/* Column values */
	uint32_t u32IfIndex;
	int32_t i32Direction;
	uint32_t u32PrimaryVid;
	uint8_t u8Active;
	int32_t i32FngState;
	uint8_t u8CciEnabled;
	uint32_t u32CcmLtmPriority;
	uint8_t au8MacAddress[6];
	int32_t i32LowPrDef;
	int32_t i32FngAlarmTime;
	int32_t i32FngResetTime;
	int32_t i32HighestPrDefect;
	uint8_t au8Defects[1];
	uint8_t au8ErrorCcmLastFailure[1522];
	size_t u16ErrorCcmLastFailure_len;	/* # of uint8_t elements */
	uint8_t au8XconCcmLastFailure[1522];
	size_t u16XconCcmLastFailure_len;	/* # of uint8_t elements */
	uint32_t u32CcmSequenceErrors;
	uint32_t u32CciSentCcms;
	uint32_t u32NextLbmTransId;
	uint32_t u32LbrIn;
	uint32_t u32LbrInOutOfOrder;
	uint32_t u32LbrBadMsdu;
	uint32_t u32LtmNextSeqNumber;
	uint32_t u32UnexpLtrIn;
	uint32_t u32LbrOut;
	uint8_t u8TransmitLbmStatus;
	uint8_t au8TransmitLbmDestMacAddress[6];
	uint32_t u32TransmitLbmDestMepId;
	uint8_t u8TransmitLbmDestIsMepId;
	int32_t i32TransmitLbmMessages;
	uint8_t au8TransmitLbmDataTlv[/* TODO: , OCTETSTR, "" */ TOBE_REPLACED];
	size_t u16TransmitLbmDataTlv_len;	/* # of uint8_t elements */
	int32_t i32TransmitLbmVlanPriority;
	uint8_t u8TransmitLbmVlanDropEnable;
	uint8_t u8TransmitLbmResultOK;
	uint32_t u32TransmitLbmSeqNumber;
	uint8_t u8TransmitLtmStatus;
	uint8_t au8TransmitLtmFlags[1];
	uint8_t au8TransmitLtmTargetMacAddress[6];
	uint32_t u32TransmitLtmTargetMepId;
	uint8_t u8TransmitLtmTargetIsMepId;
	uint32_t u32TransmitLtmTtl;
	uint8_t u8TransmitLtmResult;
	uint32_t u32TransmitLtmSeqNumber;
	uint8_t au8TransmitLtmEgressIdentifier[8];
	uint8_t u8RowStatus;
	uint8_t u8PbbTeCanReportPbbTePresence;
	uint8_t u8PbbTeTrafficMismatchDefect;
	uint32_t u32PbbTransmitLbmLtmReverseVid;
	uint8_t u8PbbTeMismatchAlarm;
	uint8_t u8PbbTeLocalMismatchDefect;
	uint8_t u8PbbTeMismatchSinceReset;
	
	xBTree_Node_t oBTreeNode;
	xBTree_Node_t oIf_BTreeNode;
} dot1agCfmMepEntry_t;

extern xBTree_t oDot1agCfmMepTable_BTree;
extern xBTree_t oDot1agCfmMepTable_If_BTree;

/* dot1agCfmMepTable table mapper */
void dot1agCfmMepTable_init (void);
dot1agCfmMepEntry_t * dot1agCfmMepTable_createEntry (
	uint32_t u32MdIndex,
	uint32_t u32MaIndex,
	uint32_t u32Identifier);
dot1agCfmMepEntry_t * dot1agCfmMepTable_getByIndex (
	uint32_t u32MdIndex,
	uint32_t u32MaIndex,
	uint32_t u32Identifier);
dot1agCfmMepEntry_t * dot1agCfmMepTable_getNextIndex (
	uint32_t u32MdIndex,
	uint32_t u32MaIndex,
	uint32_t u32Identifier);
void dot1agCfmMepTable_removeEntry (dot1agCfmMepEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point dot1agCfmMepTable_getFirst;
Netsnmp_Next_Data_Point dot1agCfmMepTable_getNext;
Netsnmp_Get_Data_Point dot1agCfmMepTable_get;
Netsnmp_Node_Handler dot1agCfmMepTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table dot1agCfmLtrTable definitions
 */
#define DOT1AGCFMLTRSEQNUMBER 1
#define DOT1AGCFMLTRRECEIVEORDER 2
#define DOT1AGCFMLTRTTL 3
#define DOT1AGCFMLTRFORWARDED 4
#define DOT1AGCFMLTRTERMINALMEP 5
#define DOT1AGCFMLTRLASTEGRESSIDENTIFIER 6
#define DOT1AGCFMLTRNEXTEGRESSIDENTIFIER 7
#define DOT1AGCFMLTRRELAY 8
#define DOT1AGCFMLTRCHASSISIDSUBTYPE 9
#define DOT1AGCFMLTRCHASSISID 10
#define DOT1AGCFMLTRMANADDRESSDOMAIN 11
#define DOT1AGCFMLTRMANADDRESS 12
#define DOT1AGCFMLTRINGRESS 13
#define DOT1AGCFMLTRINGRESSMAC 14
#define DOT1AGCFMLTRINGRESSPORTIDSUBTYPE 15
#define DOT1AGCFMLTRINGRESSPORTID 16
#define DOT1AGCFMLTREGRESS 17
#define DOT1AGCFMLTREGRESSMAC 18
#define DOT1AGCFMLTREGRESSPORTIDSUBTYPE 19
#define DOT1AGCFMLTREGRESSPORTID 20
#define DOT1AGCFMLTRORGANIZATIONSPECIFICTLV 21

enum
{
	/* enums for column dot1agCfmLtrForwarded */
	dot1agCfmLtrForwarded_true_c = 1,
	dot1agCfmLtrForwarded_false_c = 2,

	/* enums for column dot1agCfmLtrTerminalMep */
	dot1agCfmLtrTerminalMep_true_c = 1,
	dot1agCfmLtrTerminalMep_false_c = 2,

	/* enums for column dot1agCfmLtrRelay */
	dot1agCfmLtrRelay_rlyHit_c = 1,
	dot1agCfmLtrRelay_rlyFdb_c = 2,
	dot1agCfmLtrRelay_rlyMpdb_c = 3,

	/* enums for column dot1agCfmLtrChassisIdSubtype */
	dot1agCfmLtrChassisIdSubtype_chassisComponent_c = 1,
	dot1agCfmLtrChassisIdSubtype_interfaceAlias_c = 2,
	dot1agCfmLtrChassisIdSubtype_portComponent_c = 3,
	dot1agCfmLtrChassisIdSubtype_macAddress_c = 4,
	dot1agCfmLtrChassisIdSubtype_networkAddress_c = 5,
	dot1agCfmLtrChassisIdSubtype_interfaceName_c = 6,
	dot1agCfmLtrChassisIdSubtype_local_c = 7,

	/* enums for column dot1agCfmLtrIngress */
	dot1agCfmLtrIngress_ingNoTlv_c = 0,
	dot1agCfmLtrIngress_ingOk_c = 1,
	dot1agCfmLtrIngress_ingDown_c = 2,
	dot1agCfmLtrIngress_ingBlocked_c = 3,
	dot1agCfmLtrIngress_ingVid_c = 4,

	/* enums for column dot1agCfmLtrIngressPortIdSubtype */
	dot1agCfmLtrIngressPortIdSubtype_interfaceAlias_c = 1,
	dot1agCfmLtrIngressPortIdSubtype_portComponent_c = 2,
	dot1agCfmLtrIngressPortIdSubtype_macAddress_c = 3,
	dot1agCfmLtrIngressPortIdSubtype_networkAddress_c = 4,
	dot1agCfmLtrIngressPortIdSubtype_interfaceName_c = 5,
	dot1agCfmLtrIngressPortIdSubtype_agentCircuitId_c = 6,
	dot1agCfmLtrIngressPortIdSubtype_local_c = 7,

	/* enums for column dot1agCfmLtrEgress */
	dot1agCfmLtrEgress_egrNoTlv_c = 0,
	dot1agCfmLtrEgress_egrOK_c = 1,
	dot1agCfmLtrEgress_egrDown_c = 2,
	dot1agCfmLtrEgress_egrBlocked_c = 3,
	dot1agCfmLtrEgress_egrVid_c = 4,

	/* enums for column dot1agCfmLtrEgressPortIdSubtype */
	dot1agCfmLtrEgressPortIdSubtype_interfaceAlias_c = 1,
	dot1agCfmLtrEgressPortIdSubtype_portComponent_c = 2,
	dot1agCfmLtrEgressPortIdSubtype_macAddress_c = 3,
	dot1agCfmLtrEgressPortIdSubtype_networkAddress_c = 4,
	dot1agCfmLtrEgressPortIdSubtype_interfaceName_c = 5,
	dot1agCfmLtrEgressPortIdSubtype_agentCircuitId_c = 6,
	dot1agCfmLtrEgressPortIdSubtype_local_c = 7,
};

/* table dot1agCfmLtrTable row entry data structure */
typedef struct dot1agCfmLtrEntry_t
{
	/* Index values */
	uint32_t u32MdIndex;
	uint32_t u32MaIndex;
	uint32_t u32MepIdentifier;
	uint32_t u32SeqNumber;
	uint32_t u32ReceiveOrder;
	
	/* Column values */
	uint32_t u32Ttl;
	uint8_t u8Forwarded;
	uint8_t u8TerminalMep;
	uint8_t au8LastEgressIdentifier[8];
	uint8_t au8NextEgressIdentifier[8];
	int32_t i32Relay;
	int32_t i32ChassisIdSubtype;
	uint8_t au8ChassisId[255];
	size_t u16ChassisId_len;	/* # of uint8_t elements */
	xOid_t aoManAddressDomain[128];
	size_t u16ManAddressDomain_len;	/* # of xOid_t elements */
	uint8_t au8ManAddress[255];
	size_t u16ManAddress_len;	/* # of uint8_t elements */
	int32_t i32Ingress;
	uint8_t au8IngressMac[6];
	int32_t i32IngressPortIdSubtype;
	uint8_t au8IngressPortId[255];
	size_t u16IngressPortId_len;	/* # of uint8_t elements */
	int32_t i32Egress;
	uint8_t au8EgressMac[6];
	int32_t i32EgressPortIdSubtype;
	uint8_t au8EgressPortId[255];
	size_t u16EgressPortId_len;	/* # of uint8_t elements */
	uint8_t au8OrganizationSpecificTlv[1500];
	size_t u16OrganizationSpecificTlv_len;	/* # of uint8_t elements */
	
	xBTree_Node_t oBTreeNode;
} dot1agCfmLtrEntry_t;

extern xBTree_t oDot1agCfmLtrTable_BTree;

/* dot1agCfmLtrTable table mapper */
void dot1agCfmLtrTable_init (void);
dot1agCfmLtrEntry_t * dot1agCfmLtrTable_createEntry (
	uint32_t u32MdIndex,
	uint32_t u32MaIndex,
	uint32_t u32MepIdentifier,
	uint32_t u32SeqNumber,
	uint32_t u32ReceiveOrder);
dot1agCfmLtrEntry_t * dot1agCfmLtrTable_getByIndex (
	uint32_t u32MdIndex,
	uint32_t u32MaIndex,
	uint32_t u32MepIdentifier,
	uint32_t u32SeqNumber,
	uint32_t u32ReceiveOrder);
dot1agCfmLtrEntry_t * dot1agCfmLtrTable_getNextIndex (
	uint32_t u32MdIndex,
	uint32_t u32MaIndex,
	uint32_t u32MepIdentifier,
	uint32_t u32SeqNumber,
	uint32_t u32ReceiveOrder);
void dot1agCfmLtrTable_removeEntry (dot1agCfmLtrEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point dot1agCfmLtrTable_getFirst;
Netsnmp_Next_Data_Point dot1agCfmLtrTable_getNext;
Netsnmp_Get_Data_Point dot1agCfmLtrTable_get;
Netsnmp_Node_Handler dot1agCfmLtrTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	table dot1agCfmMepDbTable definitions
 */
#define DOT1AGCFMMEPDBRMEPIDENTIFIER 1
#define DOT1AGCFMMEPDBRMEPSTATE 2
#define DOT1AGCFMMEPDBRMEPFAILEDOKTIME 3
#define DOT1AGCFMMEPDBMACADDRESS 4
#define DOT1AGCFMMEPDBRDI 5
#define DOT1AGCFMMEPDBPORTSTATUSTLV 6
#define DOT1AGCFMMEPDBINTERFACESTATUSTLV 7
#define DOT1AGCFMMEPDBCHASSISIDSUBTYPE 8
#define DOT1AGCFMMEPDBCHASSISID 9
#define DOT1AGCFMMEPDBMANADDRESSDOMAIN 10
#define DOT1AGCFMMEPDBMANADDRESS 11
#define DOT1AGCFMMEPDBRMEPISACTIVE 12

enum
{
	/* enums for column dot1agCfmMepDbRMepState */
	dot1agCfmMepDbRMepState_rMepIdle_c = 1,
	dot1agCfmMepDbRMepState_rMepStart_c = 2,
	dot1agCfmMepDbRMepState_rMepFailed_c = 3,
	dot1agCfmMepDbRMepState_rMepOk_c = 4,

	/* enums for column dot1agCfmMepDbRdi */
	dot1agCfmMepDbRdi_true_c = 1,
	dot1agCfmMepDbRdi_false_c = 2,

	/* enums for column dot1agCfmMepDbPortStatusTlv */
	dot1agCfmMepDbPortStatusTlv_psNoPortStateTLV_c = 0,
	dot1agCfmMepDbPortStatusTlv_psBlocked_c = 1,
	dot1agCfmMepDbPortStatusTlv_psUp_c = 2,

	/* enums for column dot1agCfmMepDbInterfaceStatusTlv */
	dot1agCfmMepDbInterfaceStatusTlv_isNoInterfaceStatusTLV_c = 0,
	dot1agCfmMepDbInterfaceStatusTlv_isUp_c = 1,
	dot1agCfmMepDbInterfaceStatusTlv_isDown_c = 2,
	dot1agCfmMepDbInterfaceStatusTlv_isTesting_c = 3,
	dot1agCfmMepDbInterfaceStatusTlv_isUnknown_c = 4,
	dot1agCfmMepDbInterfaceStatusTlv_isDormant_c = 5,
	dot1agCfmMepDbInterfaceStatusTlv_isNotPresent_c = 6,
	dot1agCfmMepDbInterfaceStatusTlv_isLowerLayerDown_c = 7,

	/* enums for column dot1agCfmMepDbChassisIdSubtype */
	dot1agCfmMepDbChassisIdSubtype_chassisComponent_c = 1,
	dot1agCfmMepDbChassisIdSubtype_interfaceAlias_c = 2,
	dot1agCfmMepDbChassisIdSubtype_portComponent_c = 3,
	dot1agCfmMepDbChassisIdSubtype_macAddress_c = 4,
	dot1agCfmMepDbChassisIdSubtype_networkAddress_c = 5,
	dot1agCfmMepDbChassisIdSubtype_interfaceName_c = 6,
	dot1agCfmMepDbChassisIdSubtype_local_c = 7,

	/* enums for column dot1agCfmMepDbRMepIsActive */
	dot1agCfmMepDbRMepIsActive_true_c = 1,
	dot1agCfmMepDbRMepIsActive_false_c = 2,
};

/* table dot1agCfmMepDbTable row entry data structure */
typedef struct dot1agCfmMepDbEntry_t
{
	/* Index values */
	uint32_t u32MdIndex;
	uint32_t u32MaIndex;
	uint32_t u32MepIdentifier;
	uint32_t u32RMepIdentifier;
	
	/* Column values */
	int32_t i32RMepState;
	uint32_t u32RMepFailedOkTime;
	uint8_t au8MacAddress[6];
	uint8_t u8Rdi;
	int32_t i32PortStatusTlv;
	int32_t i32InterfaceStatusTlv;
	int32_t i32ChassisIdSubtype;
	uint8_t au8ChassisId[255];
	size_t u16ChassisId_len;	/* # of uint8_t elements */
	xOid_t aoManAddressDomain[128];
	size_t u16ManAddressDomain_len;	/* # of xOid_t elements */
	uint8_t au8ManAddress[255];
	size_t u16ManAddress_len;	/* # of uint8_t elements */
	uint8_t u8RMepIsActive;
	
	xBTree_Node_t oBTreeNode;
} dot1agCfmMepDbEntry_t;

extern xBTree_t oDot1agCfmMepDbTable_BTree;

/* dot1agCfmMepDbTable table mapper */
void dot1agCfmMepDbTable_init (void);
dot1agCfmMepDbEntry_t * dot1agCfmMepDbTable_createEntry (
	uint32_t u32MdIndex,
	uint32_t u32MaIndex,
	uint32_t u32MepIdentifier,
	uint32_t u32RMepIdentifier);
dot1agCfmMepDbEntry_t * dot1agCfmMepDbTable_getByIndex (
	uint32_t u32MdIndex,
	uint32_t u32MaIndex,
	uint32_t u32MepIdentifier,
	uint32_t u32RMepIdentifier);
dot1agCfmMepDbEntry_t * dot1agCfmMepDbTable_getNextIndex (
	uint32_t u32MdIndex,
	uint32_t u32MaIndex,
	uint32_t u32MepIdentifier,
	uint32_t u32RMepIdentifier);
void dot1agCfmMepDbTable_removeEntry (dot1agCfmMepDbEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point dot1agCfmMepDbTable_getFirst;
Netsnmp_Next_Data_Point dot1agCfmMepDbTable_getNext;
Netsnmp_Get_Data_Point dot1agCfmMepDbTable_get;
Netsnmp_Node_Handler dot1agCfmMepDbTable_mapper;
#endif	/* SNMP_SRC */


/**
 *	notification mapper(s)
 */
/* definitions for notification(s) of dot1agNotifications */
#	define DOT1AGCFMFAULTALARM 1

/* dot1agNotifications mapper(s) */
int dot1agCfmFaultAlarm_trap (void);



#	ifdef __cplusplus
}
#	endif

#endif /* __IEEE8021CFMMIB_H__ */
