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

#ifndef __SYSTEMMIB_H__
#	define __SYSTEMMIB_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include "lib/binaryTree.h"
#include "lib/sync.h"
#include "lib/snmp.h"

#include <stdbool.h>
#include <stdint.h>

#define TOBE_REPLACED 1


/**
 *	agent MIB function
 */
void systemMIB_init (void);


/**
 *	scalar mapper(s)
 */
/** definitions for scalar(s) of system **/
#define SYSDESCR 1
#define SYSOBJECTID 2
#define SYSUPTIME 3
#define SYSCONTACT 4
#define SYSNAME 5
#define SYSLOCATION 6
#define SYSSERVICES 7
#define SYSORLASTCHANGE 8

enum
{
	sysServices_physical_c = 0,
	sysServices_datalink_c = 1,
	sysServices_network_c = 2,
	sysServices_transport_c = 3,
	sysServices_session_c = 4,
	sysServices_presentation_c = 5,
	sysServices_application_c = 6,
};

typedef struct system_t
{
	uint8_t *pcDescr;
	size_t u16Descr_len;	/* # of uint8_t elements */
	xOid_t *poObjectID;
	size_t u16ObjectID_len;	/* # of xOid_t elements */
	uint32_t u32UpTime;
	uint8_t au8Contact[64];
	size_t u16Contact_len;	/* # of uint8_t elements */
	uint8_t au8Name[64];
	size_t u16Name_len;	/* # of uint8_t elements */
	uint8_t au8Location[128];
	size_t u16Location_len;	/* # of uint8_t elements */
	int32_t i32Services;
	uint32_t u32ORLastChange;
	
	xRwLock_t oLock;
} system_t;

extern system_t oSystem;

#ifdef SNMP_SRC
Netsnmp_Node_Handler system_mapper;
#endif	/* SNMP_SRC */

#define system_wrLock() (xRwLock_wrLock (&oSystem.oLock))
#define system_rdLock() (xRwLock_rdLock (&oSystem.oLock))
#define system_unLock() (xRwLock_unlock (&oSystem.oLock))



/**
 *	table mapper(s)
 */
/**
 *	table sysORTable definitions
 */
#define SYSORINDEX 1
#define SYSORID 2
#define SYSORDESCR 3
#define SYSORUPTIME 4

enum
{
	sysORIndex_zero_c = 0,
	sysORIndex_start_c = 1,
	sysORIndex_end_c = 0x7FFFFFFF,
};

/* table sysORTable row entry data structure */
typedef struct sysOREntry_t
{
	/* Index values */
	int32_t i32Index;
	
	/* Column values */
	xOid_t *poID;
	size_t u16ID_len;	/* # of xOid_t elements */
	uint8_t *pcDescr;
	size_t u16Descr_len;	/* # of uint8_t elements */
	uint32_t u32UpTime;
	
	xBTree_Node_t oBTreeNode;
	xBTree_Node_t oID_BTreeNode;
} sysOREntry_t;

extern xBTree_t oSysORTable_BTree;
extern xBTree_t oSysORTable_ID_BTree;

/* sysORTable table mapper */
void sysORTable_init (void);
sysOREntry_t * sysORTable_createEntry (
	int32_t i32Index,
	uint16_t u16ID_len, uint16_t u16Descr_len);
sysOREntry_t * sysORTable_getByIndex (
	int32_t i32Index);
sysOREntry_t * sysORTable_ID_getByIndex (
	xOid_t *poID, size_t u16ID_len);
sysOREntry_t * sysORTable_getNextIndex (
	int32_t i32Index);
void sysORTable_removeEntry (sysOREntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point sysORTable_getFirst;
Netsnmp_Next_Data_Point sysORTable_getNext;
Netsnmp_Get_Data_Point sysORTable_get;
Netsnmp_Node_Handler sysORTable_mapper;
#endif	/* SNMP_SRC */



#	ifdef __cplusplus
}
#	endif

#endif /* __SYSTEMMIB_H__ */
