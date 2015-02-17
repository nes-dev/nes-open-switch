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

#ifndef __NEIEEE8021BRIDGEMIB_H__
#	define __NEIEEE8021BRIDGEMIB_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include "lib/binaryTree.h"
#include "lib/snmp.h"

#include <stdbool.h>

#define TOBE_REPLACED 1


/**
 *	agent MIB function
 */
void neIeee8021BridgeMIB_init (void);


/**
 *	table mapper(s)
 */
/**
 *	table neIeee8021BridgeBaseTable definitions
 */
#define NEIEEE8021BRIDGEBASECHASSISID 1
#define NEIEEE8021BRIDGEBASENUMPORTSMAX 2
#define NEIEEE8021BRIDGEBASEPORTS 3
#define NEIEEE8021BRIDGEBASEADMINFLAGS 4
#define NEIEEE8021BRIDGEBASEOPERSTATE 5

enum
{
	/* enums for column neIeee8021BridgeBaseAdminFlags */
	neIeee8021BridgeBaseAdminFlags_bChassisBase_c = 0,

	/* enums for column neIeee8021BridgeBaseOperState */
	neIeee8021BridgeBaseOperState_unknown_c = 1,
	neIeee8021BridgeBaseOperState_disabled_c = 2,
	neIeee8021BridgeBaseOperState_enabled_c = 3,
	neIeee8021BridgeBaseOperState_testing_c = 4,
};

/* table neIeee8021BridgeBaseTable row entry data structure */
typedef struct neIeee8021BridgeBaseEntry_t
{
	/* Index values */
	uint32_t u32ComponentId;
	
	/* Column values */
	uint32_t u32ChassisId;
	uint32_t u32NumPortsMax;
	uint8_t au8Ports[/* TODO: PortList, PortList, "" */ TOBE_REPLACED];
	size_t u16Ports_len;	/* # of uint8_t elements */
	uint8_t au8AdminFlags[1];
	size_t u16AdminFlags_len;	/* # of uint8_t elements */
	int32_t i32OperState;
	
	xBTree_Node_t oBTreeNode;
} neIeee8021BridgeBaseEntry_t;

extern xBTree_t oNeIeee8021BridgeBaseTable_BTree;

/* neIeee8021BridgeBaseTable table mapper */
void neIeee8021BridgeBaseTable_init (void);
neIeee8021BridgeBaseEntry_t * neIeee8021BridgeBaseTable_createEntry (
	uint32_t u32ComponentId);
neIeee8021BridgeBaseEntry_t * neIeee8021BridgeBaseTable_getByIndex (
	uint32_t u32ComponentId);
neIeee8021BridgeBaseEntry_t * neIeee8021BridgeBaseTable_getNextIndex (
	uint32_t u32ComponentId);
void neIeee8021BridgeBaseTable_removeEntry (neIeee8021BridgeBaseEntry_t *poEntry);
#ifdef SNMP_SRC
Netsnmp_First_Data_Point neIeee8021BridgeBaseTable_getFirst;
Netsnmp_Next_Data_Point neIeee8021BridgeBaseTable_getNext;
Netsnmp_Get_Data_Point neIeee8021BridgeBaseTable_get;
Netsnmp_Node_Handler neIeee8021BridgeBaseTable_mapper;
#endif	/* SNMP_SRC */



#	ifdef __cplusplus
}
#	endif

#endif /* __NEIEEE8021BRIDGEMIB_H__ */
