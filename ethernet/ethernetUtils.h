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
//set ts=4 sw=4

#ifndef __ETHERNET_UTILS_H__
#	define __ETHERNET_UTILS_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include "ieee8021BridgeMib.h"
#include "ieee8021QBridgeMib.h"

#include <stdbool.h>
#include <stdint.h>


bool ethernetUtilsInit (void);

bool
	ieee8021BridgeBaseTable_hierUpdate (
		ieee8021BridgeBaseEntry_t *poEntry, uint8_t u8RowStatus);
bool
	ieee8021BridgeBaseTrafficClassesEnabled_update (
		ieee8021BridgeBaseEntry_t *poEntry, uint8_t u8TrafficClassesEnabled);
bool
	ieee8021BridgeBaseMmrpEnabledStatus_update (
		ieee8021BridgeBaseEntry_t *poEntry, uint8_t u8MmrpEnabledStatus);
bool
	ieee8021BridgeBaseRowStatus_update (
		ieee8021BridgeBaseEntry_t *poEntry, uint8_t u8RowStatus);
bool
	ieee8021BridgeXPortRowStatus_halUpdate (
		ieee8021BridgeBaseEntry_t *poComponent,
		void *pvEntry, int32_t i32Type, uint8_t u8CurStatus, uint8_t u8RowStatus);
bool
	ieee8021BridgeBasePortTable_hierUpdate (
		ieee8021BridgeBasePortEntry_t *poEntry, uint8_t u8RowStatus);
bool
	ieee8021BridgeBasePortRowStatus_update (
		ieee8021BridgeBaseEntry_t *poComponent,
		ieee8021BridgeBasePortEntry_t *poEntry, uint8_t u8RowStatus);
bool
	ieee8021BridgeDot1dPortRowStatus_update (
		ieee8021BridgeBaseEntry_t *poComponent,
		ieee8021BridgeDot1dPortEntry_t *poEntry, uint8_t u8RowStatus);
bool
	ieee8021QBridgeCVlanPortRowStatus_update (
		ieee8021BridgeBaseEntry_t *poComponent,
		ieee8021QBridgeCVlanPortEntry_t *poEntry, uint8_t u8RowStatus);
bool
	ieee8021QBridgeVlanCurrentTable_vlanUpdate (
		ieee8021BridgeBaseEntry_t *poComponent,
		ieee8021QBridgeVlanCurrentEntry_t *poEntry,
		uint8_t *pu8DisabledPorts, uint8_t *pu8TaggedPorts, uint8_t *pu8UntaggedPorts);
bool
	ieee8021QBridgeVlanCurrentRowStatus_update (
		ieee8021BridgeBaseEntry_t *poComponent,
		ieee8021QBridgeVlanCurrentEntry_t *poEntry, uint8_t u8RowStatus);
bool
	ieee8021QBridgeVlanStaticTable_vHandler (
		uint32_t u32ComponentId,
		uint32_t u32VlanIndex,
		bool bEnable, bool bTagged, uint32_t u32Count, uint32_t u32Port, ...);
bool
	ieee8021QBridgeVlanStaticRowStatus_update (
		ieee8021BridgeBaseEntry_t *poComponent,
		ieee8021QBridgeVlanStaticEntry_t *poEntry, uint8_t u8RowStatus);
bool
	ieee8021QBridgeVlanStaticTable_vlanUpdate (
		ieee8021BridgeBaseEntry_t *poComponent,
		ieee8021QBridgeVlanStaticEntry_t *poEntry,
		uint8_t *pu8EnabledPorts, uint8_t *pu8DisabledPorts, uint8_t *pu8UntaggedPorts);
bool
	ieee8021QBridgePortRowStatus_update (
		ieee8021BridgeBaseEntry_t *poComponent,
		ieee8021QBridgePortEntry_t *poEntry, uint8_t u8RowStatus);
bool
	ieee8021QBridgeLearningConstraintsType_update (
		ieee8021QBridgeLearningConstraintsEntry_t *poEntry, int32_t i32Type);
bool
	ieee8021QBridgeLearningConstraintsStatus_update (
		ieee8021QBridgeLearningConstraintsEntry_t *poEntry, uint8_t u8RowStatus);
bool
	ieee8021QBridgeIngressVidXRowStatus_update (
		ieee8021BridgeBaseEntry_t *poComponent,
		ieee8021QBridgeIngressVidXEntry_t *poEntry, uint8_t u8RowStatus);
bool
	ieee8021QBridgeEgressVidXRowStatus_update (
		ieee8021BridgeBaseEntry_t *poComponent,
		ieee8021QBridgeEgressVidXEntry_t *poEntry, uint8_t u8RowStatus);



#	ifdef __cplusplus
}
#	endif

#endif	// __ETHERNET_UTILS_H__
