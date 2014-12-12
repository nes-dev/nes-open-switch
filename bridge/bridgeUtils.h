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
//set ts=4 sw=4

#ifndef __BRIDGEUTILS_H__
#	define __BRIDGEUTILS_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include "ethernet/ieee8021BridgeMib.h"
#include "ethernet/ieee8021QBridgeMib.h"
#include "ieee8021PbMib.h"
#include "ieee8021PbbMib.h"

#include <stdbool.h>


bool bridgeUtilsInit (void);

bool
	ieee8021PbVlanStaticTable_vlanHandler (
		ieee8021BridgeBaseEntry_t *poComponent,
		ieee8021QBridgeVlanStaticEntry_t *poEntry,
		uint8_t *pu8EnabledPorts, uint8_t *pu8DisabledPorts, uint8_t *pu8UntaggedPorts);
bool
	ieee8021PbVlanStaticRowStatus_handler (
		ieee8021BridgeBaseEntry_t *poComponent,
		ieee8021QBridgeVlanStaticEntry_t *poEntry,
		uint8_t u8RowStatus);
bool
	ieee8021PbILan_createEntry (
		ieee8021BridgeBaseEntry_t *poSComponent, ieee8021BridgeBasePortEntry_t *poCnpPort,
		ieee8021BridgeBaseEntry_t *poCComponent, ieee8021BridgeBasePortEntry_t *poPepPort);
bool
	ieee8021PbILan_removeEntry (
		ieee8021BridgeBaseEntry_t *poSComponent, ieee8021BridgeBasePortEntry_t *poCnpPort,
		ieee8021BridgeBaseEntry_t *poCComponent, ieee8021BridgeBasePortEntry_t *poPepPort);
bool
	ieee8021PbbILan_createEntry (
		ieee8021BridgeBaseEntry_t *poBComponent, ieee8021BridgeBasePortEntry_t *poCbpPort,
		uint32_t u32PipIfIndex,
		ieee8021BridgeBaseEntry_t *poIComponent, ieee8021BridgeBasePortEntry_t *poVipPort);
bool
	ieee8021PbbILan_removeEntry (
		ieee8021BridgeBaseEntry_t *poBComponent, ieee8021BridgeBasePortEntry_t *poCbpPort,
		ieee8021BridgeBaseEntry_t *poIComponent, ieee8021BridgeBasePortEntry_t *poVipPort);
bool
	ieee8021PbCVidRegistrationRowStatus_update (
		ieee8021PbCVidRegistrationEntry_t *poEntry, uint8_t u8RowStatus);
bool
	ieee8021PbbVipRowStatus_update (
		ieee8021BridgeBaseEntry_t *poComponent,
		ieee8021PbbVipEntry_t *poEntry, uint8_t u8RowStatus);
bool
	ieee8021PbbPipTable_attachComponent (
		ieee8021BridgeBaseEntry_t *poComponent,
		ieee8021PbbPipEntry_t *poEntry);
bool
	ieee8021PbbPipRowStatus_update (
		ieee8021PbbPipEntry_t *poEntry, uint8_t u8RowStatus);
bool
	ieee8021PbbVipToPipMappingRowStatus_update (
		ieee8021PbbVipToPipMappingEntry_t *poEntry, uint8_t u8RowStatus);
bool
	ieee8021PbbCbpServiceMappingRowStatus_update (
		ieee8021PbbCbpEntry_t *poCbpPort,
		ieee8021PbbCbpServiceMappingEntry_t *poEntry, uint8_t u8RowStatus);
bool
	ieee8021PbbCbpRowStatus_update (
		ieee8021BridgeBaseEntry_t *poComponent,
		ieee8021PbbCbpEntry_t *poEntry, uint8_t u8RowStatus);



#	ifdef __cplusplus
}
#	endif

#endif	// __BRIDGEUTILS_H__
