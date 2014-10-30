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

#include <stdbool.h>


bool bridgeUtilsInit (void);

bool
	ieee8021PbILan_createEntry (
		ieee8021BridgeBasePortEntry_t *poCnpPortEntry,
		ieee8021BridgeBasePortEntry_t *poPepPortEntry);
bool
	ieee8021PbILan_removeEntry (
		ieee8021BridgeBasePortEntry_t *poCnpPortEntry,
		ieee8021BridgeBasePortEntry_t *poPepPortEntry);
bool
	ieee8021PbbILan_createEntry (
		ieee8021BridgeBasePortEntry_t *poCbpPortEntry,
		uint32_t u32PipIfIndex,
		ieee8021BridgeBasePortEntry_t *poVipPortEntry);
bool
	ieee8021PbbILan_removeEntry (
		ieee8021BridgeBasePortEntry_t *poCbpPortEntry,
		ieee8021BridgeBasePortEntry_t *poVipPortEntry);



#	ifdef __cplusplus
}
#	endif

#endif	// __BRIDGEUTILS_H__
