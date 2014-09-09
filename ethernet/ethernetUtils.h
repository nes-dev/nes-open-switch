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

#ifndef __ETHERNET_UTILS_H__
#	define __ETHERNET_UTILS_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include "ieee8021BridgeMib.h"

#include <stdbool.h>
#include <stdint.h>


bool ethernetUtilsInit (void);

bool
	ieee8021BridgeBaseRowStatus_update (
		ieee8021BridgeBaseEntry_t *poEntry, uint8_t u8RowStatus);
bool
	ieee8021BridgeBasePortRowStatus_update (
		ieee8021BridgeBasePortEntry_t *poEntry, uint8_t u8RowStatus);
bool
	ieee8021BridgeDot1dPortRowStatus_update (
		ieee8021BridgeDot1dPortEntry_t *poEntry, uint8_t u8RowStatus);



#	ifdef __cplusplus
}
#	endif

#endif	// __ETHERNET_UTILS_H__
