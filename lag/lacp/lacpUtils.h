/*
 *  Copyright (c) 2008-2016
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
//set ts=4 sw=4

#ifndef __LACP_UTILS_H__
#	define __LACP_UTILS_H__

#	ifdef __cplusplus
extern "C" {
#	endif



#include "lacp_ext.h"
#include "lag/lagMIB.h"

#include <stdbool.h>


extern bool
	dot3adAggLacpStatus_update (
		dot3adAggEntry_t *poEntry, uint8_t u8RowStatus);
extern bool
	dot3adAggPortLacpStatus_update (
		dot3adAggPortEntry_t *poEntry, uint8_t u8RowStatus);

extern bool
	dot3adAggPortLacp_stateUpdate (dot3adAggPortEntry_t *poEntry, bool bForce);
extern void
	dot3adAggLacp_processPduRx (lacpMessage_Pdu_t *pMessage);


#	ifdef __cplusplus
}
#	endif

#endif	// __LACP_UTILS_H__
