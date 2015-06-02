/*
 *  Copyright (c) 2008-2015
#*      NES Dev <nes.open.switch@gmail.com>
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

#ifndef __STP_UTILS_C__
#	define __STP_UTILS_C__



#include "ieee8021SpanningTreeMib.h"
#include "if/ifMIB.h"

#include "lib/time.h"

#include <stdbool.h>
#include <stdint.h>


bool
ieee8021StpPort_init (
	ieee8021SpanningTreeEntry_t *poStp,
	ieee8021SpanningTreePortEntry_t *poEntry)
{
	poEntry->i32State = poEntry->u8AdminStatus != ifAdminStatus_up_c ? ieee8021SpanningTreePortState_disabled_c: ieee8021SpanningTreePortState_blocking_c;
	memcpy (poEntry->au8DesignatedRoot, poStp->au8DesignatedRoot, sizeof (poEntry->au8DesignatedRoot));
	poEntry->i32DesignatedCost = 0;
	memcpy (poEntry->au8DesignatedBridge, poStp->au8DesignatedRoot, sizeof (poEntry->au8DesignatedBridge));
	memset (poEntry->au8DesignatedPort, 0, sizeof (poEntry->au8DesignatedPort));
	poEntry->u64ForwardTransitions = 0;
	//poEntry->u8RstpOperEdgePort = poEntry->u8RstpAdminEdgePort;
	poEntry->oCist.u32Uptime = xTime_centiTime (xTime_typeMono_c);
	memcpy (poEntry->oCist.au8DesignatedRoot, poStp->au8DesignatedRoot, sizeof (poEntry->oCist.au8DesignatedRoot));
	//poEntry->oCist.u8OperEdgePort = poEntry->oCist.u8AdminEdgePort;
	//poEntry->oCist.u8Disputed = ieee8021MstpCistPortDisputed_false_c;
	memcpy (poEntry->oCist.au8CistRegionalRootId, poStp->au8DesignatedRoot, sizeof (poEntry->oCist.au8CistRegionalRootId));
	poEntry->oCist.u32CistPathCost = 0;
	
	return true;
}



#endif	// __STP_UTILS_C__
