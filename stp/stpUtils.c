/*
 *  Copyright (c) 2008-2015
#*      NES Repo <nes.repo@gmail.com>
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


enum
{
	ieee8021StpPortId_portNumberMask_c = 0x0FFF,
	
	ieee8021StpBridgeId_addressOffset_c = 2,
};


#define ieee8021StpPortId_portNumber(_portId)	((_portId) & ieee8021StpPortId_portNumberMask_c)

#define ieee8021StpBridgeId_address(_bridgeId)		(&(_bridgeId)[ieee8021StpBridgeId_addressOffset_c])


int8_t
ieee8021StpPathVector_cmp (
	uint8_t *pu8CstRootId1, uint32_t u32CstPathCost1,
	uint8_t *pu8MstRootId1, uint32_t u32MstPathCost1, uint8_t *pu8TxBridgeId1, uint16_t u16TxPortId1, uint16_t u16RxPortId1,
	uint8_t *pu8CstRootId2, uint32_t u32CstPathCost2,
	uint8_t *pu8MstRootId2, uint32_t u32MstPathCost2, uint8_t *pu8TxBridgeId2, uint16_t u16TxPortId2, uint16_t u16RxPortId2)
{
	register int8_t i8Cmp =
		(memcmp (pu8CstRootId1, pu8CstRootId2, 8) < 0) ||
		(memcmp (pu8CstRootId1, pu8CstRootId2, 8) == 0 && u32CstPathCost1 < u32CstPathCost2) ||
		(memcmp (pu8CstRootId1, pu8CstRootId2, 8) == 0 && u32CstPathCost1 == u32CstPathCost2 && memcmp (pu8MstRootId1, pu8MstRootId2, 8) < 0) ||
		(memcmp (pu8CstRootId1, pu8CstRootId2, 8) == 0 && u32CstPathCost1 == u32CstPathCost2 && memcmp (pu8MstRootId1, pu8MstRootId2, 8) == 0 && u32MstPathCost1 < u32MstPathCost2) ||
		(memcmp (pu8CstRootId1, pu8CstRootId2, 8) == 0 && u32CstPathCost1 == u32CstPathCost2 && memcmp (pu8MstRootId1, pu8MstRootId2, 8) == 0 && u32MstPathCost1 == u32MstPathCost2 && memcmp (pu8TxBridgeId1, pu8TxBridgeId2, 8) < 0) ||
		(memcmp (pu8CstRootId1, pu8CstRootId2, 8) == 0 && u32CstPathCost1 == u32CstPathCost2 && memcmp (pu8MstRootId1, pu8MstRootId2, 8) == 0 && u32MstPathCost1 == u32MstPathCost2 && memcmp (pu8TxBridgeId1, pu8TxBridgeId2, 8) == 0 && u16TxPortId1 < u16TxPortId2) ||
		(memcmp (pu8CstRootId1, pu8CstRootId2, 8) == 0 && u32CstPathCost1 == u32CstPathCost2 && memcmp (pu8MstRootId1, pu8MstRootId2, 8) == 0 && u32MstPathCost1 == u32MstPathCost2 && memcmp (pu8TxBridgeId1, pu8TxBridgeId2, 8) == 0 && u16TxPortId1 == u16TxPortId2 && u16RxPortId1 < u16RxPortId2) ? -1:
		(memcmp (pu8CstRootId1, pu8CstRootId2, 8) == 0 && u32CstPathCost1 == u32CstPathCost2 && memcmp (pu8MstRootId1, pu8MstRootId2, 8) == 0 && u32MstPathCost1 == u32MstPathCost2 && memcmp (pu8TxBridgeId1, pu8TxBridgeId2, 8) == 0 && u16TxPortId1 == u16TxPortId2 && u16RxPortId1 == u16RxPortId2) ? 0: 1;
		
	if (i8Cmp != -1 &&
		memcmp (ieee8021StpBridgeId_address (pu8TxBridgeId1), ieee8021StpBridgeId_address (pu8TxBridgeId2), IeeeEui48_size_c) == 0 &&
		ieee8021StpPortId_portNumber (u16TxPortId1) == ieee8021StpPortId_portNumber (u16TxPortId2))
	{
		i8Cmp = -1;
	}
	
	return i8Cmp;
}

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
	poEntry->u8RstpOperEdgePort = poEntry->u8RstpAdminEdgePort;
	poEntry->oCist.u32Uptime = xTime_centiTime (xTime_typeMono_c);
	memcpy (poEntry->oCist.au8DesignatedRoot, poStp->au8DesignatedRoot, sizeof (poEntry->oCist.au8DesignatedRoot));
	poEntry->oCist.u8OperEdgePort = poEntry->oCist.u8AdminEdgePort;
	poEntry->oCist.u8Disputed = ieee8021MstpCistPortDisputed_false_c;
	memcpy (poEntry->oCist.au8CistRegionalRootId, poStp->au8DesignatedRoot, sizeof (poEntry->oCist.au8CistRegionalRootId));
	poEntry->oCist.u32CistPathCost = 0;
	
	return true;
}



#endif	// __STP_UTILS_C__
