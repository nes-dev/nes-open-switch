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

#ifndef __SYSTEMUTILS_C__
#	define __SYSTEMUTILS_C__



#include "systemUtils.h"
#include "ethernet/ieee8021BridgeMib.h"
#include "if/ifUtils.h"
#include "if/ifMIB.h"
#include "entityMIB.h"

#include "lib/snmp.h"

#include <stdbool.h>
#include <stdint.h>


bool
neEntPortRowStatus_update (
	neEntPortEntry_t *poEntry,
	uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	register neEntPortData_t *poPortData = neEntPortData_getByPortEntry (poEntry);
	
	switch (poEntry->i32Type)
	{
	default:
		goto neEntPortRowStatus_update_cleanup;
		
	case ifType_ethernetCsmacd_c:
	{
		ieee8021BridgePhyPortInfo_t oIeee8021BridgePhyPortInfo = ieee8021BridgePhyPortInfo_initInline (ieee8021BridgePhyPortInfo_all_c);
		
		ieee8021BridgePhyPortInfo_wrLock ();
		
		switch (u8RowStatus)
		{
		case xRowStatus_active_c:
			if (!ieee8021BridgePhyPortInfo_getByPort (poPortData->u32EntPhysicalIndex, &oIeee8021BridgePhyPortInfo) &&
				!ieee8021BridgePhyPortInfo_createExt (poPortData->u32EntPhysicalIndex, poPortData->u32IfIndex, &oIeee8021BridgePhyPortInfo))
			{
				goto neEntPortRowStatus_updateEthernet_unlock;
			}
			
			if (!neIfStatus_modify (poEntry->u32IfIndex, xOperStatus_notPresent_c, true, false))
			{
				goto neEntPortRowStatus_updateEthernet_unlock;
			}
			
			/* TODO */
			break;
			
		case xRowStatus_notInService_c:
			if (!neIfStatus_modify (poEntry->u32IfIndex, xOperStatus_down_c, true, false))
			{
				goto neEntPortRowStatus_updateEthernet_unlock;
			}
			
			/* TODO */
			break;
			
		case xRowStatus_destroy_c:
			if (!neIfStatus_modify (poEntry->u32IfIndex, xOperStatus_notPresent_c, true, false))
			{
				goto neEntPortRowStatus_updateEthernet_unlock;
			}
			
			if (!ieee8021BridgePhyPortInfo_getByPort (poPortData->u32EntPhysicalIndex, &oIeee8021BridgePhyPortInfo))
			{
				goto neEntPortRowStatus_updateEthernet_unlock;
			}
			
			if (!ieee8021BridgePhyPortInfo_removeExt (&oIeee8021BridgePhyPortInfo))
			{
				goto neEntPortRowStatus_updateEthernet_unlock;
			}
			
			/* TODO */
			break;
		}
		
		bRetCode = true;
		
neEntPortRowStatus_updateEthernet_unlock:
		ieee8021BridgePhyPortInfo_unLock ();
		break;
	}
	
	case ifType_sonet_c:
		break;
		
	case ifType_opticalTransport_c:
		break;
	}
	
neEntPortRowStatus_update_cleanup:
	
	return bRetCode;
}



#endif	// __SYSTEMUTILS_C__
