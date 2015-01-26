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
neEntPhysicalRowStatus_update (
	neEntPhysicalEntry_t *poEntry, uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	
	bRetCode = true;
	
//neEntPhysicalRowStatus_update_cleanup:
	
	return bRetCode;
}

bool
neEntChassisRowStatus_update (
	neEntChassisEntry_t *poEntry,
	uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	
	switch (u8RowStatus)
	{
	case xRowStatus_active_c:
		if (xBitmap_getBitRev (poEntry->au8PortTypes, neEntChassisPortTypes_bEthernet_c) && !ieee8021BridgeChassis_createRegister (poEntry->u32PhysicalIndex))
		{
			goto neEntChassisRowStatus_update_cleanup;
		}
		break;
		
	case xRowStatus_notInService_c:
	case xRowStatus_destroy_c:
		if (poEntry->pOldEntry == NULL)
		{
			if ((poEntry->pOldEntry = xBuffer_alloc (sizeof (*poEntry->pOldEntry))) == NULL)
			{
				goto neEntChassisRowStatus_update_cleanup;
			}
			memcpy (poEntry->pOldEntry, poEntry, sizeof (*poEntry->pOldEntry));
		}
		break;
	}
	
	
	switch (u8RowStatus)
	{
	case xRowStatus_destroy_c:
		if (xBitmap_getBitRev (poEntry->au8PortTypes, neEntChassisPortTypes_bEthernet_c) && !ieee8021BridgeChassis_removeRegister (poEntry->u32PhysicalIndex))
		{
			goto neEntChassisRowStatus_update_cleanup;
		}
		
	case xRowStatus_active_c:
		if (poEntry->pOldEntry != NULL)
		{
			xBuffer_free (poEntry->pOldEntry);
			poEntry->pOldEntry = NULL;
		}
		break;
	}
	
	bRetCode = true;
	
neEntChassisRowStatus_update_cleanup:
	
	return bRetCode;
}

bool
neEntPortRowStatus_update (
	neEntPortEntry_t *poEntry,
	uint8_t u8RowStatus)
{
	register bool bRetCode = false;
	register neEntPortData_t *poPortData = neEntPortData_getByPortEntry (poEntry);
	
	if (poPortData->u32ChassisIndex == 0)
	{
		goto neEntPortRowStatus_update_cleanup;
	}
	
	switch (poEntry->i32Type)
	{
	default:
		goto neEntPortRowStatus_update_cleanup;
		
	case ifType_ethernetCsmacd_c:
	{
		switch (u8RowStatus)
		{
		case xRowStatus_active_c:
			if (!ieee8021BridgePhyData_createRegister (poPortData->u32IfIndex, poPortData->u32PhysicalIndex, poPortData->u32ChassisIndex))
			{
				goto neEntPortRowStatus_update_cleanup;
			}
			
			if (!neIfStatus_modify (poPortData->u32IfIndex, xOperStatus_notPresent_c, true, false))
			{
				goto neEntPortRowStatus_update_cleanup;
			}
			
			/* TODO */
			break;
			
		case xRowStatus_notInService_c:
			if (!neIfStatus_modify (poPortData->u32IfIndex, xOperStatus_down_c, true, false))
			{
				goto neEntPortRowStatus_update_cleanup;
			}
			
			/* TODO */
			break;
			
		case xRowStatus_destroy_c:
			if (!neIfStatus_modify (poPortData->u32IfIndex, xOperStatus_notPresent_c, true, false))
			{
				goto neEntPortRowStatus_update_cleanup;
			}
			
			if (!ieee8021BridgePhyData_removeRegister (poPortData->u32IfIndex, poPortData->u32PhysicalIndex))
			{
				goto neEntPortRowStatus_update_cleanup;
			}
			
			/* TODO */
			break;
		}
		
		break;
	}
	
	case ifType_sonet_c:
		break;
		
	case ifType_opticalTransport_c:
		break;
	}
	
	bRetCode = true;
	
neEntPortRowStatus_update_cleanup:
	
	return bRetCode;
}



#endif	// __SYSTEMUTILS_C__
