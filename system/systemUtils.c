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

#include "lib/bitmap.h"
#include "lib/snmp.h"

#include <stdbool.h>
#include <stdint.h>


bool entPhysicalTable_getChassis (
	uint32_t u32PhysicalIndex, uint32_t u32ContainedIn, int32_t i32Class,
	uint32_t *pu32ChassisIndex);


bool
entPhysicalTable_getChassis (
	uint32_t u32PhysicalIndex, uint32_t u32ContainedIn, int32_t i32Class,
	uint32_t *pu32ChassisIndex)
{
	xUnused (u32PhysicalIndex);
	
	if (i32Class == entPhysicalClass_stack_c ||
		(i32Class == entPhysicalClass_chassis_c && u32ContainedIn == 0) ||
		u32ContainedIn == 0)
	{
		return true;
	}
	
	register neEntPhysicalEntry_t *poContainer = NULL;
	
	while (
		u32ContainedIn != 0 &&
		(poContainer = neEntPhysicalTable_getByIndex (u32ContainedIn)) != NULL &&
		poContainer->oPhy.i32Class != entPhysicalClass_chassis_c)
	{
		u32ContainedIn = poContainer->oPhy.u32ContainedIn;
	}
	
	if (poContainer == NULL || poContainer->oPhy.i32Class != entPhysicalClass_chassis_c)
	{
		return false;
	}
	
	*pu32ChassisIndex = poContainer->u32Index;
	return true;
}

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
	
	
	switch (u8RowStatus)
	{
	case xRowStatus_active_c:
		if (poEntry->u32ChassisIndex == 0)
		{
			goto neEntPortRowStatus_update_cleanup;
		}
		
		if (poEntry->oK.u32IfIndex == 0)
		{
			ifData_t *poIfData = NULL;
			
			if (!ifData_createReference (poEntry->u32IfIndex, poEntry->i32IfType, 0, true, true, true, &poIfData))
			{
				goto neEntPortRowStatus_update_cleanup;
			}
			poIfData->oIfX.i32LinkUpDownTrapEnable = ifLinkUpDownTrapEnable_enabled_c;
			poIfData->oIfX.i32ConnectorPresent = ifConnectorPresent_true_c;
			ifData_unLock (poIfData);
			
			xBTree_nodeAdd (&poEntry->oIf_BTreeNode, &oNeEntPortTable_If_BTree);
			poEntry->oK.u32IfIndex = poEntry->u32IfIndex;
			poEntry->oK.i32IfType = poEntry->i32IfType;
		}
		break;
		
	case xRowStatus_notInService_c:
	case xRowStatus_destroy_c:
		if (poEntry->pOldEntry == NULL)
		{
			if ((poEntry->pOldEntry = xBuffer_alloc (sizeof (*poEntry->pOldEntry))) == NULL)
			{
				goto neEntPortRowStatus_update_cleanup;
			}
			memcpy (poEntry->pOldEntry, poEntry, sizeof (*poEntry->pOldEntry));
		}
		break;
	}
	
	
	switch (poEntry->oK.i32IfType)
	{
	default:
		goto neEntPortRowStatus_update_cleanup;
		
	case ifType_ethernetCsmacd_c:
	{
		switch (u8RowStatus)
		{
		case xRowStatus_active_c:
			if (!ieee8021BridgePhyData_createRegister (poEntry->oK.u32IfIndex, poEntry->u32PhysicalIndex, poEntry->u32ChassisIndex))
			{
				goto neEntPortRowStatus_update_cleanup;
			}
			
			if (!neIfStatus_modify (poEntry->oK.u32IfIndex, xOperStatus_notPresent_c, true, false))
			{
				goto neEntPortRowStatus_update_cleanup;
			}
			break;
			
		case xRowStatus_notInService_c:
			if (!neIfStatus_modify (poEntry->u32IfIndex, xOperStatus_down_c, true, false))
			{
				goto neEntPortRowStatus_update_cleanup;
			}
			break;
			
		case xRowStatus_notReady_c:
			if (!neIfStatus_modify (poEntry->u32IfIndex, xOperStatus_lowerLayerDown_c, true, false))
			{
				goto neEntPortRowStatus_update_cleanup;
			}
			break;
			
		case xRowStatus_destroy_c:
			if (!neIfStatus_modify (poEntry->u32IfIndex, xOperStatus_notPresent_c, true, false))
			{
				goto neEntPortRowStatus_update_cleanup;
			}
			
			if (!ieee8021BridgePhyData_removeRegister (poEntry->oK.u32IfIndex, poEntry->u32PhysicalIndex))
			{
				goto neEntPortRowStatus_update_cleanup;
			}
			break;
		}
		
		break;
	}
	
	case ifType_sonet_c:
		break;
		
	case ifType_opticalTransport_c:
		break;
	}
	
	
	switch (u8RowStatus)
	{
	case xRowStatus_destroy_c:
		if (poEntry->oK.u32IfIndex != 0)
		{
			ifData_t *poIfData = NULL;
			
			if (!ifData_getByIndexExt (poEntry->oK.u32IfIndex, true, &poIfData))
			{
				goto neEntPortRowStatus_update_cleanup;
			}
			poIfData->oIfX.i32LinkUpDownTrapEnable = ifLinkUpDownTrapEnable_disabled_c;
			poIfData->oIfX.i32ConnectorPresent = ifConnectorPresent_false_c;
			ifData_unLock (poIfData);
			
			if (!ifData_removeReference (poEntry->oK.u32IfIndex, true, true, true))
			{
				goto neEntPortRowStatus_update_cleanup;
			}
			
			xBTree_nodeRemove (&poEntry->oIf_BTreeNode, &oNeEntPortTable_If_BTree);
			poEntry->oK.u32IfIndex = 0;
			poEntry->oK.i32IfType = 0;
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
	
neEntPortRowStatus_update_cleanup:
	
	return bRetCode;
}



#endif	// __SYSTEMUTILS_C__
